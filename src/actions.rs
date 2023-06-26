mod firewall {
    include!("cgroup_fw.skel.rs");
}

use super::*;
use crate::rule::*;
use crate::sys::*;
use crate::utils::*;
use anyhow::Result;
use clap::Args;
use crossbeam_channel::{select, tick};
use firewall::*;
use libbpf_rs::{Link, Map, MapFlags};
use log::debug;
use std::path::Path;
use std::time::Duration;

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct Direction {
    /// visit an external IP from container
    #[clap(long, value_name = "IP")]
    to: Option<String>,

    /// be visited from a remote IP
    #[clap(long, value_name = "IP")]
    from: Option<String>,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = false)]
pub struct Protocol {
    /// specify a tcp port
    #[arg(long, value_name = "TCP_PORT", value_parser = clap::value_parser!(u16).range(1001..))]
    tcp: Option<u16>,

    /// specify a udp port
    #[arg(long, value_name = "UDP_PORT", value_parser = clap::value_parser!(u16).range(1001..))]
    udp: Option<u16>,
}

/// Create a directory in bpf's pseudo file system to hold container's pinned resources
fn prepare_ctn_dir(ctn_id: &str) -> Result<()> {
    use std::fs::create_dir;
    use std::os::fd::AsRawFd;

    // (1) Create dir for container
    let ctn_dir = get_ctn_bpf_path(ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if ctn_dir_path.is_dir() {
        // return if the dir is already there
        debug!("Dir {:?} already exists.", ctn_dir_path);
        return Ok(());
    }

    create_dir(ctn_dir_path)?;

    // (2) Load bpf programs and maps
    let builder = CgroupFwSkelBuilder::default();
    increase_rlimit()?;
    // Get an opened, pre-load bpf object
    let open = builder.open()?;
    // Get a loaded bpf object
    let mut obj = open.load()?;

    // Get target cgroup id
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(format!(
            "/sys/fs/cgroup/system.slice/docker-{}.scope",
            ctn_id
        ))?;
    let cgroup_fd = f.as_raw_fd();

    // (2.a) Get loaded programs and attach to the cgroup, then pin to the fs
    let mut eg_link = obj.progs_mut().egress_filter().attach_cgroup(cgroup_fd)?;
    // The prog_type and attach_type are inferred from the c program
    // should be CgroupInetEgress here
    //println!("[DEBUG]: Attach type is {:?}", obj.progs().egress_filter().attach_type());
    eg_link.pin(format!("{}/{}", &ctn_dir, EGRESS_LINK_NAME))?;

    let mut ig_link = obj.progs_mut().ingress_filter().attach_cgroup(cgroup_fd)?;
    ig_link.pin(format!("{}/{}", &ctn_dir, INGRESS_LINK_NAME))?;

    // (2.b) Get loaded maps and pin to the fs
    let mut maps = obj.maps_mut();

    let eg_fw_map = maps.egress_blacklist();
    // Persist the map on bpf vfs
    eg_fw_map.pin(format!("{}/{}", &ctn_dir, EGRESS_MAP_NAME))?;

    let eg_l4_fw_map = maps.egress_l4_blacklist();
    eg_l4_fw_map.pin(format!("{}/{}", &ctn_dir, EGRESS_L4_MAP_NAME))?;

    let ig_fw_map = maps.ingress_blacklist();
    ig_fw_map.pin(format!("{}/{}", &ctn_dir, INGRESS_MAP_NAME))?;

    let ig_l4_fw_map = maps.ingress_l4_blacklist();
    ig_l4_fw_map.pin(format!("{}/{}", &ctn_dir, INGRESS_L4_MAP_NAME))?;

    let data_flow_map = maps.data_flow();
    data_flow_map.pin(format!("{}/{}", &ctn_dir, DATAFLOW_MAP_NAME))?;

    Ok(())
}

/// Remove container's related resources bpf's pseudo file system
pub fn free_ctn_resources(ctn_name: &str) -> Result<()> {
    use std::fs::remove_dir;

    let ctn_id = get_ctn_id_from_name(&ctn_name)?;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir is already there
        debug!("Dir {:?} already deleted.", ctn_dir_path);
        return Ok(());
    }

    let all_links = vec![EGRESS_LINK_NAME, INGRESS_LINK_NAME];
    let all_maps = get_all_maps();

    // if link is unpinned and map stays, the rules will not applied any more.
    for l in all_links {
        let path = format!("{}/{}", ctn_dir, l);
        let mut prog = Link::open(path)?;
        prog.unpin()?;
        debug!("Unpinned link {}", l);
    }

    // if map is unpinned and link stays, the rules is still in effect ?!
    for m in all_maps {
        let path = format!("{}/{}", ctn_dir, m);
        let mut map = Map::from_pinned_path(&path)?;
        map.unpin(&path)?;
        debug!("Unpinned map {}", m);
    }

    remove_dir(ctn_dir_path)?;

    Ok(())
}

/// Apply new firewall rule to container based on client's input via cli
pub fn update_rule(
    ctn_name: &str,
    direction: &Direction,
    protocol: &Protocol,
    is_block: bool,
) -> Result<()> {
    // Create a folder and store the pinned maps for the container if not exist yet
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;

    if is_block {
        prepare_ctn_dir(&ctn_id)?;
    }

    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);

    if !is_block && !ctn_dir_path.try_exists()? {
        // return if the dir doesn't exist
        println!("[INFO] No rules applied to {}.", ctn_name);
        return Ok(());
    }

    let mut builder = RuleBuilder::new();
    builder = builder.ctn_dir(&ctn_dir);

    match (protocol.tcp, protocol.udp) {
        (Some(p), None) => {
            builder.is_l4 = true;
            builder = builder.port(p);
        }
        (None, Some(p)) => {
            builder.is_l4 = true;
            builder.is_udp = true;
            builder = builder.port(p);
        }
        _ => (),
    }

    match (&direction.to, &direction.from) {
        (Some(eg), None) => {
            builder = builder.ip(&eg);
        }
        (None, Some(ing)) => {
            builder.is_ingress = true;
            builder = builder.ip(&ing);
        }
        _ => unreachable!(),
    };

    let rule = builder.build();
    let fw_map = rule.map()?;
    let key = rule.key()?;

    // Apply the firewall rule
    if is_block {
        let value = u8::from(true).to_ne_bytes();
        fw_map.update(&key, &value, MapFlags::ANY)?;
    } else {
        fw_map.lookup_and_delete(&key)?;
    }

    Ok(())
}

/// List container's active firewall rule
pub fn show_rules(ctn_name: &str) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;

    //use libbpf_rs::MapFlags;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);

    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir doesn't exist
        println!("[INFO] No rules applied to {}.", ctn_name);
        return Ok(());
    }

    let all_maps = get_rule_maps();
    let mut is_l3;
    for m in all_maps {
        match m {
            EGRESS_MAP_NAME => {
                println!("L3 Egress (to) firewall rules: ");
                is_l3 = true;
            }
            INGRESS_MAP_NAME => {
                println!("L3 Ingress (from) firewall rules: ");
                is_l3 = true;
            }
            EGRESS_L4_MAP_NAME => {
                println!("L4 Egress (to) firewall rules: ");
                is_l3 = false;
            }
            INGRESS_L4_MAP_NAME => {
                println!("L4 Ingress (from) firewall rules: ");
                is_l3 = false;
            }
            _ => unreachable!(),
        };
        let path = format!("{}/{}", ctn_dir, m);
        let map = Map::from_pinned_path(&path)?;

        for key in map.keys() {
            // print the key, the value is always 1 (true) here
            //let value = map.lookup(&key, MapFlags::ANY)?;
            //println!("  {:?}", value.unwrap())
            if is_l3 {
                println!("  - {}", u32_to_ipv4(&key)?);
            } else {
                println!("  - {}", u64_to_skt(&key)?);
            }
        }
        println!("");
    }

    Ok(())
}

/// Watch the container's ingress/egress network flow
pub fn follow(ctn_name: &str) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;
    prepare_ctn_dir(&ctn_id)?;

    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let data_flow_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, DATAFLOW_MAP_NAME))?;
    let key: [u8; 0] = [];

    // receive a signal periodically
    let ticker = tick(Duration::from_millis(1000));
    // receive a signal when pressing ctrl + c
    let cancel = ctrlc_chan().unwrap();
    println!("Tracking ... press Ctrl + c to quit");

    loop {
        select! {
            recv(ticker) -> _ => {
                while let Ok(value) = data_flow_map.lookup_and_delete(&key) {
                    match value {
                        Some(record) => {
                            println!("  {}", parse_pkt(&record).unwrap());
                        }
                        None => break,
                    }
                }
            }
            recv(cancel) -> _ => {
                println!("Ctrl-C signal caught, quit !");
                break;
            }
        }
    }

    Ok(())
}
