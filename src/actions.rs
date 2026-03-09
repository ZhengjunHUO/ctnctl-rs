mod firewall {
    include!("cgroup_fw.skel.rs");
}

use super::*;
use crate::rule::*;
use crate::sys::*;
use crate::utils::*;
use anyhow::{bail, Result};
use clap::Args;
use crossbeam_channel::{select, tick};
use firewall::*;
use libbpf_rs::{Link, Map, MapFlags, TcHook, TcHookBuilder, TC_EGRESS, TC_INGRESS};
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

/// Check if the bpf dir already exists and whether it was set up with a different hook mode
fn check_mode_conflict(ctn_id: &str, ctn_dir: &str, use_tc: bool) -> Result<bool> {
    let ctn_dir_path = Path::new(ctn_dir);
    if !ctn_dir_path.is_dir() {
        return Ok(false);
    }

    let tc_meta_path = format!("{}/{}", get_tc_meta_dir(ctn_id), TC_META_NAME);
    let has_tc_meta = Path::new(&tc_meta_path).exists();

    if use_tc && !has_tc_meta {
        bail!(
            "Container already has cgroup_skb hooks. Run 'clear' first before switching to TC mode."
        );
    }
    if !use_tc && has_tc_meta {
        bail!("Container already has TC hooks. Run 'clear' first before switching to cgroup mode.");
    }

    // Same mode, dir already exists
    debug!("Dir {:?} already exists.", ctn_dir_path);
    Ok(true)
}

/// Pin all BPF maps to the container's bpf directory
fn pin_maps(obj: &mut CgroupFwSkel<'_>, ctn_dir: &str) -> Result<()> {
    let mut maps = obj.maps_mut();

    maps.egress_blacklist()
        .pin(format!("{}/{}", ctn_dir, EGRESS_MAP_NAME))?;
    maps.egress_l4_blacklist()
        .pin(format!("{}/{}", ctn_dir, EGRESS_L4_MAP_NAME))?;
    maps.ingress_blacklist()
        .pin(format!("{}/{}", ctn_dir, INGRESS_MAP_NAME))?;
    maps.ingress_l4_blacklist()
        .pin(format!("{}/{}", ctn_dir, INGRESS_L4_MAP_NAME))?;
    maps.data_flow()
        .pin(format!("{}/{}", ctn_dir, DATAFLOW_MAP_NAME))?;

    Ok(())
}

/// Create a directory in bpf's pseudo file system and attach cgroup_skb programs
fn prepare_ctn_dir(ctn_id: &str) -> Result<()> {
    use std::fs::create_dir;
    use std::os::fd::AsRawFd;

    let ctn_dir = get_ctn_bpf_path(ctn_id);
    if check_mode_conflict(ctn_id, &ctn_dir, false)? {
        return Ok(());
    }

    create_dir(Path::new(&ctn_dir))?;

    // Load bpf programs and maps
    let builder = CgroupFwSkelBuilder::default();
    increase_rlimit()?;
    let open = builder.open()?;
    let mut obj = open.load()?;

    // Get target cgroup fd
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(format!(
            "/sys/fs/cgroup/system.slice/docker-{}.scope",
            ctn_id
        ))?;
    let cgroup_fd = f.as_raw_fd();

    // Attach programs to the cgroup, then pin to the fs
    let mut eg_link = obj.progs_mut().egress_filter().attach_cgroup(cgroup_fd)?;
    eg_link.pin(format!("{}/{}", &ctn_dir, EGRESS_LINK_NAME))?;

    let mut ig_link = obj.progs_mut().ingress_filter().attach_cgroup(cgroup_fd)?;
    ig_link.pin(format!("{}/{}", &ctn_dir, INGRESS_LINK_NAME))?;

    // Pin maps
    pin_maps(&mut obj, &ctn_dir)?;

    Ok(())
}

/// Create a directory in bpf's pseudo file system and attach TC programs to host-side veth
fn prepare_ctn_dir_tc(ctn_id: &str) -> Result<()> {
    use std::fs::{create_dir, write};

    let ctn_dir = get_ctn_bpf_path(ctn_id);
    if check_mode_conflict(ctn_id, &ctn_dir, true)? {
        return Ok(());
    }

    create_dir(Path::new(&ctn_dir))?;

    // Load bpf programs and maps
    let builder = CgroupFwSkelBuilder::default();
    increase_rlimit()?;
    let open = builder.open()?;
    let mut obj = open.load()?;

    // Get the host-side veth ifindex for the container
    let ifindex = get_ctn_ifindex(ctn_id)?;
    let fd = obj.progs().tc_filter().fd();

    // Create clsact qdisc and attach TC hooks for both directions
    let mut builder = TcHookBuilder::new();
    builder.fd(fd).ifindex(ifindex);

    let mut ingress_hook = builder.hook(TC_INGRESS);
    ingress_hook.create()?;
    ingress_hook.attach()?;
    debug!("Attached TC ingress hook on ifindex {}", ifindex);

    let mut egress_hook = builder.hook(TC_EGRESS);
    egress_hook.create()?;
    egress_hook.attach()?;
    debug!("Attached TC egress hook on ifindex {}", ifindex);

    // Pin maps (same names as cgroup mode)
    pin_maps(&mut obj, &ctn_dir)?;

    // Save ifindex as tc_meta marker for cleanup
    // bpffs only supports pinned BPF objects, so store metadata on a regular fs
    let meta_dir = get_tc_meta_dir(ctn_id);
    std::fs::create_dir_all(&meta_dir)?;
    write(
        format!("{}/{}", &meta_dir, TC_META_NAME),
        ifindex.to_string(),
    )?;

    Ok(())
}

/// Remove container's related resources from bpf's pseudo file system
/// Auto-detects whether the container uses TC or cgroup mode
pub fn free_ctn_resources(ctn_name: &str) -> Result<()> {
    use std::fs::{read_to_string, remove_dir, remove_dir_all, remove_file};

    let ctn_id = get_ctn_id_from_name(ctn_name)?;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        debug!("Dir {:?} already deleted.", ctn_dir_path);
        return Ok(());
    }

    let meta_dir = get_tc_meta_dir(&ctn_id);
    let tc_meta_path = format!("{}/{}", meta_dir, TC_META_NAME);
    let is_tc = Path::new(&tc_meta_path).exists();

    if is_tc {
        // TC mode: destroy the clsact qdisc (detaches all hooks)
        let ifindex_str = read_to_string(&tc_meta_path)?;
        let ifindex: i32 = ifindex_str.trim().parse()?;

        let mut hook = TcHook::new(0);
        hook.ifindex(ifindex).attach_point(TC_INGRESS | TC_EGRESS);
        match hook.destroy() {
            Ok(()) => debug!("Destroyed TC clsact qdisc on ifindex {}", ifindex),
            Err(e) => debug!("TC destroy (interface may be gone): {}", e),
        }

        remove_dir_all(&meta_dir)?;
        debug!("Removed tc_meta dir");
    } else {
        // Cgroup mode: unpin links
        let all_links = vec![EGRESS_LINK_NAME, INGRESS_LINK_NAME];
        for l in all_links {
            let path = format!("{}/{}", ctn_dir, l);
            let mut prog = Link::open(path)?;
            prog.unpin()?;
            debug!("Unpinned link {}", l);
        }
    }

    // Unpin maps (same for both modes)
    let all_maps = get_all_maps();
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
    use_tc: bool,
) -> Result<()> {
    // Create a folder and store the pinned maps for the container if not exist yet
    let ctn_id = get_ctn_id_from_name(ctn_name)?;

    if is_block {
        if use_tc {
            prepare_ctn_dir_tc(&ctn_id)?;
        } else {
            prepare_ctn_dir(&ctn_id)?;
        }
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
            builder = builder.ip(eg);
        }
        (None, Some(ing)) => {
            builder.is_ingress = true;
            builder = builder.ip(ing);
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
    let ctn_id = get_ctn_id_from_name(ctn_name)?;

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
        println!();
    }

    Ok(())
}

/// Watch the container's ingress/egress network flow
pub fn follow(ctn_name: &str, use_tc: bool) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(ctn_name)?;
    if use_tc {
        prepare_ctn_dir_tc(&ctn_id)?;
    } else {
        prepare_ctn_dir(&ctn_id)?;
    }

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
