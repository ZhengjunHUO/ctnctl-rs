mod firewall {
    include!(concat!(env!("OUT_DIR"), "/cgroup_fw.skel.rs"));
}

use super::*;
use anyhow::{bail, Result};
use clap::Args;
use firewall::*;
use libbpf_rs::{Link, Map, MapFlags};
use std::net::Ipv4Addr;
use std::path::Path;

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

pub fn increase_rlimit() -> Result<()> {
    let rl = libc::rlimit {
        rlim_cur: 1 << 20,
        rlim_max: 1 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl) } != 0 {
        bail!("Error increasing rlimit");
    }

    Ok(())
}

pub fn prepare_ctn_dir(ctn_id: &str) -> Result<()> {
    use std::fs::create_dir;
    use std::os::fd::AsRawFd;

    // (1) Create dir for container
    let ctn_dir = get_ctn_bpf_path(ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if ctn_dir_path.is_dir() {
        // return if the dir is already there
        //println!("[DEBUG] Dir {:?} already exists.", ctn_dir_path);
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

    let ig_fw_map = maps.ingress_blacklist();
    ig_fw_map.pin(format!("{}/{}", &ctn_dir, INGRESS_MAP_NAME))?;

    let data_flow_map = maps.data_flow();
    data_flow_map.pin(format!("{}/{}", &ctn_dir, DATAFLOW_MAP_NAME))?;

    Ok(())
}

pub fn ipv4_to_u32(ip: &str) -> Result<[u8; 4]> {
    use std::str::FromStr;

    let ip_parsed = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(ip_parsed).to_be_bytes())
}

pub fn u32_to_ipv4(v: Vec<u8>) -> Result<String> {
    if v.len() != 4 {
        bail!("Unexpected key stored in the map: {:?}", v)
    }

    let ip = Ipv4Addr::from([v[0], v[1], v[2], v[3]]);
    Ok(ip.to_string())
}

fn get_all_maps() -> Vec<&'static str> {
    let mut v = get_rule_maps();
    v.push(DATAFLOW_MAP_NAME);
    v
}

fn get_rule_maps() -> Vec<&'static str> {
    vec![EGRESS_MAP_NAME, INGRESS_MAP_NAME]
}

fn get_ctn_bpf_path(ctn_id: &str) -> String {
    format!("{}/{}", BPF_PATH, ctn_id)
}

pub fn free_ctn_resources(ctn_name: &str) -> Result<()> {
    use std::fs::remove_dir;

    let ctn_id = get_ctn_id_from_name(&ctn_name)?;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir is already there
        //println!("[DEBUG] Dir {:?} already deleted.", ctn_dir_path);
        return Ok(());
    }

    let all_links = vec![EGRESS_LINK_NAME, INGRESS_LINK_NAME];
    let all_maps = get_all_maps();

    // if link is unpinned and map stays, the rules will not applied any more.
    for l in all_links {
        let path = format!("{}/{}", ctn_dir, l);
        let mut prog = Link::open(path)?;
        prog.unpin()?;
        println!("[DEBUG] Unpinned link {}", l);
    }

    // if map is unpinned and link stays, the rules is still in effect ?!
    for m in all_maps {
        let path = format!("{}/{}", ctn_dir, m);
        let mut map = Map::from_pinned_path(&path)?;
        map.unpin(&path)?;
        println!("[DEBUG] Unpinned map {}", m);
    }

    remove_dir(ctn_dir_path)?;

    Ok(())
}

pub fn show_rules(ctn_name: &str) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;

    //use libbpf_rs::MapFlags;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);

    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir doesn't exist
        println!("No rules applied to {}.", ctn_name);
        return Ok(());
    }

    let all_maps = get_rule_maps();
    for m in all_maps {
        match m {
            EGRESS_MAP_NAME => println!("Egress (to) firewall rules: "),
            INGRESS_MAP_NAME => println!("Ingress (from) firewall rules: "),
            _ => unreachable!(),
        };
        let path = format!("{}/{}", ctn_dir, m);
        let map = Map::from_pinned_path(&path)?;

        for key in map.keys() {
            // print the key, the value is always 1 (true) here
            //let value = map.lookup(&key, MapFlags::ANY)?;
            //println!("  {:?}", value.unwrap())

            println!("  - {}", u32_to_ipv4(key)?)
        }
        println!("");
    }
    Ok(())
}

pub fn get_ctn_id_from_name(ctn_name: &str) -> Result<String> {
    use docker_api::opts::{ContainerFilter, ContainerListOpts};
    use docker_api::Docker;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();
    let docker = Docker::new("unix:///var/run/docker.sock").unwrap();

    rt.block_on(async {
        match docker
            .containers()
            .list(
                &ContainerListOpts::builder()
                    .filter(vec![ContainerFilter::Name(ctn_name.to_string())])
                    .build(),
            )
            .await
        {
            Ok(ctns) => {
                if ctns.len() < 1 {
                    bail!("Container {} not found !", ctn_name);
                }

                let ctn_id = ctns[0].id.clone().unwrap();
                Ok(ctn_id)
            }
            Err(e) => bail!("Error retrieving container {}'s ID: {}", ctn_name, e),
        }
    })
}

pub fn update_rule(ctn_name: &str, direction: &Direction, is_block: bool) -> Result<()> {
    // Create a folder and store the pinned maps for the container if not exist yet
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;

    if is_block {
        prepare_ctn_dir(&ctn_id)?;
    }

    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);

    if !is_block && !ctn_dir_path.try_exists()? {
        // return if the dir doesn't exist
        println!("No rules applied to {}.", ctn_name);
        return Ok(());
    }

    match (&direction.to, &direction.from) {
        (Some(eg), None) => {
            // Open the pinned map for egress rules inside the container's folder
            let eg_fw_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, EGRESS_MAP_NAME))?;

            // Apply the firewall rule
            let key = ipv4_to_u32(&eg)?;
            if is_block {
                let value = u8::from(true).to_ne_bytes();
                eg_fw_map.update(&key, &value, MapFlags::ANY)?;
            } else {
                eg_fw_map.lookup_and_delete(&key)?;
            }
        }
        (None, Some(ing)) => {
            // Open the pinned map for ingress rules inside the container's folder
            let ig_fw_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, INGRESS_MAP_NAME))?;

            // Apply the firewall rule
            let key = ipv4_to_u32(&ing)?;
            if is_block {
                let value = u8::from(true).to_ne_bytes();
                ig_fw_map.update(&key, &value, MapFlags::ANY)?;
            } else {
                ig_fw_map.lookup_and_delete(&key)?;
            }
        }
        _ => unreachable!(),
    };

    Ok(())
}

pub fn follow(ctn_name: &str) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;
    prepare_ctn_dir(&ctn_id)?;

    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let _data_flow_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, DATAFLOW_MAP_NAME))?;
    println!("Tracking ... press Ctrl + c to quit");

    Ok(())
}
