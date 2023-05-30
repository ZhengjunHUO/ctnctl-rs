mod firewall {
    include!("cgroup_fw.skel.rs");
}

use super::*;
use crate::sys::*;
use anyhow::{bail, Result};
use firewall::*;
use std::net::Ipv4Addr;
use std::path::Path;

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

pub fn get_all_maps() -> Vec<&'static str> {
    let mut v = get_rule_maps();
    v.push(DATAFLOW_MAP_NAME);
    v
}

pub fn get_rule_maps() -> Vec<&'static str> {
    vec![EGRESS_MAP_NAME, INGRESS_MAP_NAME]
}

pub fn get_ctn_bpf_path(ctn_id: &str) -> String {
    format!("{}/{}", BPF_PATH, ctn_id)
}
