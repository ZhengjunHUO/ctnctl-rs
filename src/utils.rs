mod firewall {
    include!(concat!(env!("OUT_DIR"), "/cgroup_fw.skel.rs"));
}

use anyhow::{bail, Result};
use firewall::*;
use std::os::fd::AsRawFd;

const BPF_PATH: &str = "/sys/fs/bpf";

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
    use std::{fs::create_dir, path::Path};

    // (1) Create dir for container
    let ctn_dir = format!("{}/{}", BPF_PATH, ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if ctn_dir_path.is_dir() {
        // return if the dir is already there
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
    println!("[DEBUG] file descriptor: {:?}", cgroup_fd);

    // (2.a) Get loaded programs and attach to the cgroup, then pin to the fs
    let mut eg_link = obj.progs_mut().egress_filter().attach_cgroup(cgroup_fd)?;
    // The prog_type and attach_type are inferred from the c program
    // should be CgroupInetEgress here
    //println!("[DEBUG]: Attach type is {:?}", obj.progs().egress_filter().attach_type());
    eg_link.pin(format!("{}/{}", &ctn_dir, "cgroup_egs_link"))?;

    // (2.b) Get loaded maps and pin to the fs
    let mut maps = obj.maps_mut();
    let eg_fw_map = maps.egress_blacklist();
    // Persist the map on bpf vfs
    eg_fw_map.pin(format!("{}/{}", &ctn_dir, "cgroup_egs_map"))?;

    Ok(())
}

pub fn ipv4_to_u32(ip: &str) -> Result<[u8; 4]> {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let ip_parsed = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(ip_parsed).to_be_bytes())
}
