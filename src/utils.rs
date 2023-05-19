mod firewall {
    include!(concat!(env!("OUT_DIR"), "/cgroup_fw.skel.rs"));
}

use super::{BPF_PATH, EGRESS_LINK_NAME, EGRESS_MAP_NAME};
use anyhow::{bail, Result};
use firewall::*;
use libbpf_rs::{Link, Map};
use std::os::fd::AsRawFd;
use std::path::Path;

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

    // (1) Create dir for container
    let ctn_dir = format!("{}/{}", BPF_PATH, ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if ctn_dir_path.is_dir() {
        // return if the dir is already there
        println!("[DEBUG] Dir {:?} already exists.", ctn_dir_path);
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

    // (2.b) Get loaded maps and pin to the fs
    let mut maps = obj.maps_mut();
    let eg_fw_map = maps.egress_blacklist();
    // Persist the map on bpf vfs
    eg_fw_map.pin(format!("{}/{}", &ctn_dir, EGRESS_MAP_NAME))?;

    Ok(())
}

pub fn ipv4_to_u32(ip: &str) -> Result<[u8; 4]> {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let ip_parsed = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(ip_parsed).to_be_bytes())
}

pub fn free_ctn_resources(ctn_id: &str) -> Result<()> {
    use std::fs::remove_dir;

    let ctn_dir = format!("{}/{}", BPF_PATH, ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir is already there
        println!("[DEBUG] Dir {:?} already deleted.", ctn_dir_path);
        return Ok(());
    }

    let all_links = vec![EGRESS_LINK_NAME];
    let all_maps = vec![EGRESS_MAP_NAME];

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
