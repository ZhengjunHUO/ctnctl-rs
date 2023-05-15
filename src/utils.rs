use anyhow::{bail, Result};
use std::os::fd::{AsRawFd, RawFd};

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

pub fn get_ctn_cgroup_fd(ctn_id: &str) -> Result<RawFd> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(format!(
            "/sys/fs/cgroup/system.slice/docker-{}.scope",
            ctn_id
        ))?;
    Ok(f.as_raw_fd())
}

pub fn ipv4_to_u32(ip: &str) -> Result<[u8; 4]> {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    let ip_parsed = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(ip_parsed).to_be_bytes())
}
