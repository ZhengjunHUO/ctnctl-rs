mod firewall {
    include!(concat!(env!("OUT_DIR"), "/cgroup_fw.skel.rs"));
}

use anyhow::Result;
use clap::{Parser, Subcommand};
use ctnctl_rs::utils;
use firewall::*;
use libbpf_rs::MapFlags;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::str::FromStr;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Block {
        #[clap(short, long)]
        egress: String,
        container_name: String,
    },
    Clear {
        container_name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.subcommand {
        Commands::Block {
            egress,
            container_name,
        } => {
            println!("[DEBUG] block -e {:?} {:?}", egress, container_name);

            let builder = CgroupFwSkelBuilder::default();
            utils::increase_rlimit()?;
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
                    container_name
                ))?;
            let cgroup_fd = f.as_raw_fd();

            // Get loaded program and attach to the cgroup
            let mut eg_link = obj.progs_mut().egress_filter().attach_cgroup(cgroup_fd)?;
            // The prog_type and attach_type are inferred from the c program
            // should be CgroupInetEgress here
            //println!("[DEBUG]: Attach type is {:?}", obj.progs().egress_filter().attach_type());
            eg_link.pin("/sys/fs/bpf/cgroup_egs_link")?;

            // Get loaded map
            let mut maps = obj.maps_mut();
            let eg_fw_map = maps.egress_blacklist();

            // Persist the map on bpf vfs
            eg_fw_map.pin("/sys/fs/bpf/cgroup_egs_map")?;

            // Apply a rule
            let ip_parsed = Ipv4Addr::from_str(&egress)?;
            let key = u32::from(ip_parsed).to_be_bytes();
            let value = u8::from(true).to_ne_bytes();
            eg_fw_map.update(&key, &value, MapFlags::ANY)?;
        }
        Commands::Clear { container_name } => {
            println!("[DEBUG] clear {:?}", container_name)
        }
    }
    println!("Done");
    Ok(())
}
