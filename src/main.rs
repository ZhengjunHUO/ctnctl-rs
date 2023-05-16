use anyhow::Result;
use clap::{Parser, Subcommand};
use ctnctl_rs::utils;
use libbpf_rs::{Map, MapFlags};

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

            // Create a folder and store the pinned maps for the container if not exist yet
            utils::prepare_ctn_dir(&container_name)?;

            // Open the pinned map for egress rules inside the container's folder
            let eg_fw_map = Map::from_pinned_path(format!(
                "{}/{}/{}",
                "/sys/fs/bpf", &container_name, "cgroup_egs_map"
            ))?;

            // Apply the firewall rule
            let key = utils::ipv4_to_u32(&egress)?;
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
