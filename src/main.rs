use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use ctnctl_rs::{utils, BPF_PATH, EGRESS_MAP_NAME, INGRESS_MAP_NAME};
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
    /// Add IP to container's blacklist
    Block {
        #[command(flatten)]
        direction: Direction,
        container_name: String,
    },
    /// Print firewall rules applied to container
    Show { container_name: String },
    /// Remove container's all firewall rules
    Clear { container_name: String },
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Direction {
    /// Disallow container to visit an external IP
    #[clap(long, value_name = "IP")]
    to: Option<String>,

    /// Prevent remote IP from visiting container
    #[clap(long, value_name = "IP")]
    from: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.subcommand {
        Commands::Block {
            direction,
            container_name,
        } => {
            // Create a folder and store the pinned maps for the container if not exist yet
            let id = utils::get_ctn_id_from_name(&container_name)?;
            utils::prepare_ctn_dir(&id)?;

            match (&direction.to, &direction.from) {
                (Some(eg), None) => {
                    //println!("[DEBUG] egress {:?}", eg);

                    // Open the pinned map for egress rules inside the container's folder
                    let eg_fw_map =
                        Map::from_pinned_path(format!("{}/{}/{}", BPF_PATH, &id, EGRESS_MAP_NAME))?;

                    // Apply the firewall rule
                    let key = utils::ipv4_to_u32(&eg)?;
                    let value = u8::from(true).to_ne_bytes();
                    eg_fw_map.update(&key, &value, MapFlags::ANY)?;
                }
                (None, Some(ing)) => {
                    //println!("[DEBUG] igress {:?}", ing);

                    // Open the pinned map for ingress rules inside the container's folder
                    let ig_fw_map = Map::from_pinned_path(format!(
                        "{}/{}/{}",
                        BPF_PATH, &id, INGRESS_MAP_NAME
                    ))?;

                    // Apply the firewall rule
                    let key = utils::ipv4_to_u32(&ing)?;
                    let value = u8::from(true).to_ne_bytes();
                    ig_fw_map.update(&key, &value, MapFlags::ANY)?;
                }
                _ => unreachable!(),
            };
        }
        Commands::Show { container_name } => {
            let id = utils::get_ctn_id_from_name(&container_name)?;
            utils::show_rules(&id)?;
        }
        Commands::Clear { container_name } => {
            let id = utils::get_ctn_id_from_name(&container_name)?;
            utils::free_ctn_resources(&id)?;
        }
    }
    println!("[DEBUG] Done");
    Ok(())
}
