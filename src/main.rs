use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use ctnctl_rs::utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: Commands,

    #[arg(global = true, required = false)]
    container_name: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add IP to container's blacklist
    Block {
        #[command(flatten)]
        direction: utils::Direction,
    },
    /// Remove IP from container's blacklist
    Unblock {
        #[command(flatten)]
        direction: utils::Direction,
    },
    /// Print firewall rules applied to container
    Show,
    /// Remove container's all firewall rules
    Clear,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctn_name;

    // strange that the if argument is global in clap, the required should be false
    // a workaround to make it required
    match cli.container_name {
        Some(name) => ctn_name = name,
        None => {
            let mut cmmd = Cli::command();
            cmmd.error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "<CONTAINER_NAME> is required",
            )
            .exit();
        }
    }

    match &cli.subcommand {
        Commands::Block { direction } => {
            utils::update_rule(&ctn_name, &direction, true)?;
        }
        Commands::Unblock { direction } => {
            utils::update_rule(&ctn_name, &direction, false)?;
        }
        Commands::Show => {
            utils::show_rules(&ctn_name)?;
        }
        Commands::Clear => {
            utils::free_ctn_resources(&ctn_name)?;
        }
    }
    Ok(())
}
