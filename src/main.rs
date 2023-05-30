use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use ctnctl_rs::actions;

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
        direction: actions::Direction,
    },
    /// Remove IP from container's blacklist
    Unblock {
        #[command(flatten)]
        direction: actions::Direction,
    },
    /// Print firewall rules applied to container
    Show,
    /// Remove container's all firewall rules
    Clear,
    /// Track container's network package flow
    Follow,
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
            actions::update_rule(&ctn_name, &direction, true)?;
        }
        Commands::Unblock { direction } => {
            actions::update_rule(&ctn_name, &direction, false)?;
        }
        Commands::Show => {
            actions::show_rules(&ctn_name)?;
        }
        Commands::Clear => {
            actions::free_ctn_resources(&ctn_name)?;
        }
        Commands::Follow => {
            actions::follow(&ctn_name)?;
        }
    }
    Ok(())
}
