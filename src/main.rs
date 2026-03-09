use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use ctnctl_rs::actions;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: Commands,

    /// Use TC hook instead of cgroup_skb (attaches to host-side veth)
    #[arg(long, global = true, default_value_t = false)]
    tc: bool,

    #[arg(global = true, required = false)]
    container_name: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add IP to container's blacklist
    Block {
        #[command(flatten)]
        direction: actions::Direction,
        #[command(flatten)]
        protocol: actions::Protocol,
    },
    /// Remove IP from container's blacklist
    Unblock {
        #[command(flatten)]
        direction: actions::Direction,
        #[command(flatten)]
        protocol: actions::Protocol,
    },
    /// Print firewall rules applied to container
    Show,
    /// Remove container's all firewall rules
    Clear,
    /// Track container's network package flow
    Follow,
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    // strange that the if argument is global in clap, the required should be false
    // a workaround to make it required
    let ctn_name = match cli.container_name {
        Some(name) => name,
        None => {
            let mut cmmd = Cli::command();
            cmmd.error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "<CONTAINER_NAME> is required",
            )
            .exit();
        }
    };

    let use_tc = cli.tc;

    match &cli.subcommand {
        Commands::Block {
            direction,
            protocol,
        } => {
            actions::update_rule(&ctn_name, direction, protocol, true, use_tc)?;
        }
        Commands::Unblock {
            direction,
            protocol,
        } => {
            actions::update_rule(&ctn_name, direction, protocol, false, use_tc)?;
        }
        Commands::Show => {
            actions::show_rules(&ctn_name)?;
        }
        Commands::Clear => {
            actions::free_ctn_resources(&ctn_name)?;
        }
        Commands::Follow => {
            actions::follow(&ctn_name, use_tc)?;
        }
    }
    Ok(())
}
