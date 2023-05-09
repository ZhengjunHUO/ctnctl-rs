use clap::{Parser, Subcommand};

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

fn main() {
    let cli = Cli::parse();
    match &cli.subcommand {
        Commands::Block { egress, container_name } => {
            println!("block -e {:?} {:?}", egress, container_name)
        },
        Commands::Clear { container_name } => {
            println!("clear {:?}", container_name)
        },
    }
    println!("Done")
}
