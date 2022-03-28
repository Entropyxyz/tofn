// use std::ffi::OsString;
// use std::path::PathBuf;
use clap::{Parser, Subcommand, Args};

/// CLI, mostly for debugging and local key generation
#[derive(Parser, Debug)]
#[clap(name = "tofn")]
#[clap(about = "A driver to test the Entropy fork of the tofn library")]
#[clap(version, long_about = None)]
struct Cli{
    /// Name of the person to greet
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand,Debug)]
enum Commands{
	Ceygen(CeygenCli),
	Sign(SignCli),
}

#[derive(Debug, Args)]
struct SignCli{}

#[derive(Debug, Args)]
struct CeygenCli{}

fn main(){
	let args = Cli::parse();
	match &args.command{
		Commands::Ceygen(keygen_cli)=> todo!(),
		Commands::Sign(sign_cli)=> todo!(),
	}


}
