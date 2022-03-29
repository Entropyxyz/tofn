use crate::sdk::api::PartyShareCounts;
use chrono::{Datelike, Timelike, Utc};
use clap::{Args, Parser, Result, Subcommand};
use k256::SecretKey;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

pub(crate) const CEYGEN_CLI_OUTPUT_DIRECTORY: &str = "CEYGEN_KEYS";

/// CLI, mostly for debugging and local key generation
#[derive(Parser, Debug)]
#[clap(name = "tofn")]
#[clap(about = "A driver to test the Entropy fork of the tofn library")]
#[clap(version, long_about = None)]
struct Cli {
    /// Name of the person to greet
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Ceygen(CeygenCli),
    Sign(SignCli),
}

#[derive(Debug, Args)]
struct CeygenCli {
    /// parties participating; Note: parties >= threshold + 1
    #[clap(short = 'p', long = "parties")]
    parties: usize,
    /// t+1 parties required to participate to produce a signature
    #[clap(short = 't', long = "threshold")]
    threshold: usize,
    /// Big endian integer array of Alice's secret_key.
    /// If no key given, a random key is generated.
    #[clap(short = 'k', long = "alice_key")]
    alice_key_byte_array: Option<Vec<u8>>,
    #[clap(short = 'o', long = "output_directory")]
    output_dir: Option<String>,
}

#[derive(Debug, Args)]
struct SignCli {}

pub fn main() -> Result<()> {
    let args = Cli::parse();
    match &args.command {
        Commands::Ceygen(cli) => ceygen(cli),
        Commands::Sign(cli) => sign(cli),
    }
}

fn ceygen(cli: &CeygenCli) -> Result<()> {
    let alice_key = match &cli.alice_key_byte_array {
        Some(v) => SecretKey::from_bytes(v).unwrap(),
        None => SecretKey::random(rand::thread_rng()),
    }
    .as_scalar_bytes()
    .to_scalar();
    let party_share_counts = PartyShareCounts::from_vec(vec![1; cli.parties]).unwrap();

    let secret_key_shares = crate::gg20::ceygen::initialize_honest_parties(
        &party_share_counts,
        cli.threshold,
        alice_key,
    );

    let output_dir = if let Some(output_dir) = cli.output_dir.as_ref() {
        output_dir.clone()
    } else {
        let now = Utc::now();
        let timestamp = format!(
            "{}{}{}:{}{}{}",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        format!("./{}_{}", CEYGEN_CLI_OUTPUT_DIRECTORY, timestamp).to_string()
    };

    let path = Path::new(&output_dir);
    fs::create_dir(path)?;

    for (index, share) in secret_key_shares.iter().enumerate() {
        // write to path
        let filepath = format!("{}/{}", output_dir, index);
		let contents = serde_json::to_string(&share).unwrap();
        fs::write(Path::new(&filepath), contents)?;
    }

    info!(
        "ceygen generated {}-of-{} keys.\nWrote to location: {}",
        cli.threshold, cli.parties, output_dir
    );
    Ok(())
}

fn sign(cli: &SignCli) -> Result<()> {
    todo!();
}
