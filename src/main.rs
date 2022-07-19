use bincode::Options;
use clap::{Args, Parser, Subcommand};
use ecdsa::{elliptic_curve::sec1::FromEncodedPoint, hazmat::VerifyPrimitive};
use rand::Rng;
use std::{
    convert::TryFrom,
    fs,
    path::{Path, PathBuf},
};
use tofn::{
    collections::{TypedUsize, VecMap},
    crypto_tools::message_digest::MessageDigest,
    gg20::{
        keygen::{KeygenPartyId, KeygenShareId, SecretKeyShare},
        sign::{new_sign, SignParties, SignShareId},
    },
    sdk::api::{PartyShareCounts, Protocol},
};
use tracing::info;

use self::execute::execute_protocol;

pub(crate) const PARTY_SHARE_COUNTS_FILE: &str = "party_share_counts";

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
    dir: Option<String>,
}

#[derive(Debug, Args)]
struct SignCli {
    /// Directory where keys are stored
    #[clap(short = 'd', long = "directory")]
    dir: String,
    /// Parties to use for signing; Eg if signing with parties 0,1,3, use -p 0 -p 1 -p 3
    #[clap(short = 'p', long = "parties", required = true)]
    parties: Vec<usize>,
    /// 32 byte array to sign, default to [42;32]
    #[clap(short = 'm', long = "msg_digest")]
    msg_digest: Option<String>,
}

pub fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    match args.command {
        Commands::Ceygen(cli) => ceygen(cli),
        Commands::Sign(cli) => sign(cli),
    }
}

/// Use `alice_key` to generate `threshold` of `parties` shares, write to directory `dir`.
fn ceygen(cli: CeygenCli) -> anyhow::Result<()> {
    // generate a random key if none provided.
    let alice_key: Vec<u8> = cli.alice_key_byte_array.unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        std::iter::repeat(rng.gen_range(0..=255)).take(32).collect()
    });
    let ceygen = tofn::gg20::ceygen::ceygen(cli.parties, cli.threshold, alice_key)?;
    tofn::gg20::ceygen::write_ceygen_results(ceygen, cli.dir.map(PathBuf::from))?;
    Ok(())
}

/// Read keys `key_array` from `dir` and sign message `msg_digest`.
fn sign(cli: SignCli) -> anyhow::Result<()> {
    // read data from keygen directory

    let bincode = bincode::DefaultOptions::new();
    let v_serialized = fs::read(Path::new(&format!(
        "{}/{}",
        cli.dir, PARTY_SHARE_COUNTS_FILE
    )))
    .unwrap();
    let party_share_counts: PartyShareCounts<KeygenPartyId> =
        bincode.deserialize(&v_serialized).unwrap();

    let secret_key_shares: VecMap<KeygenShareId, SecretKeyShare> = cli
        .parties
        .iter()
        .map(|index| {
            let bincode = bincode::DefaultOptions::new();
            let v_serialized = fs::read(Path::new(&format!("{}/{}", cli.dir, index))).unwrap();
            bincode.deserialize(&v_serialized).unwrap()
        })
        .collect();

    // sign
    let sign_parties = {
        let mut sign_parties = SignParties::with_max_size(party_share_counts.party_count());
        for i in &cli.parties {
            sign_parties
                .add(TypedUsize::from_usize(*i as usize))
                .unwrap();
        }
        sign_parties
    };

    let keygen_share_ids = VecMap::<SignShareId, _>::from_vec(
        party_share_counts.share_id_subset(&sign_parties).unwrap(),
    );
    let msg_digest = match cli.msg_digest.as_ref() {
        Some(s) => hex::decode(s).expect("Decoding failed"),
        None => vec![42; 32],
    };
    let msg_to_sign = MessageDigest::try_from(&*msg_digest).unwrap();
    let sign_shares = keygen_share_ids.map(|keygen_share_id| {
        let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
        new_sign(
            secret_key_share.group(),
            secret_key_share.share(),
            &sign_parties,
            &msg_to_sign,
            #[cfg(feature = "malicious")]
            sign::malicious::Behaviour::Honest,
        )
        .unwrap()
    });
    let sign_share_outputs = execute_protocol(sign_shares).unwrap();
    let signatures = sign_share_outputs.map(|output| match output {
        Protocol::NotDone(_) => panic!("sign share not done yet"),
        Protocol::Done(result) => result.expect("sign share finished with error"),
    });

    // grab pubkey bytes from one of the shares
    let pubkey_bytes = secret_key_shares
        .get(TypedUsize::from_usize(0))
        .unwrap()
        .group()
        .encoded_pubkey();

    // verify a signature
    let pubkey = k256::AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(pubkey_bytes).unwrap(),
    )
    .unwrap();
    let sig = k256::ecdsa::Signature::from_der(signatures.get(TypedUsize::from_usize(0)).unwrap())
        .unwrap();
    assert!(pubkey
        .verify_prehashed(k256::Scalar::from(&msg_to_sign), &sig)
        .is_ok());

    info!(
        "message: {:?} successfully signed by parties: {:?}",
        msg_to_sign, cli.parties
    );
    Ok(())
}

mod execute {
    //! Single-threaded generic protocol execution
    // copy pasted from tests/single_thread/execute.rs

    use tofn::{
        collections::{HoleVecMap, TypedUsize, VecMap},
        sdk::api::{BytesVec, Protocol, TofnResult},
    };
    use tracing::{debug, warn};

    pub fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
        mut parties: VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
    ) -> TofnResult<VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>>
    where
        K: Clone,
    {
        let mut current_round = 0;
        while nobody_done(&parties) {
            current_round += 1;
            parties = next_round(parties, current_round)?;
        }
        Ok(parties)
    }

    pub fn nobody_done<F, K, P, const MAX_MSG_IN_LEN: usize>(
        parties: &VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
    ) -> bool {
        // warn if there's disagreement
        let (mut done, mut not_done) = (
            Vec::with_capacity(parties.len()),
            Vec::with_capacity(parties.len()),
        );
        for (i, party) in parties.iter() {
            if matches!(party, Protocol::Done(_)) {
                done.push(i);
            } else {
                not_done.push(i);
            }
        }
        if !done.is_empty() && !not_done.is_empty() {
            warn!(
                "disagreement: done parties {:?}, not done parties {:?}",
                done, not_done
            );
        }
        done.is_empty()
    }

    fn next_round<F, K, P, const MAX_MSG_IN_LEN: usize>(
        parties: VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>,
        current_round: usize,
    ) -> TofnResult<VecMap<K, Protocol<F, K, P, MAX_MSG_IN_LEN>>>
    where
        K: Clone,
    {
        // extract current round from parties
        let mut rounds: VecMap<K, _> = parties
            .into_iter()
            .map(|(i, party)| match party {
                Protocol::NotDone(round) => round,
                Protocol::Done(_) => panic!("next_round called but party {} is done", i),
            })
            .collect();

        // deliver bcasts
        let bcasts: VecMap<K, Option<BytesVec>> = rounds
            .iter()
            .map(|(_, round)| round.bcast_out().cloned())
            .collect();
        for (from, bcast) in bcasts.into_iter() {
            if let Some(bytes) = bcast {
                if from.as_usize() == 0 {
                    debug!("round {} bcast byte length {}", current_round, bytes.len());
                }

                for (_, round) in rounds.iter_mut() {
                    round.msg_in(
                        round
                            .info()
                            .party_share_counts()
                            .share_to_party_id(from)
                            .unwrap(),
                        &bytes,
                    )?;
                }
            }
        }

        // deliver p2ps
        let all_p2ps: VecMap<K, Option<HoleVecMap<K, BytesVec>>> = rounds
            .iter()
            .map(|(_, round)| round.p2ps_out().cloned())
            .collect();
        for (from, p2ps) in all_p2ps.into_iter() {
            if let Some(p2ps) = p2ps {
                if from.as_usize() == 0 {
                    debug!(
                        "round {} p2p byte length {}",
                        current_round,
                        p2ps.get(TypedUsize::from_usize(1)).unwrap().len()
                    );
                }
                for (_, bytes) in p2ps {
                    for (_, round) in rounds.iter_mut() {
                        round.msg_in(
                            round
                                .info()
                                .party_share_counts()
                                .share_to_party_id(from)
                                .unwrap(), // no easy access to from_party_id
                            &bytes,
                        )?;
                    }
                }
            }
        }

        // compute next round's parties
        rounds
            .into_iter()
            .map(|(i, round)| {
                if round.expecting_more_msgs_this_round() {
                    warn!(
                        "all messages delivered this round but party {} still expecting messages",
                        i,
                    );
                }
                round.execute_next_round()
            })
            .collect::<TofnResult<_>>()
    }
}
