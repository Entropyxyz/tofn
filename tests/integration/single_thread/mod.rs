use core::convert::TryFrom;

use crate::common;
use ecdsa::hazmat::VerifyPrimitive;
use execute::*;
use k256::PublicKey;
use tofn::{
    collections::{TypedUsize, VecMap},
    gg20::{
        keygen,
        sign::{new_sign, MessageDigest, SignParties, SignShareId},
    },
    sdk::api::{PartyShareCounts, Protocol},
};

#[cfg(feature = "malicious")]
use tofn::gg20::sign;
use tracing::debug;

// use test_env_log::test;
// use tracing_test::traced_test; // enable logs in tests

fn set_up_logs() {
    // set up environment variable for log level
    // set up an event subscriber for logs
    let _ = tracing_subscriber::fmt()
        // .with_env_filter("tofnd=info,[Keygen]=info")
        .with_max_level(tracing::Level::DEBUG)
        // .json()
        // .with_ansi(atty::is(atty::Stream::Stdout))
        // .without_time()
        // .with_target(false)
        // .with_current_span(false)
        .try_init();
}
/// A simple test to illustrate use of the library
#[test]
// #[traced_test]
fn basic_correctness() {
    set_up_logs();

    // keygen
    let party_share_counts = PartyShareCounts::from_vec(vec![1, 2, 3, 4]).unwrap(); // 10 total shares
    let threshold = 5;
    let sign_parties = {
        let mut sign_parties = SignParties::with_max_size(party_share_counts.party_count());
        sign_parties.add(TypedUsize::from_usize(0)).unwrap();
        sign_parties.add(TypedUsize::from_usize(1)).unwrap();
        sign_parties.add(TypedUsize::from_usize(3)).unwrap();
        sign_parties
    };
    debug!(
        "total_share_count {}, threshold {}",
        party_share_counts.total_share_count(),
        threshold,
    );

    debug!("keygen...");
    let keygen_shares = common::keygen::initialize_honest_parties(&party_share_counts, threshold);
    let keygen_share_outputs = execute_protocol(keygen_shares).expect("internal tofn error");
    let secret_key_shares: VecMap<keygen::KeygenShareId, keygen::SecretKeyShare> =
        keygen_share_outputs.map2(|(keygen_share_id, keygen_share)| match keygen_share {
            Protocol::NotDone(_) => panic!("share_id {} not done yet", keygen_share_id),
            Protocol::Done(result) => result.expect("share finished with error"),
        });

    // sign
    debug!("sign...");

    let keygen_share_ids = VecMap::<SignShareId, _>::from_vec(
        party_share_counts.share_id_subset(&sign_parties).unwrap(),
    );
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();
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
    let vkey = secret_key_shares
        .get(TypedUsize::from_usize(0))
        .unwrap()
        .group()
        .verifying_key();

    // verify a signature
    let sig = signatures.get(TypedUsize::from_usize(0)).unwrap();
    let pk: PublicKey = vkey.into();
    assert!(pk
        .as_affine()
        .verify_prehashed((&msg_to_sign).into(), sig)
        .is_ok());
}

mod execute;

#[cfg(feature = "malicious")]
mod malicious;
