use alloc::vec;
use alloc::vec::Vec;

use crate::gg20::keygen::{
    KeygenPartyId, KeygenPartyShareCounts, KeygenShareId, PartyKeyPair, PartyKeygenData,
};
use crate::{
    collections::{TypedUsize, VecMap},
    crypto_tools::{
        k256_serde::{self, ProjectivePoint},
        paillier::{self, zk::ZkSetup},
        rng,
        ss::{Share, Ss},
    },
    gg20::{
        self,
        constants::{KEYPAIR_TAG, ZKSETUP_TAG},
        keygen::{
            secret_key_share::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo},
            SharePublicInfo,
        },
    },
    sdk::api::{PartyShareCounts, TofnFatal, TofnResult},
};
use anyhow::Result;
use bincode::Options;
use core::{convert::TryInto, ops::Mul};
use k256::{NonZeroScalar, SecretKey};
pub use rng::SecretRecoveryKey;
use tracing::error;
use tracing::info;

/// Pre-image of `SecretKeyShare` in ceygen.
pub type CeygenShareInfo = (SharePublicInfo, ShareSecretInfo);

#[cfg(feature = "malicious")]
// use super::malicious;

/// Maximum byte length of messages exchanged during keygen.
/// The sender of a message larger than this maximum will be accused as a faulter.
/// View all message sizes in the logs of the integration test `single_thred::basic_correctness`.
/// The largest keygen message is r1::Bcast with size ~4833 bytes on the wire.
/// There is also a variable-sized message in r2::Bcast that depends on the
/// threshold: 34t + 73. For t = 100, this is still smaller than the limit.
/// See https://github.com/axelarnetwork/tofn/issues/171
pub const MAX_MSG_LEN: usize = 5500;

/// The tuple of bincode-encoded PartyShareCounts, and bincode-encoded SecretKeyShares.
pub type Ceygen = (Vec<u8>, Vec<(TypedUsize<KeygenShareId>, Vec<u8>)>);

/// Validate the party parameters, then split Alice's key into an bincode-encoded byte-array of keyshares.
pub fn ceygen(parties: usize, threshold: usize, alice_key_byte_array: &[u8]) -> Result<Ceygen> {
    let alice_key = validate_secret_key(alice_key_byte_array)?;
    let party_share_counts =
        PartyShareCounts::from_vec(vec![1; parties]).expect("invalid party count");
    info!("generating secret key shares. This may take several moments.");
    let secret_key_shares =
        gg20::ceygen::initialize_honest_parties(&party_share_counts, threshold, *alice_key);
    info!("key shares generated.");

    // encode keyshares
    let secret_key_shares_encoded = secret_key_shares
        .into_iter()
        .map(|(index, share)| {
            let bincode = bincode::DefaultOptions::new();
            (index, bincode.serialize(&share).unwrap())
        })
        .collect();

    // encode party_share_counts
    let bincode = bincode::DefaultOptions::new();
    let party_share_counts_encoded = bincode
        .serialize(&party_share_counts)
        .map_err(|err| anyhow::Error::msg("Failed to serialize PartyShareCounts").context(err))?;

    info!("ceygen generated {}-of-{} keys", threshold, parties);
    Ok((party_share_counts_encoded, secret_key_shares_encoded))
}

// validate alice_key and return a SecretKey if valid.
fn validate_secret_key(alice_key_byte_array: &[u8]) -> Result<NonZeroScalar> {
    Ok(SecretKey::from_be_bytes(alice_key_byte_array)
        .map_err(|err| anyhow::Error::msg("Failed to deserialize SecretKey").context(err))?
        .to_nonzero_scalar())
}

pub(crate) fn initialize_honest_parties(
    party_share_counts: &PartyShareCounts<KeygenPartyId>,
    threshold: usize,
    alice_key: k256::Scalar,
) -> VecMap<KeygenShareId, SecretKeyShare> {
    let session_nonce = b"foobar";
    let shares = Ss::new_byok(threshold, alice_key).shares(party_share_counts.total_share_count());

    let (v_public_info, v_secret_info): (Vec<SharePublicInfo>, Vec<ShareSecretInfo>) =
        party_share_counts
            .iter()
            .zip(shares.into_iter())
            .flat_map(|((party_id, &party_share_count), share)| {
                // each party use the same secret recovery key for all its subshares
                let secret_recovery_key = super::dummy_secret_recovery_key(party_id);
                let party_keygen_data =
                    create_party_keypair_and_zksetup(party_id, &secret_recovery_key, session_nonce)
                        .unwrap();

                (0..party_share_count).map(move |subshare_id| {
                    new_ceygen(
                        party_share_counts.clone(),
                        threshold,
                        party_id,
                        subshare_id,
                        share.clone(),
                        &party_keygen_data,
                        #[cfg(feature = "malicious")]
                        gg20::sign::malicious::Behaviour::Honest,
                    )
                    .expect("bad ceygen; need parties >= threshold+1")
                })
            })
            .unzip();

    let y = ProjectivePoint::GENERATOR.mul(alice_key);

    let group_public_info = GroupPublicInfo::new(
        party_share_counts.clone(),
        threshold,
        y,
        VecMap::from_vec(v_public_info),
    );

    v_secret_info
        .into_iter()
        .map(|share_secret_info| SecretKeyShare::new(group_public_info.clone(), share_secret_info))
        .collect()
}

/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key<K>(index: TypedUsize<K>) -> SecretRecoveryKey {
    let index_bytes = index.as_usize().to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    result[..].try_into().unwrap()
}

// Since safe prime generation is expensive, a party is expected to generate
// a keypair once for all it's shares and provide it to new_keygen
pub fn create_party_keypair_and_zksetup(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeygenData> {
    let encryption_keypair =
        recover_party_keypair(my_party_id, secret_recovery_key, session_nonce)?;

    let encryption_keypair_proof = encryption_keypair
        .ek
        .correctness_proof(&encryption_keypair.dk, &my_party_id.to_bytes());

    let mut zksetup_rng =
        rng::rng_seed(ZKSETUP_TAG, my_party_id, secret_recovery_key, session_nonce)?;
    let (zk_setup, zk_setup_proof) = ZkSetup::new(&mut zksetup_rng, &my_party_id.to_bytes())?;

    Ok(PartyKeygenData {
        encryption_keypair,
        encryption_keypair_proof,
        zk_setup,
        zk_setup_proof,
    })
}

pub fn recover_party_keypair(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = paillier::keygen(&mut rng)?;

    Ok(PartyKeyPair { ek, dk })
}

// BEWARE: This is only made visible for faster integration testing
pub fn create_party_keypair_and_zksetup_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeygenData> {
    let encryption_keypair =
        recover_party_keypair_unsafe(my_party_id, secret_recovery_key, session_nonce)?;

    let encryption_keypair_proof = encryption_keypair
        .ek
        .correctness_proof(&encryption_keypair.dk, &my_party_id.to_bytes());

    let mut zksetup_rng =
        rng::rng_seed(ZKSETUP_TAG, my_party_id, secret_recovery_key, session_nonce)?;
    let (zk_setup, zk_setup_proof) =
        ZkSetup::new_unsafe(&mut zksetup_rng, &my_party_id.to_bytes())?;

    Ok(PartyKeygenData {
        encryption_keypair,
        encryption_keypair_proof,
        zk_setup,
        zk_setup_proof,
    })
}

// BEWARE: This is only made visible for faster integration testing
pub fn recover_party_keypair_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = paillier::keygen_unsafe(&mut rng)?;

    Ok(PartyKeyPair { ek, dk })
}

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

// TODO use const generics for these bounds
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

// BEWARE: This is only made visible for faster integration testing
// TODO: Use a better way to hide this from the API, while allowing it for integration tests
// since #[cfg(tests)] only works for unit tests

#[allow(clippy::too_many_arguments)]
pub fn new_ceygen(
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    my_subshare_id: usize,
    share: Share,
    party_keygen_data: &PartyKeygenData,
    #[cfg(feature = "malicious")] _behavior: gg20::sign::malicious::Behaviour,
) -> TofnResult<CeygenShareInfo> {
    if party_share_counts
        .iter()
        .any(|(_, &c)| c > MAX_PARTY_SHARE_COUNT)
    {
        error!(
            "detected a party with share count exceeding {}",
            MAX_PARTY_SHARE_COUNT
        );
        return Err(TofnFatal);
    }
    let total_share_count: usize = party_share_counts.total_share_count();
    let my_keygen_id: TypedUsize<KeygenShareId> =
        party_share_counts.party_to_share_id(my_party_id, my_subshare_id)?;

    #[allow(clippy::suspicious_operation_groupings)]
    if total_share_count <= threshold
        || total_share_count > MAX_TOTAL_SHARE_COUNT
        || my_party_id.as_usize() >= party_share_counts.party_count()
    {
        error!(
                "invalid (total_share_count, threshold, my_party_id, subshare_id, max_share_count): ({},{},{},{},{})",
            total_share_count, threshold, my_party_id, my_subshare_id, MAX_TOTAL_SHARE_COUNT
            );
        return Err(TofnFatal);
    }

    let share_public_info: SharePublicInfo = SharePublicInfo::new(
        k256_serde::ProjectivePoint::GENERATOR.mul(*share.get_scalar()),
        party_keygen_data.encryption_keypair.ek.clone(),
        party_keygen_data.zk_setup.clone(),
    );
    let share_secret_info = ShareSecretInfo::new(
        my_keygen_id,
        party_keygen_data.encryption_keypair.dk.clone(),
        *share.get_scalar(),
    );

    TofnResult::Ok((share_public_info, share_secret_info))
}
