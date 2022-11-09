//! API for tofn users
pub use k256::ecdsa::{recoverable::Signature as RecoverableSignature, Signature, VerifyingKey};

use ecdsa::hazmat::VerifyPrimitive;
use k256::{
    ecdsa::recoverable::Id,
    elliptic_curve::{
        generic_array::{
            sequence::Split,
            typenum::{U12, U20},
            GenericArray,
        },
        ops::Reduce,
        sec1::ToEncodedPoint,
    },
    FieldBytes, PublicKey, Scalar, U256,
};
use sha3::{digest::Update, Digest, Keccak256};

pub type TofnResult<T> = Result<T, TofnFatal>;
pub type BytesVec = Vec<u8>;

pub use super::{
    party_share_counts::PartyShareCounts,
    protocol::{Fault, Protocol, ProtocolFaulters, ProtocolOutput},
    round::Round,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TofnFatal;

// TODO make these into const generics wherever they're used
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

/// Expose tofn's (de)serialization functions
/// that use the appropriate bincode config options.
pub use super::wire_bytes::{deserialize, serialize};

#[cfg(feature = "malicious")]
pub use super::wire_bytes::MsgType;

pub fn to_recoverable_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Option<RecoverableSignature> {
    // TODO: replace with `RecoverableSignature::from_digest_bytes_trial_recovery()` call
    // when k256 is bumped to 0.11.

    let signature = signature.normalize_s().unwrap_or(*signature);
    let message_array = FieldBytes::from_exact_iter(message.iter().cloned())?;

    for recovery_id in 0..=1 {
        let id = Id::new(recovery_id).ok()?;
        let recoverable_signature = RecoverableSignature::new(&signature, id).ok()?;
        let recovered_key = recoverable_signature
            .recover_verify_key_from_digest_bytes(&message_array)
            .ok()?;
        if verifying_key != &recovered_key {
            continue;
        }

        let pk: PublicKey = verifying_key.into();
        let scalar_message = <Scalar as Reduce<U256>>::from_be_bytes_reduced(message_array);
        if pk
            .as_affine()
            .verify_prehashed(scalar_message, &signature)
            .is_ok()
        {
            return Some(recoverable_signature);
        }
    }

    None
}

pub fn derive_ethereum_address(vkey: &VerifyingKey) -> [u8; 20] {
    let uncompressed = vkey.to_encoded_point(false);
    let hash = Keccak256::new()
        // the first byte is the uncompressed tag (0x04)
        .chain(&uncompressed.as_bytes()[1..])
        .finalize();
    let (_, last_bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hash.split();
    last_bytes.into()
}
