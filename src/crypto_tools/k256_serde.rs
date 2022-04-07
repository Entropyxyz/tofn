//! serde support for k256
//!
//! ## References
//!
//! [Implementing Serialize · Serde](https://serde.rs/impl-serialize.html)
//! [Implementing Deserialize · Serde](https://serde.rs/impl-deserialize.html)

use ecdsa::elliptic_curve::{
    consts::U33, generic_array::GenericArray, group::GroupEncoding, Field,
};
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{de, de::Error, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// A wrapper for a random scalar value that is zeroized on drop
/// TODO why not just do this for Scalar below?
#[derive(Debug, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SecretScalar(Scalar);

impl AsRef<Scalar> for SecretScalar {
    fn as_ref(&self) -> &Scalar {
        &self.0
    }
}

impl SecretScalar {
    pub fn random_with_thread_rng() -> Self {
        Self(Scalar::random(rand::thread_rng()))
    }

    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self(Scalar::random(rng))
    }
}

#[cfg(feature = "malicious")]
impl AsMut<Scalar> for SecretScalar {
    fn as_mut(&mut self) -> &mut Scalar {
        &mut self.0
    }
}

impl From<Scalar> for SecretScalar {
    fn from(s: Scalar) -> Self {
        SecretScalar(s)
    }
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct EncodedPoint(k256::EncodedPoint);

impl Serialize for EncodedPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for EncodedPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(EncodedPointVisitor)
    }
}

struct EncodedPointVisitor;

impl<'de> Visitor<'de> for EncodedPointVisitor {
    type Value = EncodedPoint;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("SEC1-encoded secp256k1 (K-256) curve point")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(EncodedPoint(
            k256::EncodedPoint::from_bytes(v).map_err(E::custom)?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProjectivePoint(k256::ProjectivePoint);

impl ProjectivePoint {
    /// Base point of secp256k1. Wraps k256 `ProjectivePoint` generator.
    pub const GENERATOR: Self = Self(k256::ProjectivePoint::GENERATOR);

    /// Returns a SEC1-encoded compressed curve point.
    pub fn to_bytes(&self) -> [u8; 33] {
        to_array33(self.0.to_affine().to_bytes())
    }

    /// Decode from a SEC1-encoded curve point.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(
            k256::ProjectivePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(bytes).ok()?)
                .unwrap(),
        ))
    }
}

impl std::ops::Mul<Scalar> for ProjectivePoint {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0.mul(rhs))
    }
}

impl AsRef<k256::ProjectivePoint> for ProjectivePoint {
    fn as_ref(&self) -> &k256::ProjectivePoint {
        &self.0
    }
}

#[cfg(feature = "malicious")]
impl AsMut<k256::ProjectivePoint> for ProjectivePoint {
    fn as_mut(&mut self) -> &mut k256::ProjectivePoint {
        &mut self.0
    }
}

/// Use [to_bytes] when you have a [k256::ProjectivePoint] but not a [ProjectivePoint].
/// Otherwise prefer [ProjectivePoint::to_bytes].
pub fn point_to_bytes(p: &k256::ProjectivePoint) -> [u8; 33] {
    ProjectivePoint(*p).to_bytes()
}

impl From<k256::ProjectivePoint> for ProjectivePoint {
    fn from(p: k256::ProjectivePoint) -> Self {
        ProjectivePoint(p)
    }
}

impl From<&k256::ProjectivePoint> for ProjectivePoint {
    fn from(p: &k256::ProjectivePoint) -> Self {
        ProjectivePoint(*p)
    }
}

impl From<&SecretScalar> for ProjectivePoint {
    fn from(s: &SecretScalar) -> Self {
        ProjectivePoint(k256::ProjectivePoint::GENERATOR * s.0)
    }
}

impl Serialize for ProjectivePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EncodedPoint(self.0.to_encoded_point(true)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProjectivePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let projective_pt: Option<_> =
            k256::ProjectivePoint::from_encoded_point(&EncodedPoint::deserialize(deserializer)?.0)
                .into();
        match projective_pt {
            Some(x) => Ok(Self(x)),
            None => Err(D::Error::custom(
                "SEC1-encoded point is not on curve secp256k (K-256)",
            )),
        }
    }
}

/// [GenericArray] does not impl `From` for arrays of length exceeding 32.
/// Hence, this helper function.
fn to_array33(g: GenericArray<u8, U33>) -> [u8; 33] {
    [
        g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13],
        g[14], g[15], g[16], g[17], g[18], g[19], g[20], g[21], g[22], g[23], g[24], g[25], g[26],
        g[27], g[28], g[29], g[30], g[31], g[32],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::Options;
    use ecdsa::hazmat::{SignPrimitive, VerifyPrimitive};
    use k256::{ecdsa::Signature, elliptic_curve::Field, Scalar};
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;

    #[test]
    fn basic_round_trip() {
        let s = Scalar::random(rand::thread_rng());
        basic_round_trip_impl::<_, Scalar>(s, Some(32));

        let p = k256::ProjectivePoint::GENERATOR * s;
        basic_round_trip_impl::<_, ProjectivePoint>(p, None);

        let hashed_msg = Scalar::random(rand::thread_rng());
        let ephemeral_scalar = Scalar::random(rand::thread_rng());
        let signature = s.try_sign_prehashed(ephemeral_scalar, hashed_msg).unwrap();
        p.to_affine()
            .verify_prehashed(hashed_msg, &signature.0)
            .unwrap();
        basic_round_trip_impl::<_, Signature>(signature.0, None);

        let p_bytes = ProjectivePoint(p).to_bytes();
        let p_decoded = ProjectivePoint::from_bytes(&p_bytes).unwrap();
        assert_eq!(ProjectivePoint(p), p_decoded);
    }

    fn basic_round_trip_impl<T, U>(val: T, size: Option<usize>)
    where
        U: From<T> + Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let bincode = bincode::DefaultOptions::new();

        let v = U::from(val);
        let v_serialized = bincode.serialize(&v).unwrap();
        if let Some(size) = size {
            // tk note: failing: v_serialized.len() is 33, not 32 bytes
            assert_eq!(v_serialized.len(), size);
        }
        let v_deserialized = bincode.deserialize(&v_serialized).unwrap();
        assert_eq!(v, v_deserialized);
    }

    #[test]
    fn scalar_deserialization_fail() {
        let s = Scalar::random(rand::thread_rng());
        scalar_deserialization_fail_impl(s);
    }

    fn scalar_deserialization_fail_impl<S>(scalar: S)
    where
        S: Serialize + DeserializeOwned + Debug,
    {
        let bincode = bincode::DefaultOptions::new();

        // test too few bytes
        let mut too_few_bytes = bincode.serialize(&scalar).unwrap();
        too_few_bytes.pop();
        bincode.deserialize::<S>(&too_few_bytes).unwrap_err();

        // test too many bytes
        let mut too_many_bytes = bincode.serialize(&scalar).unwrap();
        too_many_bytes.push(42);
        bincode.deserialize::<S>(&too_many_bytes).unwrap_err();

        let mut modulus: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ]; // secp256k1 modulus

        // test edge case: integer too large
        bincode.deserialize::<S>(&modulus).unwrap_err();

        // test edge case: integer not too large
        // tk note: failing. I lack the knowledge about bincode to solve this quickly.
        modulus[31] -= 1;
        bincode.deserialize::<S>(&modulus).unwrap();
    }
}
