//! Output of a threshold FROST(ristretto255) signing operation.

use serde::{Deserialize, Serialize};

/// The result of a FROST(ristretto255) signing run.
///
/// `signature` is `R || S` (64 bytes): `R` is the 32-byte canonical Ristretto255
/// encoding of the group commitment, `S` the 32-byte little-endian scalar. This
/// format is **not** Ed25519-compatible; verifiers must re-derive the challenge
/// as `H2(R || pubkey || msg)` under the `FROST-RISTRETTO255-SHA512-v1`
/// ciphersuite. Field names mirror the Go `SignatureData`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureData {
    /// 32-byte canonical Ristretto255 encoding of the group commitment `R`.
    #[serde(rename = "R", with = "crate::tss::b64::vec")]
    pub r: Vec<u8>,
    /// 32-byte little-endian signature scalar `S`.
    #[serde(rename = "S", with = "crate::tss::b64::vec")]
    pub s: Vec<u8>,
    /// 64-byte signature `R || S`.
    #[serde(rename = "Signature", with = "crate::tss::b64::vec")]
    pub signature: Vec<u8>,
    /// The signed message.
    #[serde(rename = "M", with = "crate::tss::b64::vec")]
    pub m: Vec<u8>,
}

impl SignatureData {
    /// Builds a [`SignatureData`] from `r`, `s`, and `m`, deriving `signature = r || s`.
    pub fn new(r: Vec<u8>, s: Vec<u8>, m: Vec<u8>) -> Self {
        let mut signature = Vec::with_capacity(r.len() + s.len());
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);
        SignatureData { r, s, signature, m }
    }
}
