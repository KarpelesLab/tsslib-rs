//! Output of a threshold BIP340 signing run.

use crate::prelude::*;
use serde::{Deserialize, Serialize};

/// A BIP340 Schnorr signature produced by FROST(secp256k1).
///
/// `signature` is the standard 64-byte BIP340 encoding `x(R) || s` and
/// verifies under `public_key` (the 32-byte x-only key actually signed for:
/// the group key, or its HD child and/or BIP341 Taproot output key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureData {
    /// 32-byte x-only nonce point `x(R)`.
    #[serde(rename = "R", with = "crate::tss::b64::vec")]
    pub r: Vec<u8>,
    /// 32-byte big-endian scalar `s`.
    #[serde(rename = "S", with = "crate::tss::b64::vec")]
    pub s: Vec<u8>,
    /// 64-byte BIP340 signature `x(R) || s`.
    #[serde(rename = "Signature", with = "crate::tss::b64::vec")]
    pub signature: Vec<u8>,
    /// The signed message.
    #[serde(rename = "M", with = "crate::tss::b64::vec")]
    pub m: Vec<u8>,
    /// 32-byte x-only public key the signature verifies under.
    #[serde(rename = "PublicKey", with = "crate::tss::b64::vec")]
    pub public_key: Vec<u8>,
}

impl SignatureData {
    /// The signature as a fixed-size array.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.signature
            .as_slice()
            .try_into()
            .expect("signature is 64 bytes")
    }
}
