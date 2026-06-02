//! Output of a threshold FROST(Ed25519) signing operation.

use serde::{Deserialize, Serialize};

/// The result of a FROST(Ed25519) signing run.
///
/// `signature` is the 64-byte `R || S` concatenation — a standard Ed25519
/// signature verifiable by any Ed25519 verifier. `r` is the 32-byte canonical
/// encoding of the group commitment, `s` the 32-byte little-endian scalar, and
/// `m` the message that was signed. Field names mirror the Go
/// `frosttss.SignatureData`; byte fields serialize as base64 (Go `[]byte`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureData {
    /// 32-byte canonical encoding of the group commitment `R`.
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
    /// Builds a [`SignatureData`] from the group commitment encoding `r`, the
    /// signature scalar encoding `s`, and the message `m`, deriving the 64-byte
    /// `signature = r || s`.
    pub fn new(r: Vec<u8>, s: Vec<u8>, m: Vec<u8>) -> Self {
        let mut signature = Vec::with_capacity(r.len() + s.len());
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);
        SignatureData { r, s, signature, m }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_r_concat_s() {
        let sig = SignatureData::new(vec![1u8; 32], vec![2u8; 32], b"msg".to_vec());
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(&sig.signature[..32], &[1u8; 32]);
        assert_eq!(&sig.signature[32..], &[2u8; 32]);
    }

    #[test]
    fn json_uses_go_field_names_and_base64() {
        let sig = SignatureData::new(vec![0u8; 32], vec![0u8; 32], b"hi".to_vec());
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&sig).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        for k in ["R", "S", "Signature", "M"] {
            assert!(obj.contains_key(k));
        }
        assert!(v["R"].is_string()); // base64, not array
        assert_eq!(v["M"], "aGk="); // base64("hi")
    }
}
