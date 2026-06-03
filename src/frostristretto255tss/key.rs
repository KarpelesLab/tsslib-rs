//! A participant's FROST(ristretto255) key share.
//!
//! Unlike the Ed25519 variant, the Go library ships no canonical JSON for this
//! key, so we define a straightforward Rust-native format: `big.Int` fields as
//! bare decimal numbers (matching `tss::bigint`) and group elements as their
//! 32-byte canonical Ristretto255 encoding, base64-encoded.

use super::Error;
use crate::frost::{Ciphersuite, Ristretto255, Scalar};
use crate::tss::PartyId;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use purecrypto::ec::ristretto255::RistrettoPoint;
use serde::{Deserialize, Serialize};

/// Schema version of a [`Key`].
pub const KEY_VERSION: u32 = 1;

/// A single participant's share of a FROST(ristretto255, SHA-512) key.
///
/// `xi` is the secret scalar share; `share_id` is this participant's identifier
/// (`= PartyId.key`); `ks` lists keygen identifiers in keygen order; `big_xj`
/// holds the matching verification shares `Y_j = s_j·G`; `group_public_key` is
/// the FROST master public key.
#[derive(Clone)]
pub struct Key {
    /// Secret scalar share `s_i`.
    pub xi: Scalar,
    /// This participant's identifier (`= PartyId.key`).
    pub share_id: BigUintDec,
    /// Identifiers of all keygen participants, in keygen order.
    pub ks: Vec<BigUintDec>,
    /// Verification shares `Y_j = s_j·G`, aligned with `ks`.
    pub big_xj: Vec<RistrettoPoint>,
    /// Group public key `Y`.
    pub group_public_key: RistrettoPoint,
}

impl Key {
    /// Validates internal consistency: non-empty `ks` equal in length to
    /// `big_xj`, a non-identity group key, and the local share/commitment
    /// binding `xi·G == big_xj[i]` for the slot where `ks[i] == share_id`.
    pub fn validate_basic(&self) -> Result<(), Error> {
        if self.ks.is_empty() {
            return Err(Error::Validation("Ks is empty".into()));
        }
        if self.ks.len() != self.big_xj.len() {
            return Err(Error::Validation(format!(
                "Ks length {} != BigXj length {}",
                self.ks.len(),
                self.big_xj.len()
            )));
        }
        if Ristretto255::is_identity(&self.group_public_key) {
            return Err(Error::Validation(
                "GroupPublicKey is the group identity".into(),
            ));
        }
        let my_idx = self
            .ks
            .iter()
            .position(|k| k == &self.share_id)
            .ok_or_else(|| Error::Validation("ShareID not found in Ks".into()))?;
        if !Ristretto255::eq(&Ristretto255::mul_base(&self.xi), &self.big_xj[my_idx]) {
            return Err(Error::Validation(
                "Xi·G does not equal BigXj[ShareID slot] — share/commitment binding broken".into(),
            ));
        }
        Ok(())
    }

    /// Reorders `ks`/`big_xj` to match `sorted_ids` (matching by `share_id`).
    pub fn subset_for_parties(&self, sorted_ids: &[PartyId]) -> Result<Key, Error> {
        let mut ks = Vec::with_capacity(sorted_ids.len());
        let mut big_xj = Vec::with_capacity(sorted_ids.len());
        for id in sorted_ids {
            let want = strip(&id.key);
            let saved = self
                .ks
                .iter()
                .position(|k| k.as_be_bytes() == want)
                .ok_or_else(|| {
                    Error::Validation(format!("subset_for_parties: party {id} not in keygen data"))
                })?;
            ks.push(self.ks[saved].clone());
            big_xj.push(self.big_xj[saved]);
        }
        Ok(Key {
            xi: self.xi.clone(),
            share_id: self.share_id.clone(),
            ks,
            big_xj,
            group_public_key: self.group_public_key,
        })
    }

    /// Serializes the key to JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&KeyWire::from_key(self))?)
    }

    /// Parses a key from JSON (without validating).
    pub fn from_json(s: &str) -> Result<Key, Error> {
        KeyWire::deserialize_str(s)?.into_key()
    }

    /// Overwrites the secret share with zero.
    pub fn zeroize(&mut self) {
        self.xi = Scalar::ZERO;
    }
}

#[derive(Serialize, Deserialize)]
struct KeyWire {
    #[serde(rename = "Xi")]
    xi: BigUintDec,
    #[serde(rename = "ShareID")]
    share_id: BigUintDec,
    #[serde(rename = "Ks")]
    ks: Vec<BigUintDec>,
    #[serde(rename = "BigXj")]
    big_xj: Vec<B64Bytes>,
    #[serde(rename = "GroupPublicKey")]
    group_public_key: B64Bytes,
}

impl KeyWire {
    fn deserialize_str(s: &str) -> Result<KeyWire, serde_json::Error> {
        serde_json::from_str(s)
    }

    fn from_key(k: &Key) -> Self {
        KeyWire {
            xi: scalar_to_biguint(&k.xi),
            share_id: k.share_id.clone(),
            ks: k.ks.clone(),
            big_xj: k
                .big_xj
                .iter()
                .map(|p| B64Bytes(Ristretto255::encode_point(p).to_vec()))
                .collect(),
            group_public_key: B64Bytes(Ristretto255::encode_point(&k.group_public_key).to_vec()),
        }
    }

    fn into_key(self) -> Result<Key, Error> {
        let big_xj = self
            .big_xj
            .iter()
            .map(|b| decode_point(&b.0))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Key {
            xi: biguint_to_scalar(&self.xi)?,
            share_id: self.share_id,
            ks: self.ks,
            big_xj,
            group_public_key: decode_point(&self.group_public_key.0)?,
        })
    }
}

fn decode_point(b: &[u8]) -> Result<RistrettoPoint, Error> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| Error::Validation("element encoding must be 32 bytes".into()))?;
    Ristretto255::decode_point(&arr)
        .ok_or_else(|| Error::Validation("invalid Ristretto255 element".into()))
}

fn scalar_to_biguint(s: &Scalar) -> BigUintDec {
    let le = s.to_bytes();
    let mut be = [0u8; 32];
    for (i, &b) in le.iter().rev().enumerate() {
        be[i] = b;
    }
    BigUintDec::from_be_bytes(&be)
}

fn biguint_to_scalar(v: &BigUintDec) -> Result<Scalar, Error> {
    let be = v.to_be_bytes_padded(32);
    let mut le = [0u8; 32];
    for (i, &b) in be.iter().rev().enumerate() {
        le[i] = b;
    }
    Scalar::from_bytes_canonical(&le).ok_or_else(|| Error::Validation("scalar >= L".into()))
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_party_key(secret: u8) -> Key {
        let mut b = [0u8; 32];
        b[0] = secret;
        let xi = Scalar::from_bytes_canonical(&b).unwrap();
        let pk = Ristretto255::mul_base(&xi);
        Key {
            xi,
            share_id: BigUintDec::from_be_bytes(&[1]),
            ks: vec![BigUintDec::from_be_bytes(&[1])],
            big_xj: vec![pk],
            group_public_key: pk,
        }
    }

    #[test]
    fn validate_basic_accepts_consistent_key() {
        single_party_key(7).validate_basic().unwrap();
    }

    #[test]
    fn validate_basic_rejects_broken_binding() {
        let mut k = single_party_key(7);
        k.big_xj[0] = Ristretto255::generator();
        assert!(k.validate_basic().is_err());
    }

    #[test]
    fn json_roundtrip() {
        let k = single_party_key(9);
        let s = k.to_json().unwrap();
        let back = Key::from_json(&s).unwrap();
        back.validate_basic().unwrap();
        assert!(bool::from(k.xi.ct_eq(&back.xi)));
        assert!(Ristretto255::eq(
            &k.group_public_key,
            &back.group_public_key
        ));
        // Points serialize as base64 strings.
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["GroupPublicKey"].is_string());
        assert!(v["Xi"].is_number());
    }
}
