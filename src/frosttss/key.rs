//! A participant's FROST(Ed25519) key share, with Go-compatible persistence.

use super::Error;
use super::point::{EcPointJson, point_from_json, point_to_json};
use crate::frost::{Ciphersuite, Ed25519, Scalar};
use crate::tss::PartyId;
use crate::tss::bigint::BigUintDec;
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use serde::{Deserialize, Serialize};

/// Schema version of a [`Key`], matching Go `frosttss.KeyVersion`.
///
/// - 1: `Xi`, `ShareID`, `Ks`, `BigXj`, `GroupPublicKey`.
/// - 2: + `ChainCode` (optional BIP32 chain code for HD derivation).
pub const KEY_VERSION: u32 = 2;

/// A single participant's share of a FROST(Ed25519, SHA-512) key.
///
/// `xi` is the secret scalar share `s_i`. `share_id` is this participant's
/// identifier (equal to the `PartyId.key`). `ks` lists the identifiers of all
/// keygen participants, in keygen order; `big_xj` holds the matching
/// verification shares `Y_j = s_j·G`. `group_public_key` is the Ed25519 public
/// key `Y` an external verifier uses.
///
/// Field naming and JSON shape mirror the Go `frosttss.Key` so persisted keys
/// interoperate across both libraries.
#[derive(Clone)]
pub struct Key {
    /// Secret scalar share `s_i`.
    pub xi: Scalar,
    /// This participant's identifier (`= PartyId.key`).
    pub share_id: BigUintDec,
    /// Identifiers of all keygen participants, in keygen order.
    pub ks: Vec<BigUintDec>,
    /// Verification shares `Y_j = s_j·G`, aligned with `ks`.
    pub big_xj: Vec<EdwardsPoint>,
    /// Group public key `Y`.
    pub group_public_key: EdwardsPoint,
    /// Optional 32-byte BIP32 chain code (HD derivation). `None` for legacy keys.
    pub chain_code: Option<[u8; 32]>,
}

impl Key {
    /// Validates internal consistency (mirrors Go `Key.ValidateBasic`):
    /// non-empty `ks` equal in length to `big_xj`, a non-identity group public
    /// key, and the local share/commitment binding `xi·G == big_xj[i]` for the
    /// slot where `ks[i] == share_id`.
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
        if Ed25519::is_identity(&self.group_public_key) {
            return Err(Error::Validation(
                "GroupPublicKey is the curve identity".into(),
            ));
        }
        // Local share / commitment binding.
        let my_idx = self
            .ks
            .iter()
            .position(|k| k == &self.share_id)
            .ok_or_else(|| Error::Validation("ShareID not found in Ks".into()))?;
        let expect = Ed25519::mul_base(&self.xi);
        if !Ed25519::eq(&expect, &self.big_xj[my_idx]) {
            return Err(Error::Validation(
                "Xi·G does not equal BigXj[ShareID slot] — share/commitment binding broken".into(),
            ));
        }
        Ok(())
    }

    /// Reorders `ks`/`big_xj` to match `sorted_ids`, matching parties by
    /// `share_id` (the keygen identifier, compared to `PartyId.key`). Required
    /// whenever the active party set is a subset of the keygen participants
    /// (e.g. a signing committee). `xi`, `share_id`, and `group_public_key` are
    /// carried over unchanged.
    pub fn subset_for_parties(&self, sorted_ids: &[PartyId]) -> Result<Key, Error> {
        let mut ks = Vec::with_capacity(sorted_ids.len());
        let mut big_xj = Vec::with_capacity(sorted_ids.len());
        for id in sorted_ids {
            let want = strip_leading_zeros(&id.key);
            let saved = self
                .ks
                .iter()
                .position(|k| k.as_be_bytes() == want)
                .ok_or_else(|| {
                    Error::Validation(format!(
                        "subset_for_parties: party {id} not found in keygen save data"
                    ))
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
            chain_code: self.chain_code,
        })
    }

    /// Serializes the key to its Go-compatible JSON form.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&KeyWire::from_key(self))?)
    }

    /// Parses a key from its Go-compatible JSON form (without validating).
    pub fn from_json(s: &str) -> Result<Key, Error> {
        let wire: KeyWire = serde_json::from_str(s)?;
        wire.into_key()
    }

    /// Overwrites the secret share with zero, rendering the key unusable for
    /// signing or resharing. The chain code (public, but consistent with the
    /// "unusable after zeroize" contract) is also cleared.
    pub fn zeroize(&mut self) {
        self.xi = Scalar::ZERO;
        self.chain_code = None;
    }
}

// --- serde wire form (capitalized Go field names) ---

#[derive(Serialize, Deserialize)]
struct KeyWire {
    #[serde(rename = "Xi")]
    xi: BigUintDec,
    #[serde(rename = "ShareID")]
    share_id: BigUintDec,
    #[serde(rename = "Ks")]
    ks: Vec<BigUintDec>,
    #[serde(rename = "BigXj")]
    big_xj: Vec<EcPointJson>,
    #[serde(rename = "GroupPublicKey")]
    group_public_key: EcPointJson,
    #[serde(rename = "ChainCode", default, with = "crate::tss::b64::opt_array32")]
    chain_code: Option<[u8; 32]>,
}

impl KeyWire {
    fn from_key(k: &Key) -> Self {
        KeyWire {
            xi: scalar_to_biguint(&k.xi),
            share_id: k.share_id.clone(),
            ks: k.ks.clone(),
            big_xj: k.big_xj.iter().map(point_to_json).collect(),
            group_public_key: point_to_json(&k.group_public_key),
            chain_code: k.chain_code,
        }
    }

    fn into_key(self) -> Result<Key, Error> {
        let big_xj = self
            .big_xj
            .iter()
            .map(point_from_json)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Key {
            xi: biguint_to_scalar(&self.xi)?,
            share_id: self.share_id,
            ks: self.ks,
            big_xj,
            group_public_key: point_from_json(&self.group_public_key)?,
            chain_code: self.chain_code,
        })
    }
}

/// Encodes a scalar as a non-negative integer (its canonical value in `[0, L)`).
fn scalar_to_biguint(s: &Scalar) -> BigUintDec {
    let le = s.to_bytes();
    let mut be = [0u8; 32];
    for (i, &b) in le.iter().rev().enumerate() {
        be[i] = b;
    }
    BigUintDec::from_be_bytes(&be)
}

/// Decodes an integer into a canonical scalar in `[0, L)`.
fn biguint_to_scalar(v: &BigUintDec) -> Result<Scalar, Error> {
    let be = v.to_be_bytes_padded(32);
    let mut le = [0u8; 32];
    for (i, &b) in be.iter().rev().enumerate() {
        le[i] = b;
    }
    Scalar::from_bytes_canonical(&le).ok_or_else(|| Error::Validation("scalar >= L".into()))
}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial 1-of-1 key: xi=secret, single share, group key = xi·G.
    fn single_party_key(secret: u8, chain_code: Option<[u8; 32]>) -> Key {
        let mut b = [0u8; 32];
        b[0] = secret;
        let xi = Scalar::from_bytes_canonical(&b).unwrap();
        let pk = Ed25519::mul_base(&xi);
        Key {
            xi,
            share_id: BigUintDec::from_be_bytes(&[1]),
            ks: vec![BigUintDec::from_be_bytes(&[1])],
            big_xj: vec![pk],
            group_public_key: pk,
            chain_code,
        }
    }

    #[test]
    fn validate_basic_accepts_consistent_key() {
        single_party_key(7, None).validate_basic().unwrap();
    }

    #[test]
    fn validate_basic_rejects_broken_binding() {
        let mut k = single_party_key(7, None);
        k.big_xj[0] = Ed25519::generator(); // != xi·G
        assert!(k.validate_basic().is_err());
    }

    #[test]
    fn json_roundtrip_preserves_key() {
        let k = single_party_key(9, Some([0x11; 32]));
        let s = k.to_json().unwrap();
        let back = Key::from_json(&s).unwrap();
        back.validate_basic().unwrap();
        assert!(bool::from(k.xi.ct_eq(&back.xi)));
        assert_eq!(k.share_id, back.share_id);
        assert_eq!(k.ks, back.ks);
        assert!(Ed25519::eq(&k.group_public_key, &back.group_public_key));
        assert_eq!(k.chain_code, back.chain_code);
    }

    #[test]
    fn json_shape_matches_go() {
        let k = single_party_key(9, None);
        let v: serde_json::Value = serde_json::from_str(&k.to_json().unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        // Capitalized Go field names.
        for key in [
            "Xi",
            "ShareID",
            "Ks",
            "BigXj",
            "GroupPublicKey",
            "ChainCode",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        assert!(v["Xi"].is_number());
        assert!(v["Ks"].is_array());
        assert_eq!(v["GroupPublicKey"]["Curve"], "ed25519");
        assert!(v["ChainCode"].is_null()); // nil chain code -> null
    }

    #[test]
    fn chaincode_serializes_as_base64_string() {
        let k = single_party_key(9, Some([0xab; 32]));
        let v: serde_json::Value = serde_json::from_str(&k.to_json().unwrap()).unwrap();
        assert!(v["ChainCode"].is_string());
    }

    #[test]
    fn legacy_json_without_chaincode_parses() {
        // A Version-1 key JSON has no ChainCode field at all.
        let k = single_party_key(3, None);
        let mut v: serde_json::Value = serde_json::from_str(&k.to_json().unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("ChainCode");
        let s = serde_json::to_string(&v).unwrap();
        let back = Key::from_json(&s).unwrap();
        assert_eq!(back.chain_code, None);
    }

    #[test]
    fn zeroize_clears_secret() {
        let mut k = single_party_key(5, Some([1; 32]));
        k.zeroize();
        assert!(bool::from(k.xi.ct_eq(&Scalar::ZERO)));
        assert_eq!(k.chain_code, None);
    }

    #[test]
    fn key_version_is_two() {
        assert_eq!(KEY_VERSION, 2);
    }
}

#[cfg(test)]
mod go_interop_tests {
    use super::*;
    use crate::frost::binding::lagrange_coefficient;

    /// Loads the real Go-generated FROST(Ed25519) keys, round-trips them, and
    /// confirms the shares reconstruct to the group public key.
    #[test]
    fn go_keys_load_round_trip_and_reconstruct() {
        let raw = include_str!("testdata/frost.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let keys: Vec<Key> = doc["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Key::from_json(&serde_json::to_string(v).unwrap()).expect("load Go FROST key"))
            .collect();
        assert_eq!(keys.len(), 3);

        for k in &keys {
            k.validate_basic().unwrap();
            // All parties agree on the group public key.
            assert!(Ed25519::eq(&k.group_public_key, &keys[0].group_public_key));
            // Lossless JSON round-trip through the Rust writer.
            let back = Key::from_json(&k.to_json().unwrap()).unwrap();
            assert!(bool::from(k.xi.ct_eq(&back.xi)));
            assert!(Ed25519::eq(&k.group_public_key, &back.group_public_key));
            assert_eq!(k.ks, back.ks);
            assert_eq!(k.chain_code, back.chain_code);
        }

        // Any t+1 = 2 shares Lagrange-reconstruct to the group secret.
        let subset = [&keys[0], &keys[1]];
        let ids: Vec<Vec<u8>> = subset
            .iter()
            .map(|k| k.share_id.as_be_bytes().to_vec())
            .collect();
        let mut secret = Scalar::ZERO;
        for k in &subset {
            let lambda = lagrange_coefficient::<Ed25519>(k.share_id.as_be_bytes(), &ids).unwrap();
            secret = secret.add(&lambda.mul(&k.xi));
        }
        assert!(Ed25519::eq(
            &Ed25519::mul_base(&secret),
            &keys[0].group_public_key
        ));
    }
}
