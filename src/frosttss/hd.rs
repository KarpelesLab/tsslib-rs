//! BIP32-shape non-hardened HD derivation for FROST(Ed25519) keys, plus key
//! import. Port of frosttss/hd.go and import.go.
//!
//! Derivation is deterministic and public: anyone with the parent public key,
//! chain code, and path computes the same child public key and additive
//! `tweak`. The tweak feeds [`Key::new_signing_with_tweak`] so a threshold
//! signature verifies under the derived child key. Hardened indices (`>= 2^31`)
//! are rejected — they need the raw private scalar, incompatible with threshold
//! signing.

use super::Error;
use super::key::Key;
use super::signing::Signing;
use crate::frost::{Ciphersuite, Ed25519, Scalar, scalar_from_be_mod_l};
use crate::tss::bigint::BigUintDec;
use crate::tss::{Parameters, PartyId};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::hash::{HmacSha512, sha256};

/// BIP32 hardened-index boundary; path components `>= this` are rejected.
pub const HARDENED_KEY_START: u32 = 0x8000_0000;

const CHAINCODE_DOMAIN: &[u8] = b"FROST-Ed25519-chaincode-v1";
const DERIVATION_DOMAIN: &[u8] = b"FROST-Ed25519-HD-v1";

/// The canonical 32-byte master chain code for a group public key:
/// `SHA-256(domain || compress(pub))`. Deterministic, so every keygen party
/// agrees on it.
pub fn derive_chain_code(group_public_key: &EdwardsPoint) -> [u8; 32] {
    let mut data = Vec::with_capacity(CHAINCODE_DOMAIN.len() + 32);
    data.extend_from_slice(CHAINCODE_DOMAIN);
    data.extend_from_slice(&Ed25519::encode_point(group_public_key));
    sha256(&data)
}

impl Key {
    /// Walks a non-hardened derivation `path` from this key, returning
    /// `(tweak, child_pub, child_chain_code)` where `child_private =
    /// parent_private + tweak (mod L)` and `child_pub = parent_pub + tweak·G`.
    /// An empty path returns `tweak = 0` and the parent unchanged. Requires a
    /// populated 32-byte chain code (see [`Key::attach_chain_code`]).
    pub fn derive_child(&self, path: &[u32]) -> Result<(Scalar, EdwardsPoint, [u8; 32]), Error> {
        let mut cur_cc = self
            .chain_code
            .ok_or_else(|| Error::Validation("DeriveChild requires a 32-byte ChainCode".into()))?;
        for &idx in path {
            if idx >= HARDENED_KEY_START {
                return Err(Error::Validation(
                    "hardened derivation is not supported in threshold signing".into(),
                ));
            }
        }

        let mut cur_pub = self.group_public_key;
        let mut acc = Scalar::ZERO;
        for &idx in path {
            let (il, child_cc) = derive_step(&cur_cc, &cur_pub, idx)?;
            let next = Ed25519::add(&cur_pub, &Ed25519::mul_base(&il));
            if Ed25519::is_identity(&next) {
                return Err(Error::Validation(format!(
                    "DeriveChild at index {idx} produced the identity point"
                )));
            }
            cur_cc = child_cc;
            cur_pub = next;
            acc = acc.add(&il);
        }
        Ok((acc, cur_pub, cur_cc))
    }

    /// Populates the chain code for a legacy key that lacks one (deterministic
    /// from the public key; safe and idempotent).
    pub fn attach_chain_code(&mut self) {
        self.chain_code = Some(derive_chain_code(&self.group_public_key));
    }

    /// Derives the child key for `path` and starts a signing session that
    /// produces a signature verifiable under the returned child public key.
    pub fn derive_and_sign(
        &self,
        path: &[u32],
        msg: Vec<u8>,
        params: Parameters,
    ) -> Result<(Signing, EdwardsPoint), Error> {
        let (tweak, child_pub, _) = self.derive_child(path)?;
        let signing = self.new_signing_with_tweak(msg, params, Some(tweak))?;
        Ok((signing, child_pub))
    }
}

/// One HMAC-SHA512 derivation step:
/// `I = HMAC(parentCC, domain || compress(parentPub) || index_be32)`;
/// `IL = I[:32] mod L` (tweak), `IR = I[32:]` (child chain code). Rejects
/// `IL ≡ 0`.
fn derive_step(
    parent_cc: &[u8; 32],
    parent_pub: &EdwardsPoint,
    index: u32,
) -> Result<(Scalar, [u8; 32]), Error> {
    let i = HmacSha512::new(parent_cc)
        .chain(DERIVATION_DOMAIN)
        .chain(&Ed25519::encode_point(parent_pub))
        .chain(&index.to_be_bytes())
        .finalize();
    let il = scalar_from_be_mod_l(&i[..32]);
    if bool::from(il.ct_eq(&Scalar::ZERO)) {
        return Err(Error::Validation(format!(
            "derived IL ≡ 0 mod L at index {index} (retry with a different index)"
        )));
    }
    let mut child_cc = [0u8; 32];
    child_cc.copy_from_slice(&i[32..]);
    Ok((il, child_cc))
}

/// Wraps a plain Ed25519 private scalar as a trivial 1-of-1 [`Key`] owned by
/// `party`, ready to be the sole old-committee input to resharing. The group
/// public key is `priv·G`. Rejects a zero scalar or an empty party key.
///
/// ⚠️ At import the party holds the complete secret — this defeats the DKG's
/// "key never existed whole" property. Use only to migrate a pre-existing key,
/// and reshare immediately afterwards.
pub fn import_key(private: &Scalar, party: &PartyId) -> Result<Key, Error> {
    if bool::from(private.ct_eq(&Scalar::ZERO)) {
        return Err(Error::Validation(
            "ImportKey: priv is zero mod curve order".into(),
        ));
    }
    let share_id_bytes = strip(&party.key);
    if share_id_bytes.is_empty() {
        return Err(Error::Validation("ImportKey: partyID has empty key".into()));
    }
    let pub_key = Ed25519::mul_base(private);
    let share_id = BigUintDec::from_be_bytes(share_id_bytes);
    let key = Key {
        xi: private.clone(),
        share_id: share_id.clone(),
        ks: vec![share_id],
        big_xj: vec![pub_key],
        group_public_key: pub_key,
        chain_code: Some(derive_chain_code(&pub_key)),
    };
    key.validate_basic()?;
    Ok(key)
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::random_scalar;
    use purecrypto::rng::OsRng;

    fn import_test_key() -> (Scalar, Key) {
        let priv_scalar = random_scalar(&mut OsRng);
        let party = PartyId::new("imp", "imp", vec![7]);
        (
            priv_scalar.clone(),
            import_key(&priv_scalar, &party).unwrap(),
        )
    }

    #[test]
    fn import_produces_valid_1_of_1() {
        let (priv_scalar, key) = import_test_key();
        key.validate_basic().unwrap();
        assert!(Ed25519::eq(
            &key.group_public_key,
            &Ed25519::mul_base(&priv_scalar)
        ));
        assert!(key.chain_code.is_some());
    }

    #[test]
    fn import_rejects_zero() {
        let party = PartyId::new("imp", "imp", vec![7]);
        assert!(import_key(&Scalar::ZERO, &party).is_err());
    }

    #[test]
    fn empty_path_is_identity_derivation() {
        let (_, key) = import_test_key();
        let (tweak, child_pub, cc) = key.derive_child(&[]).unwrap();
        assert!(bool::from(tweak.ct_eq(&Scalar::ZERO)));
        assert!(Ed25519::eq(&child_pub, &key.group_public_key));
        assert_eq!(cc, key.chain_code.unwrap());
    }

    #[test]
    fn child_pub_equals_parent_plus_tweak_g() {
        let (_, key) = import_test_key();
        let (tweak, child_pub, _) = key.derive_child(&[1, 2, 3]).unwrap();
        let expect = Ed25519::add(&key.group_public_key, &Ed25519::mul_base(&tweak));
        assert!(Ed25519::eq(&child_pub, &expect));
    }

    #[test]
    fn derivation_is_deterministic() {
        let (_, key) = import_test_key();
        let a = key.derive_child(&[1, 7, 99]).unwrap();
        let b = key.derive_child(&[1, 7, 99]).unwrap();
        assert!(Ed25519::eq(&a.1, &b.1));
        assert_eq!(a.2, b.2);
    }

    #[test]
    fn hardened_index_rejected() {
        let (_, key) = import_test_key();
        assert!(key.derive_child(&[HARDENED_KEY_START]).is_err());
    }
}
