//! BIP32 non-hardened HD derivation + key import for dklstss.

use super::Error;
use super::key::{Key, Signature};
use super::keygen::derive_chain_code;
use super::secp::{self, ProjectivePoint, Scalar};
use crate::tss::PartyId;
use purecrypto::hash::HmacSha512;
use purecrypto::rng::RngCore;

/// BIP32 hardened-index boundary; path components `>= this` are rejected.
pub const HARDENED_KEY_START: u32 = 0x8000_0000;

/// Walks a non-hardened BIP32 path from `key`'s joint public key, returning the
/// additive `tweak` (Σ IL) and the child public key (`parent + tweak·G`).
pub fn derive_child(key: &Key, path: &[u32]) -> Result<(Scalar, ProjectivePoint), Error> {
    for &idx in path {
        if idx >= HARDENED_KEY_START {
            return Err(Error::Validation(
                "hardened derivation requires the raw private key".into(),
            ));
        }
    }
    let mut cur_pub = key.ecdsa_pub;
    let mut cur_cc = key.chain_code;
    let mut tweak = Scalar::ZERO;
    for &index in path {
        let compressed = secp::to_sec1_compressed(&cur_pub)
            .ok_or_else(|| Error::Validation("cannot compress public key".into()))?;
        let i = HmacSha512::new(&cur_cc)
            .chain(&compressed)
            .chain(&index.to_be_bytes())
            .finalize();
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let il_num = Scalar::from_bytes_be(&il)
            .map_err(|_| Error::Validation(format!("IL >= n at index {index}; pick another")))?;
        if bool::from(il_num.is_zero()) {
            return Err(Error::Validation(format!(
                "IL == 0 at index {index}; pick another"
            )));
        }
        cur_pub = cur_pub.add(&secp::mul_base(&il_num));
        cur_cc.copy_from_slice(&i[32..]);
        tweak = tweak.add(&il_num);
    }
    Ok((tweak, cur_pub))
}

/// Derives the child key for `path` and signs `hash` under it. Returns the
/// signature and the child public key for the verifier.
pub fn derive_and_sign(
    keys: &[Key],
    signer_idx: &[usize],
    path: &[u32],
    hash: &[u8],
    rng: &mut impl RngCore,
) -> Result<(Signature, ProjectivePoint), Error> {
    let first = keys
        .first()
        .ok_or_else(|| Error::Validation("no keys".into()))?;
    let (tweak, child_pub) = derive_child(first, path)?;
    let sig = super::signing::sign_with_tweak(keys, signer_idx, &tweak, hash, rng)?;
    Ok((sig, child_pub))
}

/// Wraps a plain secp256k1 private scalar as a trivial 1-of-1 [`Key`] owned by
/// `party`, ready to be the sole old-committee input to resharing.
pub fn import_key(private: &Scalar, party: &PartyId) -> Result<Key, Error> {
    if bool::from(private.is_zero()) {
        return Err(Error::Validation("ImportKey: priv is zero".into()));
    }
    let pub_key = secp::mul_base(private);
    let key = Key {
        n: 1,
        t: 0,
        idx: 0,
        party_ids: vec![party.clone()],
        xi: private.clone(),
        big_xj: vec![pub_key],
        ecdsa_pub: pub_key,
        ot: vec![None],
        chain_code: derive_chain_code(&pub_key),
    };
    key.validate_basic()?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::super::keygen::keygen;
    use super::super::signing::sign;
    use super::*;
    use purecrypto::hash::sha256;
    use purecrypto::rng::OsRng;

    fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    #[test]
    fn child_pub_equals_parent_plus_tweak_g() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let (tweak, child) = derive_child(&keys[0], &[1, 5, 9]).unwrap();
        let expect = keys[0].ecdsa_pub.add(&secp::mul_base(&tweak));
        assert!(secp::point_eq(&child, &expect));
        // All parties derive the same child.
        let (_, child2) = derive_child(&keys[1], &[1, 5, 9]).unwrap();
        assert!(secp::point_eq(&child, &child2));
    }

    #[test]
    fn derive_and_sign_verifies_under_child_key() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let msg = sha256(b"hd ecdsa");
        let (sig, child_pub) = derive_and_sign(&keys, &[0, 1], &[7, 2], &msg, &mut OsRng).unwrap();
        // Verify under the derived child public key.
        let e = super::super::signing::hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(super::super::signing::ecdsa_verify(&child_pub, &e, &r, &s));
    }

    #[test]
    fn import_then_sign() {
        let priv_scalar = secp::random_scalar(&mut OsRng);
        let party = PartyId::new("imp", "imp", vec![7]);
        let key = import_key(&priv_scalar, &party).unwrap();
        assert!(secp::point_eq(
            &key.ecdsa_pub,
            &secp::mul_base(&priv_scalar)
        ));
        // A 1-of-1 import can sign by itself (T+1 = 1 signer).
        let msg = sha256(b"imported");
        let sig = sign(std::slice::from_ref(&key), &[0], &msg, &mut OsRng).unwrap();
        let e = super::super::signing::hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(super::super::signing::ecdsa_verify(
            &key.ecdsa_pub,
            &e,
            &r,
            &s
        ));
    }
}
