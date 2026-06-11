//! Importing a plain ECDSA private key as a degenerate 1-of-1 GG18 [`Key`], the
//! migration entry point: wrap an existing single-party key, then reshare it to a
//! `t`-of-`n` committee. Port of Go `ecdsatss/import.go`.
//!
//! The imported key carries only the secret share and public points; the Paillier
//! and ring-Pedersen parameters are left zero (a placeholder) and are generated
//! when the key is reshared.

#![allow(dead_code)]

use super::key::{EcPointJson, Key, PaillierPkJson, PaillierSkJson};
use super::secp;
use super::{Error, bn};
use crate::tss::bigint::BigUintDec;
use purecrypto::bignum::BoxedUint;

fn dec(n: &BoxedUint) -> BigUintDec {
    BigUintDec::from_be_bytes(&bn::to_be(n))
}

fn zero() -> BigUintDec {
    BigUintDec::from_be_bytes(&[])
}

fn ec_point(p: &secp::ProjectivePoint) -> EcPointJson {
    let (x, y) = secp::coords(p);
    EcPointJson {
        curve: "secp256k1".into(),
        coords: [dec(&x), dec(&y)],
    }
}

/// Wraps a plain ECDSA private key `priv_d` (big-endian secret scalar) held by the
/// party identified by `party_key` (its `ShareID`/`KeyInt`, big-endian) as a
/// 1-of-1 [`Key`]. `Xi = priv_d mod q` must be non-zero.
pub fn import_key(priv_d: &[u8], party_key: &[u8]) -> Result<Key, Error> {
    let q = bn::secp256k1_order();
    let xi = bn::rem(&bn::from_be(priv_d), &q);
    if xi.is_zero() {
        return Err(Error::Validation(
            "import: private key is zero mod q".into(),
        ));
    }
    let share_id = bn::from_be(party_key);
    if share_id.is_zero() {
        return Err(Error::Validation("import: party key is empty".into()));
    }
    let pubp = secp::mul_base(&xi);

    Ok(Key {
        paillier_sk: PaillierSkJson {
            n: zero(),
            lambda_n: zero(),
            phi_n: zero(),
            p: zero(),
            q: zero(),
        },
        ntilde_i: zero(),
        h1i: zero(),
        h2i: zero(),
        alpha: zero(),
        beta: zero(),
        p: zero(),
        q: zero(),
        xi: dec(&xi),
        share_id: dec(&share_id),
        ks: vec![dec(&share_id)],
        ntilde_j: vec![zero()],
        h1j: vec![zero()],
        h2j: vec![zero()],
        big_xj: vec![ec_point(&pubp)],
        paillier_pks: vec![PaillierPkJson { n: zero() }],
        ecdsa_pub: ec_point(&pubp),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_wraps_plain_key() {
        // d = 0x42; party key = 5.
        let key = import_key(&[0x42], &[5]).unwrap();
        key.validate_basic().unwrap();
        assert_eq!(key.ks.len(), 1);
        // Xi = d mod q = 0x42; ECDSAPub = Xi·G = BigXj[0].
        assert_eq!(key.xi, BigUintDec::from_be_bytes(&[0x42]));
        assert_eq!(key.big_xj[0].coords, key.ecdsa_pub.coords);
        let pk = key.ecdsa_pub_point().unwrap();
        assert!(secp::eq(&pk, &secp::mul_base(&bn::from_be(&[0x42]))));
    }

    #[test]
    fn import_rejects_zero() {
        assert!(import_key(&[0], &[5]).is_err());
        assert!(import_key(&[0x42], &[]).is_err());
    }
}
