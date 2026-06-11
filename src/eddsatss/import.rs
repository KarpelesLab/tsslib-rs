//! Importing a plain Ed25519 private key as a 1-of-1 [`Key`] — the migration
//! entry point. Port of Go `eddsatss/import.go`.

#![allow(dead_code)]

use super::ed::{self, EcPointJson};
use super::key::Key;
use super::{Error, ed::point_to_json};
use crate::tss::bigint::BigUintDec;

/// Wraps a plain Ed25519 secret scalar `priv_be` (big-endian) held by the party
/// identified by `party_key` (its `ShareID`, big-endian) as a 1-of-1 [`Key`].
pub fn import_key(priv_be: &[u8], party_key: &[u8]) -> Result<Key, Error> {
    let xi = ed::scalar_from_be(priv_be);
    if bool::from(xi.ct_eq(&purecrypto::ec::edwards25519::hazmat::Scalar::ZERO)) {
        return Err(Error::Validation(
            "import: private key is zero mod L".into(),
        ));
    }
    if party_key.iter().all(|&b| b == 0) {
        return Err(Error::Validation("import: party key is empty".into()));
    }
    let pubp = ed::mul_base(&xi);
    let pub_json: EcPointJson = point_to_json(&pubp);

    Ok(Key {
        xi: BigUintDec::from_be_bytes(&ed::scalar_to_be(&xi)),
        share_id: BigUintDec::from_be_bytes(party_key),
        ks: vec![BigUintDec::from_be_bytes(party_key)],
        big_xj: vec![pub_json.clone()],
        eddsa_pub: pub_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_wraps_plain_key() {
        let key = import_key(&[0x42], &[5]).unwrap();
        key.validate_basic().unwrap();
        assert_eq!(key.ks.len(), 1);
        assert_eq!(key.big_xj[0].coords, key.eddsa_pub.coords);
        let pk = key.eddsa_pub_point().unwrap();
        assert!(ed::eq(&pk, &ed::mul_base(&ed::scalar_from_be(&[0x42]))));
    }

    #[test]
    fn import_rejects_zero() {
        assert!(import_key(&[0], &[5]).is_err());
        assert!(import_key(&[0x42], &[]).is_err());
    }
}
