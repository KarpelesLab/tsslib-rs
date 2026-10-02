//! A participant's FROST(secp256k1) key share and its JSON form.
//!
//! JSON shape: `Xi`, `ShareID` and `Ks` as bare JSON decimal numbers
//! (`tss::bigint`), group elements as base64 33-byte SEC1
//! compressed, and `ChainCode` as base64.

use super::Error;
use super::suite::{
    Point, Scalar, decode_point, encode_point, id_scalar, is_identity, mul_base, point_eq, x_only,
};
use crate::prelude::*;
use crate::tss::PartyId;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use serde::{Deserialize, Serialize};

/// Schema version of a [`Key`].
pub const KEY_VERSION: u32 = 1;

/// One participant's share of a FROST(secp256k1) key.
///
/// The group key is stored as a full point, with whatever `Y` parity keygen
/// produced; BIP340's even-`Y` convention is applied when signing, so the
/// usable x-only key is [`Key::x_only_public_key`].
#[derive(Clone)]
pub struct Key {
    /// Secret share `s_i`.
    pub xi: Scalar,
    /// This participant's identifier (`= PartyId.key`).
    pub share_id: BigUintDec,
    /// Identifiers of all participants holding shares, in keygen order.
    pub ks: Vec<BigUintDec>,
    /// Verification shares `Y_j = s_j·G`, aligned with `ks`.
    pub big_xj: Vec<Point>,
    /// Group public key `P`.
    pub group_public_key: Point,
    /// BIP32 chain code for non-hardened derivation from `P`.
    pub chain_code: [u8; 32],
}

impl Key {
    /// The BIP340 x-only public key (the x coordinate of `P`).
    pub fn x_only_public_key(&self) -> [u8; 32] {
        x_only(&self.group_public_key).expect("validated key is not the identity")
    }

    /// The 33-byte SEC1 compressed group public key.
    pub fn compressed_public_key(&self) -> [u8; 33] {
        encode_point(&self.group_public_key).expect("validated key is not the identity")
    }

    /// Checks internal consistency: aligned non-empty `ks`/`big_xj`, a
    /// non-identity group key, `ShareID` present in `ks`, `xi·G` equal to this
    /// party's verification share, and every `ks` entry a distinct non-zero
    /// identifier.
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
        if is_identity(&self.group_public_key) {
            return Err(Error::Validation("GroupPublicKey is the identity".into()));
        }
        let ids: Vec<Vec<u8>> = self.ks.iter().map(|k| k.as_be_bytes().to_vec()).collect();
        for (i, id) in ids.iter().enumerate() {
            let x = id_scalar(id);
            if bool::from(x.is_zero())
                || ids[..i].iter().any(|y| bool::from(id_scalar(y).ct_eq(&x)))
            {
                return Err(Error::Validation(
                    "Ks has a zero or duplicate identifier".into(),
                ));
            }
        }
        let my_idx = self
            .ks
            .iter()
            .position(|k| k == &self.share_id)
            .ok_or_else(|| Error::Validation("ShareID not found in Ks".into()))?;
        if !point_eq(&mul_base(&self.xi), &self.big_xj[my_idx]) {
            return Err(Error::Validation(
                "Xi·G does not equal this party's BigXj entry".into(),
            ));
        }
        Ok(())
    }

    /// Reorders `ks`/`big_xj` to match `sorted_ids`.
    pub fn subset_for_parties(&self, sorted_ids: &[PartyId]) -> Result<Key, Error> {
        let mut ks = Vec::with_capacity(sorted_ids.len());
        let mut big_xj = Vec::with_capacity(sorted_ids.len());
        for id in sorted_ids {
            let want = strip(&id.key);
            let saved = self
                .ks
                .iter()
                .position(|k| k.as_be_bytes() == want)
                .ok_or_else(|| Error::Validation(format!("party {id} not in this key's Ks")))?;
            ks.push(self.ks[saved].clone());
            big_xj.push(self.big_xj[saved]);
        }
        Ok(Key {
            ks,
            big_xj,
            ..self.clone()
        })
    }

    /// Serializes the key to JSON.
    #[cfg(feature = "json")]
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&KeyWire::from_key(self))?)
    }

    /// Parses and validates a key from JSON.
    #[cfg(feature = "json")]
    pub fn from_json(s: &str) -> Result<Key, Error> {
        let key = serde_json::from_str::<KeyWire>(s)?.into_key()?;
        key.validate_basic()?;
        Ok(key)
    }

    /// Overwrites the secret share with zero.
    pub fn zeroize(&mut self) {
        self.xi = Scalar::ZERO;
    }
}

crate::wire::key_codec!(Key, Error, KeyWire,
    to_wire: |k| Ok::<_, Error>(KeyWire::from_key(k)),
    from_wire: |w| {
        let key = w.into_key()?;
        key.validate_basic()?;
        Ok(key)
    },
);

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
    #[serde(rename = "ChainCode")]
    chain_code: B64Bytes,
}

impl KeyWire {
    fn from_key(k: &Key) -> Self {
        let enc = |p: &Point| B64Bytes(encode_point(p).map(|b| b.to_vec()).unwrap_or_default());
        KeyWire {
            xi: BigUintDec::from_be_bytes(&k.xi.to_bytes_be()),
            share_id: k.share_id.clone(),
            ks: k.ks.clone(),
            big_xj: k.big_xj.iter().map(enc).collect(),
            group_public_key: enc(&k.group_public_key),
            chain_code: B64Bytes(k.chain_code.to_vec()),
        }
    }

    fn into_key(self) -> Result<Key, Error> {
        let dec = |b: &B64Bytes| {
            decode_point(&b.0).ok_or_else(|| Error::Validation("invalid group element".into()))
        };
        if self.xi.as_be_bytes().len() > 32 {
            return Err(Error::Validation("Xi >= n".into()));
        }
        let xi_be: [u8; 32] = self.xi.to_be_bytes_padded(32).try_into().unwrap();
        Ok(Key {
            xi: Scalar::from_bytes_be(&xi_be).map_err(|_| Error::Validation("Xi >= n".into()))?,
            share_id: self.share_id,
            ks: self.ks,
            big_xj: self.big_xj.iter().map(dec).collect::<Result<_, _>>()?,
            group_public_key: dec(&self.group_public_key)?,
            chain_code: self
                .chain_code
                .0
                .try_into()
                .map_err(|_| Error::Validation("ChainCode must be 32 bytes".into()))?,
        })
    }
}

pub(crate) fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_party_key(secret: u8) -> Key {
        let xi = id_scalar(&[secret]);
        let pk = mul_base(&xi);
        Key {
            xi,
            share_id: BigUintDec::from_be_bytes(&[1]),
            ks: vec![BigUintDec::from_be_bytes(&[1])],
            big_xj: vec![pk],
            group_public_key: pk,
            chain_code: [5; 32],
        }
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_roundtrip() {
        let k = single_party_key(9);
        let s = k.to_json().unwrap();
        let back = Key::from_json(&s).unwrap();
        assert!(bool::from(k.xi.ct_eq(&back.xi)));
        assert!(point_eq(&k.group_public_key, &back.group_public_key));
        assert_eq!(back.chain_code, [5; 32]);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["Xi"].is_number());
        assert!(v["GroupPublicKey"].is_string());
    }

    #[test]
    fn validate_rejects_broken_binding_and_duplicate_ids() {
        let mut k = single_party_key(7);
        k.big_xj[0] = mul_base(&Scalar::ONE);
        assert!(k.validate_basic().is_err());

        let mut k = single_party_key(7);
        k.ks.push(BigUintDec::from_be_bytes(&[1]));
        k.big_xj.push(k.big_xj[0]);
        assert!(k.validate_basic().is_err());
    }

    #[cfg(feature = "json")]
    #[test]
    fn from_json_rejects_out_of_range_xi() {
        let mut v: serde_json::Value =
            serde_json::from_str(&single_party_key(3).to_json().unwrap()).unwrap();
        // n, which is not a valid scalar.
        let n = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
        v["Xi"] = serde_json::Value::Number(n.parse().unwrap());
        assert!(Key::from_json(&v.to_string()).is_err());
    }

    #[test]
    fn binary_roundtrip() {
        let k = single_party_key(9);
        let bytes = k.to_bytes().unwrap();
        let back = Key::from_bytes(&bytes).unwrap();
        back.validate_basic().unwrap();
        assert!(bool::from(k.xi.ct_eq(&back.xi)));
        assert!(point_eq(&k.group_public_key, &back.group_public_key));
        assert!(Key::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[cfg(feature = "json")]
    #[test]
    fn binary_preserves_everything_json_does() {
        let k = single_party_key(11);
        let back = Key::from_bytes(&k.to_bytes().unwrap()).unwrap();
        assert_eq!(back.to_json().unwrap(), k.to_json().unwrap());
    }
}
