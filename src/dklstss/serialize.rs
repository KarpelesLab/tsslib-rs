//! JSON save/load for a dklstss [`Key`].
//!
//! This is a Rust-native format (not yet byte-compatible with the Go library's
//! OT-state encoding): scalars are bare decimal numbers, points are base64
//! SEC1-compressed, and each peer's OT-extension state is a base64 seed blob.

use super::Error;
use super::key::{Key, PairOTState};
use super::otext::{ExtReceiver, ExtSender};
use super::secp::{self, Scalar};
use crate::tss::PartyId;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use serde::{Deserialize, Serialize};

/// Save-format version.
pub const KEY_VERSION: u32 = 1;

impl Key {
    /// Serializes the key to JSON (unencrypted — the secret share and OT state
    /// are in cleartext; the caller is responsible for confidentiality).
    pub fn to_json(&self) -> Result<String, Error> {
        self.validate_basic()?;
        let ot = self
            .ot
            .iter()
            .map(|p| {
                p.as_ref().map(|s| PairWire {
                    as_alice: B64Bytes(s.as_alice.to_bytes()),
                    as_bob: B64Bytes(s.as_bob.to_bytes()),
                })
            })
            .collect();
        let wire = KeyWire {
            version: KEY_VERSION,
            n: self.n,
            t: self.t,
            idx: self.idx,
            party_ids: self.party_ids.clone(),
            xi: scalar_to_biguint(&self.xi),
            big_xj: self
                .big_xj
                .iter()
                .map(|p| Ok::<_, Error>(B64Bytes(sec1(p)?)))
                .collect::<Result<Vec<_>, _>>()?,
            ecdsa_pub: B64Bytes(sec1(&self.ecdsa_pub)?),
            ot,
            chain_code: self.chain_code.to_vec(),
        };
        Ok(serde_json::to_string(&wire)?)
    }

    /// Parses a key previously produced by [`Key::to_json`].
    pub fn from_json(s: &str) -> Result<Key, Error> {
        let wire: KeyWire = serde_json::from_str(s)?;
        if wire.version != KEY_VERSION {
            return Err(Error::Validation(format!(
                "unsupported key version {}",
                wire.version
            )));
        }
        let big_xj = wire
            .big_xj
            .iter()
            .map(|b| {
                secp::from_sec1(&b.0).ok_or_else(|| Error::Validation("invalid BigXj point".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ot = wire
            .ot
            .into_iter()
            .map(|p| match p {
                None => Ok(None),
                Some(w) => Ok(Some(PairOTState {
                    as_alice: ExtReceiver::from_bytes(&w.as_alice.0)?,
                    as_bob: ExtSender::from_bytes(&w.as_bob.0)?,
                })),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut chain_code = [0u8; 32];
        if wire.chain_code.len() != 32 {
            return Err(Error::Validation("chain code must be 32 bytes".into()));
        }
        chain_code.copy_from_slice(&wire.chain_code);

        let key = Key {
            n: wire.n,
            t: wire.t,
            idx: wire.idx,
            party_ids: wire.party_ids,
            xi: biguint_to_scalar(&wire.xi)?,
            big_xj,
            ecdsa_pub: secp::from_sec1(&wire.ecdsa_pub.0)
                .ok_or_else(|| Error::Validation("invalid ECDSAPub point".into()))?,
            ot,
            chain_code,
        };
        key.validate_basic()?;
        Ok(key)
    }
}

#[derive(Serialize, Deserialize)]
struct KeyWire {
    version: u32,
    n: usize,
    t: usize,
    idx: usize,
    party_ids: Vec<PartyId>,
    xi: BigUintDec,
    big_xj: Vec<B64Bytes>,
    ecdsa_pub: B64Bytes,
    ot: Vec<Option<PairWire>>,
    #[serde(with = "crate::tss::b64::vec")]
    chain_code: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PairWire {
    as_alice: B64Bytes,
    as_bob: B64Bytes,
}

fn sec1(p: &secp::ProjectivePoint) -> Result<Vec<u8>, Error> {
    Ok(secp::to_sec1_compressed(p)
        .ok_or_else(|| Error::Validation("cannot encode identity point".into()))?
        .to_vec())
}

fn scalar_to_biguint(s: &Scalar) -> BigUintDec {
    BigUintDec::from_be_bytes(&s.to_bytes_be())
}

fn biguint_to_scalar(v: &BigUintDec) -> Result<Scalar, Error> {
    let be = v.to_be_bytes_padded(32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&be);
    Scalar::from_bytes_be(&arr).map_err(|_| Error::Validation("Xi >= n".into()))
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
    fn key_json_roundtrip_then_sign() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        // Round-trip every key through JSON.
        let loaded: Vec<Key> = keys
            .iter()
            .map(|k| Key::from_json(&k.to_json().unwrap()).unwrap())
            .collect();
        for (a, b) in keys.iter().zip(loaded.iter()) {
            assert!(bool::from(a.xi.ct_eq(&b.xi)));
            assert!(secp::point_eq(&a.ecdsa_pub, &b.ecdsa_pub));
            assert_eq!(a.chain_code, b.chain_code);
        }
        // The reloaded keys (with restored OT state) still sign.
        let msg = sha256(b"reloaded sign");
        let sig = sign(&loaded, &[0, 2], &msg, &mut OsRng).unwrap();
        let e = super::super::signing::hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(super::super::signing::ecdsa_verify(
            &loaded[0].ecdsa_pub,
            &e,
            &r,
            &s
        ));
    }
}
