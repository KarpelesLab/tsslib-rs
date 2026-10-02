//! JSON save/load for a dklstss [`Key`] (save-format version 4). The format is
//! fixed: existing saved keys depend on it byte for byte.
//!
//! Layout (`{"format":"dklstss-key","version":4,...}`): scalars are bare decimal
//! numbers (arbitrary precision), curve points are
//! (`{"Curve":"secp256k1","Coords":[X,Y]}`), `chain_code` is base64, and each
//! peer's OT-extension state serializes its raw seeds as fixed-size byte arrays
//! — JSON arrays of byte-valued numbers:
//! `as_bob:{delta:[…],seeds:[[…]×κ]}`, `as_alice:{seeds0:[[…]×κ],seeds1:[[…]×κ]}`.

use super::Error;
use super::key::{Key, PairOTState};
use super::otext::{self, ExtReceiver, ExtSender};
use super::secp::{self, Scalar};
use crate::prelude::*;
use crate::tss::PartyId;
use crate::tss::bigint::BigUintDec;
use serde::{Deserialize, Serialize};

/// Save-format version.
pub const KEY_VERSION: u32 = 4;
const KEY_FORMAT_MAGIC: &str = "dklstss-key";
const CURVE_NAME: &str = "secp256k1";

impl Key {
    /// Serializes the key to JSON in the version-4 save format
    /// (unencrypted — the secret share and OT state are in cleartext; the caller
    /// is responsible for confidentiality).
    #[cfg(feature = "json")]
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&self.to_wire()?)?)
    }

    /// Parses a key in the JSON save format (versions 1–4).
    #[cfg(feature = "json")]
    pub fn from_json(s: &str) -> Result<Key, Error> {
        Key::from_wire(serde_json::from_str(s)?)
    }

    /// The save-format struct both encodings serialize.
    fn to_wire(&self) -> Result<KeyWire, Error> {
        self.validate_basic()?;
        let ot = self
            .ot
            .iter()
            .map(|p| p.as_ref().map(PairWire::from_state))
            .collect();
        let wire = KeyWire {
            format: KEY_FORMAT_MAGIC.to_string(),
            version: KEY_VERSION,
            curve: CURVE_NAME.to_string(),
            n: self.n,
            t: self.t,
            idx: self.idx,
            party_ids: self.party_ids.clone(),
            xi: scalar_to_biguint(&self.xi),
            big_xj: self
                .big_xj
                .iter()
                .map(point_to_ecjson)
                .collect::<Result<Vec<_>, _>>()?,
            ecdsa_pub: point_to_ecjson(&self.ecdsa_pub)?,
            ot,
            chain_code: B64Vec(self.chain_code.to_vec()),
        };
        Ok(wire)
    }

    /// Checks and converts a decoded save-format struct.
    fn from_wire(wire: KeyWire) -> Result<Key, Error> {
        if !matches!(wire.version, 1..=KEY_VERSION) {
            return Err(Error::Validation(format!(
                "unsupported key version {}",
                wire.version
            )));
        }
        if wire.version >= 4 && wire.format != KEY_FORMAT_MAGIC {
            return Err(Error::Validation(format!(
                "format magic mismatch: {:?}",
                wire.format
            )));
        }
        if !wire.curve.is_empty() && wire.curve != CURVE_NAME {
            return Err(Error::Validation(format!(
                "dklstss is secp256k1-only, got curve {:?}",
                wire.curve
            )));
        }
        let big_xj = wire
            .big_xj
            .iter()
            .map(ecjson_to_point)
            .collect::<Result<Vec<_>, _>>()?;
        let ot = wire
            .ot
            .into_iter()
            .map(|p| match p {
                None => Ok(None),
                Some(w) => Ok(Some(w.to_state()?)),
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut chain_code = [0u8; 32];
        if wire.chain_code.0.len() != 32 {
            return Err(Error::Validation("chain code must be 32 bytes".into()));
        }
        chain_code.copy_from_slice(&wire.chain_code.0);

        let key = Key {
            n: wire.n,
            t: wire.t,
            idx: wire.idx,
            party_ids: wire.party_ids,
            xi: biguint_to_scalar(&wire.xi)?,
            big_xj,
            ecdsa_pub: ecjson_to_point(&wire.ecdsa_pub)?,
            ot,
            chain_code,
        };
        key.validate_basic()?;
        Ok(key)
    }
}

// --- wire format -----------------------------------------------------------

crate::wire::key_codec!(Key, Error, KeyWire,
    to_wire: |k| k.to_wire(),
    from_wire: |w| Key::from_wire(w),
);

#[derive(Serialize, Deserialize)]
struct KeyWire {
    #[serde(default)]
    format: String,
    version: u32,
    #[serde(default)]
    curve: String,
    n: usize,
    t: usize,
    idx: usize,
    party_ids: Vec<PartyId>,
    xi: BigUintDec,
    big_xj: Vec<EcPointJson>,
    ecdsa_pub: EcPointJson,
    ot: Vec<Option<PairWire>>,
    chain_code: B64Vec,
}

/// A `crypto.ECPoint` (`{"Curve","Coords":[X,Y]}`).
#[derive(Serialize, Deserialize)]
struct EcPointJson {
    #[serde(rename = "Curve")]
    curve: String,
    #[serde(rename = "Coords")]
    coords: [BigUintDec; 2],
}

#[derive(Serialize, Deserialize)]
struct PairWire {
    as_alice: ExtReceiverWire,
    as_bob: ExtSenderWire,
}

/// `[Kappa][KeyLen]` / `[DeltaBytes]` byte arrays, serialized as arrays of numbers.
#[derive(Serialize, Deserialize)]
struct ExtSenderWire {
    delta: Vec<u8>,
    seeds: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct ExtReceiverWire {
    seeds0: Vec<Vec<u8>>,
    seeds1: Vec<Vec<u8>>,
}

impl PairWire {
    fn from_state(s: &PairOTState) -> PairWire {
        // ExtSender.to_bytes() = delta || seeds; ExtReceiver = seeds0 || seeds1.
        let sb = s.as_bob.to_bytes();
        let (delta, seeds) = sb.split_at(otext::DELTA_BYTES);
        let rb = s.as_alice.to_bytes();
        let half = otext::KAPPA * otext::SEED_LEN;
        PairWire {
            as_alice: ExtReceiverWire {
                seeds0: chunk(&rb[..half]),
                seeds1: chunk(&rb[half..]),
            },
            as_bob: ExtSenderWire {
                delta: delta.to_vec(),
                seeds: chunk(seeds),
            },
        }
    }

    fn to_state(&self) -> Result<PairOTState, Error> {
        let mut sb = Vec::with_capacity(otext::DELTA_BYTES + otext::KAPPA * otext::SEED_LEN);
        sb.extend_from_slice(&self.as_bob.delta);
        for s in &self.as_bob.seeds {
            sb.extend_from_slice(s);
        }
        let mut rb = Vec::with_capacity(2 * otext::KAPPA * otext::SEED_LEN);
        for s in self
            .as_alice
            .seeds0
            .iter()
            .chain(self.as_alice.seeds1.iter())
        {
            rb.extend_from_slice(s);
        }
        Ok(PairOTState {
            as_alice: ExtReceiver::from_bytes(&rb)?,
            as_bob: ExtSender::from_bytes(&sb)?,
        })
    }
}

fn chunk(b: &[u8]) -> Vec<Vec<u8>> {
    b.chunks(otext::SEED_LEN).map(|c| c.to_vec()).collect()
}

// --- point <-> ECPoint JSON ------------------------------------------------

fn point_to_ecjson(p: &secp::ProjectivePoint) -> Result<EcPointJson, Error> {
    let (x, y) = secp::affine_be(p);
    if x.is_empty() && y.is_empty() {
        return Err(Error::Validation("cannot encode identity point".into()));
    }
    Ok(EcPointJson {
        curve: CURVE_NAME.to_string(),
        coords: [BigUintDec::from_be_bytes(&x), BigUintDec::from_be_bytes(&y)],
    })
}

fn ecjson_to_point(j: &EcPointJson) -> Result<secp::ProjectivePoint, Error> {
    if !j.curve.is_empty() && j.curve != CURVE_NAME {
        return Err(Error::Validation(format!("unexpected curve {:?}", j.curve)));
    }
    let x = j.coords[0].to_be_bytes_padded(32);
    let y = j.coords[1].to_be_bytes_padded(32);
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..65].copy_from_slice(&y);
    secp::from_sec1(&sec1).ok_or_else(|| Error::Validation("invalid curve point".into()))
}

// --- base64 byte slice -----------------------------------------------------

struct B64Vec(Vec<u8>);

impl Serialize for B64Vec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        crate::tss::b64::vec::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for B64Vec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<B64Vec, D::Error> {
        crate::tss::b64::vec::deserialize(d).map(B64Vec)
    }
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

#[cfg(all(test, feature = "json"))]
mod tests {
    use super::super::keygen::keygen;
    use super::super::signing::sign;
    use super::*;
    use crate::rng::SystemRng;
    use purecrypto::hash::sha256;

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
        let keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        let loaded: Vec<Key> = keys
            .iter()
            .map(|k| Key::from_json(&k.to_json().unwrap()).unwrap())
            .collect();
        for (a, b) in keys.iter().zip(loaded.iter()) {
            assert!(bool::from(a.xi.ct_eq(&b.xi)));
            assert!(secp::point_eq(&a.ecdsa_pub, &b.ecdsa_pub));
            assert_eq!(a.chain_code, b.chain_code);
            // OT state survives the structured round-trip.
            for (oa, ob) in a.ot.iter().zip(b.ot.iter()) {
                match (oa, ob) {
                    (Some(x), Some(y)) => {
                        assert_eq!(x.as_bob.to_bytes(), y.as_bob.to_bytes());
                        assert_eq!(x.as_alice.to_bytes(), y.as_alice.to_bytes());
                    }
                    (None, None) => {}
                    _ => panic!("OT slot mismatch"),
                }
            }
        }
        let msg = sha256(b"reloaded sign");
        let sig = sign(&loaded, &[0, 2], &msg, &mut SystemRng).unwrap();
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

    #[test]
    fn save_format_shape_is_stable() {
        let ids = party_ids(2);
        let keys = keygen(2, 1, &ids, &mut SystemRng).unwrap();
        let v: serde_json::Value = serde_json::from_str(&keys[0].to_json().unwrap()).unwrap();
        assert_eq!(v["format"], "dklstss-key");
        assert_eq!(v["version"], 4);
        assert_eq!(v["curve"], "secp256k1");
        assert_eq!(v["ecdsa_pub"]["Curve"], "secp256k1");
        assert!(v["ecdsa_pub"]["Coords"][0].is_number());
        assert!(v["xi"].is_number());
        assert!(v["chain_code"].is_string()); // base64
        // OT seeds are arrays of byte-numbers (fixed-size byte arrays).
        let ot = &v["ot"].as_array().unwrap();
        let bob = ot.iter().find(|o| !o.is_null()).unwrap();
        assert!(bob["as_bob"]["delta"].is_array());
        assert!(bob["as_bob"]["delta"][0].is_number());
        assert!(bob["as_bob"]["seeds"][0].is_array());
        assert!(bob["as_alice"]["seeds0"][0].is_array());
    }
}

#[cfg(all(test, feature = "json"))]
mod fixture_tests {
    use super::super::signing::{self, sign};
    use super::*;
    use crate::rng::SystemRng;
    use purecrypto::hash::sha256;

    /// Loads the frozen DKLs23 fixture keys (3-party, t=1) and signs.
    #[test]
    fn fixture_keys_load_and_sign() {
        let raw = include_str!("testdata/dkls.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let keys: Vec<Key> = doc["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Key::from_json(&serde_json::to_string(v).unwrap()).expect("load fixture key"))
            .collect();
        assert_eq!(keys.len(), 3);
        for k in &keys {
            k.validate_basic().unwrap();
            assert!(secp::point_eq(&k.ecdsa_pub, &keys[0].ecdsa_pub));
        }

        // Re-saving a fixture key and re-loading it is lossless (the writer
        // emits the same v4 format it reads): OT state, points, and chain code
        // survive.
        for k in &keys {
            let re = Key::from_json(&k.to_json().unwrap()).unwrap();
            assert!(secp::point_eq(&re.ecdsa_pub, &k.ecdsa_pub));
            assert_eq!(re.chain_code, k.chain_code);
            for (a, b) in re.ot.iter().zip(k.ot.iter()) {
                match (a, b) {
                    (Some(x), Some(y)) => {
                        assert_eq!(x.as_bob.to_bytes(), y.as_bob.to_bytes());
                        assert_eq!(x.as_alice.to_bytes(), y.as_alice.to_bytes());
                    }
                    (None, None) => {}
                    _ => panic!("OT slot mismatch after re-save"),
                }
            }
        }

        // Sign with parties 0 and 1 using the loaded fixture keys + restored OT state.
        let msg = sha256(b"fixture dkls key signs");
        let sig = sign(&keys, &[0, 1], &msg, &mut SystemRng).expect("sign with fixture keys");
        let e = signing::hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(signing::ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
    }
}

#[cfg(test)]
mod binary_tests {
    use super::super::keygen::keygen;
    use super::super::signing::{self, sign};
    use super::*;
    use crate::rng::SystemRng;
    use purecrypto::hash::sha256;

    #[test]
    fn key_binary_roundtrip_then_sign() {
        let ids: Vec<PartyId> = PartyId::sort(
            (1..=3u8)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i]))
                .collect(),
            0,
        );
        let keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        let loaded: Vec<Key> = keys
            .iter()
            .map(|k| Key::from_bytes(&k.to_bytes().unwrap()).unwrap())
            .collect();
        for (a, b) in keys.iter().zip(&loaded) {
            assert!(bool::from(a.xi.ct_eq(&b.xi)));
            assert_eq!(a.chain_code, b.chain_code);
            #[cfg(feature = "json")]
            assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
        }
        let bytes = keys[0].to_bytes().unwrap();
        assert!(Key::from_bytes(&bytes[..bytes.len() - 1]).is_err());

        let msg = sha256(b"binary reload sign");
        let sig = sign(&loaded, &[0, 2], &msg, &mut SystemRng).unwrap();
        let e = signing::hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(signing::ecdsa_verify(&loaded[0].ecdsa_pub, &e, &r, &s));
    }
}
