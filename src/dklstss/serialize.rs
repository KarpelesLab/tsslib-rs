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
use zeroize::{Zeroize, Zeroizing};

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
        Ok(serde_json::to_string(&self.to_wire(true)?)?)
    }

    /// Parses a key in the JSON save format (versions 1–4).
    #[cfg(feature = "json")]
    pub fn from_json(s: &str) -> Result<Key, Error> {
        Key::from_wire(serde_json::from_str(s)?)
    }

    /// Writes the key's **core** in the compact binary encoding: everything
    /// but the pairwise OT-extension states (the share, joint public key,
    /// chain code, parties and their public shares). It is a few hundred bytes
    /// against roughly 12.8 KB per peer for the pairwise states, which can be
    /// stored separately with [`PairOTState::write_to`].
    ///
    /// The core is an ordinary key encoding with no pairs loaded, so
    /// [`Key::read_from`] / [`Key::from_bytes`] read it back; restore the
    /// pairs with [`Key::set_pair`], or rebuild a lost one with a
    /// `PairSetupParty`. Like [`Key::write_to`], the
    /// output holds the secret share in the clear.
    pub fn write_core_to<W: crate::wire::Write>(&self, w: &mut W) -> Result<(), Error> {
        crate::wire::write_key(&self.to_wire(false)?, w)?;
        Ok(())
    }

    /// The key's core (see [`Key::write_core_to`]) as a new buffer.
    pub fn core_to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(crate::wire::key_to_vec(&self.to_wire(false)?)?)
    }

    /// The save-format struct both encodings serialize, borrowing the OT
    /// seeds rather than copying them. With `include_pairs` false every
    /// pairwise slot is written as absent (the key core).
    fn to_wire(&self, include_pairs: bool) -> Result<KeyWire<PairWireRef<'_>>, Error> {
        self.validate_basic()?;
        let ot = self
            .ot
            .iter()
            .map(|p| p.as_ref().filter(|_| include_pairs).map(PairWireRef::new))
            .collect();
        let wire = KeyWire {
            format: KEY_FORMAT_MAGIC.to_string(),
            version: KEY_VERSION,
            curve: CURVE_NAME.to_string(),
            n: self.n,
            t: self.t,
            idx: self.idx,
            party_ids: self.party_ids.clone(),
            xi: SecretDec(scalar_to_biguint(&self.xi)),
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
    fn from_wire(wire: KeyWire<PairWire>) -> Result<Key, Error> {
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
            .map(|p| p.as_ref().map(PairWire::to_state).transpose())
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
            xi: biguint_to_scalar(&wire.xi.0)?,
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

crate::wire::key_codec!(Key, Error, KeyWire<PairWire>,
    to_wire: |k| k.to_wire(true),
    from_wire: |w| Key::from_wire(w),
);

crate::wire::key_codec!(PairOTState, Error, PairWire,
    to_wire: |p| Ok::<_, Error>(PairWireRef::new(p)),
    from_wire: |w| w.to_state(),
);

/// The save format. `P` is [`PairWireRef`] when writing (borrowing the live
/// seeds) and [`PairWire`] when reading; both encode identically.
#[derive(Serialize, Deserialize)]
struct KeyWire<P> {
    #[serde(default)]
    format: String,
    version: u32,
    #[serde(default)]
    curve: String,
    n: usize,
    t: usize,
    idx: usize,
    party_ids: Vec<PartyId>,
    xi: SecretDec,
    big_xj: Vec<EcPointJson>,
    ecdsa_pub: EcPointJson,
    ot: Vec<Option<P>>,
    chain_code: B64Vec,
}

/// The secret share's encoding, wiped when dropped.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SecretDec(BigUintDec);

impl Drop for SecretDec {
    fn drop(&mut self) {
        self.0.0.zeroize();
    }
}

/// A `crypto.ECPoint` (`{"Curve","Coords":[X,Y]}`).
#[derive(Serialize, Deserialize)]
struct EcPointJson {
    #[serde(rename = "Curve")]
    curve: String,
    #[serde(rename = "Coords")]
    coords: [BigUintDec; 2],
}

// A peer's OT-extension state: `as_alice:{seeds0,seeds1}`, `as_bob:{delta,seeds}`,
// each `[N]byte` a sequence of byte values (JSON arrays of numbers).

/// Writes one pair's state straight from the live [`PairOTState`].
#[derive(Serialize)]
struct PairWireRef<'a> {
    as_alice: ExtReceiverRef<'a>,
    as_bob: ExtSenderRef<'a>,
}

#[derive(Serialize)]
struct ExtReceiverRef<'a> {
    seeds0: SeedsRef<'a>,
    seeds1: SeedsRef<'a>,
}

#[derive(Serialize)]
struct ExtSenderRef<'a> {
    delta: BytesRef<'a>,
    seeds: SeedsRef<'a>,
}

impl<'a> PairWireRef<'a> {
    fn new(s: &'a PairOTState) -> PairWireRef<'a> {
        let (seeds0, seeds1) = s.as_alice.seeds();
        PairWireRef {
            as_alice: ExtReceiverRef {
                seeds0: SeedsRef(seeds0),
                seeds1: SeedsRef(seeds1),
            },
            as_bob: ExtSenderRef {
                delta: BytesRef(&s.as_bob.delta_ref()[..]),
                seeds: SeedsRef(s.as_bob.seeds()),
            },
        }
    }
}

/// Reads one pair's state into fixed-size storage that is wiped on drop.
#[derive(Deserialize)]
struct PairWire {
    as_alice: ExtReceiverWire,
    as_bob: ExtSenderWire,
}

#[derive(Deserialize)]
struct ExtReceiverWire {
    seeds0: Seeds,
    seeds1: Seeds,
}

#[derive(Deserialize)]
struct ExtSenderWire {
    delta: Bytes<{ otext::DELTA_BYTES }>,
    seeds: Seeds,
}

impl PairWire {
    fn to_state(&self) -> Result<PairOTState, Error> {
        Ok(PairOTState {
            as_alice: ExtReceiver::from_base(
                &self.as_alice.seeds0.0[..],
                &self.as_alice.seeds1.0[..],
            )?,
            as_bob: ExtSender::from_base(&self.as_bob.delta.0, &self.as_bob.seeds.0[..])?,
        })
    }
}

/// Serializes bytes as a sequence of byte values (as serde does `Vec<u8>`).
struct BytesRef<'a>(&'a [u8]);

impl Serialize for BytesRef<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for b in self.0 {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

/// Serializes κ seeds as a sequence of byte sequences (as `Vec<Vec<u8>>`).
struct SeedsRef<'a>(&'a [[u8; otext::SEED_LEN]]);

impl Serialize for SeedsRef<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for seed in self.0 {
            seq.serialize_element(&BytesRef(seed))?;
        }
        seq.end()
    }
}

/// Exactly `N` bytes read from a sequence of byte values; wiped on drop.
struct Bytes<const N: usize>([u8; N]);

impl<const N: usize> Drop for Bytes<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const N: usize>;
        impl<'de, const N: usize> serde::de::Visitor<'de> for V<N> {
            type Value = Bytes<N>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{N} bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Bytes<N>, A::Error> {
                let mut out = Bytes([0u8; N]);
                for (i, b) in out.0.iter_mut().enumerate() {
                    *b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(N + 1, &self));
                }
                Ok(out)
            }
        }
        d.deserialize_seq(V::<N>)
    }
}

/// Exactly κ seeds, read into one allocation of fixed size; wiped on drop.
struct Seeds(Box<[[u8; otext::SEED_LEN]; otext::KAPPA]>);

impl Drop for Seeds {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for Seeds {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Seeds;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{} seeds of {} bytes", otext::KAPPA, otext::SEED_LEN)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Seeds, A::Error> {
                let mut out = Seeds(Box::new([[0u8; otext::SEED_LEN]; otext::KAPPA]));
                for i in 0..otext::KAPPA {
                    let seed: Bytes<{ otext::SEED_LEN }> = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    out.0[i] = seed.0;
                }
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(otext::KAPPA + 1, &self));
                }
                Ok(out)
            }
        }
        d.deserialize_seq(V)
    }
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
    let be = Zeroizing::new(v.to_be_bytes_padded(32));
    let mut arr = Zeroizing::new([0u8; 32]);
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

#[cfg(test)]
mod split_tests {
    use super::super::keygen::keygen;
    use super::super::signing::{self, sign};
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

    fn assert_signs(keys: &[Key], signers: &[usize], msg: &[u8]) {
        let hash = sha256(msg);
        let sig = sign(keys, signers, &hash, &mut SystemRng).unwrap();
        let e = signing::hash_to_scalar(&hash);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(signing::ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
    }

    /// The pre-split layout of one pair: `Vec<u8>` / `Vec<Vec<u8>>` fields.
    #[derive(Serialize)]
    struct LegacyPair {
        as_alice: LegacyRcv,
        as_bob: LegacySnd,
    }
    #[derive(Serialize)]
    struct LegacyRcv {
        seeds0: Vec<Vec<u8>>,
        seeds1: Vec<Vec<u8>>,
    }
    #[derive(Serialize)]
    struct LegacySnd {
        delta: Vec<u8>,
        seeds: Vec<Vec<u8>>,
    }

    fn legacy(p: &PairOTState) -> LegacyPair {
        let chunk =
            |b: &[u8]| -> Vec<Vec<u8>> { b.chunks(otext::SEED_LEN).map(|c| c.to_vec()).collect() };
        let sb = p.as_bob.to_bytes();
        let rb = p.as_alice.to_bytes();
        let half = otext::KAPPA * otext::SEED_LEN;
        LegacyPair {
            as_alice: LegacyRcv {
                seeds0: chunk(&rb[..half]),
                seeds1: chunk(&rb[half..]),
            },
            as_bob: LegacySnd {
                delta: sb[..otext::DELTA_BYTES].to_vec(),
                seeds: chunk(&sb[otext::DELTA_BYTES..]),
            },
        }
    }

    #[test]
    fn pair_encoding_matches_legacy_layout() {
        let keys = keygen(2, 1, &party_ids(2), &mut SystemRng).unwrap();
        let pair = keys[0].ot[1].as_ref().unwrap();
        let bytes = pair.to_bytes().unwrap();
        assert_eq!(bytes[0], crate::wire::KEY_ENCODING_VERSION);
        assert_eq!(&bytes[1..], crate::wire::to_vec(&legacy(pair)).unwrap());
        #[cfg(feature = "json")]
        assert_eq!(
            serde_json::to_string(&PairWireRef::new(pair)).unwrap(),
            serde_json::to_string(&legacy(pair)).unwrap()
        );
        let back = PairOTState::from_bytes(&bytes).unwrap();
        assert_eq!(back.as_bob.to_bytes(), pair.as_bob.to_bytes());
        assert_eq!(back.as_alice.to_bytes(), pair.as_alice.to_bytes());
        assert!(PairOTState::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn pair_decoding_rejects_wrong_sizes() {
        let keys = keygen(2, 1, &party_ids(2), &mut SystemRng).unwrap();
        let mut l = legacy(keys[0].ot[1].as_ref().unwrap());
        l.as_alice.seeds0.pop();
        l.as_alice.seeds1.push(vec![7; otext::SEED_LEN]);
        let mut bytes = vec![crate::wire::KEY_ENCODING_VERSION];
        bytes.extend(crate::wire::to_vec(&l).unwrap());
        assert!(PairOTState::from_bytes(&bytes).is_err());

        let mut l = legacy(keys[0].ot[1].as_ref().unwrap());
        l.as_bob.seeds[3].push(0);
        let mut bytes = vec![crate::wire::KEY_ENCODING_VERSION];
        bytes.extend(crate::wire::to_vec(&l).unwrap());
        assert!(PairOTState::from_bytes(&bytes).is_err());
    }

    #[test]
    fn core_and_pairs_roundtrip_then_sign() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        let full = keys[0].to_bytes().unwrap();
        let core = keys[0].core_to_bytes().unwrap();
        let mut via_writer = Vec::new();
        keys[0].write_core_to(&mut via_writer).unwrap();
        assert_eq!(core, via_writer);
        assert!(core.len() < 1024, "core is {} bytes", core.len());

        let mut loaded = Key::from_bytes(&core).unwrap();
        assert!(loaded.ot.iter().all(Option::is_none));
        assert_eq!(
            loaded.missing_pairs(&ids),
            vec![ids[1].clone(), ids[2].clone()]
        );
        for peer in &ids[1..] {
            let enc = keys[0].pair(peer).unwrap().to_bytes().unwrap();
            assert!(
                loaded
                    .set_pair(peer, PairOTState::from_bytes(&enc).unwrap())
                    .unwrap()
                    .is_none()
            );
        }
        assert!(loaded.missing_pairs(&ids).is_empty());
        assert_eq!(loaded.to_bytes().unwrap(), full);
        assert!(
            loaded
                .set_pair(&ids[0], keys[1].ot[0].clone().unwrap())
                .is_err()
        );
        let stranger = PartyId::new("9", "P9", vec![9]);
        assert!(
            loaded
                .set_pair(&stranger, keys[1].ot[0].clone().unwrap())
                .is_err()
        );

        let all = vec![loaded, keys[1].clone(), keys[2].clone()];
        assert_signs(&all, &[0, 2], b"split reload sign");
    }

    #[test]
    fn signing_needs_only_the_signers_pairs() {
        let ids = party_ids(3);
        let mut keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        assert!(keys[0].remove_pair(&ids[2]).is_some());
        assert!(keys[0].pair(&ids[2]).is_none());

        // Parties 0 and 1 still have their pair.
        assert_signs(&keys, &[0, 1], b"no pair with 2 needed");

        let hash = sha256(b"needs the 0-2 pair");
        match sign(&keys, &[0, 2], &hash, &mut SystemRng) {
            Err(Error::MissingPairs { party, peers }) => {
                assert_eq!(party.key, ids[0].key);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].key, ids[2].key);
            }
            other => panic!("expected MissingPairs, got {:?}", other.err()),
        }
        assert!(matches!(
            super::super::presign(&keys, &[2, 0], &mut SystemRng),
            Err(Error::MissingPairs { .. })
        ));
    }
}
