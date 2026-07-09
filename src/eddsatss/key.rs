//! GG18-style threshold-EdDSA key save-data, JSON-compatible with Go
//! `eddsatss.Key`, so legacy serialized keys load directly.
//!
//! The shape is far simpler than `ecdsatss` (no Paillier / ring-Pedersen): a
//! Shamir share `Xi`, the share ids `Ks`, the per-party public points `BigXj`,
//! and the group public key `EDDSAPub`. `*big.Int` is a bare JSON number;
//! `crypto.ECPoint` is `{"Curve":"ed25519","Coords":[X,Y]}`.

#![allow(dead_code)]

use super::Error;
use super::ed::{self, EcPointJson};
use crate::tss::PartyId;
use crate::tss::bigint::BigUintDec;
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// One party's threshold-EdDSA key share (save format). Mirrors Go `eddsatss.Key`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    #[serde(rename = "Xi")]
    pub xi: BigUintDec,
    #[serde(rename = "ShareID")]
    pub share_id: BigUintDec,
    #[serde(rename = "Ks")]
    pub ks: Vec<BigUintDec>,
    #[serde(rename = "BigXj")]
    pub big_xj: Vec<EcPointJson>,
    #[serde(rename = "EDDSAPub")]
    pub eddsa_pub: EcPointJson,
}

impl Zeroize for Key {
    /// Wipes the long-lived secret share `Xi` in place (overwrites the backing
    /// bytes, then leaves it as the canonical zero value). The remaining fields
    /// (`ShareID`, `Ks`, `BigXj`, `EDDSAPub`) are public values and are left
    /// untouched. Serialization is unaffected: this only runs on an owned,
    /// mutable key (normally via `Drop`).
    fn zeroize(&mut self) {
        self.xi.0.zeroize();
    }
}

impl Drop for Key {
    /// Ensures the secret share `Xi` does not linger in freed heap memory.
    /// Each `Clone` owns its own buffer and wipes it independently.
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Key {
    /// Parses a Go-emitted `eddsatss.Key` JSON document.
    pub fn from_json(s: &str) -> Result<Key, Error> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serializes to JSON compatible with Go `eddsatss.Key`.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }

    /// This party's secret share `Xi` as a scalar.
    pub(crate) fn xi_scalar(&self) -> Scalar {
        ed::scalar_from_be(self.xi.as_be_bytes())
    }

    /// The share ids `Ks` as scalars.
    pub(crate) fn ks_scalars(&self) -> Vec<Scalar> {
        self.ks
            .iter()
            .map(|k| ed::scalar_from_be(k.as_be_bytes()))
            .collect()
    }

    /// The public share points `BigXj`.
    pub(crate) fn big_xj_points(&self) -> Option<Vec<EdwardsPoint>> {
        self.big_xj.iter().map(ed::point_from_json).collect()
    }

    /// The group public key `EDDSAPub` as a point.
    pub(crate) fn eddsa_pub_point(&self) -> Option<EdwardsPoint> {
        ed::point_from_json(&self.eddsa_pub)
    }

    /// Basic well-formedness: matching slice lengths and the `ed25519` curve.
    pub fn validate_basic(&self) -> Result<(), Error> {
        if self.ks.len() != self.big_xj.len() {
            return Err(Error::Validation(
                "key: Ks and BigXj length mismatch".into(),
            ));
        }
        for p in self.big_xj.iter().chain(std::iter::once(&self.eddsa_pub)) {
            if p.curve != ed::CURVE_NAME {
                return Err(Error::Validation(format!(
                    "key: unexpected curve {}",
                    p.curve
                )));
            }
        }
        if self.eddsa_pub_point().is_none() || self.big_xj_points().is_none() {
            return Err(Error::Validation("key: a point is off-curve".into()));
        }
        Ok(())
    }

    /// The group public key `EDDSAPub` in RFC 8032 compressed form (32-byte
    /// little-endian `y` with the sign bit of `x`) — the standard Ed25519
    /// public-key encoding an external verifier uses. Errors if the stored
    /// point is off-curve.
    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        let p = self
            .eddsa_pub_point()
            .ok_or_else(|| Error::Validation("key: EDDSAPub is off curve".into()))?;
        Ok(ed::encode_point(&p))
    }

    /// Returns a new [`Key`] whose `Ks` and `BigXj` slices are reordered to
    /// match the given sorted party IDs. Parties are matched by their `ShareID`
    /// — i.e. the `Ks` value stored by keygen, compared to `PartyId.key`.
    ///
    /// This reindexing is required whenever the active party set is a strict
    /// subset of the parties that participated in keygen (for example, a `t+1`
    /// signing committee picked out of an `n`-party keygen, or resharing's old
    /// committee): the signing and resharing rounds index these slices by the
    /// current-party index, so they must be in current-party order.
    ///
    /// `Xi`, `ShareID`, and `EDDSAPub` are carried over unchanged; only `Ks`
    /// and `BigXj` are rebuilt.
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
                        "subset_for_parties: party 0x{} not found in keygen save data",
                        hex_lower(want)
                    ))
                })?;
            ks.push(self.ks[saved].clone());
            big_xj.push(self.big_xj[saved].clone());
        }
        Ok(Key {
            xi: self.xi.clone(),
            share_id: self.share_id.clone(),
            ks,
            big_xj,
            eddsa_pub: self.eddsa_pub.clone(),
        })
    }

    /// Returns a clone of this key shifted by an additive key-derivation delta
    /// `delta` (a big-endian scalar, reduced mod the group order `L`): `EDDSAPub`
    /// and every `BigXj[j]` are offset by `delta·G`, and the local share `Xi`
    /// has `delta` added mod `L`. The receiver (master key) is left untouched.
    ///
    /// Because the Ed25519 challenge `SHA-512(R‖A‖M)` binds the shifted
    /// `A = EDDSAPub + delta·G`, a threshold signature produced with the shifted
    /// key is a valid, stock Ed25519 signature under that child public key.
    /// Consistency is preserved: as the Lagrange weights sum to 1,
    /// `Σ λ_j (X_j + delta·G) = EDDSAPub + delta·G`.
    pub fn with_kdd(&self, delta: &[u8]) -> Result<Key, Error> {
        let d = ed::scalar_from_be(delta);
        let delta_g = ed::mul_base(&d);
        let pub_pt = self
            .eddsa_pub_point()
            .ok_or_else(|| Error::Validation("key: EDDSAPub is off curve".into()))?;
        let big_xj = self
            .big_xj_points()
            .ok_or_else(|| Error::Validation("key: a BigXj is off curve".into()))?;
        Ok(Key {
            xi: BigUintDec::from_be_bytes(&ed::scalar_to_be(&self.xi_scalar().add(&d))),
            share_id: self.share_id.clone(),
            ks: self.ks.clone(),
            big_xj: big_xj
                .iter()
                .map(|p| ed::point_to_json(&ed::add(p, &delta_g)))
                .collect(),
            eddsa_pub: ed::point_to_json(&ed::add(&pub_pt, &delta_g)),
        })
    }
}

/// Big-endian magnitude with leading zero bytes removed (matches
/// `BigUintDec::as_be_bytes`, so party keys compare canonically).
fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

/// Lower-case hex, for identifying an unmatched party in error messages.
fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::super::testvec::fixtures;
    use super::*;

    fn load_key() -> Key {
        let f = fixtures();
        serde_json::from_value(f["signing_keys"][0].clone()).expect("load Go eddsa key")
    }

    fn party_ids(key: &Key, order: &[usize]) -> Vec<PartyId> {
        order
            .iter()
            .map(|&i| {
                PartyId::new(
                    (i + 1).to_string(),
                    format!("P{i}"),
                    key.ks[i].as_be_bytes().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn public_key_is_32_bytes() {
        let key = load_key();
        assert_eq!(key.public_key().unwrap().len(), 32);
    }

    #[test]
    fn subset_reorders_ks_and_bigxj() {
        let key = load_key();
        let sub = key.subset_for_parties(&party_ids(&key, &[1, 0])).unwrap();
        assert_eq!(sub.ks[0], key.ks[1]);
        assert_eq!(sub.ks[1], key.ks[0]);
        assert_eq!(sub.big_xj[0].coords, key.big_xj[1].coords);
        // EDDSAPub, Xi, ShareID carried over unchanged.
        assert_eq!(sub.eddsa_pub.coords, key.eddsa_pub.coords);
        assert_eq!(sub.xi, key.xi);
        assert_eq!(sub.share_id, key.share_id);
        sub.validate_basic().unwrap();
    }

    #[test]
    fn with_kdd_shifts_pub_share_and_secret() {
        let key = load_key();
        let delta_be = [0x00u8, 0x11, 0x22, 0x33];
        let child = key.with_kdd(&delta_be).unwrap();

        let d = ed::scalar_from_be(&delta_be);
        let delta_g = ed::mul_base(&d);

        // EDDSAPub' = EDDSAPub + delta·G.
        let want_pub = ed::add(&key.eddsa_pub_point().unwrap(), &delta_g);
        assert!(ed::eq(&child.eddsa_pub_point().unwrap(), &want_pub));

        // Every BigXj'[j] = BigXj[j] + delta·G.
        let old_pts = key.big_xj_points().unwrap();
        let new_pts = child.big_xj_points().unwrap();
        for (o, n) in old_pts.iter().zip(new_pts.iter()) {
            assert!(ed::eq(n, &ed::add(o, &delta_g)));
        }

        // Xi' = Xi + delta (mod L).
        assert!(child.xi_scalar() == key.xi_scalar().add(&d));

        // Master key untouched (with_kdd borrows &self).
        assert_ne!(child.public_key().unwrap(), key.public_key().unwrap());
    }

    #[test]
    fn with_kdd_zero_delta_is_identity() {
        let key = load_key();
        let child = key.with_kdd(&[0u8]).unwrap();
        assert!(ed::eq(
            &child.eddsa_pub_point().unwrap(),
            &key.eddsa_pub_point().unwrap()
        ));
        assert!(child.xi_scalar() == key.xi_scalar());
    }

    #[test]
    fn subset_unknown_party_errors() {
        let key = load_key();
        let stranger = PartyId::new("x", "x", vec![0xde, 0xad]);
        match key.subset_for_parties(&[stranger]) {
            Err(e) => assert!(format!("{e}").contains("not found")),
            Ok(_) => panic!("expected unknown-party error"),
        }
    }
}
