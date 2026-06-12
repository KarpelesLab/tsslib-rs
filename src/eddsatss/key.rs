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
}
