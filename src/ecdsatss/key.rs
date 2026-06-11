//! GG18 key save-data, JSON-compatible with Go `ecdsatss.Key` /
//! `ecdsa/keygen.LocalPartySaveData`, so legacy serialized keys load directly.
//!
//! Go marshals `*big.Int` as a bare JSON number (`BigUintDec`), `[]byte` as
//! base64, `crypto.ECPoint` as `{"Curve","Coords":[X,Y]}`, and the Paillier keys
//! by their (capitalized, embedded) field names. Field order is irrelevant to
//! JSON; only names/shapes must match.

#![allow(dead_code)]

use super::Error;
use super::bn;
use super::paillier::{PrivateKey, PublicKey};
use crate::tss::bigint::BigUintDec;
use purecrypto::bignum::BoxedUint;
use serde::{Deserialize, Serialize};

/// A Paillier private key as Go serializes it (embedded `PublicKey` promotes `N`).
#[derive(Clone, Serialize, Deserialize)]
pub struct PaillierSkJson {
    #[serde(rename = "N")]
    pub n: BigUintDec,
    #[serde(rename = "LambdaN")]
    pub lambda_n: BigUintDec,
    #[serde(rename = "PhiN")]
    pub phi_n: BigUintDec,
    #[serde(rename = "P")]
    pub p: BigUintDec,
    #[serde(rename = "Q")]
    pub q: BigUintDec,
}

/// A Paillier public key (just `N`).
#[derive(Clone, Serialize, Deserialize)]
pub struct PaillierPkJson {
    #[serde(rename = "N")]
    pub n: BigUintDec,
}

/// A curve point as Go's `crypto.ECPoint` marshals it.
#[derive(Clone, Serialize, Deserialize)]
pub struct EcPointJson {
    #[serde(rename = "Curve")]
    pub curve: String,
    #[serde(rename = "Coords")]
    pub coords: [BigUintDec; 2],
}

/// One party's GG18 key share (save format). Mirrors Go `ecdsatss.Key`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    // --- LocalPreParams ---
    #[serde(rename = "PaillierSK")]
    pub paillier_sk: PaillierSkJson,
    #[serde(rename = "NTildei")]
    pub ntilde_i: BigUintDec,
    #[serde(rename = "H1i")]
    pub h1i: BigUintDec,
    #[serde(rename = "H2i")]
    pub h2i: BigUintDec,
    #[serde(rename = "Alpha")]
    pub alpha: BigUintDec,
    #[serde(rename = "Beta")]
    pub beta: BigUintDec,
    #[serde(rename = "P")]
    pub p: BigUintDec,
    #[serde(rename = "Q")]
    pub q: BigUintDec,
    // --- LocalSecrets ---
    #[serde(rename = "Xi")]
    pub xi: BigUintDec,
    #[serde(rename = "ShareID")]
    pub share_id: BigUintDec,
    // --- per-party public material ---
    #[serde(rename = "Ks")]
    pub ks: Vec<BigUintDec>,
    #[serde(rename = "NTildej")]
    pub ntilde_j: Vec<BigUintDec>,
    #[serde(rename = "H1j")]
    pub h1j: Vec<BigUintDec>,
    #[serde(rename = "H2j")]
    pub h2j: Vec<BigUintDec>,
    #[serde(rename = "BigXj")]
    pub big_xj: Vec<EcPointJson>,
    #[serde(rename = "PaillierPKs")]
    pub paillier_pks: Vec<PaillierPkJson>,
    #[serde(rename = "ECDSAPub")]
    pub ecdsa_pub: EcPointJson,
}

impl Key {
    /// Parses a Go-emitted `ecdsatss.Key` JSON document.
    pub fn from_json(s: &str) -> Result<Key, Error> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serializes to JSON byte-compatible with Go `ecdsatss.Key`.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }

    /// This party's Paillier private key as `BoxedUint`s.
    pub(crate) fn paillier_sk(&self) -> PrivateKey {
        PrivateKey {
            pk: PublicKey {
                n: bn::from_dec(&self.paillier_sk.n),
            },
            lambda: bn::from_dec(&self.paillier_sk.lambda_n),
            phi: bn::from_dec(&self.paillier_sk.phi_n),
            p: bn::from_dec(&self.paillier_sk.p),
            q: bn::from_dec(&self.paillier_sk.q),
        }
    }

    /// `(NTildej, H1j, H2j, PaillierPKs)` for peer `j` as `BoxedUint`s.
    pub(crate) fn peer_params(&self, j: usize) -> (BoxedUint, BoxedUint, BoxedUint, PublicKey) {
        (
            bn::from_dec(&self.ntilde_j[j]),
            bn::from_dec(&self.h1j[j]),
            bn::from_dec(&self.h2j[j]),
            PublicKey {
                n: bn::from_dec(&self.paillier_pks[j].n),
            },
        )
    }

    /// The party key integers `Ks` (VSS x-coordinates) as `BoxedUint`s.
    pub(crate) fn ks(&self) -> Vec<BoxedUint> {
        self.ks.iter().map(bn::from_dec).collect()
    }

    /// This party's secret share `Xi`.
    pub(crate) fn xi(&self) -> BoxedUint {
        bn::from_dec(&self.xi)
    }

    /// The public share points `BigXj`.
    pub(crate) fn big_xj_points(&self) -> Option<Vec<super::secp::ProjectivePoint>> {
        self.big_xj
            .iter()
            .map(|p| {
                super::secp::from_coords(&bn::from_dec(&p.coords[0]), &bn::from_dec(&p.coords[1]))
            })
            .collect()
    }

    /// The group public key `ECDSAPub` as a curve point.
    pub(crate) fn ecdsa_pub_point(&self) -> Option<super::secp::ProjectivePoint> {
        super::secp::from_coords(
            &bn::from_dec(&self.ecdsa_pub.coords[0]),
            &bn::from_dec(&self.ecdsa_pub.coords[1]),
        )
    }

    /// Basic well-formedness: matching per-party slice lengths and the secp256k1
    /// curve on all points.
    pub fn validate_basic(&self) -> Result<(), Error> {
        let n = self.ks.len();
        if self.ntilde_j.len() != n
            || self.h1j.len() != n
            || self.h2j.len() != n
            || self.big_xj.len() != n
            || self.paillier_pks.len() != n
        {
            return Err(Error::Validation(
                "key: per-party slice length mismatch".into(),
            ));
        }
        for p in self.big_xj.iter().chain(std::iter::once(&self.ecdsa_pub)) {
            if p.curve != "secp256k1" {
                return Err(Error::Validation(format!(
                    "key: unexpected curve {}",
                    p.curve
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testvec::fixtures;
    use super::*;

    #[test]
    fn go_key_loads_and_round_trips() {
        let f = fixtures();
        // The Go-emitted ecdsatss.Key deserializes into the Rust Key.
        let key: Key = serde_json::from_value(f["ecdsatss_key"].clone()).expect("load Go key");
        key.validate_basic().unwrap();

        // Spot-check fields against the fixture's known values.
        assert_eq!(key.ks.len(), 2);
        assert_eq!(key.share_id, BigUintDec::from_be_bytes(&[7]));
        assert_eq!(key.ks[0], BigUintDec::from_be_bytes(&[7]));
        assert_eq!(key.ks[1], BigUintDec::from_be_bytes(&[9]));
        assert_eq!(key.ecdsa_pub.curve, "secp256k1");
        // PaillierSK.N matches the standalone paillier_proof N.
        assert_eq!(
            key.paillier_sk.n,
            f["paillier_proof"]["n"]
                .as_str()
                .map(|s| BigUintDec::from_be_bytes(&crate::tss::bigint::decimal_to_be(s).unwrap()))
                .unwrap()
        );

        // Re-serialize and parse again: values are preserved.
        let json = key.to_json().unwrap();
        let key2 = Key::from_json(&json).unwrap();
        assert_eq!(key2.ks, key.ks);
        assert_eq!(key2.paillier_sk.n, key.paillier_sk.n);
        assert_eq!(key2.big_xj[1].coords, key.big_xj[1].coords);

        // The Paillier SK reconstructs as BoxedUint (N = P·Q).
        let sk = key.paillier_sk();
        assert_eq!(bn::to_be(&sk.pk.n), bn::to_be(&bn::mul(&sk.p, &sk.q)));
    }
}
