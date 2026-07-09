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
use super::secp;
use crate::tss::PartyId;
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

    /// The group public key `ECDSAPub` in 33-byte compressed SEC1 form
    /// (`0x02`/`0x03 || X`) — the standard secp256k1 encoding an external
    /// verifier or address derivation uses. Errors if the stored point is not
    /// on the curve.
    pub fn public_key(&self) -> Result<[u8; 33], Error> {
        let p = self
            .ecdsa_pub_point()
            .ok_or_else(|| Error::Validation("key: ECDSAPub is off curve".into()))?;
        let aff = p
            .to_affine()
            .ok_or_else(|| Error::Validation("key: ECDSAPub is the identity".into()))?;
        Ok(aff.to_sec1_compressed())
    }

    /// Returns a new [`Key`] whose per-party slice fields (`Ks`, `NTildej`,
    /// `H1j`, `H2j`, `BigXj`, `PaillierPKs`) are reordered to match the given
    /// sorted party IDs. Parties are matched by their `ShareID` — i.e. the `Ks`
    /// value stored by keygen, compared to `PartyId.key`.
    ///
    /// This reindexing is required whenever the active party set is a strict
    /// subset of the parties that participated in keygen (for example, a `t+1`
    /// signing committee picked out of an `n`-party keygen, or resharing's old
    /// committee): the signing and resharing rounds index these slices by the
    /// current-party index, so they must be in current-party order.
    ///
    /// The returned key carries over the pre-params, secrets, and `ECDSAPub`
    /// unchanged; only the per-party slices are rebuilt. The result is checked
    /// with [`Key::validate_consistency`], so a tampered key whose `BigXj` no
    /// longer interpolate to `ECDSAPub` is rejected here rather than surfacing
    /// as a silently invalid signature.
    pub fn subset_for_parties(&self, sorted_ids: &[PartyId]) -> Result<Key, Error> {
        let mut subset = self.clone();
        subset.ks = Vec::with_capacity(sorted_ids.len());
        subset.ntilde_j = Vec::with_capacity(sorted_ids.len());
        subset.h1j = Vec::with_capacity(sorted_ids.len());
        subset.h2j = Vec::with_capacity(sorted_ids.len());
        subset.big_xj = Vec::with_capacity(sorted_ids.len());
        subset.paillier_pks = Vec::with_capacity(sorted_ids.len());
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
            subset.ks.push(self.ks[saved].clone());
            subset.ntilde_j.push(self.ntilde_j[saved].clone());
            subset.h1j.push(self.h1j[saved].clone());
            subset.h2j.push(self.h2j[saved].clone());
            subset.big_xj.push(self.big_xj[saved].clone());
            subset.paillier_pks.push(self.paillier_pks[saved].clone());
        }
        subset.validate_consistency()?;
        Ok(subset)
    }

    /// Returns a clone of this key shifted by a BIP32-style key-derivation delta
    /// `delta` (a big-endian scalar, reduced mod the curve order): `ECDSAPub`
    /// and every `BigXj[j]` are offset by `delta·G`, and the local share `Xi`
    /// has `delta` added mod the order. Threshold signatures produced with the
    /// shifted key verify under the child public key `ECDSAPub + delta·G`; the
    /// receiver (master key) is left untouched.
    ///
    /// Consistency is preserved: because the Lagrange weights sum to 1,
    /// `Σ λ_j (X_j + delta·G) = ECDSAPub + delta·G`, so the result still passes
    /// [`Key::validate_consistency`].
    pub fn with_kdd(&self, delta: &[u8]) -> Result<Key, Error> {
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let d = modq.reduce(&bn::from_be(delta));
        let delta_g = secp::mul_base(&d);

        let pub_pt = self
            .ecdsa_pub_point()
            .ok_or_else(|| Error::Validation("key: ECDSAPub is off curve".into()))?;
        let big_xj = self
            .big_xj_points()
            .ok_or_else(|| Error::Validation("key: a BigXj is off curve".into()))?;

        let mut out = self.clone();
        out.ecdsa_pub = ec_point(&secp::add(&pub_pt, &delta_g));
        out.big_xj = big_xj
            .iter()
            .map(|p| ec_point(&secp::add(p, &delta_g)))
            .collect();
        out.xi = BigUintDec::from_be_bytes(&bn::to_be(&modq.add(&d, &self.xi())));
        Ok(out)
    }

    /// Re-verifies, on a `Key` loaded from (possibly untrusted) serialized save
    /// data, that the per-party public shares `BigXj` are mutually consistent
    /// with the stored `ECDSAPub`.
    ///
    /// It checks that `ECDSAPub` and every `BigXj[j]` are on-curve, and that the
    /// Lagrange interpolation in the exponent of the `BigXj` over the
    /// participant `Ks`, evaluated at `x = 0`, reconstructs `ECDSAPub`. This
    /// guards the signing/resharing entry paths against a tampered key whose
    /// public shares no longer agree with the group public key (which would
    /// otherwise surface only as a silently invalid signature). The local-share
    /// check (`Xi·G == BigXj[localIdx]`) is done by callers that know the local
    /// party index.
    pub fn validate_consistency(&self) -> Result<(), Error> {
        self.validate_basic()?;
        let ecdsa_pub = self
            .ecdsa_pub_point()
            .ok_or_else(|| Error::Validation("key: ECDSAPub is off curve".into()))?;
        let big_xj = self
            .big_xj_points()
            .ok_or_else(|| Error::Validation("key: a BigXj is off curve".into()))?;
        let ks = self.ks();
        let n = ks.len();
        if n == 0 {
            return Err(Error::Validation("key: empty Ks".into()));
        }

        // Lagrange interpolation in the exponent at x=0:
        //   reconstructed = Σ_j λ_j · BigXj[j],  λ_j = Π_{c≠j} Ks[c]/(Ks[c]-Ks[j]).
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let mut reconstructed: Option<secp::ProjectivePoint> = None;
        for j in 0..n {
            let mut lambda = BoxedUint::from_u64(1);
            for c in 0..n {
                if c == j {
                    continue;
                }
                let den = modq.sub(&ks[c], &ks[j]);
                let inv = modq
                    .inv(&den)
                    .ok_or_else(|| Error::Validation("key: duplicate share id in Ks".into()))?;
                lambda = modq.mul(&lambda, &modq.mul(&ks[c], &inv));
            }
            let term = secp::mul(&big_xj[j], &lambda);
            reconstructed = Some(match reconstructed {
                None => term,
                Some(acc) => secp::add(&acc, &term),
            });
        }
        match reconstructed {
            Some(r) if secp::eq(&r, &ecdsa_pub) => Ok(()),
            _ => Err(Error::Validation(
                "key: BigXj do not interpolate to ECDSAPub".into(),
            )),
        }
    }
}

/// A secp256k1 point in the `EcPointJson` wire shape Go uses.
fn ec_point(p: &secp::ProjectivePoint) -> EcPointJson {
    let (x, y) = secp::coords(p);
    EcPointJson {
        curve: "secp256k1".into(),
        coords: [
            BigUintDec::from_be_bytes(&bn::to_be(&x)),
            BigUintDec::from_be_bytes(&bn::to_be(&y)),
        ],
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

    /// A genuine (consistent) 2-party keygen key, whose `BigXj` interpolate to
    /// `ECDSAPub` — unlike the synthetic `ecdsatss_key` fixture.
    fn load_key() -> Key {
        let f = fixtures();
        serde_json::from_value(f["signing_keys"][0].clone()).expect("load Go signing key")
    }

    /// Party IDs whose `key` is the big-endian `Ks` value, in the given order.
    fn party_ids(key: &Key, order: &[usize]) -> Vec<crate::tss::PartyId> {
        order
            .iter()
            .map(|&i| {
                crate::tss::PartyId::new(
                    (i + 1).to_string(),
                    format!("P{i}"),
                    key.ks[i].as_be_bytes().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn public_key_is_33_byte_compressed() {
        let key = load_key();
        let pk = key.public_key().unwrap();
        assert_eq!(pk.len(), 33);
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
    }

    #[test]
    fn subset_identity_order_validates() {
        let key = load_key();
        let sub = key.subset_for_parties(&party_ids(&key, &[0, 1])).unwrap();
        assert_eq!(sub.ks, key.ks);
        assert_eq!(sub.big_xj[0].coords, key.big_xj[0].coords);
        // ECDSAPub is carried over unchanged.
        assert_eq!(sub.ecdsa_pub.coords, key.ecdsa_pub.coords);
    }

    #[test]
    fn subset_reorders_per_party_slices() {
        let key = load_key();
        // Reverse committee order: [9, 7] instead of [7, 9].
        let sub = key.subset_for_parties(&party_ids(&key, &[1, 0])).unwrap();
        assert_eq!(sub.ks[0], key.ks[1]);
        assert_eq!(sub.ks[1], key.ks[0]);
        assert_eq!(sub.big_xj[0].coords, key.big_xj[1].coords);
        assert_eq!(sub.paillier_pks[0].n, key.paillier_pks[1].n);
        assert_eq!(sub.ntilde_j[0], key.ntilde_j[1]);
        // Interpolation is order-independent: reversed subset still validates.
        assert_eq!(sub.ecdsa_pub.coords, key.ecdsa_pub.coords);
    }

    #[test]
    fn subset_unknown_party_errors() {
        let key = load_key();
        let stranger = crate::tss::PartyId::new("x", "x", vec![0xde, 0xad]);
        match key.subset_for_parties(&[stranger]) {
            Err(e) => assert!(format!("{e}").contains("not found")),
            Ok(_) => panic!("expected unknown-party error"),
        }
    }

    #[test]
    fn with_kdd_shifts_pub_share_and_secret() {
        let key = load_key();
        let delta_be = [0x00u8, 0x11, 0x22, 0x33];
        let child = key.with_kdd(&delta_be).unwrap();

        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let d = modq.reduce(&bn::from_be(&delta_be));
        let delta_g = secp::mul_base(&d);

        // ECDSAPub' = ECDSAPub + delta·G.
        let want_pub = secp::add(&key.ecdsa_pub_point().unwrap(), &delta_g);
        assert!(secp::eq(&child.ecdsa_pub_point().unwrap(), &want_pub));

        // Every BigXj'[j] = BigXj[j] + delta·G.
        let old_pts = key.big_xj_points().unwrap();
        let new_pts = child.big_xj_points().unwrap();
        for (o, n) in old_pts.iter().zip(new_pts.iter()) {
            assert!(secp::eq(n, &secp::add(o, &delta_g)));
        }

        // Xi' = Xi + delta (mod q).
        assert_eq!(bn::to_be(&child.xi()), bn::to_be(&modq.add(&d, &key.xi())));

        // The shifted key is still internally consistent (interpolates to the
        // child pub), so signing's subset/validate path accepts it.
        child.subset_for_parties(&party_ids(&key, &[0, 1])).unwrap();

        // Master key is untouched (with_kdd borrows &self).
        assert_ne!(child.public_key().unwrap(), key.public_key().unwrap());
    }

    #[test]
    fn with_kdd_zero_delta_is_identity() {
        let key = load_key();
        let child = key.with_kdd(&[0u8]).unwrap();
        assert!(secp::eq(
            &child.ecdsa_pub_point().unwrap(),
            &key.ecdsa_pub_point().unwrap()
        ));
        assert_eq!(bn::to_be(&child.xi()), bn::to_be(&key.xi()));
    }

    #[test]
    fn tampered_bigxj_fails_consistency() {
        let mut key = load_key();
        // Swap the two public shares so they no longer interpolate to ECDSAPub.
        key.big_xj.swap(0, 1);
        let ids = party_ids(&key, &[0, 1]);
        match key.subset_for_parties(&ids) {
            Err(e) => assert!(format!("{e}").contains("interpolate")),
            Ok(_) => panic!("expected consistency failure on swapped BigXj"),
        }
    }
}
