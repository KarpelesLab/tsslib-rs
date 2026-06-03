//! Go-compatible JSON encoding of an Ed25519 curve point.
//!
//! The Go `crypto.ECPoint.MarshalJSON` emits `{"Curve":"ed25519","Coords":[X,Y]}`
//! where `X`/`Y` are the affine coordinates as bare decimal `big.Int` numbers.
//! We reproduce that exactly so persisted keys round-trip across both libraries.

use crate::tss::bigint::BigUintDec;
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use serde::{Deserialize, Serialize};

/// The curve name used by Go's `tss` registry for Edwards25519.
const CURVE_NAME: &str = "ed25519";

/// JSON shape of a `crypto.ECPoint`.
#[derive(Serialize, Deserialize)]
pub(crate) struct EcPointJson {
    #[serde(rename = "Curve")]
    pub curve: String,
    #[serde(rename = "Coords")]
    pub coords: [BigUintDec; 2],
}

/// Error decoding a point from its JSON form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointError(pub(crate) String);

impl std::fmt::Display for PointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "frosttss: invalid point: {}", self.0)
    }
}

impl std::error::Error for PointError {}

/// Encodes an Edwards25519 point as its Go `ECPoint` JSON form (affine `X`,`Y`).
pub(crate) fn point_to_json(p: &EdwardsPoint) -> EcPointJson {
    let (x_le, y_le) = p.to_affine();
    EcPointJson {
        curve: CURVE_NAME.to_string(),
        coords: [le32_to_biguint(&x_le), le32_to_biguint(&y_le)],
    }
}

/// Reconstructs an Edwards25519 point from its Go `ECPoint` JSON form.
///
/// We rebuild the RFC 8032 compressed encoding from the affine coordinates
/// (32-byte little-endian `Y` with the sign bit set to the parity of `X`) and
/// decompress, then confirm the recovered `X` matches — rejecting coordinates
/// that are off-curve or mutually inconsistent.
pub(crate) fn point_from_json(j: &EcPointJson) -> Result<EdwardsPoint, PointError> {
    if j.curve != CURVE_NAME {
        return Err(PointError(format!("unexpected curve {:?}", j.curve)));
    }
    point_from_affine_be(j.coords[0].as_be_bytes(), j.coords[1].as_be_bytes())
}

/// Returns a point's affine `(x, y)` coordinates as big-endian magnitudes
/// (Go `big.Int.Bytes()` form), for hashing into the Schnorr challenge.
pub(crate) fn point_to_affine_be(p: &EdwardsPoint) -> (Vec<u8>, Vec<u8>) {
    let (x_le, y_le) = p.to_affine();
    (le32_to_biguint(&x_le).0, le32_to_biguint(&y_le).0)
}

/// Reconstructs a point from big-endian affine coordinates: rebuild the RFC 8032
/// compressed form (32-byte LE `y` with the parity of `x` as the sign bit),
/// decompress, and confirm the recovered `x` matches.
pub(crate) fn point_from_affine_be(x_be: &[u8], y_be: &[u8]) -> Result<EdwardsPoint, PointError> {
    let y = BigUintDec::from_be_bytes(y_be);
    let y_be32 = y.to_be_bytes_padded(32);
    let mut compressed = [0u8; 32];
    for (i, &b) in y_be32.iter().rev().enumerate() {
        compressed[i] = b;
    }
    if be_is_odd(x_be) {
        compressed[31] |= 1 << 7;
    }

    let p = EdwardsPoint::decompress(&compressed)
        .ok_or_else(|| PointError("coordinates are not on the curve".to_string()))?;

    // Defend against inconsistent (X, Y): the decompressed X must match input X.
    let (x_le, _) = p.to_affine();
    if le32_to_biguint(&x_le) != BigUintDec::from_be_bytes(x_be) {
        return Err(PointError("X coordinate inconsistent with Y".to_string()));
    }
    Ok(p)
}

/// Whether the big-endian integer is odd (its sign bit in Ed25519 compression).
fn be_is_odd(be: &[u8]) -> bool {
    match be.last() {
        Some(b) => b & 1 == 1,
        None => false, // zero
    }
}

/// Interprets 32 little-endian bytes as a non-negative integer.
fn le32_to_biguint(le: &[u8; 32]) -> BigUintDec {
    let mut be = [0u8; 32];
    for (i, &b) in le.iter().rev().enumerate() {
        be[i] = b;
    }
    BigUintDec::from_be_bytes(&be)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{Ciphersuite, Ed25519, Scalar};

    fn scalar(n: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[0] = n;
        Scalar::from_bytes_canonical(&b).unwrap()
    }

    #[test]
    fn point_json_roundtrip() {
        for n in 1u8..6 {
            let p = Ed25519::mul_base(&scalar(n));
            let j = point_to_json(&p);
            assert_eq!(j.curve, "ed25519");
            let back = point_from_json(&j).unwrap();
            assert!(Ed25519::eq(&p, &back));
        }
    }

    #[test]
    fn point_json_serializes_as_expected_shape() {
        let p = Ed25519::generator();
        let j = point_to_json(&p);
        let v = serde_json::to_value(&j).unwrap();
        assert_eq!(v["Curve"], "ed25519");
        assert!(v["Coords"].is_array());
        assert_eq!(v["Coords"].as_array().unwrap().len(), 2);
        // Coordinates are bare numbers, not strings.
        assert!(v["Coords"][0].is_number());
    }

    #[test]
    fn rejects_off_curve() {
        let j = EcPointJson {
            curve: "ed25519".to_string(),
            coords: [
                BigUintDec::from_be_bytes(&[2]),
                BigUintDec::from_be_bytes(&[2]),
            ],
        };
        assert!(point_from_json(&j).is_err());
    }

    #[test]
    fn rejects_wrong_curve() {
        let p = Ed25519::generator();
        let mut j = point_to_json(&p);
        j.curve = "secp256k1".to_string();
        assert!(point_from_json(&j).is_err());
    }
}
