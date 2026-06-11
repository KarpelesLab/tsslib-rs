//! Edwards25519 helpers bridging Go `tss-lib` big-endian `big.Int` scalars/points
//! to `purecrypto`'s little-endian Ed25519 primitives, plus the Go
//! `crypto.ECPoint` JSON shape (`{"Curve":"ed25519","Coords":[X,Y]}`).

#![allow(dead_code)]

use crate::tss::bigint::BigUintDec;
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use serde::{Deserialize, Serialize};

/// Go's `tss` registry name for Edwards25519.
pub(crate) const CURVE_NAME: &str = "ed25519";

/// JSON shape of a `crypto.ECPoint` (affine `X`,`Y` as bare decimal numbers).
#[derive(Clone, Serialize, Deserialize)]
pub struct EcPointJson {
    #[serde(rename = "Curve")]
    pub curve: String,
    #[serde(rename = "Coords")]
    pub coords: [BigUintDec; 2],
}

/// A big-endian integer (Go `big.Int.Bytes()`) reduced into the scalar field `L`.
pub(crate) fn scalar_from_be(be: &[u8]) -> Scalar {
    // Reverse to little-endian into a 64-byte buffer, then reduce mod L.
    let mut le = [0u8; 64];
    for (i, &b) in be.iter().rev().enumerate() {
        if i >= 64 {
            break;
        }
        le[i] = b;
    }
    Scalar::from_bytes_mod_order(&le)
}

/// A scalar as its minimal big-endian bytes (Go `big.Int.Bytes()`).
pub(crate) fn scalar_to_be(s: &Scalar) -> Vec<u8> {
    let le = s.to_bytes();
    let mut be: Vec<u8> = le.iter().rev().copied().collect();
    let off = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    be.drain(..off);
    be
}

/// The edwards25519 field prime `P = 2^255 − 19`, big-endian.
pub(crate) fn field_prime_be() -> Vec<u8> {
    hex_be("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
}

/// The edwards25519 group order `L`, big-endian.
pub(crate) fn order_be() -> Vec<u8> {
    hex_be("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
}

/// The basepoint's affine `(x, y)` as minimal big-endian magnitudes.
pub(crate) fn generator_coords_be() -> (Vec<u8>, Vec<u8>) {
    coords_be(&EdwardsPoint::generator())
}

/// `p · 8 · (8⁻¹ mod L)` — clears any torsion component, leaving the prime-order
/// part (Go `crypto.ECPoint.EightInvEight`). A no-op on honest prime-order points.
pub(crate) fn eight_inv_eight(p: &EdwardsPoint) -> EdwardsPoint {
    let mut eight_bytes = [0u8; 32];
    eight_bytes[0] = 8;
    let eight = Scalar::from_bytes_canonical(&eight_bytes).unwrap();
    let inv8 = eight.invert();
    p.mul(&eight).mul(&inv8)
}

fn hex_be(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// `n·G`.
pub(crate) fn mul_base(s: &Scalar) -> EdwardsPoint {
    EdwardsPoint::mul_base(s)
}

/// `s·P`.
pub(crate) fn mul(p: &EdwardsPoint, s: &Scalar) -> EdwardsPoint {
    p.mul(s)
}

/// `P + Q`.
pub(crate) fn add(a: &EdwardsPoint, b: &EdwardsPoint) -> EdwardsPoint {
    a.add(b)
}

/// Whether two points are equal.
pub(crate) fn eq(a: &EdwardsPoint, b: &EdwardsPoint) -> bool {
    bool::from(a.ct_eq(b))
}

/// The RFC 8032 compressed encoding (32-byte little-endian), used for the
/// signature's `R`/`A` and the Ed25519 challenge.
pub(crate) fn encode_point(p: &EdwardsPoint) -> [u8; 32] {
    p.compress()
}

/// Decodes a 32-byte compressed point.
pub(crate) fn decode_point(b: &[u8; 32]) -> Option<EdwardsPoint> {
    EdwardsPoint::decompress(b)
}

/// A point's affine `(x, y)` as minimal big-endian magnitudes (Go
/// `big.Int.Bytes()` form), for hashing and JSON.
pub(crate) fn coords_be(p: &EdwardsPoint) -> (Vec<u8>, Vec<u8>) {
    let (x_le, y_le) = p.to_affine();
    (le32_to_be_min(&x_le), le32_to_be_min(&y_le))
}

/// A point's affine `(x, y)` as JSON-encoded big integers.
pub(crate) fn point_to_json(p: &EdwardsPoint) -> EcPointJson {
    let (x, y) = coords_be(p);
    EcPointJson {
        curve: CURVE_NAME.into(),
        coords: [BigUintDec::from_be_bytes(&x), BigUintDec::from_be_bytes(&y)],
    }
}

/// Reconstructs a point from a `crypto.ECPoint` JSON value (curve must match).
pub(crate) fn point_from_json(j: &EcPointJson) -> Option<EdwardsPoint> {
    if j.curve != CURVE_NAME {
        return None;
    }
    point_from_affine_be(j.coords[0].as_be_bytes(), j.coords[1].as_be_bytes())
}

/// Reconstructs a point from big-endian affine coordinates: rebuild the RFC 8032
/// compressed form (32-byte LE `y` with the parity of `x` as the sign bit),
/// decompress, and confirm the recovered `x` matches the input.
pub(crate) fn point_from_affine_be(x_be: &[u8], y_be: &[u8]) -> Option<EdwardsPoint> {
    let y = BigUintDec::from_be_bytes(y_be);
    let y_be32 = y.to_be_bytes_padded(32);
    let mut compressed = [0u8; 32];
    for (i, &b) in y_be32.iter().rev().enumerate() {
        compressed[i] = b;
    }
    if be_is_odd(x_be) {
        compressed[31] |= 1 << 7;
    }
    let p = EdwardsPoint::decompress(&compressed)?;
    let (x_le, _) = p.to_affine();
    if le32_to_be_min(&x_le) == strip(x_be) {
        Some(p)
    } else {
        None
    }
}

fn be_is_odd(be: &[u8]) -> bool {
    matches!(be.last(), Some(b) if b & 1 == 1)
}

fn strip(be: &[u8]) -> Vec<u8> {
    let off = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    be[off..].to_vec()
}

fn le32_to_be_min(le: &[u8; 32]) -> Vec<u8> {
    let be: Vec<u8> = le.iter().rev().copied().collect();
    strip(&be)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(n: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[0] = n;
        Scalar::from_bytes_canonical(&b).unwrap()
    }

    #[test]
    fn point_json_roundtrip() {
        for n in 1u8..6 {
            let p = mul_base(&sc(n));
            let j = point_to_json(&p);
            assert_eq!(j.curve, "ed25519");
            assert!(eq(&point_from_json(&j).unwrap(), &p));
        }
    }

    #[test]
    fn scalar_be_roundtrip() {
        let s = sc(42);
        let be = scalar_to_be(&s);
        assert_eq!(be, vec![42]);
        assert!(bool::from(scalar_from_be(&be).ct_eq(&s)));
    }
}
