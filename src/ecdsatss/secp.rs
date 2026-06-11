//! Minimal secp256k1 point helpers for the MtA "with check" consistency proof,
//! bridging `BoxedUint` scalars to `purecrypto`'s secp256k1 group.

#![allow(dead_code)]

use super::bn;
use purecrypto::bignum::BoxedUint;
pub(crate) use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};

/// A `BoxedUint` (reduced mod the group order) as a secp256k1 scalar.
pub(crate) fn scalar(n: &BoxedUint) -> Scalar {
    let r = bn::rem(n, &bn::secp256k1_order());
    let be = bn::to_be(&r);
    let mut b = [0u8; 32];
    b[32 - be.len()..].copy_from_slice(&be);
    Scalar::from_bytes_be_reduce(&b)
}

/// A scalar as its minimal big-endian bytes (Go `big.Int.Bytes()`).
pub(crate) fn scalar_to_be(s: &Scalar) -> Vec<u8> {
    let b = s.to_bytes_be();
    let off = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[off..].to_vec()
}

/// A scalar from big-endian bytes, reduced mod the group order.
pub(crate) fn scalar_from_be(be: &[u8]) -> Scalar {
    let mut b = [0u8; 32];
    let n = be.len().min(32);
    b[32 - n..].copy_from_slice(&be[be.len() - n..]);
    Scalar::from_bytes_be_reduce(&b)
}

/// A scalar as a `BoxedUint` (its canonical residue mod the group order).
pub(crate) fn scalar_to_uint(s: &Scalar) -> BoxedUint {
    bn::from_be(&scalar_to_be(s))
}

/// secp256k1 field prime `P`.
pub(crate) fn field_prime() -> BoxedUint {
    bn::from_be(&hex32(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    ))
}

/// secp256k1 generator coordinates `(Gx, Gy)`.
pub(crate) fn generator_coords() -> (BoxedUint, BoxedUint) {
    (
        bn::from_be(&hex32(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )),
        bn::from_be(&hex32(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )),
    )
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// `n·G`.
pub(crate) fn mul_base(n: &BoxedUint) -> ProjectivePoint {
    ProjectivePoint::mul_generator(&scalar(n))
}

/// `n·P`.
pub(crate) fn mul(p: &ProjectivePoint, n: &BoxedUint) -> ProjectivePoint {
    p.mul(&scalar(n))
}

/// `P + Q`.
pub(crate) fn add(a: &ProjectivePoint, b: &ProjectivePoint) -> ProjectivePoint {
    a.add(b)
}

/// Whether two points are equal.
pub(crate) fn eq(a: &ProjectivePoint, b: &ProjectivePoint) -> bool {
    bool::from(a.ct_eq(b))
}

/// The affine `(x, y)` of `P` as big integers (`(0, 0)` for the identity).
pub(crate) fn coords(p: &ProjectivePoint) -> (BoxedUint, BoxedUint) {
    match p.to_affine() {
        Some(a) => (bn::from_be(&a.x_bytes()), bn::from_be(&a.y_bytes())),
        None => (bn::u64(0), bn::u64(0)),
    }
}

/// A point from affine `(x, y)` big integers via uncompressed SEC1; `None` if
/// off-curve.
pub(crate) fn from_coords(x: &BoxedUint, y: &BoxedUint) -> Option<ProjectivePoint> {
    let (xb, yb) = (bn::to_be(x), bn::to_be(y));
    if xb.len() > 32 || yb.len() > 32 {
        return None;
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1 + (32 - xb.len())..33].copy_from_slice(&xb);
    sec1[33 + (32 - yb.len())..65].copy_from_slice(&yb);
    AffinePoint::from_sec1(&sec1)
        .ok()
        .map(|a| a.to_projective())
}
