//! Minimal secp256k1 point helpers for the MtA "with check" consistency proof,
//! bridging `BoxedUint` scalars to `purecrypto`'s secp256k1 group.

#![allow(dead_code)]

use super::bn;
use purecrypto::bignum::BoxedUint;
use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};

/// A `BoxedUint` (reduced mod the group order) as a secp256k1 scalar.
pub(crate) fn scalar(n: &BoxedUint) -> Scalar {
    let r = bn::rem(n, &bn::secp256k1_order());
    let be = bn::to_be(&r);
    let mut b = [0u8; 32];
    b[32 - be.len()..].copy_from_slice(&be);
    Scalar::from_bytes_be_reduce(&b)
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
