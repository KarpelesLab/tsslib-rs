//! Feldman VSS over edwards25519 (eddsatss keygen/resharing), mirroring the
//! ecdsatss VSS but in the Ed25519 scalar field.

#![allow(dead_code)]

use super::ed;
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use purecrypto::rng::RngCore;

/// One Shamir share `(id, f(id))`.
pub(crate) struct Share {
    pub id: Scalar,
    pub value: Scalar,
}

/// A uniformly random non-zero scalar.
pub(crate) fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    loop {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        let s = Scalar::from_bytes_mod_order(&b);
        if !bool::from(s.ct_eq(&Scalar::ZERO)) {
            return s;
        }
    }
}

/// Creates a degree-`t` sharing of `secret` for recipients `ids`.
pub(crate) fn create<R: RngCore>(
    t: usize,
    secret: &Scalar,
    ids: &[Scalar],
    rng: &mut R,
) -> (Vec<EdwardsPoint>, Vec<Share>) {
    let mut poly: Vec<Scalar> = Vec::with_capacity(t + 1);
    poly.push(secret.clone());
    for _ in 0..t {
        poly.push(random_scalar(rng));
    }
    let commitments: Vec<EdwardsPoint> = poly.iter().map(ed::mul_base).collect();
    let shares = ids
        .iter()
        .map(|id| Share {
            id: id.clone(),
            value: eval(&poly, id),
        })
        .collect();
    (commitments, shares)
}

/// Verifies `share = f(id)` against commitments: `share·G == Σ_c id^c · v_c`.
pub(crate) fn verify(id: &Scalar, value: &Scalar, t: usize, commitments: &[EdwardsPoint]) -> bool {
    if commitments.len() != t + 1 {
        return false;
    }
    ed::eq(&ed::mul_base(value), &horner(commitments, id))
}

/// Lagrange reconstruction of `f(0)`.
pub(crate) fn reconstruct(shares: &[Share]) -> Scalar {
    let mut secret = Scalar::ZERO;
    for (i, si) in shares.iter().enumerate() {
        let mut times = Scalar::ONE;
        for (j, sj) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let sub = sj.id.sub(&si.id);
            times = times.mul(&sj.id.mul(&sub.invert()));
        }
        secret = secret.add(&si.value.mul(&times));
    }
    secret
}

/// `Σ_c id^c · v_c` (Horner).
fn horner(vs: &[EdwardsPoint], id: &Scalar) -> EdwardsPoint {
    let mut eval = vs[vs.len() - 1];
    for k in (0..vs.len() - 1).rev() {
        eval = ed::add(&ed::mul(&eval, id), &vs[k]);
    }
    eval
}

/// `poly[0] + poly[1]·x + …`.
fn eval(poly: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = poly[0].clone();
    let mut xpow = Scalar::ONE;
    for a in &poly[1..] {
        xpow = xpow.mul(x);
        result = result.add(&a.mul(&xpow));
    }
    result
}
