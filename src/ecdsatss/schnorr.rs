//! Schnorr ZK proofs used in GG18 signing (port of Go `tss-lib/crypto/schnorr`):
//! a proof of knowledge of a discrete log (`X = x·G`) and a "V proof" of
//! knowledge of `(s, l)` with `V = s·R + l·G`.
//!
//! The Fiat-Shamir challenge is `RejectionSample(q, SHA512_256i_TAGGED(...))`,
//! i.e. the tagged hash of the point coordinates reduced mod the group order.

#![allow(dead_code)]

use super::bn;
use super::secp::{self, ProjectivePoint, Scalar};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::rng::RngCore;

/// Proof of knowledge of `x` such that `X = x·G`.
pub(crate) struct ZkProof {
    pub alpha: ProjectivePoint,
    pub t: Scalar,
}

/// Proof of knowledge of `(s, l)` such that `V = s·R + l·G`.
pub(crate) struct ZkVProof {
    pub alpha: ProjectivePoint,
    pub t: Scalar,
    pub u: Scalar,
}

fn be(p: &ProjectivePoint) -> (Vec<u8>, Vec<u8>) {
    let (x, y) = secp::coords(p);
    (bn::to_be(&x), bn::to_be(&y))
}

/// `RejectionSample(q, SHA512_256i_TAGGED(session, ops...))` as a scalar.
fn challenge(session: &[u8], ops: &[&[u8]]) -> Scalar {
    let h = sha512_256i_tagged(session, ops);
    Scalar::from_bytes_be_reduce(&h)
}

impl ZkProof {
    /// Proves knowledge of `x` for `x_pub = x·G`.
    pub(crate) fn prove<R: RngCore>(
        session: &[u8],
        x: &Scalar,
        x_pub: &ProjectivePoint,
        rng: &mut R,
    ) -> ZkProof {
        let a = super::vss::random_scalar(rng);
        let alpha = ProjectivePoint::mul_generator(&a);
        let (gx, gy) = secp::generator_coords();
        let (gxb, gyb) = (bn::to_be(&gx), bn::to_be(&gy));
        let (xx, xy) = be(x_pub);
        let (ax, ay) = be(&alpha);
        let c = challenge(session, &[&xx, &xy, &gxb, &gyb, &ax, &ay]);
        let t = c.mul(x).add(&a);
        ZkProof { alpha, t }
    }

    /// Verifies the proof against `x_pub`.
    pub(crate) fn verify(&self, session: &[u8], x_pub: &ProjectivePoint) -> bool {
        let (gx, gy) = secp::generator_coords();
        let (gxb, gyb) = (bn::to_be(&gx), bn::to_be(&gy));
        let (xx, xy) = be(x_pub);
        let (ax, ay) = be(&self.alpha);
        let c = challenge(session, &[&xx, &xy, &gxb, &gyb, &ax, &ay]);
        let tg = ProjectivePoint::mul_generator(&self.t);
        let axc = self.alpha.add(&x_pub.mul(&c));
        secp::eq(&tg, &axc)
    }
}

impl ZkVProof {
    /// Proves knowledge of `(s, l)` for `v = s·R + l·G`.
    pub(crate) fn prove<R: RngCore>(
        session: &[u8],
        v: &ProjectivePoint,
        r: &ProjectivePoint,
        s: &Scalar,
        l: &Scalar,
        rng: &mut R,
    ) -> ZkVProof {
        let a = super::vss::random_scalar(rng);
        let b = super::vss::random_scalar(rng);
        let alpha = r.mul(&a).add(&ProjectivePoint::mul_generator(&b));
        let c = v_challenge(session, v, r, &alpha);
        let t = c.mul(s).add(&a);
        let u = c.mul(l).add(&b);
        ZkVProof { alpha, t, u }
    }

    /// Verifies the proof against `v` and `r`.
    pub(crate) fn verify(&self, session: &[u8], v: &ProjectivePoint, r: &ProjectivePoint) -> bool {
        let c = v_challenge(session, v, r, &self.alpha);
        let tr_ug = r.mul(&self.t).add(&ProjectivePoint::mul_generator(&self.u));
        let avc = self.alpha.add(&v.mul(&c));
        secp::eq(&tr_ug, &avc)
    }
}

fn v_challenge(
    session: &[u8],
    v: &ProjectivePoint,
    r: &ProjectivePoint,
    alpha: &ProjectivePoint,
) -> Scalar {
    let (gx, gy) = secp::generator_coords();
    let (gxb, gyb) = (bn::to_be(&gx), bn::to_be(&gy));
    let (vx, vy) = be(v);
    let (rx, ry) = be(r);
    let (ax, ay) = be(alpha);
    challenge(session, &[&vx, &vy, &rx, &ry, &gxb, &gyb, &ax, &ay])
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn zkproof_roundtrip() {
        let mut rng = OsRng;
        let x = super::super::vss::random_scalar(&mut rng);
        let xp = ProjectivePoint::mul_generator(&x);
        let pf = ZkProof::prove(b"sess", &x, &xp, &mut rng);
        assert!(pf.verify(b"sess", &xp));
        // Wrong session or point fails.
        assert!(!pf.verify(b"other", &xp));
        let bad = ProjectivePoint::mul_generator(&super::super::vss::random_scalar(&mut rng));
        assert!(!pf.verify(b"sess", &bad));
    }

    #[test]
    fn zkvproof_roundtrip() {
        let mut rng = OsRng;
        let s = super::super::vss::random_scalar(&mut rng);
        let l = super::super::vss::random_scalar(&mut rng);
        let r = ProjectivePoint::mul_generator(&super::super::vss::random_scalar(&mut rng));
        let v = r.mul(&s).add(&ProjectivePoint::mul_generator(&l));
        let pf = ZkVProof::prove(b"sess", &v, &r, &s, &l, &mut rng);
        assert!(pf.verify(b"sess", &v, &r));
        assert!(!pf.verify(b"sess", &r, &v));
    }
}
