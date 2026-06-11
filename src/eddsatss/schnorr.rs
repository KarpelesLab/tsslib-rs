//! Schnorr proof of knowledge of a discrete log (`X = x·G`) over edwards25519,
//! port of Go `tss-lib/crypto/schnorr` `ZKProof`. Used in both keygen (binding
//! `vs[0] = u_i·G`) and signing (binding `R_i = r_i·G`).
//!
//! Fiat-Shamir challenge `c = RejectionSample(L, SHA512_256i_TAGGED(session, X,
//! G, alpha))`, i.e. the tagged hash of the point coordinates reduced mod the
//! group order.

#![allow(dead_code)]

use super::ed;
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use purecrypto::rng::RngCore;

/// Proof of knowledge of `x` such that `X = x·G`.
pub(crate) struct ZkProof {
    pub alpha: EdwardsPoint,
    pub t: Scalar,
}

fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    loop {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        let s = Scalar::from_bytes_mod_order(&b);
        if !bool::from(s.ct_eq(&Scalar::from_bytes_mod_order(&[0u8; 64]))) {
            return s;
        }
    }
}

fn challenge(session: &[u8], x_pub: &EdwardsPoint, alpha: &EdwardsPoint) -> Scalar {
    let (xx, xy) = ed::coords_be(x_pub);
    let (gx, gy) = ed::generator_coords_be();
    let (ax, ay) = ed::coords_be(alpha);
    let ops: [&[u8]; 6] = [&xx, &xy, &gx, &gy, &ax, &ay];
    let h = sha512_256i_tagged(session, &ops);
    ed::scalar_from_be(&h)
}

impl ZkProof {
    /// Proves knowledge of `x` for `x_pub = x·G`.
    pub(crate) fn prove<R: RngCore>(
        session: &[u8],
        x: &Scalar,
        x_pub: &EdwardsPoint,
        rng: &mut R,
    ) -> ZkProof {
        let a = random_scalar(rng);
        let alpha = ed::mul_base(&a);
        let c = challenge(session, x_pub, &alpha);
        let t = c.mul(x).add(&a);
        ZkProof { alpha, t }
    }

    /// Verifies the proof against `x_pub`.
    pub(crate) fn verify(&self, session: &[u8], x_pub: &EdwardsPoint) -> bool {
        let c = challenge(session, x_pub, &self.alpha);
        // alpha + c·X == t·G
        let lhs = ed::add(&self.alpha, &ed::mul(x_pub, &c));
        ed::eq(&lhs, &ed::mul_base(&self.t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn zkproof_roundtrip() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let xp = ed::mul_base(&x);
        let pf = ZkProof::prove(b"sess", &x, &xp, &mut rng);
        assert!(pf.verify(b"sess", &xp));
        assert!(!pf.verify(b"other", &xp));
        let bad = ed::mul_base(&random_scalar(&mut rng));
        assert!(!pf.verify(b"sess", &bad));
    }
}
