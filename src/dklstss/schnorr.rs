//! Schnorr proof of knowledge of a discrete log over secp256k1 (GG18 Fig. 16).
//! Port of tss-lib `crypto/schnorr.ZKProof` on secp256k1.
//!
//! Challenge `c = SHA512_256i_TAGGED(session, X.x, X.y, G.x, G.y, α.x, α.y) mod n`.

use super::secp::{self, ProjectivePoint, Scalar};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::rng::RngCore;

/// A Schnorr proof of knowledge of `x` such that `X = x·G`.
pub struct ZkProof {
    /// Commitment `α = a·G`.
    pub alpha: ProjectivePoint,
    /// Response `t = c·x + a` (mod `n`).
    pub t: Scalar,
}

impl ZkProof {
    /// Proves knowledge of `x` (with `x_pub = x·G`), bound to `session`.
    pub fn prove(
        session: &[u8],
        x: &Scalar,
        x_pub: &ProjectivePoint,
        rng: &mut impl RngCore,
    ) -> Self {
        let a = secp::random_scalar(rng);
        let alpha = secp::mul_base(&a);
        let c = challenge(session, x_pub, &alpha);
        let t = c.mul(x).add(&a);
        ZkProof { alpha, t }
    }

    /// Verifies the proof for `x_pub`: `t·G == α + c·X`.
    pub fn verify(&self, session: &[u8], x_pub: &ProjectivePoint) -> bool {
        let c = challenge(session, x_pub, &self.alpha);
        let tg = secp::mul_base(&self.t);
        let axc = self.alpha.add(&x_pub.mul(&c));
        secp::point_eq(&tg, &axc)
    }

    /// Wire form: `(α SEC1-compressed, t big-endian minimal)`.
    pub fn to_wire(&self) -> Option<([u8; 33], Vec<u8>)> {
        Some((
            secp::to_sec1_compressed(&self.alpha)?,
            secp::scalar_to_be_min(&self.t),
        ))
    }

    /// Decodes a proof from its wire form.
    pub fn from_wire(alpha_sec1: &[u8], t_be: &[u8]) -> Option<Self> {
        let alpha = secp::from_sec1(alpha_sec1)?;
        Some(ZkProof {
            t: secp::scalar_from_be_reduce(t_be),
            alpha,
        })
    }
}

fn challenge(session: &[u8], x_pub: &ProjectivePoint, alpha: &ProjectivePoint) -> Scalar {
    let (xx, xy) = secp::affine_be(x_pub);
    let (gx, gy) = secp::affine_be(&secp::generator());
    let (ax, ay) = secp::affine_be(alpha);
    let digest = sha512_256i_tagged(
        session,
        &[
            xx.as_slice(),
            xy.as_slice(),
            gx.as_slice(),
            gy.as_slice(),
            ax.as_slice(),
            ay.as_slice(),
        ],
    );
    Scalar::from_bytes_be_reduce(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn prove_then_verify() {
        let x = secp::random_scalar(&mut OsRng);
        let xp = secp::mul_base(&x);
        let pf = ZkProof::prove(b"session", &x, &xp, &mut OsRng);
        assert!(pf.verify(b"session", &xp));
        assert!(!pf.verify(b"other", &xp));
        let other = secp::mul_base(&secp::random_scalar(&mut OsRng));
        assert!(!pf.verify(b"session", &other));
    }

    #[test]
    fn wire_roundtrip() {
        let x = secp::random_scalar(&mut OsRng);
        let xp = secp::mul_base(&x);
        let pf = ZkProof::prove(b"s", &x, &xp, &mut OsRng);
        let (a, t) = pf.to_wire().unwrap();
        assert!(ZkProof::from_wire(&a, &t).unwrap().verify(b"s", &xp));
    }
}
