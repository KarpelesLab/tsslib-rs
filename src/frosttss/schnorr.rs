//! Schnorr proof of knowledge of a discrete log (GG18 Fig. 16 form), over
//! Ed25519, used to bind each dealer's constant coefficient in keygen.
//!
//! Port of tss-lib `crypto/schnorr.ZKProof`. The challenge is
//! `RejectionSample(L, SHA512_256i_TAGGED(session, X.x, X.y, G.x, G.y, α.x, α.y))`,
//! reproduced byte-for-byte so Go and Rust verify each other's proofs.

use super::Error;
use super::point::{point_from_affine_be, point_to_affine_be};
use crate::frost::hashing::sha512_256i_tagged;
use crate::frost::{Ciphersuite, Ed25519, Scalar, random_scalar};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::rng::RngCore;

/// A Schnorr proof of knowledge of `x` such that `X = x·G`.
pub struct ZkProof {
    /// Commitment `α = a·G`.
    pub alpha: EdwardsPoint,
    /// Response `t = c·x + a` (mod `L`).
    pub t: Scalar,
}

impl ZkProof {
    /// Proves knowledge of `x` (with `x_pub = x·G`), bound to `session`.
    pub fn prove(session: &[u8], x: &Scalar, x_pub: &EdwardsPoint, rng: &mut impl RngCore) -> Self {
        let a = random_scalar(rng);
        let alpha = Ed25519::mul_base(&a);
        let c = challenge(session, x_pub, &alpha);
        let t = c.mul(x).add(&a);
        ZkProof { alpha, t }
    }

    /// Verifies the proof for `x_pub`, bound to `session`.
    pub fn verify(&self, session: &[u8], x_pub: &EdwardsPoint) -> bool {
        let c = challenge(session, x_pub, &self.alpha);
        let tg = Ed25519::mul_base(&self.t);
        let axc = Ed25519::add(&self.alpha, &Ed25519::scalar_mul(x_pub, &c));
        Ed25519::eq(&axc, &tg)
    }

    /// Wire encoding: `α`'s affine `(x, y)` and `t`, each big-endian minimal.
    pub fn to_wire(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (ax, ay) = point_to_affine_be(&self.alpha);
        (ax, ay, scalar_to_be_min(&self.t))
    }

    /// Decodes a proof from its wire form, rejecting an off-curve `α` or a
    /// non-canonical `t` (`>= L`), matching the Go verifier's checks.
    pub fn from_wire(alpha_x_be: &[u8], alpha_y_be: &[u8], t_be: &[u8]) -> Result<Self, Error> {
        let alpha = point_from_affine_be(alpha_x_be, alpha_y_be)?;
        let t = be_to_scalar_canonical(t_be)
            .ok_or_else(|| Error::Validation("Schnorr T not canonical (>= L)".into()))?;
        Ok(ZkProof { alpha, t })
    }
}

/// `c = SHA512_256i_TAGGED(session, X.x, X.y, G.x, G.y, α.x, α.y) mod L`.
fn challenge(session: &[u8], x_pub: &EdwardsPoint, alpha: &EdwardsPoint) -> Scalar {
    let (xx, xy) = point_to_affine_be(x_pub);
    let (gx, gy) = point_to_affine_be(&Ed25519::generator());
    let (ax, ay) = point_to_affine_be(alpha);
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
    be32_to_scalar_mod_l(&digest)
}

/// Interprets a 32-byte big-endian digest as an integer reduced mod `L`.
fn be32_to_scalar_mod_l(be: &[u8; 32]) -> Scalar {
    let mut le = [0u8; 64];
    for (i, &b) in be.iter().rev().enumerate() {
        le[i] = b;
    }
    Scalar::from_bytes_mod_order(&le)
}

/// A scalar as its big-endian minimal magnitude (Go `big.Int.Bytes()`).
fn scalar_to_be_min(s: &Scalar) -> Vec<u8> {
    let le = s.to_bytes();
    let be: Vec<u8> = le.iter().rev().copied().collect();
    let start = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    be[start..].to_vec()
}

/// Decodes a big-endian magnitude into a canonical scalar in `[0, L)`, or `None`
/// if it is `>= L` or longer than 32 bytes.
fn be_to_scalar_canonical(be: &[u8]) -> Option<Scalar> {
    if be.len() > 32 {
        return None;
    }
    let mut le = [0u8; 32];
    for (i, &b) in be.iter().rev().enumerate() {
        le[i] = b;
    }
    Scalar::from_bytes_canonical(&le)
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    fn secret(n: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[0] = n;
        Scalar::from_bytes_canonical(&b).unwrap()
    }

    #[test]
    fn prove_then_verify() {
        let x = random_scalar(&mut OsRng);
        let xp = Ed25519::mul_base(&x);
        let pf = ZkProof::prove(b"session-a", &x, &xp, &mut OsRng);
        assert!(pf.verify(b"session-a", &xp));
    }

    #[test]
    fn wrong_session_fails() {
        let x = secret(5);
        let xp = Ed25519::mul_base(&x);
        let pf = ZkProof::prove(b"session-a", &x, &xp, &mut OsRng);
        assert!(!pf.verify(b"session-b", &xp));
    }

    #[test]
    fn wrong_statement_fails() {
        let x = secret(5);
        let xp = Ed25519::mul_base(&x);
        let pf = ZkProof::prove(b"s", &x, &xp, &mut OsRng);
        let other = Ed25519::mul_base(&secret(6));
        assert!(!pf.verify(b"s", &other));
    }

    #[test]
    fn wire_roundtrip() {
        let x = random_scalar(&mut OsRng);
        let xp = Ed25519::mul_base(&x);
        let pf = ZkProof::prove(b"s", &x, &xp, &mut OsRng);
        let (ax, ay, t) = pf.to_wire();
        let back = ZkProof::from_wire(&ax, &ay, &t).unwrap();
        assert!(back.verify(b"s", &xp));
    }
}
