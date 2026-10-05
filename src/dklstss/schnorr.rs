//! Schnorr proof of knowledge of a discrete log over secp256k1 (GG18 Fig. 16).
//!
//! Challenge `c = SHA512_256i_TAGGED(session, X.x, X.y, G.x, G.y, α.x, α.y) mod n`.

use super::secp::{self, ProjectivePoint, Scalar};
use crate::prelude::*;
use crate::tss::hashing::sha512_256i_tagged;
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

/// A dealer's proof of knowledge of its polynomial's constant term `a_0`
/// (`V[0] = a_0·G`), as sent with keygen and reshare commitments.
///
/// Without it, dealers that move last can choose `V[0]` as a function of the
/// honest dealers' commitments (e.g. `a·G − Σ V_honest[0]`) without knowing its
/// discrete log, and derive the remaining commitments and the honest parties'
/// shares "in the exponent". That hands them the joint key whenever they
/// control at least as many parties as there are honest ones (`n ≤ 2t`). A
/// dealer can only prove knowledge of a `V[0]` it chose itself, which closes
/// that attack (rushing dealers can still bias the key, as in FROST's DKG).
///
/// The challenge is bound to `tag`, the session id, the dealer's party key and
/// the dealer's whole flattened commitment vector, so a proof cannot be moved
/// to another dealer, session or commitment set.
pub(crate) struct ConstantTermPok;

impl ConstantTermPok {
    fn session(tag: &str, ssid: &[u8], dealer_key: &[u8], flat_commitments: &[Vec<u8>]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(tag.as_bytes());
        s.push(0);
        s.extend_from_slice(ssid);
        let dk = super::echo::strip(dealer_key);
        s.extend_from_slice(&(dk.len() as u32).to_be_bytes());
        s.extend_from_slice(dk);
        for c in flat_commitments {
            s.extend_from_slice(&(c.len() as u32).to_be_bytes());
            s.extend_from_slice(c);
        }
        s
    }

    #[allow(clippy::too_many_arguments)]
    /// Proves knowledge of `a0` with `commitments[0] = a0·G`. Returns
    /// `(α.x, α.y, t)` as minimal big-endian byte strings.
    pub(crate) fn prove(
        tag: &str,
        ssid: &[u8],
        dealer_key: &[u8],
        a0: &Scalar,
        commitments: &[ProjectivePoint],
        flat_commitments: &[Vec<u8>],
        rng: &mut impl RngCore,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let session = Self::session(tag, ssid, dealer_key, flat_commitments);
        let pf = ZkProof::prove(&session, a0, &commitments[0], rng);
        let (ax, ay) = secp::affine_be(&pf.alpha);
        (ax, ay, secp::scalar_to_be_min(&pf.t))
    }

    #[allow(clippy::too_many_arguments)]
    /// Verifies a proof produced by [`ConstantTermPok::prove`] for the dealer's
    /// decoded `commitments` and their flattened wire form. Rejects an invalid
    /// `α` and a non-canonical `t`.
    pub(crate) fn verify(
        tag: &str,
        ssid: &[u8],
        dealer_key: &[u8],
        commitments: &[ProjectivePoint],
        flat_commitments: &[Vec<u8>],
        alpha_x: &[u8],
        alpha_y: &[u8],
        t: &[u8],
    ) -> bool {
        let Some(alpha) = super::echo::point_from_be_xy(alpha_x, alpha_y) else {
            return false;
        };
        let Some(t) = canonical_scalar(t) else {
            return false;
        };
        let session = Self::session(tag, ssid, dealer_key, flat_commitments);
        !commitments.is_empty() && ZkProof { alpha, t }.verify(&session, &commitments[0])
    }
}

/// A big-endian scalar that is `< n` and at most 32 bytes.
fn canonical_scalar(be: &[u8]) -> Option<Scalar> {
    let be = super::echo::strip(be);
    if be.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - be.len()..].copy_from_slice(be);
    Scalar::from_bytes_be(&buf).ok()
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

    #[test]
    fn constant_term_pok_is_bound_to_dealer_session_and_commitments() {
        use super::super::echo::flatten_point_xy;
        let a0 = secp::scalar_from_be_reduce(&[11]);
        let a1 = secp::scalar_from_be_reduce(&[13]);
        let vs = vec![secp::mul_base(&a0), secp::mul_base(&a1)];
        let flat: Vec<Vec<u8>> = flatten_point_xy(&vs).into_iter().map(|b| b.0).collect();
        let (ax, ay, t) =
            ConstantTermPok::prove("tag", b"ssid", &[1], &a0, &vs, &flat, &mut SystemRng);
        let ok = |tag: &str,
                  ssid: &[u8],
                  dealer: &[u8],
                  vs: &[ProjectivePoint],
                  flat: &[Vec<u8>],
                  t: &[u8]| {
            ConstantTermPok::verify(tag, ssid, dealer, vs, flat, &ax, &ay, t)
        };
        assert!(ok("tag", b"ssid", &[1], &vs, &flat, &t));
        // Leading zeros on the dealer key don't matter (keys compare stripped).
        assert!(ok("tag", b"ssid", &[0, 1], &vs, &flat, &t));
        assert!(!ok("other", b"ssid", &[1], &vs, &flat, &t));
        assert!(!ok("tag", b"other", &[1], &vs, &flat, &t));
        assert!(!ok("tag", b"ssid", &[2], &vs, &flat, &t));
        // A different higher coefficient changes the bound commitment vector.
        let vs2 = vec![vs[0], secp::mul_base(&a0)];
        let flat2: Vec<Vec<u8>> = flatten_point_xy(&vs2).into_iter().map(|b| b.0).collect();
        assert!(!ok("tag", b"ssid", &[1], &vs2, &flat2, &t));
        // Non-canonical response (t + n) is refused.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut t_plus_n = vec![0u8; 33];
        let mut carry = 0u16;
        let tp = {
            let mut b = vec![0u8; 32 - t.len()];
            b.extend_from_slice(&t);
            b
        };
        for i in (0..32).rev() {
            let v = tp[i] as u16 + n[i] as u16 + carry;
            t_plus_n[i + 1] = v as u8;
            carry = v >> 8;
        }
        t_plus_n[0] = carry as u8;
        assert!(!ok("tag", b"ssid", &[1], &vs, &flat, &t_plus_n));
    }
    use crate::rng::SystemRng;

    #[test]
    fn prove_then_verify() {
        let x = secp::random_scalar(&mut SystemRng);
        let xp = secp::mul_base(&x);
        let pf = ZkProof::prove(b"session", &x, &xp, &mut SystemRng);
        assert!(pf.verify(b"session", &xp));
        assert!(!pf.verify(b"other", &xp));
        let other = secp::mul_base(&secp::random_scalar(&mut SystemRng));
        assert!(!pf.verify(b"session", &other));
    }

    #[test]
    fn wire_roundtrip() {
        let x = secp::random_scalar(&mut SystemRng);
        let xp = secp::mul_base(&x);
        let pf = ZkProof::prove(b"s", &x, &xp, &mut SystemRng);
        let (a, t) = pf.to_wire().unwrap();
        assert!(ZkProof::from_wire(&a, &t).unwrap().verify(b"s", &xp));
    }
}
