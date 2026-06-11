//! No-small-factor proof: a Paillier modulus `N0` is a product of two primes,
//! relative to a verifier's ring-Pedersen parameters `(NCap, s, t)`. Port of Go
//! `tss-lib/crypto/facproof` (GG18 keygen round 2).
//!
//! Note on `V`: Go computes `V = r + e·(σ − ν·N0p)` (signed) but serializes its
//! magnitude (`big.Int.Bytes()`), so a negative `V` is unrecoverable on the wire
//! in Go too. We therefore match the working `V ≥ 0` case and emit `|V|`.

#![allow(dead_code)]

use super::bn::{self, Modulus};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// The 11 field elements of a fac-proof.
pub(crate) struct ProofFac {
    pub p: BoxedUint,
    pub q: BoxedUint,
    pub a: BoxedUint,
    pub b: BoxedUint,
    pub t: BoxedUint,
    pub sigma: BoxedUint,
    pub z1: BoxedUint,
    pub z2: BoxedUint,
    pub w1: BoxedUint,
    pub w2: BoxedUint,
    pub v: BoxedUint,
}

impl ProofFac {
    /// Big-endian parts in field order `P,Q,A,B,T,σ,Z1,Z2,W1,W2,V`.
    pub(crate) fn to_parts(&self) -> Vec<Vec<u8>> {
        [
            &self.p,
            &self.q,
            &self.a,
            &self.b,
            &self.t,
            &self.sigma,
            &self.z1,
            &self.z2,
            &self.w1,
            &self.w2,
            &self.v,
        ]
        .iter()
        .map(|x| bn::to_be(x))
        .collect()
    }

    /// Inverse of [`ProofFac::to_parts`].
    pub(crate) fn from_parts(parts: &[Vec<u8>]) -> Option<ProofFac> {
        if parts.len() != 11 {
            return None;
        }
        let g = |i: usize| bn::from_be(&parts[i]);
        Some(ProofFac {
            p: g(0),
            q: g(1),
            a: g(2),
            b: g(3),
            t: g(4),
            sigma: g(5),
            z1: g(6),
            z2: g(7),
            w1: g(8),
            w2: g(9),
            v: g(10),
        })
    }
}

/// `e = SHA512_256i_TAGGED(session, N0, NCap, s, t, P, Q, A, B, T, σ) mod q`.
fn challenge(
    session: &[u8],
    q: &BoxedUint,
    n0: &BoxedUint,
    ncap: &BoxedUint,
    s: &BoxedUint,
    t: &BoxedUint,
    pf: &ProofFac,
) -> BoxedUint {
    let ops: Vec<Vec<u8>> = [n0, ncap, s, t, &pf.p, &pf.q, &pf.a, &pf.b, &pf.t, &pf.sigma]
        .iter()
        .map(|x| bn::to_be(x))
        .collect();
    let refs: Vec<&[u8]> = ops.iter().map(|v| v.as_slice()).collect();
    let h = sha512_256i_tagged(session, &refs);
    bn::rem(&bn::from_be(&h), q)
}

/// Proves `N0 = N0p·N0q` against ring-Pedersen `(NCap, s, t)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove<R: RngCore>(
    session: &[u8],
    n0: &BoxedUint,
    ncap: &BoxedUint,
    s: &BoxedUint,
    t: &BoxedUint,
    n0p: &BoxedUint,
    n0q: &BoxedUint,
    rng: &mut R,
) -> ProofFac {
    let q = bn::secp256k1_order();
    let q3 = bn::mul(&bn::mul(&q, &q), &q);
    let qncap = bn::mul(&q, ncap);
    let qn0ncap = bn::mul(&qncap, n0);
    let q3ncap = bn::mul(&q3, ncap);
    let q3n0ncap = bn::mul(&q3ncap, n0);
    let q3sqrtn0 = bn::mul(&q3, &bn::sqrt(n0));

    let alpha = bn::rand_below(&q3sqrtn0, rng);
    let beta = bn::rand_below(&q3sqrtn0, rng);
    let mu = bn::rand_below(&qncap, rng);
    let nu = bn::rand_below(&qncap, rng);
    let sigma = bn::rand_below(&qn0ncap, rng);
    let r = bn::rand_unit(&q3n0ncap, rng);
    let x = bn::rand_below(&q3ncap, rng);
    let y = bn::rand_below(&q3ncap, rng);

    let m = Modulus::new(ncap);
    let pp = m.mul(&m.pow(s, n0p), &m.pow(t, &mu));
    let qq = m.mul(&m.pow(s, n0q), &m.pow(t, &nu));
    let a = m.mul(&m.pow(s, &alpha), &m.pow(t, &x));
    let b = m.mul(&m.pow(s, &beta), &m.pow(t, &y));
    let tt = m.mul(&m.pow(&qq, &alpha), &m.pow(t, &r));

    let mut pf = ProofFac {
        p: pp,
        q: qq,
        a,
        b,
        t: tt,
        sigma: sigma.clone(),
        z1: bn::u64(0),
        z2: bn::u64(0),
        w1: bn::u64(0),
        w2: bn::u64(0),
        v: bn::u64(0),
    };
    let e = challenge(session, &q, n0, ncap, s, t, &pf);

    pf.z1 = bn::add(&bn::mul(&e, n0p), &alpha);
    pf.z2 = bn::add(&bn::mul(&e, n0q), &beta);
    pf.w1 = bn::add(&bn::mul(&e, &mu), &x);
    pf.w2 = bn::add(&bn::mul(&e, &nu), &y);
    // v = |(r + e·σ) − (e·ν·N0p)|  (Go serializes the magnitude).
    let a_val = bn::add(&r, &bn::mul(&e, &sigma));
    let b_val = bn::mul(&bn::mul(&e, &nu), n0p);
    pf.v = if bn::ge(&a_val, &b_val) {
        bn::sub(&a_val, &b_val)
    } else {
        bn::sub(&b_val, &a_val)
    };
    pf
}

/// Verifies a fac-proof for `(N0, NCap, s, t)`.
pub(crate) fn verify(
    session: &[u8],
    n0: &BoxedUint,
    ncap: &BoxedUint,
    s: &BoxedUint,
    t: &BoxedUint,
    pf: &ProofFac,
) -> bool {
    if n0.is_zero() {
        return false;
    }
    let q = bn::secp256k1_order();
    let q3 = bn::mul(&bn::mul(&q, &q), &q);
    let q3sqrtn0 = bn::mul(&q3, &bn::sqrt(n0));

    // Range checks: 0 ≤ z1,z2 < q³·√N0.
    if !pf.z1.lt(&q3sqrtn0) || !pf.z2.lt(&q3sqrtn0) {
        return false;
    }
    let e = challenge(session, &q, n0, ncap, s, t, pf);
    let m = Modulus::new(ncap);

    // s^z1 · t^w1 == A · P^e
    let lhs1 = m.mul(&m.pow_pub(s, &pf.z1), &m.pow_pub(t, &pf.w1));
    let rhs1 = m.mul(&pf.a, &m.pow_pub(&pf.p, &e));
    if lhs1 != rhs1 {
        return false;
    }
    // s^z2 · t^w2 == B · Q^e
    let lhs2 = m.mul(&m.pow_pub(s, &pf.z2), &m.pow_pub(t, &pf.w2));
    let rhs2 = m.mul(&pf.b, &m.pow_pub(&pf.q, &e));
    if lhs2 != rhs2 {
        return false;
    }
    // R = s^N0 · t^σ ; Q^z1 · t^v == T · R^e
    let r = m.mul(&m.pow_pub(s, n0), &m.pow_pub(t, &pf.sigma));
    let lhs3 = m.mul(&m.pow_pub(&pf.q, &pf.z1), &m.pow_pub(t, &pf.v));
    let rhs3 = m.mul(&pf.t, &m.pow_pub(&r, &e));
    lhs3 == rhs3
}

#[cfg(test)]
mod tests {
    use super::super::testvec::{dec, fixtures};
    use super::*;

    #[test]
    fn go_facproof_verifies() {
        let f = fixtures();
        let fp = &f["facproof"];
        let session = fp["session"].as_str().unwrap().as_bytes();
        let (n0, ncap, s, t) = (
            dec(&fp["n0"]),
            dec(&fp["ncap"]),
            dec(&fp["s"]),
            dec(&fp["t"]),
        );
        let pf = ProofFac {
            p: dec(&fp["P"]),
            q: dec(&fp["Q"]),
            a: dec(&fp["A"]),
            b: dec(&fp["B"]),
            t: dec(&fp["T"]),
            sigma: dec(&fp["Sigma"]),
            z1: dec(&fp["Z1"]),
            z2: dec(&fp["Z2"]),
            w1: dec(&fp["W1"]),
            w2: dec(&fp["W2"]),
            v: dec(&fp["V"]),
        };
        assert!(
            verify(session, &n0, &ncap, &s, &t, &pf),
            "Go facproof must verify"
        );

        // Tamper.
        let mut bad = pf;
        bad.z1 = bn::add(&bad.z1, &bn::one());
        assert!(!verify(session, &n0, &ncap, &s, &t, &bad));
    }

    #[test]
    fn rust_facproof_roundtrip() {
        let f = fixtures();
        let fp = &f["facproof"];
        // Reuse the fixture's N0 (a real Paillier modulus) + its factors, and the
        // ring-Pedersen params; reprove and verify in Rust.
        let pp = &f["paillier_proof"];
        let (n0, n0p, n0q) = (dec(&pp["n"]), dec(&pp["p"]), dec(&pp["q"]));
        let (ncap, s, t) = (dec(&fp["ncap"]), dec(&fp["s"]), dec(&fp["t"]));
        let session = b"rust-fac-session";
        let mut rng = purecrypto::rng::OsRng;
        let proof = prove(session, &n0, &ncap, &s, &t, &n0p, &n0q, &mut rng);
        assert!(verify(session, &n0, &ncap, &s, &t, &proof));
        // Different session must fail.
        assert!(!verify(b"other", &n0, &ncap, &s, &t, &proof));
    }
}
