//! Zero-knowledge proof of knowledge of a discrete log over a safe-prime product
//! (`h2 = h1^x mod Ñ`). Two run in parallel in GG18 keygen to show `h1, h2`
//! generate the same group mod `Ñ`. Port of Go `tss-lib/crypto/dlnproof`.

#![allow(dead_code)]

use super::bn::{self, Modulus};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// Soundness iterations (must match Go).
pub(crate) const ITERATIONS: usize = 128;

/// A DLN proof: per-iteration commitments `alpha` and responses `t`.
pub(crate) struct DlnProof {
    pub alpha: Vec<BoxedUint>,
    pub t: Vec<BoxedUint>,
}

/// Bit `i` (LSB-first) of the 32-byte challenge interpreted as a big-endian int.
fn challenge_bit(c: &[u8; 32], i: usize) -> u8 {
    (c[31 - i / 8] >> (i % 8)) & 1
}

/// Fiat-Shamir challenge `c = SHA512_256i_TAGGED("DLNProof", h1, h2, Ñ, alpha…)`.
fn challenge(h1: &BoxedUint, h2: &BoxedUint, ntilde: &BoxedUint, alpha: &[BoxedUint]) -> [u8; 32] {
    let mut ops: Vec<Vec<u8>> = Vec::with_capacity(3 + alpha.len());
    ops.push(bn::to_be(h1));
    ops.push(bn::to_be(h2));
    ops.push(bn::to_be(ntilde));
    for a in alpha {
        ops.push(bn::to_be(a));
    }
    let refs: Vec<&[u8]> = ops.iter().map(|v| v.as_slice()).collect();
    sha512_256i_tagged(b"DLNProof", &refs)
}

/// Proves `h2 = h1^x mod Ñ` given the Sophie-Germain factors `(p, q)` of the
/// QR-subgroup order (`Ñ = (2p+1)(2q+1)`, subgroup order `p·q`).
pub(crate) fn prove<R: RngCore>(
    h1: &BoxedUint,
    h2: &BoxedUint,
    x: &BoxedUint,
    p: &BoxedUint,
    q: &BoxedUint,
    ntilde: &BoxedUint,
    rng: &mut R,
) -> DlnProof {
    let pq = bn::mul(p, q);
    let modn = Modulus::new(ntilde);
    let modpq = Modulus::new(&pq);

    let mut a = Vec::with_capacity(ITERATIONS);
    let mut alpha = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let ai = bn::rand_below(&pq, rng);
        alpha.push(modn.pow(h1, &ai));
        a.push(ai);
    }
    let c = challenge(h1, h2, ntilde, &alpha);
    let mut t = Vec::with_capacity(ITERATIONS);
    for (i, ai) in a.iter().enumerate() {
        let bit = bn::u64(challenge_bit(&c, i) as u64);
        // t = a + (bit · x) mod pq
        t.push(modpq.add(ai, &modpq.mul(&bit, x)));
    }
    DlnProof { alpha, t }
}

/// Verifies a DLN proof for `(h1, h2, Ñ)`.
pub(crate) fn verify(proof: &DlnProof, h1: &BoxedUint, h2: &BoxedUint, ntilde: &BoxedUint) -> bool {
    if proof.alpha.len() != ITERATIONS || proof.t.len() != ITERATIONS {
        return false;
    }
    // 1 < h1,h2 < Ñ and distinct.
    let in_range = |v: &BoxedUint| bn::gt(v, &bn::one()) && v.lt(ntilde);
    let h1m = bn::rem(h1, ntilde);
    let h2m = bn::rem(h2, ntilde);
    if !in_range(&h1m) || !in_range(&h2m) || h1m == h2m {
        return false;
    }
    for v in proof.t.iter().chain(proof.alpha.iter()) {
        let vm = bn::rem(v, ntilde);
        if !in_range(&vm) {
            return false;
        }
    }
    let modn = Modulus::new(ntilde);
    let c = challenge(h1, h2, ntilde, &proof.alpha);
    for i in 0..ITERATIONS {
        let lhs = modn.pow_pub(h1, &proof.t[i]); // h1^t
        let bit = bn::u64(challenge_bit(&c, i) as u64);
        let h2c = modn.pow_pub(h2, &bit); // h2^c_i
        let rhs = modn.mul(&proof.alpha[i], &h2c);
        if lhs != rhs {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::testvec::{dec, fixtures};
    use super::*;

    fn load(v: &serde_json::Value) -> DlnProof {
        DlnProof {
            alpha: v["alpha"].as_array().unwrap().iter().map(dec).collect(),
            t: v["t"].as_array().unwrap().iter().map(dec).collect(),
        }
    }

    #[test]
    fn go_dlnproof_verifies() {
        let f = fixtures();
        let d = &f["dlnproof"];
        let (h1, h2, nt) = (dec(&d["h1"]), dec(&d["h2"]), dec(&d["ntilde"]));
        let proof = load(d);
        assert!(verify(&proof, &h1, &h2, &nt), "Go DLN proof must verify");

        // Tamper: flip one response.
        let mut bad = load(d);
        bad.t[5] = bn::add(&bad.t[5], &bn::one());
        assert!(!verify(&bad, &h1, &h2, &nt));
    }

    #[test]
    fn rust_prove_verify_roundtrip() {
        // Use the fixture's (h1, h2, Ñ); reprove needs the dlog + factors, which
        // the fixture does not expose, so build a fresh small instance here.
        let mut rng = purecrypto::rng::OsRng;
        // Small Sophie-Germain primes p, q with Ñ = (2p+1)(2q+1).
        let (p, sp) = loop {
            let p = bn::rand_bits(64, &mut rng);
            if bn::is_probable_prime(&p, &mut rng, 20) {
                let sp = bn::add(&bn::add(&p, &p), &bn::one());
                if bn::is_probable_prime(&sp, &mut rng, 20) {
                    break (p, sp);
                }
            }
        };
        let (q, sq) = loop {
            let q = bn::rand_bits(64, &mut rng);
            if bn::is_probable_prime(&q, &mut rng, 20) {
                let sq = bn::add(&bn::add(&q, &q), &bn::one());
                if bn::is_probable_prime(&sq, &mut rng, 20) {
                    break (q, sq);
                }
            }
        };
        let ntilde = bn::mul(&sp, &sq);
        let ord = bn::mul(&p, &q);
        let modn = Modulus::new(&ntilde);
        let f = bn::rand_below(&ntilde, &mut rng);
        let h1 = modn.mul(&f, &f); // a quadratic residue
        let x = bn::rand_below(&ord, &mut rng);
        let h2 = modn.pow(&h1, &x);
        let proof = prove(&h1, &h2, &x, &p, &q, &ntilde, &mut rng);
        assert!(verify(&proof, &h1, &h2, &ntilde));
        // Wrong h2 must fail.
        let h2_bad = modn.mul(&h2, &h1);
        assert!(!verify(&proof, &h1, &h2_bad, &ntilde));
    }
}
