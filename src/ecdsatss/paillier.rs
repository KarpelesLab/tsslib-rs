//! Paillier cryptosystem (additively homomorphic) + the GG18 key-correctness
//! proof, on `BoxedUint`. Byte/value-compatible with Go `tss-lib/crypto/paillier`.

#![allow(dead_code)]

use super::Error;
use super::bn::{self, Modulus};
use crate::frost::hashing::sha512_256_parts;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// Number of iterations in the Paillier key-correctness proof (GG18).
pub(crate) const PROOF_ITERS: usize = 13;

/// A Paillier public key: the modulus `N`.
#[derive(Clone)]
pub struct PublicKey {
    pub n: BoxedUint,
}

/// A Paillier private key: public key plus secret factorization.
#[derive(Clone)]
pub struct PrivateKey {
    pub pk: PublicKey,
    pub lambda: BoxedUint, // lcm(p-1, q-1)
    pub phi: BoxedUint,    // (p-1)(q-1)
    pub p: BoxedUint,
    pub q: BoxedUint,
}

impl PublicKey {
    /// `N + 1` (the Paillier generator `g`).
    pub(crate) fn gamma(&self) -> BoxedUint {
        bn::add(&self.n, &bn::one())
    }

    /// `N²` (the ciphertext modulus).
    pub(crate) fn nsquare(&self) -> BoxedUint {
        bn::mul(&self.n, &self.n)
    }

    /// Encrypts `m` with caller-supplied randomness `x` (must be a unit mod `N`):
    /// `c = (N+1)^m · x^N mod N²`. `m` must satisfy `0 ≤ m < N`.
    pub(crate) fn encrypt_with(&self, m: &BoxedUint, x: &BoxedUint) -> Result<BoxedUint, Error> {
        if bn::ge(m, &self.n) {
            return Err(Error::Validation("paillier: message >= N".into()));
        }
        let n2 = Modulus::new(&self.nsquare());
        let gm = n2.pow(&self.gamma(), m);
        let xn = n2.pow_pub(x, &self.n);
        Ok(n2.mul(&gm, &xn))
    }

    /// Encrypts `m` with fresh randomness, returning `(c, x)`.
    pub(crate) fn encrypt<R: RngCore>(
        &self,
        m: &BoxedUint,
        rng: &mut R,
    ) -> Result<(BoxedUint, BoxedUint), Error> {
        let x = bn::rand_unit(&self.n, rng);
        let c = self.encrypt_with(m, &x)?;
        Ok((c, x))
    }

    /// `Enc(m₁ + m₂)` from `Enc(m₁)`, `Enc(m₂)`: `c₁·c₂ mod N²`.
    pub(crate) fn homo_add(&self, c1: &BoxedUint, c2: &BoxedUint) -> BoxedUint {
        Modulus::new(&self.nsquare()).mul(c1, c2)
    }

    /// `Enc(m·plaintext(c₁))` from a plaintext scalar `m`: `c₁^m mod N²`.
    pub(crate) fn homo_mult(&self, m: &BoxedUint, c1: &BoxedUint) -> BoxedUint {
        Modulus::new(&self.nsquare()).pow(c1, m)
    }
}

impl PrivateKey {
    /// Builds a private key from its two prime factors.
    pub(crate) fn from_primes(p: BoxedUint, q: BoxedUint) -> PrivateKey {
        let n = bn::mul(&p, &q);
        let pm1 = bn::sub(&p, &bn::one());
        let qm1 = bn::sub(&q, &bn::one());
        let phi = bn::mul(&pm1, &qm1);
        let g = bn::gcd(&pm1, &qm1);
        let (lambda, _) = bn::divrem(&phi, &g);
        PrivateKey {
            pk: PublicKey { n },
            lambda,
            phi,
            p,
            q,
        }
    }

    /// Decrypts `c` to its plaintext `m`.
    pub(crate) fn decrypt(&self, c: &BoxedUint) -> Result<BoxedUint, Error> {
        let n2v = self.pk.nsquare();
        if bn::ge(c, &n2v) {
            return Err(Error::Validation("paillier: ciphertext >= N²".into()));
        }
        if !bn::is_one(&bn::gcd(c, &n2v)) {
            return Err(Error::Validation("paillier: malformed ciphertext".into()));
        }
        let n2 = Modulus::new(&n2v);
        let n = &self.pk.n;
        // L(u) = (u - 1) / N.
        let l = |u: &BoxedUint| -> BoxedUint {
            let t = bn::sub(u, &bn::one());
            bn::divrem(&t, n).0
        };
        let lc = l(&n2.pow(c, &self.lambda));
        let lg = l(&n2.pow(&self.pk.gamma(), &self.lambda));
        let modn = Modulus::new(n);
        let inv = modn
            .inv(&lg)
            .ok_or_else(|| Error::Validation("paillier: Lg not invertible".into()))?;
        Ok(modn.mul(&lc, &inv))
    }

    /// The GG18 key-correctness proof binding the key to `(k, ecdsa_pub)`.
    pub(crate) fn proof(
        &self,
        k: &BoxedUint,
        ecdsa_x: &BoxedUint,
        ecdsa_y: &BoxedUint,
    ) -> Result<[BoxedUint; PROOF_ITERS], Error> {
        let xs = generate_xs(PROOF_ITERS, k, &self.pk.n, ecdsa_x, ecdsa_y);
        // M = N⁻¹ mod φ(N); φ(N) is even, so use the non-Montgomery inverse.
        let m = bn::mod_inv(&self.pk.n, &self.phi)
            .ok_or_else(|| Error::Validation("paillier: N not invertible mod φ(N)".into()))?;
        let modn = Modulus::new(&self.pk.n);
        let pi: Vec<BoxedUint> = xs.iter().map(|x| modn.pow(x, &m)).collect();
        Ok(pi.try_into().map_err(|_| ()).expect("PROOF_ITERS items"))
    }
}

/// Verifies the GG18 Paillier key-correctness proof against public `n`.
pub(crate) fn verify_proof(
    n: &BoxedUint,
    k: &BoxedUint,
    ecdsa_x: &BoxedUint,
    ecdsa_y: &BoxedUint,
    pi: &[BoxedUint],
) -> bool {
    if pi.len() != PROOF_ITERS {
        return false;
    }
    // N must have no prime factor below 1000.
    for &p in PRIMES_BELOW_1000 {
        if bn::mod_small(n, p) == 0 {
            return false;
        }
    }
    let xs = generate_xs(PROOF_ITERS, k, n, ecdsa_x, ecdsa_y);
    let modn = Modulus::new(n);
    for (xi, yi) in xs.iter().zip(pi.iter()) {
        // xi mod N == yi^N mod N
        if bn::rem(xi, n) != modn.pow_pub(yi, n) {
            return false;
        }
    }
    true
}

/// GG18 `GenerateXs`: the deterministic challenge values for the Paillier proof.
fn generate_xs(
    m: usize,
    k: &BoxedUint,
    n: &BoxedUint,
    sx: &BoxedUint,
    sy: &BoxedUint,
) -> Vec<BoxedUint> {
    let blocks = n.bit_len().div_ceil(256);
    let (kb, sxb, syb, nb) = (bn::to_be(k), bn::to_be(sx), bn::to_be(sy), bn::to_be(n));
    let mut ret = Vec::with_capacity(m);
    let mut i = 0usize;
    let mut nn = 0usize;
    while i < m {
        let ib = i.to_string().into_bytes();
        let nbz = nn.to_string().into_bytes();
        let mut xi_bytes = Vec::with_capacity(blocks * 32);
        for j in 0..blocks {
            let jb = j.to_string().into_bytes();
            let h = sha512_256_parts(&[&ib, &jb, &nbz, &kb, &sxb, &syb, &nb]);
            xi_bytes.extend_from_slice(&h);
        }
        let xi = bn::from_be(&xi_bytes);
        if in_mult_group(n, &xi) {
            ret.push(xi);
            i += 1;
        } else {
            nn += 1;
        }
    }
    ret
}

/// `1 ≤ v < n` and `gcd(v, n) = 1`.
fn in_mult_group(n: &BoxedUint, v: &BoxedUint) -> bool {
    !v.is_zero() && v.lt(n) && bn::is_one(&bn::gcd(v, n))
}

/// All primes below 1000 (matches Go `primesBelow1000`).
const PRIMES_BELOW_1000: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
];

#[cfg(test)]
mod tests {
    use super::super::testvec::{dec, fixtures};
    use super::*;

    #[test]
    fn small_key_encrypt_decrypt_homo() {
        let f = fixtures();
        let ps = &f["paillier_small"];
        let p = dec(&ps["p"]);
        let q = dec(&ps["q"]);
        let sk = PrivateKey::from_primes(p, q);
        assert_eq!(bn::to_be(&sk.pk.n), bn::to_be(&dec(&ps["n"])));
        assert_eq!(bn::to_be(&sk.lambda), bn::to_be(&dec(&ps["lambda"])));

        // Each (m, x, c): encrypt_with reproduces Go's c, and decrypt recovers m.
        for e in ps["enc"].as_array().unwrap() {
            let m = dec(&e["M"]);
            let x = dec(&e["X"]);
            let c = dec(&e["C"]);
            assert_eq!(
                bn::to_be(&sk.pk.encrypt_with(&m, &x).unwrap()),
                bn::to_be(&c)
            );
            assert_eq!(bn::to_be(&sk.decrypt(&c).unwrap()), bn::to_be(&m));
        }

        // Homomorphic add: Dec(c) == 9042.
        let add_c = dec(&ps["homo_add"]["c"]);
        assert_eq!(
            bn::to_be(&sk.decrypt(&add_c).unwrap()),
            bn::to_be(&dec(&ps["homo_add"]["m"]))
        );
        // Homomorphic mult: Dec(c) == 294.
        let mult_c = dec(&ps["homo_mult"]["c"]);
        assert_eq!(
            bn::to_be(&sk.decrypt(&mult_c).unwrap()),
            bn::to_be(&dec(&ps["homo_mult"]["m"]))
        );
    }

    #[test]
    fn proof_fixture_verifies() {
        let f = fixtures();
        let pp = &f["paillier_proof"];
        let n = dec(&pp["n"]);
        let k = dec(&pp["k"]);
        let sx = dec(&pp["ecdsa_x"]);
        let sy = dec(&pp["ecdsa_y"]);
        let pi: Vec<BoxedUint> = pp["pi"].as_array().unwrap().iter().map(dec).collect();
        // The Go-emitted proof verifies in Rust.
        assert!(verify_proof(&n, &k, &sx, &sy, &pi), "Go proof must verify");

        // A Rust-built proof (same key) also verifies.
        let sk = PrivateKey::from_primes(dec(&pp["p"]), dec(&pp["q"]));
        let rust_pi = sk.proof(&k, &sx, &sy).unwrap();
        assert!(verify_proof(&n, &k, &sx, &sy, &rust_pi));

        // A tampered proof fails.
        let mut bad = pi.clone();
        bad[0] = bn::add(&bad[0], &bn::one());
        assert!(!verify_proof(&n, &k, &sx, &sy, &bad));
    }

    #[test]
    fn roundtrip_fresh_key() {
        let mut rng = purecrypto::rng::OsRng;
        // Small generated key for a quick self-contained round-trip.
        let p = bn::generate_safe_prime(128, &mut rng);
        let q = bn::generate_safe_prime(128, &mut rng);
        let sk = PrivateKey::from_primes(p, q);
        let m = bn::u64(123456);
        let (c, _x) = sk.pk.encrypt(&m, &mut rng).unwrap();
        assert_eq!(bn::to_be(&sk.decrypt(&c).unwrap()), bn::to_be(&m));
    }
}
