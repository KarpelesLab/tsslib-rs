//! Paillier cryptosystem (additively homomorphic) + the GG18 key-correctness
//! proof, on `BoxedUint`, in the legacy GG18 encoding.

#![allow(dead_code)]

use super::Error;
use super::bn::{self, Modulus};
use crate::prelude::*;
use crate::tss::hashing::sha512_256_parts;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// Number of iterations in the Paillier key-correctness proof (GG18).
pub(crate) const PROOF_ITERS: usize = 13;

/// Maximum number of rejected candidates [`generate_xs`] tolerates before
/// giving up. Each candidate is built from `⌈bitlen(N)/256⌉` hash blocks, so
/// for a modulus whose bit length is just above a multiple of 256 (e.g. 2049
/// bits) almost every candidate exceeds `N`; without a cap a peer sending such
/// an `N` would pin every verifier in an endless loop. An honest `N` has its
/// top bit set and a bit length that is a multiple of 256 (2048 bits), so each
/// candidate is accepted with probability ≥ 1/2 and the chance of 1000
/// rejections before 13 acceptances is negligible.
const MAX_XS_REJECTIONS: usize = 1000;

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

    /// `(N+1)^m mod N²`, computed as `1 + (m mod N)·N` (binomial theorem: all
    /// higher terms are multiples of `N²`). No exponentiation, so no
    /// exponent-dependent timing, and much faster than a ladder.
    pub(crate) fn gamma_pow(&self, m: &BoxedUint) -> BoxedUint {
        let m = if m.lt(&self.n) {
            m.clone()
        } else {
            bn::rem(m, &self.n)
        };
        bn::add(&bn::mul(&m, &self.n), &bn::one())
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
        let gm = self.gamma_pow(m);
        // N is a public exponent (the base x is secret, which pow_pub allows).
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

    /// `Enc(m·plaintext(c₁))` from a secret plaintext scalar `m < 2^m_bits`
    /// (`m_bits` a public bound, e.g. the curve order's width): `c₁^m mod N²`,
    /// computed in constant time.
    pub(crate) fn homo_mult(&self, m: &BoxedUint, m_bits: usize, c1: &BoxedUint) -> BoxedUint {
        Modulus::new(&self.nsquare()).pow_secret_bits(c1, m, m_bits)
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
        let lc = l(&n2.pow_secret(c, &self.lambda));
        let lg = l(&n2.pow_secret(&self.pk.gamma(), &self.lambda));
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
        let xs = generate_xs(PROOF_ITERS, k, &self.pk.n, ecdsa_x, ecdsa_y).ok_or_else(|| {
            Error::Validation("paillier: N unsuitable for the key-correctness proof".into())
        })?;
        // M = N⁻¹ mod φ(N); φ(N) is even, so use the non-Montgomery inverse.
        let m = bn::mod_inv(&self.pk.n, &self.phi)
            .ok_or_else(|| Error::Validation("paillier: N not invertible mod φ(N)".into()))?;
        let modn = Modulus::new(&self.pk.n);
        let pi: Vec<BoxedUint> = xs.iter().map(|x| modn.pow_secret(x, &m)).collect();
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
    // Honest pi are reduced mod N; wider ones are only a way to burn CPU.
    if pi.iter().any(|y| y.is_zero() || !y.lt(n)) {
        return false;
    }
    // N must have no prime factor below 1000.
    if bn::has_small_factor(n) {
        return false;
    }
    let Some(xs) = generate_xs(PROOF_ITERS, k, n, ecdsa_x, ecdsa_y) else {
        return false;
    };
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
/// `None` if more than [`MAX_XS_REJECTIONS`] candidates are rejected.
fn generate_xs(
    m: usize,
    k: &BoxedUint,
    n: &BoxedUint,
    sx: &BoxedUint,
    sy: &BoxedUint,
) -> Option<Vec<BoxedUint>> {
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
            if nn > MAX_XS_REJECTIONS {
                return None;
            }
        }
    }
    Some(ret)
}

/// `1 ≤ v < n` and `gcd(v, n) = 1`.
fn in_mult_group(n: &BoxedUint, v: &BoxedUint) -> bool {
    !v.is_zero() && v.lt(n) && bn::is_one(&bn::gcd(v, n))
}

#[cfg(all(test, feature = "json"))]
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

        // Each (m, x, c): encrypt_with reproduces the fixture c, and decrypt recovers m.
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
        // The fixture proof verifies.
        assert!(
            verify_proof(&n, &k, &sx, &sy, &pi),
            "fixture proof must verify"
        );

        // A Rust-built proof (same key) also verifies.
        let sk = PrivateKey::from_primes(dec(&pp["p"]), dec(&pp["q"]));
        let rust_pi = sk.proof(&k, &sx, &sy).unwrap();
        assert!(verify_proof(&n, &k, &sx, &sy, &rust_pi));

        // A tampered proof fails.
        let mut bad = pi.clone();
        bad[0] = bn::add(&bad[0], &bn::one());
        assert!(!verify_proof(&n, &k, &sx, &sy, &bad));

        // An oversized pi (>= N) is rejected outright.
        let mut big = pi.clone();
        big[3] = bn::add(&big[3], &n);
        assert!(!verify_proof(&n, &k, &sx, &sy, &big));
    }

    /// A modulus of bit length ≡ 1 (mod 256) makes almost every challenge
    /// candidate exceed `N`; generation and verification must give up rather
    /// than loop forever.
    #[test]
    fn generate_xs_is_bounded() {
        // 2^2048 + c: 2049 bits, odd, no prime factor below 1000 (so
        // verify_proof gets past its trial division to generate_xs).
        let base = bn::from_be(&{
            let mut b = vec![0u8; 257];
            b[0] = 1;
            b
        });
        let n = (1u64..)
            .step_by(2)
            .map(|c| bn::add(&base, &bn::u64(c)))
            .find(|n| !bn::has_small_factor(n))
            .unwrap();
        assert_eq!(n.bit_len(), 2049);
        let (k, sx, sy) = (bn::u64(1), bn::u64(2), bn::u64(3));
        assert!(generate_xs(PROOF_ITERS, &k, &n, &sx, &sy).is_none());
        let pi: Vec<BoxedUint> = (0..PROOF_ITERS).map(|_| bn::one()).collect();
        assert!(!verify_proof(&n, &k, &sx, &sy, &pi));
    }

    #[test]
    fn roundtrip_fresh_key() {
        let mut rng = crate::rng::SystemRng;
        // Small generated key for a quick self-contained round-trip.
        let p = bn::generate_safe_prime(128, &mut rng);
        let q = bn::generate_safe_prime(128, &mut rng);
        let sk = PrivateKey::from_primes(p, q);
        let m = bn::u64(123456);
        let (c, _x) = sk.pk.encrypt(&m, &mut rng).unwrap();
        assert_eq!(bn::to_be(&sk.decrypt(&c).unwrap()), bn::to_be(&m));
    }
}
