//! Big-integer helpers for GG18 (Paillier + ZK proofs), built on
//! `purecrypto::bignum::BoxedUint`.
//!
//! GG18 follows Go's arbitrary-precision *signed* `math/big`; `BoxedUint` is
//! unsigned, so all subtraction here is modular (results live in `[0, m)`).
//! Callers mirror the reference's modular reductions, and the Go-generated
//! fixtures catch any sign mishandling. None of this is field arithmetic over a
//! fixed prime — it is integer/modular algorithms (GCD, Jacobi, Miller-Rabin,
//! safe-prime search) layered on purecrypto's `BoxedMontModulus`.
//!
//! These helpers are the shared foundation for `paillier` / the ZK proofs /
//! `mta`; some are consumed only by later phases of the GG18 port.
#![allow(dead_code)]

use crate::tss::bigint::BigUintDec;
use purecrypto::bignum::{BoxedMontModulus, BoxedUint, inv_mod_boxed};
use purecrypto::rng::RngCore;
use std::cmp::Ordering;

// --- construction / conversion ---------------------------------------------

/// `BoxedUint` for a small `u64`.
pub(crate) fn u64(v: u64) -> BoxedUint {
    BoxedUint::from_u64(v)
}

/// `1`.
pub(crate) fn one() -> BoxedUint {
    BoxedUint::from_u64(1)
}

/// Whether `n == 1`.
pub(crate) fn is_one(n: &BoxedUint) -> bool {
    *n == one()
}

/// Big-endian magnitude with leading zeros stripped (empty for zero) — matches
/// Go `big.Int.Bytes()`.
pub(crate) fn to_be(n: &BoxedUint) -> Vec<u8> {
    if n.is_zero() {
        return Vec::new();
    }
    let byte_len = n.bit_len().div_ceil(8);
    let b = n.to_be_bytes(byte_len);
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[start..].to_vec()
}

/// Parse a big-endian magnitude.
pub(crate) fn from_be(b: &[u8]) -> BoxedUint {
    if b.is_empty() {
        return BoxedUint::zero(1);
    }
    BoxedUint::from_be_bytes(b)
}

/// `BigUintDec` (Go-compatible JSON number) → `BoxedUint`.
pub(crate) fn from_dec(d: &BigUintDec) -> BoxedUint {
    from_be(d.as_be_bytes())
}

/// `BoxedUint` → `BigUintDec`.
pub(crate) fn to_dec(n: &BoxedUint) -> BigUintDec {
    BigUintDec::from_be_bytes(&to_be(n))
}

// --- comparison ------------------------------------------------------------

/// Total ordering of two unsigned big integers.
pub(crate) fn cmp(a: &BoxedUint, b: &BoxedUint) -> Ordering {
    if a == b {
        Ordering::Equal
    } else if a.lt(b) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// `a >= b`.
pub(crate) fn ge(a: &BoxedUint, b: &BoxedUint) -> bool {
    cmp(a, b) != Ordering::Less
}

/// `a > b`.
pub(crate) fn gt(a: &BoxedUint, b: &BoxedUint) -> bool {
    cmp(a, b) == Ordering::Greater
}

/// Low 64 bits of `n` (for small-modulus checks).
fn low_u64(n: &BoxedUint) -> u64 {
    n.as_limbs().first().copied().unwrap_or(0)
}

/// Bit `i` of `n` (LSB-first), as 0 or 1.
pub(crate) fn bit(n: &BoxedUint, i: usize) -> u8 {
    let limb = i / 64;
    n.as_limbs()
        .get(limb)
        .map_or(0, |&l| ((l >> (i % 64)) & 1) as u8)
}

/// A `BoxedUint` from a `u128`.
pub(crate) fn from_u128(v: u128) -> BoxedUint {
    from_be(&v.to_be_bytes())
}

/// `n mod m` for a small `m` (≤ u32 range), returned as `u64`.
pub(crate) fn mod_small(n: &BoxedUint, m: u64) -> u64 {
    let (_, r) = n.divrem(&u64(m));
    low_u64(&r)
}

// --- plain integer arithmetic ----------------------------------------------

/// `a + b`.
pub(crate) fn add(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    a.add(b)
}

/// `a * b`.
pub(crate) fn mul(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    a.mul(b)
}

/// `a - b`, requires `a >= b`.
pub(crate) fn sub(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    debug_assert!(ge(a, b), "bn::sub underflow");
    a.sub(b)
}

/// `a mod m`.
pub(crate) fn rem(a: &BoxedUint, m: &BoxedUint) -> BoxedUint {
    a.reduce(m)
}

/// `(a, b) -> (a/b, a mod b)`.
pub(crate) fn divrem(a: &BoxedUint, b: &BoxedUint) -> (BoxedUint, BoxedUint) {
    a.divrem(b)
}

/// Floor integer square root (`⌊√n⌋`), matching Go `big.Int.Sqrt`.
pub(crate) fn sqrt(n: &BoxedUint) -> BoxedUint {
    if n.bit_len() <= 1 {
        return n.clone(); // 0 -> 0, 1 -> 1
    }
    // Newton's method, converging downward from an overestimate.
    let mut x = n.clone();
    loop {
        let (q, _) = divrem(n, &x);
        let y = add(&x, &q).shr_bits(1); // (x + n/x) / 2
        if !y.lt(&x) {
            break;
        }
        x = y;
    }
    x
}

/// The secp256k1 group order `n`.
pub(crate) fn secp256k1_order() -> BoxedUint {
    from_be(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ])
}

/// `a⁻¹ mod m` for an arbitrary modulus (even or odd) — extended Euclid, no
/// Montgomery context. `None` if not invertible.
pub(crate) fn mod_inv(a: &BoxedUint, m: &BoxedUint) -> Option<BoxedUint> {
    inv_mod_boxed(&rem(a, m), m)
}

/// Greatest common divisor (binary GCD).
pub(crate) fn gcd(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    let mut a = a.clone();
    let mut b = b.clone();
    if a.is_zero() {
        return b;
    }
    if b.is_zero() {
        return a;
    }
    // Factor out common powers of two.
    let shift = {
        let mut s = 0;
        while !a.is_odd() && !b.is_odd() {
            a = a.shr_bits(1);
            b = b.shr_bits(1);
            s += 1;
        }
        s
    };
    while !a.is_odd() {
        a = a.shr_bits(1);
    }
    loop {
        while !b.is_odd() {
            b = b.shr_bits(1);
        }
        // Now a, b both odd; ensure a <= b then subtract.
        if gt(&a, &b) {
            std::mem::swap(&mut a, &mut b);
        }
        b = b.sub(&a);
        if b.is_zero() {
            break;
        }
    }
    // gcd = a << shift
    let mut g = a;
    for _ in 0..shift {
        g = g.add(&g);
    }
    g
}

// --- modular arithmetic with a fixed modulus -------------------------------

/// A modulus with a cached Montgomery context, for repeated modular ops. The
/// modulus must be odd (all GG18 moduli — `N`, `N²`, `Ñ`, `p`, `q` — are odd).
pub(crate) struct Modulus {
    m: BoxedUint,
    mont: BoxedMontModulus,
}

impl Modulus {
    pub(crate) fn new(m: &BoxedUint) -> Self {
        Modulus {
            m: m.clone(),
            mont: BoxedMontModulus::new(m),
        }
    }

    pub(crate) fn modulus(&self) -> &BoxedUint {
        &self.m
    }

    /// `a mod m`.
    pub(crate) fn reduce(&self, a: &BoxedUint) -> BoxedUint {
        a.reduce(&self.m)
    }

    /// `(a · b) mod m`.
    pub(crate) fn mul(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        self.mont.mul_mod(&self.reduce(a), &self.reduce(b))
    }

    /// `(a + b) mod m`.
    pub(crate) fn add(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        self.mont.add_mod(&self.reduce(a), &self.reduce(b))
    }

    /// `(a − b) mod m`.
    pub(crate) fn sub(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        self.mont.sub_mod(&self.reduce(a), &self.reduce(b))
    }

    /// `base^exp mod m` in constant time (use for secret exponents).
    pub(crate) fn pow(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        self.mont.pow(&self.reduce(base), exp)
    }

    /// `base^exp mod m` for a **public** exponent (faster; do not use for secret
    /// exponents).
    pub(crate) fn pow_pub(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        self.mont.pow_public(&self.reduce(base), exp)
    }

    /// `a⁻¹ mod m`, or `None` if not invertible.
    pub(crate) fn inv(&self, a: &BoxedUint) -> Option<BoxedUint> {
        inv_mod_boxed(&self.reduce(a), &self.m)
    }
}

// --- primality + prime generation ------------------------------------------

const SMALL_PRIMES: &[u64] = &[
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// Miller–Rabin probable-prime test with small-prime trial division.
pub(crate) fn is_probable_prime<R: RngCore>(n: &BoxedUint, rng: &mut R, rounds: usize) -> bool {
    if n.is_zero() || is_one(n) {
        return false;
    }
    let two = u64(2);
    if *n == two {
        return true;
    }
    if !n.is_odd() {
        return false;
    }
    for &p in SMALL_PRIMES {
        if mod_small(n, p) == 0 {
            return *n == u64(p);
        }
    }
    // Write n-1 = d · 2^s.
    let n_minus_1 = sub(n, &one());
    let mut d = n_minus_1.clone();
    let mut s = 0usize;
    while !d.is_odd() {
        d = d.shr_bits(1);
        s += 1;
    }
    let modn = Modulus::new(n);
    'witness: for _ in 0..rounds {
        // Random base a in [2, n-2].
        let a = rand_range(&two, &sub(n, &two), rng);
        let mut x = modn.pow_pub(&a, &d);
        if is_one(&x) || x == n_minus_1 {
            continue;
        }
        for _ in 0..s.saturating_sub(1) {
            x = modn.mul(&x, &x);
            if x == n_minus_1 {
                continue 'witness;
            }
            if is_one(&x) {
                return false;
            }
        }
        return false;
    }
    true
}

/// Generates a Sophie-Germain *safe prime* `p = 2q + 1` (both `p` and `q` prime)
/// of `bits` bits. Slow — callers should cache the result.
pub(crate) fn generate_safe_prime<R: RngCore>(bits: usize, rng: &mut R) -> BoxedUint {
    assert!(bits >= 4);
    let rounds = 20;
    loop {
        // q has bits-1 bits; p = 2q+1 has `bits` bits.
        let mut q = rand_bits(bits - 1, rng);
        // q ≡ 2 (mod 3) keeps p = 2q+1 ≢ 0 (mod 3) (cheap pre-filter).
        if mod_small(&q, 3) != 2 {
            continue;
        }
        if !q.is_odd() {
            q = add(&q, &one());
        }
        let p = add(&add(&q, &q), &one());
        if is_probable_prime(&q, rng, rounds) && is_probable_prime(&p, rng, rounds) {
            return p;
        }
    }
}

// --- randomness ------------------------------------------------------------

/// A uniformly random integer with exactly `bits` bits (top bit set, odd).
pub(crate) fn rand_bits<R: RngCore>(bits: usize, rng: &mut R) -> BoxedUint {
    assert!(bits >= 2);
    let nbytes = bits.div_ceil(8);
    let mut buf = vec![0u8; nbytes];
    rng.fill_bytes(&mut buf);
    // Clear the high bits above `bits`.
    let excess = nbytes * 8 - bits;
    buf[0] &= 0xffu8 >> excess;
    // Set the top bit (exact width) and make odd.
    buf[0] |= 0x80u8 >> excess;
    let last = nbytes - 1;
    buf[last] |= 1;
    from_be(&buf)
}

/// A uniformly random integer in `[0, n)` (rejection sampling).
pub(crate) fn rand_below<R: RngCore>(n: &BoxedUint, rng: &mut R) -> BoxedUint {
    assert!(!n.is_zero());
    let bits = n.bit_len();
    let nbytes = bits.div_ceil(8);
    let excess = nbytes * 8 - bits;
    loop {
        let mut buf = vec![0u8; nbytes];
        rng.fill_bytes(&mut buf);
        buf[0] &= 0xffu8 >> excess;
        let c = from_be(&buf);
        if c.lt(n) {
            return c;
        }
    }
}

/// A uniformly random integer in `[lo, hi]` (inclusive).
pub(crate) fn rand_range<R: RngCore>(lo: &BoxedUint, hi: &BoxedUint, rng: &mut R) -> BoxedUint {
    // span = hi - lo + 1 ; result = lo + rand_below(span)
    let span = add(&sub(hi, lo), &one());
    add(lo, &rand_below(&span, rng))
}

/// A uniformly random unit in `Z*_m` (`gcd(x, m) = 1`).
pub(crate) fn rand_unit<R: RngCore>(m: &BoxedUint, rng: &mut R) -> BoxedUint {
    loop {
        let x = rand_below(m, rng);
        if !x.is_zero() && is_one(&gcd(&x, m)) {
            return x;
        }
    }
}

// --- Jacobi symbol ---------------------------------------------------------

/// Jacobi symbol `(a / n)` for odd `n > 0`, in `{-1, 0, 1}`.
pub(crate) fn jacobi(a: &BoxedUint, n: &BoxedUint) -> i32 {
    debug_assert!(n.is_odd());
    let mut a = rem(a, n);
    let mut n = n.clone();
    let mut result = 1i32;
    while !a.is_zero() {
        while !a.is_odd() {
            a = a.shr_bits(1);
            let r = mod_small(&n, 8);
            if r == 3 || r == 5 {
                result = -result;
            }
        }
        std::mem::swap(&mut a, &mut n);
        if mod_small(&a, 4) == 3 && mod_small(&n, 4) == 3 {
            result = -result;
        }
        a = rem(&a, &n);
    }
    if is_one(&n) { result } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn be_roundtrip_and_dec() {
        let n = from_be(&[0x01, 0x00, 0x00]); // 65536
        assert_eq!(to_be(&n), vec![0x01, 0x00, 0x00]);
        assert_eq!(to_dec(&n).as_be_bytes(), &[0x01, 0x00, 0x00]);
        assert_eq!(to_be(&BoxedUint::zero(1)), Vec::<u8>::new());
    }

    #[test]
    fn gcd_known() {
        assert_eq!(to_be(&gcd(&u64(48), &u64(36))), vec![12]);
        assert_eq!(to_be(&gcd(&u64(17), &u64(5))), vec![1]);
        assert_eq!(to_be(&gcd(&u64(0), &u64(9))), vec![9]);
    }

    #[test]
    fn modular_ops() {
        let m = Modulus::new(&u64(97));
        assert_eq!(to_be(&m.mul(&u64(20), &u64(20))), vec![12]); // 400 mod 97 = 12
        assert_eq!(to_be(&m.pow(&u64(5), &u64(3))), vec![125 % 97]); // 28
        let inv = m.inv(&u64(5)).unwrap();
        assert_eq!(to_be(&m.mul(&u64(5), &inv)), vec![1]);
    }

    #[test]
    fn sqrt_known() {
        assert_eq!(to_be(&sqrt(&u64(0))), Vec::<u8>::new());
        assert_eq!(to_be(&sqrt(&u64(1))), vec![1]);
        assert_eq!(to_be(&sqrt(&u64(15))), vec![3]);
        assert_eq!(to_be(&sqrt(&u64(16))), vec![4]);
        assert_eq!(to_be(&sqrt(&u64(17))), vec![4]);
        assert_eq!(to_be(&sqrt(&u64(1_000_000))), vec![0x03, 0xe8]); // 1000
        let big = mul(&u64(1_234_567), &u64(1_234_567));
        assert_eq!(to_be(&sqrt(&add(&big, &u64(5)))), to_be(&u64(1_234_567)));
    }

    #[test]
    fn jacobi_known() {
        // (2/15) = 1, (7/15) = -1, (3/15) = 0
        assert_eq!(jacobi(&u64(2), &u64(15)), 1);
        assert_eq!(jacobi(&u64(7), &u64(15)), -1);
        assert_eq!(jacobi(&u64(3), &u64(15)), 0);
    }

    #[test]
    fn primality() {
        let mut rng = OsRng;
        assert!(is_probable_prime(&u64(2), &mut rng, 10));
        assert!(is_probable_prime(&u64(97), &mut rng, 10));
        assert!(is_probable_prime(&u64(7919), &mut rng, 10));
        assert!(!is_probable_prime(&u64(91), &mut rng, 10)); // 7·13
        assert!(!is_probable_prime(&u64(1), &mut rng, 10));
    }

    #[test]
    fn safe_prime_small() {
        let mut rng = OsRng;
        let p = generate_safe_prime(20, &mut rng);
        assert!(is_probable_prime(&p, &mut rng, 20));
        let q = sub(&p, &one());
        let q = q.shr_bits(1); // (p-1)/2
        assert!(is_probable_prime(&q, &mut rng, 20), "(p-1)/2 must be prime");
        assert_eq!(p.bit_len(), 20);
    }
}
