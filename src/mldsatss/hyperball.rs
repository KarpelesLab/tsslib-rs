//! Constant-time hyperball rejection sampler for threshold ML-DSA-44.
//!
//! Threshold signing (ePrint 2025/1166 §4) masks each party's response with a
//! point drawn (approximately) uniformly from a ν-scaled L2 hyperball. The
//! direction is realised by a constant-time discrete Gaussian `D_σ` (σ = 8) over
//! the integers — a CDT lookup against uniform random bits scanned in full — and
//! the radius by integer `ceil(sqrt(·))`. The only cryptographic primitive is
//! SHAKE256 (from `purecrypto`); everything else is plain constant-time integer
//! and float arithmetic, so it lives here rather than being field arithmetic.
//! The output must stay byte-for-byte stable: signers must agree on it.

use crate::prelude::*;
use purecrypto::hash::shake256;
use purecrypto::mldsa::hazmat::{N, Poly, Q};

const L: usize = 4;
const K: usize = 4;
/// Length of an [`FVec`]: `N · (L + K)` float lanes.
pub const FVEC_LEN: usize = N * (L + K);

// Only the test derivation of [`HYPERBALL_CDT`] reads σ at run time.
#[cfg_attr(not(test), allow(dead_code))]
const HYPERBALL_SIGMA: f64 = 8.0;
const HYPERBALL_CDT_SIZE: usize = 64;
const HYPERBALL_BYTES_PER_SAMPLE: usize = 9;

/// `HYPERBALL_CDT[k] = floor(2^64 · Pr[|X| ≤ k])` for `X ~ D_σ` over `Z`.
/// Input-independent; frozen here so the `no_std` build needs no `exp`. The
/// `cdt_matches_exp_derivation` test recomputes it from `exp`.
const HYPERBALL_CDT: [u64; HYPERBALL_CDT_SIZE] = [
    0x0cc42299ea1b2880,
    0x26198a31e7087c00,
    0x3ed8b5d2ebc74a00,
    0x56a52f21ad2a4c00,
    0x6d2d6c23cdb0f800,
    0x822e0300bd88c000,
    0x9573d8f06abcd800,
    0xa6dd324e9aaf6000,
    0xb659a515b43b0000,
    0xc3e90825cd5eb800,
    0xcf998defe6572000,
    0xd98546808e29e800,
    0xe1cf4aabf7392800,
    0xe8a0d08e5065a800,
    0xee2661dc002b3000,
    0xf28d606945e1e800,
    0xf601f6f022e94000,
    0xf8ad856ef1d0a000,
    0xfab58b2e9988d800,
    0xfc3b05c2c1bdd800,
    0xfd5a34c819b30000,
    0xfe2aadde0e9c9000,
    0xfebfab0871b6a000,
    0xff287eb1d119d800,
    0xff711b36d077b000,
    0xffa29f7bab6d7800,
    0xffc3dded6e81c800,
    0xffd9d6fcdb6a4000,
    0xffe82348c40e3000,
    0xfff14c288123b800,
    0xfff7130d3c4e6000,
    0xfffaa9514aa8a000,
    0xfffcdaa46700b800,
    0xfffe2c740ced1800,
    0xfffef4998bdc6000,
    0xffff69581cee7800,
    0xffffac62863b7000,
    0xffffd249459f1800,
    0xffffe761aa0ed000,
    0xfffff2f0d5ca7000,
    0xfffff92d3023a000,
    0xfffffc7d0132d000,
    0xfffffe384bbeb000,
    0xffffff1c7b8db000,
    0xffffff901f3e9800,
    0xffffffc9d112f000,
    0xffffffe627c54000,
    0xfffffff3dbe99800,
    0xfffffffa6209d800,
    0xfffffffd70cf9000,
    0xfffffffeda003800,
    0xffffffff7e143000,
    0xffffffffc7758800,
    0xffffffffe7c49800,
    0xfffffffff5c5d800,
    0xfffffffffbbfd800,
    0xfffffffffe42a800,
    0xffffffffff4c8800,
    0xffffffffffb8c800,
    0xffffffffffe43000,
    0xfffffffffff55000,
    0xfffffffffffbf800,
    0xfffffffffffe8000,
    0xffffffffffff7800,
];

/// Returns `1` if `a ≥ b` (unsigned), `0` otherwise, in constant time.
fn ct_ge_u64(a: u64, b: u64) -> u64 {
    1 - (a.overflowing_sub(b).1 as u64)
}

/// One sample from `D_σ` over `Z` (σ = [`HYPERBALL_SIGMA`]), constant time in
/// the input bytes. `mag_bytes` is compared against the CDT; `sign_byte`'s LSB
/// picks the sign.
fn ct_sample_d_gaussian(mag_bytes: u64, sign_byte: u8) -> i32 {
    let mut k: u64 = 0;
    for &entry in HYPERBALL_CDT.iter().take(HYPERBALL_CDT_SIZE - 1) {
        k += ct_ge_u64(mag_bytes, entry);
    }
    let mag = k as i32;
    let sign_mask = -((sign_byte & 1) as i32);
    (mag ^ sign_mask) - sign_mask
}

/// `x` rounded to the nearest integer, ties away from zero: `f64::round`
/// without `std`, saturating to `i32` like `as i32`. Exact for
/// `|x| < 2^52`, where `x - trunc(x)` is representable; larger doubles are
/// already integers. No data-dependent branch on the (secret) value.
fn round_ties_away(x: f64) -> i32 {
    let t = x as i64; // trunc toward zero; NaN -> 0
    let frac = x - t as f64;
    let r = t
        .saturating_add((frac >= 0.5) as i64)
        .saturating_sub((frac <= -0.5) as i64);
    r.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// `floor(sqrt(n))` via branch-free digit-by-digit iteration (32 rounds).
fn ct_isqrt64(n: u64) -> u64 {
    let mut res: u64 = 0;
    let mut rem = n;
    let mut bit: u64 = 1u64 << 62;
    while bit != 0 {
        let sum = res + bit;
        let ge = ct_ge_u64(rem, sum);
        rem -= ge * sum;
        res = (res >> 1) + ge * bit;
        bit >>= 2;
    }
    res
}

/// `ceil(sqrt(n))` (for `n ≤ ~2^23`, so `s*s` cannot overflow `u64`).
fn ct_iceil_sqrt64(n: u64) -> u64 {
    let s = ct_isqrt64(n);
    s + ct_ge_u64(n, s * s + 1)
}

/// A float vector of `L + K` polynomials × `N` coefficients used by the
/// threshold-ML-DSA-44 hyperball rejection sampler.
#[derive(Clone)]
pub struct FVec {
    v: Vec<f64>,
}

impl FVec {
    /// A zero vector, ready to be filled by [`sample_hyperball`].
    pub fn zero() -> Self {
        FVec {
            v: vec![0.0; FVEC_LEN],
        }
    }

    /// `self = self + other`, coefficient-wise.
    pub fn add_assign(&mut self, other: &FVec) {
        for (a, b) in self.v.iter_mut().zip(other.v.iter()) {
            *a += *b;
        }
    }

    /// Loads `(s1, s2)` into the vector, recentering each coefficient modulo `Q`
    /// into `(-Q/2, Q/2]` before converting to `f64`.
    pub fn from_polys(s1: &[Poly; L], s2: &[Poly; K]) -> FVec {
        let mut out = FVec::zero();
        let half = (Q / 2) as i32;
        for i in 0..(L + K) {
            let poly = if i < L { &s1[i] } else { &s2[i - L] };
            for j in 0..N {
                let mut u = poly.c[j] as i32;
                u += half;
                let t = u - Q as i32;
                u = t + ((t >> 31) & Q as i32);
                u -= half;
                out.v[i * N + j] = u as f64;
            }
        }
        out
    }

    /// Writes the rounded, mod-`Q`-normalized integers back into `(s1, s2)`.
    pub fn round_into(&self, s1: &mut [Poly; L], s2: &mut [Poly; K]) {
        for i in 0..(L + K) {
            for j in 0..N {
                let mut u = round_ties_away(self.v[i * N + j]);
                let t = u >> 31;
                u += t & Q as i32;
                if u >= Q as i32 {
                    u -= Q as i32;
                }
                if i < L {
                    s1[i].c[j] = u as u32;
                } else {
                    s2[i - L].c[j] = u as u32;
                }
            }
        }
    }

    /// Best-effort wipe of every float lane. The vector holds the secret
    /// hyperball mask `y` during signing; call this once the sample is no
    /// longer needed.
    pub fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.v);
    }

    /// Reports whether the ν-scaled L2 norm exceeds `r`. The first `L`
    /// polynomial-worths of lanes are re-divided by `ν²` before accumulation.
    pub fn excess(&self, r: f64, nu: f64) -> bool {
        let mut sq = 0.0f64;
        for i in 0..(L + K) {
            for j in 0..N {
                let val = self.v[i * N + j];
                if i < L {
                    sq += val * val / (nu * nu);
                } else {
                    sq += val * val;
                }
            }
        }
        sq > r * r
    }
}

/// Fills `p` with a point on the ν-scaled L2 hyperball of radius `r`,
/// deterministically derived from `(rhop, nonce)` via SHAKE256. All
/// secret-dependent steps (CDT sampling, `Σ z²`, integer sqrt) are constant
/// time; the trailing `r / sqrt(·)` division and the float scaling operate on
/// quantities recoverable from the public output norm.
pub fn sample_hyperball(p: &mut FVec, r: f64, nu: f64, rhop: &[u8; 64], nonce: u16) {
    const TOTAL: usize = N * (K + L) + 2;
    let mut input = Vec::with_capacity(1 + 64 + 2);
    input.push(b'H'); // domain separator
    input.extend_from_slice(rhop);
    input.push(nonce as u8);
    input.push((nonce >> 8) as u8);

    let mut buf = vec![0u8; TOTAL * HYPERBALL_BYTES_PER_SAMPLE];
    shake256(&input, &mut buf);

    let mut z = [0i32; TOTAL];
    let mut sq: u64 = 0;
    for (i, zi) in z.iter_mut().enumerate() {
        let base = i * HYPERBALL_BYTES_PER_SAMPLE;
        let mut mb = [0u8; 8];
        mb.copy_from_slice(&buf[base..base + 8]);
        let mag_bytes = u64::from_le_bytes(mb);
        *zi = ct_sample_d_gaussian(mag_bytes, buf[base + 8]);
        let v = *zi as i64;
        sq += (v * v) as u64;
    }

    // ceil(sqrt(sq)) guarantees the output norm over the first N·(K+L) lanes is
    // strictly ≤ r.
    let isqrt = ct_iceil_sqrt64(sq);
    let factor = r / isqrt as f64;
    let scale_l = factor * nu;
    let scale_k = factor;

    for i in 0..(N * L) {
        p.v[i] = z[i] as f64 * scale_l;
    }
    for i in (N * L)..(N * (K + L)) {
        p.v[i] = z[i] as f64 * scale_k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference derivation of the CDT (`exp`-based), run with `std`'s floats.
    fn derive_cdt() -> [u64; HYPERBALL_CDT_SIZE] {
        let sigma2 = HYPERBALL_SIGMA * HYPERBALL_SIGMA;
        let tail_extent: i64 = HYPERBALL_CDT_SIZE as i64 + 16;
        let mut rho = 0.0f64;
        let mut k = -tail_extent;
        while k <= tail_extent {
            rho += (-((k * k) as f64) / (2.0 * sigma2)).exp();
            k += 1;
        }
        let scale = (2.0f64).powi(64);
        let mut cdt = [0u64; HYPERBALL_CDT_SIZE];
        let mut acc = 0.0f64;
        for (k, slot) in cdt.iter_mut().enumerate() {
            if k == 0 {
                acc = 1.0 / rho;
            } else {
                acc += 2.0 * (-((k * k) as f64) / (2.0 * sigma2)).exp() / rho;
            }
            let scaled = acc * scale;
            // Clamp to u64::MAX / 0 at the ends (as `f64 as u64` saturates).
            *slot = if scaled >= scale {
                u64::MAX
            } else if scaled <= 0.0 {
                0
            } else {
                scaled as u64
            };
        }
        cdt
    }

    #[test]
    fn cdt_matches_exp_derivation() {
        assert_eq!(derive_cdt(), HYPERBALL_CDT);
    }

    #[test]
    fn round_matches_std() {
        let mut cases = std::vec![
            0.0,
            -0.0,
            0.5,
            -0.5,
            1.5,
            -1.5,
            2.5,
            -2.5,
            0.49999999999999994,
            -0.49999999999999994,
            4503599627370495.5,
            8380416.5,
            -8380416.5,
            1e300,
            -1e300,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        let mut x = 0x9e3779b97f4a7c15u64;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            cases.push((x as i64 as f64) / 2f64.powi((x % 40) as i32));
        }
        for c in cases {
            assert_eq!(round_ties_away(c), c.round() as i32, "round({c})");
        }
    }

    #[test]
    fn deterministic_in_seed_and_nonce() {
        let rhop = [3u8; 64];
        let mut a = FVec::zero();
        let mut b = FVec::zero();
        sample_hyperball(&mut a, 1000.0, 3.0, &rhop, 0);
        sample_hyperball(&mut b, 1000.0, 3.0, &rhop, 0);
        assert_eq!(a.v, b.v, "same (rhop, nonce) must reproduce the sample");
        let mut c = FVec::zero();
        sample_hyperball(&mut c, 1000.0, 3.0, &rhop, 1);
        assert_ne!(a.v, c.v, "different nonce must differ");
    }

    #[test]
    fn norm_within_radius() {
        // The sampled point's ν-scaled L2 norm must be ≤ r (excess is false).
        let rhop = [9u8; 64];
        let mut p = FVec::zero();
        let (r, nu) = (310060.0, 3.0);
        sample_hyperball(&mut p, r, nu, &rhop, 7);
        assert!(!p.excess(r * 1.000001, nu), "norm must not exceed r");
    }

    #[test]
    fn isqrt_matches_floor() {
        for n in [0u64, 1, 2, 3, 4, 15, 16, 17, 1_000_000, 8_380_416] {
            let s = ct_isqrt64(n);
            assert!(s * s <= n && (s + 1) * (s + 1) > n, "isqrt({n})={s}");
        }
    }
}
