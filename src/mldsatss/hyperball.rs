//! Constant-time hyperball rejection sampler for threshold ML-DSA-44.
//!
//! Threshold signing (ePrint 2025/1166 §4) masks each party's response with a
//! point drawn (approximately) uniformly from a ν-scaled L2 hyperball. The
//! direction is realised by a constant-time discrete Gaussian `D_σ` (σ = 8) over
//! the integers — a CDT lookup against uniform random bits scanned in full — and
//! the radius by integer `ceil(sqrt(·))`. The only cryptographic primitive is
//! SHAKE256 (from `purecrypto`); everything else is plain constant-time integer
//! and float arithmetic, so it lives here rather than being field arithmetic.
//! Byte-identical to Go `mldsa` `SampleHyperball44` / `FVec44`.

use purecrypto::hash::shake256;
use purecrypto::mldsa::hazmat::{N, Poly, Q};
use std::sync::OnceLock;

const L: usize = 4;
const K: usize = 4;
/// Length of an [`FVec`]: `N · (L + K)` float lanes.
pub const FVEC_LEN: usize = N * (L + K);

const HYPERBALL_SIGMA: f64 = 8.0;
const HYPERBALL_CDT_SIZE: usize = 64;
const HYPERBALL_BYTES_PER_SAMPLE: usize = 9;

/// `hyperball_cdt()[k] = floor(2^64 · Pr[|X| ≤ k])` for `X ~ D_σ` over `Z`.
/// Computed once from `exp`; the table is input-independent, so the non-CT
/// `exp` here does not affect the side-channel posture of [`sample_hyperball`].
fn hyperball_cdt() -> &'static [u64; HYPERBALL_CDT_SIZE] {
    static CDT: OnceLock<[u64; HYPERBALL_CDT_SIZE]> = OnceLock::new();
    CDT.get_or_init(|| {
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
            // `f64 as u64` saturates to u64::MAX / 0 (matches the Go clamp).
            *slot = if scaled >= scale {
                u64::MAX
            } else if scaled <= 0.0 {
                0
            } else {
                scaled as u64
            };
        }
        cdt
    })
}

/// Returns `1` if `a ≥ b` (unsigned), `0` otherwise, in constant time.
fn ct_ge_u64(a: u64, b: u64) -> u64 {
    1 - (a.overflowing_sub(b).1 as u64)
}

/// One sample from `D_σ` over `Z` (σ = [`HYPERBALL_SIGMA`]), constant time in
/// the input bytes. `mag_bytes` is compared against the CDT; `sign_byte`'s LSB
/// picks the sign.
fn ct_sample_d_gaussian(mag_bytes: u64, sign_byte: u8) -> i32 {
    let cdt = hyperball_cdt();
    let mut k: u64 = 0;
    for &entry in cdt.iter().take(HYPERBALL_CDT_SIZE - 1) {
        k += ct_ge_u64(mag_bytes, entry);
    }
    let mag = k as i32;
    let sign_mask = -((sign_byte & 1) as i32);
    (mag ^ sign_mask) - sign_mask
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
                let mut u = self.v[i * N + j].round() as i32;
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
