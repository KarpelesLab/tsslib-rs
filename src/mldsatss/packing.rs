//! Full-range (23-bit) polynomial packing for threshold ML-DSA-44.
//!
//! Threshold signing commits to `w = A·r + e` whose coefficients span all of
//! `Z_q`, so the FIPS 204 packers (10-bit `t1`, 18-bit `z`, 6-bit `w1`, …) don't
//! apply. This is the 23-bit-per-coefficient packing the reference uses for the
//! round-2 `w` reveal. It is pure bit-serialization — no field arithmetic — so
//! it lives here rather than in `purecrypto`. Byte-identical to Go
//! `mldsa.PackPolyQ` / `UnpackPolyQ`.
//!
//! Consumed by threshold signing (round-2 `w` reveal), which is blocked on the
//! `purecrypto` hyperball sampler; until that lands these are exercised only by
//! their round-trip tests.
#![allow(dead_code)]

use purecrypto::mldsa::hazmat::{N, Poly};

/// Packed size of one full-range polynomial: `N · 23 / 8 = 736` bytes.
pub const PACK_POLYQ_SIZE: usize = N * 23 / 8;

/// Packs a polynomial with 23-bit little-endian coefficients into `out`.
/// Coefficients must already be reduced into `[0, q)`. Panics if `out` is
/// shorter than [`PACK_POLYQ_SIZE`].
pub fn pack_polyq(f: &Poly, out: &mut [u8]) {
    assert!(out.len() >= PACK_POLYQ_SIZE, "pack_polyq: output too short");
    let mut bit_buf: u64 = 0;
    let mut bit_len: u32 = 0;
    let mut b_idx = 0;
    for &c in f.c.iter() {
        bit_buf |= (c as u64) << bit_len;
        bit_len += 23;
        while bit_len >= 8 {
            out[b_idx] = bit_buf as u8;
            bit_buf >>= 8;
            bit_len -= 8;
            b_idx += 1;
        }
    }
}

/// Allocating form of [`pack_polyq`].
pub fn pack_polyq_vec(f: &Poly) -> Vec<u8> {
    let mut out = vec![0u8; PACK_POLYQ_SIZE];
    pack_polyq(f, &mut out);
    out
}

/// Unpacks a polynomial packed by [`pack_polyq`]. Reads exactly
/// [`PACK_POLYQ_SIZE`] bytes from the front of `b`.
pub fn unpack_polyq(b: &[u8]) -> Poly {
    let mut f = Poly::zero();
    let mut bit_buf: u64 = 0;
    let mut bit_len: u32 = 0;
    let mut b_idx = 0;
    for c in f.c.iter_mut() {
        while bit_len < 23 {
            bit_buf |= (b[b_idx] as u64) << bit_len;
            b_idx += 1;
            bit_len += 8;
        }
        *c = (bit_buf & ((1 << 23) - 1)) as u32;
        bit_buf >>= 23;
        bit_len -= 23;
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::mldsa::hazmat::Q;

    #[test]
    fn roundtrip_full_range() {
        // Spread coefficients across [0, q), including the top of the range.
        let mut p = Poly::zero();
        for (i, c) in p.c.iter_mut().enumerate() {
            *c = ((i as u64 * 0x9E37) % (Q as u64)) as u32;
        }
        let packed = pack_polyq_vec(&p);
        assert_eq!(packed.len(), PACK_POLYQ_SIZE);
        assert_eq!(unpack_polyq(&packed), p);
    }

    #[test]
    fn roundtrip_extremes() {
        let mut p = Poly::zero();
        for (i, c) in p.c.iter_mut().enumerate() {
            *c = if i % 2 == 0 { 0 } else { Q - 1 };
        }
        assert_eq!(unpack_polyq(&pack_polyq_vec(&p)), p);
    }
}
