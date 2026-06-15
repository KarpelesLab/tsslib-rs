//! Paillier-Blum modulus proof: `N` is a product of two primes `≡ 3 (mod 4)`.
//! 80-iteration ZK proof. Port of Go `tss-lib/crypto/modproof` (GG18 keygen).

#![allow(dead_code)]
// Index-paired loops over the per-iteration X/Z/Y/A-bit/B-bit arrays read closer
// to the reference than iterator adapters; allow them module-wide.
#![allow(clippy::needless_range_loop)]

use super::Error;
use super::bn::{self, Modulus};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// Soundness iterations (must match Go).
pub(crate) const ITERATIONS: usize = 80;

/// A Paillier-Blum modulus proof.
pub(crate) struct ProofMod {
    pub w: BoxedUint,
    pub x: Vec<BoxedUint>, // ITERATIONS
    pub a: BoxedUint,
    pub b: BoxedUint,
    pub z: Vec<BoxedUint>, // ITERATIONS
}

impl ProofMod {
    /// Big-endian parts: `W, A, B`, then 80 `X` values, then 80 `Z` values.
    pub(crate) fn to_parts(&self) -> Vec<Vec<u8>> {
        let mut out = vec![bn::to_be(&self.w), bn::to_be(&self.a), bn::to_be(&self.b)];
        out.extend(self.x.iter().map(bn::to_be));
        out.extend(self.z.iter().map(bn::to_be));
        out
    }

    /// Inverse of [`ProofMod::to_parts`].
    pub(crate) fn from_parts(parts: &[Vec<u8>]) -> Option<ProofMod> {
        if parts.len() != 3 + 2 * ITERATIONS {
            return None;
        }
        let w = bn::from_be(&parts[0]);
        let a = bn::from_be(&parts[1]);
        let b = bn::from_be(&parts[2]);
        let x = parts[3..3 + ITERATIONS]
            .iter()
            .map(|p| bn::from_be(p))
            .collect();
        let z = parts[3 + ITERATIONS..]
            .iter()
            .map(|p| bn::from_be(p))
            .collect();
        Some(ProofMod { w, x, a, b, z })
    }
}

/// `Jacobi(v, n) == 1`.
fn is_qr(v: &BoxedUint, n: &BoxedUint) -> bool {
    bn::jacobi(v, n) == 1
}

/// The sequential challenges `Y[i] = SHA512_256i_TAGGED(session, W, N, Y[0..i]) mod N`.
fn challenges(session: &[u8], w: &BoxedUint, n: &BoxedUint) -> Vec<BoxedUint> {
    let mut y: Vec<BoxedUint> = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let mut ops: Vec<Vec<u8>> = Vec::with_capacity(2 + i);
        ops.push(bn::to_be(w));
        ops.push(bn::to_be(n));
        for yj in &y {
            ops.push(bn::to_be(yj));
        }
        let refs: Vec<&[u8]> = ops.iter().map(|v| v.as_slice()).collect();
        let h = sha512_256i_tagged(session, &refs);
        y.push(bn::rem(&bn::from_be(&h), n));
    }
    y
}

/// A random quadratic non-residue mod `N` (`Jacobi == −1`).
fn random_qnr<R: RngCore>(n: &BoxedUint, rng: &mut R) -> BoxedUint {
    loop {
        let w = bn::rand_below(n, rng);
        if !w.is_zero() && bn::jacobi(&w, n) == -1 {
            return w;
        }
    }
}

/// Proves `N = P·Q` with `P, Q ≡ 3 (mod 4)` (Blum integer).
pub(crate) fn prove<R: RngCore>(
    session: &[u8],
    n: &BoxedUint,
    p: &BoxedUint,
    q: &BoxedUint,
    rng: &mut R,
) -> Result<ProofMod, Error> {
    let phi = bn::mul(&bn::sub(p, &bn::one()), &bn::sub(q, &bn::one()));
    let w = random_qnr(n, rng);
    let y = challenges(session, &w, n);

    let inv_n = bn::mod_inv(n, &phi)
        .ok_or_else(|| Error::Validation("modproof: N not invertible mod φ".into()))?;
    // expo = ((φ + 4) >> 3)² mod φ  (φ is even, so reduce without Montgomery).
    let e0 = bn::add(&phi, &bn::u64(4)).shr_bits(3);
    let expo = bn::rem(&bn::mul(&e0, &e0), &phi);

    let modn = Modulus::new(n);
    let mut x = vec![bn::u64(0); ITERATIONS];
    let mut z = vec![bn::u64(0); ITERATIONS];
    let mut a_bits: u128 = 1 << ITERATIONS;
    let mut b_bits: u128 = 1 << ITERATIONS;
    for i in 0..ITERATIONS {
        let mut found = false;
        for j in 0..4u8 {
            let (ab, bb) = (j & 1, (j >> 1) & 1);
            let mut yi = y[i].clone();
            if ab == 1 {
                yi = modn.sub(&bn::u64(0), &yi); // −Y[i] mod N
            }
            if bb == 1 {
                yi = modn.mul(&w, &yi); // W·Y[i] mod N
            }
            if is_qr(&yi, p) && is_qr(&yi, q) {
                x[i] = modn.pow_secret(&yi, &expo); // fourth root
                z[i] = modn.pow_secret(&y[i], &inv_n);
                a_bits |= (ab as u128) << i;
                b_bits |= (bb as u128) << i;
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Validation(
                "modproof: modulus is not a Blum integer".into(),
            ));
        }
    }
    Ok(ProofMod {
        w,
        x,
        a: bn::from_u128(a_bits),
        b: bn::from_u128(b_bits),
        z,
    })
}

/// Verifies a Paillier-Blum modulus proof for `N`.
pub(crate) fn verify<R: RngCore>(
    session: &[u8],
    n: &BoxedUint,
    pf: &ProofMod,
    rng: &mut R,
) -> bool {
    if pf.x.len() != ITERATIONS || pf.z.len() != ITERATIONS {
        return false;
    }
    // W: quadratic non-residue, unit, in (0, N).
    if is_qr(&pf.w, n) || pf.w.is_zero() || !pf.w.lt(n) {
        return false;
    }
    if !bn::is_one(&bn::gcd(&pf.w, n)) {
        return false;
    }
    for v in pf.z.iter().chain(pf.x.iter()) {
        if v.is_zero() || !v.lt(n) {
            return false;
        }
    }
    if pf.a.bit_len() != ITERATIONS + 1 || pf.b.bit_len() != ITERATIONS + 1 {
        return false;
    }
    // N odd and composite.
    if !n.is_odd() || bn::is_probable_prime(n, rng, 30) {
        return false;
    }

    let y = challenges(session, &pf.w, n);
    let modn = Modulus::new(n);
    let four = bn::u64(4);
    for i in 0..ITERATIONS {
        // Z[i]^N == Y[i]
        if modn.pow_pub(&pf.z[i], n) != y[i] {
            return false;
        }
        // X[i]^4 == (±)(W^b)·Y[i]
        let left = modn.pow_pub(&pf.x[i], &four);
        let mut right = y[i].clone();
        if bn::bit(&pf.a, i) == 1 {
            right = modn.sub(&bn::u64(0), &right);
        }
        if bn::bit(&pf.b, i) == 1 {
            right = modn.mul(&pf.w, &right);
        }
        if left != right {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::testvec::{dec, fixtures};
    use super::*;

    fn load(v: &serde_json::Value) -> ProofMod {
        ProofMod {
            w: dec(&v["W"]),
            x: v["X"].as_array().unwrap().iter().map(dec).collect(),
            a: dec(&v["A"]),
            b: dec(&v["B"]),
            z: v["Z"].as_array().unwrap().iter().map(dec).collect(),
        }
    }

    #[test]
    fn go_modproof_verifies() {
        let f = fixtures();
        let mp = &f["modproof"];
        let session = mp["session"].as_str().unwrap().as_bytes();
        let n = dec(&mp["n"]);
        let pf = load(mp);
        let mut rng = purecrypto::rng::OsRng;
        assert!(
            verify(session, &n, &pf, &mut rng),
            "Go modproof must verify"
        );

        let mut bad = load(mp);
        bad.z[3] = bn::add(&bad.z[3], &bn::one());
        assert!(!verify(session, &n, &bad, &mut rng));
    }

    #[test]
    fn rust_modproof_roundtrip() {
        let f = fixtures();
        let mp = &f["modproof"];
        let (n, p, q) = (dec(&mp["n"]), dec(&mp["p"]), dec(&mp["q"]));
        let session = b"rust-mod-session";
        let mut rng = purecrypto::rng::OsRng;
        let proof = prove(session, &n, &p, &q, &mut rng).unwrap();
        assert!(verify(session, &n, &proof, &mut rng));
        assert!(!verify(b"other", &n, &proof, &mut rng));
    }
}
