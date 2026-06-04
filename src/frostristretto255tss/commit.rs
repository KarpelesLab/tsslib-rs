//! Byte-based hash commitment over a list of group elements. Port of
//! `commitElements` / `verifyCommitElements` in internal.go.
//!
//! `commit = SHA-512(randomness(32) || enc(e0) || enc(e1) || …)` where each
//! `enc(e)` is the 32-byte canonical Ristretto255 encoding. The decommitment is
//! `randomness || encodings`. This avoids the `big.Int` length ambiguity of the
//! Ed25519 variant's commitment for 32-byte encodings with leading zeros.

use crate::frost::{Ciphersuite, Ristretto255};
use purecrypto::ec::ristretto255::RistrettoPoint;
use purecrypto::hash::sha512;
use purecrypto::rng::RngCore;

/// Commits to `elements`, returning `(commit, decommit)`. `commit` is the
/// 64-byte SHA-512 digest; `decommit` is `randomness || encodings`.
pub fn commit_elements(rng: &mut impl RngCore, elements: &[RistrettoPoint]) -> (Vec<u8>, Vec<u8>) {
    let mut decommit = Vec::with_capacity(32 + elements.len() * 32);
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);
    decommit.extend_from_slice(&randomness);
    for e in elements {
        decommit.extend_from_slice(&Ristretto255::encode_point(e));
    }
    let commit = sha512(&decommit).to_vec();
    (commit, decommit)
}

/// Verifies a `(commit, decommit)` pair and recovers `count` elements. Returns
/// `None` on a length mismatch, a digest mismatch, or an invalid encoding.
pub fn verify_commit_elements(
    commit: &[u8],
    decommit: &[u8],
    count: usize,
) -> Option<Vec<RistrettoPoint>> {
    if decommit.len() != 32 + count * 32 {
        return None;
    }
    if sha512(decommit).as_slice() != commit {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let enc: [u8; 32] = decommit[32 + i * 32..32 + (i + 1) * 32].try_into().ok()?;
        out.push(Ristretto255::decode_point(&enc)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::Scalar;
    use purecrypto::rng::OsRng;

    fn point(n: u8) -> RistrettoPoint {
        let mut b = [0u8; 32];
        b[0] = n;
        Ristretto255::mul_base(&Scalar::from_bytes_canonical(&b).unwrap())
    }

    #[test]
    fn commit_verify_roundtrip() {
        let els = vec![point(1), point(2), point(3)];
        let (c, d) = commit_elements(&mut OsRng, &els);
        let got = verify_commit_elements(&c, &d, 3).unwrap();
        for (a, b) in els.iter().zip(got.iter()) {
            assert!(Ristretto255::eq(a, b));
        }
    }

    #[test]
    fn tampered_fails() {
        let els = vec![point(1), point(2)];
        let (mut c, d) = commit_elements(&mut OsRng, &els);
        c[0] ^= 1;
        assert!(verify_commit_elements(&c, &d, 2).is_none());
        let (c2, mut d2) = commit_elements(&mut OsRng, &els);
        d2[40] ^= 1;
        assert!(verify_commit_elements(&c2, &d2, 2).is_none());
    }

    #[test]
    fn wrong_count_fails() {
        let els = vec![point(1), point(2)];
        let (c, d) = commit_elements(&mut OsRng, &els);
        assert!(verify_commit_elements(&c, &d, 3).is_none());
    }
}
