//! Hash commitments and the `[][]big.Int` length-prefixed "secrets" framing, ports
//! of Go `tss-lib/crypto/commitments`. A commitment is `C = SHA512_256i(r,
//! secrets...)` with decommitment `D = [r, secrets...]`; verification re-hashes.

#![allow(dead_code)]

use super::bn;
use crate::frost::hashing::sha512_256i;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// `(C, D)` for `secrets`: a random 256-bit nonce `r` is prepended, `C =
/// SHA512_256i(r, secrets...)`, `D = [r, secrets...]`.
pub(crate) fn commit<R: RngCore>(
    secrets: &[BoxedUint],
    rng: &mut R,
) -> (BoxedUint, Vec<BoxedUint>) {
    let r = bn::rand_bits(256, rng);
    let mut d = Vec::with_capacity(secrets.len() + 1);
    d.push(r);
    d.extend_from_slice(secrets);
    let c = hash_ints(&d);
    (c, d)
}

/// Recomputes the commitment from a decommitment and checks it equals `c`; on
/// success returns the committed secrets (`D[1..]`).
pub(crate) fn decommit(c: &BoxedUint, d: &[BoxedUint]) -> Option<Vec<BoxedUint>> {
    if d.len() < 2 {
        return None;
    }
    let got = hash_ints(d);
    if bn::to_be(&got) == bn::to_be(c) {
        Some(d[1..].to_vec())
    } else {
        None
    }
}

/// Flattens parts into the length-prefixed secrets vector (Go `builder.Secrets`):
/// for each part, `len(part)` followed by its elements.
pub(crate) fn build_secrets(parts: &[Vec<BoxedUint>]) -> Vec<BoxedUint> {
    let mut out = Vec::new();
    for p in parts {
        out.push(bn::u64(p.len() as u64));
        out.extend_from_slice(p);
    }
    out
}

/// Inverse of [`build_secrets`] (Go `ParseSecrets`).
pub(crate) fn parse_secrets(secrets: &[BoxedUint]) -> Option<Vec<Vec<BoxedUint>>> {
    if secrets.len() < 2 {
        return None;
    }
    let mut parts = Vec::new();
    let mut el = 0usize;
    let mut is_len = true;
    let mut next_len = 0usize;
    while el < secrets.len() {
        if is_len {
            // The committed length must actually fit in 64 bits before calling
            // `bn::to_u64` (which silently keeps only the low 64 bits), and in
            // usize; otherwise a huge length prefix could be truncated into a
            // small, bogus value.
            if secrets[el].bit_len() > 64 {
                return None;
            }
            next_len = usize::try_from(bn::to_u64(&secrets[el])).ok()?;
            el += 1;
        } else {
            // Checked add: `el + next_len` could otherwise wrap usize in
            // release builds, bypassing the bound check and panicking on the
            // slice below.
            let end = el.checked_add(next_len)?;
            if end > secrets.len() {
                return None;
            }
            parts.push(secrets[el..end].to_vec());
            el = end;
        }
        is_len = !is_len;
    }
    Some(parts)
}

/// `SHA512_256i(ints...)` as a big integer (Go `common.SHA512_256i`).
fn hash_ints(v: &[BoxedUint]) -> BoxedUint {
    let bytes: Vec<Vec<u8>> = v.iter().map(bn::to_be).collect();
    let refs: Vec<&[u8]> = bytes.iter().map(|b| b.as_slice()).collect();
    bn::from_be(&sha512_256i(&refs))
}
