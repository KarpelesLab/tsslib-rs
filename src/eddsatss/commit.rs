//! Hash commitments over big-endian integer "parts" (Go `crypto/commitments`):
//! `C = SHA512_256i(r, parts...)`, decommitment `D = [r, parts...]`. Parts are
//! the big-endian magnitudes of the committed `big.Int`s (e.g. flattened point
//! coordinates).

#![allow(dead_code)]

use crate::frost::hashing::sha512_256i;
use purecrypto::rng::RngCore;

/// `(C, D)` for `parts`: a random 256-bit nonce `r` is prepended; `C` is the
/// 32-byte hash, `D = [r, parts...]` (each big-endian, leading zeros stripped).
pub(crate) fn commit<R: RngCore>(parts: &[Vec<u8>], rng: &mut R) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut r = vec![0u8; 32];
    rng.fill_bytes(&mut r);
    let r = strip(&r);
    let mut d = Vec::with_capacity(parts.len() + 1);
    d.push(r);
    d.extend(parts.iter().map(|p| strip(p)));
    let c = hash(&d);
    (c, d)
}

/// Recomputes the commitment and checks it equals `c`; returns the parts `D[1..]`.
pub(crate) fn decommit(c: &[u8], d: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if d.len() < 2 {
        return None;
    }
    if hash(d) == strip(c) {
        Some(d[1..].to_vec())
    } else {
        None
    }
}

fn hash(parts: &[Vec<u8>]) -> Vec<u8> {
    let stripped: Vec<Vec<u8>> = parts.iter().map(|p| strip(p)).collect();
    let refs: Vec<&[u8]> = stripped.iter().map(|p| p.as_slice()).collect();
    strip(&sha512_256i(&refs))
}

fn strip(be: &[u8]) -> Vec<u8> {
    let off = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    be[off..].to_vec()
}
