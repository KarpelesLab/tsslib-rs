//! Hash-based commitments. Port of tss-lib `crypto/commitments`.
//!
//! `commit` hashes a random 256-bit nonce together with the secret integers
//! (their big-endian magnitudes) via the untagged [`sha512_256i`]. The
//! commitment `C` is published; the decommitment `D = [r, secrets...]` is
//! revealed later, and `decommit` re-hashes `D` and checks it equals `C`,
//! returning the secrets.

use super::hashing::sha512_256i;
use purecrypto::rng::RngCore;

/// Produces a commitment `C` and decommitment `D = [r, secrets...]` over the
/// given secret big-endian magnitudes. `r` is a fresh 256-bit nonce. Both `C`
/// and the `D` entries are returned as big-endian minimal magnitudes (Go
/// `big.Int.Bytes()` form), ready for the wire.
pub fn commit(rng: &mut impl RngCore, secrets: &[Vec<u8>]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut r);

    let mut d: Vec<Vec<u8>> = Vec::with_capacity(secrets.len() + 1);
    d.push(strip(&r).to_vec());
    d.extend(secrets.iter().cloned());

    let c = digest(&d);
    (c, d)
}

/// Verifies that `d` opens `c`, returning the secrets (`d` without its leading
/// nonce) on success.
pub fn decommit(c: &[u8], d: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if d.is_empty() {
        return None;
    }
    if digest(d) != strip(c) {
        return None;
    }
    Some(d[1..].to_vec())
}

/// `SHA512_256i(parts)` as a big-endian minimal magnitude.
fn digest(parts: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    strip(&sha512_256i(&refs)).to_vec()
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn commit_decommit_roundtrip() {
        let secrets = vec![vec![1, 2, 3], vec![0xff, 0x00, 0x11], vec![42]];
        let (c, d) = commit(&mut OsRng, &secrets);
        let opened = decommit(&c, &d).unwrap();
        assert_eq!(opened, secrets);
    }

    #[test]
    fn tampered_commitment_fails() {
        let secrets = vec![vec![1, 2, 3]];
        let (mut c, d) = commit(&mut OsRng, &secrets);
        c[0] ^= 0x01;
        assert!(decommit(&c, &d).is_none());
    }

    #[test]
    fn tampered_decommitment_fails() {
        let secrets = vec![vec![1, 2, 3]];
        let (c, mut d) = commit(&mut OsRng, &secrets);
        d[1][0] ^= 0x01;
        assert!(decommit(&c, &d).is_none());
    }
}
