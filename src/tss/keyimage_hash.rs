//! Hash selection for the threshold key-image PRF.
//!
//! The key-image construction (`frosttss::KeyImageParty`,
//! `dklstss::KeyImageParty`) hashes twice: an identifier to a curve point, and
//! the resulting key image to a secret scalar. Which digest does that work is a
//! caller choice — a deployment built around Ethereum tooling wants
//! Keccak-256, one following RFC 8032 wants SHA-512, others BLAKE3 or SHA3 —
//! so the ceremonies take a [`HashAlgorithm`] rather than fixing one.
//!
//! The choice is **part of the derivation**: the algorithm's canonical name is
//! mixed into every domain string, so one key and identifier under two digests
//! give two unrelated secrets. It is also bound into the DLEQ transcript, so a
//! committee whose members disagree aborts on a failed proof rather than
//! silently producing an unusable child key. Pick one per deployment and never
//! change it — a different digest makes every previously derived child key
//! unreachable.
//!
//! This module holds only the two adapters the ceremonies need on top of
//! purecrypto's enum: a 32-byte digest for curve-point candidates, and a
//! 64-byte one for unbiased reduction into a scalar field.

pub use purecrypto::hash::HashAlgorithm;

/// The shortest digest a key-image derivation accepts, in bytes. A 32-byte
/// digest is what the curve-point candidate and the scalar reduction both
/// consume; anything shorter would have to be stretched, which buys no security
/// over just naming a wider digest.
pub(crate) const MIN_OUTPUT_LEN: usize = 32;

/// Rejects digests unfit to key a derivation: the broken/short legacy set
/// (`is_legacy`, e.g. SHA-1 and MD5) and anything under 32 bytes of output.
///
/// Returns the reason on rejection, for the caller's error message.
pub(crate) fn validate(alg: HashAlgorithm) -> Result<(), String> {
    if alg.is_legacy() {
        return Err(format!(
            "hash {} is legacy (broken or sub-128-bit collision resistance)",
            alg.name()
        ));
    }
    if alg.output_len() < MIN_OUTPUT_LEN {
        return Err(format!(
            "hash {} emits {} bytes, need at least {MIN_OUTPUT_LEN}",
            alg.name(),
            alg.output_len()
        ));
    }
    Ok(())
}

/// A 32-byte digest of `data` — the leading 32 bytes for wider algorithms.
///
/// Callers must have passed `alg` through [`validate`] first; a shorter digest
/// panics rather than silently zero-padding.
pub(crate) fn digest32(alg: HashAlgorithm, data: &[u8]) -> [u8; 32] {
    let d = alg.digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d.as_slice()[..32]);
    out
}

/// A 64-byte digest of `data`, for unbiased reduction into a ~256-bit scalar
/// field. A 64-byte algorithm is used directly; anything narrower is extended
/// as `H(0x00 ‖ data) ‖ H(0x01 ‖ data)`, truncated to 32 bytes per half.
pub(crate) fn digest64(alg: HashAlgorithm, data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    if alg.output_len() == 64 {
        out.copy_from_slice(alg.digest(data).as_slice());
        return out;
    }
    let mut buf = Vec::with_capacity(data.len() + 1);
    buf.push(0u8);
    buf.extend_from_slice(data);
    out[..32].copy_from_slice(&digest32(alg, &buf));
    buf[0] = 1u8;
    out[32..].copy_from_slice(&digest32(alg, &buf));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::hash::{sha256, sha512};

    #[test]
    fn legacy_and_short_digests_are_rejected() {
        assert!(validate(HashAlgorithm::Sha1).is_err());
        assert!(validate(HashAlgorithm::Md5).is_err());
        // Not legacy, but only 28 bytes out.
        assert!(validate(HashAlgorithm::Sha224).is_err());
        for alg in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Keccak256,
            HashAlgorithm::Blake2b512,
            HashAlgorithm::Blake3,
        ] {
            validate(alg).unwrap_or_else(|e| panic!("{} rejected: {e}", alg.name()));
        }
    }

    #[test]
    fn wide_digests_pass_through_narrow_ones_are_extended() {
        assert_eq!(digest64(HashAlgorithm::Sha512, b"x").to_vec(), sha512(b"x"));
        assert_eq!(
            digest32(HashAlgorithm::Sha512, b"x").to_vec(),
            sha512(b"x")[..32].to_vec()
        );

        let wide = digest64(HashAlgorithm::Sha256, b"x");
        assert_eq!(wide[..32].to_vec(), sha256(&[&[0u8][..], b"x"].concat()));
        assert_eq!(wide[32..].to_vec(), sha256(&[&[1u8][..], b"x"].concat()));
        assert_ne!(wide[..32], wide[32..]);
        // Not just the plain digest repeated.
        assert_ne!(wide[..32].to_vec(), sha256(b"x").to_vec());
    }

    /// Domain separation relies on distinct names and distinct digests.
    #[test]
    fn every_accepted_algorithm_is_distinct() {
        let mut names = std::collections::HashSet::new();
        let mut d32 = std::collections::HashSet::new();
        let mut d64 = std::collections::HashSet::new();
        for &alg in HashAlgorithm::ALL {
            if validate(alg).is_err() {
                continue;
            }
            assert!(names.insert(alg.name()), "duplicate name {}", alg.name());
            assert!(d32.insert(digest32(alg, b"same input")), "{}", alg.name());
            assert!(d64.insert(digest64(alg, b"same input")), "{}", alg.name());
        }
        assert!(names.len() >= 7, "expected a broad accepted set");
    }

    /// Names are the derivation's domain separator; they must round-trip.
    #[test]
    fn names_round_trip_through_from_name() {
        for &alg in HashAlgorithm::ALL {
            assert_eq!(HashAlgorithm::from_name(alg.name()), Some(alg));
        }
    }
}
