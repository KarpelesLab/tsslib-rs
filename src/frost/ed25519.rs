//! FROST(Ed25519, SHA-512) ciphersuite — RFC 9591 §6.1.

use super::{Ciphersuite, Scalar};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::hash::sha512;

/// The FROST(Ed25519, SHA-512) ciphersuite domain separator (RFC 9591 §6.1.4).
/// Mixed into H1/H3/H4/H5 but deliberately NOT into H2 — H2 is the plain
/// Ed25519 challenge hash so signatures verify under any Ed25519 verifier.
const CONTEXT_STRING: &[u8] = b"FROST-ED25519-SHA512-v1";

/// FROST(Ed25519, SHA-512). Produces signatures verifiable by any standard
/// Ed25519 verifier.
pub struct Ed25519;

impl Ciphersuite for Ed25519 {
    type Point = EdwardsPoint;

    const NAME: &'static str = "ed25519";

    fn context_string() -> &'static [u8] {
        CONTEXT_STRING
    }

    fn generator() -> EdwardsPoint {
        EdwardsPoint::generator()
    }

    fn identity() -> EdwardsPoint {
        EdwardsPoint::identity()
    }

    fn add(a: &EdwardsPoint, b: &EdwardsPoint) -> EdwardsPoint {
        a.add(b)
    }

    fn negate(a: &EdwardsPoint) -> EdwardsPoint {
        a.negate()
    }

    fn scalar_mul(p: &EdwardsPoint, s: &Scalar) -> EdwardsPoint {
        p.mul(s)
    }

    fn mul_base(s: &Scalar) -> EdwardsPoint {
        EdwardsPoint::mul_base(s)
    }

    fn eq(a: &EdwardsPoint, b: &EdwardsPoint) -> bool {
        bool::from(a.ct_eq(b))
    }

    fn is_identity(p: &EdwardsPoint) -> bool {
        bool::from(p.ct_eq(&EdwardsPoint::identity()))
    }

    fn encode_point(p: &EdwardsPoint) -> [u8; 32] {
        p.compress()
    }

    fn decode_point(b: &[u8; 32]) -> Option<EdwardsPoint> {
        // Match Go group/ed25519 DecodeElement: decode then cofactor-clear
        // (EightInvEight) to project any on-curve point into the prime-order
        // subgroup. A no-op for the prime-order points honest senders produce.
        let p = EdwardsPoint::decompress(b)?;
        Some(p.mul_by_cofactor().mul(&eight_inv()))
    }

    fn h1(msg: &[u8]) -> Scalar {
        hash_to_scalar(&[CONTEXT_STRING, b"rho", msg])
    }

    fn h2(msg: &[u8]) -> Scalar {
        // Bare SHA-512, reduced mod L: byte-identical to the Ed25519 challenge.
        Scalar::from_bytes_mod_order(&sha512(msg))
    }

    fn h3(msg: &[u8]) -> Scalar {
        hash_to_scalar(&[CONTEXT_STRING, b"nonce", msg])
    }

    fn h4(msg: &[u8]) -> [u8; 64] {
        sha512(&concat(&[CONTEXT_STRING, b"msg", msg]))
    }

    fn h5(msg: &[u8]) -> [u8; 64] {
        sha512(&concat(&[CONTEXT_STRING, b"com", msg]))
    }
}

/// SHA-512(parts...) reduced mod L (RFC 9591 hash-to-scalar).
fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order(&sha512(&concat(parts)))
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    buf
}

/// `(8 mod L)^{-1}` — the scalar used to undo cofactor multiplication when
/// clearing torsion from a decoded element.
fn eight_inv() -> Scalar {
    let mut eight = [0u8; 32];
    eight[0] = 8;
    Scalar::from_bytes_canonical(&eight)
        .expect("8 < L")
        .invert()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::Ciphersuite;

    #[test]
    fn h2_is_bare_sha512_reduced() {
        // H2 must equal from_bytes_mod_order(sha512(msg)) — the Ed25519 challenge.
        let msg = b"FROST H2 test input";
        let got = Ed25519::h2(msg);
        let want = Scalar::from_bytes_mod_order(&sha512(msg));
        assert!(bool::from(got.ct_eq(&want)));
    }

    #[test]
    fn generator_roundtrips_through_encoding() {
        let g = Ed25519::generator();
        let enc = Ed25519::encode_point(&g);
        let dec = Ed25519::decode_point(&enc).unwrap();
        assert!(Ed25519::eq(&g, &dec));
    }

    #[test]
    fn scalar_base_mult_matches_repeated_add() {
        // [3]G == G + G + G
        let mut three = [0u8; 32];
        three[0] = 3;
        let s = Scalar::from_bytes_canonical(&three).unwrap();
        let lhs = Ed25519::mul_base(&s);
        let g = Ed25519::generator();
        let rhs = Ed25519::add(&Ed25519::add(&g, &g), &g);
        assert!(Ed25519::eq(&lhs, &rhs));
    }

    #[test]
    fn identity_is_detected() {
        assert!(Ed25519::is_identity(&Ed25519::identity()));
        assert!(!Ed25519::is_identity(&Ed25519::generator()));
    }

    #[test]
    fn negate_then_add_is_identity() {
        let g = Ed25519::generator();
        let sum = Ed25519::add(&g, &Ed25519::negate(&g));
        assert!(Ed25519::is_identity(&sum));
    }
}
