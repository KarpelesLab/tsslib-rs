//! Shared FROST core (RFC 9591), generic over the prime-order group.
//!
//! Both FROST ciphersuites this crate ships — FROST(Ed25519, SHA-512) and
//! FROST(ristretto255, SHA-512) — operate over Curve25519's scalar field, so
//! the [`Scalar`] type is shared and only the point operations and a couple of
//! hash domains differ. The [`Ciphersuite`] trait captures that difference; the
//! protocol math ([`binding`]) is written once against it.
//!
//! This mirrors the Go `crypto/frost` package. Scalar arithmetic is implicitly
//! reduced mod the group order `L`.

pub mod binding;
mod ed25519;

pub use ed25519::Ed25519;
pub use purecrypto::ec::edwards25519::hazmat::Scalar;

/// A FROST ciphersuite: a prime-order group plus the RFC 9591 §6 hash suite
/// (H1..H5). The associated [`Point`](Ciphersuite::Point) is the group element
/// type; scalars are the shared Curve25519 [`Scalar`].
pub trait Ciphersuite {
    /// The group element type.
    type Point: Clone + Copy;

    /// Short identifier ("ed25519", "ristretto255").
    const NAME: &'static str;

    /// The RFC 9591 ciphersuite-specific domain prefix
    /// (e.g. `b"FROST-ED25519-SHA512-v1"`).
    fn context_string() -> &'static [u8];

    // --- group operations ---

    /// The group generator `G` (FROST basepoint).
    fn generator() -> Self::Point;
    /// The group identity element.
    fn identity() -> Self::Point;
    /// `a + b`.
    fn add(a: &Self::Point, b: &Self::Point) -> Self::Point;
    /// `-a`.
    fn negate(a: &Self::Point) -> Self::Point;
    /// `[s] p`.
    fn scalar_mul(p: &Self::Point, s: &Scalar) -> Self::Point;
    /// `[s] G`.
    fn mul_base(s: &Scalar) -> Self::Point;
    /// Group equality.
    fn eq(a: &Self::Point, b: &Self::Point) -> bool;
    /// Whether `p` is the identity element.
    fn is_identity(p: &Self::Point) -> bool;
    /// Canonical 32-byte element encoding (RFC 8032 / RFC 9496).
    fn encode_point(p: &Self::Point) -> [u8; 32];
    /// Decodes a canonical 32-byte element, projecting into the prime-order
    /// subgroup (cofactor clearing). Returns `None` on an invalid encoding.
    fn decode_point(b: &[u8; 32]) -> Option<Self::Point>;

    // --- ciphersuite hashes (RFC 9591 §6) ---

    /// H1: hash to scalar, domain `"rho"` — the per-signer binding factor.
    fn h1(msg: &[u8]) -> Scalar;
    /// H2: the challenge hash. Ed25519 uses bare SHA-512 (no FROST prefix) so
    /// signatures verify under stock Ed25519; ristretto255 uses domain `"chal"`.
    fn h2(msg: &[u8]) -> Scalar;
    /// H3: hash to scalar, domain `"nonce"` — deterministic nonce generation.
    fn h3(msg: &[u8]) -> Scalar;
    /// H4: raw 64-byte digest, domain `"msg"`.
    fn h4(msg: &[u8]) -> [u8; 64];
    /// H5: raw 64-byte digest, domain `"com"`.
    fn h5(msg: &[u8]) -> [u8; 64];
}

// --- shared scalar helpers (Curve25519 scalar field, mod L) ---

/// Encodes a scalar as 32 bytes little-endian (RFC 9591 `EncodeScalar`).
pub fn encode_scalar(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

/// Decodes a canonical 32-byte little-endian scalar in `[0, L)`. Returns `None`
/// if the encoding is non-canonical (`>= L`).
pub fn decode_scalar(b: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_bytes_canonical(b)
}

/// Reduces a big-endian integer (e.g. a participant identifier / `PartyId` key,
/// which may be `>= L`) into a scalar mod `L`. Inputs longer than 64 bytes are
/// reduced from their low 64 bytes — identifiers are always far shorter.
pub fn scalar_from_be_mod_l(be: &[u8]) -> Scalar {
    // Convert big-endian -> little-endian, into a 64-byte buffer for the wide
    // mod-L reduction (matching Go's reduce-then-use of identifiers).
    let mut le = [0u8; 64];
    for (i, &byte) in be.iter().rev().enumerate() {
        if i >= 64 {
            break;
        }
        le[i] = byte;
    }
    Scalar::from_bytes_mod_order(&le)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_encode_decode_roundtrip() {
        // Small canonical scalar.
        let mut le = [0u8; 32];
        le[0] = 42;
        let s = decode_scalar(&le).unwrap();
        assert_eq!(encode_scalar(&s), le);
    }

    #[test]
    fn identifier_reduction_small() {
        // Identifier 5 (big-endian) reduces to scalar 5.
        let s = scalar_from_be_mod_l(&[5]);
        let mut want = [0u8; 32];
        want[0] = 5;
        assert_eq!(encode_scalar(&s), want);
    }
}
