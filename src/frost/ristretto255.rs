//! FROST(ristretto255, SHA-512) ciphersuite — RFC 9591 §6.2.

use super::{Ciphersuite, Scalar};
use purecrypto::ec::ristretto255::{CompressedRistretto, RistrettoPoint};
use purecrypto::hash::sha512;

/// The FROST(ristretto255, SHA-512) ciphersuite domain separator (RFC 9591 §6.2.4).
/// Unlike Ed25519, every H1..H5 includes this prefix — ristretto255 signatures
/// are FROST-specific, not constrained to verify under a stock verifier.
const CONTEXT_STRING: &[u8] = b"FROST-RISTRETTO255-SHA512-v1";

/// FROST(ristretto255, SHA-512). Signatures are 32-byte `R` || 32-byte `S` in
/// the natural Ristretto255 format; not Ed25519-compatible.
pub struct Ristretto255;

impl Ciphersuite for Ristretto255 {
    type Point = RistrettoPoint;

    const NAME: &'static str = "ristretto255";

    fn context_string() -> &'static [u8] {
        CONTEXT_STRING
    }

    fn generator() -> RistrettoPoint {
        RistrettoPoint::basepoint()
    }

    fn identity() -> RistrettoPoint {
        RistrettoPoint::identity()
    }

    fn add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
        a.add(b)
    }

    fn negate(a: &RistrettoPoint) -> RistrettoPoint {
        a.negate()
    }

    fn scalar_mul(p: &RistrettoPoint, s: &Scalar) -> RistrettoPoint {
        p.mul(s)
    }

    fn mul_base(s: &Scalar) -> RistrettoPoint {
        RistrettoPoint::mul_base(s)
    }

    fn eq(a: &RistrettoPoint, b: &RistrettoPoint) -> bool {
        bool::from(a.ct_eq(b))
    }

    fn is_identity(p: &RistrettoPoint) -> bool {
        bool::from(p.ct_eq(&RistrettoPoint::identity()))
    }

    fn encode_point(p: &RistrettoPoint) -> [u8; 32] {
        p.compress().to_bytes()
    }

    fn decode_point(b: &[u8; 32]) -> Option<RistrettoPoint> {
        // Ristretto255 is a prime-order group: no cofactor clearing needed, and
        // decompress already rejects non-canonical encodings (RFC 9496 §4.3.1).
        CompressedRistretto::from_slice(b).decompress()
    }

    fn h1(msg: &[u8]) -> Scalar {
        hash_to_scalar(b"rho", msg)
    }

    fn h2(msg: &[u8]) -> Scalar {
        hash_to_scalar(b"chal", msg)
    }

    fn h3(msg: &[u8]) -> Scalar {
        hash_to_scalar(b"nonce", msg)
    }

    fn h4(msg: &[u8]) -> [u8; 64] {
        sha512(&concat(&[CONTEXT_STRING, b"msg", msg]))
    }

    fn h5(msg: &[u8]) -> [u8; 64] {
        sha512(&concat(&[CONTEXT_STRING, b"com", msg]))
    }
}

/// SHA-512(context || tag || msg) reduced mod L.
fn hash_to_scalar(tag: &[u8], msg: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(&sha512(&concat(&[CONTEXT_STRING, tag, msg])))
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(n: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[0] = n;
        Scalar::from_bytes_canonical(&b).unwrap()
    }

    #[test]
    fn generator_roundtrips_through_encoding() {
        let g = Ristretto255::generator();
        let enc = Ristretto255::encode_point(&g);
        let dec = Ristretto255::decode_point(&enc).unwrap();
        assert!(Ristretto255::eq(&g, &dec));
    }

    #[test]
    fn scalar_base_mult_matches_repeated_add() {
        let lhs = Ristretto255::mul_base(&scalar(3));
        let g = Ristretto255::generator();
        let rhs = Ristretto255::add(&Ristretto255::add(&g, &g), &g);
        assert!(Ristretto255::eq(&lhs, &rhs));
    }

    #[test]
    fn identity_and_negate() {
        assert!(Ristretto255::is_identity(&Ristretto255::identity()));
        assert!(!Ristretto255::is_identity(&Ristretto255::generator()));
        let g = Ristretto255::generator();
        assert!(Ristretto255::is_identity(&Ristretto255::add(
            &g,
            &Ristretto255::negate(&g)
        )));
    }

    #[test]
    fn h2_uses_chal_domain_not_bare() {
        // Unlike Ed25519, H2 is domain-prefixed, so it differs from bare SHA-512.
        let msg = b"x";
        let got = Ristretto255::h2(msg);
        let bare = Scalar::from_bytes_mod_order(&sha512(msg));
        assert!(!bool::from(got.ct_eq(&bare)));
    }
}
