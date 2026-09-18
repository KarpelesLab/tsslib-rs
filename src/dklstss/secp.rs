//! Thin secp256k1 group helpers over purecrypto, used throughout dklstss.
//!
//! Scalars are mod the group order `n` (big-endian bytes); points use SEC1
//! compressed encoding on the wire and affine `(x, y)` big-endian magnitudes
//! when hashed into challenges.

pub use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use purecrypto::rng::RngCore;

/// Samples a uniformly random non-zero scalar mod `n`.
pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let s = Scalar::from_bytes_be_reduce(&b);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Reduces a big-endian integer of any length (e.g. a `PartyId` key) mod `n`,
/// as Go's `new(big.Int).Mod(key, n)` does.
pub fn scalar_from_be_reduce(be: &[u8]) -> Scalar {
    let b = strip(be);
    // 2^256 mod n, as (2^128)²: folds the input 32 bytes at a time.
    let mut two128 = [0u8; 32];
    two128[15] = 1;
    let two128 = Scalar::from_bytes_be_reduce(&two128);
    let two256 = two128.mul(&two128);

    let mut acc = Scalar::from_bytes_be_reduce(&[0u8; 32]);
    let head = b.len() % 32;
    let (first, rest) = b.split_at(head);
    for chunk in std::iter::once(first).chain(rest.chunks(32)) {
        let mut buf = [0u8; 32];
        buf[32 - chunk.len()..].copy_from_slice(chunk);
        acc = acc.mul(&two256).add(&Scalar::from_bytes_be_reduce(&buf));
    }
    acc
}

/// A scalar as its big-endian minimal magnitude (Go `big.Int.Bytes()`).
pub fn scalar_to_be_min(s: &Scalar) -> Vec<u8> {
    strip(&s.to_bytes_be()).to_vec()
}

/// `[s]·G`.
pub fn mul_base(s: &Scalar) -> ProjectivePoint {
    ProjectivePoint::mul_generator(s)
}

/// Whether two points are equal.
pub fn point_eq(a: &ProjectivePoint, b: &ProjectivePoint) -> bool {
    bool::from(a.ct_eq(b))
}

/// The affine `(x, y)` coordinates of `p` as big-endian minimal magnitudes, for
/// hashing into a Fiat-Shamir challenge. Returns `(0, 0)` for the identity.
pub fn affine_be(p: &ProjectivePoint) -> (Vec<u8>, Vec<u8>) {
    match p.to_affine() {
        Some(a) => (strip(&a.x_bytes()).to_vec(), strip(&a.y_bytes()).to_vec()),
        None => (Vec::new(), Vec::new()),
    }
}

/// Encodes a non-identity point as 33-byte SEC1 compressed; `None` for identity.
pub fn to_sec1_compressed(p: &ProjectivePoint) -> Option<[u8; 33]> {
    p.to_affine().map(|a| a.to_sec1_compressed())
}

/// Decodes a SEC1 point (compressed or uncompressed) into a projective point.
pub fn from_sec1(bytes: &[u8]) -> Option<ProjectivePoint> {
    AffinePoint::from_sec1(bytes)
        .ok()
        .map(|a| a.to_projective())
}

/// The secp256k1 generator `G`.
pub fn generator() -> ProjectivePoint {
    ProjectivePoint::generator()
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
    fn reduce_handles_inputs_longer_than_32_bytes() {
        // n·2^16 + 5 is 5 mod n; truncating to the low 32 bytes would not be.
        let mut be =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap();
        be.extend_from_slice(&[0, 5]);
        let five = scalar_from_be_reduce(&[5]);
        assert!(bool::from(scalar_from_be_reduce(&be).ct_eq(&five)));
        assert!(bool::from(scalar_from_be_reduce(&be[..32]).is_zero()));
    }

    #[test]
    fn sec1_roundtrip() {
        let s = random_scalar(&mut OsRng);
        let p = mul_base(&s);
        let enc = to_sec1_compressed(&p).unwrap();
        assert_eq!(enc.len(), 33);
        let back = from_sec1(&enc).unwrap();
        assert!(point_eq(&p, &back));
    }

    #[test]
    fn base_mult_matches_add() {
        let three = scalar_from_be_reduce(&[3]);
        let g = generator();
        let lhs = mul_base(&three);
        let rhs = g.add(&g).add(&g);
        assert!(point_eq(&lhs, &rhs));
    }

    #[test]
    fn identifier_reduction() {
        let s = scalar_from_be_reduce(&[5]);
        assert_eq!(scalar_to_be_min(&s), vec![5]);
    }
}
