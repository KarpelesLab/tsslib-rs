//! FROST(secp256k1, SHA-256) primitives (RFC 9591 §6.5) and the BIP340 /
//! BIP341 pieces Taproot needs.
//!
//! Hashes follow RFC 9591 under the context string
//! `FROST-secp256k1-SHA256-TR-v1`, except the challenge, which is BIP340's
//! `hash_BIP0340/challenge(x(R) || x(P) || m)` so the aggregate is a plain
//! BIP340 signature. The RFC test vectors run against the same code under the
//! RFC's own context string (see the tests).

use crate::prelude::*;
use purecrypto::ec::secp256k1::schnorr::tagged_hash;
pub use purecrypto::ec::secp256k1::{AffinePoint, ProjectivePoint as Point, Scalar};
use purecrypto::hash::sha256;

/// A ciphersuite context: the RFC 9591 `contextString` every hash is
/// domain-separated with.
#[derive(Clone, Copy)]
pub(crate) struct Suite {
    ctx: &'static [u8],
}

/// The suite this module signs with.
pub(crate) const TR: Suite = Suite {
    ctx: b"FROST-secp256k1-SHA256-TR-v1",
};

/// Length of an encoded group element (SEC1 compressed).
pub const ELEMENT_LEN: usize = 33;

impl Suite {
    pub(crate) fn context(&self) -> &'static [u8] {
        self.ctx
    }

    /// `hash_to_field(m, 1)` with `expand_message_xmd(SHA-256)`, `L = 48` and
    /// `DST = contextString || tag` (RFC 9591 H1/H2/H3).
    pub(crate) fn hash_to_scalar(&self, tag: &[u8], msg: &[u8]) -> Scalar {
        let mut dst = Vec::with_capacity(self.ctx.len() + tag.len());
        dst.extend_from_slice(self.ctx);
        dst.extend_from_slice(tag);
        scalar_from_be_reduce(&expand_message_xmd_sha256::<48>(msg, &dst))
    }

    /// H1: the per-signer binding factor.
    pub(crate) fn h1(&self, msg: &[u8]) -> Scalar {
        self.hash_to_scalar(b"rho", msg)
    }

    /// H3: nonce derivation.
    pub(crate) fn h3(&self, msg: &[u8]) -> Scalar {
        self.hash_to_scalar(b"nonce", msg)
    }

    /// H4: message digest.
    pub(crate) fn h4(&self, msg: &[u8]) -> [u8; 32] {
        sha256(&concat(&[self.ctx, b"msg", msg]))
    }

    /// H5: commitment-list digest.
    pub(crate) fn h5(&self, msg: &[u8]) -> [u8; 32] {
        sha256(&concat(&[self.ctx, b"com", msg]))
    }

    /// RFC 9591 `nonce_generate`: `H3(random_bytes || SerializeScalar(secret))`
    /// (only the RFC test vectors use the unlabeled form).
    #[cfg(test)]
    pub(crate) fn nonce_generate(&self, random_bytes: &[u8; 32], secret: &Scalar) -> Scalar {
        self.h3(&concat(&[random_bytes, &secret.to_bytes_be()]))
    }

    /// [`nonce_generate`](Self::nonce_generate) with a `label` appended, so the
    /// hiding and binding nonces differ even if the RNG repeats itself (equal
    /// nonces would leak the share).
    pub(crate) fn nonce_generate_labeled(
        &self,
        random_bytes: &[u8; 32],
        secret: &Scalar,
        label: &[u8],
    ) -> Scalar {
        self.h3(&concat(&[random_bytes, &secret.to_bytes_be(), label]))
    }

    /// RFC 9591 §4.4 binding factors, one per commitment in input order:
    /// `H1(Encode(PK) || H4(msg) || H5(encoded list) || SerializeScalar(id))`.
    pub(crate) fn binding_factors(
        &self,
        group_public_key: &Point,
        msg: &[u8],
        commitments: &[NonceCommitment],
    ) -> Option<Vec<Scalar>> {
        let mut prefix = Vec::with_capacity(ELEMENT_LEN + 64);
        prefix.extend_from_slice(&encode_point(group_public_key)?);
        prefix.extend_from_slice(&self.h4(msg));
        prefix.extend_from_slice(&self.h5(&encode_commitment_list(commitments)?));
        Some(
            commitments
                .iter()
                .map(|c| self.h1(&concat(&[&prefix, &c.id.to_bytes_be()])))
                .collect(),
        )
    }
}

/// One signer's nonce commitments `(D_i, E_i)` and identifier.
#[derive(Clone)]
pub(crate) struct NonceCommitment {
    pub id: Scalar,
    pub hiding: Point,
    pub binding: Point,
}

/// RFC 9591 §4.3: `SerializeScalar(id) || Encode(D) || Encode(E)` for each
/// signer in ascending identifier order. `None` if a commitment is the
/// identity (which has no encoding).
fn encode_commitment_list(commitments: &[NonceCommitment]) -> Option<Vec<u8>> {
    let mut sorted: Vec<(&NonceCommitment, [u8; 32])> = commitments
        .iter()
        .map(|c| (c, c.id.to_bytes_be()))
        .collect();
    sorted.sort_unstable_by_key(|c| c.1);
    let mut buf = Vec::with_capacity(commitments.len() * (32 + 2 * ELEMENT_LEN));
    for (c, id) in sorted {
        buf.extend_from_slice(&id);
        buf.extend_from_slice(&encode_point(&c.hiding)?);
        buf.extend_from_slice(&encode_point(&c.binding)?);
    }
    Some(buf)
}

/// RFC 9591 §4.5: `R = Σ_i (D_i + ρ_i·E_i)`, `rho` aligned with `commitments`.
pub(crate) fn group_commitment(commitments: &[NonceCommitment], rho: &[Scalar]) -> Point {
    commitments
        .iter()
        .zip(rho)
        .fold(Point::identity(), |acc, (c, r)| {
            acc.add(&c.hiding.add(&c.binding.mul(r)))
        })
}

/// The Lagrange coefficient at 0 for `id` within `signers` (which lists `id`
/// itself once). `None` if another identifier equals `id` (zero denominator).
pub(crate) fn lagrange_coefficient(id: &Scalar, signers: &[Scalar]) -> Option<Scalar> {
    let mut lambda = Scalar::ONE;
    let mut skipped_self = false;
    for xj in signers {
        if !skipped_self && bool::from(xj.ct_eq(id)) {
            skipped_self = true;
            continue;
        }
        let den = xj.sub(id);
        if bool::from(den.is_zero()) {
            return None;
        }
        lambda = lambda.mul(&xj.mul(&den.invert()));
    }
    Some(lambda)
}

// --- encodings ---

/// SEC1 compressed encoding; `None` for the identity (RFC 9591
/// `SerializeElement` rejects it).
pub fn encode_point(p: &Point) -> Option<[u8; ELEMENT_LEN]> {
    p.to_affine().map(|a| a.to_sec1_compressed())
}

/// Decodes a 33-byte SEC1 compressed element (on-curve, not the identity).
pub fn decode_point(b: &[u8]) -> Option<Point> {
    if b.len() != ELEMENT_LEN || (b[0] != 0x02 && b[0] != 0x03) {
        return None;
    }
    AffinePoint::from_sec1(b).ok().map(|a| a.to_projective())
}

/// Decodes a canonical 32-byte big-endian scalar (`< n`).
pub fn decode_scalar(b: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Scalar::from_bytes_be(&arr).ok()
}

/// Reduces a big-endian integer of any length mod `n` (participant
/// identifiers, 48-byte hash-to-field outputs).
pub fn scalar_from_be_reduce(be: &[u8]) -> Scalar {
    // 2^256 mod n, as (2^128)²: folds the input 32 bytes at a time.
    let mut two128 = [0u8; 32];
    two128[15] = 1;
    let two128 = Scalar::from_bytes_be_reduce(&two128);
    let two256 = two128.mul(&two128);

    let mut acc = Scalar::ZERO;
    let head = be.len() % 32;
    let (first, rest) = be.split_at(head);
    for chunk in core::iter::once(first).chain(rest.chunks(32)) {
        let mut buf = [0u8; 32];
        buf[32 - chunk.len()..].copy_from_slice(chunk);
        acc = acc.mul(&two256).add(&Scalar::from_bytes_be_reduce(&buf));
    }
    acc
}

/// A participant identifier (`PartyId.key`) as a scalar.
pub(crate) fn id_scalar(key: &[u8]) -> Scalar {
    scalar_from_be_reduce(key)
}

/// `[s]G`.
pub(crate) fn mul_base(s: &Scalar) -> Point {
    Point::mul_generator(s)
}

pub(crate) fn point_eq(a: &Point, b: &Point) -> bool {
    bool::from(a.ct_eq(b))
}

pub(crate) fn is_identity(p: &Point) -> bool {
    bool::from(p.is_identity())
}

// --- BIP340 / BIP341 ---

/// Whether `p` has an even `Y` (BIP340 `has_even_y`). The identity is odd.
pub(crate) fn has_even_y(p: &Point) -> bool {
    p.to_affine().is_some_and(|a| a.y_bytes()[31] & 1 == 0)
}

/// The 32-byte x-only encoding of a non-identity point.
pub fn x_only(p: &Point) -> Option<[u8; 32]> {
    p.to_affine().map(|a| a.x_bytes())
}

/// `p` or `-p`, whichever has an even `Y`, and whether `p` was negated.
pub(crate) fn even_y(p: &Point) -> (Point, bool) {
    if has_even_y(p) {
        (*p, false)
    } else {
        (p.negate(), true)
    }
}

/// `+1` or `-1` as a scalar.
pub(crate) fn sign_scalar(negative: bool) -> Scalar {
    if negative {
        Scalar::ONE.negate()
    } else {
        Scalar::ONE
    }
}

/// The BIP340 challenge `int(hash_BIP0340/challenge(x(R) || x(P) || m)) mod n`.
pub(crate) fn bip340_challenge(r_x: &[u8; 32], p_x: &[u8; 32], msg: &[u8]) -> Scalar {
    Scalar::from_bytes_be_reduce(&tagged_hash("BIP0340/challenge", &[r_x, p_x, msg]))
}

/// The BIP341 tweak `t = int(hash_TapTweak(x(P) || merkle_root))`, with an
/// empty merkle root for a key-path-only output (BIP86). `None` if `t >= n`
/// (BIP341 says such an output key is invalid).
pub(crate) fn tap_tweak(internal_x: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Option<Scalar> {
    let h = match merkle_root {
        Some(root) => tagged_hash("TapTweak", &[internal_x, root]),
        None => tagged_hash("TapTweak", &[internal_x]),
    };
    Scalar::from_bytes_be(&h).ok()
}

// --- helpers ---

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256 (`b = 32`, `s = 64`).
fn expand_message_xmd_sha256<const L: usize>(msg: &[u8], dst: &[u8]) -> [u8; L] {
    const B: usize = 32;
    let ell = L.div_ceil(B);
    assert!(ell <= 255 && L <= 0xffff && dst.len() <= 255);
    let mut dst_prime = Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    let l_be = (L as u16).to_be_bytes();
    let b0 = sha256(&concat(&[&[0u8; 64], msg, &l_be, &[0], &dst_prime]));
    let mut out = [0u8; L];
    let mut prev = sha256(&concat(&[&b0, &[1], &dst_prime]));
    for i in 1..=ell {
        let off = (i - 1) * B;
        let n = B.min(L - off);
        out[off..off + n].copy_from_slice(&prev[..n]);
        if i < ell {
            let mut x = [0u8; B];
            for (j, v) in x.iter_mut().enumerate() {
                *v = b0[j] ^ prev[j];
            }
            prev = sha256(&concat(&[&x, &[(i + 1) as u8], &dst_prime]));
        }
    }
    out
}

pub(crate) fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: Suite = Suite {
        ctx: b"FROST-secp256k1-SHA256-v1",
    };

    fn s(h: &str) -> Scalar {
        decode_scalar(&hex::decode(h).unwrap()).unwrap()
    }

    fn p(h: &str) -> Point {
        decode_point(&hex::decode(h).unwrap()).unwrap()
    }

    fn hx(b: &[u8]) -> String {
        hex::encode(b)
    }

    #[test]
    fn expand_message_xmd_matches_rfc9380() {
        // RFC 9380 Appendix K.1, expand_message_xmd(SHA-256), len_in_bytes = 0x20.
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let out = expand_message_xmd_sha256::<32>(b"", dst);
        assert_eq!(
            hx(&out),
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
        );
        let out = expand_message_xmd_sha256::<32>(b"abc", dst);
        assert_eq!(
            hx(&out),
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
        );
    }

    /// RFC 9591 Appendix E.5, FROST(secp256k1, SHA-256): nonces, binding
    /// factors and signature shares, run through this module's primitives
    /// (with the RFC's H2 standing in for the BIP340 challenge).
    #[test]
    fn rfc9591_secp256k1_vectors() {
        let group_pub = p("02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
        let msg = hex::decode("74657374").unwrap();
        let share1 = s("08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c");
        let share3 = s("00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc");

        let rand = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
        let d1 = RFC.nonce_generate(
            &rand("7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2"),
            &share1,
        );
        let e1 = RFC.nonce_generate(
            &rand("47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5"),
            &share1,
        );
        let d3 = RFC.nonce_generate(
            &rand("e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544"),
            &share3,
        );
        let e3 = RFC.nonce_generate(
            &rand("7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9"),
            &share3,
        );
        assert_eq!(
            hx(&d1.to_bytes_be()),
            "841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0"
        );
        assert_eq!(
            hx(&e1.to_bytes_be()),
            "8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80"
        );
        assert_eq!(
            hx(&d3.to_bytes_be()),
            "2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2"
        );
        assert_eq!(
            hx(&e3.to_bytes_be()),
            "7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98"
        );
        assert_eq!(
            hx(&encode_point(&mul_base(&d1)).unwrap()),
            "03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904"
        );

        // Listed out of order on purpose: the encoding sorts by identifier.
        let commitments = vec![
            NonceCommitment {
                id: id_scalar(&[3]),
                hiding: mul_base(&d3),
                binding: mul_base(&e3),
            },
            NonceCommitment {
                id: id_scalar(&[1]),
                hiding: mul_base(&d1),
                binding: mul_base(&e1),
            },
        ];
        let rho = RFC.binding_factors(&group_pub, &msg, &commitments).unwrap();
        assert_eq!(
            hx(&rho[1].to_bytes_be()),
            "3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6"
        );
        assert_eq!(
            hx(&rho[0].to_bytes_be()),
            "93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7"
        );

        let r = group_commitment(&commitments, &rho);
        let c = RFC.hash_to_scalar(
            b"chal",
            &concat(&[
                &encode_point(&r).unwrap(),
                &encode_point(&group_pub).unwrap(),
                &msg,
            ]),
        );
        let ids = [id_scalar(&[1]), id_scalar(&[3])];
        let z1 = d1.add(&e1.mul(&rho[1])).add(
            &lagrange_coefficient(&ids[0], &ids)
                .unwrap()
                .mul(&share1)
                .mul(&c),
        );
        let z3 = d3.add(&e3.mul(&rho[0])).add(
            &lagrange_coefficient(&ids[1], &ids)
                .unwrap()
                .mul(&share3)
                .mul(&c),
        );
        assert_eq!(
            hx(&z1.to_bytes_be()),
            "c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197"
        );
        assert_eq!(
            hx(&z3.to_bytes_be()),
            "0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d"
        );
        let mut sig = encode_point(&r).unwrap().to_vec();
        sig.extend_from_slice(&z1.add(&z3).to_bytes_be());
        assert_eq!(
            hx(&sig),
            "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14\
             d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324"
        );
    }

    #[test]
    fn decode_rejects_non_compressed_and_bad_scalars() {
        let g = encode_point(&Point::generator()).unwrap();
        assert!(decode_point(&g).is_some());
        let mut bad = g;
        bad[0] = 0x04;
        assert!(decode_point(&bad).is_none());
        assert!(decode_point(&g[..32]).is_none());
        // n itself is not a canonical scalar.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        assert!(decode_scalar(&n).is_none());
    }

    #[test]
    fn even_y_normalizes() {
        let p = mul_base(&id_scalar(&[7]));
        let (e, neg) = even_y(&p);
        assert!(has_even_y(&e));
        assert_eq!(neg, !has_even_y(&p));
        assert_eq!(x_only(&e), x_only(&p));
    }
}
