//! FROST binding factors, group commitment/challenge, Lagrange coefficients,
//! and nonce generation — RFC 9591 §4. Written once against [`Ciphersuite`].

use super::{Ciphersuite, Scalar, encode_scalar, scalar_from_be_mod_l};
use std::collections::HashMap;

/// One signer's pair of nonce commitments `(D_i, E_i)` (RFC 9591 §5.1):
/// `D_i = d_i·G` (hiding) and `E_i = e_i·G` (binding).
#[derive(Clone)]
pub struct NonceCommitment<C: Ciphersuite> {
    /// Participant identifier (big-endian, as stored in `PartyId.key`).
    pub identifier: Vec<u8>,
    /// Hiding commitment `D_i`.
    pub hiding: C::Point,
    /// Binding commitment `E_i`.
    pub binding: C::Point,
}

/// Compares two big-endian magnitudes numerically.
fn cmp_be(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let a = strip(a);
    let b = strip(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

/// Canonical map key for an identifier (leading zeros stripped).
fn id_key(id: &[u8]) -> Vec<u8> {
    strip(id).to_vec()
}

/// Serializes a commitment list sorted by identifier (RFC 9591 §4.3):
/// for each signer, `EncodeScalar(id) || Encode(D_i) || Encode(E_i)`.
pub fn encode_commitment_list<C: Ciphersuite>(commitments: &[NonceCommitment<C>]) -> Vec<u8> {
    let mut sorted: Vec<&NonceCommitment<C>> = commitments.iter().collect();
    sorted.sort_by(|a, b| cmp_be(&a.identifier, &b.identifier));

    let mut buf = Vec::new();
    for c in sorted {
        buf.extend_from_slice(&encode_scalar(&scalar_from_be_mod_l(&c.identifier)));
        buf.extend_from_slice(&C::encode_point(&c.hiding));
        buf.extend_from_slice(&C::encode_point(&c.binding));
    }
    buf
}

/// Derives the per-signer binding factor `rho_i` for every signer
/// (RFC 9591 §4.4). Keyed by canonical identifier bytes.
pub fn compute_binding_factors<C: Ciphersuite>(
    msg: &[u8],
    commitments: &[NonceCommitment<C>],
) -> HashMap<Vec<u8>, Scalar> {
    let encoded_msg = C::h4(msg);
    let encoded_commitments = encode_commitment_list(commitments);
    let encoded_commitment_hash = C::h5(&encoded_commitments);

    let mut prefix = Vec::with_capacity(encoded_msg.len() + encoded_commitment_hash.len());
    prefix.extend_from_slice(&encoded_msg);
    prefix.extend_from_slice(&encoded_commitment_hash);

    let mut out = HashMap::with_capacity(commitments.len());
    for c in commitments {
        let mut input = prefix.clone();
        input.extend_from_slice(&encode_scalar(&scalar_from_be_mod_l(&c.identifier)));
        out.insert(id_key(&c.identifier), C::h1(&input));
    }
    out
}

/// Aggregates per-signer commitments into the group commitment
/// `R = Σ_i (D_i + rho_i·E_i)` (RFC 9591 §4.5). Returns `None` on an empty list
/// or a missing binding factor.
pub fn compute_group_commitment<C: Ciphersuite>(
    commitments: &[NonceCommitment<C>],
    binding_factors: &HashMap<Vec<u8>, Scalar>,
) -> Option<C::Point> {
    let mut r: Option<C::Point> = None;
    for c in commitments {
        let rho = binding_factors.get(&id_key(&c.identifier))?;
        let term = C::add(&c.hiding, &C::scalar_mul(&c.binding, rho));
        r = Some(match r {
            None => term,
            Some(acc) => C::add(&acc, &term),
        });
    }
    r
}

/// Computes the challenge `c = H2(Encode(R) || Encode(A) || msg)` where `A` is
/// the group public key. For Ed25519 this is byte-identical to the RFC 8032
/// challenge.
pub fn compute_group_challenge<C: Ciphersuite>(
    r: &C::Point,
    group_public_key: &C::Point,
    msg: &[u8],
) -> Scalar {
    let mut input = Vec::new();
    input.extend_from_slice(&C::encode_point(r));
    input.extend_from_slice(&C::encode_point(group_public_key));
    input.extend_from_slice(msg);
    C::h2(&input)
}

/// Returns the Lagrange coefficient `lambda_i` for identifier `id` within the
/// signing set `signers`, computed mod `L` (standard Shamir formula at x=0).
/// Identifiers are big-endian and reduced mod `L`. Returns `None` on a
/// duplicate identifier (zero denominator).
pub fn lagrange_coefficient<C: Ciphersuite>(id: &[u8], signers: &[Vec<u8>]) -> Option<Scalar> {
    let id_s = scalar_from_be_mod_l(id);
    let mut lambda = Scalar::ONE;
    for xj in signers {
        let xj_s = scalar_from_be_mod_l(xj);
        if bool::from(xj_s.ct_eq(&id_s)) {
            continue;
        }
        let den = xj_s.sub(&id_s);
        let den_inv = den.invert();
        // invert(0) == 0; a zero denominator means a duplicate identifier.
        if bool::from(den_inv.ct_eq(&Scalar::ZERO)) {
            return None;
        }
        lambda = lambda.mul(&xj_s.mul(&den_inv));
    }
    Some(lambda)
}

/// `nonce_generate` with an extra domain-separation `label` folded into the H3
/// input: `k = H3(random_bytes || EncodeScalar(secret) || label)`.
///
/// FROST signing derives its hiding and binding nonces from the same secret
/// share; labeling the two derivations (`"hiding"` / `"binding"`) guarantees
/// `d_i != e_i` even if the RNG returns identical bytes for both reads (a
/// `d == e` nonce would leak the share).
pub fn nonce_generate_labeled<C: Ciphersuite>(
    random_bytes: &[u8; 32],
    secret: &Scalar,
    label: &[u8],
) -> Scalar {
    let mut input = Vec::with_capacity(64 + label.len());
    input.extend_from_slice(random_bytes);
    input.extend_from_slice(&encode_scalar(secret));
    input.extend_from_slice(label);
    C::h3(&input)
}

/// RFC 9591 §4.1 `nonce_generate`: `k = H3(random_bytes || EncodeScalar(secret))`.
///
/// Mixing the long-term secret into the hash means two calls collide only if
/// *both* the 32 random bytes and the secret collide — far weaker than "the RNG
/// never repeats." `random_bytes` must come from a cryptographic RNG.
pub fn nonce_generate<C: Ciphersuite>(random_bytes: &[u8; 32], secret: &Scalar) -> Scalar {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(random_bytes);
    input.extend_from_slice(&encode_scalar(secret));
    C::h3(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::Ed25519;

    fn scalar_small(n: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[0] = n;
        Scalar::from_bytes_canonical(&b).unwrap()
    }

    #[test]
    fn lagrange_single_signer_is_one() {
        let id = vec![7u8];
        let lam = lagrange_coefficient::<Ed25519>(&id, std::slice::from_ref(&id)).unwrap();
        assert!(bool::from(lam.ct_eq(&Scalar::ONE)));
    }

    #[test]
    fn lagrange_two_signers_matches_formula() {
        // signers {3,5}: lambda_3 = 5/(5-3) = 5 * 2^{-1}.
        let signers = vec![vec![3u8], vec![5u8]];
        let lam3 = lagrange_coefficient::<Ed25519>(&[3], &signers).unwrap();
        let want3 = scalar_small(5).mul(&scalar_small(2).invert());
        assert!(bool::from(lam3.ct_eq(&want3)));

        // lambda_5 = 3/(3-5) = 3 * (-2)^{-1}.
        let lam5 = lagrange_coefficient::<Ed25519>(&[5], &signers).unwrap();
        let want5 = scalar_small(3).mul(&scalar_small(2).negate().invert());
        assert!(bool::from(lam5.ct_eq(&want5)));
    }

    #[test]
    fn lagrange_reconstructs_constant_term() {
        // Degree-1 polynomial f(x) = a0 + a1*x. With shares at x=3 and x=5,
        // a0 == lambda_3*f(3) + lambda_5*f(5).
        let a0 = scalar_small(11);
        let a1 = scalar_small(4);
        let f = |x: u8| a0.add(&a1.mul(&scalar_small(x)));
        let signers = vec![vec![3u8], vec![5u8]];
        let l3 = lagrange_coefficient::<Ed25519>(&[3], &signers).unwrap();
        let l5 = lagrange_coefficient::<Ed25519>(&[5], &signers).unwrap();
        let recon = l3.mul(&f(3)).add(&l5.mul(&f(5)));
        assert!(bool::from(recon.ct_eq(&a0)));
    }

    #[test]
    fn binding_factors_are_deterministic_and_per_signer() {
        let commitments = vec![
            NonceCommitment::<Ed25519> {
                identifier: vec![1],
                hiding: Ed25519::generator(),
                binding: Ed25519::generator(),
            },
            NonceCommitment::<Ed25519> {
                identifier: vec![2],
                hiding: Ed25519::generator(),
                binding: Ed25519::generator(),
            },
        ];
        let msg = b"hello";
        let bf1 = compute_binding_factors::<Ed25519>(msg, &commitments);
        let bf2 = compute_binding_factors::<Ed25519>(msg, &commitments);
        // Deterministic.
        assert!(bool::from(bf1[&vec![1u8]].ct_eq(&bf2[&vec![1u8]])));
        // Distinct per signer.
        assert!(!bool::from(bf1[&vec![1u8]].ct_eq(&bf1[&vec![2u8]])));
    }

    #[test]
    fn group_commitment_sums_terms() {
        let commitments = vec![NonceCommitment::<Ed25519> {
            identifier: vec![1],
            hiding: Ed25519::generator(),
            binding: Ed25519::generator(),
        }];
        let bf = compute_binding_factors::<Ed25519>(b"m", &commitments);
        let r = compute_group_commitment::<Ed25519>(&commitments, &bf).unwrap();
        // R = D + rho*E = G + rho*G = (1+rho)*G.
        let rho = &bf[&vec![1u8]];
        let want = Ed25519::mul_base(&Scalar::ONE.add(rho));
        assert!(Ed25519::eq(&r, &want));
    }
}
