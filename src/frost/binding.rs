//! FROST binding factors, group commitment/challenge, Lagrange coefficients,
//! and nonce generation — RFC 9591 §4. Written once against `Ciphersuite`.

use super::{Ciphersuite, Scalar, encode_scalar, scalar_from_be_mod_l};
use crate::prelude::*;
use alloc::collections::BTreeMap;

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
fn cmp_be(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
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
    sorted.sort_unstable_by(|a, b| cmp_be(&a.identifier, &b.identifier));

    let mut buf = Vec::new();
    for c in sorted {
        buf.extend_from_slice(&encode_scalar(&scalar_from_be_mod_l(&c.identifier)));
        buf.extend_from_slice(&C::encode_point(&c.hiding));
        buf.extend_from_slice(&C::encode_point(&c.binding));
    }
    buf
}

/// Derives the per-signer binding factor `rho_i` for every signer
/// (RFC 9591 §4.4):
/// `H1(Encode(group_public_key) || H4(msg) || H5(encoded commitment list) || EncodeScalar(id))`.
/// `group_public_key` is the key the signature will verify under (the derived
/// child key when signing with an HD tweak). Keyed by canonical identifier bytes.
pub fn compute_binding_factors_with_group_key<C: Ciphersuite>(
    group_public_key: &C::Point,
    msg: &[u8],
    commitments: &[NonceCommitment<C>],
) -> BTreeMap<Vec<u8>, Scalar> {
    binding_factors::<C>(&C::encode_point(group_public_key), msg, commitments)
}

/// Derives the per-signer binding factor `rho_i` for every signer without
/// the group public key:
/// `H1(H4(msg) || H5(encoded commitment list) || EncodeScalar(id))`.
/// Keyed by canonical identifier bytes.
///
/// This is the derivation earlier releases used. RFC 9591 §4.4 also hashes the group
/// public key first; the crate's signing protocols now use
/// [`compute_binding_factors_with_group_key`], and new code should too.
#[deprecated(
    note = "omits the group public key that RFC 9591 §4.4 requires; use compute_binding_factors_with_group_key"
)]
pub fn compute_binding_factors<C: Ciphersuite>(
    msg: &[u8],
    commitments: &[NonceCommitment<C>],
) -> BTreeMap<Vec<u8>, Scalar> {
    binding_factors::<C>(&[], msg, commitments)
}

/// `rho_i = H1(prefix || H4(msg) || H5(encoded commitment list) || EncodeScalar(id))`
/// for every signer, keyed by canonical identifier bytes.
fn binding_factors<C: Ciphersuite>(
    prefix: &[u8],
    msg: &[u8],
    commitments: &[NonceCommitment<C>],
) -> BTreeMap<Vec<u8>, Scalar> {
    let encoded_msg = C::h4(msg);
    let encoded_commitments = encode_commitment_list(commitments);
    let encoded_commitment_hash = C::h5(&encoded_commitments);

    let mut head =
        Vec::with_capacity(prefix.len() + encoded_msg.len() + encoded_commitment_hash.len());
    head.extend_from_slice(prefix);
    head.extend_from_slice(&encoded_msg);
    head.extend_from_slice(&encoded_commitment_hash);

    let mut out = BTreeMap::new();
    for c in commitments {
        let mut input = head.clone();
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
    binding_factors: &BTreeMap<Vec<u8>, Scalar>,
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
/// Identifiers are big-endian and reduced mod `L`. Returns `None` if another
/// signer's identifier is congruent to `id` mod `L` (zero denominator).
pub fn lagrange_coefficient<C: Ciphersuite>(id: &[u8], signers: &[Vec<u8>]) -> Option<Scalar> {
    let id_s = scalar_from_be_mod_l(id);
    let mut lambda = Scalar::ONE;
    // `signers` lists `id` itself once; only that one entry is skipped, so a
    // second identifier congruent to it reaches the zero-denominator check.
    let mut skipped_self = false;
    for xj in signers {
        let xj_s = scalar_from_be_mod_l(xj);
        if !skipped_self && bool::from(xj_s.ct_eq(&id_s)) {
            skipped_self = true;
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

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn scalar_hex(s: &str) -> Scalar {
        Scalar::from_bytes_canonical(&hex32(s)).unwrap()
    }

    /// One signer of an RFC 9591 Appendix E vector, all values hex.
    struct RfcSigner {
        id: u8,
        share: &'static str,
        hiding_nonce: &'static str,
        binding_nonce: &'static str,
        hiding_commitment: &'static str,
        binding_commitment: &'static str,
        binding_factor: &'static str,
        sig_share: &'static str,
    }

    /// Replays an RFC 9591 Appendix E signing vector (participants 1 and 3,
    /// message "test"): binding factors, signature shares, and the final
    /// signature must all match.
    fn check_rfc9591_vector<C: Ciphersuite>(
        group_public_key: &str,
        signers: &[RfcSigner],
        sig: &str,
    ) {
        let gpk = C::decode_point(&hex32(group_public_key)).unwrap();
        let msg = b"test";
        let commitments: Vec<NonceCommitment<C>> = signers
            .iter()
            .map(|s| NonceCommitment {
                identifier: vec![s.id],
                hiding: C::decode_point(&hex32(s.hiding_commitment)).unwrap(),
                binding: C::decode_point(&hex32(s.binding_commitment)).unwrap(),
            })
            .collect();
        let bf = compute_binding_factors_with_group_key::<C>(&gpk, msg, &commitments);
        let r = compute_group_commitment::<C>(&commitments, &bf).unwrap();
        let c = compute_group_challenge::<C>(&r, &gpk, msg);
        let ids: Vec<Vec<u8>> = signers.iter().map(|s| vec![s.id]).collect();
        let mut z = Scalar::ZERO;
        for (s, cm) in signers.iter().zip(commitments.iter()) {
            let rho = &bf[&vec![s.id]];
            assert_eq!(
                encode_scalar(rho),
                hex32(s.binding_factor),
                "rho of P{}",
                s.id
            );
            let d = scalar_hex(s.hiding_nonce);
            let e = scalar_hex(s.binding_nonce);
            assert!(C::eq(&C::mul_base(&d), &cm.hiding));
            assert!(C::eq(&C::mul_base(&e), &cm.binding));
            let lambda = lagrange_coefficient::<C>(&[s.id], &ids).unwrap();
            let zi = d
                .add(&e.mul(rho))
                .add(&lambda.mul(&scalar_hex(s.share)).mul(&c));
            assert_eq!(encode_scalar(&zi), hex32(s.sig_share), "z of P{}", s.id);
            z = z.add(&zi);
        }
        let mut got = C::encode_point(&r).to_vec();
        got.extend_from_slice(&encode_scalar(&z));
        assert_eq!(hex::encode(got), sig);
    }

    /// The deprecated two-argument form keeps its old output: the same
    /// derivation with an empty prefix, so it differs from the RFC form.
    #[test]
    #[allow(deprecated)]
    fn legacy_binding_factors_omit_the_group_key() {
        let gpk = Ed25519::generator();
        let commitments = vec![NonceCommitment::<Ed25519> {
            identifier: vec![1],
            hiding: Ed25519::generator(),
            binding: Ed25519::generator(),
        }];
        let legacy = compute_binding_factors::<Ed25519>(b"m", &commitments);
        assert_eq!(
            legacy[&vec![1u8]],
            binding_factors::<Ed25519>(&[], b"m", &commitments)[&vec![1u8]]
        );
        let rfc = compute_binding_factors_with_group_key::<Ed25519>(&gpk, b"m", &commitments);
        assert_ne!(legacy[&vec![1u8]], rfc[&vec![1u8]]);
    }
    #[test]
    fn rfc9591_ed25519_vector() {
        check_rfc9591_vector::<Ed25519>(
            "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
            &[
                RfcSigner {
                    id: 1,
                    share: "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
                    hiding_nonce: "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
                    binding_nonce: "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
                    hiding_commitment: "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
                    binding_commitment: "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
                    binding_factor: "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603",
                    sig_share: "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
                },
                RfcSigner {
                    id: 3,
                    share: "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
                    hiding_nonce: "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
                    binding_nonce: "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
                    hiding_commitment: "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
                    binding_commitment: "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
                    binding_factor: "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f",
                    sig_share: "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
                },
            ],
            "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe\
             bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b",
        );
    }

    #[cfg(feature = "frostristretto255tss")]
    #[test]
    fn rfc9591_ristretto255_vector() {
        check_rfc9591_vector::<crate::frost::Ristretto255>(
            "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
            &[
                RfcSigner {
                    id: 1,
                    share: "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
                    hiding_nonce: "214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03",
                    binding_nonce: "c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c",
                    hiding_commitment: "965def4d0958398391fc06d8c2d72932608b1e6255226de4fb8d972dac15fd57",
                    binding_commitment: "ec5170920660820007ae9e1d363936659ef622f99879898db86e5bf1d5bf2a14",
                    binding_factor: "8967fd70fa06a58e5912603317fa94c77626395a695a0e4e4efc4476662eba0c",
                    sig_share: "9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09",
                },
                RfcSigner {
                    id: 3,
                    share: "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
                    hiding_nonce: "3f7927872b0f9051dd98dd73eb2b91494173bbe0feb65a3e7e58d3e2318fa40f",
                    binding_nonce: "ffd79445fb8030f0a3ddd3861aa4b42b618759282bfe24f1f9304c7009728305",
                    hiding_commitment: "480e06e3de182bf83489c45d7441879932fd7b434a26af41455756264fbd5d6e",
                    binding_commitment: "3064746dfd3c1862ef58fc68c706da287dd925066865ceacc816b3a28c7b363b",
                    binding_factor: "f2c1bb7c33a10511158c2f1766a4a5fadf9f86f2a92692ed333128277cc31006",
                    sig_share: "7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908",
                },
            ],
            "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb2555\
             2164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802",
        );
    }

    #[test]
    fn lagrange_detects_identifier_congruent_to_self() {
        // L + 3, big-endian: byte-distinct from [3] but the same scalar.
        let mut dup =
            hex::decode("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
                .unwrap();
        *dup.last_mut().unwrap() += 3;
        let signers = vec![vec![3u8], dup, vec![5u8]];
        assert!(lagrange_coefficient::<Ed25519>(&[3], &signers).is_none());
    }

    #[test]
    fn lagrange_single_signer_is_one() {
        let id = vec![7u8];
        let lam = lagrange_coefficient::<Ed25519>(&id, core::slice::from_ref(&id)).unwrap();
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
        let gpk = Ed25519::generator();
        let bf1 = compute_binding_factors_with_group_key::<Ed25519>(&gpk, msg, &commitments);
        let bf2 = compute_binding_factors_with_group_key::<Ed25519>(&gpk, msg, &commitments);
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
        let bf = compute_binding_factors_with_group_key::<Ed25519>(
            &Ed25519::generator(),
            b"m",
            &commitments,
        );
        let r = compute_group_commitment::<Ed25519>(&commitments, &bf).unwrap();
        // R = D + rho*E = G + rho*G = (1+rho)*G.
        let rho = &bf[&vec![1u8]];
        let want = Ed25519::mul_base(&Scalar::ONE.add(rho));
        assert!(Ed25519::eq(&r, &want));
    }
}
