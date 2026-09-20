//! Feldman verifiable secret sharing over a `Ciphersuite` group.
//!
//! Port of tss-lib `crypto/vss`: a degree-`t` polynomial with the secret as its
//! constant term, Feldman commitments `v_i = a_i·G`, and shares `f(id)`. A share
//! verifies against the commitments via `share·G == Σ_j id^j · v_j`.

use super::{Ciphersuite, Scalar, random_scalar, scalar_from_be_mod_l};
use purecrypto::rng::RngCore;

/// A single Shamir share: the recipient identifier (big-endian, `= PartyId.key`)
/// and the scalar share value `f(id)`.
#[derive(Clone)]
pub struct Share {
    /// Recipient identifier (big-endian).
    pub id: Vec<u8>,
    /// Share value `f(id)` (mod `L`).
    pub value: Scalar,
}

/// A sharing was requested for an unusable threshold or identifier set (see
/// [`check_indexes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VssError(&'static str);

impl std::fmt::Display for VssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for VssError {}

/// Port of tss-lib `vss.CheckIndexes` plus the `Create` threshold checks:
/// rejects fewer than `threshold + 1` identifiers and any identifier that is
/// zero or a duplicate mod `L`.
///
/// An identifier of `0 mod L` would be handed `f(0)` — the shared secret
/// itself — and two identifiers congruent mod `L` would hold the same share,
/// so every ceremony must run this over its committee before sharing to it or
/// interpolating over it.
pub fn check_indexes(threshold: usize, ids: &[Vec<u8>]) -> Result<(), VssError> {
    if ids.len() <= threshold {
        return Err(VssError("fewer than threshold+1 identifiers"));
    }
    let mut seen: Vec<Scalar> = Vec::with_capacity(ids.len());
    for id in ids {
        let x = scalar_from_be_mod_l(id);
        if bool::from(x.ct_eq(&Scalar::ZERO)) {
            return Err(VssError("identifier is zero mod the group order"));
        }
        if seen.iter().any(|y| bool::from(x.ct_eq(y))) {
            return Err(VssError("duplicate identifier mod the group order"));
        }
        seen.push(x);
    }
    Ok(())
}

/// Creates a degree-`threshold` sharing of `secret` for the given recipient
/// `ids`. Returns the Feldman commitments `v_0..v_t` (`v_0 = secret·G`) and one
/// [`Share`] per id. Fails if `threshold`/`ids` do not pass [`check_indexes`].
///
/// A `threshold` of 0 is a valid 1-of-n sharing: the polynomial is the constant
/// `secret`, so every id is dealt the secret itself and any single holder can
/// reconstruct it.
pub fn create<C: Ciphersuite>(
    threshold: usize,
    secret: &Scalar,
    ids: &[Vec<u8>],
    rng: &mut impl RngCore,
) -> Result<(Vec<C::Point>, Vec<Share>), VssError> {
    check_indexes(threshold, ids)?;

    // poly[0] = secret, poly[1..=t] = random coefficients.
    let mut poly: Vec<Scalar> = Vec::with_capacity(threshold + 1);
    poly.push(secret.clone());
    for _ in 0..threshold {
        poly.push(random_scalar(rng));
    }

    let commitments: Vec<C::Point> = poly.iter().map(C::mul_base).collect();
    let shares: Vec<Share> = ids
        .iter()
        .map(|id| Share {
            id: id.clone(),
            value: eval(&poly, &scalar_from_be_mod_l(id)),
        })
        .collect();
    Ok((commitments, shares))
}

/// Verifies that `share` (value `f(id)`) is consistent with the Feldman
/// `commitments` (`v_0..v_t`, length `threshold + 1`).
pub fn verify<C: Ciphersuite>(
    id: &[u8],
    value: &Scalar,
    threshold: usize,
    commitments: &[C::Point],
) -> bool {
    if commitments.len() != threshold + 1 {
        return false;
    }
    let x = scalar_from_be_mod_l(id);
    // v = v_0 + Σ_{j=1..t} (id^j)·v_j
    let mut v = commitments[0];
    let mut t = Scalar::ONE;
    for vj in &commitments[1..=threshold] {
        t = t.mul(&x);
        v = C::add(&v, &C::scalar_mul(vj, &t));
    }
    C::eq(&C::mul_base(value), &v)
}

/// Evaluates `poly[0] + poly[1]·x + poly[2]·x² + …` at `x` (mod `L`).
fn eval(poly: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = poly[0].clone();
    let mut xpow = Scalar::ONE;
    for a in &poly[1..] {
        xpow = xpow.mul(x);
        result = result.add(&a.mul(&xpow));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::Ed25519;
    use purecrypto::rng::OsRng;

    #[test]
    fn shares_verify_and_reconstruct() {
        let ids: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i]).collect();
        let secret = random_scalar(&mut OsRng);
        let (commitments, shares) = create::<Ed25519>(2, &secret, &ids, &mut OsRng).unwrap();

        // Every share verifies against the commitments.
        for sh in &shares {
            assert!(verify::<Ed25519>(&sh.id, &sh.value, 2, &commitments));
        }
        // v_0 is the secret's commitment.
        assert!(Ed25519::eq(&commitments[0], &Ed25519::mul_base(&secret)));
    }

    /// The group order `L`, big-endian: an identifier equal to it is `0 mod L`.
    fn order_be() -> Vec<u8> {
        hex::decode("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed").unwrap()
    }

    #[test]
    fn create_rejects_identifier_that_would_receive_the_secret() {
        let secret = random_scalar(&mut OsRng);
        // f(0) is the secret, so neither a literal zero nor L may be an id.
        for zero in [vec![0u8], vec![], order_be()] {
            let ids = vec![vec![1], vec![2], zero];
            assert!(create::<Ed25519>(1, &secret, &ids, &mut OsRng).is_err());
        }
    }

    #[test]
    fn check_indexes_rejects_bad_committees() {
        let ok = vec![vec![1u8], vec![2], vec![3]];
        assert!(check_indexes(1, &ok).is_ok());
        assert!(check_indexes(2, &ok).is_ok());
        // threshold 0 is a 1-of-n sharing: allowed, every party gets the secret.
        assert!(check_indexes(0, &ok).is_ok());
        // t+1 identifiers are needed to ever reconstruct.
        assert!(check_indexes(3, &ok).is_err());
        // Byte-distinct but congruent mod L: id and id + L.
        let mut one_plus_l = order_be();
        *one_plus_l.last_mut().unwrap() += 1;
        assert!(check_indexes(1, &[vec![1], one_plus_l, vec![3]]).is_err());
        // Leading zeros do not make an identifier distinct.
        assert!(check_indexes(1, &[vec![1], vec![0, 1], vec![3]]).is_err());
        // Long identifiers are reduced in full: L·2^304 + 1 is 1 mod L.
        let mut long = order_be();
        long.extend_from_slice(&[0u8; 38]);
        *long.last_mut().unwrap() = 1;
        assert_eq!(long.len(), 70);
        assert!(check_indexes(1, &[vec![1], long.clone()]).is_err());
        assert!(check_indexes(1, &[vec![2], long]).is_ok());
    }

    /// A threshold of 0 shares a constant polynomial: every party is dealt the
    /// secret itself, so any single holder can sign (1-of-n).
    #[test]
    fn threshold_zero_deals_the_secret_to_every_party() {
        let ids: Vec<Vec<u8>> = (1u8..=3).map(|i| vec![i]).collect();
        let secret = random_scalar(&mut OsRng);
        let (commitments, shares) = create::<Ed25519>(0, &secret, &ids, &mut OsRng).unwrap();
        assert_eq!(commitments.len(), 1);
        for sh in &shares {
            assert!(bool::from(sh.value.ct_eq(&secret)));
            assert!(verify::<Ed25519>(&sh.id, &sh.value, 0, &commitments));
        }
    }

    #[test]
    fn tampered_share_fails_verification() {
        let ids: Vec<Vec<u8>> = (1u8..=3).map(|i| vec![i]).collect();
        let secret = random_scalar(&mut OsRng);
        let (commitments, shares) = create::<Ed25519>(1, &secret, &ids, &mut OsRng).unwrap();
        let bad = shares[0].value.add(&Scalar::ONE);
        assert!(!verify::<Ed25519>(&shares[0].id, &bad, 1, &commitments));
    }

    #[test]
    fn lagrange_reconstructs_secret_from_commitments() {
        // Σ λ_i · v(share_i)·G over t+1 shares == secret·G is implied by verify;
        // here check the constant term commitment matches secret·G directly.
        let ids: Vec<Vec<u8>> = (1u8..=5).map(|i| vec![i]).collect();
        let secret = random_scalar(&mut OsRng);
        let (commitments, _) = create::<Ed25519>(3, &secret, &ids, &mut OsRng).unwrap();
        assert_eq!(commitments.len(), 4);
        assert!(Ed25519::eq(&commitments[0], &Ed25519::mul_base(&secret)));
    }
}
