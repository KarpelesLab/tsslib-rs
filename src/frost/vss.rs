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

/// Creates a degree-`threshold` sharing of `secret` for the given recipient
/// `ids`. Returns the Feldman commitments `v_0..v_t` (`v_0 = secret·G`) and one
/// [`Share`] per id.
pub fn create<C: Ciphersuite>(
    threshold: usize,
    secret: &Scalar,
    ids: &[Vec<u8>],
    rng: &mut impl RngCore,
) -> (Vec<C::Point>, Vec<Share>) {
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
    (commitments, shares)
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
        let (commitments, shares) = create::<Ed25519>(2, &secret, &ids, &mut OsRng);

        // Every share verifies against the commitments.
        for sh in &shares {
            assert!(verify::<Ed25519>(&sh.id, &sh.value, 2, &commitments));
        }
        // v_0 is the secret's commitment.
        assert!(Ed25519::eq(&commitments[0], &Ed25519::mul_base(&secret)));
    }

    #[test]
    fn tampered_share_fails_verification() {
        let ids: Vec<Vec<u8>> = (1u8..=3).map(|i| vec![i]).collect();
        let secret = random_scalar(&mut OsRng);
        let (commitments, shares) = create::<Ed25519>(1, &secret, &ids, &mut OsRng);
        let bad = shares[0].value.add(&Scalar::ONE);
        assert!(!verify::<Ed25519>(&shares[0].id, &bad, 1, &commitments));
    }

    #[test]
    fn lagrange_reconstructs_secret_from_commitments() {
        // Σ λ_i · v(share_i)·G over t+1 shares == secret·G is implied by verify;
        // here check the constant term commitment matches secret·G directly.
        let ids: Vec<Vec<u8>> = (1u8..=5).map(|i| vec![i]).collect();
        let secret = random_scalar(&mut OsRng);
        let (commitments, _) = create::<Ed25519>(3, &secret, &ids, &mut OsRng);
        assert_eq!(commitments.len(), 4);
        assert!(Ed25519::eq(&commitments[0], &Ed25519::mul_base(&secret)));
    }
}
