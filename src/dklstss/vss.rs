//! Feldman verifiable secret sharing over secp256k1 (for DKLs keygen).

use super::secp::{self, ProjectivePoint, Scalar};
use purecrypto::rng::RngCore;

/// Creates a degree-`t` sharing of `secret` for recipient ids `ids`. Returns the
/// Feldman commitments `v_0..v_t` (`v_0 = secret·G`) and `shares[k] = f(ids[k])`.
pub fn create(
    t: usize,
    secret: &Scalar,
    ids: &[Scalar],
    rng: &mut impl RngCore,
) -> (Vec<ProjectivePoint>, Vec<Scalar>) {
    let mut poly: Vec<Scalar> = Vec::with_capacity(t + 1);
    poly.push(secret.clone());
    for _ in 0..t {
        poly.push(secp::random_scalar(rng));
    }
    let commitments: Vec<ProjectivePoint> = poly.iter().map(secp::mul_base).collect();
    let shares: Vec<Scalar> = ids.iter().map(|id| eval(&poly, id)).collect();
    (commitments, shares)
}

/// Verifies `share = f(id)` against the commitments: `share·G == Σ_c id^c · v_c`.
pub fn verify(id: &Scalar, share: &Scalar, t: usize, commitments: &[ProjectivePoint]) -> bool {
    if commitments.len() != t + 1 {
        return false;
    }
    secp::point_eq(&secp::mul_base(share), &horner_eval_points(commitments, id))
}

/// `Σ_i (commitments[i] evaluated at id)` — the point `(Σ_i f_i(id))·G`.
pub fn evaluate_commitment_sum(
    commitments: &[Vec<ProjectivePoint>],
    id: &Scalar,
) -> ProjectivePoint {
    let mut acc: Option<ProjectivePoint> = None;
    for vs in commitments {
        let e = horner_eval_points(vs, id);
        acc = Some(match acc {
            None => e,
            Some(a) => a.add(&e),
        });
    }
    acc.expect("at least one commitment")
}

/// Horner evaluation of a committed polynomial at `id`: `Σ_c id^c · v_c`.
fn horner_eval_points(vs: &[ProjectivePoint], id: &Scalar) -> ProjectivePoint {
    let mut eval = vs[vs.len() - 1];
    for k in (0..vs.len() - 1).rev() {
        eval = eval.mul(id).add(&vs[k]);
    }
    eval
}

/// Evaluates `poly[0] + poly[1]·x + …` at `x` (mod n).
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
    use purecrypto::rng::OsRng;

    #[test]
    fn shares_verify() {
        let ids: Vec<Scalar> = (1u8..=4)
            .map(|i| secp::scalar_from_be_reduce(&[i]))
            .collect();
        let secret = secp::random_scalar(&mut OsRng);
        let (commitments, shares) = create(2, &secret, &ids, &mut OsRng);
        for (id, sh) in ids.iter().zip(shares.iter()) {
            assert!(verify(id, sh, 2, &commitments));
        }
        assert!(secp::point_eq(&commitments[0], &secp::mul_base(&secret)));
    }

    #[test]
    fn tampered_share_fails() {
        let ids: Vec<Scalar> = (1u8..=3)
            .map(|i| secp::scalar_from_be_reduce(&[i]))
            .collect();
        let secret = secp::random_scalar(&mut OsRng);
        let (commitments, shares) = create(1, &secret, &ids, &mut OsRng);
        let bad = shares[0].add(&Scalar::ONE);
        assert!(!verify(&ids[0], &bad, 1, &commitments));
    }
}
