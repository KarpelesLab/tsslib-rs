//! Feldman VSS over secp256k1 (GG18 keygen/resharing). Port of Go
//! `tss-lib/crypto/vss`. Works in the scalar field mod the curve order `q`.

#![allow(dead_code)]

use super::secp;
use purecrypto::ec::secp256k1::{ProjectivePoint, Scalar};
use purecrypto::rng::RngCore;

/// One Shamir share: `(id, f(id))`.
pub(crate) struct Share {
    pub id: Scalar,
    pub value: Scalar,
}

/// Random non-zero scalar mod `q`.
pub(crate) fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let s = Scalar::from_bytes_be_reduce(&b);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Port of Go `vss.CheckIndexes`: rejects a share id that is zero or a
/// duplicate mod the group order. An id of zero would be dealt `f(0)` — the
/// secret itself — and two equal ids would hold the same share.
pub(crate) fn check_indexes(ids: &[Scalar]) -> Result<(), &'static str> {
    for (i, a) in ids.iter().enumerate() {
        if bool::from(a.is_zero()) {
            return Err("party key is zero mod the group order");
        }
        if ids[i + 1..].iter().any(|b| bool::from(a.ct_eq(b))) {
            return Err("duplicate party keys mod the group order");
        }
    }
    Ok(())
}

/// Creates a degree-`t` sharing of `secret` for recipient `ids`. Returns the
/// Feldman commitments `v_0..v_t` (`v_0 = secret·G`) and one share per id.
pub(crate) fn create<R: RngCore>(
    t: usize,
    secret: &Scalar,
    ids: &[Scalar],
    rng: &mut R,
) -> Result<(Vec<ProjectivePoint>, Vec<Share>), &'static str> {
    if t < 1 {
        return Err("threshold must be at least 1");
    }
    if ids.len() <= t {
        return Err("fewer than threshold+1 share ids");
    }
    check_indexes(ids)?;

    let mut poly: Vec<Scalar> = Vec::with_capacity(t + 1);
    poly.push(secret.clone());
    for _ in 0..t {
        poly.push(random_scalar(rng));
    }
    let commitments: Vec<ProjectivePoint> =
        poly.iter().map(ProjectivePoint::mul_generator).collect();
    let shares = ids
        .iter()
        .map(|id| Share {
            id: id.clone(),
            value: eval(&poly, id),
        })
        .collect();
    Ok((commitments, shares))
}

/// Verifies `share = f(id)` against commitments: `share·G == Σ_c id^c · v_c`.
pub(crate) fn verify(
    id: &Scalar,
    value: &Scalar,
    t: usize,
    commitments: &[ProjectivePoint],
) -> bool {
    if commitments.len() != t + 1 {
        return false;
    }
    secp::eq(
        &ProjectivePoint::mul_generator(value),
        &horner(commitments, id),
    )
}

/// `Σ_i eval(commitments[i], id)` — sum of multiple dealers' commitments at `id`.
pub(crate) fn evaluate_commitment_sum(
    commitments: &[Vec<ProjectivePoint>],
    id: &Scalar,
) -> ProjectivePoint {
    let mut acc: Option<ProjectivePoint> = None;
    for vs in commitments {
        let e = horner(vs, id);
        acc = Some(match acc {
            None => e,
            Some(a) => a.add(&e),
        });
    }
    acc.expect("at least one commitment")
}

/// Lagrange reconstruction of `f(0)` from `shares`.
pub(crate) fn reconstruct(shares: &[Share]) -> Scalar {
    let mut secret = Scalar::ZERO;
    for (i, si) in shares.iter().enumerate() {
        let mut times = Scalar::ONE;
        for (j, sj) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let sub = sj.id.sub(&si.id);
            let div = sj.id.mul(&sub.invert());
            times = times.mul(&div);
        }
        secret = secret.add(&si.value.mul(&times));
    }
    secret
}

/// `Σ_c id^c · v_c` (Horner over the committed polynomial).
fn horner(vs: &[ProjectivePoint], id: &Scalar) -> ProjectivePoint {
    let mut eval = vs[vs.len() - 1];
    for k in (0..vs.len() - 1).rev() {
        eval = eval.mul(id).add(&vs[k]);
    }
    eval
}

/// `poly[0] + poly[1]·x + …` (mod q).
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

    #[test]
    fn create_rejects_ids_that_leak_or_collide() {
        let mut rng = purecrypto::rng::OsRng;
        let id = |b: &[u8]| secp::scalar_from_be(b);
        let secret = random_scalar(&mut rng);
        let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        // A key equal to the group order is id 0 and would be dealt the secret.
        assert!(create(1, &secret, &[id(&[1]), id(&order)], &mut rng).is_err());
        // Equal ids hold the same share.
        assert!(create(1, &secret, &[id(&[1]), id(&[0, 1])], &mut rng).is_err());
        // Threshold 0 hands every party the secret; t+1 ids are needed.
        assert!(create(0, &secret, &[id(&[1]), id(&[2])], &mut rng).is_err());
        assert!(create(2, &secret, &[id(&[1]), id(&[2])], &mut rng).is_err());
        assert!(create(1, &secret, &[id(&[1]), id(&[2])], &mut rng).is_ok());
    }
}
