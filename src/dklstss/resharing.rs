//! Synchronous in-process DKLs resharing (old→new committee) and proactive
//! refresh. Both preserve the joint public key. Mirrors tss-lib `dklstss.Reshare`
//! / `dklstss.Refresh`.

use super::Error;
use super::key::Key;
use super::secp::{self, ProjectivePoint, Scalar};
use super::setup::setup_pairs;
use super::signing::lagrange_coefficient;
use super::vss;
use crate::tss::PartyId;
use purecrypto::rng::RngCore;

/// Transfers the joint secret from an old committee to a new committee
/// (possibly different size/threshold/membership), preserving the public key.
pub fn reshare(
    old_keys: &[Key],
    old_subset_idx: &[usize],
    new_party_ids: &[PartyId],
    new_threshold: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<Key>, Error> {
    if old_keys.is_empty() || old_subset_idx.is_empty() {
        return Err(Error::Validation(
            "Reshare requires old keys + subset".into(),
        ));
    }
    let first = &old_keys[old_subset_idx[0]];
    let t_old = first.t;
    let n_new = new_party_ids.len();
    if old_subset_idx.len() < t_old + 1 {
        return Err(Error::Validation(format!(
            "Reshare needs ≥ {} old participants",
            t_old + 1
        )));
    }
    if new_threshold < 1 || new_threshold >= n_new {
        return Err(Error::Validation(
            "Reshare requires 1 ≤ T_new < N_new".into(),
        ));
    }
    let pub_key = first.ecdsa_pub;
    let chain_code = first.chain_code;

    // Resolve + validate old participants.
    let mut participants: Vec<&Key> = Vec::with_capacity(old_subset_idx.len());
    for (a, &idx) in old_subset_idx.iter().enumerate() {
        if idx >= old_keys.len() || old_subset_idx[..a].contains(&idx) {
            return Err(Error::Validation(
                "Reshare bad/duplicate oldSubsetIdx".into(),
            ));
        }
        if !secp::point_eq(&old_keys[idx].ecdsa_pub, &pub_key) {
            return Err(Error::Validation(
                "Reshare inconsistent old public key".into(),
            ));
        }
        participants.push(&old_keys[idx]);
    }

    let new_ids: Vec<Scalar> = new_party_ids
        .iter()
        .map(|p| secp::scalar_from_be_reduce(&p.key))
        .collect();
    check_indexes(&new_ids)?;

    // Old-subset Lagrange coefficients.
    let old_ids: Vec<Scalar> = participants
        .iter()
        .map(|k| secp::scalar_from_be_reduce(&k.party_ids[k.idx].key))
        .collect();

    // Phase 1: each old participant Feldman-shares λ_i·x_i to the new committee.
    let mut commitments: Vec<Vec<ProjectivePoint>> = Vec::with_capacity(participants.len());
    let mut shares: Vec<Vec<Scalar>> = Vec::with_capacity(participants.len());
    for (i, k) in participants.iter().enumerate() {
        let lam = lagrange_coefficient(&old_ids, i)?;
        let scaled = lam.mul(&k.xi);
        if bool::from(scaled.is_zero()) {
            return Err(Error::Validation("Reshare λ·x_i ≡ 0".into()));
        }
        let (vs, s) = vss::create(new_threshold, &scaled, &new_ids, rng);
        commitments.push(vs);
        shares.push(s);
    }

    // Phase 2: new shares x_j' = Σ_i f_i(id_j); joint constant term = x.
    let mut new_xj: Vec<Scalar> = Vec::with_capacity(n_new);
    for j in 0..n_new {
        let mut sum = Scalar::ZERO;
        for (i, s) in shares.iter().enumerate() {
            if !vss::verify(&new_ids[j], &s[j], new_threshold, &commitments[i]) {
                return Err(Error::Validation(format!(
                    "Reshare share to new party {j} failed verify"
                )));
            }
            sum = sum.add(&s[j]);
        }
        new_xj.push(sum);
    }

    // Phase 3 + 4: BigXj and public-key preservation.
    let mut new_big_xj: Vec<ProjectivePoint> = Vec::with_capacity(n_new);
    for (j, id) in new_ids.iter().enumerate() {
        let xjg = secp::mul_base(&new_xj[j]);
        if !secp::point_eq(&xjg, &vss::evaluate_commitment_sum(&commitments, id)) {
            return Err(Error::Validation(format!(
                "Reshare BigXj[{j}] inconsistent"
            )));
        }
        new_big_xj.push(xjg);
    }
    let mut reconstructed = commitments[0][0];
    for c in &commitments[1..] {
        reconstructed = reconstructed.add(&c[0]);
    }
    if !secp::point_eq(&reconstructed, &pub_key) {
        return Err(Error::Validation(
            "Reshare did not preserve the public key".into(),
        ));
    }

    // Phase 5 + 6: fresh OT setup, assemble new keys.
    let ot = ot_setup(b"DKLS23-reshare-otsetup-v1-", &pub_key, n_new, rng);
    assemble(
        n_new,
        new_threshold,
        new_party_ids,
        new_xj,
        new_big_xj,
        pub_key,
        ot,
        chain_code,
    )
}

/// Proactively rotates every party's share (preserving the public key) and
/// re-establishes all pairwise OT state.
pub fn refresh(keys: &[Key], rng: &mut impl RngCore) -> Result<Vec<Key>, Error> {
    if keys.is_empty() {
        return Err(Error::Validation(
            "Refresh requires at least one key".into(),
        ));
    }
    let n = keys[0].n;
    let t = keys[0].t;
    let pub_key = keys[0].ecdsa_pub;
    let chain_code = keys[0].chain_code;
    let party_ids = keys[0].party_ids.clone();
    if keys.len() != n {
        return Err(Error::Validation("Refresh key count mismatch".into()));
    }
    for (i, k) in keys.iter().enumerate() {
        if k.n != n || k.t != t || k.idx != i || !secp::point_eq(&k.ecdsa_pub, &pub_key) {
            return Err(Error::Validation(format!("Refresh key[{i}] inconsistent")));
        }
    }
    let ids: Vec<Scalar> = party_ids
        .iter()
        .map(|p| secp::scalar_from_be_reduce(&p.key))
        .collect();

    // Phase 1: each party shares a zero-constant degree-t polynomial.
    let mut commitments: Vec<Vec<ProjectivePoint>> = Vec::with_capacity(n); // [n][t] (no v_0)
    let mut shares: Vec<Vec<Scalar>> = Vec::with_capacity(n);
    for _ in 0..n {
        let coeffs: Vec<Scalar> = (0..t).map(|_| secp::random_scalar(rng)).collect();
        commitments.push(coeffs.iter().map(secp::mul_base).collect());
        shares.push(ids.iter().map(|id| eval_zero_const(&coeffs, id)).collect());
    }

    // Phase 2: each party sums its incoming (verified) deltas.
    let mut delta: Vec<Scalar> = Vec::with_capacity(n);
    for j in 0..n {
        let mut sum = Scalar::ZERO;
        for (i, s) in shares.iter().enumerate() {
            if !verify_zero_const(&commitments[i], &ids[j], &s[j]) {
                return Err(Error::Validation(format!(
                    "Refresh VSS verify {i}→{j} failed"
                )));
            }
            sum = sum.add(&s[j]);
        }
        delta.push(sum);
    }

    // Phase 3: new shares + commitments.
    let mut new_xj: Vec<Scalar> = Vec::with_capacity(n);
    let mut new_big_xj: Vec<ProjectivePoint> = Vec::with_capacity(n);
    for j in 0..n {
        new_xj.push(keys[j].xi.add(&delta[j]));
        let xj = keys[0].big_xj[j].add(&secp::mul_base(&delta[j]));
        if !secp::point_eq(&secp::mul_base(&new_xj[j]), &xj) {
            return Err(Error::Validation(format!(
                "Refresh consistency check failed at {j}"
            )));
        }
        new_big_xj.push(xj);
    }

    let ot = ot_setup(b"DKLS23-refresh-otsetup-v1-", &pub_key, n, rng);
    assemble(
        n, t, &party_ids, new_xj, new_big_xj, pub_key, ot, chain_code,
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    n: usize,
    t: usize,
    party_ids: &[PartyId],
    xj: Vec<Scalar>,
    big_xj: Vec<ProjectivePoint>,
    pub_key: ProjectivePoint,
    mut ot: Vec<Vec<Option<super::key::PairOTState>>>,
    chain_code: [u8; 32],
) -> Result<Vec<Key>, Error> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let key = Key {
            n,
            t,
            idx: i,
            party_ids: party_ids.to_vec(),
            xi: xj[i].clone(),
            big_xj: big_xj.clone(),
            ecdsa_pub: pub_key,
            ot: std::mem::take(&mut ot[i]),
            chain_code,
        };
        key.validate_basic()?;
        out.push(key);
    }
    Ok(out)
}

fn ot_setup(
    domain: &[u8],
    pub_key: &ProjectivePoint,
    n: usize,
    rng: &mut impl RngCore,
) -> Vec<Vec<Option<super::key::PairOTState>>> {
    let (px, _) = secp::affine_be(pub_key);
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let mut sid_prefix = domain.to_vec();
    sid_prefix.extend_from_slice(&px);
    sid_prefix.push(b'|');
    sid_prefix.extend_from_slice(&nonce);
    setup_pairs(n, &sid_prefix, rng)
}

/// `f(id) = Σ_{k=1..t} coeffs[k-1]·id^k` (zero constant term).
fn eval_zero_const(coeffs: &[Scalar], id: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut xpow = Scalar::ONE;
    for a in coeffs {
        xpow = xpow.mul(id);
        result = result.add(&a.mul(&xpow));
    }
    result
}

/// Verifies a zero-constant share: `share·G == Σ_{k=1..t} id^k · V_{k-1}`.
fn verify_zero_const(vs: &[ProjectivePoint], id: &Scalar, share: &Scalar) -> bool {
    let mut acc: Option<ProjectivePoint> = None;
    let mut xpow = Scalar::ONE;
    for v in vs {
        xpow = xpow.mul(id);
        let term = v.mul(&xpow);
        acc = Some(match acc {
            None => term,
            Some(a) => a.add(&term),
        });
    }
    match acc {
        Some(a) => secp::point_eq(&secp::mul_base(share), &a),
        None => bool::from(share.is_zero()),
    }
}

fn check_indexes(ids: &[Scalar]) -> Result<(), Error> {
    for (i, a) in ids.iter().enumerate() {
        if bool::from(a.is_zero()) {
            return Err(Error::Validation("party index must not be zero".into()));
        }
        for b in &ids[i + 1..] {
            if bool::from(a.ct_eq(b)) {
                return Err(Error::Validation("duplicate party indexes".into()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::keygen::keygen;
    use super::super::signing::{self, sign};
    use super::*;
    use purecrypto::hash::sha256;
    use purecrypto::rng::OsRng;

    fn ids(keys: &[u8]) -> Vec<PartyId> {
        PartyId::sort(
            keys.iter()
                .map(|&k| PartyId::new(k.to_string(), format!("P{k}"), vec![k]))
                .collect(),
            0,
        )
    }

    fn check_sig(keys: &[Key], idxs: &[usize], msg: &[u8]) {
        let sig = sign(keys, idxs, msg, &mut OsRng).unwrap();
        let e = signing::hash_to_scalar(msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(signing::ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
    }

    #[test]
    fn reshare_preserves_key_and_signs() {
        let old_ids = ids(&[1, 2, 3]);
        let old = keygen(3, 1, &old_ids, &mut OsRng).unwrap();
        let pub0 = old[0].ecdsa_pub;

        let new_ids = ids(&[11, 12, 13, 14, 15]);
        let new = reshare(&old, &[0, 1], &new_ids, 2, &mut OsRng).unwrap();
        assert_eq!(new.len(), 5);
        for k in &new {
            assert!(secp::point_eq(&k.ecdsa_pub, &pub0));
        }
        check_sig(&new, &[0, 2, 4], &sha256(b"post-reshare"));
    }

    #[test]
    fn refresh_preserves_key_and_signs() {
        let id_set = ids(&[1, 2, 3]);
        let keys = keygen(3, 1, &id_set, &mut OsRng).unwrap();
        let pub0 = keys[0].ecdsa_pub;
        let refreshed = refresh(&keys, &mut OsRng).unwrap();
        for k in &refreshed {
            assert!(secp::point_eq(&k.ecdsa_pub, &pub0));
        }
        // Shares actually rotated.
        assert!(!bool::from(keys[0].xi.ct_eq(&refreshed[0].xi)));
        check_sig(&refreshed, &[0, 1], &sha256(b"post-refresh"));
    }
}
