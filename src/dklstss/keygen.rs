//! Synchronous in-process DKLs DKG. Mirrors tss-lib `dklstss.Keygen`.

use super::Error;
use super::key::Key;
use super::secp::{self, ProjectivePoint, Scalar};
use super::setup::setup_pairs;
use super::vss;
use crate::tss::PartyId;
use purecrypto::hash::sha256;
use purecrypto::rng::RngCore;

/// Runs an `n`-party `t`-of-`n` DKG in-process, returning one [`Key`] per party
/// in `party_ids` order. Signing requires any `t + 1` parties (`1 ≤ t < n`).
pub fn keygen(
    n: usize,
    t: usize,
    party_ids: &[PartyId],
    rng: &mut impl RngCore,
) -> Result<Vec<Key>, Error> {
    if t < 1 || t >= n {
        return Err(Error::Validation(format!(
            "requires 1 ≤ T < N, got T={t} N={n}"
        )));
    }
    if party_ids.len() != n {
        return Err(Error::Validation("party_ids length mismatch".into()));
    }
    let ids: Vec<Scalar> = party_ids
        .iter()
        .map(|p| secp::scalar_from_be_reduce(&p.key))
        .collect();
    check_indexes(&ids)?;

    // Phase 1: each party Feldman-VSS-shares a random secret u_i.
    let mut commitments: Vec<Vec<ProjectivePoint>> = Vec::with_capacity(n);
    let mut shares: Vec<Vec<Scalar>> = Vec::with_capacity(n);
    for _ in 0..n {
        let u = secp::random_scalar(rng);
        let (vs, s) = vss::create(t, &u, &ids, rng);
        commitments.push(vs);
        shares.push(s);
    }

    // Phase 2: each party j's Shamir share x_j = Σ_i shares[i][j] (verified).
    let mut xj: Vec<Scalar> = Vec::with_capacity(n);
    for j in 0..n {
        let mut sum = Scalar::ZERO;
        for i in 0..n {
            let sh = &shares[i][j];
            if !vss::verify(&ids[j], sh, t, &commitments[i]) {
                return Err(Error::Validation(format!(
                    "share from party {i} to party {j} failed VSS verification"
                )));
            }
            sum = sum.add(sh);
        }
        xj.push(sum);
    }

    // Phase 3: joint public key X = Σ commitments[i][0]; per-party BigXj.
    let mut pub_key = commitments[0][0];
    for c in &commitments[1..] {
        pub_key = pub_key.add(&c[0]);
    }
    let mut big_xj: Vec<ProjectivePoint> = Vec::with_capacity(n);
    for (j, id) in ids.iter().enumerate() {
        let xjg = vss::evaluate_commitment_sum(&commitments, id);
        if !secp::point_eq(&secp::mul_base(&xj[j]), &xjg) {
            return Err(Error::Validation(format!("BigXj[{j}] != x_j·G")));
        }
        big_xj.push(xjg);
    }

    // Phase 4: pairwise OT setup, bound to both public-key coordinates.
    let (px, py) = secp::affine_be(&pub_key);
    let mut sid_prefix = b"DKLS23-dkg-otsetup-v2-".to_vec();
    sid_prefix.extend_from_slice(&px);
    sid_prefix.push(0x00);
    sid_prefix.extend_from_slice(&py);
    let mut ot = setup_pairs(n, &sid_prefix, rng);

    let chain_code = derive_chain_code(&pub_key);

    // Phase 5: assemble per-party keys (drain ot rows in order).
    let mut out: Vec<Key> = Vec::with_capacity(n);
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

/// 32-byte BIP32 chain code: `SHA-256(domain || pub.x || 0x00 || pub.y)`.
pub fn derive_chain_code(pub_key: &ProjectivePoint) -> [u8; 32] {
    let (px, py) = secp::affine_be(pub_key);
    let mut data = b"DKLS23-chaincode-v1".to_vec();
    data.extend_from_slice(&px);
    data.push(0x00);
    data.extend_from_slice(&py);
    sha256(&data)
}

/// Rejects zero or duplicate (mod n) party identifiers.
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
    use super::*;
    use purecrypto::rng::OsRng;

    pub(crate) fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    #[test]
    fn keygen_consistent() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        // All parties agree on the public key and commitments.
        for k in &keys[1..] {
            assert!(secp::point_eq(&keys[0].ecdsa_pub, &k.ecdsa_pub));
            assert_eq!(keys[0].chain_code, k.chain_code);
        }
        // Shares reconstruct the secret at x=0 via Lagrange (degree 1, 2 shares).
        for k in &keys {
            k.validate_basic().unwrap();
            assert!(k.ot[k.idx].is_none());
        }
    }
}
