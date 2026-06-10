//! DKLs23 pre-signing: an offline phase that does everything except touch the
//! message, plus an online [`sign_with_presign`] that consumes a presign exactly
//! once to finalize an ECDSA signature. Port of Go `dklstss/presign.go`.
//!
//! A [`PresignOutput`] binds to one `(public key, signing subset, group nonce
//! R)` and MUST be consumed once: reusing it is ECDSA nonce reuse and leaks the
//! key. Single use is enforced in-memory by an atomic flag; for cross-restart
//! durability use [`sign_with_presign_durable`] with a [`UsedPresignStore`].

use super::Error;
use super::key::{Key, Signature};
use super::ole;
use super::secp::{self, ProjectivePoint, Scalar};
use super::signing::{
    cmp_be, ecdsa_verify, hash_to_scalar, is_high_s, lagrange_coefficient, make_sid, pad32,
};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::rng::RngCore;
use std::sync::atomic::{AtomicBool, Ordering};

/// One party's offline pre-signing shares.
struct PartyPresign {
    rho: Scalar,
    sigma: Scalar,       // share of x·ρ (Lagrange-scaled)
    k_rho_share: Scalar, // share of k·ρ
}

/// The result of the offline pre-signing phase, consumable once by
/// [`sign_with_presign`].
pub struct PresignOutput {
    pub_key: ProjectivePoint,
    r_point: ProjectivePoint,
    r: Scalar,
    parties: Vec<PartyPresign>,
    consumed: AtomicBool,
}

impl PresignOutput {
    /// Whether this presign has already been consumed.
    pub fn consumed(&self) -> bool {
        self.consumed.load(Ordering::Acquire)
    }

    /// A 32-byte identifier of this presign's `R`, for a durable consumed-set.
    /// Two presigns sharing an `R` must never both be consumed.
    pub fn r_hash(&self) -> [u8; 32] {
        let (rx, ry) = secp::affine_be(&self.r_point);
        sha512_256i_tagged(b"DKLS23-presign-rhash-v1", &[&rx, &ry])
    }
}

/// Runs the offline pre-signing phase for the `t+1` parties named by
/// `signer_idx`. Does not touch any message digest. The returned output may be
/// consumed once via [`sign_with_presign`].
pub fn presign(
    keys: &[Key],
    signer_idx: &[usize],
    rng: &mut impl RngCore,
) -> Result<PresignOutput, Error> {
    if keys.is_empty() {
        return Err(Error::Validation(
            "Presign requires at least one key".into(),
        ));
    }
    let n = keys[0].n;
    let t = keys[0].t;
    let pub_key = keys[0].ecdsa_pub;
    if signer_idx.len() != t + 1 {
        return Err(Error::Validation(format!("requires T+1={} signers", t + 1)));
    }
    for (a, &idx) in signer_idx.iter().enumerate() {
        if idx >= n {
            return Err(Error::Validation("signer index out of range".into()));
        }
        if signer_idx[..a].contains(&idx) {
            return Err(Error::Validation("duplicate signer index".into()));
        }
    }

    // Resolve and sort the signing subset by party id.
    let mut signers: Vec<&Key> = signer_idx.iter().map(|&i| &keys[i]).collect();
    signers.sort_by(|a, b| cmp_be(&a.party_ids[a.idx].key, &b.party_ids[b.idx].key));
    let sgn = signers.len();

    // Lagrange coefficients and effective shares sx_i = λ_i·x_i.
    let ids: Vec<Scalar> = signers
        .iter()
        .map(|k| secp::scalar_from_be_reduce(&k.party_ids[k.idx].key))
        .collect();
    let mut sx: Vec<Scalar> = Vec::with_capacity(sgn);
    for (i, k) in signers.iter().enumerate() {
        let lam = lagrange_coefficient(&ids, i)?;
        sx.push(lam.mul(&k.xi));
    }

    // Session id (no message binding).
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let mut ssid = b"DKLS23-presign-v1-".to_vec();
    ssid.extend_from_slice(&nonce);

    // Per-party nonce k_i, masking ρ_i; K_i = k_i·G; R = Σ K_i.
    let mut k: Vec<Scalar> = Vec::with_capacity(sgn);
    let mut rho: Vec<Scalar> = Vec::with_capacity(sgn);
    let mut big_k: Vec<ProjectivePoint> = Vec::with_capacity(sgn);
    for _ in 0..sgn {
        let ki = secp::random_scalar(rng);
        big_k.push(secp::mul_base(&ki));
        k.push(ki);
        rho.push(secp::random_scalar(rng));
    }
    let mut r_point = big_k[0];
    for kp in &big_k[1..] {
        r_point = r_point.add(kp);
    }
    let (rx, _) = secp::affine_be(&r_point);
    let r = secp::scalar_from_be_reduce(&rx);
    if bool::from(r.is_zero()) {
        return Err(Error::Validation("R.x is 0 mod q; retry".into()));
    }

    // Pairwise ΠMul to additive-share k·ρ and x·ρ (diagonal + cross terms).
    let mut k_rho: Vec<Scalar> = (0..sgn).map(|i| k[i].mul(&rho[i])).collect();
    let mut x_rho: Vec<Scalar> = (0..sgn).map(|i| sx[i].mul(&rho[i])).collect();
    for ai in 0..sgn {
        for bj in 0..sgn {
            if ai == bj {
                continue;
            }
            let alice = signers[ai];
            let bob = signers[bj];
            let alice_pair = alice.ot[bob.idx]
                .as_ref()
                .ok_or_else(|| Error::Validation("missing OT state".into()))?;
            let bob_pair = bob.ot[alice.idx]
                .as_ref()
                .ok_or_else(|| Error::Validation("missing OT state".into()))?;

            let sid_k = make_sid(&ssid, "presign-kxrho", alice.idx, bob.idx);
            let (a_msg, a_state) = ole::alice_step1(&sid_k, &alice_pair.as_alice, &k[ai])?;
            let (b_msg, u_b) = ole::bob_step1(&sid_k, &bob_pair.as_bob, &rho[bj], &a_msg)?;
            let u_a = ole::alice_step2(&a_state, &b_msg)?;
            k_rho[ai] = k_rho[ai].add(&u_a);
            k_rho[bj] = k_rho[bj].add(&u_b);

            let sid_x = make_sid(&ssid, "presign-xxrho", alice.idx, bob.idx);
            let (a_msg, a_state) = ole::alice_step1(&sid_x, &alice_pair.as_alice, &sx[ai])?;
            let (b_msg, u_b) = ole::bob_step1(&sid_x, &bob_pair.as_bob, &rho[bj], &a_msg)?;
            let u_a = ole::alice_step2(&a_state, &b_msg)?;
            x_rho[ai] = x_rho[ai].add(&u_a);
            x_rho[bj] = x_rho[bj].add(&u_b);
        }
    }

    let parties = (0..sgn)
        .map(|i| PartyPresign {
            rho: rho[i].clone(),
            sigma: x_rho[i].clone(),
            k_rho_share: k_rho[i].clone(),
        })
        .collect();

    Ok(PresignOutput {
        pub_key,
        r_point,
        r,
        parties,
        consumed: AtomicBool::new(false),
    })
}

/// Consumes a [`PresignOutput`] exactly once and finalizes the ECDSA signature
/// of `hash`. Pass `tweak` to sign under a BIP32 child key (spread across all
/// parties' shares). Subsequent calls return an "already consumed" error.
pub fn sign_with_presign(
    presign: &PresignOutput,
    hash: &[u8],
    tweak: Option<&Scalar>,
) -> Result<Signature, Error> {
    if hash.is_empty() {
        return Err(Error::Validation("hash must be non-empty".into()));
    }
    // Atomic single-use: only one caller flips false → true.
    if presign
        .consumed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::Validation(
            "presign output already consumed — reuse equals nonce reuse equals key extraction"
                .into(),
        ));
    }

    // φ = Σ kRhoShare = k·ρ.
    let mut phi = Scalar::ZERO;
    for p in &presign.parties {
        phi = phi.add(&p.k_rho_share);
    }
    if bool::from(phi.is_zero()) {
        return Err(Error::Validation("φ is 0; presign was malformed".into()));
    }

    // ŝ = Σ (ρ_i·H + r·σ_i), with σ_i += τ·ρ_i under an HD tweak.
    let e = hash_to_scalar(hash);
    let mut sigma_sum = Scalar::ZERO;
    for p in &presign.parties {
        let mut sigma = p.sigma.clone();
        if let Some(tw) = tweak {
            sigma = sigma.add(&tw.mul(&p.rho));
        }
        let shati = p.rho.mul(&e).add(&presign.r.mul(&sigma));
        sigma_sum = sigma_sum.add(&shati);
    }

    let mut s = sigma_sum.mul(&phi.invert());
    if bool::from(s.is_zero()) {
        return Err(Error::Validation("produced s = 0".into()));
    }

    // Low-S normalization (BIP-62).
    let (_, ry) = secp::affine_be(&presign.r_point);
    let mut v = ry.last().copied().unwrap_or(0) & 1;
    if is_high_s(&s) {
        s = s.negate();
        v ^= 1;
    }

    // Final gate: verify under the (possibly tweaked) public key.
    let verify_pub = match tweak {
        Some(tw) => presign.pub_key.add(&secp::mul_base(tw)),
        None => presign.pub_key,
    };
    if !ecdsa_verify(&verify_pub, &e, &presign.r, &s) {
        return Err(Error::Validation(
            "presign finalize failed ECDSA verification".into(),
        ));
    }

    Ok(Signature {
        r: pad32(&secp::scalar_to_be_min(&presign.r)),
        s: pad32(&secp::scalar_to_be_min(&s)),
        v,
    })
}

/// A caller-supplied durable record of consumed presign `R`-hashes. A correct
/// implementation MUST survive restart: reusing a presign across a crash is
/// ECDSA nonce reuse. `check_and_record` returns `Ok(true)` iff the hash was
/// absent before and is now recorded (atomically).
pub trait UsedPresignStore {
    /// Records `r_hash`, returning whether it was newly inserted.
    fn check_and_record(&self, r_hash: &[u8; 32]) -> Result<bool, Error>;
}

/// A non-durable [`UsedPresignStore`] for tests. Does NOT survive restart.
#[derive(Default)]
pub struct InMemoryPresignStore {
    seen: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
}

impl InMemoryPresignStore {
    /// An empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl UsedPresignStore for InMemoryPresignStore {
    fn check_and_record(&self, r_hash: &[u8; 32]) -> Result<bool, Error> {
        Ok(self.seen.lock().unwrap().insert(*r_hash))
    }
}

/// [`sign_with_presign`] with cross-restart single-use enforcement: the store is
/// consulted before the in-memory flag, so the same presign is rejected by any
/// node holding the durable record.
pub fn sign_with_presign_durable(
    presign: &PresignOutput,
    hash: &[u8],
    tweak: Option<&Scalar>,
    store: &dyn UsedPresignStore,
) -> Result<Signature, Error> {
    if hash.is_empty() {
        return Err(Error::Validation("hash must be non-empty".into()));
    }
    if !store.check_and_record(&presign.r_hash())? {
        return Err(Error::Validation(
            "presign output already consumed — reuse equals nonce reuse equals key extraction"
                .into(),
        ));
    }
    sign_with_presign(presign, hash, tweak)
}

#[cfg(test)]
mod tests {
    use super::super::keygen::keygen;
    use super::*;
    use purecrypto::hash::sha256;
    use purecrypto::rng::OsRng;

    fn party_ids(n: usize) -> Vec<crate::tss::PartyId> {
        crate::tss::PartyId::sort(
            (1..=n)
                .map(|i| crate::tss::PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    #[test]
    fn presign_then_sign_verifies() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let po = presign(&keys, &[0, 2], &mut OsRng).unwrap();
        let msg = sha256(b"presigned message");
        let sig = sign_with_presign(&po, &msg, None).unwrap();

        let e = hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
        assert!(!is_high_s(&s));
    }

    #[test]
    fn presign_is_single_use() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let po = presign(&keys, &[0, 1], &mut OsRng).unwrap();
        let msg = sha256(b"once");
        assert!(!po.consumed());
        sign_with_presign(&po, &msg, None).unwrap();
        assert!(po.consumed());
        // Second consume must fail.
        assert!(sign_with_presign(&po, &msg, None).is_err());
    }

    #[test]
    fn durable_store_rejects_reuse() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let store = InMemoryPresignStore::new();
        let msg = sha256(b"durable");

        let po1 = presign(&keys, &[0, 1], &mut OsRng).unwrap();
        sign_with_presign_durable(&po1, &msg, None, &store).unwrap();
        // Re-recording the same R-hash is rejected.
        assert!(!store.check_and_record(&po1.r_hash()).unwrap());
    }

    #[test]
    fn presign_tweak_verifies_under_child_key() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let po = presign(&keys, &[1, 2], &mut OsRng).unwrap();
        let tweak = secp::scalar_from_be_reduce(&[0x11, 0x22, 0x33]);
        let msg = sha256(b"tweaked presign");
        let sig = sign_with_presign(&po, &msg, Some(&tweak)).unwrap();

        let child_pub = keys[0].ecdsa_pub.add(&secp::mul_base(&tweak));
        let e = hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&child_pub, &e, &r, &s));
    }
}
