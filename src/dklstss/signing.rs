//! Synchronous in-process DKLs threshold-ECDSA signing. Mirrors tss-lib
//! `dklstss.Sign`. Produces a standard ECDSA signature verifiable under the
//! joint public key.

use super::Error;
use super::key::{Key, Signature};
use super::ole;
use super::secp::{self, ProjectivePoint, Scalar};
use purecrypto::rng::RngCore;

/// Signs `hash` with the `t+1` parties named by `signer_idx`.
pub fn sign(
    keys: &[Key],
    signer_idx: &[usize],
    hash: &[u8],
    rng: &mut impl RngCore,
) -> Result<Signature, Error> {
    sign_core(keys, signer_idx, None, hash, rng)
}

/// Like [`sign`], adding `tweak` to the effective key (HD derivation). The first
/// signer (sorted) absorbs the tweak.
pub fn sign_with_tweak(
    keys: &[Key],
    signer_idx: &[usize],
    tweak: &Scalar,
    hash: &[u8],
    rng: &mut impl RngCore,
) -> Result<Signature, Error> {
    sign_core(keys, signer_idx, Some(tweak), hash, rng)
}

fn sign_core(
    keys: &[Key],
    signer_idx: &[usize],
    tweak: Option<&Scalar>,
    hash: &[u8],
    rng: &mut impl RngCore,
) -> Result<Signature, Error> {
    if keys.is_empty() {
        return Err(Error::Validation("Sign requires at least one key".into()));
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
    if hash.is_empty() {
        return Err(Error::Validation("hash must be non-empty".into()));
    }

    // Resolve and sort the signing subset by party id (the tweak slot).
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
    if let Some(tw) = tweak {
        sx[0] = sx[0].add(tw);
    }

    // Session id bound to the message.
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let mut ssid = b"DKLS23-sign-v1-".to_vec();
    ssid.extend_from_slice(&nonce);
    ssid.push(b'|');
    ssid.extend_from_slice(hash);

    // Round 1: per-party nonce k_i, masking ρ_i; K_i = k_i·G; R = Σ K_i.
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

    // Round 2: pairwise ΠMul to additive-share k·ρ and x·ρ.
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

            // ΠMul(k_ai, ρ_bj).
            let sid_k = make_sid(&ssid, "kxrho", alice.idx, bob.idx);
            let (a_msg, a_state) = ole::alice_step1(&sid_k, &alice_pair.as_alice, &k[ai])?;
            let (b_msg, u_b) = ole::bob_step1(&sid_k, &bob_pair.as_bob, &rho[bj], &a_msg)?;
            let u_a = ole::alice_step2(&a_state, &b_msg)?;
            k_rho[ai] = k_rho[ai].add(&u_a);
            k_rho[bj] = k_rho[bj].add(&u_b);

            // ΠMul(sx_ai, ρ_bj).
            let sid_x = make_sid(&ssid, "xxrho", alice.idx, bob.idx);
            let (a_msg, a_state) = ole::alice_step1(&sid_x, &alice_pair.as_alice, &sx[ai])?;
            let (b_msg, u_b) = ole::bob_step1(&sid_x, &bob_pair.as_bob, &rho[bj], &a_msg)?;
            let u_a = ole::alice_step2(&a_state, &b_msg)?;
            x_rho[ai] = x_rho[ai].add(&u_a);
            x_rho[bj] = x_rho[bj].add(&u_b);
        }
    }

    // φ = Σ k_rho = k·ρ.
    let mut phi = Scalar::ZERO;
    for v in &k_rho {
        phi = phi.add(v);
    }
    if bool::from(phi.is_zero()) {
        return Err(Error::Validation("φ = k·ρ is 0; retry".into()));
    }

    // ŝ = Σ (ρ_i·H(m) + r·x_rho_i).
    let e = hash_to_scalar(hash);
    let mut sigma = Scalar::ZERO;
    for i in 0..sgn {
        let shati = rho[i].mul(&e).add(&r.mul(&x_rho[i]));
        sigma = sigma.add(&shati);
    }

    // s = ŝ · φ^{-1}.
    let mut s = sigma.mul(&phi.invert());
    if bool::from(s.is_zero()) {
        return Err(Error::Validation("s = 0; retry".into()));
    }

    // Low-S normalization (BIP-62).
    let (_, ry) = secp::affine_be(&r_point);
    let mut v = ry.last().copied().unwrap_or(0) & 1;
    if is_high_s(&s) {
        s = s.negate();
        v ^= 1;
    }

    // Final gate: the signature must verify under the (possibly tweaked) key.
    let verify_pub = match tweak {
        Some(tw) => pub_key.add(&secp::mul_base(tw)),
        None => pub_key,
    };
    if !ecdsa_verify(&verify_pub, &e, &r, &s) {
        return Err(Error::Validation(
            "aggregated signature failed ECDSA verification".into(),
        ));
    }

    Ok(Signature {
        r: pad32(&secp::scalar_to_be_min(&r)),
        s: pad32(&secp::scalar_to_be_min(&s)),
        v,
    })
}

/// Lagrange coefficient `λ_i = Π_{j≠i} id_j / (id_j − id_i)` (mod n) at x=0.
pub(crate) fn lagrange_coefficient(ids: &[Scalar], i: usize) -> Result<Scalar, Error> {
    let mut lambda = Scalar::ONE;
    for (j, idj) in ids.iter().enumerate() {
        if j == i {
            continue;
        }
        let den = idj.sub(&ids[i]);
        if bool::from(den.is_zero()) {
            return Err(Error::Validation("duplicate signer identifier".into()));
        }
        lambda = lambda.mul(&idj.mul(&den.invert()));
    }
    Ok(lambda)
}

/// SEC1 §4.1.3 hash-to-scalar: leftmost `qlen` bits of the digest, mod n.
pub(crate) fn hash_to_scalar(hash: &[u8]) -> Scalar {
    let mut e = [0u8; 32];
    if hash.len() >= 32 {
        e.copy_from_slice(&hash[..32]);
    } else {
        e[32 - hash.len()..].copy_from_slice(hash);
    }
    Scalar::from_bytes_be_reduce(&e)
}

/// ECDSA verification: `(s^{-1}·e)·G + (s^{-1}·r)·Q` has x-coordinate `r`.
pub(crate) fn ecdsa_verify(pub_key: &ProjectivePoint, e: &Scalar, r: &Scalar, s: &Scalar) -> bool {
    let w = s.invert();
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);
    let p = secp::mul_base(&u1).add(&pub_key.mul(&u2));
    let (px, _) = secp::affine_be(&p);
    bool::from(secp::scalar_from_be_reduce(&px).ct_eq(r))
}

/// Whether `s > n/2` (high-S). secp256k1 `n/2` (big-endian).
fn is_high_s(s: &Scalar) -> bool {
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    cmp_be(&s.to_bytes_be(), &HALF_N) == std::cmp::Ordering::Greater
}

fn make_sid(ssid: &[u8], kind: &str, alice: usize, bob: usize) -> Vec<u8> {
    let a = (alice as u32).to_be_bytes();
    let b = (bob as u32).to_be_bytes();
    let mut out = ssid.to_vec();
    out.push(b'|');
    out.extend_from_slice(kind.as_bytes());
    out.push(b'|');
    out.extend_from_slice(&a);
    out.push(b'|');
    out.extend_from_slice(&b);
    out
}

fn pad32(be: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[32 - be.len()..].copy_from_slice(be);
    out
}

fn cmp_be(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let sa = strip(a);
    let sb = strip(b);
    sa.len().cmp(&sb.len()).then_with(|| sa.cmp(sb))
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
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
    fn keygen_sign_verify_2_of_3() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let msg = sha256(b"hello dkls");
        let sig = sign(&keys, &[0, 2], &msg, &mut OsRng).unwrap();

        // Independently verify under the joint public key.
        let e = hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
        assert!(!is_high_s(&s), "signature must be low-S");
    }

    #[test]
    fn keygen_sign_verify_3_of_5() {
        let ids = party_ids(5);
        let keys = keygen(5, 2, &ids, &mut OsRng).unwrap();
        let msg = sha256(b"another message");
        let sig = sign(&keys, &[1, 3, 4], &msg, &mut OsRng).unwrap();
        let e = hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
    }
}
