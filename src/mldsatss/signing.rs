//! Threshold ML-DSA-44 signing (ePrint 2025/1166) — shared crypto + a
//! synchronous in-process signer.
//!
//! The 3-phase protocol masks each party's response with a constant-time
//! [hyperball](super::hyperball) sample of `k` parallel tries; a try succeeds
//! only if every party accepts it (its `ν`-scaled L2 norm stays within radius
//! `r`). Combine recomputes `c̃ = H(μ ‖ w₁)`, checks `‖A·z − 2ᵈ·c·t₁ − w‖∞ < γ₂`
//! and the hint weight, then assembles `(c̃, z, h)` — byte-identical to stock
//! FIPS 204. The per-phase primitives ([`sample_w`], [`compute_response`],
//! [`combine_try`]) are reused by the broker-driven signer in
//! [`signing_party`](super::signing_party).
//!
//! All lattice crypto (NTT, challenge sampling, packing) comes from
//! `purecrypto`; only the orchestration and the hyperball rejection gate live
//! here.

use super::Error;
use super::hyperball::{FVec, sample_hyperball};
use super::key::Key44;
use super::params::ThresholdParams44;
use purecrypto::hash::shake256;
use purecrypto::mldsa::MlDsa44PublicKey;
use purecrypto::mldsa::hazmat::{self, D, GAMMA2_88, ML_DSA_44, N, Poly, Q};
use purecrypto::rng::RngCore;

pub(crate) const L: usize = 4;
pub(crate) const K: usize = 4;
/// Outer attempts before giving up (each attempt runs `k` parallel tries with
/// fresh hyperball randomness). Failure past this bound is astronomically
/// unlikely for the tabulated parameters.
const MAX_ATTEMPTS: usize = 512;

/// Produces a FIPS 204 ML-DSA-44 signature of `msg` (context `ctx`, ≤ 255 bytes)
/// from the threshold signing set `signers` (exactly `params.t` distinct
/// parties). The result verifies under the group [`MlDsa44PublicKey`].
pub fn sign44(
    signers: &[&Key44],
    params: &ThresholdParams44,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, Error> {
    if ctx.len() > 255 {
        return Err(Error::Validation("context longer than 255 bytes".into()));
    }
    if signers.len() != params.t as usize {
        return Err(Error::Validation(format!(
            "signing set has {} parties, expected t={}",
            signers.len(),
            params.t
        )));
    }
    for k in signers {
        k.validate()?;
    }
    let kk = params.k as usize;
    let (nu, rp_rad) = (params.nu, params.rp);

    let mu = compute_mu(&signers[0].tr, ctx, msg);
    let a = signers[0].matrix();
    let t1 = signers[0].t1;

    let mut act = 0u8;
    for k in signers {
        act |= 1 << k.id;
    }
    let mut s1h: Vec<[Poly; L]> = Vec::with_capacity(signers.len());
    let mut s2h: Vec<[Poly; K]> = Vec::with_capacity(signers.len());
    for k in signers {
        let (a1, a2) = k.recover_share(act, params)?;
        s1h.push(a1);
        s2h.push(a2);
    }
    let nsign = signers.len();

    for _attempt in 0..MAX_ATTEMPTS {
        // Phase 1: each party samples k hyperball points and computes w = A·r+e.
        let mut stws: Vec<Vec<FVec>> = Vec::with_capacity(nsign);
        let mut w_by: Vec<Vec<[Poly; K]>> = Vec::with_capacity(nsign);
        for _ in 0..nsign {
            let mut rhop = [0u8; 64];
            rng.fill_bytes(&mut rhop);
            let mut my_stws = Vec::with_capacity(kk);
            let mut my_w = Vec::with_capacity(kk);
            for tri in 0..kk {
                let (fv, wi) = sample_w(&a, rp_rad, nu, &rhop, tri as u16);
                my_stws.push(fv);
                my_w.push(wi);
            }
            stws.push(my_stws);
            w_by.push(my_w);
        }

        // Aggregate w per try.
        let mut wfinal: Vec<[Poly; K]> = (0..kk).map(|_| [Poly::zero(); K]).collect();
        for (tri, wf) in wfinal.iter_mut().enumerate() {
            for w in w_by.iter() {
                for (i, wfi) in wf.iter_mut().enumerate() {
                    *wfi = wfi.add(&w[tri][i]);
                }
            }
        }

        // Phase 2: each party's response z_i per try (None = rejected).
        let mut zresp: Vec<Vec<Option<[Poly; L]>>> = Vec::with_capacity(nsign);
        for s in 0..nsign {
            let mut my_z = Vec::with_capacity(kk);
            for (tri, wf) in wfinal.iter().enumerate() {
                my_z.push(compute_response(
                    &s1h[s],
                    &s2h[s],
                    &stws[s][tri],
                    wf,
                    &mu,
                    params,
                ));
            }
            zresp.push(my_z);
        }

        // Combine: find a try every party accepted that also verifies.
        for (tri, wf) in wfinal.iter().enumerate() {
            if zresp.iter().any(|zs| zs[tri].is_none()) {
                continue;
            }
            let mut zfinal = [Poly::zero(); L];
            for zs in zresp.iter() {
                let z = zs[tri].as_ref().unwrap();
                for j in 0..L {
                    zfinal[j] = zfinal[j].add(&z[j]);
                }
            }
            if let Some(sig) = combine_try(&a, &t1, &mu, wf, &zfinal) {
                return Ok(sig);
            }
        }
    }

    Err(Error::Validation(
        "all signing attempts rejected; retry with fresh randomness".into(),
    ))
}

/// Convenience wrapper that verifies the produced signature under `pk` before
/// returning it (a self-check gate; returns an error if verification fails).
pub fn sign44_checked(
    pk: &MlDsa44PublicKey,
    signers: &[&Key44],
    params: &ThresholdParams44,
    msg: &[u8],
    ctx: &[u8],
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, Error> {
    let sig = sign44(signers, params, msg, ctx, rng)?;
    if !pk.verify(&sig, msg, ctx) {
        return Err(Error::Validation(
            "assembled threshold signature failed FIPS 204 verification".into(),
        ));
    }
    Ok(sig)
}

// --- shared per-phase primitives (also used by the broker signer) ----------

/// Phase 1 for one try: draws a hyperball sample `fv` and computes this party's
/// `w = A·r + e` (where `(r, e)` is the rounded split of `fv`). Returns
/// `(fv, w)`; `fv` is retained as the response mask.
pub(crate) fn sample_w(
    a: &[Poly],
    rp: f64,
    nu: f64,
    rhop: &[u8; 64],
    tri: u16,
) -> (FVec, [Poly; K]) {
    let mut fv = FVec::zero();
    sample_hyperball(&mut fv, rp, nu, rhop, tri);

    let mut rpoly = [Poly::zero(); L];
    let mut epoly = [Poly::zero(); K];
    fv.round_into(&mut rpoly, &mut epoly);

    let mut rh = [Poly::zero(); L];
    for j in 0..L {
        let mut h = rpoly[j];
        h.ntt();
        rh[j] = h;
    }
    let mut wi = [Poly::zero(); K];
    for (i, wij) in wi.iter_mut().enumerate() {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&hazmat::ntt_mul(&a[i * L + j], &rh[j]));
        }
        acc.inv_ntt();
        *wij = acc.add(&epoly[i]);
    }
    (fv, wi)
}

/// Phase 2 for one try: this party's response `z_i = round(c·s1_i + y_i)`, or
/// `None` if the masked response exceeds the `ν`-scaled radius `r` (rejected).
/// `c` is derived from the aggregated `wfinal_tri`.
pub(crate) fn compute_response(
    s1h: &[Poly; L],
    s2h: &[Poly; K],
    stws_tri: &FVec,
    wfinal_tri: &[Poly; K],
    mu: &[u8; 64],
    params: &ThresholdParams44,
) -> Option<[Poly; L]> {
    let tau = ML_DSA_44.params.tau;
    let w1 = high_bits_vec(wfinal_tri);
    let ctilde = compute_ctilde(mu, &w1);
    let mut chat = hazmat::sample_challenge(&ctilde, tau);
    chat.ntt();

    let mut zpart = [Poly::zero(); L];
    for j in 0..L {
        let mut p = hazmat::ntt_mul(&chat, &s1h[j]);
        p.inv_ntt();
        zpart[j] = p;
    }
    let mut ypart = [Poly::zero(); K];
    for j in 0..K {
        let mut p = hazmat::ntt_mul(&chat, &s2h[j]);
        p.inv_ntt();
        ypart[j] = p;
    }
    let mut zf = FVec::from_polys(&zpart, &ypart);
    zf.add_assign(stws_tri);
    if zf.excess(params.r, params.nu) {
        None
    } else {
        let mut z2 = [Poly::zero(); L];
        let mut yd = [Poly::zero(); K];
        zf.round_into(&mut z2, &mut yd);
        Some(z2)
    }
}

/// Combine for one try: given the aggregated `wfinal_tri` and `zfinal_tri`,
/// run the FIPS 204 correctness checks (`‖z‖∞`, `‖A·z − 2ᵈ·c·t₁ − w‖∞`, hint
/// weight) and, on success, return the assembled signature `(c̃ ‖ z ‖ h)`.
pub(crate) fn combine_try(
    a: &[Poly],
    t1: &[Poly; K],
    mu: &[u8; 64],
    wfinal_tri: &[Poly; K],
    zfinal_tri: &[Poly; L],
) -> Option<Vec<u8>> {
    let tau = ML_DSA_44.params.tau;
    let gamma1 = ML_DSA_44.params.gamma1;
    let beta = ML_DSA_44.params.beta;
    let omega = ML_DSA_44.params.omega;

    if !z_within_bound(zfinal_tri, gamma1 - beta) {
        return None;
    }
    let w1 = high_bits_vec(wfinal_tri);
    let ctilde = compute_ctilde(mu, &w1);
    let mut chat = hazmat::sample_challenge(&ctilde, tau);
    chat.ntt();

    let mut zhat = [Poly::zero(); L];
    for j in 0..L {
        let mut h = zfinal_tri[j];
        h.ntt();
        zhat[j] = h;
    }
    let mut f = [Poly::zero(); K];
    for (i, fi) in f.iter_mut().enumerate() {
        let mut az = Poly::zero();
        for j in 0..L {
            az = az.add(&hazmat::ntt_mul(&a[i * L + j], &zhat[j]));
        }
        let mut t1s = Poly::zero();
        for j in 0..N {
            t1s.c[j] = t1[i].c[j] << D;
        }
        t1s.ntt();
        let ct1 = hazmat::ntt_mul(&chat, &t1s);
        let mut diff = az.sub(&ct1);
        diff.inv_ntt();
        *fi = diff.sub(&wfinal_tri[i]);
    }
    if vec_inf_norm(&f) >= GAMMA2_88 {
        return None;
    }

    let mut hints = [Poly::zero(); K];
    let mut ones = 0usize;
    for i in 0..K {
        for j in 0..N {
            let (_, r0) = hazmat::decompose(wfinal_tri[i].c[j], GAMMA2_88);
            let w0mod = if r0 < 0 { Q - (-r0) as u32 } else { r0 as u32 };
            let mut z0 = w0mod + f[i].c[j];
            if z0 >= Q {
                z0 -= Q;
            }
            let h = make_hint_low_bits(z0, w1[i].c[j]);
            hints[i].c[j] = h;
            ones += h as usize;
        }
    }
    if ones > omega {
        return None;
    }

    let mut sig = Vec::with_capacity(ML_DSA_44.params.sig);
    sig.extend_from_slice(&ctilde);
    for j in 0..L {
        sig.extend_from_slice(&hazmat::pack_z(&zfinal_tri[j], &ML_DSA_44.params));
    }
    sig.extend_from_slice(&hazmat::pack_hint(&hints, omega));
    Some(sig)
}

/// μ = SHAKE256(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ msg) — the FIPS 204 message digest.
pub(crate) fn compute_mu(tr: &[u8; 64], ctx: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut input = Vec::with_capacity(64 + 2 + ctx.len() + msg.len());
    input.extend_from_slice(tr);
    input.push(0);
    input.push(ctx.len() as u8);
    input.extend_from_slice(ctx);
    input.extend_from_slice(msg);
    let mut mu = [0u8; 64];
    shake256(&input, &mut mu);
    mu
}

/// c̃ = SHAKE256(μ ‖ pack_w1(w₁)) → λ/4 bytes.
pub(crate) fn compute_ctilde(mu: &[u8; 64], w1: &[Poly; K]) -> Vec<u8> {
    let mut input = Vec::with_capacity(64 + K * 192);
    input.extend_from_slice(mu);
    for row in w1.iter() {
        input.extend_from_slice(&hazmat::pack_w1(row, &ML_DSA_44.params));
    }
    let mut out = vec![0u8; ML_DSA_44.params.ctilde];
    shake256(&input, &mut out);
    out
}

/// w₁ = HighBits(w) per coefficient (γ₂ = (q−1)/88).
pub(crate) fn high_bits_vec(w: &[Poly; K]) -> [Poly; K] {
    let mut out = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..N {
            out[i].c[j] = hazmat::high_bits(w[i].c[j], GAMMA2_88);
        }
    }
    out
}

/// Whether every coefficient of `z` has centered infinity norm `< bound`.
fn z_within_bound(z: &[Poly; L], bound: u32) -> bool {
    z.iter()
        .all(|p| p.c.iter().all(|&c| hazmat::inf_norm(c) < bound))
}

/// Max centered infinity norm over a `K`-vector.
fn vec_inf_norm(f: &[Poly; K]) -> u32 {
    f.iter()
        .flat_map(|p| p.c.iter())
        .map(|&c| hazmat::inf_norm(c))
        .max()
        .unwrap_or(0)
}

/// Two-valued hint (FIPS 204 UseHint-compatible) over perturbed low bits.
fn make_hint_low_bits(z0: u32, r1: u32) -> u32 {
    let g = GAMMA2_88;
    if z0 <= g || z0 > Q - g || (z0 == Q - g && r1 == 0) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::super::keygen::trusted_dealer_keygen44;
    use super::super::params::get_threshold_params44;
    use super::*;

    fn run(t: usize, n: usize, signer_idx: &[usize], seed: u8) {
        let params = get_threshold_params44(t, n).unwrap();
        let (pk, keys) = trusted_dealer_keygen44(&[seed; 32], &params).unwrap();
        let signers: Vec<&Key44> = signer_idx.iter().map(|&i| &keys[i]).collect();
        let msg = b"threshold ml-dsa message";
        let ctx = b"ctx";
        let mut rng = purecrypto::rng::OsRng;
        let sig = sign44(&signers, &params, msg, ctx, &mut rng).expect("sign succeeds");
        assert!(
            pk.verify(&sig, msg, ctx),
            "threshold signature must verify under the FIPS 204 public key"
        );
        assert!(!pk.verify(&sig, b"other message", ctx));
    }

    #[test]
    fn sign_2_of_3() {
        run(2, 3, &[0, 1], 7);
    }

    #[test]
    fn sign_2_of_3_other_subset() {
        run(2, 3, &[1, 2], 7);
    }

    #[test]
    fn sign_3_of_5() {
        run(3, 5, &[0, 2, 4], 9);
    }

    #[test]
    fn sign_checked_wrapper() {
        let params = get_threshold_params44(2, 2).unwrap();
        let (pk, keys) = trusted_dealer_keygen44(&[5u8; 32], &params).unwrap();
        let signers: Vec<&Key44> = keys.iter().collect();
        let mut rng = purecrypto::rng::OsRng;
        let sig = sign44_checked(&pk, &signers, &params, b"hi", b"", &mut rng).unwrap();
        assert!(pk.verify(&sig, b"hi", b""));
    }
}
