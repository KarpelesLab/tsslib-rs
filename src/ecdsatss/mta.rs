//! MtA (multiplicative-to-additive) share conversion with range proofs. Alice
//! holds `a`, Bob holds `b`; afterwards Alice has `α` and Bob has `β` with
//! `α + β ≡ a·b (mod q)`. Port of Go `tss-lib/crypto/mta`.
//!
//! The "with check" (WC) variant additionally proves Bob's input matches a public
//! point `B = b·G` (used in GG18 signing round 2).

#![allow(dead_code)]

use super::bn::{self, Modulus};
use super::paillier::{PrivateKey, PublicKey};
use super::{Error, secp};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::bignum::BoxedUint;
use purecrypto::ec::secp256k1::ProjectivePoint;
use purecrypto::rng::RngCore;

const RANGE_TAG: &[u8] = b"MTA-RangeProofAlice";

/// `SHA512_256i_TAGGED(tag, ops…) mod q`.
fn rejection_sample(tag: &[u8], ops: &[&BoxedUint]) -> BoxedUint {
    let q = bn::secp256k1_order();
    let ov: Vec<Vec<u8>> = ops.iter().map(|x| bn::to_be(x)).collect();
    let refs: Vec<&[u8]> = ov.iter().map(|v| v.as_slice()).collect();
    bn::rem(&bn::from_be(&sha512_256i_tagged(tag, &refs)), &q)
}

// =========================== Alice's range proof ===========================

/// Alice's range proof that her Paillier plaintext is in range.
pub(crate) struct RangeProofAlice {
    pub z: BoxedUint,
    pub u: BoxedUint,
    pub w: BoxedUint,
    pub s: BoxedUint,
    pub s1: BoxedUint,
    pub s2: BoxedUint,
}

impl RangeProofAlice {
    /// Big-endian parts `Z, U, W, S, S1, S2` (Go `RangeProofAlice.Bytes`).
    pub(crate) fn to_parts(&self) -> Vec<Vec<u8>> {
        [&self.z, &self.u, &self.w, &self.s, &self.s1, &self.s2]
            .iter()
            .map(|x| bn::to_be(x))
            .collect()
    }

    /// Inverse of [`RangeProofAlice::to_parts`].
    pub(crate) fn from_parts(parts: &[Vec<u8>]) -> Option<RangeProofAlice> {
        if parts.len() != 6 {
            return None;
        }
        let g = |i: usize| bn::from_be(&parts[i]);
        Some(RangeProofAlice {
            z: g(0),
            u: g(1),
            w: g(2),
            s: g(3),
            s1: g(4),
            s2: g(5),
        })
    }
}

/// Proves Alice's ciphertext `c = Enc(m; r)` encrypts an in-range `m`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_range_alice<R: RngCore>(
    pk: &PublicKey,
    c: &BoxedUint,
    ntilde: &BoxedUint,
    h1: &BoxedUint,
    h2: &BoxedUint,
    m: &BoxedUint,
    r: &BoxedUint,
    rng: &mut R,
) -> RangeProofAlice {
    let q = bn::secp256k1_order();
    let q3 = bn::mul(&bn::mul(&q, &q), &q);
    let qnt = bn::mul(&q, ntilde);
    let q3nt = bn::mul(&q3, ntilde);

    let alpha = bn::rand_below(&q3, rng);
    let beta = bn::rand_unit(&pk.n, rng);
    let gamma = bn::rand_below(&q3nt, rng);
    let rho = bn::rand_below(&qnt, rng);

    let mnt = Modulus::new(ntilde);
    let mns = Modulus::new(&pk.nsquare());
    let z = mnt.mul(&mnt.pow(h1, m), &mnt.pow(h2, &rho));
    let u = mns.mul(&mns.pow(&pk.gamma(), &alpha), &mns.pow(&beta, &pk.n));
    let w = mnt.mul(&mnt.pow(h1, &alpha), &mnt.pow(h2, &gamma));

    let e = rejection_sample(RANGE_TAG, &[&pk.n, &pk.gamma(), c, &z, &u, &w]);
    let mn = Modulus::new(&pk.n);
    let s = mn.mul(&mn.pow(r, &e), &beta);
    let s1 = bn::add(&bn::mul(&e, m), &alpha);
    let s2 = bn::add(&bn::mul(&e, &rho), &gamma);
    RangeProofAlice { z, u, w, s, s1, s2 }
}

/// Verifies Alice's range proof.
pub(crate) fn verify_range_alice(
    pk: &PublicKey,
    ntilde: &BoxedUint,
    h1: &BoxedUint,
    h2: &BoxedUint,
    c: &BoxedUint,
    pf: &RangeProofAlice,
) -> bool {
    let q = bn::secp256k1_order();
    let q3 = bn::mul(&bn::mul(&q, &q), &q);
    let n2 = pk.nsquare();

    if !pf.z.lt(ntilde) || !pf.u.lt(&n2) || !pf.w.lt(ntilde) || !pf.s.lt(&pk.n) {
        return false;
    }
    if !bn::is_one(&bn::gcd(&pf.z, ntilde))
        || !bn::is_one(&bn::gcd(&pf.u, &n2))
        || !bn::is_one(&bn::gcd(&pf.w, ntilde))
    {
        return false;
    }
    if pf.s1.lt(&q) || pf.s2.lt(&q) || bn::is_one(&pf.s) || bn::is_one(&pf.z) || pf.s1 == pf.s2 {
        return false;
    }
    if bn::gt(&pf.s1, &q3) {
        return false;
    }

    let e = rejection_sample(RANGE_TAG, &[&pk.n, &pk.gamma(), c, &pf.z, &pf.u, &pf.w]);

    // u == Γ^s1 · S^N · c^(−e)  (mod N²)
    let mns = Modulus::new(&n2);
    let Some(c_inv) = mns.inv(c) else {
        return false;
    };
    let products = mns.mul(
        &mns.mul(
            &mns.pow_pub(&pk.gamma(), &pf.s1),
            &mns.pow_pub(&pf.s, &pk.n),
        ),
        &mns.pow_pub(&c_inv, &e),
    );
    if pf.u != products {
        return false;
    }
    // w == h1^s1 · h2^s2 · z^(−e)  (mod Ñ)
    let mnt = Modulus::new(ntilde);
    let Some(z_inv) = mnt.inv(&pf.z) else {
        return false;
    };
    let products = mnt.mul(
        &mnt.mul(&mnt.pow_pub(h1, &pf.s1), &mnt.pow_pub(h2, &pf.s2)),
        &mnt.pow_pub(&z_inv, &e),
    );
    pf.w == products
}

// ============================== Bob's proof ===============================

/// Bob's MtA proof; `u` present only in the "with check" variant.
pub(crate) struct ProofBob {
    pub z: BoxedUint,
    pub zprm: BoxedUint,
    pub t: BoxedUint,
    pub v: BoxedUint,
    pub w: BoxedUint,
    pub s: BoxedUint,
    pub s1: BoxedUint,
    pub s2: BoxedUint,
    pub t1: BoxedUint,
    pub t2: BoxedUint,
    pub u: Option<ProjectivePoint>,
}

impl ProofBob {
    /// Big-endian parts `Z, ZPrm, T, V, W, S, S1, S2, T1, T2` (10), plus `Ux, Uy`
    /// (12 total) for the "with check" variant.
    pub(crate) fn to_parts(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = [
            &self.z, &self.zprm, &self.t, &self.v, &self.w, &self.s, &self.s1, &self.s2, &self.t1,
            &self.t2,
        ]
        .iter()
        .map(|x| bn::to_be(x))
        .collect();
        if let Some(u) = &self.u {
            let (ux, uy) = super::secp::coords(u);
            out.push(bn::to_be(&ux));
            out.push(bn::to_be(&uy));
        }
        out
    }

    /// Inverse of [`ProofBob::to_parts`]; 10 parts → basic, 12 → "with check".
    pub(crate) fn from_parts(parts: &[Vec<u8>]) -> Option<ProofBob> {
        if parts.len() != 10 && parts.len() != 12 {
            return None;
        }
        let g = |i: usize| bn::from_be(&parts[i]);
        let u = if parts.len() == 12 {
            Some(super::secp::from_coords(&g(10), &g(11))?)
        } else {
            None
        };
        Some(ProofBob {
            z: g(0),
            zprm: g(1),
            t: g(2),
            v: g(3),
            w: g(4),
            s: g(5),
            s1: g(6),
            s2: g(7),
            t1: g(8),
            t2: g(9),
            u,
        })
    }
}

/// Bob's proof; pass `x_point = Some(b·G)` for the "with check" variant.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bob<R: RngCore>(
    session: &[u8],
    pk: &PublicKey,
    ntilde: &BoxedUint,
    h1: &BoxedUint,
    h2: &BoxedUint,
    c1: &BoxedUint,
    c2: &BoxedUint,
    x: &BoxedUint,
    y: &BoxedUint,
    r: &BoxedUint,
    x_point: Option<&ProjectivePoint>,
    rng: &mut R,
) -> ProofBob {
    let q = bn::secp256k1_order();
    let q3 = bn::mul(&bn::mul(&q, &q), &q);
    let q7 = bn::mul(&bn::mul(&q3, &q3), &q);
    let qnt = bn::mul(&q, ntilde);
    let q3nt = bn::mul(&q3, ntilde);

    let alpha = bn::rand_below(&q3, rng);
    let rho = bn::rand_below(&qnt, rng);
    let sigma = bn::rand_below(&qnt, rng);
    let tau = bn::rand_below(&q3nt, rng);
    let rhoprm = bn::rand_below(&q3nt, rng);
    let beta = bn::rand_unit(&pk.n, rng);
    let gamma = bn::rand_below(&q7, rng);

    let u = x_point.map(|_| secp::mul_base(&alpha));

    let mnt = Modulus::new(ntilde);
    let mns = Modulus::new(&pk.nsquare());
    let z = mnt.mul(&mnt.pow(h1, x), &mnt.pow(h2, &rho));
    let zprm = mnt.mul(&mnt.pow(h1, &alpha), &mnt.pow(h2, &rhoprm));
    let t = mnt.mul(&mnt.pow(h1, y), &mnt.pow(h2, &sigma));
    let v = mns.mul(
        &mns.mul(&mns.pow(c1, &alpha), &mns.pow(&pk.gamma(), &gamma)),
        &mns.pow(&beta, &pk.n),
    );
    let w = mnt.mul(&mnt.pow(h1, &gamma), &mnt.pow(h2, &tau));

    let e = bob_challenge(
        session,
        pk,
        x_point,
        u.as_ref(),
        c1,
        c2,
        &z,
        &zprm,
        &t,
        &v,
        &w,
    );

    let mn = Modulus::new(&pk.n);
    let s = mn.mul(&mn.pow(r, &e), &beta);
    let s1 = bn::add(&bn::mul(&e, x), &alpha);
    let s2 = bn::add(&bn::mul(&e, &rho), &rhoprm);
    let t1 = bn::add(&bn::mul(&e, y), &gamma);
    let t2 = bn::add(&bn::mul(&e, &sigma), &tau);
    ProofBob {
        z,
        zprm,
        t,
        v,
        w,
        s,
        s1,
        s2,
        t1,
        t2,
        u,
    }
}

#[allow(clippy::too_many_arguments)]
fn bob_challenge(
    session: &[u8],
    pk: &PublicKey,
    x_point: Option<&ProjectivePoint>,
    u: Option<&ProjectivePoint>,
    c1: &BoxedUint,
    c2: &BoxedUint,
    z: &BoxedUint,
    zprm: &BoxedUint,
    t: &BoxedUint,
    v: &BoxedUint,
    w: &BoxedUint,
) -> BoxedUint {
    let gamma = pk.gamma();
    match (x_point, u) {
        (Some(xp), Some(up)) => {
            let (xx, xy) = secp::coords(xp);
            let (ux, uy) = secp::coords(up);
            rejection_sample(
                session,
                &[&pk.n, &gamma, &xx, &xy, c1, c2, &ux, &uy, z, zprm, t, v, w],
            )
        }
        _ => rejection_sample(session, &[&pk.n, &gamma, c1, c2, z, zprm, t, v, w]),
    }
}

/// Verifies Bob's proof; pass `x_point` for the "with check" variant.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_bob(
    session: &[u8],
    pk: &PublicKey,
    ntilde: &BoxedUint,
    h1: &BoxedUint,
    h2: &BoxedUint,
    c1: &BoxedUint,
    c2: &BoxedUint,
    pf: &ProofBob,
    x_point: Option<&ProjectivePoint>,
) -> bool {
    let q = bn::secp256k1_order();
    let q3 = bn::mul(&bn::mul(&q, &q), &q);
    let q7 = bn::mul(&bn::mul(&q3, &q3), &q);
    let n2 = pk.nsquare();

    if !pf.z.lt(ntilde) || !pf.zprm.lt(ntilde) || !pf.t.lt(ntilde) {
        return false;
    }
    if !pf.v.lt(&n2) || !pf.w.lt(ntilde) || !pf.s.lt(&pk.n) {
        return false;
    }
    for (v, m) in [
        (&pf.z, ntilde),
        (&pf.zprm, ntilde),
        (&pf.t, ntilde),
        (&pf.v, &n2),
        (&pf.w, ntilde),
    ] {
        if !bn::is_one(&bn::gcd(v, m)) {
            return false;
        }
    }
    if pf.s.is_zero() || !bn::is_one(&bn::gcd(&pf.s, &pk.n)) {
        return false;
    }
    if pf.v.is_zero() || !bn::is_one(&bn::gcd(&pf.v, &pk.n)) {
        return false;
    }
    if pf.s1.lt(&q) || pf.s2.lt(&q) || pf.t1.lt(&q) || pf.t2.lt(&q) {
        return false;
    }
    if bn::gt(&pf.s1, &q3) || bn::gt(&pf.t1, &q7) {
        return false;
    }

    let e = bob_challenge(
        session,
        pk,
        x_point,
        pf.u.as_ref(),
        c1,
        c2,
        &pf.z,
        &pf.zprm,
        &pf.t,
        &pf.v,
        &pf.w,
    );

    // (4) WC: g^(s1 mod q) == X·e + U
    if let (Some(xp), Some(up)) = (x_point, pf.u.as_ref()) {
        let gs1 = secp::mul_base(&bn::rem(&pf.s1, &q));
        let xeu = secp::add(&secp::mul(xp, &e), up);
        if !secp::eq(&gs1, &xeu) {
            return false;
        }
    }

    let mnt = Modulus::new(ntilde);
    // (5) h1^s1 · h2^s2 == z^e · zprm
    let left = mnt.mul(&mnt.pow_pub(h1, &pf.s1), &mnt.pow_pub(h2, &pf.s2));
    let right = mnt.mul(&mnt.pow_pub(&pf.z, &e), &pf.zprm);
    if left != right {
        return false;
    }
    // (6) h1^t1 · h2^t2 == t^e · w
    let left = mnt.mul(&mnt.pow_pub(h1, &pf.t1), &mnt.pow_pub(h2, &pf.t2));
    let right = mnt.mul(&mnt.pow_pub(&pf.t, &e), &pf.w);
    if left != right {
        return false;
    }
    // (7) c1^s1 · S^N · Γ^t1 == c2^e · V  (mod N²)
    let mns = Modulus::new(&n2);
    let left = mns.mul(
        &mns.mul(&mns.pow_pub(c1, &pf.s1), &mns.pow_pub(&pf.s, &pk.n)),
        &mns.pow_pub(&pk.gamma(), &pf.t1),
    );
    let right = mns.mul(&mns.pow_pub(c2, &e), &pf.v);
    left == right
}

// ============================ share protocol ==============================

/// Alice's first message: `cA = Enc(a)` and a range proof.
pub(crate) fn alice_init<R: RngCore>(
    pk: &PublicKey,
    a: &BoxedUint,
    ntilde_b: &BoxedUint,
    h1b: &BoxedUint,
    h2b: &BoxedUint,
    rng: &mut R,
) -> Result<(BoxedUint, RangeProofAlice), Error> {
    let (ca, ra) = pk.encrypt(a, rng)?;
    let pf = prove_range_alice(pk, &ca, ntilde_b, h1b, h2b, a, &ra, rng);
    Ok((ca, pf))
}

/// Bob's middle step (basic / no consistency check). Returns `(β, cB, β', proof)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bob_mid<R: RngCore>(
    session: &[u8],
    pk: &PublicKey,
    range_pf: &RangeProofAlice,
    b: &BoxedUint,
    ca: &BoxedUint,
    ntilde_a: &BoxedUint,
    h1a: &BoxedUint,
    h2a: &BoxedUint,
    ntilde_b: &BoxedUint,
    h1b: &BoxedUint,
    h2b: &BoxedUint,
    rng: &mut R,
) -> Result<(BoxedUint, BoxedUint, BoxedUint, ProofBob), Error> {
    bob_mid_inner(
        session, pk, range_pf, b, ca, ntilde_a, h1a, h2a, ntilde_b, h1b, h2b, None, rng,
    )
}

/// Bob's middle step "with check": additionally binds `B = b·G`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bob_mid_wc<R: RngCore>(
    session: &[u8],
    pk: &PublicKey,
    range_pf: &RangeProofAlice,
    b: &BoxedUint,
    ca: &BoxedUint,
    ntilde_a: &BoxedUint,
    h1a: &BoxedUint,
    h2a: &BoxedUint,
    ntilde_b: &BoxedUint,
    h1b: &BoxedUint,
    h2b: &BoxedUint,
    b_point: &ProjectivePoint,
    rng: &mut R,
) -> Result<(BoxedUint, BoxedUint, BoxedUint, ProofBob), Error> {
    bob_mid_inner(
        session,
        pk,
        range_pf,
        b,
        ca,
        ntilde_a,
        h1a,
        h2a,
        ntilde_b,
        h1b,
        h2b,
        Some(b_point),
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn bob_mid_inner<R: RngCore>(
    session: &[u8],
    pk: &PublicKey,
    range_pf: &RangeProofAlice,
    b: &BoxedUint,
    ca: &BoxedUint,
    ntilde_a: &BoxedUint,
    h1a: &BoxedUint,
    h2a: &BoxedUint,
    ntilde_b: &BoxedUint,
    h1b: &BoxedUint,
    h2b: &BoxedUint,
    b_point: Option<&ProjectivePoint>,
    rng: &mut R,
) -> Result<(BoxedUint, BoxedUint, BoxedUint, ProofBob), Error> {
    if !verify_range_alice(pk, ntilde_b, h1b, h2b, ca, range_pf) {
        return Err(Error::Validation("mta: Alice range proof failed".into()));
    }
    let q = bn::secp256k1_order();
    let q5 = bn::mul(&bn::mul(&bn::mul(&q, &q), &bn::mul(&q, &q)), &q);
    let betaprm = bn::rand_below(&q5, rng);
    let (c_betaprm, c_rand) = pk.encrypt(&betaprm, rng)?;
    let cb = pk.homo_add(&pk.homo_mult(b, ca), &c_betaprm);
    let beta = Modulus::new(&q).sub(&bn::u64(0), &betaprm); // (−β') mod q
    let pi = prove_bob(
        session, pk, ntilde_a, h1a, h2a, ca, &cb, b, &betaprm, &c_rand, b_point, rng,
    );
    Ok((beta, cb, betaprm, pi))
}

/// Alice's final step (basic): verifies Bob's proof, decrypts `cB`, returns `α`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn alice_end(
    session: &[u8],
    pk: &PublicKey,
    sk: &PrivateKey,
    pi: &ProofBob,
    ntilde_a: &BoxedUint,
    h1a: &BoxedUint,
    h2a: &BoxedUint,
    ca: &BoxedUint,
    cb: &BoxedUint,
) -> Result<BoxedUint, Error> {
    if !verify_bob(session, pk, ntilde_a, h1a, h2a, ca, cb, pi, None) {
        return Err(Error::Validation("mta: Bob proof failed".into()));
    }
    let alpha_prm = sk.decrypt(cb)?;
    Ok(bn::rem(&alpha_prm, &bn::secp256k1_order()))
}

/// Alice's final step "with check": verifies against `B = b·G`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn alice_end_wc(
    session: &[u8],
    pk: &PublicKey,
    sk: &PrivateKey,
    pi: &ProofBob,
    b_point: &ProjectivePoint,
    ntilde_a: &BoxedUint,
    h1a: &BoxedUint,
    h2a: &BoxedUint,
    ca: &BoxedUint,
    cb: &BoxedUint,
) -> Result<BoxedUint, Error> {
    if !verify_bob(session, pk, ntilde_a, h1a, h2a, ca, cb, pi, Some(b_point)) {
        return Err(Error::Validation("mta: Bob WC proof failed".into()));
    }
    let alpha_prm = sk.decrypt(cb)?;
    Ok(bn::rem(&alpha_prm, &bn::secp256k1_order()))
}

#[cfg(test)]
mod tests {
    use super::super::paillier::PrivateKey;
    use super::super::testvec::{dec, fixtures};
    use super::*;

    /// A ring-Pedersen `(Ñ, h1, h2)` setup from the dlnproof fixture.
    fn ring_pedersen() -> (BoxedUint, BoxedUint, BoxedUint) {
        let f = fixtures();
        let d = &f["dlnproof"];
        (dec(&d["ntilde"]), dec(&d["h1"]), dec(&d["h2"]))
    }

    fn alice_pk() -> (PrivateKey, PublicKey) {
        let f = fixtures();
        let pp = &f["paillier_proof"];
        let sk = PrivateKey::from_primes(dec(&pp["p"]), dec(&pp["q"]));
        let pk = sk.pk.clone();
        (sk, pk)
    }

    // These round-trips run several 2048-bit Paillier proofs; with purecrypto's
    // current BoxedMontModulus they take >1 min each, so they are #[ignore]d in
    // CI and run manually (`cargo test --features ecdsatss -- --ignored`).
    #[test]
    #[ignore = "slow: multiple 2048-bit Paillier proofs"]
    fn mta_roundtrip_alpha_plus_beta_eq_ab() {
        let (sk, pk) = alice_pk();
        let (nt, h1, h2) = ring_pedersen();
        let session = b"mta-test";
        let mut rng = purecrypto::rng::OsRng;

        let a = bn::u64(0x9876_5432);
        let b = bn::u64(0x1234_5678);
        let (ca, range_pf) = alice_init(&pk, &a, &nt, &h1, &h2, &mut rng).unwrap();
        let (beta, cb, _bp, pi) = bob_mid(
            session, &pk, &range_pf, &b, &ca, &nt, &h1, &h2, &nt, &h1, &h2, &mut rng,
        )
        .unwrap();
        let alpha = alice_end(session, &pk, &sk, &pi, &nt, &h1, &h2, &ca, &cb).unwrap();

        let q = bn::secp256k1_order();
        let lhs = Modulus::new(&q).add(&alpha, &beta);
        let rhs = bn::rem(&bn::mul(&a, &b), &q);
        assert_eq!(bn::to_be(&lhs), bn::to_be(&rhs)); // α + β ≡ a·b (mod q)
    }

    #[test]
    #[ignore = "slow: multiple 2048-bit Paillier proofs"]
    fn mta_wc_roundtrip() {
        let (sk, pk) = alice_pk();
        let (nt, h1, h2) = ring_pedersen();
        let session = b"mta-wc-test";
        let mut rng = purecrypto::rng::OsRng;

        let a = bn::u64(7777);
        let b = bn::u64(31337);
        let b_point = secp::mul_base(&b); // B = b·G
        let (ca, range_pf) = alice_init(&pk, &a, &nt, &h1, &h2, &mut rng).unwrap();
        let (beta, cb, _bp, pi) = bob_mid_wc(
            session, &pk, &range_pf, &b, &ca, &nt, &h1, &h2, &nt, &h1, &h2, &b_point, &mut rng,
        )
        .unwrap();
        let alpha =
            alice_end_wc(session, &pk, &sk, &pi, &b_point, &nt, &h1, &h2, &ca, &cb).unwrap();

        let q = bn::secp256k1_order();
        let lhs = Modulus::new(&q).add(&alpha, &beta);
        let rhs = bn::rem(&bn::mul(&a, &b), &q);
        assert_eq!(bn::to_be(&lhs), bn::to_be(&rhs));
    }

    #[test]
    #[ignore = "slow: 2048-bit Paillier range proof"]
    fn range_proof_tamper_rejected() {
        let (_sk, pk) = alice_pk();
        let (nt, h1, h2) = ring_pedersen();
        let mut rng = purecrypto::rng::OsRng;
        let m = bn::u64(424242);
        let (c, r) = pk.encrypt(&m, &mut rng).unwrap();
        let mut pf = prove_range_alice(&pk, &c, &nt, &h1, &h2, &m, &r, &mut rng);
        assert!(verify_range_alice(&pk, &nt, &h1, &h2, &c, &pf));
        pf.s1 = bn::add(&pf.s1, &bn::one());
        assert!(!verify_range_alice(&pk, &nt, &h1, &h2, &c, &pf));
    }
}
