//! GG18 threshold ECDSA signing over a `MessageBroker` (9 rounds + finalize).
//!
//! Port of Go `ecdsatss/signing.go`. Produces a standard ECDSA signature
//! `(r, s)` verifiable against the group public key. The committee must be
//! exactly the parties of the supplied [`Key`] (indices aligned); to sign with a
//! strict subset, first narrow the key to that subset.
//!
//! Outline: round 1 runs the MtA `AliceInit` to every peer and commits to
//! `Γ_i = γ_i·G`; round 2 answers each peer's MtA with `BobMid`/`BobMidWC`;
//! round 3 finishes the MtA (`AliceEnd`) and shares `θ_i`; round 4 opens `Γ_i`
//! with a Schnorr proof and reveals `θ`'s inverse; round 5 reconstructs `R`,
//! computes `s_i` and commits to `(V_i, A_i)`; round 6 opens them with Schnorr +
//! V-proofs; round 7 runs the GG18 consistency check committing to `(U_i, T_i)`;
//! round 8 opens them; round 9 broadcasts `s_i` and finalize sums the shares.

#![allow(dead_code)]

use super::key::Key;
use super::mta::{self, ProofBob, RangeProofAlice};
use super::schnorr::{ZkProof, ZkVProof};
use super::secp::{self, ProjectivePoint};
use super::{Error, bn};
use crate::frost::hashing::sha512_256i;
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

/// A completed threshold-ECDSA signature.
#[derive(Clone, Debug)]
pub struct SignatureData {
    /// The `r` component (32 bytes, big-endian).
    pub r: Vec<u8>,
    /// The `s` component (32 bytes, big-endian, low-S normalized).
    pub s: Vec<u8>,
    /// Public-key recovery id.
    pub recovery: u8,
    /// The signed message hash.
    pub m: Vec<u8>,
}

/// A running GG18 signing session.
pub struct SigningParty {
    result_rx: MpscReceiver<Result<SignatureData, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    m: BoxedUint,
    ssid: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<SignatureData, Error>>>>,
}

struct State {
    k: BoxedUint,
    gamma: BoxedUint,
    point_gamma: Option<ProjectivePoint>,
    decommit: Vec<BoxedUint>,
    w: BoxedUint,
    big_ws: Vec<ProjectivePoint>,
    cis: Vec<Option<BoxedUint>>,

    betas: Vec<Option<BoxedUint>>,
    c1jis: Vec<Option<BoxedUint>>,
    c2jis: Vec<Option<BoxedUint>>,
    vs: Vec<Option<BoxedUint>>,

    r1m1: Vec<R1Msg1>,
    r1m1_from: Vec<PartyId>,
    r1_commitments: Vec<Option<BoxedUint>>,
    r1_join: u8,

    theta: BoxedUint,
    sigma: BoxedUint,
    theta_inverse: BoxedUint,

    si: BoxedUint,
    rx: BoxedUint,
    ry: BoxedUint,
    li: BoxedUint,
    roi: BoxedUint,
    big_r: Option<ProjectivePoint>,
    big_ai: Option<ProjectivePoint>,
    big_vi: Option<ProjectivePoint>,
    r5_decommit: Vec<BoxedUint>,
    r5_commitments: Vec<Option<BoxedUint>>,

    ui: Option<ProjectivePoint>,
    ti: Option<ProjectivePoint>,
    r7_decommit: Vec<BoxedUint>,
    r7_commitments: Vec<Option<BoxedUint>>,
}

impl SigningParty {
    /// Starts signing `message_hash` (a 32-byte digest, big-endian) with this
    /// party's share. The committee is the parties of `params`, aligned to `key`.
    pub fn new(params: Parameters, key: Key, message_hash: &[u8]) -> Result<SigningParty, Error> {
        let (tx, rx) = channel();
        let n = params.party_count();
        let m = bn::from_be(message_hash);
        let q = bn::secp256k1_order();
        if m.is_zero() || !m.lt(&q) {
            return Err(Error::Validation("signing: invalid message hash".into()));
        }
        let ssid = compute_ssid(&params, &key);
        let shared = Arc::new(Shared {
            params,
            key,
            m,
            ssid,
            state: Mutex::new(State {
                k: bn::u64(0),
                gamma: bn::u64(0),
                point_gamma: None,
                decommit: Vec::new(),
                w: bn::u64(0),
                big_ws: Vec::new(),
                cis: vec_none(n),
                betas: vec_none(n),
                c1jis: vec_none(n),
                c2jis: vec_none(n),
                vs: vec_none(n),
                r1m1: Vec::new(),
                r1m1_from: Vec::new(),
                r1_commitments: vec_none(n),
                r1_join: 0,
                theta: bn::u64(0),
                sigma: bn::u64(0),
                theta_inverse: bn::u64(0),
                si: bn::u64(0),
                rx: bn::u64(0),
                ry: bn::u64(0),
                li: bn::u64(0),
                roi: bn::u64(0),
                big_r: None,
                big_ai: None,
                big_vi: None,
                r5_decommit: Vec::new(),
                r5_commitments: vec_none(n),
                ui: None,
                ti: None,
                r7_decommit: Vec::new(),
                r7_commitments: vec_none(n),
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(SigningParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until signing completes.
    pub fn wait(&self) -> Result<SignatureData, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "signing session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<SignatureData, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn fail(&self, msg: impl Into<String>) {
        self.deliver(Err(Error::Validation(msg.into())));
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let i = self.params.party_index();
        let q = bn::secp256k1_order();

        // Lagrange-weighted share w_i and the transformed public shares bigWs.
        let (w, big_ws) = self.prepare_for_signing()?;

        // [1, q) like Go's GetRandomPositiveInt; rand_range is upper-inclusive
        // and would (with prob 2^-256) yield q ≡ 0 mod q.
        let k = bn::rand_positive_below(&q, &mut rng);
        let gamma = bn::rand_positive_below(&q, &mut rng);
        let point_gamma = secp::mul_base(&gamma);
        let (gx, gy) = secp::coords(&point_gamma);
        let (c, d) = super::commit::commit(&[gx, gy], &mut rng);

        let others = self.params.other_parties();
        let own_pk = self.key.paillier_sk().pk;
        for pj in &others {
            let j = pj.index as usize;
            let (ntj, h1j, h2j, _) = self.key.peer_params(j);
            let (ca, rp) = mta::alice_init(&own_pk, &k, &ntj, &h1j, &h2j, &mut rng)?;
            self.state.lock().unwrap().cis[j] = Some(ca.clone());
            let r1m1 = R1Msg1 {
                c: B64Bytes(bn::to_be(&ca)),
                range_proof_alice: parts_b64(&rp.to_parts()),
            };
            self.send_to(TYPE_R1_1, &r1m1, pj)?;
        }
        let r1m2 = R1Msg2 {
            commitment: B64Bytes(bn::to_be(&c)),
        };
        for pj in &others {
            self.send_to(TYPE_R1_2, &r1m2, pj)?;
        }

        {
            let mut st = self.state.lock().unwrap();
            st.k = k;
            st.gamma = gamma;
            st.point_gamma = Some(point_gamma);
            st.decommit = d;
            st.w = w;
            st.big_ws = big_ws;
        }
        let _ = i;

        self.connect(TYPE_R1_1, &others, {
            let me = Arc::clone(self);
            let others = others.clone();
            move |msgs| me.on_r1_1(&others, msgs)
        });
        self.connect(TYPE_R1_2, &others, {
            let me = Arc::clone(self);
            let others = others.clone();
            move |msgs| me.on_r1_2(&others, msgs)
        });
        Ok(())
    }

    fn on_r1_1(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R1Msg1>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r1m1 = d,
                Err(e) => return self.deliver(Err(Error::from(e))),
            }
            st.r1m1_from = others.to_vec();
            st.r1_join += 1;
            st.r1_join == 2
        };
        if ready {
            self.round2(others);
        }
    }

    fn on_r1_2(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let ready = {
            let mut st = self.state.lock().unwrap();
            for (k, m) in msgs.iter().enumerate() {
                let r1m2: R1Msg2 = match json_get(m) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(Error::from(e))),
                };
                let j = others[k].index as usize;
                st.r1_commitments[j] = Some(bn::from_be(&r1m2.commitment.0));
            }
            st.r1_join += 1;
            st.r1_join == 2
        };
        if ready {
            self.round2(others);
        }
    }

    fn round2(self: &Arc<Self>, _others: &[PartyId]) {
        let mut rng = OsRng;
        let i = self.params.party_index();
        let context_i = context_bytes(&self.ssid, i);
        let (r1m1, r1m1_from) = {
            let st = self.state.lock().unwrap();
            (st.r1m1.clone(), st.r1m1_from.clone())
        };
        let (my_nt, my_h1, my_h2, _) = self.key.peer_params(i);
        let (gamma, w, big_w_i) = {
            let st = self.state.lock().unwrap();
            (st.gamma.clone(), st.w.clone(), st.big_ws[i])
        };

        for (k, oid) in r1m1_from.iter().enumerate() {
            let j = oid.index as usize;
            let (ntj, h1j, h2j, pkj) = self.key.peer_params(j);
            let rp = match RangeProofAlice::from_parts(&parts_bytes(&r1m1[k].range_proof_alice)) {
                Some(v) => v,
                None => return self.fail("signing: bad range proof"),
            };
            let ca = bn::from_be(&r1m1[k].c.0);

            let (beta, c1, _, pi_bob) = match mta::bob_mid(
                &context_i, &pkj, &rp, &gamma, &ca, &ntj, &h1j, &h2j, &my_nt, &my_h1, &my_h2,
                &mut rng,
            ) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let (v, c2, _, pi_bob_wc) = match mta::bob_mid_wc(
                &context_i, &pkj, &rp, &w, &ca, &ntj, &h1j, &h2j, &my_nt, &my_h1, &my_h2, &big_w_i,
                &mut rng,
            ) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            {
                let mut st = self.state.lock().unwrap();
                st.betas[j] = Some(beta);
                st.c1jis[j] = Some(c1.clone());
                st.vs[j] = Some(v);
                st.c2jis[j] = Some(c2.clone());
            }
            let r2m = R2Msg {
                c1: B64Bytes(bn::to_be(&c1)),
                proof_bob: parts_b64(&pi_bob.to_parts()),
                c2: B64Bytes(bn::to_be(&c2)),
                proof_bob_wc: parts_b64(&pi_bob_wc.to_parts()),
            };
            if let Err(e) = self.send_to(TYPE_R2, &r2m, oid) {
                return self.deliver(Err(e));
            }
        }

        let others = self.params.other_parties();
        self.connect(TYPE_R2, &others, {
            let me = Arc::clone(self);
            move |msgs| me.round3(msgs)
        });
    }

    fn round3(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let i = self.params.party_index();
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let sk = self.key.paillier_sk();
        let pk = sk.pk.clone();
        let (my_nt, my_h1, my_h2, _) = self.key.peer_params(i);

        let from = self.params.other_parties();
        let (cis, betas, vs, k, gamma, w, big_ws) = {
            let st = self.state.lock().unwrap();
            (
                st.cis.clone(),
                st.betas.clone(),
                st.vs.clone(),
                st.k.clone(),
                st.gamma.clone(),
                st.w.clone(),
                st.big_ws.clone(),
            )
        };

        let mut theta = modq.mul(&k, &gamma);
        let mut sigma = modq.mul(&k, &w);

        for (k_idx, m) in msgs.iter().enumerate() {
            let r2: R2Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let j = from[k_idx].index as usize;
            let context_j = context_bytes(&self.ssid, j);

            let pi_bob = match ProofBob::from_parts(&parts_bytes(&r2.proof_bob)) {
                Some(v) => v,
                None => return self.fail("signing: bad proof_bob"),
            };
            let alpha = match mta::alice_end(
                &context_j,
                &pk,
                &sk,
                &pi_bob,
                &my_nt,
                &my_h1,
                &my_h2,
                cis[j].as_ref().unwrap(),
                &bn::from_be(&r2.c1.0),
            ) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let pi_bob_wc = match ProofBob::from_parts(&parts_bytes(&r2.proof_bob_wc)) {
                Some(v) => v,
                None => return self.fail("signing: bad proof_bob_wc"),
            };
            let u = match mta::alice_end_wc(
                &context_j,
                &pk,
                &sk,
                &pi_bob_wc,
                &big_ws[j],
                &my_nt,
                &my_h1,
                &my_h2,
                cis[j].as_ref().unwrap(),
                &bn::from_be(&r2.c2.0),
            ) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };

            theta = modq.add(&theta, &modq.add(&alpha, betas[j].as_ref().unwrap()));
            sigma = modq.add(&sigma, &modq.add(&u, vs[j].as_ref().unwrap()));
        }

        {
            let mut st = self.state.lock().unwrap();
            st.theta = theta.clone();
            st.sigma = sigma;
        }
        let r3 = R3Msg {
            theta: B64Bytes(bn::to_be(&theta)),
        };
        for pj in &from {
            if let Err(e) = self.send_to(TYPE_R3, &r3, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R3, &from, {
            let me = Arc::clone(self);
            move |msgs| me.round4(msgs)
        });
    }

    fn round4(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let i = self.params.party_index();
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);

        let (theta0, gamma, point_gamma, decommit) = {
            let st = self.state.lock().unwrap();
            (
                st.theta.clone(),
                st.gamma.clone(),
                st.point_gamma.unwrap(),
                st.decommit.clone(),
            )
        };
        let mut theta_total = theta0;
        for m in &msgs {
            let r3: R3Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            theta_total = modq.add(&theta_total, &bn::from_be(&r3.theta.0));
        }
        let theta_inverse = match modq.inv(&theta_total) {
            Some(v) => v,
            None => return self.fail("signing: theta not invertible"),
        };
        self.state.lock().unwrap().theta_inverse = theta_inverse;

        let context_i = context_bytes(&self.ssid, i);
        let pf = ZkProof::prove(&context_i, &secp::scalar(&gamma), &point_gamma, &mut rng);
        let (ax, ay) = secp::coords(&pf.alpha);

        let r4 = R4Msg {
            de_commitment: parts_b64(&decommit.iter().map(bn::to_be).collect::<Vec<_>>()),
            proof_alpha_x: B64Bytes(bn::to_be(&ax)),
            proof_alpha_y: B64Bytes(bn::to_be(&ay)),
            proof_t: B64Bytes(secp::scalar_to_be(&pf.t)),
        };
        let from = self.params.other_parties();
        for pj in &from {
            if let Err(e) = self.send_to(TYPE_R4, &r4, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R4, &from, {
            let me = Arc::clone(self);
            move |msgs| me.round5(msgs)
        });
    }

    fn round5(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let from = self.params.other_parties();

        let (point_gamma, theta_inverse, m_hash, k, sigma, r1_commitments) = {
            let st = self.state.lock().unwrap();
            (
                st.point_gamma.unwrap(),
                st.theta_inverse.clone(),
                self.m.clone(),
                st.k.clone(),
                st.sigma.clone(),
                st.r1_commitments.clone(),
            )
        };

        let mut r = point_gamma;
        for (k_idx, msg) in msgs.iter().enumerate() {
            let r4: R4Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let j = from[k_idx].index as usize;
            let context_j = context_bytes(&self.ssid, j);

            let cj = match &r1_commitments[j] {
                Some(c) => c.clone(),
                None => return self.fail("signing: missing round1 commitment"),
            };
            let d = parts_bytes(&r4.de_commitment)
                .iter()
                .map(|b| bn::from_be(b))
                .collect::<Vec<_>>();
            let opened = match super::commit::decommit(&cj, &d) {
                Some(v) if v.len() == 2 => v,
                _ => return self.fail("signing: bad Gamma decommitment"),
            };
            let big_gamma_j = match secp::from_coords(&opened[0], &opened[1]) {
                Some(p) => p,
                None => return self.fail("signing: Gamma_j off curve"),
            };
            let alpha = match secp::from_coords(
                &bn::from_be(&r4.proof_alpha_x.0),
                &bn::from_be(&r4.proof_alpha_y.0),
            ) {
                Some(p) => p,
                None => return self.fail("signing: Schnorr alpha off curve"),
            };
            let pf = ZkProof {
                alpha,
                t: secp::scalar_from_be(&r4.proof_t.0),
            };
            if !pf.verify(&context_j, &big_gamma_j) {
                return self.fail("signing: Schnorr proof for Gamma failed");
            }
            r = r.add(&big_gamma_j);
        }

        let r = secp::mul(&r, &theta_inverse);
        let (rx, ry) = secp::coords(&r);
        let si = modq.add(&modq.mul(&m_hash, &k), &modq.mul(&rx, &sigma));

        // [1, q) like Go's GetRandomPositiveInt (see round1).
        let li = bn::rand_positive_below(&q, &mut rng);
        let roi = bn::rand_positive_below(&q, &mut rng);
        let big_ai = secp::mul_base(&roi);
        let big_vi = secp::add(&secp::mul(&r, &si), &secp::mul_base(&li));

        let (vx, vy) = secp::coords(&big_vi);
        let (ax, ay) = secp::coords(&big_ai);
        let (c, d) = super::commit::commit(&[vx, vy, ax, ay], &mut rng);

        {
            let mut st = self.state.lock().unwrap();
            st.li = li;
            st.roi = roi;
            st.big_ai = Some(big_ai);
            st.big_vi = Some(big_vi);
            st.si = si;
            st.rx = rx;
            st.ry = ry;
            st.big_r = Some(r);
            st.r5_decommit = d;
        }
        let r5 = R5Msg {
            commitment: B64Bytes(bn::to_be(&c)),
        };
        for pj in &from {
            if let Err(e) = self.send_to(TYPE_R5, &r5, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R5, &from, {
            let me = Arc::clone(self);
            let from = from.clone();
            move |msgs| me.round6(&from, msgs)
        });
    }

    fn round6(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let i = self.params.party_index();

        {
            let mut st = self.state.lock().unwrap();
            for (k, msg) in msgs.iter().enumerate() {
                let r5: R5Msg = match json_get(msg) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e.into())),
                };
                let j = from[k].index as usize;
                st.r5_commitments[j] = Some(bn::from_be(&r5.commitment.0));
            }
        }

        let context_i = context_bytes(&self.ssid, i);
        let (roi, big_ai, big_vi, big_r, si, li, decommit) = {
            let st = self.state.lock().unwrap();
            (
                st.roi.clone(),
                st.big_ai.unwrap(),
                st.big_vi.unwrap(),
                st.big_r.unwrap(),
                st.si.clone(),
                st.li.clone(),
                st.r5_decommit.clone(),
            )
        };
        let pf_ai = ZkProof::prove(&context_i, &secp::scalar(&roi), &big_ai, &mut rng);
        let pf_v = ZkVProof::prove(
            &context_i,
            &big_vi,
            &big_r,
            &secp::scalar(&si),
            &secp::scalar(&li),
            &mut rng,
        );
        let (aax, aay) = secp::coords(&pf_ai.alpha);
        let (vax, vay) = secp::coords(&pf_v.alpha);

        let r6 = R6Msg {
            de_commitment: parts_b64(&decommit.iter().map(bn::to_be).collect::<Vec<_>>()),
            proof_alpha_x: B64Bytes(bn::to_be(&aax)),
            proof_alpha_y: B64Bytes(bn::to_be(&aay)),
            proof_t: B64Bytes(secp::scalar_to_be(&pf_ai.t)),
            v_proof_alpha_x: B64Bytes(bn::to_be(&vax)),
            v_proof_alpha_y: B64Bytes(bn::to_be(&vay)),
            v_proof_t: B64Bytes(secp::scalar_to_be(&pf_v.t)),
            v_proof_u: B64Bytes(secp::scalar_to_be(&pf_v.u)),
        };
        for pj in from {
            if let Err(e) = self.send_to(TYPE_R6, &r6, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R6, from, {
            let me = Arc::clone(self);
            let from = from.to_vec();
            move |msgs| me.round7(&from, msgs)
        });
    }

    fn round7(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);

        let (big_r, big_ai, big_vi, roi, li, m_hash, rx) = {
            let st = self.state.lock().unwrap();
            (
                st.big_r.unwrap(),
                st.big_ai.unwrap(),
                st.big_vi.unwrap(),
                st.roi.clone(),
                st.li.clone(),
                self.m.clone(),
                st.rx.clone(),
            )
        };
        let r5_commitments = self.state.lock().unwrap().r5_commitments.clone();

        // Σ V_j and Σ A_j (starting from own).
        let minus_m = modq.sub(&bn::u64(0), &m_hash);
        let minus_r = modq.sub(&bn::u64(0), &rx);
        let ecdsa_pub = match self.key.ecdsa_pub_point() {
            Some(p) => p,
            None => return self.fail("signing: ECDSAPub off curve"),
        };
        let mut v = secp::add(&secp::mul_base(&minus_m), &secp::mul(&ecdsa_pub, &minus_r));
        v = secp::add(&v, &big_vi);
        let mut a = big_ai;

        for (k, msg) in msgs.iter().enumerate() {
            let r6: R6Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let j = from[k].index as usize;
            let context_j = context_bytes(&self.ssid, j);
            let cj = match &r5_commitments[j] {
                Some(c) => c.clone(),
                None => return self.fail("signing: missing round5 commitment"),
            };
            let d = parts_bytes(&r6.de_commitment)
                .iter()
                .map(|b| bn::from_be(b))
                .collect::<Vec<_>>();
            let opened = match super::commit::decommit(&cj, &d) {
                Some(v) if v.len() == 4 => v,
                _ => return self.fail("signing: bad V/A decommitment"),
            };
            let big_vj = match secp::from_coords(&opened[0], &opened[1]) {
                Some(p) => p,
                None => return self.fail("signing: V_j off curve"),
            };
            let big_aj = match secp::from_coords(&opened[2], &opened[3]) {
                Some(p) => p,
                None => return self.fail("signing: A_j off curve"),
            };
            let pf_a = ZkProof {
                alpha: match secp::from_coords(
                    &bn::from_be(&r6.proof_alpha_x.0),
                    &bn::from_be(&r6.proof_alpha_y.0),
                ) {
                    Some(p) => p,
                    None => return self.fail("signing: A proof alpha off curve"),
                },
                t: secp::scalar_from_be(&r6.proof_t.0),
            };
            if !pf_a.verify(&context_j, &big_aj) {
                return self.fail("signing: Schnorr proof for A_j failed");
            }
            let pf_v = ZkVProof {
                alpha: match secp::from_coords(
                    &bn::from_be(&r6.v_proof_alpha_x.0),
                    &bn::from_be(&r6.v_proof_alpha_y.0),
                ) {
                    Some(p) => p,
                    None => return self.fail("signing: V proof alpha off curve"),
                },
                t: secp::scalar_from_be(&r6.v_proof_t.0),
                u: secp::scalar_from_be(&r6.v_proof_u.0),
            };
            if !pf_v.verify(&context_j, &big_vj, &big_r) {
                return self.fail("signing: V-proof for V_j failed");
            }
            v = secp::add(&v, &big_vj);
            a = secp::add(&a, &big_aj);
        }

        let ui = secp::mul(&v, &roi);
        let ti = secp::mul(&a, &li);
        let (ux, uy) = secp::coords(&ui);
        let (tx, ty) = secp::coords(&ti);
        let (c, d) = super::commit::commit(&[ux, uy, tx, ty], &mut rng);

        {
            let mut st = self.state.lock().unwrap();
            st.ui = Some(ui);
            st.ti = Some(ti);
            st.r7_decommit = d;
        }
        let r7 = R7Msg {
            commitment: B64Bytes(bn::to_be(&c)),
        };
        for pj in from {
            if let Err(e) = self.send_to(TYPE_R7, &r7, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R7, from, {
            let me = Arc::clone(self);
            let from = from.to_vec();
            move |msgs| me.round8(&from, msgs)
        });
    }

    fn round8(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        {
            let mut st = self.state.lock().unwrap();
            for (k, msg) in msgs.iter().enumerate() {
                let r7: R7Msg = match json_get(msg) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e.into())),
                };
                let j = from[k].index as usize;
                st.r7_commitments[j] = Some(bn::from_be(&r7.commitment.0));
            }
        }
        let decommit = self.state.lock().unwrap().r7_decommit.clone();
        let r8 = R8Msg {
            de_commitment: parts_b64(&decommit.iter().map(bn::to_be).collect::<Vec<_>>()),
        };
        for pj in from {
            if let Err(e) = self.send_to(TYPE_R8, &r8, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R8, from, {
            let me = Arc::clone(self);
            let from = from.to_vec();
            move |msgs| me.round9(&from, msgs)
        });
    }

    fn round9(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let (ui, ti, r7_commitments, si) = {
            let st = self.state.lock().unwrap();
            (
                st.ui.unwrap(),
                st.ti.unwrap(),
                st.r7_commitments.clone(),
                st.si.clone(),
            )
        };
        let mut u = ui;
        let mut t = ti;
        for (k, msg) in msgs.iter().enumerate() {
            let r8: R8Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let j = from[k].index as usize;
            let cj = match &r7_commitments[j] {
                Some(c) => c.clone(),
                None => return self.fail("signing: missing round7 commitment"),
            };
            let d = parts_bytes(&r8.de_commitment)
                .iter()
                .map(|b| bn::from_be(b))
                .collect::<Vec<_>>();
            let opened = match super::commit::decommit(&cj, &d) {
                Some(v) if v.len() == 4 => v,
                _ => return self.fail("signing: bad U/T decommitment"),
            };
            let uj = match secp::from_coords(&opened[0], &opened[1]) {
                Some(p) => p,
                None => return self.fail("signing: U_j off curve"),
            };
            let tj = match secp::from_coords(&opened[2], &opened[3]) {
                Some(p) => p,
                None => return self.fail("signing: T_j off curve"),
            };
            u = secp::add(&u, &uj);
            t = secp::add(&t, &tj);
        }
        if !secp::eq(&u, &t) {
            return self.fail("signing: U != T (consistency check failed)");
        }

        let r9 = R9Msg {
            si: B64Bytes(bn::to_be(&si)),
        };
        for pj in from {
            if let Err(e) = self.send_to(TYPE_R9, &r9, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R9, from, {
            let me = Arc::clone(self);
            move |msgs| me.finalize(msgs)
        });
    }

    fn finalize(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let (si, rx, ry) = {
            let st = self.state.lock().unwrap();
            (st.si.clone(), st.rx.clone(), st.ry.clone())
        };
        let mut sum_s = si;
        for msg in &msgs {
            let r9: R9Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            sum_s = modq.add(&sum_s, &bn::from_be(&r9.si.0));
        }

        let mut recid = 0u8;
        if bn::gt(&rx, &q) {
            recid = 2;
        }
        if bn::bit(&ry, 0) != 0 {
            recid |= 1;
        }
        // Low-S normalization.
        let half_n = q.shr_bits(1);
        if bn::gt(&sum_s, &half_n) {
            sum_s = bn::sub(&q, &sum_s);
            recid ^= 1;
        }

        // Verify the assembled ECDSA signature against the group public key.
        let ecdsa_pub = match self.key.ecdsa_pub_point() {
            Some(p) => p,
            None => return self.fail("signing: ECDSAPub off curve"),
        };
        if !ecdsa_verify(&self.m, &rx, &sum_s, &ecdsa_pub) {
            return self.fail("signing: final signature verification failed");
        }

        self.deliver(Ok(SignatureData {
            r: pad32(&bn::to_be(&rx)),
            s: pad32(&bn::to_be(&sum_s)),
            recovery: recid,
            m: bn::to_be(&self.m),
        }));
    }

    /// Computes `w_i` (Lagrange-weighted share) and the transformed public shares.
    fn prepare_for_signing(&self) -> Result<(BoxedUint, Vec<ProjectivePoint>), Error> {
        let i = self.params.party_index();
        let q = bn::secp256k1_order();
        let modq = bn::Modulus::new(&q);
        let ks = self.key.ks();
        let big_xs = self
            .key
            .big_xj_points()
            .ok_or_else(|| Error::Validation("signing: BigXj off curve".into()))?;
        let n = ks.len();
        if self.params.threshold() + 1 > n {
            return Err(Error::Validation("signing: t+1 > parties".into()));
        }

        let mut wi = self.key.xi();
        for j in 0..n {
            if j == i {
                continue;
            }
            let denom = modq.sub(&ks[j], &ks[i]);
            let inv = modq
                .inv(&denom)
                .ok_or_else(|| Error::Validation("signing: duplicate party index".into()))?;
            let coef = modq.mul(&ks[j], &inv);
            wi = modq.mul(&wi, &coef);
        }

        let mut big_ws = Vec::with_capacity(n);
        for (j, big_xj) in big_xs.iter().enumerate() {
            let mut point = *big_xj;
            for c in 0..n {
                if j == c {
                    continue;
                }
                let denom = modq.sub(&ks[c], &ks[j]);
                let inv = modq
                    .inv(&denom)
                    .ok_or_else(|| Error::Validation("signing: duplicate party index".into()))?;
                let iota = modq.mul(&ks[c], &inv);
                point = secp::mul(&point, &iota);
            }
            big_ws.push(point);
        }
        Ok((wi, big_ws))
    }

    fn connect<F>(self: &Arc<Self>, typ: &str, others: &[PartyId], cb: F)
    where
        F: FnOnce(Vec<JsonMessage>) + Send + 'static,
    {
        let exp = JsonExpect::new(typ, others.to_vec(), Box::new(cb));
        self.params.broker().connect(typ, Arc::new(exp));
    }

    fn send_to<T: Serialize>(&self, typ: &str, body: &T, to: &PartyId) -> Result<(), Error> {
        let msg = json_wrap(
            typ,
            body,
            Some(self.params.party_id().clone()),
            Some(to.clone()),
        )?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }
}

// --- ECDSA verification ----------------------------------------------------

fn ecdsa_verify(m: &BoxedUint, r: &BoxedUint, s: &BoxedUint, pubkey: &ProjectivePoint) -> bool {
    let q = bn::secp256k1_order();
    let modq = bn::Modulus::new(&q);
    let r = bn::rem(r, &q);
    if r.is_zero() || s.is_zero() {
        return false;
    }
    let w = match modq.inv(s) {
        Some(v) => v,
        None => return false,
    };
    let u1 = modq.mul(m, &w);
    let u2 = modq.mul(&r, &w);
    let p = secp::add(&secp::mul_base(&u1), &secp::mul(pubkey, &u2));
    let (px, _) = secp::coords(&p);
    bn::rem(&px, &q) == r
}

// --- helpers ---------------------------------------------------------------

const TYPE_R1_1: &str = "ecdsa:sign:round1-1";
const TYPE_R1_2: &str = "ecdsa:sign:round1-2";
const TYPE_R2: &str = "ecdsa:sign:round2";
const TYPE_R3: &str = "ecdsa:sign:round3";
const TYPE_R4: &str = "ecdsa:sign:round4";
const TYPE_R5: &str = "ecdsa:sign:round5";
const TYPE_R6: &str = "ecdsa:sign:round6";
const TYPE_R7: &str = "ecdsa:sign:round7";
const TYPE_R8: &str = "ecdsa:sign:round8";
const TYPE_R9: &str = "ecdsa:sign:round9";

fn vec_none<T>(n: usize) -> Vec<Option<T>> {
    (0..n).map(|_| None).collect()
}

fn compute_ssid(params: &Parameters, key: &Key) -> Vec<u8> {
    let (gx, gy) = secp::generator_coords();
    // Go: P, N, B(=7), Gx, Gy, keys..., flatten(BigXj), NTildej..., H1j..., H2j..., 1, nonce.
    let mut list: Vec<Vec<u8>> = vec![
        bn::to_be(&secp::field_prime()),
        bn::to_be(&q_order()),
        bn::to_be(&bn::u64(7)), // secp256k1 B
        bn::to_be(&gx),
        bn::to_be(&gy),
    ];
    for p in params.parties() {
        list.push(p.key.clone());
    }
    if let Some(pts) = key.big_xj_points() {
        for p in &pts {
            let (x, y) = secp::coords(p);
            list.push(bn::to_be(&x));
            list.push(bn::to_be(&y));
        }
    }
    let n = params.party_count();
    for j in 0..n {
        list.push(bn::to_be(&key.peer_params(j).0));
    }
    for j in 0..n {
        list.push(bn::to_be(&key.peer_params(j).1));
    }
    for j in 0..n {
        list.push(bn::to_be(&key.peer_params(j).2));
    }
    list.push(bn::to_be(&bn::u64(1)));
    list.push(bn::to_be(&bn::u64(0)));
    let refs: Vec<&[u8]> = list.iter().map(|b| b.as_slice()).collect();
    sha512_256i(&refs).to_vec()
}

fn q_order() -> BoxedUint {
    bn::secp256k1_order()
}

fn context_bytes(ssid: &[u8], idx: usize) -> Vec<u8> {
    let mut c = ssid.to_vec();
    c.extend_from_slice(&bn::to_be(&bn::u64(idx as u64)));
    c
}

fn pad32(be: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = be.len().min(32);
    out[32 - n..].copy_from_slice(&be[be.len() - n..]);
    out
}

fn parts_b64(parts: &[Vec<u8>]) -> Vec<B64Bytes> {
    parts.iter().map(|p| B64Bytes(p.clone())).collect()
}

fn parts_bytes(parts: &[B64Bytes]) -> Vec<Vec<u8>> {
    parts.iter().map(|p| p.0.clone()).collect()
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg1 {
    #[serde(rename = "c")]
    c: B64Bytes,
    #[serde(rename = "range_proof_alice")]
    range_proof_alice: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg2 {
    #[serde(rename = "commitment")]
    commitment: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg {
    #[serde(rename = "c1")]
    c1: B64Bytes,
    #[serde(rename = "proof_bob")]
    proof_bob: Vec<B64Bytes>,
    #[serde(rename = "c2")]
    c2: B64Bytes,
    #[serde(rename = "proof_bob_wc")]
    proof_bob_wc: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg {
    #[serde(rename = "theta")]
    theta: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R4Msg {
    #[serde(rename = "de_commitment")]
    de_commitment: Vec<B64Bytes>,
    #[serde(rename = "proof_alpha_x")]
    proof_alpha_x: B64Bytes,
    #[serde(rename = "proof_alpha_y")]
    proof_alpha_y: B64Bytes,
    #[serde(rename = "proof_t")]
    proof_t: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R5Msg {
    #[serde(rename = "commitment")]
    commitment: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R6Msg {
    #[serde(rename = "de_commitment")]
    de_commitment: Vec<B64Bytes>,
    #[serde(rename = "proof_alpha_x")]
    proof_alpha_x: B64Bytes,
    #[serde(rename = "proof_alpha_y")]
    proof_alpha_y: B64Bytes,
    #[serde(rename = "proof_t")]
    proof_t: B64Bytes,
    #[serde(rename = "v_proof_alpha_x")]
    v_proof_alpha_x: B64Bytes,
    #[serde(rename = "v_proof_alpha_y")]
    v_proof_alpha_y: B64Bytes,
    #[serde(rename = "v_proof_t")]
    v_proof_t: B64Bytes,
    #[serde(rename = "v_proof_u")]
    v_proof_u: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R7Msg {
    #[serde(rename = "commitment")]
    commitment: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R8Msg {
    #[serde(rename = "de_commitment")]
    de_commitment: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R9Msg {
    #[serde(rename = "si")]
    si: B64Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsatss::testvec::fixtures;
    use crate::tss::testhub::TestHub;

    /// Loads the real Go-generated 2-party (t=1) keys and builds the matching
    /// committee party IDs (key = `Ks[i]` big-endian), sorted ascending.
    fn load_signing_keys() -> (Vec<Key>, Vec<PartyId>) {
        let f = fixtures();
        let keys: Vec<Key> = f["signing_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .collect();
        let ksu = keys[0].ks();
        let ids = PartyId::sort(
            (0..keys.len())
                .map(|i| PartyId::new((i + 1).to_string(), format!("P{i}"), bn::to_be(&ksu[i])))
                .collect(),
            0,
        );
        (keys, ids)
    }

    #[test]
    #[ignore = "2048-bit MtA signing is slow with the current bignum"]
    fn go_keys_sign_and_verify() {
        let (keys, ids) = load_signing_keys();
        let t = 1;

        // A 32-byte digest in range.
        let mut digest = [0u8; 32];
        digest[31] = 0x2a;
        digest[0] = 0x11;

        let shub = TestHub::new(&ids);
        let sparties: Vec<SigningParty> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, shub.broker(i));
                SigningParty::new(params, keys[i].clone(), &digest).unwrap()
            })
            .collect();
        let sigs: Vec<SignatureData> = sparties
            .iter()
            .map(|p| p.wait().expect("signing succeeds"))
            .collect();

        // All parties output the same (r, s); it verifies against ECDSAPub.
        for s in &sigs[1..] {
            assert_eq!(s.r, sigs[0].r);
            assert_eq!(s.s, sigs[0].s);
        }
        let r = bn::from_be(&sigs[0].r);
        let s = bn::from_be(&sigs[0].s);
        let m = bn::from_be(&digest);
        let pk = keys[0].ecdsa_pub_point().unwrap();
        assert!(ecdsa_verify(&m, &r, &s, &pk));
    }
}
