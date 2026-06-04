//! Broker-driven DKLs23 threshold-ECDSA signing.
//!
//! The per-party state machine that runs DKLs23 signing over a
//! [`MessageBroker`], the distributed counterpart to the synchronous
//! [`sign`](super::sign). Each signer in the chosen `T+1` subset constructs its
//! own [`SigningParty`] against the same key, message hash, and committee; the
//! parties converge on one standard ECDSA signature.
//!
//! Rounds: (1) broadcast `K_i = k_i·G`; (1-echo) cross-check every `K_j` for
//! equivocation; (2) per-peer Alice ΠMul envelopes for `k·ρ` and `x·ρ`;
//! (3) per-peer Bob ΠMul responses; (4) broadcast `(φ_i, ŝ_i)`; (4-echo)
//! cross-check the reveals; finalize aggregates and emits `s = ŝ·φ⁻¹`.
//! Wire-compatible with Go `dklstss` signing.

use super::echo::{EchoMsg, commit_digest, other_parties, peer_key_str, point_from_be_xy, strip};
use super::key::{Key, Signature};
use super::ole::{self, AliceState};
use super::otext::{self, ExtendMsg1};
use super::secp::{self, ProjectivePoint, Scalar};
use super::signing::{ecdsa_verify, hash_to_scalar, is_high_s, lagrange_coefficient};
use super::{Error, echo::verify_echoes};
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::hash::sha256;
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "dkls:sign:r1";
const TYPE_R1ECHO: &str = "dkls:sign:r1echo";
const TYPE_R2: &str = "dkls:sign:r2";
const TYPE_R3: &str = "dkls:sign:r3";
const TYPE_R4: &str = "dkls:sign:r4";
const TYPE_R4ECHO: &str = "dkls:sign:r4echo";

const ECHO_TAG_SIGN: &str = "DKLS23-echo-sign-v1";
const ECHO_TAG_SIGN_R4: &str = "DKLS23-echo-sign-r4-v1";
const ECHO_SOURCE_SIGN: &str = "dklstss-sign";

/// A running DKLs23 threshold-ECDSA signing session. Construct with
/// [`SigningParty::new`]; retrieve the [`Signature`] with [`SigningParty::wait`].
pub struct SigningParty {
    result_rx: MpscReceiver<Result<Signature, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    hash: Vec<u8>,
    tweak: Option<Scalar>,
    subset: Vec<PartyId>,
    other_subset: Vec<PartyId>,
    my_pos: usize,
    sx_mine: Scalar,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<Signature, Error>>>>,
}

struct State {
    ssid: Vec<u8>,
    k_i: Scalar,
    rho_i: Scalar,
    big_k_i: ProjectivePoint,
    r: Scalar,
    alice_k: HashMap<String, AliceState>,
    alice_x: HashMap<String, AliceState>,
    peer_k: HashMap<String, ProjectivePoint>,
    k_rho_mine: Scalar,
    x_rho_mine: Scalar,
    phi_i: Scalar,
    shat_i: Scalar,
    r4msgs: HashMap<String, SignR4>,
}

impl SigningParty {
    /// Starts broker-driven signing for this party. `subset` must be the sorted
    /// `T+1` signing committee (by party key) including this party; `tweak` is
    /// the optional HD-derived additive tweak (absorbed by the first signer).
    pub fn new(
        params: Parameters,
        key: Key,
        hash: Vec<u8>,
        subset: Vec<PartyId>,
        tweak: Option<Scalar>,
    ) -> Result<SigningParty, Error> {
        if hash.is_empty() {
            return Err(Error::Validation("NewSigning empty hash".into()));
        }
        key.validate_basic()?;
        if subset.len() != key.t + 1 {
            return Err(Error::Validation(format!(
                "subset size {}, expected T+1={}",
                subset.len(),
                key.t + 1
            )));
        }
        validate_sorted_subset(&subset)?;

        let me = params.party_id().clone();
        let my_pos = subset
            .iter()
            .position(|p| p.cmp_key(&me) == std::cmp::Ordering::Equal)
            .ok_or_else(|| Error::Validation("self not in signing subset".into()))?;

        // λ_myPos · x_i (+ tweak if this is the first signer).
        let ids: Vec<Scalar> = subset
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();
        let lam = lagrange_coefficient(&ids, my_pos)?;
        let mut sx_mine = lam.mul(&key.xi);
        if my_pos == 0 {
            if let Some(tw) = &tweak {
                sx_mine = sx_mine.add(tw);
            }
        }

        let other_subset = other_parties(&subset, &me);
        let ssid = sign_session(&key, &hash, &subset);

        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key,
            hash,
            tweak,
            subset,
            other_subset,
            my_pos,
            sx_mine,
            state: Mutex::new(State {
                ssid,
                k_i: Scalar::ZERO,
                rho_i: Scalar::ZERO,
                big_k_i: secp::generator(),
                r: Scalar::ZERO,
                alice_k: HashMap::new(),
                alice_x: HashMap::new(),
                peer_k: HashMap::new(),
                k_rho_mine: Scalar::ZERO,
                x_rho_mine: Scalar::ZERO,
                phi_i: Scalar::ZERO,
                shat_i: Scalar::ZERO,
                r4msgs: HashMap::new(),
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(SigningParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until signing completes, returning the signature or an error.
    pub fn wait(&self) -> Result<Signature, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "signing session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<Signature, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let k_i = secp::random_scalar(&mut rng);
        let rho_i = secp::random_scalar(&mut rng);
        let big_k_i = secp::mul_base(&k_i);

        {
            let mut st = self.state.lock().unwrap();
            st.k_rho_mine = k_i.mul(&rho_i);
            st.x_rho_mine = self.sx_mine.mul(&rho_i);
            st.k_i = k_i;
            st.rho_i = rho_i;
            st.big_k_i = big_k_i;
        }

        let (kx, ky) = secp::affine_be(&big_k_i);
        let r1 = SignR1 {
            k_i_x: B64Bytes(kx),
            k_i_y: B64Bytes(ky),
        };
        self.broadcast(TYPE_R1, &r1)?;

        let me = Arc::clone(self);
        let others = self.other_subset.clone();
        let exp = JsonExpect::new(
            TYPE_R1,
            self.other_subset.clone(),
            Box::new(move |msgs| me.on_r1(&others, msgs)),
        );
        self.params.broker().connect(TYPE_R1, Arc::new(exp));
        Ok(())
    }

    fn on_r1(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let r1s: Vec<SignR1> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        let me = self.params.party_id().clone();
        let digests: HashMap<String, B64Bytes> = {
            let mut st = self.state.lock().unwrap();
            let mut r_point = st.big_k_i;
            for (pid, r1) in others.iter().zip(r1s.iter()) {
                let Some(kj) = point_from_be_xy(&r1.k_i_x.0, &r1.k_i_y.0) else {
                    return self
                        .deliver(Err(echo_fail(format!("party {pid} sent invalid K_j"), pid)));
                };
                st.peer_k.insert(peer_key_str(pid), kj);
                r_point = r_point.add(&kj);
            }
            let (rx, _) = secp::affine_be(&r_point);
            let r = secp::scalar_from_be_reduce(&rx);
            if bool::from(r.is_zero()) {
                return self.deliver(Err(Error::Validation(
                    "R.x mod n == 0, retry with fresh randomness".into(),
                )));
            }
            st.r = r;

            others
                .iter()
                .map(|pid| {
                    let kj = st.peer_k[&peer_key_str(pid)];
                    (peer_key_str(pid), B64Bytes(ki_digest(pid, &kj)))
                })
                .collect()
        };

        if let Err(e) = self.broadcast(TYPE_R1ECHO, &EchoMsg { digests }) {
            return self.deliver(Err(e));
        }
        let _ = me;
        let me = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R1ECHO,
            self.other_subset.clone(),
            Box::new(move |msgs| me.on_r1_echo(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_R1ECHO, Arc::new(exp));
    }

    fn on_r1_echo(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let echoes: Vec<EchoMsg> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };
        let me = self.params.party_id().clone();
        let self_key = peer_key_str(&me);

        let my_digests: HashMap<String, Vec<u8>> = {
            let st = self.state.lock().unwrap();
            let mut m = HashMap::with_capacity(others.len() + 1);
            for pid in others {
                let kj = st.peer_k[&peer_key_str(pid)];
                m.insert(peer_key_str(pid), ki_digest(pid, &kj));
            }
            m.insert(self_key.clone(), ki_digest(&me, &st.big_k_i));
            m
        };
        let mut all = vec![me.clone()];
        all.extend(others.iter().cloned());
        if let Err(e) = verify_echoes(
            &my_digests,
            &self_key,
            others,
            &echoes,
            &all,
            ECHO_SOURCE_SIGN,
        ) {
            return self.deliver(Err(e));
        }

        // Mix every signer's K_i into the effective ssid for rounds 2+.
        {
            let mut st = self.state.lock().unwrap();
            let peer_k = st.peer_k.clone();
            let base = st.ssid.clone();
            st.ssid = mix_round_one_ssid(&base, &me, &st.big_k_i, others, &peer_k);
        }

        // For each peer, play Alice in two ΠMul instances: (k_i, ρ_j), (sx_i, ρ_j).
        for pj in &self.other_subset {
            let idx = self.index_in_full_committee(pj);
            let alice_pair = match idx.and_then(|i| self.key.ot[i].as_ref()) {
                Some(p) => &p.as_alice,
                None => {
                    return self.deliver(Err(Error::Validation(format!(
                        "missing OT state with {pj}"
                    ))));
                }
            };
            let (ssid, k_i) = {
                let st = self.state.lock().unwrap();
                (st.ssid.clone(), st.k_i.clone())
            };
            let sid_k = sign_mul_sid(&ssid, "kxrho", &me.key, &pj.key);
            let sid_x = sign_mul_sid(&ssid, "xxrho", &me.key, &pj.key);

            let (msg_k, st_k) = match ole::alice_step1(&sid_k, alice_pair, &k_i) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let (msg_x, st_x) = match ole::alice_step1(&sid_x, alice_pair, &self.sx_mine) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            {
                let mut st = self.state.lock().unwrap();
                st.alice_k.insert(peer_key_str(pj), st_k);
                st.alice_x.insert(peer_key_str(pj), st_x);
            }
            let r2 = SignR2 {
                alice_k: EncExtendMsg::from_msg(&msg_k),
                alice_x: EncExtendMsg::from_msg(&msg_x),
            };
            if let Err(e) = self.send_to(TYPE_R2, &r2, pj) {
                return self.deliver(Err(e));
            }
        }

        let me_arc = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R2,
            self.other_subset.clone(),
            Box::new(move |msgs| me_arc.on_r2(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_R2, Arc::new(exp));
    }

    fn on_r2(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let r2s: Vec<SignR2> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };
        let me = self.params.party_id().clone();

        for (pid, r2) in others.iter().zip(r2s.iter()) {
            let idx = self.index_in_full_committee(pid);
            let bob_pair = match idx.and_then(|i| self.key.ot[i].as_ref()) {
                Some(p) => &p.as_bob,
                None => {
                    return self.deliver(Err(Error::Validation(format!(
                        "missing OT state with {pid}"
                    ))));
                }
            };
            let ext_k = match r2.alice_k.to_msg() {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e)),
            };
            let ext_x = match r2.alice_x.to_msg() {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e)),
            };
            let (ssid, rho_i) = {
                let st = self.state.lock().unwrap();
                (st.ssid.clone(), st.rho_i.clone())
            };
            // peer is Alice, self is Bob.
            let sid_k = sign_mul_sid(&ssid, "kxrho", &pid.key, &me.key);
            let sid_x = sign_mul_sid(&ssid, "xxrho", &pid.key, &me.key);

            let (bmsg_k, u_bk) = match ole::bob_step1(&sid_k, bob_pair, &rho_i, &ext_k) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let (bmsg_x, u_bx) = match ole::bob_step1(&sid_x, bob_pair, &rho_i, &ext_x) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            {
                let mut st = self.state.lock().unwrap();
                st.k_rho_mine = st.k_rho_mine.add(&u_bk);
                st.x_rho_mine = st.x_rho_mine.add(&u_bx);
            }
            let r3 = SignR3 {
                bob_k: encode_bob(&bmsg_k),
                bob_x: encode_bob(&bmsg_x),
            };
            if let Err(e) = self.send_to(TYPE_R3, &r3, pid) {
                return self.deliver(Err(e));
            }
        }

        let me_arc = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R3,
            self.other_subset.clone(),
            Box::new(move |msgs| me_arc.on_r3(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_R3, Arc::new(exp));
    }

    fn on_r3(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let r3s: Vec<SignR3> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        for (pid, r3) in others.iter().zip(r3s.iter()) {
            let bob_k = match decode_bob(&r3.bob_k) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let bob_x = match decode_bob(&r3.bob_x) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let key = peer_key_str(pid);
            let (u_ak, u_ax) = {
                let st = self.state.lock().unwrap();
                let st_k = match st.alice_k.get(&key) {
                    Some(s) => s,
                    None => {
                        return self.deliver(Err(Error::Validation(format!(
                            "missing Alice state for {pid}"
                        ))));
                    }
                };
                let st_x = st.alice_x.get(&key).expect("alice_x present");
                let u_ak = match ole::alice_step2(st_k, &bob_k) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e)),
                };
                let u_ax = match ole::alice_step2(st_x, &bob_x) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e)),
                };
                (u_ak, u_ax)
            };
            let mut st = self.state.lock().unwrap();
            st.k_rho_mine = st.k_rho_mine.add(&u_ak);
            st.x_rho_mine = st.x_rho_mine.add(&u_ax);
        }

        // φ_i = k_rho_mine ; ŝ_i = ρ_i·H + r·x_rho_mine.
        let e = hash_to_scalar(&self.hash);
        let r4 = {
            let mut st = self.state.lock().unwrap();
            let phi_i = st.k_rho_mine.clone();
            let shat_i = st.rho_i.mul(&e).add(&st.r.mul(&st.x_rho_mine));
            st.phi_i = phi_i.clone();
            st.shat_i = shat_i.clone();
            SignR4 {
                phi: B64Bytes(secp::scalar_to_be_min(&phi_i)),
                shat: B64Bytes(secp::scalar_to_be_min(&shat_i)),
            }
        };
        if let Err(e) = self.broadcast(TYPE_R4, &r4) {
            return self.deliver(Err(e));
        }

        let me_arc = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R4,
            self.other_subset.clone(),
            Box::new(move |msgs| me_arc.on_r4_echo(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_R4, Arc::new(exp));
    }

    fn on_r4_echo(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let r4s: Vec<SignR4> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };
        let me = self.params.party_id().clone();
        let digests: HashMap<String, B64Bytes> = {
            let mut st = self.state.lock().unwrap();
            let mut d = HashMap::with_capacity(others.len());
            for (pid, r4) in others.iter().zip(r4s.iter()) {
                st.r4msgs.insert(peer_key_str(pid), r4.clone());
                d.insert(peer_key_str(pid), B64Bytes(r4_digest(pid, r4)));
            }
            d
        };
        if let Err(e) = self.broadcast(TYPE_R4ECHO, &EchoMsg { digests }) {
            return self.deliver(Err(e));
        }
        let _ = me;
        let me_arc = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R4ECHO,
            self.other_subset.clone(),
            Box::new(move |msgs| me_arc.finalize(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_R4ECHO, Arc::new(exp));
    }

    fn finalize(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let echoes: Vec<EchoMsg> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };
        let me = self.params.party_id().clone();
        let self_key = peer_key_str(&me);

        let st = self.state.lock().unwrap();

        // Cross-check every signer's (φ, ŝ) reveal.
        let my_digests: HashMap<String, Vec<u8>> = {
            let mut m = HashMap::with_capacity(others.len() + 1);
            for pid in others {
                m.insert(
                    peer_key_str(pid),
                    r4_digest(pid, &st.r4msgs[&peer_key_str(pid)]),
                );
            }
            let own = SignR4 {
                phi: B64Bytes(secp::scalar_to_be_min(&st.phi_i)),
                shat: B64Bytes(secp::scalar_to_be_min(&st.shat_i)),
            };
            m.insert(self_key.clone(), r4_digest(&me, &own));
            m
        };
        let mut all = vec![me.clone()];
        all.extend(others.iter().cloned());
        if let Err(e) = verify_echoes(
            &my_digests,
            &self_key,
            others,
            &echoes,
            &all,
            ECHO_SOURCE_SIGN,
        ) {
            return self.deliver(Err(e));
        }

        // φ = Σ φ_i, ŝ = Σ ŝ_i.
        let mut phi = st.phi_i.clone();
        let mut shat = st.shat_i.clone();
        for pid in others {
            let m = &st.r4msgs[&peer_key_str(pid)];
            phi = phi.add(&secp::scalar_from_be_reduce(&m.phi.0));
            shat = shat.add(&secp::scalar_from_be_reduce(&m.shat.0));
        }
        if bool::from(phi.is_zero()) {
            return self.deliver(Err(Error::Validation(
                "φ aggregated to 0; retry signing".into(),
            )));
        }
        let mut s = shat.mul(&phi.invert());
        if bool::from(s.is_zero()) {
            return self.deliver(Err(Error::Validation("s = 0; retry signing".into())));
        }

        // Reconstruct R for the recovery bit, then low-S normalize.
        let mut r_point = st.big_k_i;
        for pid in &self.other_subset {
            r_point = r_point.add(&st.peer_k[&peer_key_str(pid)]);
        }
        let r = st.r.clone();
        drop(st);

        let (_, ry) = secp::affine_be(&r_point);
        let mut v = ry.last().copied().unwrap_or(0) & 1;
        if is_high_s(&s) {
            s = s.negate();
            v ^= 1;
        }

        // Final gate: verify under the (possibly tweaked) public key.
        let e = hash_to_scalar(&self.hash);
        let verify_pub = match &self.tweak {
            Some(tw) => self.key.ecdsa_pub.add(&secp::mul_base(tw)),
            None => self.key.ecdsa_pub,
        };
        if !ecdsa_verify(&verify_pub, &e, &r, &s) {
            return self.deliver(Err(Error::Validation(
                "aggregated signature failed ECDSA verification".into(),
            )));
        }

        self.deliver(Ok(Signature {
            r: pad32(&secp::scalar_to_be_min(&r)),
            s: pad32(&secp::scalar_to_be_min(&s)),
            v,
        }));
    }

    fn index_in_full_committee(&self, p: &PartyId) -> Option<usize> {
        self.key
            .party_ids
            .iter()
            .position(|q| q.cmp_key(p) == std::cmp::Ordering::Equal)
    }

    fn broadcast<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        let msg = json_wrap(typ, body, Some(self.params.party_id().clone()), None)?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
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

fn echo_fail(cause: String, culprit: &PartyId) -> Error {
    Error::Tss(Box::new(crate::tss::TssError::new(
        cause,
        ECHO_SOURCE_SIGN,
        0,
        None,
        vec![culprit.clone()],
    )))
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct SignR1 {
    #[serde(rename = "k_i_x")]
    k_i_x: B64Bytes,
    #[serde(rename = "k_i_y")]
    k_i_y: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct SignR2 {
    #[serde(rename = "alice_k")]
    alice_k: EncExtendMsg,
    #[serde(rename = "alice_x")]
    alice_x: EncExtendMsg,
}

#[derive(Clone, Serialize, Deserialize)]
struct SignR3 {
    #[serde(rename = "bob_k")]
    bob_k: Vec<B64Bytes>,
    #[serde(rename = "bob_x")]
    bob_x: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SignR4 {
    #[serde(rename = "phi")]
    phi: B64Bytes,
    #[serde(rename = "shat")]
    shat: B64Bytes,
}

/// Wire form of [`ExtendMsg1`].
#[derive(Clone, Serialize, Deserialize)]
struct EncExtendMsg {
    #[serde(rename = "l")]
    l: usize,
    #[serde(rename = "u")]
    u: Vec<B64Bytes>,
    #[serde(rename = "x_check")]
    x_check: B64Bytes,
    #[serde(rename = "t_check")]
    t_check: Vec<B64Bytes>,
}

impl EncExtendMsg {
    fn from_msg(m: &ExtendMsg1) -> Self {
        EncExtendMsg {
            l: m.l,
            u: m.u.iter().map(|r| B64Bytes(r.clone())).collect(),
            x_check: B64Bytes(m.x.to_vec()),
            t_check: m.t.iter().map(|r| B64Bytes(r.to_vec())).collect(),
        }
    }

    fn to_msg(&self) -> Result<ExtendMsg1, Error> {
        if self.x_check.0.len() != otext::SIGMA / 8 {
            return Err(Error::Validation("otext: X length mismatch".into()));
        }
        if self.t_check.len() != otext::SIGMA {
            return Err(Error::Validation("otext: T length mismatch".into()));
        }
        let mut x = [0u8; otext::SIGMA / 8];
        x.copy_from_slice(&self.x_check.0);
        let mut t = Vec::with_capacity(otext::SIGMA);
        for row in &self.t_check {
            if row.0.len() != otext::DELTA_BYTES {
                return Err(Error::Validation("otext: T row length mismatch".into()));
            }
            let mut r = [0u8; otext::DELTA_BYTES];
            r.copy_from_slice(&row.0);
            t.push(r);
        }
        Ok(ExtendMsg1 {
            l: self.l,
            u: self.u.iter().map(|r| r.0.clone()).collect(),
            x,
            t,
        })
    }
}

fn encode_bob(b: &ole::BobMsg) -> Vec<B64Bytes> {
    b.corrections
        .iter()
        .map(|c| B64Bytes(secp::scalar_to_be_min(c)))
        .collect()
}

fn decode_bob(in_: &[B64Bytes]) -> Result<ole::BobMsg, Error> {
    Ok(ole::BobMsg {
        corrections: in_
            .iter()
            .map(|b| secp::scalar_from_be_reduce(&b.0))
            .collect(),
    })
}

// --- helpers ---------------------------------------------------------------

/// Session id binding the protocol tag, joint public key, message, and the
/// sorted signing subset.
fn sign_session(key: &Key, hash: &[u8], subset: &[PartyId]) -> Vec<u8> {
    let (px, py) = secp::affine_be(&key.ecdsa_pub);
    let mut data = b"DKLS23-sign-party-v1-".to_vec();
    data.extend_from_slice(&px);
    data.extend_from_slice(&py);
    data.extend_from_slice(hash);
    for p in subset {
        data.extend_from_slice(strip(&p.key));
        data.push(0);
    }
    sha256(&data).to_vec()
}

/// Per-ΠMul session id: `SHA256(ssid || '|' || kind || '|' || alice || '|' ||
/// bob)` over big-endian-minimal party keys.
fn sign_mul_sid(ssid: &[u8], kind: &str, alice: &[u8], bob: &[u8]) -> Vec<u8> {
    let mut data = ssid.to_vec();
    data.push(b'|');
    data.extend_from_slice(kind.as_bytes());
    data.push(b'|');
    data.extend_from_slice(strip(alice));
    data.push(b'|');
    data.extend_from_slice(strip(bob));
    sha256(&data).to_vec()
}

/// Folds every signer's freshly-sampled `K_i` into the effective ssid so the
/// per-call ΠMul sids vary per signing (preventing OT-extension seed reuse).
/// Sorts by party key so every honest party derives the same value.
fn mix_round_one_ssid(
    base: &[u8],
    self_id: &PartyId,
    self_k: &ProjectivePoint,
    peer_ids: &[PartyId],
    peer_k: &HashMap<String, ProjectivePoint>,
) -> Vec<u8> {
    let mut all: Vec<(Vec<u8>, ProjectivePoint)> = vec![(strip(&self_id.key).to_vec(), *self_k)];
    for pid in peer_ids {
        if let Some(k) = peer_k.get(&peer_key_str(pid)) {
            all.push((strip(&pid.key).to_vec(), *k));
        }
    }
    all.sort_by(|a, b| {
        a.0.len()
            .cmp(&b.0.len())
            .then_with(|| a.0.as_slice().cmp(b.0.as_slice()))
    });
    let mut data = b"DKLS23-sign-ssid-mix-v1".to_vec();
    data.push(b'|');
    data.extend_from_slice(base);
    for (id, k) in &all {
        let (kx, ky) = secp::affine_be(k);
        data.push(b'|');
        data.extend_from_slice(id);
        data.push(b'|');
        data.extend_from_slice(&kx);
        data.push(b'|');
        data.extend_from_slice(&ky);
    }
    sha256(&data).to_vec()
}

/// Echo digest of a party's `K_i = k_i·G` commitment.
fn ki_digest(dealer: &PartyId, k: &ProjectivePoint) -> Vec<u8> {
    let (x, y) = secp::affine_be(k);
    commit_digest(ECHO_TAG_SIGN, dealer, &[x, y])
}

/// Echo digest of a party's round-4 `(φ, ŝ)` partial-signature reveal.
fn r4_digest(dealer: &PartyId, r4: &SignR4) -> Vec<u8> {
    commit_digest(
        ECHO_TAG_SIGN_R4,
        dealer,
        &[r4.phi.0.clone(), r4.shat.0.clone()],
    )
}

fn pad32(be: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[32 - be.len()..].copy_from_slice(be);
    out
}

/// Rejects a subset that is not strictly increasing by party key.
fn validate_sorted_subset(subset: &[PartyId]) -> Result<(), Error> {
    for w in subset.windows(2) {
        if w[0].cmp_key(&w[1]) != std::cmp::Ordering::Less {
            return Err(Error::Validation(
                "signing subset must be sorted and distinct by key".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::keygen_party::KeygenParty;
    use super::*;
    use crate::tss::testhub::TestHub;

    fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    fn run_keygen(ids: &[PartyId], t: usize) -> Vec<Key> {
        let hub = TestHub::new(ids);
        let parties: Vec<KeygenParty> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                KeygenParty::new(params).unwrap()
            })
            .collect();
        parties.iter().map(|p| p.wait().unwrap()).collect()
    }

    /// Runs broker-driven signing over the subset `pick` (full-committee
    /// indices) and returns the signatures from each signer.
    fn run_signing(keys: &[Key], pick: &[usize], hash: &[u8]) -> Vec<Signature> {
        let subset: Vec<PartyId> = pick
            .iter()
            .map(|&i| keys[i].party_ids[keys[i].idx].clone())
            .collect();
        let subset = PartyId::sort(subset, 0);
        let hub = TestHub::new(&subset);
        let signers: Vec<SigningParty> = subset
            .iter()
            .enumerate()
            .map(|(pos, sid)| {
                // Find the key whose own id matches this subset slot.
                let key = keys
                    .iter()
                    .find(|k| k.party_ids[k.idx].cmp_key(sid) == std::cmp::Ordering::Equal)
                    .unwrap()
                    .clone();
                let params = Parameters::new(subset.clone(), sid, keys[0].t, hub.broker(pos));
                SigningParty::new(params, key, hash.to_vec(), subset.clone(), None).unwrap()
            })
            .collect();
        signers.iter().map(|s| s.wait().unwrap()).collect()
    }

    #[test]
    fn broker_keygen_sign_verify_2_of_3() {
        let ids = party_ids(3);
        let keys = run_keygen(&ids, 1);
        let hash = purecrypto::hash::sha256(b"broker sign");
        let sigs = run_signing(&keys, &[0, 2], &hash);

        let e = hash_to_scalar(&hash);
        for sig in &sigs {
            let r = secp::scalar_from_be_reduce(&sig.r);
            let s = secp::scalar_from_be_reduce(&sig.s);
            assert!(ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
            assert!(!is_high_s(&s));
        }
        // All signers agree on (r, s).
        for sig in &sigs[1..] {
            assert_eq!(sig.r, sigs[0].r);
            assert_eq!(sig.s, sigs[0].s);
        }
    }
}
