//! Broker-driven, opt-in **Mul-then-check** DKLs23 threshold-ECDSA signing.
//!
//! The malicious-secure analog of [`super::signing_party::SigningParty`]: it
//! runs the same three-round DKLs23 signing flow but invokes the
//! Mul-then-check primitives in [`super::ole_check`] so that a malicious peer
//! who uses inconsistent `β` across the two parallel ΠMul instances is caught
//! with **identifiable abort** — the offending peer is named in
//! [`crate::tss::TssError::culprits`]. Port of tss-lib
//! `dklstss.CheckedSigningParty` (`signing_checked_party.go`).
//!
//! Cost is roughly 2× the wire traffic and CPU of [`SigningParty`] (two
//! parallel ΠMul flows per pair instead of one).
//!
//! Wire-level differences from the default path:
//!   - Round 2 (Alice envelope): two extension messages per ΠMul kind, one per
//!     parallel instance (sub-sid `|1` and `|2`).
//!   - Round 3 (Bob response): per kind, two correction slices plus Bob's
//!     cross-run consistency value `Z = u_B1 − u_B2`.
//!   - Round 4 (Alice second step): verifies `Z_A + Z == 0 (mod n)`; on failure
//!     aborts with the offending Bob in `culprits`.
//!
//! The `K_i` echo-broadcast equivocation defense and the round-4 `(φ, ŝ)` echo
//! cross-check from the default party are replicated here. The default
//! [`SigningParty`] and its wire format are left untouched.
//!
//! [`SigningParty`]: super::signing_party::SigningParty

use super::echo::{EchoMsg, commit_digest, other_parties, peer_key_str, point_from_be_xy, strip};
use super::key::{Key, Signature};
use super::ole_check::{self, CheckedAliceState, CheckedBobMsg};
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

const TYPE_R1: &str = "dkls:csign:r1";
const TYPE_R1ECHO: &str = "dkls:csign:r1echo";
const TYPE_R2: &str = "dkls:csign:r2";
const TYPE_R3: &str = "dkls:csign:r3";
const TYPE_R4: &str = "dkls:csign:r4";
const TYPE_R4ECHO: &str = "dkls:csign:r4echo";

// Echo digest tags: Go's CheckedSigningParty reuses the unchecked sign-phase
// digest helpers (kIDigest/r4Digest in signing_party.go), so these MUST be the
// `-sign-` tags, not `-csign-`, for cross-implementation checked signing to
// agree on echo digests. The message-type strings and echo-source string below
// are independently `csign` to match Go's checkedSign* / echoSourceCheckedSign.
const ECHO_TAG_SIGN: &str = "DKLS23-echo-sign-v1";
const ECHO_TAG_SIGN_R4: &str = "DKLS23-echo-sign-r4-v1";
const ECHO_SOURCE_SIGN: &str = "dklstss-csign";

/// A running opt-in Mul-then-check DKLs23 signing session. Construct with
/// [`CheckedSigningParty::new`]; retrieve the [`Signature`] with
/// [`CheckedSigningParty::wait`].
pub struct CheckedSigningParty {
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
    // Alice-side state: per peer × per ΠMul-kind. The checked variant holds a
    // `CheckedAliceState` (two parallel runs) rather than a plain `AliceState`.
    alice_k: HashMap<String, CheckedAliceState>,
    alice_x: HashMap<String, CheckedAliceState>,
    peer_k: HashMap<String, ProjectivePoint>,
    k_rho_mine: Scalar,
    x_rho_mine: Scalar,
    phi_i: Scalar,
    shat_i: Scalar,
    r4msgs: HashMap<String, SignR4>,
}

impl CheckedSigningParty {
    /// Starts broker-driven Mul-then-check signing for this party. Same input
    /// contract as [`super::signing_party::SigningParty::new`]: `subset` is the
    /// sorted `T+1` committee including this party; `tweak` is the optional
    /// HD-derived additive tweak (absorbed by the first signer).
    pub fn new(
        params: Parameters,
        key: Key,
        hash: Vec<u8>,
        subset: Vec<PartyId>,
        tweak: Option<Scalar>,
    ) -> Result<CheckedSigningParty, Error> {
        if hash.is_empty() {
            return Err(Error::Validation("NewCheckedSigning empty hash".into()));
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
        Ok(CheckedSigningParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until signing completes, returning the signature or an error.
    /// On a caught β-inconsistency the error is a [`Error::Tss`] whose
    /// `culprits` names the deviating peer.
    pub fn wait(&self) -> Result<Signature, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "checked signing session dropped without result".into(),
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

        // For each peer, play Alice in two CHECKED ΠMul instances:
        // (k_i, ρ_j) and (sx_i, ρ_j). Each launches two parallel runs.
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
            let sid_k = sign_mul_sid(&ssid, "checked-kxrho", &me.key, &pj.key);
            let sid_x = sign_mul_sid(&ssid, "checked-xxrho", &me.key, &pj.key);

            let (msg_k1, msg_k2, st_k) =
                match ole_check::checked_alice_step1(&sid_k, alice_pair, &k_i) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e)),
                };
            let (msg_x1, msg_x2, st_x) =
                match ole_check::checked_alice_step1(&sid_x, alice_pair, &self.sx_mine) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e)),
                };
            {
                let mut st = self.state.lock().unwrap();
                st.alice_k.insert(peer_key_str(pj), st_k);
                st.alice_x.insert(peer_key_str(pj), st_x);
            }
            let r2 = CheckedSignR2 {
                alice_k1: EncExtendMsg::from_msg(&msg_k1),
                alice_k2: EncExtendMsg::from_msg(&msg_k2),
                alice_x1: EncExtendMsg::from_msg(&msg_x1),
                alice_x2: EncExtendMsg::from_msg(&msg_x2),
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
        let r2s: Vec<CheckedSignR2> = match msgs.iter().map(json_get).collect() {
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
            let ext_k1 = match r2.alice_k1.to_msg() {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e)),
            };
            let ext_k2 = match r2.alice_k2.to_msg() {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e)),
            };
            let ext_x1 = match r2.alice_x1.to_msg() {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e)),
            };
            let ext_x2 = match r2.alice_x2.to_msg() {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e)),
            };
            let (ssid, rho_i) = {
                let st = self.state.lock().unwrap();
                (st.ssid.clone(), st.rho_i.clone())
            };
            // peer is Alice, self is Bob.
            let sid_k = sign_mul_sid(&ssid, "checked-kxrho", &pid.key, &me.key);
            let sid_x = sign_mul_sid(&ssid, "checked-xxrho", &pid.key, &me.key);

            let (bmsg_k, u_bk) =
                match ole_check::checked_bob_step1(&sid_k, bob_pair, &rho_i, &ext_k1, &ext_k2) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e)),
                };
            let (bmsg_x, u_bx) =
                match ole_check::checked_bob_step1(&sid_x, bob_pair, &rho_i, &ext_x1, &ext_x2) {
                    Ok(v) => v,
                    Err(e) => return self.deliver(Err(e)),
                };
            {
                let mut st = self.state.lock().unwrap();
                st.k_rho_mine = st.k_rho_mine.add(&u_bk);
                st.x_rho_mine = st.x_rho_mine.add(&u_bx);
            }
            let r3 = CheckedSignR3 {
                bob_k1: encode_bob(&bmsg_k.msg1),
                bob_k2: encode_bob(&bmsg_k.msg2),
                bob_kz: B64Bytes(secp::scalar_to_be_min(&bmsg_k.z)),
                bob_x1: encode_bob(&bmsg_x.msg1),
                bob_x2: encode_bob(&bmsg_x.msg2),
                bob_xz: B64Bytes(secp::scalar_to_be_min(&bmsg_x.z)),
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
        let r3s: Vec<CheckedSignR3> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        for (pid, r3) in others.iter().zip(r3s.iter()) {
            let bob_k1 = match decode_bob(&r3.bob_k1) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let bob_k2 = match decode_bob(&r3.bob_k2) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let bob_x1 = match decode_bob(&r3.bob_x1) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let bob_x2 = match decode_bob(&r3.bob_x2) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            // Range-check Z: must be a canonical (< n) encoding, mirroring Go's
            // explicit `Z >= q` rejection (scalar_from_be_reduce would silently
            // reduce otherwise).
            let z_k = match scalar_canonical(&r3.bob_kz.0) {
                Some(z) => z,
                None => {
                    return self.deliver(Err(echo_fail(
                        format!("party {pid} sent non-canonical Z (>= n)"),
                        pid,
                    )));
                }
            };
            let z_x = match scalar_canonical(&r3.bob_xz.0) {
                Some(z) => z,
                None => {
                    return self.deliver(Err(echo_fail(
                        format!("party {pid} sent non-canonical Z (>= n)"),
                        pid,
                    )));
                }
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
                let bmsg_k = CheckedBobMsg {
                    msg1: bob_k1,
                    msg2: bob_k2,
                    z: z_k,
                };
                let bmsg_x = CheckedBobMsg {
                    msg1: bob_x1,
                    msg2: bob_x2,
                    z: z_x,
                };
                // Mul-then-check failure → attribute to this Bob (identifiable
                // abort), matching Go's tss.Error culprit attribution.
                let u_ak = match ole_check::checked_alice_step2(st_k, &bmsg_k) {
                    Ok(v) => v,
                    Err(e) => {
                        return self.deliver(Err(mulcheck_fail(
                            format!("Mul-then-check failed for k·ρ with {pid}: {e}"),
                            pid,
                        )));
                    }
                };
                let u_ax = match ole_check::checked_alice_step2(st_x, &bmsg_x) {
                    Ok(v) => v,
                    Err(e) => {
                        return self.deliver(Err(mulcheck_fail(
                            format!("Mul-then-check failed for sx·ρ with {pid}: {e}"),
                            pid,
                        )));
                    }
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

        // Cross-check every signer's (φ, ŝ) reveal for equivocation.
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

/// Wraps a Mul-then-check rejection as a `tss` error naming the deviating Bob —
/// the identifiable-abort attribution that is the whole point of this path.
fn mulcheck_fail(cause: String, culprit: &PartyId) -> Error {
    Error::Tss(Box::new(crate::tss::TssError::new(
        cause,
        ECHO_SOURCE_SIGN,
        0,
        None,
        vec![culprit.clone()],
    )))
}

/// Returns `Some(scalar)` iff `be` is already a canonical (< n) big-endian
/// encoding; `None` if reducing mod n would change it. Mirrors Go's explicit
/// `Z >= q` rejection of a non-canonical consistency value.
fn scalar_canonical(be: &[u8]) -> Option<Scalar> {
    let s = secp::scalar_from_be_reduce(be);
    if secp::scalar_to_be_min(&s) == strip(be) {
        Some(s)
    } else {
        None
    }
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
struct CheckedSignR2 {
    #[serde(rename = "alice_k1")]
    alice_k1: EncExtendMsg,
    #[serde(rename = "alice_k2")]
    alice_k2: EncExtendMsg,
    #[serde(rename = "alice_x1")]
    alice_x1: EncExtendMsg,
    #[serde(rename = "alice_x2")]
    alice_x2: EncExtendMsg,
}

#[derive(Clone, Serialize, Deserialize)]
struct CheckedSignR3 {
    #[serde(rename = "bob_k1")]
    bob_k1: Vec<B64Bytes>,
    #[serde(rename = "bob_k2")]
    bob_k2: Vec<B64Bytes>,
    #[serde(rename = "bob_kz")]
    bob_kz: B64Bytes,
    #[serde(rename = "bob_x1")]
    bob_x1: Vec<B64Bytes>,
    #[serde(rename = "bob_x2")]
    bob_x2: Vec<B64Bytes>,
    #[serde(rename = "bob_xz")]
    bob_xz: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct SignR4 {
    #[serde(rename = "phi")]
    phi: B64Bytes,
    #[serde(rename = "shat")]
    shat: B64Bytes,
}

/// Wire form of [`ExtendMsg1`]. Replicated from the default party so that file
/// stays byte-untouched.
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

fn encode_bob(b: &super::ole::BobMsg) -> Vec<B64Bytes> {
    b.corrections
        .iter()
        .map(|c| B64Bytes(secp::scalar_to_be_min(c)))
        .collect()
}

fn decode_bob(in_: &[B64Bytes]) -> Result<super::ole::BobMsg, Error> {
    Ok(super::ole::BobMsg {
        corrections: in_
            .iter()
            .map(|b| secp::scalar_from_be_reduce(&b.0))
            .collect(),
    })
}

// --- helpers (replicated from signing_party to leave that file untouched) ---

/// Session id binding the protocol tag, joint public key, message, and the
/// sorted signing subset. Distinct domain tag from the default party so checked
/// and unchecked sessions never share an ssid.
fn sign_session(key: &Key, hash: &[u8], subset: &[PartyId]) -> Vec<u8> {
    let (px, py) = secp::affine_be(&key.ecdsa_pub);
    let mut data = b"DKLS23-csign-party-v1-".to_vec();
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

/// Folds every signer's freshly-sampled `K_i` into the effective ssid.
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
    let mut data = b"DKLS23-csign-ssid-mix-v1".to_vec();
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

fn ki_digest(dealer: &PartyId, k: &ProjectivePoint) -> Vec<u8> {
    let (x, y) = secp::affine_be(k);
    commit_digest(ECHO_TAG_SIGN, dealer, &[x, y])
}

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
    use crate::tss::{BrokerResult, MessageBroker, MessageReceiver};
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

    fn key_for<'a>(keys: &'a [Key], sid: &PartyId) -> &'a Key {
        keys.iter()
            .find(|k| k.party_ids[k.idx].cmp_key(sid) == std::cmp::Ordering::Equal)
            .unwrap()
    }

    /// Positive: the broker-driven checked path produces a valid ECDSA
    /// signature when all parties behave, and all signers agree on (r, s).
    #[test]
    fn broker_checked_sign_verify_2_of_3() {
        let ids = party_ids(3);
        let keys = run_keygen(&ids, 1);
        let hash = sha256(b"checked broker sign").to_vec();

        let subset: Vec<PartyId> = vec![
            keys[0].party_ids[keys[0].idx].clone(),
            keys[2].party_ids[keys[2].idx].clone(),
        ];
        let subset = PartyId::sort(subset, 0);
        let hub = TestHub::new(&subset);
        let parties: Vec<CheckedSigningParty> = subset
            .iter()
            .enumerate()
            .map(|(pos, sid)| {
                let key = key_for(&keys, sid).clone();
                let params = Parameters::new(subset.clone(), sid, keys[0].t, hub.broker(pos));
                CheckedSigningParty::new(params, key, hash.clone(), subset.clone(), None).unwrap()
            })
            .collect();
        let sigs: Vec<Signature> = parties.iter().map(|p| p.wait().unwrap()).collect();

        let e = hash_to_scalar(&hash);
        for sig in &sigs {
            let r = secp::scalar_from_be_reduce(&sig.r);
            let s = secp::scalar_from_be_reduce(&sig.s);
            assert!(ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
            assert!(!is_high_s(&s));
        }
        for sig in &sigs[1..] {
            assert_eq!(sig.r, sigs[0].r);
            assert_eq!(sig.s, sigs[0].s);
        }
    }

    /// Broker that tampers with EVERY checked-R3 message it relays from a chosen
    /// Bob: it flips the low bit of Bob's `bob_kz` (the cross-run consistency
    /// value Z). This simulates "Bob used inconsistent β across the two parallel
    /// ΠMul runs" — each receiving Alice's `checked_alice_step2` must then
    /// reject with identifiable abort naming the tampered Bob.
    ///
    /// We tamper every R3 (not just the first) so that *all* of Bob's Alices
    /// abort: under the synchronous test hub, a party whose result is never
    /// delivered would block `wait()` forever, so we ensure every honest peer
    /// reaches a terminal (aborted) state.
    struct BetaTamperingBroker {
        inner: Arc<dyn MessageBroker + Send + Sync>,
        bob: PartyId,
    }

    impl MessageReceiver for BetaTamperingBroker {
        fn receive(&self, msg: &JsonMessage) -> BrokerResult {
            if msg.typ == TYPE_R3
                && msg
                    .from
                    .as_ref()
                    .map(|f| f.cmp_key(&self.bob) == std::cmp::Ordering::Equal)
                    .unwrap_or(false)
            {
                if let Ok(mut r3) = json_get::<CheckedSignR3>(msg) {
                    if let Some(last) = r3.bob_kz.0.last_mut() {
                        *last ^= 0x01;
                        let rewritten =
                            json_wrap(&msg.typ, &r3, msg.from.clone(), msg.to.clone())?;
                        return self.inner.receive(&rewritten);
                    }
                }
            }
            self.inner.receive(msg)
        }
    }

    impl MessageBroker for BetaTamperingBroker {
        fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
            self.inner.connect(typ, dest);
        }
    }

    /// Negative end-to-end: a malicious Bob whose Z value is corrupted (β
    /// inconsistency) is caught with identifiable abort — at least one honest
    /// peer surfaces a `tss` error naming the tampered Bob in `culprits`.
    /// The default unchecked path carries no such consistency value and would
    /// not catch this.
    #[test]
    fn broker_checked_catches_beta_inconsistency() {
        let ids = party_ids(4);
        let keys = run_keygen(&ids, 2);
        let hash = sha256(b"checked beta tampering").to_vec();

        let subset: Vec<PartyId> = vec![
            keys[0].party_ids[keys[0].idx].clone(),
            keys[1].party_ids[keys[1].idx].clone(),
            keys[2].party_ids[keys[2].idx].clone(),
        ];
        let subset = PartyId::sort(subset, 0);
        let bob = subset[0].clone();
        let hub = TestHub::new(&subset);

        let parties: Vec<CheckedSigningParty> = subset
            .iter()
            .enumerate()
            .map(|(pos, sid)| {
                let key = key_for(&keys, sid).clone();
                let broker: Arc<dyn MessageBroker + Send + Sync> = if pos == 0 {
                    Arc::new(BetaTamperingBroker {
                        inner: hub.broker(pos),
                        bob: bob.clone(),
                    })
                } else {
                    hub.broker(pos)
                };
                let params = Parameters::new(subset.clone(), sid, keys[0].t, broker);
                CheckedSigningParty::new(params, key, hash.clone(), subset.clone(), None).unwrap()
            })
            .collect();

        // At least one honest peer (positions 1,2 — the Alices for the tampered
        // Bob at position 0) must abort with the tampered Bob in culprits.
        let mut saw_attribution = false;
        for (pos, p) in parties.iter().enumerate() {
            if pos == 0 {
                continue;
            }
            if let Err(Error::Tss(e)) = p.wait() {
                if e.culprits()
                    .iter()
                    .any(|c| c.cmp_key(&bob) == std::cmp::Ordering::Equal)
                {
                    saw_attribution = true;
                }
            }
        }
        assert!(
            saw_attribution,
            "checked signing must attribute β-inconsistency to the tampered Bob"
        );
    }
}
