//! Broker-driven DKLs23 resharing / refresh.
//!
//! The distributed counterpart to the synchronous [`reshare`](super::reshare).
//! OLD-committee participants re-share their Lagrange-scaled secret to the NEW
//! committee via Feldman VSS; NEW members verify, aggregate their fresh share,
//! cross-check the OLD commitments with an echo phase, then set up fresh
//! pairwise OT among themselves (the keygen round-1/2 dance). The reconstructed
//! public key is checked against the advertised `old_ecdsa_pub` — the security
//! hinge that stops a malicious OLD party rotating the key. Wire-compatible with
//! Go `dklstss` resharing.
//!
//! Disjoint and overlapping committees are supported; a hybrid OLD+NEW party
//! excludes its own commitments from the echo cross-check (it trusts its own
//! canonical view). Result: NEW members receive the fresh [`Key`]; OLD-only
//! members receive `None`.

use super::baseot;
use super::echo::{
    EchoMsg, commit_digest, flatten_point_xy, pair_base_sid, peer_key_str, point_from_be_xy, strip,
    unflatten_point_xy, verify_echoes,
};
use super::key::{Key, PairOTState};
use super::keygen::derive_chain_code;
use super::otext::{self, ExtReceiver, ExtSender};
use super::schnorr::ZkProof;
use super::secp::{self, ProjectivePoint, Scalar};
use super::signing::lagrange_coefficient;
use super::vss;
use super::{Error, echo::other_parties};
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, PartyId, ReSharingParameters, json_get, json_wrap};
use purecrypto::hash::sha256;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1BC: &str = "dkls:reshare:r1bc";
const TYPE_R1UC: &str = "dkls:reshare:r1uc";
const TYPE_ECHO: &str = "dkls:reshare:echo";
const TYPE_R2: &str = "dkls:reshare:r2";
const TYPE_R3: &str = "dkls:reshare:r3";
const ECHO_TAG: &str = "DKLS23-echo-reshare-v1";
const ECHO_SOURCE: &str = "dklstss-reshare";

type ReshareResult = Result<Option<Key>, Error>;

/// A running DKLs23 resharing session. Construct with [`ResharingParty::new`];
/// retrieve the result with [`ResharingParty::wait`] (NEW members get
/// `Some(Key)`, OLD-only members get `None`).
pub struct ResharingParty {
    result_rx: MpscReceiver<ReshareResult>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: ReSharingParameters,
    old_ecdsa_pub: ProjectivePoint,
    is_old: bool,
    is_new: bool,
    old_key: Option<Key>,
    my_new_idx: Option<usize>,
    old_lambda: Option<Scalar>,
    ssid: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<ReshareResult>>>,
}

struct State {
    own_vs: Vec<ProjectivePoint>,
    r1_bcasts: Vec<ReshareR1Bcast>,
    r1_unicasts: Vec<ReshareR1Unicast>,
    r1_join: u8,
    received_shares: HashMap<String, Scalar>,
    received_commits: HashMap<String, Vec<ProjectivePoint>>,
    new_ot_snd: HashMap<String, baseot::Sender>,
    new_ot_rcv: HashMap<String, baseot::Receiver>,
    my_delta: HashMap<String, Vec<u8>>,
    new_xi: Scalar,
}

impl ResharingParty {
    /// Starts resharing for this party. `old_ecdsa_pub` is the public key being
    /// resharded (every party must supply it); `old_key` is required iff this
    /// party is in the old committee.
    pub fn new(
        params: ReSharingParameters,
        old_ecdsa_pub: ProjectivePoint,
        old_key: Option<Key>,
    ) -> Result<ResharingParty, Error> {
        let is_old = params.is_old_committee();
        let is_new = params.is_new_committee();
        if !is_old && !is_new {
            return Err(Error::Validation("self is in neither committee".into()));
        }
        if is_old && old_key.is_none() {
            return Err(Error::Validation("old_key required for OLD role".into()));
        }
        if let Some(k) = &old_key {
            k.validate_basic()?;
            if params.old_parties().len() < k.t + 1 {
                return Err(Error::Validation(format!(
                    "old subset size {} < T+1={}",
                    params.old_parties().len(),
                    k.t + 1
                )));
            }
            if !secp::point_eq(&old_ecdsa_pub, &k.ecdsa_pub) {
                return Err(Error::Validation(
                    "old_ecdsa_pub does not match old_key.ecdsa_pub".into(),
                ));
            }
        }
        let new_t = params.new_threshold();
        if is_new && (new_t < 1 || new_t >= params.new_parties().len()) {
            return Err(Error::Validation(format!("invalid new threshold {new_t}")));
        }

        let my_new_idx = params
            .new_parties()
            .iter()
            .position(|p| p.cmp_key(params.party_id()) == std::cmp::Ordering::Equal);

        // OLD role: Lagrange coefficient over the active old subset.
        let old_lambda = if is_old {
            let ids: Vec<Scalar> = params
                .old_parties()
                .iter()
                .map(|p| secp::scalar_from_be_reduce(&p.key))
                .collect();
            let my_old = params.old_index().expect("old member");
            Some(lagrange_coefficient(&ids, my_old)?)
        } else {
            None
        };

        let ssid = resharing_session(&params, &old_ecdsa_pub);
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            old_ecdsa_pub,
            is_old,
            is_new,
            old_key,
            my_new_idx,
            old_lambda,
            ssid,
            state: Mutex::new(State {
                own_vs: Vec::new(),
                r1_bcasts: Vec::new(),
                r1_unicasts: Vec::new(),
                r1_join: 0,
                received_shares: HashMap::new(),
                received_commits: HashMap::new(),
                new_ot_snd: HashMap::new(),
                new_ot_rcv: HashMap::new(),
                my_delta: HashMap::new(),
                new_xi: Scalar::ZERO,
            }),
            result_tx: Mutex::new(Some(tx)),
        });

        // NEW-side: register round-1 receivers first so nothing is dropped.
        if shared.is_new {
            shared.connect_r1();
        }
        // OLD-side: emit round 1.
        if shared.is_old {
            shared.old_round1()?;
        }
        Ok(ResharingParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until resharing completes. NEW members return `Some(Key)`;
    /// OLD-only members return `None`.
    pub fn wait(&self) -> ReshareResult {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("resharing dropped without result".into())),
        }
    }
}

impl Shared {
    fn deliver(&self, r: ReshareResult) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn connect_r1(self: &Arc<Self>) {
        let old_ids = self.params.old_parties().to_vec();
        let me_bc = Arc::clone(self);
        let exp_bc = JsonExpect::new(
            TYPE_R1BC,
            old_ids.clone(),
            Box::new(move |msgs| me_bc.on_r1bc(msgs)),
        );
        self.params.broker().connect(TYPE_R1BC, Arc::new(exp_bc));

        let me_uc = Arc::clone(self);
        let exp_uc = JsonExpect::new(
            TYPE_R1UC,
            old_ids,
            Box::new(move |msgs| me_uc.on_r1uc(msgs)),
        );
        self.params.broker().connect(TYPE_R1UC, Arc::new(exp_uc));
    }

    fn old_round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let key = self.old_key.as_ref().expect("OLD has key");
        let lambda = self.old_lambda.as_ref().expect("OLD has lambda");
        let new_t = self.params.new_threshold();

        let scaled = lambda.mul(&key.xi);
        if bool::from(scaled.is_zero()) {
            return Err(Error::Validation(
                "old λ·Xi ≡ 0 mod n (key material likely corrupted)".into(),
            ));
        }

        let new_ids: Vec<Scalar> = self
            .params
            .new_parties()
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();
        let (vs, shares) = vss::create(new_t, &scaled, &new_ids, &mut rng);
        {
            let mut st = self.state.lock().unwrap();
            st.own_vs = vs.clone();
        }

        let bcast = ReshareR1Bcast {
            vss_commitments: flatten_point_xy(&vs),
        };
        self.broadcast(TYPE_R1BC, &bcast)?;

        for (n, pj) in self.params.new_parties().iter().enumerate() {
            let uc = ReshareR1Unicast {
                share: B64Bytes(secp::scalar_to_be_min(&shares[n])),
            };
            self.send_to(TYPE_R1UC, &uc, pj)?;
        }

        if !self.is_new {
            self.deliver(Ok(None));
        }
        Ok(())
    }

    fn on_r1bc(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<ReshareR1Bcast>, Error> =
            msgs.iter().map(|m| Ok(json_get(m)?)).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r1_bcasts = d,
                Err(e) => return self.deliver(Err(e)),
            }
            st.r1_join += 1;
            st.r1_join == 2
        };
        if ready {
            self.start_echo();
        }
    }

    fn on_r1uc(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<ReshareR1Unicast>, Error> =
            msgs.iter().map(|m| Ok(json_get(m)?)).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r1_unicasts = d,
                Err(e) => return self.deliver(Err(e)),
            }
            st.r1_join += 1;
            st.r1_join == 2
        };
        if ready {
            self.start_echo();
        }
    }

    fn start_echo(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let self_key = peer_key_str(&me);
        let old_ids = self.params.old_parties().to_vec();

        let digests: HashMap<String, B64Bytes> = {
            let st = self.state.lock().unwrap();
            let mut d = HashMap::new();
            for (n, dealer) in old_ids.iter().enumerate() {
                let dk = peer_key_str(dealer);
                if dk == self_key {
                    continue; // hybrid: don't echo about my own commitments
                }
                let raw = vss_bytes(&st.r1_bcasts[n].vss_commitments);
                d.insert(dk, B64Bytes(commit_digest(ECHO_TAG, dealer, &raw)));
            }
            d
        };

        let new_others = other_parties(self.params.new_parties(), &me);
        if let Err(e) = self.broadcast(TYPE_ECHO, &EchoMsg { digests }) {
            return self.deliver(Err(e));
        }
        let me_arc = Arc::clone(self);
        let exp = JsonExpect::new(
            TYPE_ECHO,
            new_others,
            Box::new(move |msgs| me_arc.on_echo(msgs)),
        );
        self.params.broker().connect(TYPE_ECHO, Arc::new(exp));
    }

    fn on_echo(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let echoes: Vec<EchoMsg> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };
        let me = self.params.party_id().clone();
        let self_key = peer_key_str(&me);
        let old_ids = self.params.old_parties().to_vec();
        let new_others = other_parties(self.params.new_parties(), &me);

        let my_digests: HashMap<String, Vec<u8>> = {
            let st = self.state.lock().unwrap();
            let mut m = HashMap::new();
            for (n, dealer) in old_ids.iter().enumerate() {
                let dk = peer_key_str(dealer);
                if dk == self_key {
                    if !st.own_vs.is_empty() {
                        m.insert(
                            self_key.clone(),
                            commit_digest(ECHO_TAG, dealer, &flatten_to_bytes(&st.own_vs)),
                        );
                    }
                    continue;
                }
                let raw = vss_bytes(&st.r1_bcasts[n].vss_commitments);
                m.insert(dk, commit_digest(ECHO_TAG, dealer, &raw));
            }
            m
        };

        if let Err(e) = verify_echoes(
            &my_digests,
            &self_key,
            &new_others,
            &echoes,
            &old_ids,
            ECHO_SOURCE,
        ) {
            return self.deliver(Err(e));
        }
        self.after_round1();
    }

    fn after_round1(self: &Arc<Self>) {
        let mut rng = OsRng;
        let me = self.params.party_id().clone();
        let new_t = self.params.new_threshold();
        let my_id = secp::scalar_from_be_reduce(&me.key);
        let old_ids = self.params.old_parties().to_vec();

        let (bcasts, ucs) = {
            let st = self.state.lock().unwrap();
            (st.r1_bcasts.clone(), st.r1_unicasts.clone())
        };

        let mut new_xi = Scalar::ZERO;
        for (n, pid) in old_ids.iter().enumerate() {
            let bc = &bcasts[n];
            let uc = &ucs[n];
            if bc.vss_commitments.len() != 2 * (new_t + 1) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent {} Vs coords, expected {}",
                    bc.vss_commitments.len(),
                    2 * (new_t + 1)
                ))));
            }
            let vsj = match unflatten_point_xy(&bc.vss_commitments) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            if !is_canonical_scalar(&uc.share.0) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent non-canonical reshare-share (>= n)"
                ))));
            }
            let share = secp::scalar_from_be_reduce(&uc.share.0);
            if !vss::verify(&my_id, &share, new_t, &vsj) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} reshare-share verification failed"
                ))));
            }
            new_xi = new_xi.add(&share);
            let mut st = self.state.lock().unwrap();
            st.received_shares.insert(peer_key_str(pid), share);
            st.received_commits.insert(peer_key_str(pid), vsj);
        }
        self.state.lock().unwrap().new_xi = new_xi;

        // Kick off pairwise base-OT with the other NEW members.
        let new_others = other_parties(self.params.new_parties(), &me);
        for pj in &new_others {
            let sid = pair_base_sid(&self.ssid, &me.key, &pj.key, &pj.key);
            let (snd, smsg) = baseot::Sender::new(&sid, otext::KAPPA, &mut rng);
            self.state
                .lock()
                .unwrap()
                .new_ot_snd
                .insert(peer_key_str(pj), snd);

            let (sx, sy) = secp::affine_be(&smsg.s);
            let (ax, ay) = secp::affine_be(&smsg.pok.alpha);
            let r2 = ReshareR2 {
                ot_sender_s_x: B64Bytes(sx),
                ot_sender_s_y: B64Bytes(sy),
                ot_sender_pok_alpha_x: B64Bytes(ax),
                ot_sender_pok_alpha_y: B64Bytes(ay),
                ot_sender_pok_t: B64Bytes(secp::scalar_to_be_min(&smsg.pok.t)),
            };
            if let Err(e) = self.send_to(TYPE_R2, &r2, pj) {
                return self.deliver(Err(e));
            }
        }

        let me_arc = Arc::clone(self);
        let exp = JsonExpect::new(
            TYPE_R2,
            new_others.clone(),
            Box::new(move |msgs| me_arc.after_round2(&new_others, msgs)),
        );
        self.params.broker().connect(TYPE_R2, Arc::new(exp));
    }

    fn after_round2(self: &Arc<Self>, new_others: &[PartyId], msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let me = self.params.party_id().clone();
        let r2s: Vec<ReshareR2> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        for (pid, r2) in new_others.iter().zip(r2s.iter()) {
            let Some(s) = point_from_be_xy(&r2.ot_sender_s_x.0, &r2.ot_sender_s_y.0) else {
                return self.deliver(Err(Error::Validation(format!("party {pid} OT-S invalid"))));
            };
            let Some(alpha) =
                point_from_be_xy(&r2.ot_sender_pok_alpha_x.0, &r2.ot_sender_pok_alpha_y.0)
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} PoK alpha invalid"
                ))));
            };
            let pok = ZkProof {
                alpha,
                t: secp::scalar_from_be_reduce(&r2.ot_sender_pok_t.0),
            };
            let smsg = baseot::SenderMsg1 { s, pok };
            let sid = pair_base_sid(&self.ssid, &pid.key, &me.key, &me.key);
            let mut delta = vec![0u8; otext::DELTA_BYTES];
            rng.fill_bytes(&mut delta);
            let Some((rcvr, rmsg)) =
                baseot::Receiver::new(&sid, otext::KAPPA, &delta, &smsg, &mut rng)
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} base-OT receiver setup failed"
                ))));
            };
            {
                let mut st = self.state.lock().unwrap();
                st.new_ot_rcv.insert(peer_key_str(pid), rcvr);
                st.my_delta.insert(peer_key_str(pid), delta);
            }
            let r3 = ReshareR3 {
                ot_receiver_r: flatten_point_xy(&rmsg.r),
            };
            if let Err(e) = self.send_to(TYPE_R3, &r3, pid) {
                return self.deliver(Err(e));
            }
        }

        let me_arc = Arc::clone(self);
        let others = new_others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R3,
            new_others.to_vec(),
            Box::new(move |msgs| me_arc.finalize(&others, msgs)),
        );
        self.params.broker().connect(TYPE_R3, Arc::new(exp));
    }

    fn finalize(self: &Arc<Self>, new_others: &[PartyId], msgs: Vec<JsonMessage>) {
        let me = self.params.party_id().clone();
        let new_parties = self.params.new_parties().to_vec();
        let n = new_parties.len();
        let new_t = self.params.new_threshold();
        let my_new_idx = self.my_new_idx.expect("NEW has index");

        let r3s: Vec<ReshareR3> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        let st = self.state.lock().unwrap();

        // Reconstruct the public key from Σ V_old[0] and bind it to the
        // advertised old_ecdsa_pub (stops a malicious OLD party rotating it).
        let mut pub_acc: Option<ProjectivePoint> = None;
        for vs in st.received_commits.values() {
            pub_acc = Some(match pub_acc {
                None => vs[0],
                Some(a) => a.add(&vs[0]),
            });
        }
        match pub_acc {
            Some(p) if secp::point_eq(&p, &self.old_ecdsa_pub) => {}
            _ => {
                return self.deliver(Err(Error::Validation(
                    "reshare reconstructed public key does not match old_ecdsa_pub".into(),
                )));
            }
        }
        let pub_key = self.old_ecdsa_pub;

        // BigXj per new party = Σ_dealers eval(V_dealer, id_j).
        let all_commits: Vec<Vec<ProjectivePoint>> =
            st.received_commits.values().cloned().collect();
        let mut big_xj = vec![secp::generator(); n];
        for (pos, pj) in new_parties.iter().enumerate() {
            let id = secp::scalar_from_be_reduce(&pj.key);
            big_xj[pos] = vss::evaluate_commitment_sum(&all_commits, &id);
        }

        // Per-pair OT-extension state with each new peer.
        let mut ot: Vec<Option<PairOTState>> = (0..n).map(|_| None).collect();
        for pj in new_others {
            let k = peer_key_str(pj);
            let chosen = st.new_ot_rcv[&k].finalize();
            let ext_sender = match ExtSender::from_base(&st.my_delta[&k], &chosen) {
                Ok(e) => e,
                Err(e) => return self.deliver(Err(e)),
            };
            let idx = new_others
                .iter()
                .position(|p| p.cmp_key(pj) == std::cmp::Ordering::Equal)
                .expect("peer present");
            let peer_r = match unflatten_point_xy(&r3s[idx].ot_receiver_r) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let Some((k0, k1)) = st.new_ot_snd[&k].finalize(&baseot::ReceiverMsg1 { r: peer_r })
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "base-OT sender finalize for {pj} failed"
                ))));
            };
            let ext_receiver = match ExtReceiver::from_base(&k0, &k1) {
                Ok(e) => e,
                Err(e) => return self.deliver(Err(e)),
            };
            let pos = new_parties
                .iter()
                .position(|p| p.cmp_key(pj) == std::cmp::Ordering::Equal)
                .expect("peer in new committee");
            ot[pos] = Some(PairOTState {
                as_alice: ext_receiver,
                as_bob: ext_sender,
            });
        }

        let new_xi = st.new_xi.clone();
        drop(st);

        let chain_code = derive_chain_code(&pub_key);
        let key = Key {
            n,
            t: new_t,
            idx: my_new_idx,
            party_ids: new_parties,
            xi: new_xi,
            big_xj,
            ecdsa_pub: pub_key,
            ot,
            chain_code,
        };
        if let Err(e) = key.validate_basic() {
            return self.deliver(Err(e));
        }
        let _ = me;
        self.deliver(Ok(Some(key)));
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

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct ReshareR1Bcast {
    #[serde(rename = "vss_commitments")]
    vss_commitments: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ReshareR1Unicast {
    #[serde(rename = "share")]
    share: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct ReshareR2 {
    #[serde(rename = "ot_sender_s_x")]
    ot_sender_s_x: B64Bytes,
    #[serde(rename = "ot_sender_s_y")]
    ot_sender_s_y: B64Bytes,
    #[serde(rename = "ot_sender_pok_alpha_x")]
    ot_sender_pok_alpha_x: B64Bytes,
    #[serde(rename = "ot_sender_pok_alpha_y")]
    ot_sender_pok_alpha_y: B64Bytes,
    #[serde(rename = "ot_sender_pok_t")]
    ot_sender_pok_t: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct ReshareR3 {
    #[serde(rename = "ot_receiver_r")]
    ot_receiver_r: Vec<B64Bytes>,
}

// --- helpers ---------------------------------------------------------------

fn resharing_session(params: &ReSharingParameters, old_pub: &ProjectivePoint) -> Vec<u8> {
    let (px, py) = secp::affine_be(old_pub);
    let mut data = b"DKLS23-reshare-party-v2-".to_vec();
    data.extend_from_slice(&px);
    data.push(b'|');
    data.extend_from_slice(&py);
    data.push(b'|');
    for p in params.old_parties() {
        data.extend_from_slice(strip(&p.key));
        data.push(0);
    }
    data.push(b'|');
    for p in params.new_parties() {
        data.extend_from_slice(strip(&p.key));
        data.push(0);
    }
    data.extend_from_slice(&(params.new_threshold() as u32).to_be_bytes());
    sha256(&data).to_vec()
}

fn vss_bytes(flat: &[B64Bytes]) -> Vec<Vec<u8>> {
    flat.iter().map(|b| b.0.clone()).collect()
}

fn flatten_to_bytes(vs: &[ProjectivePoint]) -> Vec<Vec<u8>> {
    flatten_point_xy(vs).iter().map(|b| b.0.clone()).collect()
}

fn is_canonical_scalar(bytes: &[u8]) -> bool {
    let s = secp::scalar_from_be_reduce(bytes);
    secp::scalar_to_be_min(&s) == strip(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::keygen::keygen;
    use super::super::signing::{ecdsa_verify, hash_to_scalar};
    use super::*;
    use crate::tss::testhub::ReshareHub;
    use purecrypto::hash::sha256;
    use purecrypto::rng::OsRng;

    fn party_ids(vals: &[u8]) -> Vec<PartyId> {
        PartyId::sort(
            vals.iter()
                .map(|&i| PartyId::new(i.to_string(), format!("P{i}"), vec![i]))
                .collect(),
            0,
        )
    }

    #[test]
    fn reshare_1of3_to_2of5_preserves_key_and_signs() {
        let old_ids = party_ids(&[1, 2, 3]);
        let old_t = 1;
        let old_keys = keygen(old_ids.len(), old_t, &old_ids, &mut OsRng).unwrap();
        let group_pub = old_keys[0].ecdsa_pub;

        let new_ids = party_ids(&[11, 12, 13, 14, 15]);
        let new_t = 2;

        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        let hub = ReshareHub::new(&all);

        let mut sessions: Vec<ResharingParty> = Vec::new();
        for (i, p) in old_ids.iter().enumerate() {
            let params = ReSharingParameters::new(
                old_ids.clone(),
                new_ids.clone(),
                old_t,
                new_t,
                p.clone(),
                hub.broker(p),
            );
            sessions
                .push(ResharingParty::new(params, group_pub, Some(old_keys[i].clone())).unwrap());
        }
        let old_count = old_ids.len();
        for p in &new_ids {
            let params = ReSharingParameters::new(
                old_ids.clone(),
                new_ids.clone(),
                old_t,
                new_t,
                p.clone(),
                hub.broker(p),
            );
            sessions.push(ResharingParty::new(params, group_pub, None).unwrap());
        }

        let mut new_keys: Vec<Key> = Vec::new();
        for (i, s) in sessions.iter().enumerate() {
            let r = s.wait().expect("resharing succeeds");
            if i < old_count {
                assert!(r.is_none(), "old party gets no key");
            } else {
                let k = r.expect("new party gets a key");
                k.validate_basic().unwrap();
                assert!(
                    secp::point_eq(&k.ecdsa_pub, &group_pub),
                    "public key preserved"
                );
                new_keys.push(k);
            }
        }

        // Sign with the new committee (sync signer) under the preserved key.
        let hash = sha256(b"after reshare");
        let sig = super::super::sign(&new_keys, &[0, 1, 2], &hash, &mut OsRng).unwrap();
        let e = hash_to_scalar(&hash);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&group_pub, &e, &r, &s));
    }
}
