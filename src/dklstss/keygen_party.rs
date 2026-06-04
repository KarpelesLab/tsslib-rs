//! Broker-driven DKLs23 distributed key generation.
//!
//! The per-party state machine that runs the DKG over a [`MessageBroker`],
//! the broker-driven equivalent of the synchronous [`keygen`](super::keygen).
//! Round 1 broadcasts the dealer's Feldman-VSS commitments and unicasts each
//! peer its Shamir share plus a base-OT-Sender first message; an echo phase
//! cross-checks the broadcast commitments for equivocation; round 2 returns the
//! base-OT-Receiver response; finalize assembles the per-pair OT-extension state
//! and this party's [`Key`]. Wire-compatible with Go `dklstss` keygen.

use super::Error;
use super::baseot;
use super::echo::{
    EchoMsg, commit_digest, flatten_point_xy, other_parties, pair_base_sid, peer_key_str,
    point_from_be_xy, strip, unflatten_point_xy, verify_echoes,
};
use super::key::{Key, PairOTState};
use super::keygen::derive_chain_code;
use super::otext::{self, ExtReceiver, ExtSender};
use super::schnorr::ZkProof;
use super::secp::{self, ProjectivePoint, Scalar};
use super::vss;
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::hash::sha256;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1BC: &str = "dkls:keygen:r1bc";
const TYPE_R1UC: &str = "dkls:keygen:r1uc";
const TYPE_ECHO: &str = "dkls:keygen:echo";
const TYPE_R2: &str = "dkls:keygen:r2";
const ECHO_TAG: &str = "DKLS23-echo-keygen-v1";
const ECHO_SOURCE: &str = "dklstss-keygen";

/// A running DKLs23 distributed key-generation session. Construct with
/// [`KeygenParty::new`]; retrieve the resulting [`Key`] with [`KeygenParty::wait`].
pub struct KeygenParty {
    result_rx: MpscReceiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    ssid: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<Key, Error>>>>,
}

struct State {
    vs: Vec<ProjectivePoint>,
    shares: Vec<Scalar>,
    base_snd: HashMap<String, baseot::Sender>,

    r1_bcasts: Vec<KeygenR1Bcast>,
    r1_unicasts: Vec<KeygenR1Unicast>,
    r1_join: u8,

    base_rcv: HashMap<String, baseot::Receiver>,
    my_delta: HashMap<String, Vec<u8>>,
    peer_vs: HashMap<String, Vec<ProjectivePoint>>,
    peer_shares: HashMap<String, Scalar>,
}

impl KeygenParty {
    /// Starts the DKG for this party. Returns immediately after round 1 is
    /// emitted; the result is delivered once all rounds complete.
    pub fn new(params: Parameters) -> Result<KeygenParty, Error> {
        let (tx, rx) = channel();
        let ssid = keygen_session(&params);
        let shared = Arc::new(Shared {
            params,
            ssid,
            state: Mutex::new(State {
                vs: Vec::new(),
                shares: Vec::new(),
                base_snd: HashMap::new(),
                r1_bcasts: Vec::new(),
                r1_unicasts: Vec::new(),
                r1_join: 0,
                base_rcv: HashMap::new(),
                my_delta: HashMap::new(),
                peer_vs: HashMap::new(),
                peer_shares: HashMap::new(),
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(KeygenParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until the DKG completes, returning the generated key or an error.
    pub fn wait(&self) -> Result<Key, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "keygen session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let t = self.params.threshold();
        let parties = self.params.parties().to_vec();
        let me = self.params.party_id().clone();

        let ids: Vec<Scalar> = parties
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();
        check_indexes(&ids)?;

        let u = secp::random_scalar(&mut rng);
        let (vs, shares) = vss::create(t, &u, &ids, &mut rng);

        let others = other_parties(&parties, &me);

        // BROADCAST: VSS commitments — identical bytes to every recipient.
        let bcast = KeygenR1Bcast {
            vss_commitments: flatten_point_xy(&vs),
        };
        self.broadcast(TYPE_R1BC, &bcast)?;

        // UNICAST: per-peer share + base-OT-Sender first message.
        for pj in &others {
            let share = &shares[pj.index as usize];
            // Direction "j becomes ExtSender, i becomes ExtReceiver": i is the
            // base-OT Sender; the sid names j as the OT-extension sender.
            let sid = pair_base_sid(&self.ssid, &me.key, &pj.key, &pj.key);
            let (snd, smsg) = baseot::Sender::new(&sid, otext::KAPPA, &mut rng);
            self.state
                .lock()
                .unwrap()
                .base_snd
                .insert(peer_key_str(pj), snd);

            let (sx, sy) = secp::affine_be(&smsg.s);
            let (ax, ay) = secp::affine_be(&smsg.pok.alpha);
            let uc = KeygenR1Unicast {
                share: B64Bytes(secp::scalar_to_be_min(share)),
                ot_sender_s_x: B64Bytes(sx),
                ot_sender_s_y: B64Bytes(sy),
                ot_sender_pok_alpha_x: B64Bytes(ax),
                ot_sender_pok_alpha_y: B64Bytes(ay),
                ot_sender_pok_t: B64Bytes(secp::scalar_to_be_min(&smsg.pok.t)),
            };
            self.send_to(TYPE_R1UC, &uc, pj)?;
        }

        {
            let mut st = self.state.lock().unwrap();
            st.vs = vs;
            st.shares = shares;
        }

        self.connect_r1(&others);
        Ok(())
    }

    fn connect_r1(self: &Arc<Self>, others: &[PartyId]) {
        let me_bc = Arc::clone(self);
        let others_bc = others.to_vec();
        let exp_bc = JsonExpect::new(
            TYPE_R1BC,
            others.to_vec(),
            Box::new(move |msgs| me_bc.on_r1bc(&others_bc, msgs)),
        );
        self.params.broker().connect(TYPE_R1BC, Arc::new(exp_bc));

        let me_uc = Arc::clone(self);
        let others_uc = others.to_vec();
        let exp_uc = JsonExpect::new(
            TYPE_R1UC,
            others.to_vec(),
            Box::new(move |msgs| me_uc.on_r1uc(&others_uc, msgs)),
        );
        self.params.broker().connect(TYPE_R1UC, Arc::new(exp_uc));
    }

    fn on_r1bc(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<KeygenR1Bcast>, Error> =
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
            self.start_echo(others);
        }
    }

    fn on_r1uc(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<KeygenR1Unicast>, Error> =
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
            self.start_echo(others);
        }
    }

    fn start_echo(self: &Arc<Self>, others: &[PartyId]) {
        let digests: HashMap<String, B64Bytes> = {
            let st = self.state.lock().unwrap();
            others
                .iter()
                .enumerate()
                .map(|(n, pid)| {
                    let raw = vss_bytes(&st.r1_bcasts[n].vss_commitments);
                    (
                        peer_key_str(pid),
                        B64Bytes(commit_digest(ECHO_TAG, pid, &raw)),
                    )
                })
                .collect()
        };
        let out = EchoMsg { digests };
        if let Err(e) = self.broadcast(TYPE_ECHO, &out) {
            return self.deliver(Err(e));
        }
        let me = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_ECHO,
            others.to_vec(),
            Box::new(move |msgs| me.on_echo(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_ECHO, Arc::new(exp));
    }

    fn on_echo(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let echoes: Vec<EchoMsg> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };
        let me = self.params.party_id().clone();
        let self_key = peer_key_str(&me);

        let my_digests: HashMap<String, Vec<u8>> = {
            let st = self.state.lock().unwrap();
            let mut m = HashMap::with_capacity(others.len() + 1);
            m.insert(
                self_key.clone(),
                commit_digest(ECHO_TAG, &me, &flatten_to_bytes(&st.vs)),
            );
            for (n, pid) in others.iter().enumerate() {
                let raw = vss_bytes(&st.r1_bcasts[n].vss_commitments);
                m.insert(peer_key_str(pid), commit_digest(ECHO_TAG, pid, &raw));
            }
            m
        };

        let mut all = vec![me.clone()];
        all.extend(others.iter().cloned());
        if let Err(e) = verify_echoes(&my_digests, &self_key, others, &echoes, &all, ECHO_SOURCE) {
            return self.deliver(Err(e));
        }
        self.round2(others);
    }

    fn round2(self: &Arc<Self>, others: &[PartyId]) {
        let mut rng = OsRng;
        let t = self.params.threshold();
        let me = self.params.party_id().clone();
        let my_id = secp::scalar_from_be_reduce(&me.key);

        // Snapshot the round-1 payloads (others order).
        let (bcasts, ucs) = {
            let st = self.state.lock().unwrap();
            (st.r1_bcasts.clone(), st.r1_unicasts.clone())
        };

        for (n, pid) in others.iter().enumerate() {
            let bc = &bcasts[n];
            let uc = &ucs[n];

            if bc.vss_commitments.len() != 2 * (t + 1) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent {} VSS-commitment coords, expected {}",
                    bc.vss_commitments.len(),
                    2 * (t + 1)
                ))));
            }
            let vsj = match unflatten_point_xy(&bc.vss_commitments) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };

            // Reject non-canonical (>= n) shares: VSS.verify reduces mod n, so a
            // dealer shipping `share + k·n` would still verify while hashing to a
            // different echo digest — an echo-bypass channel.
            if !is_canonical_scalar(&uc.share.0) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent non-canonical share (>= n)"
                ))));
            }
            let share = secp::scalar_from_be_reduce(&uc.share.0);
            if !vss::verify(&my_id, &share, t, &vsj) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} VSS share verification failed"
                ))));
            }

            // Reconstruct the peer's base-OT-Sender message (direction "i is
            // ExtSender": the sid names i as the OT-extension sender).
            let Some(s) = point_from_be_xy(&uc.ot_sender_s_x.0, &uc.ot_sender_s_y.0) else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} OT Sender S invalid"
                ))));
            };
            let Some(alpha) =
                point_from_be_xy(&uc.ot_sender_pok_alpha_x.0, &uc.ot_sender_pok_alpha_y.0)
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} OT Sender PoK alpha invalid"
                ))));
            };
            let pok = ZkProof {
                alpha,
                t: secp::scalar_from_be_reduce(&uc.ot_sender_pok_t.0),
            };
            let smsg = baseot::SenderMsg1 { s, pok };

            let sid = pair_base_sid(&self.ssid, &pid.key, &me.key, &me.key);
            let mut delta = vec![0u8; otext::DELTA_BYTES];
            rng.fill_bytes(&mut delta);
            let Some((rcvr, rmsg)) =
                baseot::Receiver::new(&sid, otext::KAPPA, &delta, &smsg, &mut rng)
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} base-OT receiver setup failed (bad PoK?)"
                ))));
            };

            {
                let mut st = self.state.lock().unwrap();
                let k = peer_key_str(pid);
                st.base_rcv.insert(k.clone(), rcvr);
                st.my_delta.insert(k.clone(), delta);
                st.peer_vs.insert(k.clone(), vsj);
                st.peer_shares.insert(k, share);
            }

            let r2 = KeygenR2 {
                ot_receiver_r: flatten_point_xy(&rmsg.r),
            };
            if let Err(e) = self.send_to(TYPE_R2, &r2, pid) {
                return self.deliver(Err(e));
            }
        }

        let me_arc = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R2,
            others.to_vec(),
            Box::new(move |msgs| me_arc.finalize(&others_owned, msgs)),
        );
        self.params.broker().connect(TYPE_R2, Arc::new(exp));
    }

    fn finalize(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let t = self.params.threshold();
        let parties = self.params.parties().to_vec();
        let n = parties.len();
        let self_idx = self.params.party_index();
        let me = self.params.party_id().clone();

        let r2s: Vec<KeygenR2> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        let st = self.state.lock().unwrap();

        // x_i = my own share + Σ peer shares (mod n).
        let mut xi = st.shares[self_idx].clone();
        for pid in others {
            xi = xi.add(&st.peer_shares[&peer_key_str(pid)]);
        }

        // Joint public key X = Σ dealers' v_0.
        let mut pub_key = st.vs[0];
        for pid in others {
            pub_key = pub_key.add(&st.peer_vs[&peer_key_str(pid)][0]);
        }

        // Per-party verification points BigXj = Σ_dealers eval(V_dealer, id_j).
        let mut all_vss: Vec<Vec<ProjectivePoint>> = vec![Vec::new(); n];
        for p in &parties {
            if p.cmp_key(&me) == std::cmp::Ordering::Equal {
                all_vss[p.index as usize] = st.vs.clone();
            } else {
                all_vss[p.index as usize] = st.peer_vs[&peer_key_str(p)].clone();
            }
        }
        let mut big_xj = vec![secp::generator(); n];
        for p in &parties {
            let id = secp::scalar_from_be_reduce(&p.key);
            big_xj[p.index as usize] = vss::evaluate_commitment_sum(&all_vss, &id);
        }

        // Per-pair OT-extension state.
        let mut ot: Vec<Option<PairOTState>> = (0..n).map(|_| None).collect();
        for pj in others {
            let k = peer_key_str(pj);

            // Direction "i is ExtSender": local base-OT Receiver finalizes.
            let chosen = st.base_rcv[&k].finalize();
            let ext_sender = match ExtSender::from_base(&st.my_delta[&k], &chosen) {
                Ok(e) => e,
                Err(e) => return self.deliver(Err(e)),
            };

            // Direction "peer is ExtSender": local base-OT Sender finalizes with
            // the peer's round-2 R points.
            let idx = others
                .iter()
                .position(|p| p.cmp_key(pj) == std::cmp::Ordering::Equal)
                .expect("peer present");
            let peer_r = match unflatten_point_xy(&r2s[idx].ot_receiver_r) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let Some((k0, k1)) = st.base_snd[&k].finalize(&baseot::ReceiverMsg1 { r: peer_r })
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "base-OT sender finalize for {pj} failed"
                ))));
            };
            let ext_receiver = match ExtReceiver::from_base(&k0, &k1) {
                Ok(e) => e,
                Err(e) => return self.deliver(Err(e)),
            };

            ot[pj.index as usize] = Some(PairOTState {
                as_alice: ext_receiver,
                as_bob: ext_sender,
            });
        }

        let chain_code = derive_chain_code(&pub_key);
        drop(st);

        let key = Key {
            n,
            t,
            idx: self_idx,
            party_ids: parties,
            xi,
            big_xj,
            ecdsa_pub: pub_key,
            ot,
            chain_code,
        };
        if let Err(e) = key.validate_basic() {
            return self.deliver(Err(e));
        }
        self.deliver(Ok(key));
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
struct KeygenR1Bcast {
    #[serde(rename = "vss_commitments")]
    vss_commitments: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct KeygenR1Unicast {
    #[serde(rename = "share")]
    share: B64Bytes,
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
struct KeygenR2 {
    #[serde(rename = "ot_receiver_r")]
    ot_receiver_r: Vec<B64Bytes>,
}

// --- helpers ---------------------------------------------------------------

/// Session id binding the protocol tag, threshold, and sorted party set.
fn keygen_session(params: &Parameters) -> Vec<u8> {
    let mut data = b"DKLS23-keygen-party-v2-".to_vec();
    data.extend_from_slice(&(params.threshold() as u32).to_be_bytes());
    for p in params.parties() {
        data.extend_from_slice(strip(&p.key));
        data.push(0);
    }
    sha256(&data).to_vec()
}

/// The inner byte slices of a flattened-commitment field, for digesting.
fn vss_bytes(flat: &[B64Bytes]) -> Vec<Vec<u8>> {
    flat.iter().map(|b| b.0.clone()).collect()
}

/// The flattened-XY byte form of a point vector, for digesting one's own V.
fn flatten_to_bytes(vs: &[ProjectivePoint]) -> Vec<Vec<u8>> {
    flatten_point_xy(vs).iter().map(|b| b.0.clone()).collect()
}

/// True if `bytes` is the canonical big-endian encoding of a scalar in `[0, n)`
/// (i.e. reducing mod n leaves it unchanged).
fn is_canonical_scalar(bytes: &[u8]) -> bool {
    let s = secp::scalar_from_be_reduce(bytes);
    secp::scalar_to_be_min(&s) == strip(bytes)
}

/// Rejects zero or duplicate party identifiers (mod n).
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
        parties
            .iter()
            .map(|p| p.wait().expect("keygen succeeds"))
            .collect()
    }

    #[test]
    fn keygen_consistent_2_of_3() {
        let ids = party_ids(3);
        let keys = run_keygen(&ids, 1);
        for k in &keys {
            k.validate_basic().unwrap();
            assert!(k.ot[k.idx].is_none());
        }
        for k in &keys[1..] {
            assert!(secp::point_eq(&keys[0].ecdsa_pub, &k.ecdsa_pub));
            assert_eq!(keys[0].chain_code, k.chain_code);
            for (a, b) in keys[0].big_xj.iter().zip(k.big_xj.iter()) {
                assert!(secp::point_eq(a, b));
            }
        }
    }

    #[test]
    fn keygen_then_sign_verifies() {
        let ids = party_ids(3);
        let keys = run_keygen(&ids, 1);
        // The broker-generated keys must sign via the existing sync signer.
        let hash = [0x42u8; 32];
        let sig = super::super::sign(&keys, &[0, 1], &hash, &mut OsRng).expect("sign");
        assert!(!sig.r.is_empty() && !sig.s.is_empty());
    }
}
