//! Broker-driven DKLs23 proactive refresh.
//!
//! The distributed counterpart to the synchronous [`refresh`](super::refresh).
//! Every party re-shares a *zero-constant* Feldman polynomial to the same
//! committee; the per-party shares sum to zero, so the joint public key is
//! unchanged while every share (and all pairwise OT-extension state) is rotated.
//! Same round shape as [`KeygenParty`](super::KeygenParty) — broadcast
//! commitments + unicast share & base-OT-Sender message, echo cross-check, then
//! base-OT-Receiver response — differing only in the zero-constant polynomial
//! and the additive share/commitment update. Wire-compatible with Go `dklstss`.

use super::Error;
use super::baseot;
use super::echo::{
    EchoMsg, commit_digest, flatten_point_xy, other_parties, pair_base_sid, peer_key_str,
    point_from_be_xy, strip, unflatten_point_xy, verify_echoes,
};
use super::key::{Key, PairOTState};
use super::otext::{self, ExtReceiver, ExtSender};
use super::schnorr::ZkProof;
use super::secp::{self, ProjectivePoint, Scalar};
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::hash::sha256;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1BC: &str = "dkls:refresh:r1bc";
const TYPE_R1UC: &str = "dkls:refresh:r1uc";
const TYPE_ECHO: &str = "dkls:refresh:echo";
const TYPE_R2: &str = "dkls:refresh:r2";
const ECHO_TAG: &str = "DKLS23-echo-refresh-v1";
const ECHO_SOURCE: &str = "dklstss-refresh";

/// A running DKLs23 proactive-refresh session. Construct with
/// [`RefreshParty::new`]; retrieve the rotated [`Key`] with
/// [`RefreshParty::wait`]. The joint public key is preserved.
pub struct RefreshParty {
    result_rx: MpscReceiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    old: Key,
    ssid: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<Key, Error>>>>,
}

struct State {
    own_vs: Vec<ProjectivePoint>,
    my_self_share: Scalar,
    base_snd: HashMap<String, baseot::Sender>,
    r1_bcasts: Vec<RefreshR1Bcast>,
    r1_unicasts: Vec<RefreshR1Unicast>,
    r1_join: u8,
    base_rcv: HashMap<String, baseot::Receiver>,
    my_delta: HashMap<String, Vec<u8>>,
    peer_vs: HashMap<String, Vec<ProjectivePoint>>,
    peer_shares: HashMap<String, Scalar>,
}

impl RefreshParty {
    /// Starts proactive refresh for this party using its current key.
    pub fn new(params: Parameters, old: Key) -> Result<RefreshParty, Error> {
        old.validate_basic()?;
        let ssid = refresh_session(&params, &old);
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            old,
            ssid,
            state: Mutex::new(State {
                own_vs: Vec::new(),
                my_self_share: Scalar::ZERO,
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
        Ok(RefreshParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until refresh completes, returning the rotated key or an error.
    pub fn wait(&self) -> Result<Key, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("refresh dropped without result".into())),
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
        let t = self.old.t;
        let me = self.params.party_id().clone();

        // Zero-constant polynomial: T coefficients a_1..a_T, commitments a_k·G.
        let coeffs: Vec<Scalar> = (0..t).map(|_| secp::random_scalar(&mut rng)).collect();
        let vs: Vec<ProjectivePoint> = coeffs.iter().map(secp::mul_base).collect();

        let my_id = secp::scalar_from_be_reduce(&me.key);
        let my_self_share = eval_zero_const_poly(&coeffs, &my_id);

        let others = other_parties(self.params.parties(), &me);

        let bcast = RefreshR1Bcast {
            vss_commitments: flatten_point_xy(&vs),
        };
        self.broadcast(TYPE_R1BC, &bcast)?;

        for pj in &others {
            let id = secp::scalar_from_be_reduce(&pj.key);
            let share = eval_zero_const_poly(&coeffs, &id);
            let sid = pair_base_sid(&self.ssid, &me.key, &pj.key, &pj.key);
            let (snd, smsg) = baseot::Sender::new(&sid, otext::KAPPA, &mut rng);
            self.state
                .lock()
                .unwrap()
                .base_snd
                .insert(peer_key_str(pj), snd);

            let (sx, sy) = secp::affine_be(&smsg.s);
            let (ax, ay) = secp::affine_be(&smsg.pok.alpha);
            let uc = RefreshR1Unicast {
                share: B64Bytes(secp::scalar_to_be_min(&share)),
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
            st.own_vs = vs;
            st.my_self_share = my_self_share;
        }

        let me_bc = Arc::clone(self);
        let others_bc = others.clone();
        let exp_bc = JsonExpect::new(
            TYPE_R1BC,
            others.clone(),
            Box::new(move |msgs| me_bc.on_r1bc(&others_bc, msgs)),
        );
        self.params.broker().connect(TYPE_R1BC, Arc::new(exp_bc));

        let me_uc = Arc::clone(self);
        let others_uc = others.clone();
        let exp_uc = JsonExpect::new(
            TYPE_R1UC,
            others,
            Box::new(move |msgs| me_uc.on_r1uc(&others_uc, msgs)),
        );
        self.params.broker().connect(TYPE_R1UC, Arc::new(exp_uc));
        Ok(())
    }

    fn on_r1bc(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<RefreshR1Bcast>, Error> =
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
        let decoded: Result<Vec<RefreshR1Unicast>, Error> =
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
        if let Err(e) = self.broadcast(TYPE_ECHO, &EchoMsg { digests }) {
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
                commit_digest(ECHO_TAG, &me, &flatten_to_bytes(&st.own_vs)),
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
        let t = self.old.t;
        let me = self.params.party_id().clone();
        let my_id = secp::scalar_from_be_reduce(&me.key);

        let (bcasts, ucs) = {
            let st = self.state.lock().unwrap();
            (st.r1_bcasts.clone(), st.r1_unicasts.clone())
        };

        for (n, pid) in others.iter().enumerate() {
            let bc = &bcasts[n];
            let uc = &ucs[n];
            if bc.vss_commitments.len() != 2 * t {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent {} Vs coords, expected {}",
                    bc.vss_commitments.len(),
                    2 * t
                ))));
            }
            let vsj = match unflatten_point_xy(&bc.vss_commitments) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            if !is_canonical_scalar(&uc.share.0) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent non-canonical refresh-share (>= n)"
                ))));
            }
            let share = secp::scalar_from_be_reduce(&uc.share.0);
            if !verify_zero_const_share(&vsj, &my_id, &share) {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} refresh-share verification failed"
                ))));
            }

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
                    "party {pid} base-OT receiver setup failed"
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
            let r2 = RefreshR2 {
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
        let parties = self.params.parties().to_vec();
        let n = parties.len();
        let self_idx = self.params.party_index();

        let r2s: Vec<RefreshR2> = match msgs.iter().map(json_get).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(Error::Serde(e))),
        };

        let st = self.state.lock().unwrap();

        // new x_i = old x_i + (own eval at self + Σ peer evals at self).
        let mut delta_self = st.my_self_share.clone();
        for pid in others {
            delta_self = delta_self.add(&st.peer_shares[&peer_key_str(pid)]);
        }
        let new_xi = self.old.xi.add(&delta_self);

        // new BigXj[j] = old BigXj[j] + (Σ_dealers eval(V_dealer, id_j))·G.
        let mut new_big_xj = vec![secp::generator(); n];
        for pj in &parties {
            let id = secp::scalar_from_be_reduce(&pj.key);
            let mut delta_g = eval_commitment_zero_const(&st.own_vs, &id);
            for vs in st.peer_vs.values() {
                let term = eval_commitment_zero_const(vs, &id);
                delta_g = match (delta_g, term) {
                    (Some(a), Some(b)) => Some(a.add(&b)),
                    (Some(a), None) => Some(a),
                    (None, b) => b,
                };
            }
            let old_pt = self.old.big_xj[pj.index as usize];
            new_big_xj[pj.index as usize] = match delta_g {
                Some(d) => old_pt.add(&d),
                None => old_pt,
            };
        }

        // Consistency: new_xi·G == new BigXj[self].
        if !secp::point_eq(&secp::mul_base(&new_xi), &new_big_xj[self_idx]) {
            return self.deliver(Err(Error::Validation(
                "refresh consistency check failed: new_xi·G != new BigXj[self]".into(),
            )));
        }

        // Rotate per-pair OT-extension state (same dance as keygen finalize).
        let mut ot: Vec<Option<PairOTState>> = (0..n).map(|_| None).collect();
        for pj in others {
            let k = peer_key_str(pj);
            let chosen = st.base_rcv[&k].finalize();
            let ext_sender = match ExtSender::from_base(&st.my_delta[&k], &chosen) {
                Ok(e) => e,
                Err(e) => return self.deliver(Err(e)),
            };
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

        drop(st);

        let key = Key {
            n: self.old.n,
            t: self.old.t,
            idx: self.old.idx,
            party_ids: self.old.party_ids.clone(),
            xi: new_xi,
            big_xj: new_big_xj,
            ecdsa_pub: self.old.ecdsa_pub,
            ot,
            chain_code: self.old.chain_code,
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
struct RefreshR1Bcast {
    #[serde(rename = "vss_commitments")]
    vss_commitments: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RefreshR1Unicast {
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
struct RefreshR2 {
    #[serde(rename = "ot_receiver_r")]
    ot_receiver_r: Vec<B64Bytes>,
}

// --- helpers ---------------------------------------------------------------

/// Evaluates a zero-constant polynomial `Σ_{k=1}^{T} a_k·x^k` at `x`.
fn eval_zero_const_poly(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut xpow = x.clone(); // x^1
    for c in coeffs {
        acc = acc.add(&c.mul(&xpow));
        xpow = xpow.mul(x);
    }
    acc
}

/// `Σ_{k=1}^{T} id^k · V[k-1]` — the zero-constant commitment evaluated at `id`.
fn eval_commitment_zero_const(vs: &[ProjectivePoint], id: &Scalar) -> Option<ProjectivePoint> {
    let mut acc: Option<ProjectivePoint> = None;
    let mut idpow = id.clone(); // id^1
    for v in vs {
        let term = v.mul(&idpow);
        acc = Some(match acc {
            None => term,
            Some(a) => a.add(&term),
        });
        idpow = idpow.mul(id);
    }
    acc
}

/// Verifies `share·G == Σ_{k=1}^{T} id^k · V[k-1]`.
fn verify_zero_const_share(vs: &[ProjectivePoint], id: &Scalar, share: &Scalar) -> bool {
    match eval_commitment_zero_const(vs, id) {
        Some(expect) => secp::point_eq(&secp::mul_base(share), &expect),
        None => false,
    }
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

/// Session id binding the protocol tag, joint public key, threshold, and the
/// sorted party set.
fn refresh_session(params: &Parameters, key: &Key) -> Vec<u8> {
    let (px, py) = secp::affine_be(&key.ecdsa_pub);
    let mut data = b"DKLS23-refresh-party-v2-".to_vec();
    data.extend_from_slice(&px);
    data.extend_from_slice(&py);
    data.extend_from_slice(&(params.threshold() as u32).to_be_bytes());
    for p in params.parties() {
        data.extend_from_slice(strip(&p.key));
        data.push(0);
    }
    sha256(&data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::super::keygen_party::KeygenParty;
    use super::super::signing::{ecdsa_verify, hash_to_scalar};
    use super::*;
    use crate::tss::testhub::TestHub;
    use purecrypto::hash::sha256;
    use purecrypto::rng::OsRng;

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

    #[test]
    fn refresh_preserves_key_and_signs() {
        let ids = party_ids(3);
        let t = 1;
        let keys = run_keygen(&ids, t);
        let group_pub = keys[0].ecdsa_pub;

        let hub = TestHub::new(&ids);
        let refreshers: Vec<RefreshParty> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                RefreshParty::new(params, keys[i].clone()).unwrap()
            })
            .collect();
        let new_keys: Vec<Key> = refreshers.iter().map(|r| r.wait().unwrap()).collect();

        for k in &new_keys {
            k.validate_basic().unwrap();
            assert!(secp::point_eq(&k.ecdsa_pub, &group_pub), "pub preserved");
        }
        // Shares actually rotated.
        assert!(!bool::from(new_keys[0].xi.ct_eq(&keys[0].xi)));

        // The refreshed keys still sign under the unchanged public key.
        let hash = sha256(b"after refresh");
        let sig = super::super::sign(&new_keys, &[0, 2], &hash, &mut OsRng).unwrap();
        let e = hash_to_scalar(&hash);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&group_pub, &e, &r, &s));
    }
}
