//! FROST(secp256k1) Pedersen DKG, broker-driven (two rounds).
//!
//! Round 1 broadcasts each dealer's Feldman commitments, a Schnorr proof of
//! knowledge of its constant term (stopping rogue-key contributions), a
//! session nonce and an ephemeral X25519 key. Round 2 sends each peer its
//! share sealed under the pairwise X25519 key. Finalization verifies every
//! share against its dealer's commitments and sums them.
//!
//! As in the other FROST modules, round-1 broadcasts are not echoed: a dealer
//! that sends different commitments to different parties leaves them with
//! different group keys, which surfaces as a failed signing session rather
//! than during keygen.

use super::Error;
use super::hd::derive_chain_code;
use super::key::{Key, strip};
use super::suite::{
    Point, Scalar, TR, decode_point, decode_scalar, encode_point, id_scalar, is_identity,
};
use super::vss::{self, ZkProof};
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::share_aead as aead;
use crate::sync::{Mutex, Receiver, Sender, channel};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use crate::vecmap::VecMap;
use alloc::sync::Arc;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const ROUND1_TYPE: &str = "frost:secp256k1-tr:keygen:round1";
const ROUND2_TYPE: &str = "frost:secp256k1-tr:keygen:round2";
const SESSION_NONCE_LEN: usize = 16;
const AD_PREFIX: &[u8] = b"frostsecp256k1tss/keygen/r2/v1|";
const POK_TAG: &[u8] = b"dkg-pok";

#[derive(Serialize, Deserialize)]
struct KeygenRound1Msg {
    #[serde(rename = "poly_commitments")]
    poly_commitments: Vec<B64Bytes>,
    #[serde(rename = "session_nonce", with = "crate::tss::b64::vec")]
    session_nonce: Vec<u8>,
    #[serde(rename = "eph_pub", with = "crate::tss::b64::vec")]
    eph_pub: Vec<u8>,
    #[serde(rename = "schnorr_r", with = "crate::tss::b64::vec")]
    schnorr_r: Vec<u8>,
    #[serde(rename = "schnorr_t", with = "crate::tss::b64::vec")]
    schnorr_t: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct KeygenRound2Msg {
    #[serde(rename = "ciphertext", with = "crate::tss::b64::vec")]
    ciphertext: Vec<u8>,
}

/// A running key-generation session.
pub struct Keygen {
    result_rx: Receiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    state: Mutex<State>,
    result_tx: Mutex<Option<Sender<Result<Key, Error>>>>,
}

#[derive(Default)]
struct State {
    vs: Vec<Point>,
    shares: Vec<Scalar>,
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    my_session_nonce: [u8; SESSION_NONCE_LEN],
    peer_eph_pubs: VecMap<Vec<u8>, [u8; 32]>,
    peer_session_nonces: VecMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    peer_vs: VecMap<Vec<u8>, Vec<Point>>,
}

/// The X25519 private key opens the share envelopes; wiped with the session.
impl Drop for State {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.eph_priv);
    }
}

impl Keygen {
    /// Starts the DKG for this party over `params.parties()`.
    pub fn new(params: Parameters) -> Result<Keygen, Error> {
        let ks: Vec<Vec<u8>> = params.parties().iter().map(|p| p.key.clone()).collect();
        vss::check_indexes(params.threshold(), &ks)
            .map_err(|e| Error::Validation(format!("keygen committee: {e}")))?;
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            state: Mutex::new(State::default()),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1(&ks);
        Ok(Keygen {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Non-blocking peek at the result: `Some(_)` once the key (or an error)
    /// is ready, `None` while rounds are pending.
    pub fn try_result(&self) -> Option<Result<Key, Error>> {
        self.result_rx.try_recv().ok()
    }

    /// Blocks until the DKG completes.
    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> Result<Key, Error> {
        self.result_rx
            .recv()
            .unwrap_or_else(|_| Err(Error::Validation("keygen dropped without result".into())))
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    fn fail(&self, m: impl Into<String>) {
        self.deliver(Err(Error::Validation(m.into())));
    }

    fn round1(self: &Arc<Self>, ks: &[Vec<u8>]) {
        let mut rng = SystemRng;
        let a0 = vss::random_scalar(&mut rng);
        let (vs, shares) = vss::create(self.params.threshold(), &a0, ks, &mut rng);

        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut session_nonce);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);

        let session = pok_session(&self.params.party_id().key, &session_nonce);
        let (schnorr_r, schnorr_t) = ZkProof::prove(&session, &a0, &vs[0], &mut rng).to_wire();
        let Some(poly_commitments) = vs
            .iter()
            .map(|p| encode_point(p).map(|b| B64Bytes(b.to_vec())))
            .collect::<Option<Vec<_>>>()
        else {
            return self.fail("zero polynomial coefficient");
        };
        let r1 = KeygenRound1Msg {
            poly_commitments,
            session_nonce: session_nonce.to_vec(),
            eph_pub: eph_pub.to_vec(),
            schnorr_r,
            schnorr_t,
        };

        {
            let mut st = self.state.lock();
            st.vs = vs;
            st.shares = shares;
            st.eph_priv = eph_priv;
            st.eph_pub = eph_pub;
            st.my_session_nonce = session_nonce;
        }
        if let Err(e) = self.broadcast(ROUND1_TYPE, &r1) {
            return self.deliver(Err(e));
        }

        let me = Arc::clone(self);
        let others = self.params.other_parties();
        let expect = JsonExpect::new(
            ROUND1_TYPE,
            others.clone(),
            Box::new(move |msgs| me.round2(&others, msgs)),
        );
        self.params.broker().connect(ROUND1_TYPE, Arc::new(expect));
    }

    fn round2(self: &Arc<Self>, others: &[PartyId], r1msgs: Vec<JsonMessage>) {
        for (pid, msg) in others.iter().zip(&r1msgs) {
            let r1: KeygenRound1Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let vsj = match self.verify_peer_round1(pid, &r1) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let key = strip(&pid.key).to_vec();
            let mut st = self.state.lock();
            st.peer_eph_pubs
                .insert(key.clone(), r1.eph_pub.try_into().unwrap());
            st.peer_session_nonces
                .insert(key.clone(), r1.session_nonce.try_into().unwrap());
            st.peer_vs.insert(key, vsj);
        }

        // Seal under the lock, send after releasing it: a synchronous broker
        // may run this party's handlers from inside `send_to`.
        let mut rng = SystemRng;
        let mut outbox = Vec::with_capacity(others.len());
        {
            let st = self.state.lock();
            let parties = self.params.parties();
            for pid in others {
                let Some(idx) = parties.iter().position(|p| p.key == pid.key) else {
                    return self.fail(format!("{pid} is not in the committee"));
                };
                let recipient_pub = *st
                    .peer_eph_pubs
                    .get(strip(&pid.key))
                    .expect("recorded above");
                let ad = round2_ad(&st.my_session_nonce, &st.eph_pub, &recipient_pub);
                let share = Zeroizing::new(st.shares[idx].to_bytes_be());
                match aead::seal_share(&mut rng, &st.eph_priv, &recipient_pub, &ad, &*share) {
                    Ok(ciphertext) => outbox.push((pid, KeygenRound2Msg { ciphertext })),
                    Err(e) => return self.fail(format!("seal share to {pid}: {e}")),
                }
            }
        }
        for (pid, msg) in &outbox {
            if let Err(e) = self.send_to(ROUND2_TYPE, msg, pid) {
                return self.deliver(Err(e));
            }
        }

        let me = Arc::clone(self);
        let others = others.to_vec();
        let expect = JsonExpect::new(
            ROUND2_TYPE,
            others.clone(),
            Box::new(move |msgs| me.finalize(&others, msgs)),
        );
        self.params.broker().connect(ROUND2_TYPE, Arc::new(expect));
    }

    fn verify_peer_round1(&self, pid: &PartyId, r1: &KeygenRound1Msg) -> Result<Vec<Point>, Error> {
        let threshold = self.params.threshold();
        if r1.poly_commitments.len() != threshold + 1 {
            return Err(Error::Validation(format!(
                "party {pid} sent {} commitments, expected {}",
                r1.poly_commitments.len(),
                threshold + 1
            )));
        }
        if r1.session_nonce.len() != SESSION_NONCE_LEN
            || r1.eph_pub.len() != aead::EPHEMERAL_KEY_BYTES
        {
            return Err(Error::Validation(format!(
                "party {pid} sent a malformed session nonce or ephemeral key"
            )));
        }
        let vsj = r1
            .poly_commitments
            .iter()
            .map(|b| decode_point(&b.0))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Error::Validation(format!("party {pid} sent an invalid commitment")))?;
        let session = pok_session(&pid.key, &r1.session_nonce);
        if !ZkProof::from_wire(&r1.schnorr_r, &r1.schnorr_t)?.verify(&session, &vsj[0]) {
            return Err(Error::Validation(format!(
                "party {pid} proof of knowledge failed"
            )));
        }
        Ok(vsj)
    }

    fn finalize(self: &Arc<Self>, others: &[PartyId], r2msgs: Vec<JsonMessage>) {
        let threshold = self.params.threshold();
        let me = self.params.party_id();
        let my_idx = self.params.party_index();
        let st = self.state.lock();

        let mut xi = st.shares[my_idx].clone();
        let mut vc = st.vs.clone();
        for (pid, msg) in others.iter().zip(&r2msgs) {
            let key = strip(&pid.key);
            let (Some(vsj), Some(nonce), Some(sender_pub)) = (
                st.peer_vs.get(key),
                st.peer_session_nonces.get(key),
                st.peer_eph_pubs.get(key),
            ) else {
                return self.fail(format!("share from {pid} has no round-1 data"));
            };
            let r2: KeygenRound2Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let ad = round2_ad(nonce, sender_pub, &st.eph_pub);
            let share = match aead::open_share(&st.eph_priv, sender_pub, &ad, &r2.ciphertext) {
                Ok(b) => decode_scalar(&b),
                Err(e) => return self.fail(format!("share from {pid} failed to open: {e}")),
            };
            let Some(share) = share else {
                return self.fail(format!("share from {pid} is not a valid scalar"));
            };
            if !vss::verify(&me.key, &share, threshold, vsj) {
                return self.fail(format!("share from {pid} failed VSS verification"));
            }
            xi = xi.add(&share);
            for (acc, v) in vc.iter_mut().zip(vsj) {
                *acc = acc.add(v);
            }
        }
        drop(st);

        let group_public_key = vc[0];
        if is_identity(&group_public_key) {
            return self.fail("group public key is the identity");
        }
        let parties = self.params.parties();
        self.deliver(Ok(Key {
            xi,
            share_id: BigUintDec::from_be_bytes(&me.key),
            ks: parties
                .iter()
                .map(|p| BigUintDec::from_be_bytes(&p.key))
                .collect(),
            big_xj: parties
                .iter()
                .map(|p| vss::share_image(&id_scalar(&p.key), &vc))
                .collect(),
            group_public_key,
            chain_code: derive_chain_code(&group_public_key),
        }));
    }

    fn broadcast<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        self.deliver_msg(json_wrap(
            typ,
            body,
            Some(self.params.party_id().clone()),
            None,
        )?)
    }

    fn send_to<T: Serialize>(&self, typ: &str, body: &T, to: &PartyId) -> Result<(), Error> {
        self.deliver_msg(json_wrap(
            typ,
            body,
            Some(self.params.party_id().clone()),
            Some(to.clone()),
        )?)
    }

    fn deliver_msg(&self, msg: JsonMessage) -> Result<(), Error> {
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }
}

fn pok_session(party_key: &[u8], session_nonce: &[u8]) -> Vec<u8> {
    let pk = strip(party_key);
    [TR.context(), POK_TAG, &[pk.len() as u8], pk, session_nonce].concat()
}

fn round2_ad(sender_nonce: &[u8], sender_pub: &[u8], recipient_pub: &[u8]) -> Vec<u8> {
    [
        AD_PREFIX,
        sender_nonce,
        b"|",
        sender_pub,
        b"|",
        recipient_pub,
    ]
    .concat()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::frostsecp256k1tss::suite::point_eq;
    use crate::tss::testhub::TestHub;

    pub(crate) fn party_ids(keys: &[u8]) -> Vec<PartyId> {
        PartyId::sort(
            keys.iter()
                .map(|&k| PartyId::new(k.to_string(), format!("P{k}"), vec![k]))
                .collect(),
            0,
        )
    }

    pub(crate) fn run_keygen(ids: &[PartyId], t: usize) -> Vec<Key> {
        let hub = TestHub::new(ids);
        let sessions: Vec<Keygen> = (0..ids.len())
            .map(|i| Keygen::new(Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i))).unwrap())
            .collect();
        sessions.iter().map(|s| s.wait().expect("keygen")).collect()
    }

    #[test]
    fn keygen_parties_agree() {
        let ids = party_ids(&[1, 2, 3]);
        let keys = run_keygen(&ids, 1);
        for k in &keys {
            k.validate_basic().unwrap();
            assert!(point_eq(&k.group_public_key, &keys[0].group_public_key));
            assert_eq!(k.chain_code, keys[0].chain_code);
            assert_eq!(k.ks, keys[0].ks);
        }
        // Any t+1 shares interpolate to the group secret.
        let xs: Vec<Scalar> = ids[1..].iter().map(|p| id_scalar(&p.key)).collect();
        let mut secret = Scalar::ZERO;
        for (x, k) in xs.iter().zip(&keys[1..]) {
            let l = super::super::suite::lagrange_coefficient(x, &xs).unwrap();
            secret = secret.add(&l.mul(&k.xi));
        }
        assert!(point_eq(
            &super::super::suite::mul_base(&secret),
            &keys[0].group_public_key
        ));
    }

    #[test]
    fn keygen_rejects_bad_committee() {
        let ids = party_ids(&[1, 2]);
        let hub = TestHub::new(&ids);
        assert!(Keygen::new(Parameters::new(ids.clone(), &ids[0], 2, hub.broker(0))).is_err());
    }
}
