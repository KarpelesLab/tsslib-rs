//! FROST(ristretto255) Pedersen DKG, broker-driven. Mirrors frosttss keygen
//! over the Ristretto255 group, with a Schnorr-over-encoded-points PoK and no
//! chain code (this variant has no HD derivation).
//!
//! Round-1 broadcasts are not echoed in an extra round. Instead every party
//! hashes all parties' round-1 payloads (in committee order) into a
//! transcript and binds it into the associated data of every round-2 share
//! envelope. A dealer that sends different round-1 payloads (for instance
//! different higher-degree commitments) to different parties leaves them with
//! different transcripts, so their round-2 envelopes fail to open and keygen
//! aborts instead of producing inconsistent keys.

use super::Error;
use super::key::Key;
use super::schnorr::ZkProof;
use crate::frost::aead;
use crate::frost::vss;
use crate::frost::{
    Ciphersuite, Ristretto255, Scalar, random_scalar, scalar_from_be_mod_l, scalar_to_be,
};
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::sync::{Mutex, Receiver, Sender, channel};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{Message, Parameters, PartyId, decode, encode};
use crate::vecmap::VecMap;
use alloc::sync::Arc;
use purecrypto::ec::ristretto255::RistrettoPoint;
use purecrypto::hash::sha256;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};

const ROUND1_TYPE: &str = "frost:ristretto255:keygen:v2:round1";
const ROUND2_TYPE: &str = "frost:ristretto255:keygen:v2:round2";
const SESSION_NONCE_LEN: usize = 16;
const COMMITMENT_BYTES: usize = 32;
const AD_PREFIX: &[u8] = b"frostristretto255tss/keygen/r2/v2|";
const TRANSCRIPT_TAG: &[u8] = b"frostristretto255tss/keygen/r1-transcript/v1";
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

/// A running FROST(ristretto255) key-generation session.
pub struct Keygen {
    result_rx: Receiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    state: Mutex<State>,
    result_tx: Mutex<Option<Sender<Result<Key, Error>>>>,
}

struct State {
    vs: Vec<RistrettoPoint>,
    shares: Vec<vss::Share>,
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    my_session_nonce: [u8; SESSION_NONCE_LEN],
    ks: Vec<Vec<u8>>,
    peer_eph_pubs: VecMap<Vec<u8>, [u8; 32]>,
    peer_session_nonces: VecMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    peer_vs: VecMap<Vec<u8>, Vec<RistrettoPoint>>,
    /// This party's round-1 payload, as hashed into the transcript.
    my_r1_part: Vec<u8>,
    /// Hash of every party's round-1 payload, bound into the round-2 AD.
    transcript: [u8; 32],
}

/// The X25519 private key opens the share envelopes; wiped with the session.
impl Drop for State {
    fn drop(&mut self) {
        purecrypto::zeroize::Zeroize::zeroize(&mut self.eph_priv);
    }
}

impl Keygen {
    /// Starts the FROST(ristretto255) Pedersen DKG for this party.
    pub fn new(params: Parameters) -> Result<Keygen, Error> {
        let ks: Vec<Vec<u8>> = params.parties().iter().map(|p| p.key.clone()).collect();
        vss::check_indexes(params.threshold(), &ks)
            .map_err(|e| Error::Validation(format!("keygen committee: {e}")))?;
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            state: Mutex::new(State {
                vs: Vec::new(),
                shares: Vec::new(),
                eph_priv: [0u8; 32],
                eph_pub: [0u8; 32],
                my_session_nonce: [0u8; SESSION_NONCE_LEN],
                ks: Vec::new(),
                peer_eph_pubs: VecMap::new(),
                peer_session_nonces: VecMap::new(),
                peer_vs: VecMap::new(),
                my_r1_part: Vec::new(),
                transcript: [0u8; 32],
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1();
        Ok(Keygen {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until the DKG completes, returning the generated key.
    /// Non-blocking peek at the ceremony result: `Some(_)` once the result (or
    /// error) is ready, `None` while rounds are still pending. Unlike [`wait`](Self::wait)
    /// it never blocks, so a single-threaded async driver (e.g. wasm/browser) can
    /// poll it after feeding each inbound message.
    pub fn try_result(&self) -> Option<Result<Key, Error>> {
        self.result_rx.try_recv().ok()
    }

    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> Result<Key, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("keygen dropped without result".into())),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) {
        let mut rng = SystemRng;
        let threshold = self.params.threshold();
        let ks: Vec<Vec<u8>> = self
            .params
            .parties()
            .iter()
            .map(|p| p.key.clone())
            .collect();
        let me_idx = self.params.party_index();

        let a_i_0 = random_scalar(&mut rng);
        let (vs, shares) = vss::create::<Ristretto255>(threshold, &a_i_0, &ks, &mut rng)
            .expect("committee checked in Keygen::new");

        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut session_nonce);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);

        let session = build_keygen_session(&ks[me_idx], &session_nonce);
        let pok = ZkProof::prove(&session, &a_i_0, &vs[0], &mut rng);
        let (schnorr_r, schnorr_t) = pok.to_wire();

        let r1 = KeygenRound1Msg {
            poly_commitments: vs
                .iter()
                .map(|p| B64Bytes(Ristretto255::encode_point(p).to_vec()))
                .collect(),
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
            st.ks = ks;
            st.my_r1_part = round1_part(&r1);
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

    fn round2(self: &Arc<Self>, others: &[PartyId], r1msgs: Vec<Message>) {
        let threshold = self.params.threshold();
        let mut rng = SystemRng;

        let mut parts: VecMap<Vec<u8>, Vec<u8>> = VecMap::new();
        for (pid, msg) in others.iter().zip(r1msgs.iter()) {
            let r1: KeygenRound1Msg = match decode(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let vsj = match self.verify_peer_round1(pid, &r1, threshold) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let key = strip(&pid.key).to_vec();
            parts.insert(key.clone(), round1_part(&r1));
            let mut st = self.state.lock();
            st.peer_eph_pubs.insert(key.clone(), to_arr32(&r1.eph_pub));
            st.peer_session_nonces
                .insert(key.clone(), to_arr16(&r1.session_nonce));
            st.peer_vs.insert(key, vsj);
        }

        // Seal under the lock (borrowing the private key and shares instead
        // of copying them out), send after releasing it: a synchronous broker
        // may run this party's handlers from inside `send_to`.
        let mut outbox = Vec::with_capacity(others.len());
        {
            let mut st = self.state.lock();
            let me = strip(&self.params.party_id().key);
            parts.insert(me.to_vec(), core::mem::take(&mut st.my_r1_part));
            st.transcript = round1_transcript(&self.params, &parts);
            for pid in others {
                let Some(share) = st.shares.iter().find(|s| cmp_eq(&s.id, &pid.key)) else {
                    drop(st);
                    return self
                        .deliver(Err(Error::Validation(format!("missing share for {pid}"))));
                };
                let recipient_pub = st
                    .peer_eph_pubs
                    .get(strip(&pid.key))
                    .expect("peer eph pub present");
                let ad = keygen_round2_ad(
                    &st.transcript,
                    &st.my_session_nonce,
                    &st.eph_pub,
                    recipient_pub,
                );
                match aead::seal_share(
                    &mut rng,
                    &st.eph_priv,
                    recipient_pub,
                    &ad,
                    &purecrypto::zeroize::Zeroizing::new(scalar_to_be(&share.value)),
                ) {
                    Ok(ciphertext) => outbox.push((pid, KeygenRound2Msg { ciphertext })),
                    Err(e) => {
                        drop(st);
                        return self
                            .deliver(Err(Error::Validation(format!("seal share to {pid}: {e}"))));
                    }
                }
            }
        }
        for (pid, r2) in &outbox {
            if let Err(e) = self.send_to(ROUND2_TYPE, r2, pid) {
                return self.deliver(Err(e));
            }
        }

        let me = Arc::clone(self);
        let others_owned = others.to_vec();
        let expect = JsonExpect::new(
            ROUND2_TYPE,
            others_owned.clone(),
            Box::new(move |msgs| me.finalize(&others_owned, msgs)),
        );
        self.params.broker().connect(ROUND2_TYPE, Arc::new(expect));
    }

    fn verify_peer_round1(
        &self,
        pid: &PartyId,
        r1: &KeygenRound1Msg,
        threshold: usize,
    ) -> Result<Vec<RistrettoPoint>, Error> {
        if r1.poly_commitments.len() != threshold + 1 {
            return Err(Error::Validation(format!(
                "party {pid} sent {} commitments, expected {}",
                r1.poly_commitments.len(),
                threshold + 1
            )));
        }
        if r1.session_nonce.len() != SESSION_NONCE_LEN {
            return Err(Error::Validation(format!(
                "party {pid} malformed session nonce"
            )));
        }
        if r1.eph_pub.len() != aead::EPHEMERAL_KEY_BYTES {
            return Err(Error::Validation(format!("party {pid} malformed eph pub")));
        }

        let mut vsj = Vec::with_capacity(r1.poly_commitments.len());
        for (k, enc) in r1.poly_commitments.iter().enumerate() {
            if enc.0.len() != COMMITMENT_BYTES {
                return Err(Error::Validation(format!(
                    "party {pid} commitment[{k}] wrong length"
                )));
            }
            let arr: [u8; 32] = enc.0.as_slice().try_into().unwrap();
            let p = Ristretto255::decode_point(&arr).ok_or_else(|| {
                Error::Validation(format!("party {pid} sent invalid commitment {k}"))
            })?;
            vsj.push(p);
        }
        if Ristretto255::is_identity(&vsj[0]) {
            return Err(Error::Validation(format!(
                "party {pid} phi_0 is the group identity (rogue-zero contribution)"
            )));
        }

        let session = build_keygen_session(&pid.key, &r1.session_nonce);
        let pok = ZkProof::from_wire(&r1.schnorr_r, &r1.schnorr_t)?;
        if !pok.verify(&session, &vsj[0]) {
            return Err(Error::Validation(format!(
                "party {pid} Schnorr PoK verification failed"
            )));
        }
        Ok(vsj)
    }

    fn finalize(self: &Arc<Self>, others: &[PartyId], r2msgs: Vec<Message>) {
        let threshold = self.params.threshold();
        let me_idx = self.params.party_index();
        let st = self.state.lock();

        let mut xi = st.shares[me_idx].value.clone();
        let my_id = &st.ks[me_idx];

        for (pid, msg) in others.iter().zip(r2msgs.iter()) {
            let key = strip(&pid.key);
            let Some(vsj) = st.peer_vs.get(key) else {
                return self.deliver(Err(Error::Validation(format!(
                    "share from {pid} had no matching round-1 commitments"
                ))));
            };
            let r2: KeygenRound2Msg = match decode(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let sender_nonce = st.peer_session_nonces.get(key).expect("peer nonce present");
            let sender_pub = st.peer_eph_pubs.get(key).expect("peer eph pub present");
            let ad = keygen_round2_ad(&st.transcript, sender_nonce, sender_pub, &st.eph_pub);
            let share_bytes = match aead::open_share(&st.eph_priv, sender_pub, &ad, &r2.ciphertext)
            {
                Ok(b) => b,
                Err(e) => {
                    return self.deliver(Err(Error::Validation(format!(
                        "share from {pid} failed to open: {e}"
                    ))));
                }
            };
            let share = scalar_from_be_mod_l(&share_bytes);
            if !vss::verify::<Ristretto255>(my_id, &share, threshold, vsj) {
                return self.deliver(Err(Error::Validation(format!(
                    "VSS share verification failed for {pid}"
                ))));
            }
            xi = xi.add(&share);
        }

        let mut vc = st.vs.clone();
        for vsj in st.peer_vs.values() {
            for c in 0..=threshold {
                vc[c] = Ristretto255::add(&vc[c], &vsj[c]);
            }
        }

        let mut big_xj = Vec::with_capacity(self.params.party_count());
        for p in self.params.parties() {
            let kj = scalar_from_be_mod_l(&p.key);
            let mut acc = vc[0];
            let mut z = Scalar::ONE;
            for vcc in vc.iter().take(threshold + 1).skip(1) {
                z = z.mul(&kj);
                acc = Ristretto255::add(&acc, &Ristretto255::scalar_mul(vcc, &z));
            }
            big_xj.push(acc);
        }

        let group_public_key = vc[0];
        if Ristretto255::is_identity(&group_public_key) {
            return self.deliver(Err(Error::Validation(
                "joint public key is the group identity".into(),
            )));
        }

        let ks: Vec<BigUintDec> = st.ks.iter().map(|k| BigUintDec::from_be_bytes(k)).collect();
        let share_id = BigUintDec::from_be_bytes(my_id);
        drop(st);

        self.deliver(Ok(Key {
            xi,
            share_id,
            ks,
            big_xj,
            group_public_key,
        }));
    }

    fn broadcast<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        let msg = encode(
            self.params.wire_format(),
            typ,
            body,
            Some(self.params.party_id().clone()),
            None,
        )?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }

    fn send_to<T: Serialize>(&self, typ: &str, body: &T, to: &PartyId) -> Result<(), Error> {
        let msg = encode(
            self.params.wire_format(),
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

fn build_keygen_session(party_key: &[u8], session_nonce: &[u8]) -> Vec<u8> {
    let pk = strip(party_key);
    let mut out = Vec::with_capacity(
        Ristretto255::context_string().len() + POK_TAG.len() + 1 + pk.len() + session_nonce.len(),
    );
    out.extend_from_slice(Ristretto255::context_string());
    out.extend_from_slice(POK_TAG);
    out.push(pk.len() as u8);
    out.extend_from_slice(pk);
    out.extend_from_slice(session_nonce);
    out
}

/// The round-2 AD binds the round-1 transcript, so parties holding different
/// views of the round-1 broadcasts cannot open each other's shares.
fn keygen_round2_ad(
    transcript: &[u8; 32],
    sender_nonce: &[u8],
    sender_pub: &[u8],
    recipient_pub: &[u8],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(
        AD_PREFIX.len() + sender_nonce.len() + sender_pub.len() + recipient_pub.len() + 35,
    );
    ad.extend_from_slice(AD_PREFIX);
    ad.extend_from_slice(sender_nonce);
    ad.push(b'|');
    ad.extend_from_slice(sender_pub);
    ad.push(b'|');
    ad.extend_from_slice(recipient_pub);
    ad.push(b'|');
    ad.extend_from_slice(transcript);
    ad
}

/// A round-1 payload in length-prefixed form, for the transcript.
fn round1_part(r1: &KeygenRound1Msg) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(r1.poly_commitments.len() as u32).to_be_bytes());
    for c in &r1.poly_commitments {
        lp(&mut buf, &c.0);
    }
    for f in [&r1.session_nonce, &r1.eph_pub, &r1.schnorr_r, &r1.schnorr_t] {
        lp(&mut buf, f);
    }
    buf
}

/// Hash of every party's round-1 payload (`parts`, keyed by stripped party
/// key), in committee order and domain-separated.
fn round1_transcript(params: &Parameters, parts: &VecMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let mut buf = Vec::new();
    lp(&mut buf, TRANSCRIPT_TAG);
    buf.extend_from_slice(&(params.threshold() as u32).to_be_bytes());
    buf.extend_from_slice(&(params.party_count() as u32).to_be_bytes());
    for p in params.parties() {
        let key = strip(&p.key);
        lp(&mut buf, key);
        lp(&mut buf, parts.get(key).map_or(&[][..], |v| v.as_slice()));
    }
    sha256(&buf)
}

/// Appends `b` with a 4-byte big-endian length prefix.
fn lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

fn cmp_eq(a: &[u8], b: &[u8]) -> bool {
    strip(a) == strip(b)
}

fn to_arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

fn to_arr16(b: &[u8]) -> [u8; SESSION_NONCE_LEN] {
    let mut a = [0u8; SESSION_NONCE_LEN];
    a.copy_from_slice(b);
    a
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
        let kgs: Vec<Keygen> = (0..ids.len())
            .map(|i| Keygen::new(Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i))).unwrap())
            .collect();
        kgs.iter()
            .map(|kg| kg.wait().expect("keygen succeeds"))
            .collect()
    }

    /// A dealer that sends one party a different higher-degree commitment
    /// than the others (the PoK only covers the constant term, so round 1
    /// verifies everywhere) must make keygen fail for every party, not just
    /// the one it lied to.
    #[test]
    fn round1_equivocation_aborts_everyone() {
        use crate::tss::testhub::BatchHub;
        let ids = party_ids(3);
        let hub = BatchHub::new(&ids);
        let sessions: Vec<Keygen> = (0..ids.len())
            .map(|i| Keygen::new(Parameters::new(ids.to_vec(), &ids[i], 1, hub.broker(i))).unwrap())
            .collect();
        // Party 0 tells party 1 that its degree-1 coefficient is a1 + 1.
        let tamper = |from: usize, to: usize, msg: &mut Message| {
            if from != 0 || to != 1 || msg.typ != ROUND1_TYPE {
                return;
            }
            let mut r1: KeygenRound1Msg = decode(msg).unwrap();
            let arr: [u8; 32] = r1.poly_commitments[1].0.as_slice().try_into().unwrap();
            let c1 = Ristretto255::decode_point(&arr).unwrap();
            let shifted = Ristretto255::add(&c1, &Ristretto255::generator());
            r1.poly_commitments[1] = B64Bytes(Ristretto255::encode_point(&shifted).to_vec());
            *msg = encode(
                msg.format(),
                &msg.typ,
                &r1,
                msg.from.clone(),
                msg.to.clone(),
            )
            .unwrap();
        };
        while hub.flush(Some(&tamper)) > 0 {}
        for (i, s) in sessions.iter().enumerate() {
            let r = s.try_result().expect("keygen finished");
            assert!(r.is_err(), "party {i} accepted an equivocated keygen");
        }
    }

    #[test]
    fn keygen_consistent_then_sign() {
        let ids = party_ids(3);
        let t = 1;
        let keys = run_keygen(&ids, t);
        for k in &keys {
            k.validate_basic().unwrap();
        }
        for k in &keys[1..] {
            assert!(Ristretto255::eq(
                &keys[0].group_public_key,
                &k.group_public_key
            ));
            assert_eq!(keys[0].ks, k.ks);
        }

        // keygen -> sign with a t+1 committee.
        let committee: Vec<PartyId> = ids[..t + 1].to_vec();
        let hub = TestHub::new(&committee);
        let msg = b"ristretto keygen then sign".to_vec();
        let sigs: Vec<_> = (0..committee.len())
            .map(|i| {
                let params = Parameters::new(committee.clone(), &committee[i], t, hub.broker(i));
                keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();
        for s in &sigs {
            let sig = s.wait().expect("signing succeeds");
            assert_eq!(sig.signature.len(), 64);
        }
    }

    /// The rogue-key attack on 3-of-3 (`n ≤ 2t`): the last dealer replaces its
    /// commitments with ones whose constant term is `a·G − Σ V_honest[0]`, for
    /// an `a` it knows. The forgery admits freely chosen shares for the honest
    /// parties and would make the joint key `a·G`; the dealer cannot prove
    /// knowledge of the forged constant term, so the honest parties refuse it.
    #[test]
    fn last_dealer_cannot_choose_the_key() {
        use crate::frost::scalar_from_be_mod_l;
        use std::sync::{Arc as StdArc, Mutex as StdMutex};
        type C = Ristretto255;

        let ids = party_ids(3);
        let t = 2;
        let xs = [
            scalar_from_be_mod_l(&ids[0].key),
            scalar_from_be_mod_l(&ids[1].key),
        ];
        let a = scalar_from_be_mod_l(&[0x42; 32]);
        let shares = [scalar_from_be_mod_l(&[7]), scalar_from_be_mod_l(&[9])];
        let honest_v0: StdArc<StdMutex<Vec<RistrettoPoint>>> = StdArc::default();
        let forged: StdArc<StdMutex<Option<Vec<RistrettoPoint>>>> = StdArc::default();

        let tamper = {
            let (honest_v0, forged) = (honest_v0.clone(), forged.clone());
            let (a, xs, shares) = (a.clone(), xs.clone(), shares.clone());
            move |from: usize, _to: usize, msg: &mut Message| {
                if msg.typ != ROUND1_TYPE {
                    return;
                }
                let mut r1: KeygenRound1Msg = msg.decode().unwrap();
                if from != 2 {
                    let v0 =
                        C::decode_point(&r1.poly_commitments[0].0.as_slice().try_into().unwrap())
                            .unwrap();
                    let mut h = honest_v0.lock().unwrap();
                    if !h.iter().any(|p| C::eq(p, &v0)) {
                        h.push(v0);
                    }
                    return;
                }
                // The attacker keeps its original proof: it cannot prove the
                // forged constant term.
                let vs = forged
                    .lock()
                    .unwrap()
                    .get_or_insert_with(|| {
                        vss::forge_rogue_commitments::<C>(
                            &a,
                            &xs,
                            &shares,
                            &honest_v0.lock().unwrap(),
                        )
                    })
                    .clone();
                r1.poly_commitments = vs
                    .iter()
                    .map(|p| B64Bytes(C::encode_point(p).to_vec()))
                    .collect();
                *msg = Message::encode(
                    msg.format(),
                    &msg.typ,
                    &r1,
                    msg.from.clone(),
                    msg.to.clone(),
                )
                .unwrap();
            }
        };
        let (results, _) = crate::tss::testhub::run_batched(
            &ids,
            t,
            Some(&tamper),
            |params| Keygen::new(params).unwrap(),
            Keygen::try_result,
        );

        // The forgery is complete: the chosen shares verify and the joint key
        // would be a·G.
        let vs = forged.lock().unwrap().clone().expect("attack ran");
        for i in 0..2 {
            assert!(vss::verify::<C>(&ids[i].key, &shares[i], t, &vs));
        }
        let joint = honest_v0
            .lock()
            .unwrap()
            .iter()
            .fold(vs[0], |acc, v| C::add(&acc, v));
        assert!(C::eq(&joint, &C::mul_base(&a)));

        // ...and the honest parties refuse it.
        for (i, r) in results.iter().take(2).enumerate() {
            let err = r
                .as_ref()
                .expect("honest parties finish")
                .as_ref()
                .err()
                .unwrap_or_else(|| panic!("honest party {i} accepted"));
            assert!(err.to_string().contains("PoK"), "party {i}: {err}");
        }
    }
}
