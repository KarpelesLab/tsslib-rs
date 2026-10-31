//! FROST Pedersen DKG (Komlo–Goldberg, eprint 2020/852), broker-driven.
//!
//! Round 1 broadcasts Feldman commitments, a fresh session nonce, an ephemeral
//! X25519 public key, and a Schnorr PoK of the constant coefficient. Round 2
//! sends each peer their secret share, sealed under the X25519+ChaCha20-Poly1305
//! envelope. Finalize verifies each share against its dealer's commitments and
//! aggregates into this party's [`Key`].
//!
//! # Broadcast consistency
//!
//! Round 1 is a broadcast, but the broker only promises per-sender
//! authenticity, not that every recipient saw the *same* message. A dealer that
//! keeps its constant term (so its PoK and the group key still check out) but
//! sends each peer a different higher-degree polynomial plus a matching share
//! would otherwise leave every party with the same address and mutually
//! inconsistent shares. To rule that out without an extra echo round, every
//! party hashes the full round-1 transcript it received (all parties' payloads,
//! its own included, in committee order) and binds that digest into the
//! associated data of every round-2 share envelope. Two honest parties whose
//! round-1 views differ cannot open each other's shares, so the session aborts.

use super::Error;
use super::key::Key;
use super::schnorr::ZkProof;
use crate::frost::aead;
use crate::frost::vss;
use crate::frost::{
    Ciphersuite, Ed25519, Scalar, random_scalar, scalar_from_be_mod_l, scalar_to_be,
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
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};

// `v2`: round-2 envelopes bind the round-1 transcript digest (wire change;
// v1 peers fail cleanly on the unknown message type).
const ROUND1_TYPE: &str = "frost:ed25519:keygen:v2:round1";
const ROUND2_TYPE: &str = "frost:ed25519:keygen:v2:round2";
const SESSION_NONCE_LEN: usize = 16;
const COMMITMENT_BYTES: usize = 32;
const SCALAR_BYTES: usize = 32;
const AD_PREFIX: &[u8] = b"frosttss/keygen/r2/v2|";
/// Domain tag of the round-1 transcript digest bound into the round-2 AD.
const TRANSCRIPT_TAG: &[u8] = b"frosttss/keygen/r1-transcript/v2";
const POK_TAG: &[u8] = b"dkg-pok";

/// Round-1 broadcast. Byte fields are base64.
#[derive(Clone, Serialize, Deserialize)]
struct KeygenRound1Msg {
    #[serde(rename = "poly_commitments")]
    poly_commitments: Vec<B64Bytes>,
    #[serde(rename = "session_nonce", with = "crate::tss::b64::vec")]
    session_nonce: Vec<u8>,
    #[serde(rename = "eph_pub", with = "crate::tss::b64::vec")]
    eph_pub: Vec<u8>,
    #[serde(rename = "schnorr_proof_alpha_x", with = "crate::tss::b64::vec")]
    schnorr_proof_alpha_x: Vec<u8>,
    #[serde(rename = "schnorr_proof_alpha_y", with = "crate::tss::b64::vec")]
    schnorr_proof_alpha_y: Vec<u8>,
    #[serde(rename = "schnorr_proof_t", with = "crate::tss::b64::vec")]
    schnorr_proof_t: Vec<u8>,
}

/// Round-2 point-to-point sealed share.
#[derive(Serialize, Deserialize)]
struct KeygenRound2Msg {
    #[serde(rename = "ciphertext", with = "crate::tss::b64::vec")]
    ciphertext: Vec<u8>,
}

/// A running FROST(Ed25519) key-generation session. Construct with
/// [`Keygen::new`]; retrieve the resulting [`Key`] with [`Keygen::wait`].
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
    vs: Vec<EdwardsPoint>,
    shares: Vec<vss::Share>,
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    my_session_nonce: [u8; SESSION_NONCE_LEN],
    /// Our own round-1 payload, hashed into the round-1 transcript.
    my_r1: Option<KeygenRound1Msg>,
    /// Digest of every party's round-1 payload, bound into the round-2 AD.
    transcript: [u8; 32],
    ks: Vec<Vec<u8>>,
    peer_eph_pubs: VecMap<Vec<u8>, [u8; 32]>,
    peer_session_nonces: VecMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    peer_vs: VecMap<Vec<u8>, Vec<EdwardsPoint>>,
}

/// The X25519 private key opens the share envelopes; wiped with the session.
impl Drop for State {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.eph_priv);
    }
}

impl Keygen {
    /// Starts the FROST Pedersen DKG for this party. Returns immediately after
    /// round 1 is broadcast; the result is delivered once all rounds complete.
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
                my_r1: None,
                transcript: [0u8; 32],
                ks: Vec::new(),
                peer_eph_pubs: VecMap::new(),
                peer_session_nonces: VecMap::new(),
                peer_vs: VecMap::new(),
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1();
        Ok(Keygen {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until the DKG completes, returning the generated key or an error.
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
            Err(_) => Err(Error::Validation(
                "keygen session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    /// Round 1: sample the polynomial, broadcast commitments + session nonce +
    /// ephemeral X25519 pub + a Schnorr PoK of the constant coefficient.
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
        let (vs, shares) = vss::create::<Ed25519>(threshold, &a_i_0, &ks, &mut rng)
            .expect("committee checked in Keygen::new");

        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut session_nonce);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);

        // Schnorr PoK of a_{i,0}, bound to phi_{i,0} = vs[0] and the session.
        let session = build_keygen_session(&ks[me_idx], &session_nonce);
        let pok = ZkProof::prove(&session, &a_i_0, &vs[0], &mut rng);
        let (alpha_x, alpha_y, t) = pok.to_wire();

        let r1 = KeygenRound1Msg {
            poly_commitments: vs
                .iter()
                .map(|p| B64Bytes(Ed25519::encode_point(p).to_vec()))
                .collect(),
            session_nonce: session_nonce.to_vec(),
            eph_pub: eph_pub.to_vec(),
            schnorr_proof_alpha_x: alpha_x,
            schnorr_proof_alpha_y: alpha_y,
            schnorr_proof_t: t,
        };

        {
            let mut st = self.state.lock();
            st.vs = vs;
            st.shares = shares;
            st.eph_priv = eph_priv;
            st.eph_pub = eph_pub;
            st.my_session_nonce = session_nonce;
            st.my_r1 = Some(r1.clone());
            st.ks = ks;
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

    /// Round 2: verify each peer's commitments + PoK, then seal and send each
    /// peer their share.
    fn round2(self: &Arc<Self>, others: &[PartyId], r1msgs: Vec<Message>) {
        let threshold = self.params.threshold();
        let mut rng = SystemRng;

        // Decode and verify every peer's round-1 message.
        let mut peer_r1s: Vec<KeygenRound1Msg> = Vec::with_capacity(others.len());
        for (pid, msg) in others.iter().zip(r1msgs.iter()) {
            // Round 1 is a broadcast: a copy addressed to us alone means the
            // sender (or the transport) is not broadcasting, so refuse it.
            if msg.to.is_some() {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent its round-1 broadcast point-to-point"
                ))));
            }
            let r1: KeygenRound1Msg = match decode(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let vsj = match self.verify_peer_round1(pid, &r1, threshold) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let key = strip(&pid.key).to_vec();
            let mut st = self.state.lock();
            st.peer_eph_pubs.insert(key.clone(), to_arr32(&r1.eph_pub));
            st.peer_session_nonces
                .insert(key.clone(), to_arr16(&r1.session_nonce));
            st.peer_vs.insert(key, vsj);
            drop(st);
            peer_r1s.push(r1);
        }

        // Digest our view of the whole round-1 broadcast, in committee order.
        let transcript = {
            let mut st = self.state.lock();
            let mine = st.my_r1.take().expect("round 1 ran");
            let me = self.params.party_id();
            let mut entries: Vec<(&[u8], &KeygenRound1Msg)> = Vec::new();
            let mut peers = others.iter().zip(peer_r1s.iter());
            for p in self.params.parties() {
                if p.cmp_key(me) == core::cmp::Ordering::Equal {
                    entries.push((&me.key, &mine));
                } else if let Some((pid, r1)) = peers.next() {
                    entries.push((&pid.key, r1));
                }
            }
            let t = keygen_transcript(threshold, &entries);
            st.transcript = t;
            t
        };

        // Seal and send each peer their P2P share. The X25519 private key is
        // used in place under the lock, so no unwiped copy of it is made.
        let (eph_pub, my_nonce) = {
            let st = self.state.lock();
            (st.eph_pub, st.my_session_nonce)
        };
        for pid in others {
            let sealed = {
                let st = self.state.lock();
                match st.shares.iter().find(|s| cmp_eq(&s.id, &pid.key)) {
                    None => Err(Error::Validation(format!("missing share for {pid}"))),
                    Some(share) => {
                        let recipient_pub = st
                            .peer_eph_pubs
                            .get(strip(&pid.key))
                            .expect("peer eph pub present");
                        let ad = keygen_round2_ad(&my_nonce, &eph_pub, recipient_pub, &transcript);
                        let plaintext = zeroize::Zeroizing::new(scalar_to_be(&share.value));
                        aead::seal_share(&mut rng, &st.eph_priv, recipient_pub, &ad, &plaintext)
                            .map_err(|e| Error::Validation(format!("seal share to {pid}: {e}")))
                    }
                }
            };
            let ct = match sealed {
                Ok(ct) => ct,
                Err(e) => return self.deliver(Err(e)),
            };
            let r2 = KeygenRound2Msg { ciphertext: ct };
            if let Err(e) = self.send_to(ROUND2_TYPE, &r2, pid) {
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

    /// Validates a peer's round-1 commitments and Schnorr PoK, returning the
    /// (cofactor-cleared) commitment vector.
    fn verify_peer_round1(
        &self,
        pid: &PartyId,
        r1: &KeygenRound1Msg,
        threshold: usize,
    ) -> Result<Vec<EdwardsPoint>, Error> {
        if r1.poly_commitments.len() != threshold + 1 {
            return Err(Error::Validation(format!(
                "party {pid} sent {} commitments, expected {}",
                r1.poly_commitments.len(),
                threshold + 1
            )));
        }
        if r1.session_nonce.len() != SESSION_NONCE_LEN {
            return Err(Error::Validation(format!(
                "party {pid} sent malformed session nonce"
            )));
        }
        if r1.eph_pub.len() != aead::EPHEMERAL_KEY_BYTES {
            return Err(Error::Validation(format!(
                "party {pid} sent malformed eph pub"
            )));
        }
        if r1.schnorr_proof_alpha_x.len() > COMMITMENT_BYTES
            || r1.schnorr_proof_alpha_y.len() > COMMITMENT_BYTES
            || r1.schnorr_proof_t.len() > SCALAR_BYTES
        {
            return Err(Error::Validation(format!(
                "party {pid} sent oversize Schnorr proof field"
            )));
        }

        let mut vsj = Vec::with_capacity(r1.poly_commitments.len());
        for (k, enc) in r1.poly_commitments.iter().enumerate() {
            if enc.0.len() != COMMITMENT_BYTES {
                return Err(Error::Validation(format!(
                    "party {pid} commitment[{k}] has wrong length"
                )));
            }
            let arr: [u8; 32] = enc.0.as_slice().try_into().unwrap();
            let p = Ed25519::decode_point(&arr).ok_or_else(|| {
                Error::Validation(format!("party {pid} sent invalid commitment {k}"))
            })?;
            vsj.push(p);
        }
        // Reject a rogue-zero contribution (phi_{j,0} == identity).
        if Ed25519::is_identity(&vsj[0]) {
            return Err(Error::Validation(format!(
                "party {pid} phi_0 is the curve identity (rogue-zero contribution)"
            )));
        }

        let session = build_keygen_session(&pid.key, &r1.session_nonce);
        let pok = ZkProof::from_wire(
            &r1.schnorr_proof_alpha_x,
            &r1.schnorr_proof_alpha_y,
            &r1.schnorr_proof_t,
        )?;
        if !pok.verify(&session, &vsj[0]) {
            return Err(Error::Validation(format!(
                "party {pid} Schnorr PoK verification failed"
            )));
        }
        Ok(vsj)
    }

    /// Finalize: decrypt + verify each peer's share, aggregate Xi, the
    /// verification shares BigXj, the group public key, and the chain code.
    fn finalize(self: &Arc<Self>, others: &[PartyId], r2msgs: Vec<Message>) {
        let threshold = self.params.threshold();
        let me_idx = self.params.party_index();
        let st = self.state.lock();

        // Xi starts with our own share to ourselves.
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
            let ad = keygen_round2_ad(sender_nonce, sender_pub, &st.eph_pub, &st.transcript);
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
            if !vss::verify::<Ed25519>(my_id, &share, threshold, vsj) {
                return self.deliver(Err(Error::Validation(format!(
                    "VSS share verification failed for {pid}"
                ))));
            }
            xi = xi.add(&share);
        }

        // Aggregate Feldman commitments column-wise: Vc[c] = Σ_j vs_j[c].
        let mut vc = st.vs.clone();
        for vsj in st.peer_vs.values() {
            for c in 0..=threshold {
                vc[c] = Ed25519::add(&vc[c], &vsj[c]);
            }
        }

        // BigXj for every party = Σ_c (k_j)^c · Vc[c].
        let mut big_xj = Vec::with_capacity(self.params.party_count());
        for p in self.params.parties() {
            let kj = scalar_from_be_mod_l(&p.key);
            let mut acc = vc[0];
            let mut z = Scalar::ONE;
            for vcc in vc.iter().take(threshold + 1).skip(1) {
                z = z.mul(&kj);
                acc = Ed25519::add(&acc, &Ed25519::scalar_mul(vcc, &z));
            }
            big_xj.push(acc);
        }

        let group_public_key = vc[0];
        if Ed25519::is_identity(&group_public_key) {
            return self.deliver(Err(Error::Validation(
                "joint public key is the curve identity".into(),
            )));
        }
        let chain_code = super::hd::derive_chain_code(&group_public_key);

        let ks: Vec<BigUintDec> = st.ks.iter().map(|k| BigUintDec::from_be_bytes(k)).collect();
        let share_id = BigUintDec::from_be_bytes(my_id);
        drop(st);

        self.deliver(Ok(Key {
            xi,
            share_id,
            ks,
            big_xj,
            group_public_key,
            chain_code: Some(chain_code),
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

/// Session string for the round-1 Schnorr PoK:
/// `context || "dkg-pok" || len(pk):u8 || pk || sessionNonce`.
fn build_keygen_session(party_key: &[u8], session_nonce: &[u8]) -> Vec<u8> {
    let pk = strip(party_key);
    let mut out = Vec::with_capacity(
        Ed25519::context_string().len() + POK_TAG.len() + 1 + pk.len() + session_nonce.len(),
    );
    out.extend_from_slice(Ed25519::context_string());
    out.extend_from_slice(POK_TAG);
    out.push(pk.len() as u8);
    out.extend_from_slice(pk);
    out.extend_from_slice(session_nonce);
    out
}

/// Associated data for the sealed round-2 share:
/// `"frosttss/keygen/r2/v2|" || senderNonce || "|" || senderPub || "|" ||
/// recipientPub || "|" || transcript`, where `transcript` is
/// [`keygen_transcript`] over the round-1 broadcast as this party saw it.
fn keygen_round2_ad(
    sender_nonce: &[u8],
    sender_pub: &[u8],
    recipient_pub: &[u8],
    transcript: &[u8; 32],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(
        AD_PREFIX.len()
            + sender_nonce.len()
            + sender_pub.len()
            + recipient_pub.len()
            + transcript.len()
            + 3,
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

/// Digest of the whole round-1 broadcast as one party received it: a
/// length-framed SHA-512/256 (`sha512_256_parts`) over the domain tag, the
/// threshold, the committee size, then for every party in committee order its
/// identifier followed by each round-1 field (commitment count, commitments,
/// session nonce, ephemeral key, PoK).
fn keygen_transcript(threshold: usize, entries: &[(&[u8], &KeygenRound1Msg)]) -> [u8; 32] {
    let t = (threshold as u64).to_le_bytes();
    let n = (entries.len() as u64).to_le_bytes();
    let counts: Vec<[u8; 8]> = entries
        .iter()
        .map(|(_, r1)| (r1.poly_commitments.len() as u64).to_le_bytes())
        .collect();
    let mut parts: Vec<&[u8]> = vec![TRANSCRIPT_TAG, &t, &n];
    for ((key, r1), count) in entries.iter().zip(counts.iter()) {
        parts.push(strip(key));
        parts.push(count);
        parts.extend(r1.poly_commitments.iter().map(|c| c.0.as_slice()));
        parts.push(&r1.session_nonce);
        parts.push(&r1.eph_pub);
        parts.push(&r1.schnorr_proof_alpha_x);
        parts.push(&r1.schnorr_proof_alpha_y);
        parts.push(&r1.schnorr_proof_t);
    }
    crate::tss::hashing::sha512_256_parts(&parts)
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
    use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};

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
        let keygens: Vec<Keygen> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                Keygen::new(params).unwrap()
            })
            .collect();
        keygens
            .iter()
            .map(|kg| kg.wait().expect("keygen succeeds"))
            .collect()
    }

    /// Records every message handed to it.
    struct Capture(std::sync::Mutex<Vec<Message>>);

    impl crate::tss::MessageReceiver for Capture {
        fn receive(&self, msg: &Message) -> crate::tss::BrokerResult {
            self.0.lock().unwrap().push(msg.clone());
            Ok(())
        }
    }

    /// Runs a 2-of-3 keygen whose party 0 is a hand-driven dealer. With
    /// `equivocate`, the dealer keeps one constant term (so its PoK and the
    /// group key are the same for everyone) but gives each honest party a
    /// different higher-degree polynomial with a matching share, sealing each
    /// share under the AD that recipient's own round-1 view yields. With
    /// `addressed`, its round-1 messages are sent point-to-point. Returns the
    /// two honest parties' results.
    fn run_with_dealer(equivocate: bool, addressed: bool) -> Vec<Result<Key, Error>> {
        let t = 1;
        let ids = party_ids(3);
        let hub = TestHub::new(&ids);
        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        hub.broker(0).connect(ROUND1_TYPE, capture.clone());
        let honest: Vec<Keygen> = (1..3)
            .map(|i| Keygen::new(Parameters::new(ids.clone(), &ids[i], t, hub.broker(i))).unwrap())
            .collect();
        let honest_r1: Vec<KeygenRound1Msg> = capture
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|m| decode(m).unwrap())
            .collect();
        assert_eq!(honest_r1.len(), 2);
        let wire = Parameters::new(ids.clone(), &ids[0], t, hub.broker(0)).wire_format();

        let mut rng = SystemRng;
        let ks: Vec<Vec<u8>> = ids.iter().map(|p| p.key.clone()).collect();
        let a0 = random_scalar(&mut rng);
        let mut nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);
        let common = vss::create::<Ed25519>(t, &a0, &ks, &mut rng).unwrap();
        let pok = ZkProof::prove(
            &build_keygen_session(&ks[0], &nonce),
            &a0,
            &common.0[0],
            &mut rng,
        );
        let (ax, ay, tt) = pok.to_wire();

        for j in 1..3 {
            let (vs, shares) = if equivocate {
                vss::create::<Ed25519>(t, &a0, &ks, &mut rng).unwrap()
            } else {
                (common.0.clone(), common.1.clone())
            };
            let r1 = KeygenRound1Msg {
                poly_commitments: vs
                    .iter()
                    .map(|p| B64Bytes(Ed25519::encode_point(p).to_vec()))
                    .collect(),
                session_nonce: nonce.to_vec(),
                eph_pub: eph_pub.to_vec(),
                schnorr_proof_alpha_x: ax.clone(),
                schnorr_proof_alpha_y: ay.clone(),
                schnorr_proof_t: tt.clone(),
            };
            let to = addressed.then(|| ids[j].clone());
            let m = encode(wire, ROUND1_TYPE, &r1, Some(ids[0].clone()), to).unwrap();
            let _ = hub.broker(j).receive(&m);

            // Seal party j's share exactly as party j will try to open it.
            let entries = [
                (ids[0].key.as_slice(), &r1),
                (ids[1].key.as_slice(), &honest_r1[0]),
                (ids[2].key.as_slice(), &honest_r1[1]),
            ];
            let transcript = keygen_transcript(t, &entries);
            let recipient_pub = to_arr32(&honest_r1[j - 1].eph_pub);
            let ad = keygen_round2_ad(&nonce, &eph_pub, &recipient_pub, &transcript);
            let ct = aead::seal_share(
                &mut rng,
                &eph_priv,
                &recipient_pub,
                &ad,
                &scalar_to_be(&shares[j].value),
            )
            .unwrap();
            let r2 = KeygenRound2Msg { ciphertext: ct };
            let m = encode(
                wire,
                ROUND2_TYPE,
                &r2,
                Some(ids[0].clone()),
                Some(ids[j].clone()),
            )
            .unwrap();
            let _ = hub.broker(j).receive(&m);
        }
        honest
            .iter()
            .map(|kg| kg.try_result().expect("keygen finished"))
            .collect()
    }

    #[test]
    fn hand_driven_honest_dealer_succeeds() {
        // Control for the tests below: the hand-driven dealer itself is sound.
        let keys: Vec<Key> = run_with_dealer(false, false)
            .into_iter()
            .map(|r| r.expect("honest dealer"))
            .collect();
        assert!(Ed25519::eq(
            &keys[0].group_public_key,
            &keys[1].group_public_key
        ));
        for (a, b) in keys[0].big_xj.iter().zip(keys[1].big_xj.iter()) {
            assert!(Ed25519::eq(a, b));
        }
    }

    #[test]
    fn equivocating_dealer_is_detected() {
        for r in run_with_dealer(true, false) {
            let e = r.err().expect("equivocation must abort keygen");
            assert!(format!("{e}").contains("failed to open"), "{e}");
        }
    }

    #[test]
    fn addressed_round1_broadcast_is_rejected() {
        for r in run_with_dealer(false, true) {
            let e = r.err().expect("point-to-point round 1 must abort keygen");
            assert!(format!("{e}").contains("point-to-point"), "{e}");
        }
    }

    #[test]
    fn keygen_produces_consistent_keys() {
        let ids = party_ids(3);
        let keys = run_keygen(&ids, 1);
        for k in &keys {
            k.validate_basic().unwrap();
        }
        // All parties agree on the public material.
        for k in &keys[1..] {
            assert!(Ed25519::eq(&keys[0].group_public_key, &k.group_public_key));
            assert_eq!(keys[0].ks, k.ks);
            assert_eq!(keys[0].chain_code, k.chain_code);
            assert_eq!(keys[0].big_xj.len(), k.big_xj.len());
            for (a, b) in keys[0].big_xj.iter().zip(k.big_xj.iter()) {
                assert!(Ed25519::eq(a, b));
            }
        }
        // Distinct secret shares.
        assert!(!bool::from(keys[0].xi.ct_eq(&keys[1].xi)));
    }

    #[test]
    fn keygen_then_sign_verifies() {
        let n = 3;
        let t = 1;
        let ids = party_ids(n);
        let keys = run_keygen(&ids, t);
        let group_pub = keys[0].group_public_key;

        // Sign with a t+1 committee.
        let committee = t + 1;
        let committee_ids: Vec<PartyId> = ids[..committee].to_vec();
        let hub = TestHub::new(&committee_ids);
        let msg = b"keygen then sign".to_vec();
        let signings: Vec<_> = (0..committee)
            .map(|i| {
                let params =
                    Parameters::new(committee_ids.clone(), &committee_ids[i], t, hub.broker(i));
                keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();

        let pk = Ed25519PublicKey::from_bytes(Ed25519::encode_point(&group_pub));
        for s in &signings {
            let sig = s.wait().expect("signing succeeds");
            let mut sb = [0u8; 64];
            sb.copy_from_slice(&sig.signature);
            pk.verify(&msg, &Ed25519Signature::from_bytes(sb))
                .expect("keygen+sign verifies under the DKG public key");
        }
    }

    #[test]
    fn keygen_2_of_4() {
        let ids = party_ids(4);
        let keys = run_keygen(&ids, 2);
        for k in &keys {
            k.validate_basic().unwrap();
        }
    }

    #[test]
    fn keygen_derive_child_then_sign_verifies_under_child_key() {
        let n = 3;
        let t = 1;
        let ids = party_ids(n);
        let keys = run_keygen(&ids, t);
        let path = [1u32, 5, 9];

        // Every party derives the same child public key from public inputs.
        let (_, child_pub, _) = keys[0].derive_child(&path).unwrap();
        for k in &keys[1..] {
            let (_, cp, _) = k.derive_child(&path).unwrap();
            assert!(Ed25519::eq(&cp, &child_pub));
        }

        // Sign under the derived child key with a t+1 committee.
        let committee = t + 1;
        let committee_ids: Vec<PartyId> = ids[..committee].to_vec();
        let hub = TestHub::new(&committee_ids);
        let msg = b"hd signing".to_vec();
        let signings: Vec<_> = (0..committee)
            .map(|i| {
                let params =
                    Parameters::new(committee_ids.clone(), &committee_ids[i], t, hub.broker(i));
                let (sg, _) = keys[i].derive_and_sign(&path, msg.clone(), params).unwrap();
                sg
            })
            .collect();

        let pk = Ed25519PublicKey::from_bytes(Ed25519::encode_point(&child_pub));
        for s in &signings {
            let sig = s.wait().expect("hd signing succeeds");
            let mut sb = [0u8; 64];
            sb.copy_from_slice(&sig.signature);
            pk.verify(&msg, &Ed25519Signature::from_bytes(sb))
                .expect("verifies under the derived child key");
        }
    }
}
