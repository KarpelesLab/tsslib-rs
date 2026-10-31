//! FROST(Ed25519) resharing: move a key from an old committee to a new one
//! while preserving the group public key.
//!
//! Old members Lagrange-weight their share (`wi`), VSS-share `wi` to the new
//! committee under a fresh polynomial, prove knowledge of `wi`, and commit to
//! the polynomial; the new committee verifies, sums the received sub-shares into
//! a fresh share, and reconstructs the same public key.
//!
//! The round-3 sub-shares travel sealed under the X25519+HKDF+ChaCha20-Poly1305
//! envelope ([`crate::share_aead`]): each new member publishes a fresh
//! ephemeral X25519 key and nonce in its round-2 ACK, and each old dealer seals
//! every sub-share to that key with its own per-run ephemeral key.
//!
//! Every message is point-to-point, so nothing stops an old dealer from showing
//! each new member a different polynomial with the same constant term (each
//! sub-share then verifies, and the group key checks out). To catch that, each
//! new member's round-4 ACK carries a digest of its view ([`ack_digest`]: group
//! key, chain code, both committees, every dealer's commitments). New members
//! compare it with their own, and old-only members only report success once
//! all new members sent the same digest; any mismatch aborts the session.

use super::Error;
use super::key::Key;
use super::point::{point_from_affine_be, point_to_affine_be};
use super::schnorr::ZkProof;
use crate::frost::binding::lagrange_coefficient;
use crate::frost::commitments;
use crate::frost::{
    Ciphersuite, Ed25519, Scalar, aead, decode_scalar, encode_scalar, scalar_from_be_mod_l, vss,
};
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::sync::{Mutex, Receiver, Sender, channel};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{Message, PartyId, ReSharingParameters, decode, encode};
use crate::vecmap::VecMap;
use alloc::sync::Arc;
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};

// `v2`: round-3 sub-shares are sealed and the round-4 ACK carries a
// consistency digest (wire change; v1 peers fail cleanly on the unknown type).
const ROUND1: &str = "frost:ed25519:reshare:v2:round1";
const ROUND2: &str = "frost:ed25519:reshare:v2:round2";
const ROUND3_1: &str = "frost:ed25519:reshare:v2:round3-1";
const ROUND3_2: &str = "frost:ed25519:reshare:v2:round3-2";
const ROUND4: &str = "frost:ed25519:reshare:v2:round4";
const SESSION_NONCE_LEN: usize = 16;
const COMMITMENT_BYTES: usize = 32;
const POK_TAG: &[u8] = b"reshare-wi-pok";
const AD_PREFIX: &[u8] = b"frosttss/reshare/r3/v2|";
const ACK_DIGEST_TAG: &[u8] = b"frosttss/reshare/ack-digest/v2";

#[derive(Serialize, Deserialize)]
struct Round1Msg {
    #[serde(rename = "group_public_key", with = "crate::tss::b64::vec")]
    group_public_key: Vec<u8>,
    #[serde(rename = "vi0", with = "crate::tss::b64::vec")]
    vi0: Vec<u8>,
    #[serde(rename = "session_nonce", with = "crate::tss::b64::vec")]
    session_nonce: Vec<u8>,
    #[serde(rename = "schnorr_proof_alpha_x", with = "crate::tss::b64::vec")]
    alpha_x: Vec<u8>,
    #[serde(rename = "schnorr_proof_alpha_y", with = "crate::tss::b64::vec")]
    alpha_y: Vec<u8>,
    #[serde(rename = "schnorr_proof_t", with = "crate::tss::b64::vec")]
    t: Vec<u8>,
    #[serde(rename = "v_commitment", with = "crate::tss::b64::vec")]
    v_commitment: Vec<u8>,
}

/// Round-2 ACK from a new member: its ephemeral X25519 key and nonce, so the
/// old dealers can seal its sub-shares.
#[derive(Serialize, Deserialize)]
struct Round2Msg {
    #[serde(rename = "eph_pub", with = "crate::tss::b64::vec")]
    eph_pub: Vec<u8>,
    #[serde(rename = "session_nonce", with = "crate::tss::b64::vec")]
    session_nonce: Vec<u8>,
}

/// Round-3 sub-share message: the dealer's ephemeral X25519 key and the
/// sub-share (32-byte little-endian scalar) sealed to the recipient.
#[derive(Serialize, Deserialize)]
struct Round3Msg1 {
    #[serde(rename = "eph_pub", with = "crate::tss::b64::vec")]
    eph_pub: Vec<u8>,
    #[serde(rename = "ciphertext", with = "crate::tss::b64::vec")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Round3Msg2 {
    #[serde(rename = "v_decommitment")]
    v_decommitment: Vec<B64Bytes>,
}

/// Round-4 ACK from a new member: [`ack_digest`] of its resharing view.
#[derive(Serialize, Deserialize)]
struct Round4Msg {
    #[serde(rename = "digest", with = "crate::tss::b64::vec")]
    digest: Vec<u8>,
}

/// A running FROST(Ed25519) resharing session. Construct with
/// [`Resharing::new`]; retrieve the result with [`Resharing::wait`]. New-committee
/// parties receive `Some(key)`; old-only parties receive `None`.
/// A resharing outcome: a fresh key for new-committee members, `None` for
/// old-only members.
type ReshareResult = Result<Option<Key>, Error>;

pub struct Resharing {
    result_rx: Receiver<ReshareResult>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: ReSharingParameters,
    state: Mutex<State>,
    result_tx: Mutex<Option<Sender<ReshareResult>>>,
}

#[derive(Default)]
struct State {
    // old side
    new_shares: Vec<vss::Share>,
    v_d: Vec<Vec<u8>>,
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    new_eph_pubs: VecMap<Vec<u8>, [u8; 32]>,
    new_session_nonces: VecMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    // new side
    group_pub_key: Option<EdwardsPoint>,
    my_eph_priv: [u8; 32],
    my_eph_pub: [u8; 32],
    my_session_nonce: [u8; SESSION_NONCE_LEN],
    r1: Option<Vec<Message>>,
    r3m1: Option<Vec<Message>>,
    r3m2: Option<Vec<Message>>,
    /// Set once `round4_new` has been claimed, so it runs exactly once even if
    /// the last round-3 messages land on two threads.
    round4_started: bool,
    round5_new_key: Option<Key>,
    /// New members: [`ack_digest`] of our own view, sent in our round-4 ACK.
    my_digest: Option<[u8; 32]>,
    /// The other new parties' round-4 digests, once all have arrived.
    peer_digests: Option<Vec<(PartyId, [u8; 32])>>,
}

/// The X25519 private keys seal and open the share envelopes; wiped with the session.
impl Drop for State {
    fn drop(&mut self) {
        purecrypto::zeroize::Zeroize::zeroize(&mut self.eph_priv);
        purecrypto::zeroize::Zeroize::zeroize(&mut self.my_eph_priv);
    }
}

impl Resharing {
    /// Starts a resharing session. `input` is the old key for old-committee
    /// members and `None` for pure new members.
    pub fn new(params: ReSharingParameters, input: Option<Key>) -> Result<Resharing, Error> {
        let keys = |ps: &[PartyId]| ps.iter().map(|p| p.key.clone()).collect::<Vec<_>>();
        vss::check_old_committee(params.old_threshold(), &keys(params.old_parties()))
            .map_err(|e| Error::Validation(format!("old committee: {e}")))?;
        vss::check_indexes(params.new_threshold(), &keys(params.new_parties()))
            .map_err(|e| Error::Validation(format!("new committee: {e}")))?;
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            state: Mutex::new(State::default()),
            result_tx: Mutex::new(Some(tx)),
        });
        if shared.params.is_new_committee() {
            // This new party's ephemeral key + nonce, so dealers can seal our
            // share. Sampled before any old-side round runs: a dual member's
            // `round3_old` seals to its own entry and may fire before
            // `round2_new` does.
            let mut rng = SystemRng;
            let (my_eph_priv, my_eph_pub) = aead::new_ephemeral_key(&mut rng);
            let mut my_nonce = [0u8; SESSION_NONCE_LEN];
            rng.fill_bytes(&mut my_nonce);
            let mut st = shared.state.lock();
            st.my_eph_priv = my_eph_priv;
            st.my_eph_pub = my_eph_pub;
            st.my_session_nonce = my_nonce;
            if shared.params.is_old_committee() {
                let key = strip(&shared.params.party_id().key).to_vec();
                st.new_eph_pubs.insert(key.clone(), my_eph_pub);
                st.new_session_nonces.insert(key, my_nonce);
            }
        }
        if shared.params.is_old_committee() {
            let key = input.ok_or_else(|| {
                Error::Validation("old-committee party requires its existing key".into())
            })?;
            shared.round1_old(key)?;
        }
        if shared.params.is_new_committee() {
            shared.setup_new_round1_receiver();
        }
        Ok(Resharing {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until resharing completes. `Some(key)` for new-committee members,
    /// `None` for old-only members.
    /// Non-blocking peek at the ceremony result: `Some(_)` once the result (or
    /// error) is ready, `None` while rounds are still pending. Unlike [`wait`](Self::wait)
    /// it never blocks, so a single-threaded async driver (e.g. wasm/browser) can
    /// poll it after feeding each inbound message.
    pub fn try_result(&self) -> Option<ReshareResult> {
        self.result_rx.try_recv().ok()
    }

    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> ReshareResult {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("resharing dropped without result".into())),
        }
    }
}

impl Shared {
    fn deliver(&self, r: ReshareResult) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    /// Round 1 (old): Lagrange-weight the share, VSS-share it to the new
    /// committee, broadcast commitments + PoK to all new parties.
    fn round1_old(self: &Arc<Self>, input: Key) -> Result<(), Error> {
        let mut rng = SystemRng;
        let me = self.params.party_id().clone();
        let subset = input.subset_for_parties(self.params.old_parties())?;
        if self.params.old_threshold() + 1 > subset.ks.len() {
            return Err(Error::Validation(
                "t+1 not satisfied by old key count".into(),
            ));
        }

        // wi = xi · λ_i over the old committee.
        let old_ks: Vec<Vec<u8>> = subset.ks.iter().map(|k| k.as_be_bytes().to_vec()).collect();
        let lambda = lagrange_coefficient::<Ed25519>(&me.key, &old_ks)
            .ok_or_else(|| Error::Validation("duplicate old identifier".into()))?;
        let wi = subset.xi.mul(&lambda);

        // VSS-share wi to the new committee.
        let new_ks: Vec<Vec<u8>> = self
            .params
            .new_parties()
            .iter()
            .map(|p| p.key.clone())
            .collect();
        let (vi, new_shares) =
            vss::create::<Ed25519>(self.params.new_threshold(), &wi, &new_ks, &mut rng)
                .map_err(|e| Error::Validation(format!("new committee: {e}")))?;

        // Commit to the flattened polynomial points; decommitment follows in round 3.
        let flat = flatten(&vi);
        let (v_commitment, v_d) = commitments::commit(&mut rng, &flat);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);

        // Schnorr PoK of wi bound to vi[0].
        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut session_nonce);
        let session = build_reshare_session(&me.key, &session_nonce);
        let pok = ZkProof::prove(&session, &wi, &vi[0], &mut rng);
        let (alpha_x, alpha_y, t) = pok.to_wire();

        let r1 = Round1Msg {
            group_public_key: Ed25519::encode_point(&subset.group_public_key).to_vec(),
            vi0: Ed25519::encode_point(&vi[0]).to_vec(),
            session_nonce: session_nonce.to_vec(),
            alpha_x,
            alpha_y,
            t,
            v_commitment,
        };

        {
            let mut st = self.state.lock();
            st.new_shares = new_shares;
            st.v_d = v_d;
            st.eph_priv = eph_priv;
            st.eph_pub = eph_pub;
        }

        // Send round 1 to every new party (and to self if dual-membership).
        for pj in self.params.new_parties() {
            if pj.cmp_key(&me) != core::cmp::Ordering::Equal {
                self.send_to(ROUND1, &r1, pj)?;
            }
        }
        if self.params.is_new_committee() {
            self.send_to(ROUND1, &r1, &me)?;
        }

        // Await round-2 ACKs from new parties, then send shares.
        let new_others: Vec<PartyId> = self
            .params
            .new_parties()
            .iter()
            .filter(|p| p.cmp_key(&me) != core::cmp::Ordering::Equal)
            .cloned()
            .collect();
        if new_others.is_empty() {
            self.round3_old();
        } else {
            let me2 = Arc::clone(self);
            let others = new_others.clone();
            let expect = JsonExpect::new(
                ROUND2,
                new_others,
                Box::new(move |msgs| {
                    if let Err(e) = me2.harvest_new_eph_keys(&others, &msgs) {
                        return me2.deliver(Err(e));
                    }
                    me2.round3_old();
                }),
            );
            self.params.broker().connect(ROUND2, Arc::new(expect));
        }
        Ok(())
    }

    /// Records each new party's round-2 ephemeral key and nonce.
    fn harvest_new_eph_keys(&self, others: &[PartyId], msgs: &[Message]) -> Result<(), Error> {
        let mut st = self.state.lock();
        for (pid, msg) in others.iter().zip(msgs.iter()) {
            let r2: Round2Msg = decode(msg)?;
            if r2.eph_pub.len() != aead::EPHEMERAL_KEY_BYTES
                || r2.session_nonce.len() != SESSION_NONCE_LEN
            {
                return Err(Error::Validation(format!(
                    "new party {pid} sent malformed round-2 keys"
                )));
            }
            let key = strip(&pid.key).to_vec();
            st.new_eph_pubs.insert(key.clone(), to_arr32(&r2.eph_pub));
            st.new_session_nonces
                .insert(key, to_arr16(&r2.session_nonce));
        }
        Ok(())
    }

    fn setup_new_round1_receiver(self: &Arc<Self>) {
        let me = Arc::clone(self);
        let old_parties = self.params.old_parties().to_vec();
        let expect = JsonExpect::new(
            ROUND1,
            old_parties.clone(),
            Box::new(move |msgs| me.round2_new(&old_parties, msgs)),
        );
        self.params.broker().connect(ROUND1, Arc::new(expect));
    }

    /// Round 2 (new): verify every old dealer's public key, Vi0, and PoK; ACK.
    fn round2_new(self: &Arc<Self>, old_parties: &[PartyId], r1msgs: Vec<Message>) {
        let me = self.params.party_id().clone();
        let mut group_pub: Option<EdwardsPoint> = None;

        for (pid, msg) in old_parties.iter().zip(r1msgs.iter()) {
            let r1: Round1Msg = match decode(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            if let Err(e) = self.verify_old_round1(pid, &r1, &mut group_pub) {
                return self.deliver(Err(e));
            }
        }
        // ACK every old party (except self if dual) with the ephemeral key +
        // nonce sampled in `Resharing::new`.
        let ack = {
            let mut st = self.state.lock();
            st.group_pub_key = group_pub;
            st.r1 = Some(r1msgs);
            Round2Msg {
                eph_pub: st.my_eph_pub.to_vec(),
                session_nonce: st.my_session_nonce.to_vec(),
            }
        };
        for pj in self.params.old_parties() {
            if pj.cmp_key(&me) != core::cmp::Ordering::Equal
                && let Err(e) = self.send_to(ROUND2, &ack, pj)
            {
                return self.deliver(Err(e));
            }
        }

        self.setup_new_round3_receivers();
    }

    fn verify_old_round1(
        &self,
        pid: &PartyId,
        r1: &Round1Msg,
        group_pub: &mut Option<EdwardsPoint>,
    ) -> Result<(), Error> {
        let candidate = decode_point(&r1.group_public_key)
            .ok_or_else(|| Error::Validation(format!("party {pid} sent invalid GroupPublicKey")))?;
        match group_pub {
            None => *group_pub = Some(candidate),
            Some(p) if !Ed25519::eq(p, &candidate) => {
                return Err(Error::Validation(format!(
                    "party {pid} sent inconsistent GroupPublicKey"
                )));
            }
            _ => {}
        }
        if r1.session_nonce.len() != SESSION_NONCE_LEN {
            return Err(Error::Validation(format!(
                "party {pid} malformed session nonce"
            )));
        }
        if r1.vi0.len() != COMMITMENT_BYTES {
            return Err(Error::Validation(format!("party {pid} malformed Vi0")));
        }
        let vi0 = decode_point(&r1.vi0)
            .ok_or_else(|| Error::Validation(format!("party {pid} sent invalid Vi0")))?;
        if Ed25519::is_identity(&vi0) {
            return Err(Error::Validation(format!(
                "party {pid} Vi0 is the curve identity"
            )));
        }
        let session = build_reshare_session(&pid.key, &r1.session_nonce);
        let pok = ZkProof::from_wire(&r1.alpha_x, &r1.alpha_y, &r1.t)?;
        if !pok.verify(&session, &vi0) {
            return Err(Error::Validation(format!(
                "party {pid} wi PoK verification failed"
            )));
        }
        Ok(())
    }

    fn setup_new_round3_receivers(self: &Arc<Self>) {
        let old_parties = self.params.old_parties().to_vec();
        let me1 = Arc::clone(self);
        let e1 = JsonExpect::new(
            ROUND3_1,
            old_parties.clone(),
            Box::new(move |msgs| {
                me1.state.lock().r3m1 = Some(msgs);
                me1.try_round4();
            }),
        );
        self.params.broker().connect(ROUND3_1, Arc::new(e1));

        let me2 = Arc::clone(self);
        let e2 = JsonExpect::new(
            ROUND3_2,
            old_parties,
            Box::new(move |msgs| {
                me2.state.lock().r3m2 = Some(msgs);
                me2.try_round4();
            }),
        );
        self.params.broker().connect(ROUND3_2, Arc::new(e2));
    }

    /// Round 3 (old): send each new party its sealed sub-share and the VSS
    /// decommitment.
    fn round3_old(self: &Arc<Self>) {
        let mut rng = SystemRng;
        let (v_d, eph_pub) = {
            let st = self.state.lock();
            (st.v_d.clone(), st.eph_pub)
        };
        for (n, pj) in self.params.new_parties().iter().enumerate() {
            // Seal under the lock so neither the sub-share nor the X25519
            // private key is copied out of the session state.
            let sealed = {
                let st = self.state.lock();
                let key = strip(&pj.key);
                match (
                    st.new_shares.get(n),
                    st.new_eph_pubs.get(key),
                    st.new_session_nonces.get(key),
                ) {
                    (Some(share), Some(recipient_pub), Some(recipient_nonce)) => {
                        let ad = reshare_round3_ad(recipient_nonce, &eph_pub, recipient_pub);
                        let plaintext =
                            purecrypto::zeroize::Zeroizing::new(encode_scalar(&share.value));
                        aead::seal_share(&mut rng, &st.eph_priv, recipient_pub, &ad, &*plaintext)
                            .map_err(|e| {
                                Error::Validation(format!("seal reshare share to {pj}: {e}"))
                            })
                    }
                    _ => Err(Error::Validation(format!(
                        "missing new-party share or eph key for {pj}"
                    ))),
                }
            };
            let m = match sealed {
                Ok(ciphertext) => Round3Msg1 {
                    eph_pub: eph_pub.to_vec(),
                    ciphertext,
                },
                Err(e) => return self.deliver(Err(e)),
            };
            if let Err(e) = self.send_to(ROUND3_1, &m, pj) {
                return self.deliver(Err(e));
            }
        }
        let r3m2 = Round3Msg2 {
            v_decommitment: v_d.iter().map(|b| B64Bytes(b.clone())).collect(),
        };
        for pj in self.params.new_parties() {
            if let Err(e) = self.send_to(ROUND3_2, &r3m2, pj) {
                return self.deliver(Err(e));
            }
        }
        self.setup_round4_receiver();
    }

    fn try_round4(self: &Arc<Self>) {
        let ready = {
            let mut st = self.state.lock();
            let ready =
                !st.round4_started && st.r1.is_some() && st.r3m1.is_some() && st.r3m2.is_some();
            st.round4_started |= ready;
            ready
        };
        if ready {
            self.round4_new();
        }
    }

    /// Round 4 (new): verify each old dealer's share + decommitment, sum into a
    /// fresh share, reconstruct the public key, ACK old+new.
    fn round4_new(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let new_threshold = self.params.new_threshold();
        let old_parties = self.params.old_parties().to_vec();

        let (r1msgs, r3m1, r3m2, group_pub, my_eph_pub, my_nonce) = {
            let mut st = self.state.lock();
            (
                st.r1.take().unwrap(),
                st.r3m1.take().unwrap(),
                st.r3m2.take().unwrap(),
                st.group_pub_key.unwrap(),
                st.my_eph_pub,
                st.my_session_nonce,
            )
        };

        let mut new_xi = Scalar::ZERO;
        let mut vjc: Vec<Vec<EdwardsPoint>> = Vec::with_capacity(old_parties.len());

        for n in 0..old_parties.len() {
            let pid = &old_parties[n];
            let r1: Round1Msg = match decode(&r1msgs[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let r3a: Round3Msg1 = match decode(&r3m1[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let r3b: Round3Msg2 = match decode(&r3m2[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };

            // Open the polynomial-points commitment.
            let d: Vec<Vec<u8>> = r3b.v_decommitment.iter().map(|b| b.0.clone()).collect();
            let Some(flat) = commitments::decommit(&r1.v_commitment, &d) else {
                return self.deliver(Err(Error::Validation(format!(
                    "decommitment verify failed for old party {pid}"
                ))));
            };
            if flat.len() != (new_threshold + 1) * 2 {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} sent wrong commitment width"
                ))));
            }
            let Some(vj) = unflatten(&flat) else {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} sent invalid polynomial points"
                ))));
            };

            // Cross-check round-1 Vi0 against the round-3 vi[0].
            let Some(vi0_r1) = decode_point(&r1.vi0) else {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} invalid Vi0"
                ))));
            };
            if !Ed25519::eq(&vi0_r1, &vj[0]) {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} round-1 Vi0 disagrees with round-3 vi[0] (equivocation)"
                ))));
            }

            // Open the sealed sub-share (a 32-byte little-endian scalar).
            if r3a.eph_pub.len() != aead::EPHEMERAL_KEY_BYTES {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} malformed eph pub"
                ))));
            }
            let sender_pub = to_arr32(&r3a.eph_pub);
            let ad = reshare_round3_ad(&my_nonce, &sender_pub, &my_eph_pub);
            let opened = {
                let st = self.state.lock();
                aead::open_share(&st.my_eph_priv, &sender_pub, &ad, &r3a.ciphertext)
            };
            let share_bytes = match opened {
                Ok(b) => b,
                Err(e) => {
                    return self.deliver(Err(Error::Validation(format!(
                        "old party {pid} share failed to open: {e}"
                    ))));
                }
            };
            let Some(share) = <[u8; 32]>::try_from(share_bytes.as_slice())
                .ok()
                .map(purecrypto::zeroize::Zeroizing::new)
                .and_then(|a| decode_scalar(&a))
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} sent a malformed share scalar"
                ))));
            };

            // Verify this party's sub-share against the dealer's commitments.
            if !vss::verify::<Ed25519>(&me.key, &share, new_threshold, &vj) {
                return self.deliver(Err(Error::Validation(format!(
                    "VSS share verification failed for old party {pid}"
                ))));
            }
            new_xi = new_xi.add(&share);
            vjc.push(vj);
        }

        // Aggregate Vc[c] = Σ_j vj[c]; Vc[0] must equal the preserved pubkey.
        let mut vc = vjc[0].clone();
        for vj in &vjc[1..] {
            for c in 0..=new_threshold {
                vc[c] = Ed25519::add(&vc[c], &vj[c]);
            }
        }
        if !Ed25519::eq(&vc[0], &group_pub) {
            return self.deliver(Err(Error::Validation(
                "reconstructed public key != preserved GroupPublicKey".into(),
            )));
        }

        // Derive every new party's verification share.
        let mut big_xj = Vec::with_capacity(self.params.new_party_count());
        let mut new_ks = Vec::with_capacity(self.params.new_party_count());
        for pj in self.params.new_parties() {
            new_ks.push(BigUintDec::from_be_bytes(&pj.key));
            let kj = scalar_from_be_mod_l(&pj.key);
            let mut acc = vc[0];
            let mut z = Scalar::ONE;
            for vcc in vc.iter().take(new_threshold + 1).skip(1) {
                z = z.mul(&kj);
                acc = Ed25519::add(&acc, &Ed25519::scalar_mul(vcc, &z));
            }
            big_xj.push(acc);
        }

        let new_key = Key {
            xi: new_xi,
            share_id: BigUintDec::from_be_bytes(&me.key),
            ks: new_ks,
            big_xj,
            group_public_key: group_pub,
            chain_code: Some(super::hd::derive_chain_code(&group_pub)),
        };
        let digest = ack_digest(
            &group_pub,
            &new_key.chain_code.expect("chain code set above"),
            self.params.old_parties(),
            self.params.old_threshold(),
            self.params.new_parties(),
            new_threshold,
            &vjc,
        );
        {
            let mut st = self.state.lock();
            st.round5_new_key = Some(new_key);
            st.my_digest = Some(digest);
        }

        // ACK all old+new parties (except self) with our view's digest.
        let ack = Round4Msg {
            digest: digest.to_vec(),
        };
        for pj in self.params.old_and_new_parties() {
            if pj.cmp_key(&me) != core::cmp::Ordering::Equal
                && let Err(e) = self.send_to(ROUND4, &ack, &pj)
            {
                return self.deliver(Err(e));
            }
        }

        // Old (and dual) members registered their ACK receiver in round 3.
        if !self.params.is_old_committee() {
            self.setup_round4_receiver();
        }
        self.try_finish();
    }

    /// Records the other new parties' round-4 digests, then tries to finish.
    fn on_round4_acks(self: &Arc<Self>, from: &[PartyId], msgs: &[Message]) {
        let mut digests = Vec::with_capacity(msgs.len());
        for (pid, msg) in from.iter().zip(msgs.iter()) {
            let r4: Round4Msg = match decode(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let Ok(d) = <[u8; 32]>::try_from(r4.digest.as_slice()) else {
                return self.deliver(Err(Error::Validation(format!(
                    "new party {pid} sent a malformed round-4 digest"
                ))));
            };
            digests.push((pid.clone(), d));
        }
        self.state.lock().peer_digests = Some(digests);
        self.try_finish();
    }

    /// Delivers the result once everything it depends on is in: the other new
    /// parties' digests and, for new members, our own key and digest. Every
    /// digest must agree: a dealer that showed different polynomials to
    /// different new parties makes their views (and so digests) differ.
    /// Old-only members succeed only once every new party confirmed the same
    /// view, so they never retire their share for an unusable resharing.
    fn try_finish(self: &Arc<Self>) {
        let outcome = {
            let st = self.state.lock();
            let Some(peers) = st.peer_digests.as_ref() else {
                return;
            };
            let expected = if self.params.is_new_committee() {
                match st.my_digest {
                    Some(d) => d,
                    None => return, // our own round 4 has not run yet
                }
            } else {
                match peers.first() {
                    Some((_, d)) => *d,
                    None => return,
                }
            };
            match peers.iter().find(|(_, d)| *d != expected) {
                Some((pid, _)) => Err(Error::Validation(format!(
                    "new party {pid} reported a different resharing view \
                     (inconsistent dealer commitments)"
                ))),
                None => Ok(st.round5_new_key.clone()),
            }
        };
        self.deliver(outcome);
    }

    /// Registers the round-4 ACK receiver (the other new parties' digests).
    fn setup_round4_receiver(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let new_others: Vec<PartyId> = self
            .params
            .new_parties()
            .iter()
            .filter(|p| p.cmp_key(&me) != core::cmp::Ordering::Equal)
            .cloned()
            .collect();
        if new_others.is_empty() {
            self.state.lock().peer_digests = Some(Vec::new());
            self.try_finish();
            return;
        }
        let me2 = Arc::clone(self);
        let from = new_others.clone();
        let expect = JsonExpect::new(
            ROUND4,
            new_others,
            Box::new(move |msgs| me2.on_round4_acks(&from, &msgs)),
        );
        self.params.broker().connect(ROUND4, Arc::new(expect));
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

/// Session string for the round-1 Schnorr PoK on `wi`.
fn build_reshare_session(party_key: &[u8], session_nonce: &[u8]) -> Vec<u8> {
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

/// Associated data for a sealed round-3 sub-share:
/// `"frosttss/reshare/r3/v2|" || recipientNonce || "|" || senderPub || "|" || recipientPub`.
fn reshare_round3_ad(recipient_nonce: &[u8], sender_pub: &[u8], recipient_pub: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(
        AD_PREFIX.len() + recipient_nonce.len() + sender_pub.len() + recipient_pub.len() + 2,
    );
    ad.extend_from_slice(AD_PREFIX);
    ad.extend_from_slice(recipient_nonce);
    ad.push(b'|');
    ad.extend_from_slice(sender_pub);
    ad.push(b'|');
    ad.extend_from_slice(recipient_pub);
    ad
}

/// Digest of a new member's view of the resharing, exchanged in the round-4
/// ACK: a length-framed SHA-512/256 (`sha512_256_parts`) over the domain tag,
/// the group key, the chain code, the old committee (threshold, identifiers),
/// the new committee (threshold, identifiers), then every old dealer's
/// polynomial commitments in committee order. Identical for all new members
/// exactly when every dealer showed each of them the same polynomial.
fn ack_digest(
    group_pub: &EdwardsPoint,
    chain_code: &[u8; 32],
    old_parties: &[PartyId],
    old_threshold: usize,
    new_parties: &[PartyId],
    new_threshold: usize,
    dealer_commitments: &[Vec<EdwardsPoint>],
) -> [u8; 32] {
    let gpk = Ed25519::encode_point(group_pub);
    let counts = [
        (old_threshold as u64).to_le_bytes(),
        (old_parties.len() as u64).to_le_bytes(),
        (new_threshold as u64).to_le_bytes(),
        (new_parties.len() as u64).to_le_bytes(),
        (dealer_commitments.len() as u64).to_le_bytes(),
    ];
    let points: Vec<Vec<[u8; 32]>> = dealer_commitments
        .iter()
        .map(|vj| vj.iter().map(Ed25519::encode_point).collect())
        .collect();
    let widths: Vec<[u8; 8]> = points
        .iter()
        .map(|vj| (vj.len() as u64).to_le_bytes())
        .collect();
    let mut parts: Vec<&[u8]> = vec![ACK_DIGEST_TAG, &gpk, chain_code, &counts[0], &counts[1]];
    parts.extend(old_parties.iter().map(|p| strip(&p.key)));
    parts.push(&counts[2]);
    parts.push(&counts[3]);
    parts.extend(new_parties.iter().map(|p| strip(&p.key)));
    parts.push(&counts[4]);
    for (vj, w) in points.iter().zip(widths.iter()) {
        parts.push(w);
        parts.extend(vj.iter().map(|p| p.as_slice()));
    }
    crate::tss::hashing::sha512_256_parts(&parts)
}

/// Flattens points to `[x0, y0, x1, y1, …]` big-endian affine coordinates.
fn flatten(points: &[EdwardsPoint]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(points.len() * 2);
    for p in points {
        let (x, y) = point_to_affine_be(p);
        out.push(x);
        out.push(y);
    }
    out
}

/// Inverse of [`flatten`]: rebuilds points from coordinate pairs, projecting
/// each into the prime-order subgroup like every other peer-supplied point
/// ([`Ciphersuite::decode_point`]); a no-op for honestly generated points.
fn unflatten(flat: &[Vec<u8>]) -> Option<Vec<EdwardsPoint>> {
    if !flat.len().is_multiple_of(2) {
        return None;
    }
    flat.chunks(2)
        .map(|c| {
            let p = point_from_affine_be(&c[0], &c[1]).ok()?;
            Ed25519::decode_point(&Ed25519::encode_point(&p))
        })
        .collect()
}

fn decode_point(b: &[u8]) -> Option<EdwardsPoint> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Ed25519::decode_point(&arr)
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
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
    use crate::frosttss::Keygen;
    use crate::tss::Parameters;
    use crate::tss::testhub::{ReshareHub, TestHub};
    use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};

    fn ids(keys: &[u8]) -> Vec<PartyId> {
        PartyId::sort(
            keys.iter()
                .map(|&k| PartyId::new(k.to_string(), format!("P{k}"), vec![k]))
                .collect(),
            0,
        )
    }

    fn keygen(ids: &[PartyId], t: usize) -> Vec<Key> {
        let hub = TestHub::new(ids);
        let kgs: Vec<Keygen> = (0..ids.len())
            .map(|i| Keygen::new(Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i))).unwrap())
            .collect();
        kgs.iter().map(|kg| kg.wait().unwrap()).collect()
    }

    /// Records every message handed to it.
    struct Capture(std::sync::Mutex<Vec<Message>>);

    impl crate::tss::MessageReceiver for Capture {
        fn receive(&self, msg: &Message) -> crate::tss::BrokerResult {
            self.0.lock().unwrap().push(msg.clone());
            Ok(())
        }
    }

    /// Reshares old {1,2,3} (1-of-3) to new {11,12,13} (1-of-3) where old
    /// party 1 is a hand-driven dealer. With `equivocate`, it gives each new
    /// party a different polynomial with the same constant term (so its PoK,
    /// Vi0 and the group key check out for everyone), with matching
    /// commitments, decommitment and sealed sub-share. Returns the honest old
    /// parties' and the new parties' results.
    fn reshare_with_dealer(equivocate: bool) -> (Vec<ReshareResult>, Vec<ReshareResult>) {
        let old_ids = ids(&[1, 2, 3]);
        let new_ids = ids(&[11, 12, 13]);
        let (old_t, new_t) = (1, 1);
        let old_keys = keygen(&old_ids, old_t);
        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        let hub = ReshareHub::new(&all);
        let params = |p: &PartyId| {
            ReSharingParameters::new(
                old_ids.clone(),
                new_ids.clone(),
                old_t,
                new_t,
                p.clone(),
                hub.broker(p),
            )
        };
        let dealer = &old_ids[0];
        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        hub.broker(dealer).connect(ROUND2, capture.clone());
        let wire = params(dealer).wire_format();

        let new_sessions: Vec<Resharing> = new_ids
            .iter()
            .map(|p| Resharing::new(params(p), None).unwrap())
            .collect();
        let old_sessions: Vec<Resharing> = (1..3)
            .map(|i| Resharing::new(params(&old_ids[i]), Some(old_keys[i].clone())).unwrap())
            .collect();

        // The dealer's round 1: one constant term, per-recipient polynomials.
        let mut rng = SystemRng;
        let old_ks: Vec<Vec<u8>> = old_ids.iter().map(|p| p.key.clone()).collect();
        let new_ks: Vec<Vec<u8>> = new_ids.iter().map(|p| p.key.clone()).collect();
        let lambda = lagrange_coefficient::<Ed25519>(&dealer.key, &old_ks).unwrap();
        let wi = old_keys[0].xi.mul(&lambda);
        let common = vss::create::<Ed25519>(new_t, &wi, &new_ks, &mut rng).unwrap();
        let mut nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let session = build_reshare_session(&dealer.key, &nonce);
        let (alpha_x, alpha_y, t) = ZkProof::prove(&session, &wi, &common.0[0], &mut rng).to_wire();
        let mut per_party = Vec::new();
        for (j, pj) in new_ids.iter().enumerate() {
            let (vi, shares) = if equivocate {
                vss::create::<Ed25519>(new_t, &wi, &new_ks, &mut rng).unwrap()
            } else {
                (common.0.clone(), common.1.clone())
            };
            let (v_commitment, v_d) = commitments::commit(&mut rng, &flatten(&vi));
            let r1 = Round1Msg {
                group_public_key: Ed25519::encode_point(&old_keys[0].group_public_key).to_vec(),
                vi0: Ed25519::encode_point(&vi[0]).to_vec(),
                session_nonce: nonce.to_vec(),
                alpha_x: alpha_x.clone(),
                alpha_y: alpha_y.clone(),
                t: t.clone(),
                v_commitment,
            };
            let m = encode(wire, ROUND1, &r1, Some(dealer.clone()), Some(pj.clone())).unwrap();
            let _ = hub.broker(pj).receive(&m);
            per_party.push((shares[j].value.clone(), v_d));
        }

        // The new parties' round-2 ACKs carry the keys to seal their shares to.
        let acks: Vec<Round2Msg> = capture
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|m| decode(m).unwrap())
            .collect();
        assert_eq!(acks.len(), new_ids.len());
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);
        for (j, pj) in new_ids.iter().enumerate() {
            let ack = &acks[j];
            let ad = reshare_round3_ad(&ack.session_nonce, &eph_pub, &ack.eph_pub);
            let recipient_pub = to_arr32(&ack.eph_pub);
            let (share, v_d) = &per_party[j];
            let ciphertext = aead::seal_share(
                &mut rng,
                &eph_priv,
                &recipient_pub,
                &ad,
                &encode_scalar(share),
            )
            .unwrap();
            let m1 = Round3Msg1 {
                eph_pub: eph_pub.to_vec(),
                ciphertext,
            };
            let m2 = Round3Msg2 {
                v_decommitment: v_d.iter().map(|b| B64Bytes(b.clone())).collect(),
            };
            for m in [
                encode(wire, ROUND3_1, &m1, Some(dealer.clone()), Some(pj.clone())).unwrap(),
                encode(wire, ROUND3_2, &m2, Some(dealer.clone()), Some(pj.clone())).unwrap(),
            ] {
                let _ = hub.broker(pj).receive(&m);
            }
        }

        let done = |s: &Resharing| s.try_result().expect("resharing finished");
        (
            old_sessions.iter().map(done).collect(),
            new_sessions.iter().map(done).collect(),
        )
    }

    #[test]
    fn hand_driven_honest_reshare_dealer_succeeds() {
        // Control for the test below: the hand-driven dealer itself is sound.
        let (old, new) = reshare_with_dealer(false);
        for r in old {
            assert!(r.expect("old party succeeds").is_none());
        }
        for r in new {
            r.expect("new party succeeds")
                .expect("new party gets a key")
                .validate_basic()
                .unwrap();
        }
    }

    #[test]
    fn equivocating_reshare_dealer_is_detected() {
        let (old, new) = reshare_with_dealer(true);
        // Old parties must not report success (and retire their shares).
        for r in old.into_iter().chain(new) {
            let e = r.err().expect("equivocation must abort resharing");
            assert!(format!("{e}").contains("different resharing view"), "{e}");
        }
    }

    #[test]
    fn reshare_3of_to_5of_preserves_key_and_signs() {
        // Old committee 1-of-3.
        let old_ids = ids(&[1, 2, 3]);
        let old_t = 1;
        let old_keys = keygen(&old_ids, old_t);
        let group_pub = old_keys[0].group_public_key;

        // Reshare to a disjoint new committee, 2-of-5.
        let new_ids = ids(&[11, 12, 13, 14, 15]);
        let new_t = 2;

        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        let hub = ReshareHub::new(&all);

        let mut sessions: Vec<Resharing> = Vec::new();
        for (i, p) in old_ids.iter().enumerate() {
            let params = ReSharingParameters::new(
                old_ids.clone(),
                new_ids.clone(),
                old_t,
                new_t,
                p.clone(),
                hub.broker(p),
            );
            sessions.push(Resharing::new(params, Some(old_keys[i].clone())).unwrap());
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
            sessions.push(Resharing::new(params, None).unwrap());
        }

        // Old parties get None; new parties get their fresh key.
        let mut new_keys: Vec<Key> = Vec::new();
        for (i, s) in sessions.iter().enumerate() {
            let r = s.wait().expect("resharing succeeds");
            if i < old_count {
                assert!(r.is_none(), "old party should receive no key");
            } else {
                let k = r.expect("new party receives a key");
                k.validate_basic().unwrap();
                assert!(
                    Ed25519::eq(&k.group_public_key, &group_pub),
                    "public key preserved"
                );
                new_keys.push(k);
            }
        }

        // Sign with a new-committee subset (t+1 = 3) and verify under the
        // preserved public key.
        let committee: Vec<PartyId> = new_ids[..new_t + 1].to_vec();
        let sign_hub = TestHub::new(&committee);
        let msg = b"post-reshare signature".to_vec();
        let signings: Vec<_> = (0..committee.len())
            .map(|i| {
                let params =
                    Parameters::new(committee.clone(), &committee[i], new_t, sign_hub.broker(i));
                new_keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();
        let pk = Ed25519PublicKey::from_bytes(Ed25519::encode_point(&group_pub));
        for s in &signings {
            let sig = s.wait().expect("signing succeeds");
            let mut sb = [0u8; 64];
            sb.copy_from_slice(&sig.signature);
            pk.verify(&msg, &Ed25519Signature::from_bytes(sb))
                .expect("post-reshare signature verifies under preserved key");
        }
    }

    /// `import_key`'s 1-of-1 output is a valid sole old committee
    /// (threshold 0): reshare it to 2-of-3 and sign under the original key.
    #[test]
    fn import_then_reshare_then_sign() {
        let secret = crate::frost::random_scalar(&mut crate::rng::SystemRng);
        let dealer = PartyId::new("100", "dealer", vec![100]);
        let imported = crate::frosttss::import_key(&secret, &dealer).unwrap();
        let group_pub = imported.group_public_key;
        let old_ids = vec![dealer.clone()];
        let new_ids = ids(&[1, 2, 3]);
        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        let hub = ReshareHub::new(&all);
        let params = |p: &PartyId| {
            ReSharingParameters::new(
                old_ids.clone(),
                new_ids.clone(),
                0,
                1,
                p.clone(),
                hub.broker(p),
            )
        };
        let dealer_session = Resharing::new(params(&dealer), Some(imported)).unwrap();
        let sessions: Vec<Resharing> = new_ids
            .iter()
            .map(|p| Resharing::new(params(p), None).unwrap())
            .collect();
        assert!(dealer_session.wait().unwrap().is_none());
        let keys: Vec<Key> = sessions
            .iter()
            .map(|s| s.wait().unwrap().expect("new party receives a key"))
            .collect();

        let committee = new_ids[..2].to_vec();
        let sign_hub = TestHub::new(&committee);
        let msg = b"imported, reshared, signed".to_vec();
        let signings: Vec<_> = (0..2)
            .map(|i| {
                let params =
                    Parameters::new(committee.clone(), &committee[i], 1, sign_hub.broker(i));
                keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();
        let pk = Ed25519PublicKey::from_bytes(Ed25519::encode_point(&group_pub));
        for s in &signings {
            let sig = s.wait().expect("signing succeeds");
            pk.verify(
                &msg,
                &Ed25519Signature::from_bytes(sig.signature.try_into().unwrap()),
            )
            .expect("verifies under the imported key");
        }
    }

    /// Every start order of an overlapping old {1,2,3} → new {2,3,4} reshare
    /// must hand each new member (dual or not) its key and each old-only member
    /// `None`. The hub is synchronous, so the start order is the message order.
    #[test]
    fn reshare_overlapping_committees_any_start_order() {
        let old_ids = ids(&[1, 2, 3]);
        let new_ids = ids(&[2, 3, 4]);
        let old_keys = keygen(&old_ids, 1);
        let group_pub = old_keys[0].group_public_key;
        let all = ids(&[1, 2, 3, 4]);

        // All 24 permutations of the four participants.
        let mut orders: Vec<Vec<usize>> = vec![vec![]];
        for _ in 0..all.len() {
            orders = orders
                .into_iter()
                .flat_map(|o| {
                    (0..all.len())
                        .filter(|i| !o.contains(i))
                        .map(|i| [o.clone(), vec![i]].concat())
                        .collect::<Vec<_>>()
                })
                .collect();
        }

        for order in orders {
            let hub = ReshareHub::new(&all);
            let sessions: Vec<(usize, Resharing)> = order
                .iter()
                .map(|&i| {
                    let p = &all[i];
                    let params = ReSharingParameters::new(
                        old_ids.clone(),
                        new_ids.clone(),
                        1,
                        1,
                        p.clone(),
                        hub.broker(p),
                    );
                    let input = old_ids
                        .iter()
                        .position(|o| o.cmp_key(p) == core::cmp::Ordering::Equal)
                        .map(|j| old_keys[j].clone());
                    (i, Resharing::new(params, input).unwrap())
                })
                .collect();
            for (i, s) in &sessions {
                let r = s
                    .try_result()
                    .unwrap_or_else(|| panic!("order {order:?}: party {i} has no result"))
                    .unwrap_or_else(|e| panic!("order {order:?}: party {i} failed: {e}"));
                let is_new = new_ids
                    .iter()
                    .any(|n| n.cmp_key(&all[*i]) == core::cmp::Ordering::Equal);
                assert_eq!(r.is_some(), is_new, "order {order:?}: party {i}");
                if let Some(k) = r {
                    k.validate_basic().unwrap();
                    assert!(Ed25519::eq(&k.group_public_key, &group_pub));
                }
            }
        }
    }
}
