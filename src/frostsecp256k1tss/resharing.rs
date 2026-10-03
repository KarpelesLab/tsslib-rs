//! FROST(secp256k1) resharing: move a key to a new committee (and/or
//! threshold) while keeping the group public key and chain code.
//!
//! Same flow as the ristretto255 variant:
//!
//! 1. Each old member scales its share to an additive piece `w_i = λ_i·s_i`,
//!    shares it to the new committee, and sends every new member the group
//!    key, chain code, `w_i·G` with a proof of knowledge, and a hash
//!    commitment to its Feldman commitments.
//! 2. New members check the old members agree, then publish an ephemeral
//!    X25519 key so the old members can seal their shares.
//! 3. Old members send each new member its sealed share and open the
//!    commitment.
//! 4. New members verify every share, sum them, check the result still
//!    interpolates to the group key, and acknowledge.

use super::Error;
use super::key::{Key, strip};
use super::suite::{
    Point, Scalar, TR, decode_point, decode_scalar, encode_point, id_scalar, is_identity,
    lagrange_coefficient, point_eq,
};
use super::vss::{self, ZkProof, commit_elements, open_elements};
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::share_aead as aead;
use crate::sync::{Mutex, Receiver, Sender, channel};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{Message, PartyId, ReSharingParameters, decode, encode};
use crate::vecmap::VecMap;
use alloc::sync::Arc;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const ROUND1: &str = "frost:secp256k1-tr:reshare:round1";
const ROUND2: &str = "frost:secp256k1-tr:reshare:round2";
const ROUND3_1: &str = "frost:secp256k1-tr:reshare:round3-1";
const ROUND3_2: &str = "frost:secp256k1-tr:reshare:round3-2";
const ROUND4: &str = "frost:secp256k1-tr:reshare:round4";
const SESSION_NONCE_LEN: usize = 16;
const POK_TAG: &[u8] = b"reshare-wi-pok";
const AD_PREFIX: &[u8] = b"frostsecp256k1tss/reshare/r3/v1|";

#[derive(Serialize, Deserialize)]
struct Round1Msg {
    #[serde(rename = "group_public_key", with = "crate::tss::b64::vec")]
    group_public_key: Vec<u8>,
    #[serde(rename = "chain_code", with = "crate::tss::b64::vec")]
    chain_code: Vec<u8>,
    #[serde(rename = "vi0", with = "crate::tss::b64::vec")]
    vi0: Vec<u8>,
    #[serde(rename = "session_nonce", with = "crate::tss::b64::vec")]
    session_nonce: Vec<u8>,
    #[serde(rename = "schnorr_r", with = "crate::tss::b64::vec")]
    schnorr_r: Vec<u8>,
    #[serde(rename = "schnorr_t", with = "crate::tss::b64::vec")]
    schnorr_t: Vec<u8>,
    #[serde(rename = "v_commitment", with = "crate::tss::b64::vec")]
    v_commitment: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Round2Msg {
    #[serde(rename = "eph_pub", with = "crate::tss::b64::vec")]
    eph_pub: Vec<u8>,
    #[serde(rename = "session_nonce", with = "crate::tss::b64::vec")]
    session_nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Round3Msg1 {
    #[serde(rename = "eph_pub", with = "crate::tss::b64::vec")]
    eph_pub: Vec<u8>,
    #[serde(rename = "ciphertext", with = "crate::tss::b64::vec")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Round3Msg2 {
    #[serde(rename = "v_randomness", with = "crate::tss::b64::vec")]
    v_randomness: Vec<u8>,
    #[serde(rename = "v_elements")]
    v_elements: Vec<B64Bytes>,
}

#[derive(Serialize, Deserialize)]
struct Round4Msg {}

/// A resharing outcome: the new key for new-committee members, `None` for
/// members of the old committee only.
type ReshareResult = Result<Option<Key>, Error>;

/// A running resharing session.
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
    // old dealer
    new_shares: Vec<Scalar>,
    v_elements: Vec<Point>,
    v_randomness: [u8; 32],
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    new_eph_pubs: VecMap<Vec<u8>, [u8; 32]>,
    new_session_nonces: VecMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    // new member
    group_pub_key: Option<Point>,
    chain_code: [u8; 32],
    my_eph_priv: [u8; 32],
    my_eph_pub: [u8; 32],
    my_session_nonce: [u8; SESSION_NONCE_LEN],
    r1: Option<Vec<Message>>,
    r3m1: Option<Vec<Message>>,
    r3m2: Option<Vec<Message>>,
    /// Set once `round4_new` is claimed, so it runs once even if the last
    /// round-3 messages land on two threads.
    round4_started: bool,
    new_key: Option<Key>,
    /// Dual (old+new) members: the other new members' ACKs are all in.
    acks_done: bool,
}

/// The X25519 private keys seal and open the share envelopes; wiped with the
/// session.
impl Drop for State {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.eph_priv);
        zeroize::Zeroize::zeroize(&mut self.my_eph_priv);
    }
}

impl Resharing {
    /// Starts a resharing session. `input` is the existing key for
    /// old-committee members and `None` for new-only members.
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
            // Sampled before any old-side round runs: a dual member's
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

    /// Non-blocking peek at the result: `Some(_)` once ready, `None` while
    /// rounds are pending.
    pub fn try_result(&self) -> Option<ReshareResult> {
        self.result_rx.try_recv().ok()
    }

    /// Blocks until resharing completes: `Some(key)` for new members, `None`
    /// for old-only members.
    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> ReshareResult {
        self.result_rx
            .recv()
            .unwrap_or_else(|_| Err(Error::Validation("resharing dropped without result".into())))
    }
}

impl Shared {
    fn deliver(&self, r: ReshareResult) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    fn fail(&self, m: impl Into<String>) {
        self.deliver(Err(Error::Validation(m.into())));
    }

    fn round1_old(self: &Arc<Self>, input: Key) -> Result<(), Error> {
        let mut rng = SystemRng;
        let me = self.params.party_id().clone();
        let subset = input.subset_for_parties(self.params.old_parties())?;

        let old_ids: Vec<Scalar> = subset
            .ks
            .iter()
            .map(|k| id_scalar(k.as_be_bytes()))
            .collect();
        let lambda = lagrange_coefficient(&id_scalar(&me.key), &old_ids)
            .ok_or_else(|| Error::Validation("duplicate old identifier".into()))?;
        let wi = subset.xi.mul(&lambda);

        let new_ks: Vec<Vec<u8>> = self
            .params
            .new_parties()
            .iter()
            .map(|p| p.key.clone())
            .collect();
        let (vi, new_shares) = vss::create(self.params.new_threshold(), &wi, &new_ks, &mut rng);
        if vi.iter().any(is_identity) {
            return Err(Error::Validation("zero resharing coefficient".into()));
        }
        let (v_commitment, v_randomness) = commit_elements(&mut rng, &vi);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);

        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut session_nonce);
        let session = pok_session(&me.key, &session_nonce);
        let (schnorr_r, schnorr_t) = ZkProof::prove(&session, &wi, &vi[0], &mut rng).to_wire();

        let r1 = Round1Msg {
            group_public_key: subset.compressed_public_key().to_vec(),
            chain_code: subset.chain_code.to_vec(),
            vi0: encode_point(&vi[0]).expect("checked above").to_vec(),
            session_nonce: session_nonce.to_vec(),
            schnorr_r,
            schnorr_t,
            v_commitment,
        };

        {
            let mut st = self.state.lock();
            st.new_shares = new_shares;
            st.v_elements = vi;
            st.v_randomness = v_randomness;
            st.eph_priv = eph_priv;
            st.eph_pub = eph_pub;
        }

        for pj in self.params.new_parties() {
            self.send_to(ROUND1, &r1, pj)?;
        }

        let new_others = self.new_others();
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

    fn harvest_new_eph_keys(&self, others: &[PartyId], msgs: &[Message]) -> Result<(), Error> {
        let mut st = self.state.lock();
        for (pid, msg) in others.iter().zip(msgs) {
            let r2: Round2Msg = decode(msg)?;
            let (Ok(eph_pub), Ok(nonce)) = (
                <[u8; 32]>::try_from(r2.eph_pub.as_slice()),
                <[u8; SESSION_NONCE_LEN]>::try_from(r2.session_nonce.as_slice()),
            ) else {
                return Err(Error::Validation(format!(
                    "new party {pid} sent malformed round-2 keys"
                )));
            };
            let key = strip(&pid.key).to_vec();
            st.new_eph_pubs.insert(key.clone(), eph_pub);
            st.new_session_nonces.insert(key, nonce);
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

    fn round2_new(self: &Arc<Self>, old_parties: &[PartyId], r1msgs: Vec<Message>) {
        let mut agreed: Option<(Point, [u8; 32])> = None;
        for (pid, msg) in old_parties.iter().zip(&r1msgs) {
            let r1: Round1Msg = match decode(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            if let Err(e) = verify_old_round1(pid, &r1, &mut agreed) {
                return self.deliver(Err(e));
            }
        }
        let Some((group_pub, chain_code)) = agreed else {
            return self.fail("no old committee members");
        };

        let (my_eph_pub, my_nonce) = {
            let mut st = self.state.lock();
            st.group_pub_key = Some(group_pub);
            st.chain_code = chain_code;
            st.r1 = Some(r1msgs);
            (st.my_eph_pub, st.my_session_nonce)
        };
        let r2 = Round2Msg {
            eph_pub: my_eph_pub.to_vec(),
            session_nonce: my_nonce.to_vec(),
        };
        let me = self.params.party_id();
        for pj in self.params.old_parties() {
            if pj.cmp_key(me) != core::cmp::Ordering::Equal
                && let Err(e) = self.send_to(ROUND2, &r2, pj)
            {
                return self.deliver(Err(e));
            }
        }
        self.setup_new_round3_receivers();
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

    fn round3_old(self: &Arc<Self>) {
        let mut rng = SystemRng;
        let mut sealed = Vec::with_capacity(self.params.new_party_count());
        let r3m2 = {
            let st = self.state.lock();
            for (pj, share) in self.params.new_parties().iter().zip(&st.new_shares) {
                let key = strip(&pj.key);
                let (Some(recipient_pub), Some(recipient_nonce)) =
                    (st.new_eph_pubs.get(key), st.new_session_nonces.get(key))
                else {
                    return self.fail(format!("missing ephemeral key for new party {pj}"));
                };
                let ad = round3_ad(recipient_nonce, &st.eph_pub, recipient_pub);
                let share = Zeroizing::new(share.to_bytes_be());
                match aead::seal_share(&mut rng, &st.eph_priv, recipient_pub, &ad, &*share) {
                    Ok(ciphertext) => sealed.push((
                        pj,
                        Round3Msg1 {
                            eph_pub: st.eph_pub.to_vec(),
                            ciphertext,
                        },
                    )),
                    Err(e) => return self.fail(format!("seal share to {pj}: {e}")),
                }
            }
            Round3Msg2 {
                v_randomness: st.v_randomness.to_vec(),
                v_elements: st
                    .v_elements
                    .iter()
                    .map(|p| B64Bytes(encode_point(p).expect("non-identity").to_vec()))
                    .collect(),
            }
        };
        for (pj, msg) in &sealed {
            if let Err(e) = self.send_to(ROUND3_1, msg, pj) {
                return self.deliver(Err(e));
            }
        }
        for pj in self.params.new_parties() {
            if let Err(e) = self.send_to(ROUND3_2, &r3m2, pj) {
                return self.deliver(Err(e));
            }
        }
        self.setup_old_round4_receiver();
    }

    fn setup_old_round4_receiver(self: &Arc<Self>) {
        let new_others = self.new_others();
        if new_others.is_empty() {
            return self.round5_old();
        }
        let me = Arc::clone(self);
        let expect = JsonExpect::new(ROUND4, new_others, Box::new(move |_| me.round5_old()));
        self.params.broker().connect(ROUND4, Arc::new(expect));
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

    fn round4_new(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let new_threshold = self.params.new_threshold();
        let old_parties = self.params.old_parties().to_vec();
        let (r1msgs, r3m1, r3m2, group_pub, chain_code, my_eph_priv, my_eph_pub, my_nonce) = {
            let mut st = self.state.lock();
            (
                st.r1.take().unwrap(),
                st.r3m1.take().unwrap(),
                st.r3m2.take().unwrap(),
                st.group_pub_key.unwrap(),
                st.chain_code,
                Zeroizing::new(st.my_eph_priv),
                st.my_eph_pub,
                st.my_session_nonce,
            )
        };

        let mut new_xi = Scalar::ZERO;
        let mut vc: Option<Vec<Point>> = None;
        for (n, pid) in old_parties.iter().enumerate() {
            let (r1, r3a, r3b) = match (
                decode::<Round1Msg>(&r1msgs[n]),
                decode::<Round3Msg1>(&r3m1[n]),
                decode::<Round3Msg2>(&r3m2[n]),
            ) {
                (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                    return self.deliver(Err(e.into()));
                }
            };
            let encoded: Vec<Vec<u8>> = r3b.v_elements.into_iter().map(|b| b.0).collect();
            let Some(vj) = open_elements(
                &r1.v_commitment,
                &r3b.v_randomness,
                &encoded,
                new_threshold + 1,
            ) else {
                return self.fail(format!("commitment from old party {pid} failed to open"));
            };
            if decode_point(&r1.vi0).is_none_or(|v| !point_eq(&v, &vj[0])) {
                return self.fail(format!(
                    "old party {pid} round-1 Vi0 disagrees with its round-3 commitments"
                ));
            }
            let Ok(sender_pub) = <[u8; 32]>::try_from(r3a.eph_pub.as_slice()) else {
                return self.fail(format!("old party {pid} sent a malformed ephemeral key"));
            };
            let ad = round3_ad(&my_nonce, &sender_pub, &my_eph_pub);
            let share = match aead::open_share(&my_eph_priv, &sender_pub, &ad, &r3a.ciphertext) {
                Ok(b) => decode_scalar(&b),
                Err(e) => {
                    return self.fail(format!("share from old party {pid} failed to open: {e}"));
                }
            };
            let Some(share) = share else {
                return self.fail(format!("old party {pid} sent an invalid share"));
            };
            if !vss::verify(&me.key, &share, new_threshold, &vj) {
                return self.fail(format!(
                    "share from old party {pid} failed VSS verification"
                ));
            }
            new_xi = new_xi.add(&share);
            vc = Some(match vc {
                None => vj,
                Some(acc) => acc.iter().zip(&vj).map(|(a, b)| a.add(b)).collect(),
            });
        }
        let vc = vc.expect("old committee is non-empty");
        if !point_eq(&vc[0], &group_pub) {
            return self.fail("reshared polynomial does not match the group public key");
        }

        let new_parties = self.params.new_parties();
        let new_key = Key {
            xi: new_xi,
            share_id: BigUintDec::from_be_bytes(&me.key),
            ks: new_parties
                .iter()
                .map(|p| BigUintDec::from_be_bytes(&p.key))
                .collect(),
            big_xj: new_parties
                .iter()
                .map(|p| vss::share_image(&id_scalar(&p.key), &vc))
                .collect(),
            group_public_key: group_pub,
            chain_code,
        };
        self.state.lock().new_key = Some(new_key.clone());

        for pj in self.params.old_and_new_parties() {
            if pj.cmp_key(&me) != core::cmp::Ordering::Equal
                && let Err(e) = self.send_to(ROUND4, &Round4Msg {}, &pj)
            {
                return self.deliver(Err(e));
            }
        }

        if self.params.is_old_committee() {
            // Dual member: whichever of `round4_new` / `round5_old` finishes
            // last delivers.
            if self.state.lock().acks_done {
                self.deliver(Ok(Some(new_key)));
            }
            return;
        }
        let new_others = self.new_others();
        if new_others.is_empty() {
            return self.deliver(Ok(Some(new_key)));
        }
        let me2 = Arc::clone(self);
        let expect = JsonExpect::new(
            ROUND4,
            new_others,
            Box::new(move |_| {
                let k = me2.state.lock().new_key.clone();
                me2.deliver(Ok(k));
            }),
        );
        self.params.broker().connect(ROUND4, Arc::new(expect));
    }

    fn round5_old(self: &Arc<Self>) {
        if !self.params.is_new_committee() {
            return self.deliver(Ok(None));
        }
        let new_key = {
            let mut st = self.state.lock();
            st.acks_done = true;
            st.new_key.clone()
        };
        if let Some(k) = new_key {
            self.deliver(Ok(Some(k)));
        }
    }

    /// New-committee members other than this party.
    fn new_others(&self) -> Vec<PartyId> {
        let me = self.params.party_id();
        self.params
            .new_parties()
            .iter()
            .filter(|p| p.cmp_key(me) != core::cmp::Ordering::Equal)
            .cloned()
            .collect()
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

/// Checks one old member's round-1 message and that it agrees with the
/// others on the group key and chain code.
fn verify_old_round1(
    pid: &PartyId,
    r1: &Round1Msg,
    agreed: &mut Option<(Point, [u8; 32])>,
) -> Result<(), Error> {
    let bad = |what: &str| Error::Validation(format!("old party {pid} sent {what}"));
    let group_pub =
        decode_point(&r1.group_public_key).ok_or_else(|| bad("an invalid group key"))?;
    let chain_code: [u8; 32] = r1
        .chain_code
        .as_slice()
        .try_into()
        .map_err(|_| bad("a malformed chain code"))?;
    match agreed {
        None => *agreed = Some((group_pub, chain_code)),
        Some((p, cc)) if !point_eq(p, &group_pub) || *cc != chain_code => {
            return Err(bad("a group key or chain code the others disagree with"));
        }
        _ => {}
    }
    if r1.session_nonce.len() != SESSION_NONCE_LEN {
        return Err(bad("a malformed session nonce"));
    }
    let vi0 = decode_point(&r1.vi0).ok_or_else(|| bad("an invalid Vi0"))?;
    let session = pok_session(&pid.key, &r1.session_nonce);
    if !ZkProof::from_wire(&r1.schnorr_r, &r1.schnorr_t)?.verify(&session, &vi0) {
        return Err(bad("a proof of knowledge that does not verify"));
    }
    Ok(())
}

fn pok_session(party_key: &[u8], session_nonce: &[u8]) -> Vec<u8> {
    let pk = strip(party_key);
    [TR.context(), POK_TAG, &[pk.len() as u8], pk, session_nonce].concat()
}

fn round3_ad(recipient_nonce: &[u8], sender_pub: &[u8], recipient_pub: &[u8]) -> Vec<u8> {
    [
        AD_PREFIX,
        recipient_nonce,
        b"|",
        sender_pub,
        b"|",
        recipient_pub,
    ]
    .concat()
}
