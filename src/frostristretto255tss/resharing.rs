//! FROST(ristretto255) resharing: move a key to a new committee while
//! preserving the group public key. Port of frostristretto255tss/resharing.go.
//!
//! Like the Ed25519 variant but: the round-3 sub-shares are encrypted (new
//! members publish a fresh ephemeral X25519 key + nonce in a round-2 ACK so old
//! dealers can seal each share), and the polynomial is committed with the
//! byte-based [`commit_elements`](super::commit::commit_elements).

use super::Error;
use super::commit::{commit_elements, verify_commit_elements};
use super::key::Key;
use super::schnorr::ZkProof;
use crate::frost::binding::lagrange_coefficient;
use crate::frost::{
    Ciphersuite, Ristretto255, Scalar, aead, encode_scalar, scalar_from_be_mod_l, vss,
};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, PartyId, ReSharingParameters, json_get, json_wrap};
use purecrypto::ec::ristretto255::RistrettoPoint;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const ROUND1: &str = "frost:ristretto255:reshare:round1";
const ROUND2: &str = "frost:ristretto255:reshare:round2";
const ROUND3_1: &str = "frost:ristretto255:reshare:round3-1";
const ROUND3_2: &str = "frost:ristretto255:reshare:round3-2";
const ROUND4: &str = "frost:ristretto255:reshare:round4";
const SESSION_NONCE_LEN: usize = 16;
const COMMITMENT_BYTES: usize = 32;
const POK_TAG: &[u8] = b"reshare-wi-pok";
const AD_PREFIX: &[u8] = b"frostristretto255tss/reshare/r3/v1|";

#[derive(Serialize, Deserialize)]
struct Round1Msg {
    #[serde(rename = "group_public_key", with = "crate::tss::b64::vec")]
    group_public_key: Vec<u8>,
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
    #[serde(rename = "v_decommitment")]
    v_decommitment: Vec<B64Bytes>,
}

#[derive(Serialize, Deserialize)]
struct Round4Msg {}

/// A resharing outcome: a fresh key for new-committee members, `None` for
/// old-only members.
type ReshareResult = Result<Option<Key>, Error>;

/// A running FROST(ristretto255) resharing session.
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
    new_shares: Vec<vss::Share>,
    v_decommit: Vec<u8>,
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
    new_eph_pubs: HashMap<Vec<u8>, [u8; 32]>,
    new_session_nonces: HashMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    // new member
    group_pub_key: Option<RistrettoPoint>,
    my_eph_priv: [u8; 32],
    my_eph_pub: [u8; 32],
    my_session_nonce: [u8; SESSION_NONCE_LEN],
    r1: Option<Vec<JsonMessage>>,
    r3m1: Option<Vec<JsonMessage>>,
    r3m2: Option<Vec<JsonMessage>>,
    round5_new_key: Option<Key>,
}

impl Resharing {
    /// Starts a resharing session. `input` is the old key for old-committee
    /// members and `None` for pure new members.
    pub fn new(params: ReSharingParameters, input: Option<Key>) -> Result<Resharing, Error> {
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            state: Mutex::new(State::default()),
            result_tx: Mutex::new(Some(tx)),
        });
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

    /// Blocks until resharing completes. `Some(key)` for new members, `None` otherwise.
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

    fn round1_old(self: &Arc<Self>, input: Key) -> Result<(), Error> {
        let mut rng = OsRng;
        let me = self.params.party_id().clone();
        let subset = input.subset_for_parties(self.params.old_parties())?;
        if self.params.old_threshold() + 1 > subset.ks.len() {
            return Err(Error::Validation(
                "t+1 not satisfied by old key count".into(),
            ));
        }

        let old_ks: Vec<Vec<u8>> = subset.ks.iter().map(|k| k.as_be_bytes().to_vec()).collect();
        let lambda = lagrange_coefficient::<Ristretto255>(&me.key, &old_ks)
            .ok_or_else(|| Error::Validation("duplicate old identifier".into()))?;
        let wi = subset.xi.mul(&lambda);

        let new_ks: Vec<Vec<u8>> = self
            .params
            .new_parties()
            .iter()
            .map(|p| p.key.clone())
            .collect();
        let (vi, new_shares) =
            vss::create::<Ristretto255>(self.params.new_threshold(), &wi, &new_ks, &mut rng);
        let (v_commitment, v_decommit) = commit_elements(&mut rng, &vi);
        let (eph_priv, eph_pub) = aead::new_ephemeral_key(&mut rng);

        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut session_nonce);
        let session = build_reshare_session(&me.key, &session_nonce);
        let pok = ZkProof::prove(&session, &wi, &vi[0], &mut rng);
        let (schnorr_r, schnorr_t) = pok.to_wire();

        let r1 = Round1Msg {
            group_public_key: Ristretto255::encode_point(&subset.group_public_key).to_vec(),
            vi0: Ristretto255::encode_point(&vi[0]).to_vec(),
            session_nonce: session_nonce.to_vec(),
            schnorr_r,
            schnorr_t,
            v_commitment,
        };

        {
            let mut st = self.state.lock().unwrap();
            st.new_shares = new_shares;
            st.v_decommit = v_decommit;
            st.eph_priv = eph_priv;
            st.eph_pub = eph_pub;
        }

        for pj in self.params.new_parties() {
            if pj.cmp_key(&me) != std::cmp::Ordering::Equal {
                self.send_to(ROUND1, &r1, pj)?;
            }
        }
        if self.params.is_new_committee() {
            self.send_to(ROUND1, &r1, &me)?;
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

    fn harvest_new_eph_keys(&self, others: &[PartyId], msgs: &[JsonMessage]) -> Result<(), Error> {
        let mut st = self.state.lock().unwrap();
        for (pid, msg) in others.iter().zip(msgs.iter()) {
            let r2: Round2Msg = json_get(msg)?;
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

    fn round2_new(self: &Arc<Self>, old_parties: &[PartyId], r1msgs: Vec<JsonMessage>) {
        let me = self.params.party_id().clone();
        let mut group_pub: Option<RistrettoPoint> = None;
        for (pid, msg) in old_parties.iter().zip(r1msgs.iter()) {
            let r1: Round1Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            if let Err(e) = verify_old_round1(pid, &r1, &mut group_pub) {
                return self.deliver(Err(e));
            }
        }

        // This new party's ephemeral key + nonce, so dealers can seal our share.
        let mut rng = OsRng;
        let (my_eph_priv, my_eph_pub) = aead::new_ephemeral_key(&mut rng);
        let mut my_nonce = [0u8; SESSION_NONCE_LEN];
        rng.fill_bytes(&mut my_nonce);
        {
            let mut st = self.state.lock().unwrap();
            st.group_pub_key = group_pub;
            st.r1 = Some(r1msgs);
            st.my_eph_priv = my_eph_priv;
            st.my_eph_pub = my_eph_pub;
            st.my_session_nonce = my_nonce;
            // Dual membership: seed our own entry for round3Old.
            if self.params.is_old_committee() {
                let key = strip(&me.key).to_vec();
                st.new_eph_pubs.insert(key.clone(), my_eph_pub);
                st.new_session_nonces.insert(key, my_nonce);
            }
        }

        let r2 = Round2Msg {
            eph_pub: my_eph_pub.to_vec(),
            session_nonce: my_nonce.to_vec(),
        };
        for pj in self.params.old_parties() {
            if pj.cmp_key(&me) != std::cmp::Ordering::Equal {
                if let Err(e) = self.send_to(ROUND2, &r2, pj) {
                    return self.deliver(Err(e));
                }
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
                me1.state.lock().unwrap().r3m1 = Some(msgs);
                me1.try_round4();
            }),
        );
        self.params.broker().connect(ROUND3_1, Arc::new(e1));

        let me2 = Arc::clone(self);
        let e2 = JsonExpect::new(
            ROUND3_2,
            old_parties,
            Box::new(move |msgs| {
                me2.state.lock().unwrap().r3m2 = Some(msgs);
                me2.try_round4();
            }),
        );
        self.params.broker().connect(ROUND3_2, Arc::new(e2));
    }

    fn round3_old(self: &Arc<Self>) {
        let mut rng = OsRng;
        let (new_shares, v_decommit, eph_priv, eph_pub, new_eph_pubs, new_nonces) = {
            let st = self.state.lock().unwrap();
            (
                st.new_shares.clone(),
                st.v_decommit.clone(),
                st.eph_priv,
                st.eph_pub,
                st.new_eph_pubs.clone(),
                st.new_session_nonces.clone(),
            )
        };

        for (pj, share) in self.params.new_parties().iter().zip(new_shares.iter()) {
            let key = strip(&pj.key);
            let (Some(recipient_pub), Some(recipient_nonce)) =
                (new_eph_pubs.get(key), new_nonces.get(key))
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "missing new-party eph key for {pj}"
                ))));
            };
            let ad = reshare_round3_ad(recipient_nonce, &eph_pub, recipient_pub);
            let ct = match aead::seal_share(
                &mut rng,
                &eph_priv,
                recipient_pub,
                &ad,
                &encode_scalar(&share.value),
            ) {
                Ok(ct) => ct,
                Err(e) => {
                    return self.deliver(Err(Error::Validation(format!(
                        "seal reshare share to {pj}: {e}"
                    ))));
                }
            };
            let r3m1 = Round3Msg1 {
                eph_pub: eph_pub.to_vec(),
                ciphertext: ct,
            };
            if let Err(e) = self.send_to(ROUND3_1, &r3m1, pj) {
                return self.deliver(Err(e));
            }
        }

        let chunks: Vec<B64Bytes> = v_decommit
            .chunks(32)
            .map(|c| B64Bytes(c.to_vec()))
            .collect();
        let r3m2 = Round3Msg2 {
            v_decommitment: chunks,
        };
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
            self.round5_old();
            return;
        }
        let me2 = Arc::clone(self);
        let expect = JsonExpect::new(ROUND4, new_others, Box::new(move |_| me2.round5_old()));
        self.params.broker().connect(ROUND4, Arc::new(expect));
    }

    fn try_round4(self: &Arc<Self>) {
        let ready = {
            let st = self.state.lock().unwrap();
            st.r1.is_some() && st.r3m1.is_some() && st.r3m2.is_some()
        };
        if ready {
            self.round4_new();
        }
    }

    fn round4_new(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let new_threshold = self.params.new_threshold();
        let old_parties = self.params.old_parties().to_vec();

        let (r1msgs, r3m1, r3m2, group_pub, my_eph_priv, my_eph_pub, my_nonce) = {
            let st = self.state.lock().unwrap();
            (
                st.r1.clone().unwrap(),
                st.r3m1.clone().unwrap(),
                st.r3m2.clone().unwrap(),
                st.group_pub_key.unwrap(),
                st.my_eph_priv,
                st.my_eph_pub,
                st.my_session_nonce,
            )
        };

        let mut new_xi = Scalar::ZERO;
        let mut vjc: Vec<Vec<RistrettoPoint>> = Vec::with_capacity(old_parties.len());

        for n in 0..old_parties.len() {
            let pid = &old_parties[n];
            let r1: Round1Msg = match json_get(&r1msgs[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let r3a: Round3Msg1 = match json_get(&r3m1[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let r3b: Round3Msg2 = match json_get(&r3m2[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };

            // Reassemble decommit bytes and open the commitment.
            let mut decommit = Vec::new();
            for chunk in &r3b.v_decommitment {
                decommit.extend_from_slice(&chunk.0);
            }
            let Some(vj) = verify_commit_elements(&r1.v_commitment, &decommit, new_threshold + 1)
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "commit verify failed for old party {pid}"
                ))));
            };

            // Cross-check round-1 Vi0 against the round-3 vi[0].
            let Some(vi0_r1) = decode_point(&r1.vi0) else {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} invalid Vi0"
                ))));
            };
            if !Ristretto255::eq(&vi0_r1, &vj[0]) {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} round-1 Vi0 disagrees with round-3 vi[0] (equivocation)"
                ))));
            }

            // Decrypt and verify the sub-share.
            if r3a.eph_pub.len() != aead::EPHEMERAL_KEY_BYTES {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} malformed eph pub"
                ))));
            }
            let sender_pub = to_arr32(&r3a.eph_pub);
            let ad = reshare_round3_ad(&my_nonce, &sender_pub, &my_eph_pub);
            let share_bytes =
                match aead::open_share(&my_eph_priv, &sender_pub, &ad, &r3a.ciphertext) {
                    Ok(b) => b,
                    Err(e) => {
                        return self.deliver(Err(Error::Validation(format!(
                            "old party {pid} share failed to open: {e}"
                        ))));
                    }
                };
            // The sealed share is a 32-byte little-endian scalar (encode_scalar).
            let Some(share) = share_bytes
                .as_slice()
                .try_into()
                .ok()
                .and_then(|a: [u8; 32]| crate::frost::decode_scalar(&a))
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "old party {pid} sent a malformed share scalar"
                ))));
            };
            if !vss::verify::<Ristretto255>(&me.key, &share, new_threshold, &vj) {
                return self.deliver(Err(Error::Validation(format!(
                    "VSS share verification failed for old party {pid}"
                ))));
            }
            new_xi = new_xi.add(&share);
            vjc.push(vj);
        }

        // Aggregate Vc; Vc[0] must equal the preserved public key.
        let mut vc = vjc[0].clone();
        for vj in &vjc[1..] {
            for c in 0..=new_threshold {
                vc[c] = Ristretto255::add(&vc[c], &vj[c]);
            }
        }
        if !Ristretto255::eq(&vc[0], &group_pub) {
            return self.deliver(Err(Error::Validation(
                "reconstructed public key != preserved GroupPublicKey".into(),
            )));
        }

        let mut big_xj = Vec::with_capacity(self.params.new_party_count());
        let mut new_ks = Vec::with_capacity(self.params.new_party_count());
        for pj in self.params.new_parties() {
            new_ks.push(BigUintDec::from_be_bytes(&pj.key));
            let kj = scalar_from_be_mod_l(&pj.key);
            let mut acc = vc[0];
            let mut z = Scalar::ONE;
            for vcc in vc.iter().take(new_threshold + 1).skip(1) {
                z = z.mul(&kj);
                acc = Ristretto255::add(&acc, &Ristretto255::scalar_mul(vcc, &z));
            }
            big_xj.push(acc);
        }

        let new_key = Key {
            xi: new_xi,
            share_id: BigUintDec::from_be_bytes(&me.key),
            ks: new_ks,
            big_xj,
            group_public_key: group_pub,
        };
        self.state.lock().unwrap().round5_new_key = Some(new_key.clone());

        let ack = Round4Msg {};
        for pj in self.params.old_and_new_parties() {
            if pj.cmp_key(&me) != std::cmp::Ordering::Equal {
                if let Err(e) = self.send_to(ROUND4, &ack, &pj) {
                    return self.deliver(Err(e));
                }
            }
        }

        if self.params.is_old_committee() {
            return; // round5_old delivers on the dual path
        }
        let new_others = self.new_others();
        if new_others.is_empty() {
            self.deliver(Ok(Some(new_key)));
            return;
        }
        let me2 = Arc::clone(self);
        let expect = JsonExpect::new(
            ROUND4,
            new_others,
            Box::new(move |_| {
                let k = me2.state.lock().unwrap().round5_new_key.clone();
                me2.deliver(Ok(k));
            }),
        );
        self.params.broker().connect(ROUND4, Arc::new(expect));
    }

    fn round5_old(self: &Arc<Self>) {
        let new_key = self.state.lock().unwrap().round5_new_key.clone();
        if self.params.is_new_committee() {
            self.deliver(Ok(new_key));
        } else {
            self.deliver(Ok(None));
        }
    }

    /// New-committee parties other than this one.
    fn new_others(&self) -> Vec<PartyId> {
        let me = self.params.party_id();
        self.params
            .new_parties()
            .iter()
            .filter(|p| p.cmp_key(me) != std::cmp::Ordering::Equal)
            .cloned()
            .collect()
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

fn verify_old_round1(
    pid: &PartyId,
    r1: &Round1Msg,
    group_pub: &mut Option<RistrettoPoint>,
) -> Result<(), Error> {
    let candidate = decode_point(&r1.group_public_key)
        .ok_or_else(|| Error::Validation(format!("party {pid} sent invalid GroupPublicKey")))?;
    match group_pub {
        None => *group_pub = Some(candidate),
        Some(p) if !Ristretto255::eq(p, &candidate) => {
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
        .ok_or_else(|| Error::Validation(format!("party {pid} invalid Vi0")))?;
    if Ristretto255::is_identity(&vi0) {
        return Err(Error::Validation(format!(
            "party {pid} Vi0 is the group identity"
        )));
    }
    let session = build_reshare_session(&pid.key, &r1.session_nonce);
    let pok = ZkProof::from_wire(&r1.schnorr_r, &r1.schnorr_t)?;
    if !pok.verify(&session, &vi0) {
        return Err(Error::Validation(format!(
            "party {pid} wi PoK verification failed"
        )));
    }
    Ok(())
}

fn build_reshare_session(party_key: &[u8], session_nonce: &[u8]) -> Vec<u8> {
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

fn decode_point(b: &[u8]) -> Option<RistrettoPoint> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Ristretto255::decode_point(&arr)
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
    use crate::frostristretto255tss::Keygen;
    use crate::tss::Parameters;
    use crate::tss::testhub::{ReshareHub, TestHub};

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

    #[test]
    fn reshare_preserves_key_and_signs() {
        let old_ids = ids(&[1, 2, 3]);
        let old_t = 1;
        let old_keys = keygen(&old_ids, old_t);
        let group_pub = old_keys[0].group_public_key;

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

        let mut new_keys: Vec<Key> = Vec::new();
        for (i, s) in sessions.iter().enumerate() {
            let r = s.wait().expect("resharing succeeds");
            if i < old_count {
                assert!(r.is_none());
            } else {
                let k = r.expect("new party receives a key");
                k.validate_basic().unwrap();
                assert!(Ristretto255::eq(&k.group_public_key, &group_pub));
                new_keys.push(k);
            }
        }

        // Sign with the new committee.
        let committee: Vec<PartyId> = new_ids[..new_t + 1].to_vec();
        let sign_hub = TestHub::new(&committee);
        let msg = b"post-reshare ristretto signature".to_vec();
        let signings: Vec<_> = (0..committee.len())
            .map(|i| {
                let params =
                    Parameters::new(committee.clone(), &committee[i], new_t, sign_hub.broker(i));
                new_keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();
        for s in &signings {
            s.wait().expect("post-reshare signing succeeds");
        }
    }
}
