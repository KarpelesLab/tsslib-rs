//! FROST(Ed25519) resharing: move a key from an old committee to a new one
//! while preserving the group public key. Port of frosttss/resharing.go.
//!
//! Old members Lagrange-weight their share (`wi`), VSS-share `wi` to the new
//! committee under a fresh polynomial, prove knowledge of `wi`, and commit to
//! the polynomial; the new committee verifies, sums the received sub-shares into
//! a fresh share, and reconstructs the same public key.

use super::Error;
use super::key::Key;
use super::point::{point_from_affine_be, point_to_affine_be};
use super::schnorr::ZkProof;
use crate::frost::binding::lagrange_coefficient;
use crate::frost::commitments;
use crate::frost::{Ciphersuite, Ed25519, Scalar, scalar_from_be_mod_l, scalar_to_be, vss};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, PartyId, ReSharingParameters, json_get, json_wrap};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const ROUND1: &str = "frost:ed25519:reshare:round1";
const ROUND2: &str = "frost:ed25519:reshare:round2";
const ROUND3_1: &str = "frost:ed25519:reshare:round3-1";
const ROUND3_2: &str = "frost:ed25519:reshare:round3-2";
const ROUND4: &str = "frost:ed25519:reshare:round4";
const SESSION_NONCE_LEN: usize = 16;
const COMMITMENT_BYTES: usize = 32;
const POK_TAG: &[u8] = b"reshare-wi-pok";

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

#[derive(Serialize, Deserialize)]
struct Round2Msg {}

/// Round-3 sub-share message. The share is sent in **cleartext** and relies on
/// the broker's per-recipient confidentiality (see the `frosttss` module docs);
/// it is *not* wrapped in the X25519+ChaCha20-Poly1305 envelope that keygen and
/// the `frostristretto255tss` resharing use. This is byte-compatible with the Go
/// `frosttss` resharing (`resharing.go`, `round3Old`); encrypting it would change
/// the wire format and is deferred to a coordinated Go+Rust change.
#[derive(Serialize, Deserialize)]
struct Round3Msg1 {
    #[serde(rename = "share", with = "crate::tss::b64::vec")]
    share: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Round3Msg2 {
    #[serde(rename = "v_decommitment")]
    v_decommitment: Vec<B64Bytes>,
}

#[derive(Serialize, Deserialize)]
struct Round4Msg {}

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
    // new side
    group_pub_key: Option<EdwardsPoint>,
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

    /// Blocks until resharing completes. `Some(key)` for new-committee members,
    /// `None` for old-only members.
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

    /// Round 1 (old): Lagrange-weight the share, VSS-share it to the new
    /// committee, broadcast commitments + PoK to all new parties.
    fn round1_old(self: &Arc<Self>, input: Key) -> Result<(), Error> {
        let mut rng = OsRng;
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
            vss::create::<Ed25519>(self.params.new_threshold(), &wi, &new_ks, &mut rng);

        // Commit to the flattened polynomial points; decommitment follows in round 3.
        let flat = flatten(&vi);
        let (v_commitment, v_d) = commitments::commit(&mut rng, &flat);

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
            let mut st = self.state.lock().unwrap();
            st.new_shares = new_shares;
            st.v_d = v_d;
        }

        // Send round 1 to every new party (and to self if dual-membership).
        for pj in self.params.new_parties() {
            if pj.cmp_key(&me) != std::cmp::Ordering::Equal {
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
            .filter(|p| p.cmp_key(&me) != std::cmp::Ordering::Equal)
            .cloned()
            .collect();
        if new_others.is_empty() {
            self.round3_old();
        } else {
            let me2 = Arc::clone(self);
            let expect = JsonExpect::new(ROUND2, new_others, Box::new(move |_| me2.round3_old()));
            self.params.broker().connect(ROUND2, Arc::new(expect));
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
    fn round2_new(self: &Arc<Self>, old_parties: &[PartyId], r1msgs: Vec<JsonMessage>) {
        let me = self.params.party_id().clone();
        let mut group_pub: Option<EdwardsPoint> = None;

        for (pid, msg) in old_parties.iter().zip(r1msgs.iter()) {
            let r1: Round1Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            if let Err(e) = self.verify_old_round1(pid, &r1, &mut group_pub) {
                return self.deliver(Err(e));
            }
        }
        {
            let mut st = self.state.lock().unwrap();
            st.group_pub_key = group_pub;
            st.r1 = Some(r1msgs);
        }

        // ACK every old party (except self if dual).
        let ack = Round2Msg {};
        for pj in self.params.old_parties() {
            if pj.cmp_key(&me) != std::cmp::Ordering::Equal {
                if let Err(e) = self.send_to(ROUND2, &ack, pj) {
                    return self.deliver(Err(e));
                }
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

    /// Round 3 (old): send each new party its sub-share and the VSS decommitment.
    fn round3_old(self: &Arc<Self>) {
        let (new_shares, v_d) = {
            let st = self.state.lock().unwrap();
            (st.new_shares.clone(), st.v_d.clone())
        };
        for (pj, share) in self.params.new_parties().iter().zip(new_shares.iter()) {
            let m = Round3Msg1 {
                share: scalar_to_be(&share.value),
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
        self.setup_old_round4_receiver();
    }

    fn setup_old_round4_receiver(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let new_others: Vec<PartyId> = self
            .params
            .new_parties()
            .iter()
            .filter(|p| p.cmp_key(&me) != std::cmp::Ordering::Equal)
            .cloned()
            .collect();
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

    /// Round 4 (new): verify each old dealer's share + decommitment, sum into a
    /// fresh share, reconstruct the public key, ACK old+new.
    fn round4_new(self: &Arc<Self>) {
        let me = self.params.party_id().clone();
        let new_threshold = self.params.new_threshold();
        let old_parties = self.params.old_parties().to_vec();

        let (r1msgs, r3m1, r3m2, group_pub) = {
            let st = self.state.lock().unwrap();
            (
                st.r1.clone().unwrap(),
                st.r3m1.clone().unwrap(),
                st.r3m2.clone().unwrap(),
                st.group_pub_key.unwrap(),
            )
        };

        let mut new_xi = Scalar::ZERO;
        let mut vjc: Vec<Vec<EdwardsPoint>> = Vec::with_capacity(old_parties.len());

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

            // Verify this party's sub-share against the dealer's commitments.
            let share = scalar_from_be_mod_l(&r3a.share);
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
        self.state.lock().unwrap().round5_new_key = Some(new_key.clone());

        // ACK all old+new parties (except self).
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

        // New-only: wait for other new parties' ACKs, then deliver.
        let new_others: Vec<PartyId> = self
            .params
            .new_parties()
            .iter()
            .filter(|p| p.cmp_key(&me) != std::cmp::Ordering::Equal)
            .cloned()
            .collect();
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

/// Inverse of [`flatten`]: rebuilds points from coordinate pairs.
fn unflatten(flat: &[Vec<u8>]) -> Option<Vec<EdwardsPoint>> {
    if flat.len() % 2 != 0 {
        return None;
    }
    flat.chunks(2)
        .map(|c| point_from_affine_be(&c[0], &c[1]).ok())
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
}
