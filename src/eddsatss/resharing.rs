//! Threshold-EdDSA key resharing over a `MessageBroker` (old + new committees).
//!
//! Port of Go `eddsatss/resharing.go`. The old committee re-splits its secret to
//! a fresh `new_threshold`-of-`new_party_count` committee while preserving
//! `EDDSAPub`. Unlike `ecdsatss` there are no Paillier/ring parameters and no
//! zero-knowledge proofs: the new committee verifies each old party's VSS share
//! against the committed (hash-opened) polynomial and checks `Vc[0] == EDDSAPub`.
//!
//! The old committee is assumed to be exactly the input key's party set.
//!
//! Rounds: (old) round1 broadcasts `EDDSAPub` + a VSS commitment; (new) round2
//! acks; (old) round3 unicasts each new party its share and opens the VSS
//! commitment; (new) round4 rebuilds the share/public key and acks; old-only
//! parties then retire their share.

#![allow(dead_code)]

use super::ed::{self, EcPointJson};
use super::key::Key;
use super::vss;
use super::{Error, ed::point_to_json};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, PartyId, ReSharingParameters, json_get, json_wrap};
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "eddsa:reshare:round1";
const TYPE_R2: &str = "eddsa:reshare:round2";
const TYPE_R3_1: &str = "eddsa:reshare:round3-1";
const TYPE_R3_2: &str = "eddsa:reshare:round3-2";
const TYPE_R4: &str = "eddsa:reshare:round4";

/// A running threshold-EdDSA resharing session.
pub struct ResharingParty {
    result_rx: MpscReceiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: ReSharingParameters,
    input: Key,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<Key, Error>>>>,
}

struct State {
    eddsa_pub: Option<EdwardsPoint>,

    // old side
    vd: Vec<Vec<u8>>,
    new_shares: Vec<Scalar>, // aligned to new_parties

    // collected (new side)
    r1msgs: Vec<R1Msg>,
    r1_from: Vec<PartyId>,
    r3m1: Vec<R3Msg1>,
    r3m1_from: Vec<PartyId>,
    r3m2: Vec<R3Msg2>,
    r3m2_from: Vec<PartyId>,
    r3_join: u8,

    new_key: Option<Key>,
}

impl ResharingParty {
    /// Starts resharing.
    pub fn new(params: ReSharingParameters, input: Key) -> Result<ResharingParty, Error> {
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            input,
            state: Mutex::new(State {
                eddsa_pub: None,
                vd: Vec::new(),
                new_shares: Vec::new(),
                r1msgs: Vec::new(),
                r1_from: Vec::new(),
                r3m1: Vec::new(),
                r3m1_from: Vec::new(),
                r3m2: Vec::new(),
                r3m2_from: Vec::new(),
                r3_join: 0,
                new_key: None,
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        if shared.params.is_new_committee() {
            shared.setup_new_round1();
        }
        if shared.params.is_old_committee() {
            shared.round1_old()?;
        }
        Ok(ResharingParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until resharing completes (new key, or retired input for old-only).
    pub fn wait(&self) -> Result<Key, Error> {
        self.result_rx
            .recv()
            .unwrap_or_else(|_| Err(Error::Validation("resharing dropped without result".into())))
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn fail(&self, m: impl Into<String>) {
        self.deliver(Err(Error::Validation(m.into())));
    }

    // --- old committee ---

    fn round1_old(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let new_t = self.params.new_threshold();
        let wi = self.prepare_wi()?;

        let new_ids = self.params.new_parties().to_vec();
        let new_ks: Vec<Scalar> = new_ids.iter().map(|p| ed::scalar_from_be(&p.key)).collect();
        let (vi, shares) = vss::create(new_t, &wi, &new_ks, &mut rng);
        let (vc, vd) = super::commit::commit(&flatten_points(&vi), &mut rng);

        let pub_pt = self
            .input
            .eddsa_pub_point()
            .ok_or_else(|| Error::Validation("resharing: input EDDSAPub off curve".into()))?;
        let (px, py) = ed::coords_be(&pub_pt);

        {
            let mut st = self.state.lock().unwrap();
            st.vd = vd;
            st.new_shares = shares.iter().map(|s| s.value.clone()).collect();
            st.eddsa_pub = Some(pub_pt);
        }

        let r1 = R1Msg {
            eddsa_pub_x: B64Bytes(px),
            eddsa_pub_y: B64Bytes(py),
            v_commitment: B64Bytes(vc),
        };
        let new_others = self.new_others();
        for pj in &new_others {
            self.send_to(TYPE_R1, &r1, pj)?;
        }

        if new_others.is_empty() {
            self.round3_old();
        } else {
            self.connect(TYPE_R2, &new_others, {
                let me = Arc::clone(self);
                move |_| me.round3_old()
            });
        }
        Ok(())
    }

    fn round3_old(self: &Arc<Self>) {
        let new_ids = self.params.new_parties().to_vec();
        let (new_shares, vd) = {
            let st = self.state.lock().unwrap();
            (st.new_shares.clone(), st.vd.clone())
        };
        for (j, pj) in new_ids.iter().enumerate() {
            let r3m1 = R3Msg1 {
                share: B64Bytes(ed::scalar_to_be(&new_shares[j])),
            };
            if let Err(e) = self.send_to(TYPE_R3_1, &r3m1, pj) {
                return self.deliver(Err(e));
            }
        }
        let r3m2 = R3Msg2 {
            v_decommitment: vd.into_iter().map(B64Bytes).collect(),
        };
        for pj in &new_ids {
            if let Err(e) = self.send_to(TYPE_R3_2, &r3m2, pj) {
                return self.deliver(Err(e));
            }
        }

        let new_others = self.new_others();
        if new_others.is_empty() {
            self.round5_old();
        } else {
            self.connect(TYPE_R4, &new_others, {
                let me = Arc::clone(self);
                move |_| me.round5_old()
            });
        }
    }

    fn round5_old(self: &Arc<Self>) {
        // New members deliver the new key from round4_new; old-only members
        // retire their share.
        if !self.params.is_new_committee() {
            let mut retired = self.input.clone();
            retired.xi = BigUintDec::from_be_bytes(&[]);
            self.deliver(Ok(retired));
        }
    }

    // --- new committee ---

    fn setup_new_round1(self: &Arc<Self>) {
        let old_ids = self.params.old_parties().to_vec();
        self.connect(TYPE_R1, &old_ids, {
            let me = Arc::clone(self);
            let old_ids = old_ids.clone();
            move |msgs| me.round2_new(&old_ids, msgs)
        });
    }

    fn round2_new(self: &Arc<Self>, old_ids: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R1Msg>, _> = msgs.iter().map(json_get).collect();
        let r1msgs = match decoded {
            Ok(d) => d,
            Err(e) => return self.deliver(Err(e.into())),
        };

        // EDDSAPub must agree across all old parties.
        let mut eddsa_pub: Option<EdwardsPoint> = None;
        for m in &r1msgs {
            let cand = match ed::point_from_affine_be(&m.eddsa_pub_x.0, &m.eddsa_pub_y.0) {
                Some(p) => p,
                None => return self.fail("resharing: EDDSAPub off curve"),
            };
            match &eddsa_pub {
                None => eddsa_pub = Some(cand),
                Some(p) if !ed::eq(p, &cand) => return self.fail("resharing: EDDSAPub mismatch"),
                _ => {}
            }
        }
        {
            let mut st = self.state.lock().unwrap();
            st.eddsa_pub = eddsa_pub;
            st.r1msgs = r1msgs;
            st.r1_from = old_ids.to_vec();
        }

        // Ack to old parties.
        for pj in old_ids {
            if pj.key != self.params.party_id().key {
                let _ = self.send_to(TYPE_R2, &R2Msg {}, pj);
            }
        }

        self.connect(TYPE_R3_1, old_ids, {
            let me = Arc::clone(self);
            let old_ids = old_ids.to_vec();
            move |msgs| me.on_r3m1(&old_ids, msgs)
        });
        self.connect(TYPE_R3_2, old_ids, {
            let me = Arc::clone(self);
            let old_ids = old_ids.to_vec();
            move |msgs| me.on_r3m2(&old_ids, msgs)
        });
    }

    fn on_r3m1(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R3Msg1>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r3m1 = d,
                Err(e) => return self.deliver(Err(e.into())),
            }
            st.r3m1_from = from.to_vec();
            st.r3_join += 1;
            st.r3_join == 2
        };
        if ready {
            self.round4_new();
        }
    }

    fn on_r3m2(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R3Msg2>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r3m2 = d,
                Err(e) => return self.deliver(Err(e.into())),
            }
            st.r3m2_from = from.to_vec();
            st.r3_join += 1;
            st.r3_join == 2
        };
        if ready {
            self.round4_new();
        }
    }

    fn round4_new(self: &Arc<Self>) {
        let new_t = self.params.new_threshold();
        let new_ids = self.params.new_parties().to_vec();
        let me_id = ed::scalar_from_be(&self.params.party_id().key);

        let (eddsa_pub, r1msgs, r1_from, r3m1, r3m1_from, r3m2, r3m2_from) = {
            let st = self.state.lock().unwrap();
            (
                st.eddsa_pub.unwrap(),
                st.r1msgs.clone(),
                st.r1_from.clone(),
                st.r3m1.clone(),
                st.r3m1_from.clone(),
                st.r3m2.clone(),
                st.r3m2_from.clone(),
            )
        };

        let mut new_xi = Scalar::ZERO;
        let mut vc_agg: Vec<Option<EdwardsPoint>> = (0..=new_t).map(|_| None).collect();

        for (k, r3m1_msg) in r3m1.iter().enumerate() {
            let oid = &r3m1_from[k];
            let r1pos = match r1_from.iter().position(|p| p.key == oid.key) {
                Some(p) => p,
                None => return self.fail("resharing: missing round1 for old party"),
            };
            let r2pos = match r3m2_from.iter().position(|p| p.key == oid.key) {
                Some(p) => p,
                None => return self.fail("resharing: missing round3-2 for old party"),
            };
            let vc = r1msgs[r1pos].v_commitment.0.clone();
            let d: Vec<Vec<u8>> = r3m2[r2pos]
                .v_decommitment
                .iter()
                .map(|b| b.0.clone())
                .collect();
            let flat = match super::commit::decommit(&vc, &d) {
                Some(v) if v.len() == (new_t + 1) * 2 => v,
                _ => return self.fail("resharing: VSS decommitment failed"),
            };
            let vj = match unflatten_points(&flat) {
                Some(v) => v,
                None => return self.fail("resharing: VSS commitments off curve"),
            };
            let share = ed::scalar_from_be(&r3m1_msg.share.0);
            if !vss::verify(&me_id, &share, new_t, &vj) {
                return self.fail("resharing: VSS share verification failed");
            }
            new_xi = new_xi.add(&share);
            for (c, slot) in vc_agg.iter_mut().enumerate() {
                *slot = Some(match slot {
                    None => vj[c],
                    Some(acc) => ed::add(acc, &vj[c]),
                });
            }
        }

        let vc0 = match vc_agg[0] {
            Some(p) => p,
            None => return self.fail("resharing: no old shares received"),
        };
        if !ed::eq(&vc0, &eddsa_pub) {
            return self.fail("resharing: reconstructed key != EDDSAPub");
        }

        let mut new_big_xjs = Vec::with_capacity(new_ids.len());
        for pj in &new_ids {
            let kj = ed::scalar_from_be(&pj.key);
            let mut bx = vc0;
            let mut z = Scalar::ONE;
            for slot in vc_agg.iter().take(new_t + 1).skip(1) {
                z = z.mul(&kj);
                bx = ed::add(&bx, &ed::mul(&slot.unwrap(), &z));
            }
            new_big_xjs.push(bx);
        }

        let new_key = Key {
            xi: BigUintDec::from_be_bytes(&ed::scalar_to_be(&new_xi)),
            share_id: BigUintDec::from_be_bytes(&self.params.party_id().key),
            ks: new_ids
                .iter()
                .map(|p| BigUintDec::from_be_bytes(&p.key))
                .collect(),
            big_xj: new_big_xjs.iter().map(ec_point).collect(),
            eddsa_pub: ec_point(&eddsa_pub),
        };
        self.state.lock().unwrap().new_key = Some(new_key.clone());

        // Ack round4 to every other old+new party.
        let mut all = self.params.old_parties().to_vec();
        all.extend(new_ids.iter().cloned());
        for pj in &all {
            if pj.key != self.params.party_id().key {
                let _ = self.send_to(TYPE_R4, &R4Msg {}, pj);
            }
        }

        let new_others = self.new_others();
        if new_others.is_empty() {
            self.deliver(Ok(new_key));
        } else {
            self.connect(TYPE_R4, &new_others, {
                let me = Arc::clone(self);
                move |_| {
                    let k = me.state.lock().unwrap().new_key.clone();
                    if let Some(k) = k {
                        me.deliver(Ok(k));
                    }
                }
            });
        }
    }

    // --- helpers ---

    fn prepare_wi(&self) -> Result<Scalar, Error> {
        let i = self
            .params
            .old_index()
            .ok_or_else(|| Error::Validation("resharing: not an old-committee member".into()))?;
        let ks = self.input.ks_scalars();
        if self.params.old_threshold() + 1 > ks.len() {
            return Err(Error::Validation("resharing: old t+1 > parties".into()));
        }
        let mut wi = self.input.xi_scalar();
        for (j, ksj) in ks.iter().enumerate() {
            if j == i {
                continue;
            }
            let denom = ksj.sub(&ks[i]);
            wi = wi.mul(&ksj.mul(&denom.invert()));
        }
        Ok(wi)
    }

    fn new_others(&self) -> Vec<PartyId> {
        let me = self.params.party_id();
        self.params
            .new_parties()
            .iter()
            .filter(|p| p.key != me.key)
            .cloned()
            .collect()
    }

    fn connect<F>(self: &Arc<Self>, typ: &str, others: &[PartyId], cb: F)
    where
        F: FnOnce(Vec<JsonMessage>) + Send + 'static,
    {
        let exp = JsonExpect::new(typ, others.to_vec(), Box::new(cb));
        self.params.broker().connect(typ, Arc::new(exp));
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

// --- helpers ---------------------------------------------------------------

fn flatten_points(vs: &[EdwardsPoint]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(vs.len() * 2);
    for p in vs {
        let (x, y) = ed::coords_be(p);
        out.push(x);
        out.push(y);
    }
    out
}

fn unflatten_points(flat: &[Vec<u8>]) -> Option<Vec<EdwardsPoint>> {
    if flat.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(flat.len() / 2);
    for pair in flat.chunks(2) {
        out.push(ed::eight_inv_eight(&ed::point_from_affine_be(
            &pair[0], &pair[1],
        )?));
    }
    Some(out)
}

fn ec_point(p: &EdwardsPoint) -> EcPointJson {
    point_to_json(p)
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg {
    #[serde(rename = "eddsa_pub_x")]
    eddsa_pub_x: B64Bytes,
    #[serde(rename = "eddsa_pub_y")]
    eddsa_pub_y: B64Bytes,
    #[serde(rename = "v_commitment")]
    v_commitment: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg {}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg1 {
    #[serde(rename = "share")]
    share: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg2 {
    #[serde(rename = "v_decommitment")]
    v_decommitment: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R4Msg {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsatss::import::import_key;
    use crate::eddsatss::signing::{SignatureData, SigningParty};
    use crate::tss::testhub::ReshareHub;
    use crate::tss::{Parameters, testhub::TestHub};
    use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};

    fn pid(key: u8) -> PartyId {
        PartyId::new(key.to_string(), format!("P{key}"), vec![key])
    }

    #[test]
    fn import_then_reshare_then_sign() {
        // Import a plain Ed25519 key as 1-of-1, reshare to 2-of-3, then sign.
        let d = [0x42u8];
        let old = pid(5);
        let input = import_key(&d, &old.key).unwrap();
        let eddsa_pub = input.eddsa_pub_point().unwrap();

        let old_ids = vec![old.clone()];
        let new_ids = PartyId::sort(vec![pid(11), pid(12), pid(13)], 0);
        let (old_t, new_t) = (0usize, 1usize);

        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        let hub = ReshareHub::new(&all);

        let mut sessions: Vec<ResharingParty> = Vec::new();
        sessions.push(
            ResharingParty::new(
                ReSharingParameters::new(
                    old_ids.clone(),
                    new_ids.clone(),
                    old_t,
                    new_t,
                    old.clone(),
                    hub.broker(&old),
                ),
                input.clone(),
            )
            .unwrap(),
        );
        for p in &new_ids {
            sessions.push(
                ResharingParty::new(
                    ReSharingParameters::new(
                        old_ids.clone(),
                        new_ids.clone(),
                        old_t,
                        new_t,
                        p.clone(),
                        hub.broker(p),
                    ),
                    input.clone(),
                )
                .unwrap(),
            );
        }

        let results: Vec<Key> = sessions
            .iter()
            .map(|s| s.wait().expect("resharing succeeds"))
            .collect();
        let new_keys: Vec<Key> = results[1..].to_vec();
        for k in &new_keys {
            k.validate_basic().unwrap();
            assert_eq!(k.eddsa_pub.coords, new_keys[0].eddsa_pub.coords);
        }
        // Public key preserved.
        assert!(ed::eq(&new_keys[0].eddsa_pub_point().unwrap(), &eddsa_pub));

        // Sign with a 2-of-3 subset of the new committee (parties 11, 12).
        let signers: Vec<PartyId> = new_ids[..2].to_vec();
        // Build per-signer keys narrowed to the signing committee.
        let signer_keys: Vec<Key> = (0..2).map(|i| subset_key(&new_keys[i], &signers)).collect();
        let msg = b"reshared eddsa signs";
        let hub2 = TestHub::new(&signers);
        let sparties: Vec<SigningParty> = (0..signers.len())
            .map(|i| {
                let params = Parameters::new(signers.to_vec(), &signers[i], new_t, hub2.broker(i));
                SigningParty::new(params, signer_keys[i].clone(), msg).unwrap()
            })
            .collect();
        let sigs: Vec<SignatureData> = sparties.iter().map(|p| p.wait().unwrap()).collect();

        let pk = Ed25519PublicKey::from_bytes(ed::encode_point(&eddsa_pub));
        let mut s = [0u8; 64];
        s.copy_from_slice(&sigs[0].signature);
        assert!(pk.verify(msg, &Ed25519Signature::from_bytes(s)).is_ok());
    }

    /// Narrows a new-committee key to a signing subset (reindex Ks/BigXj, keep Xi).
    fn subset_key(k: &Key, signers: &[PartyId]) -> Key {
        let idx: Vec<usize> = signers
            .iter()
            .map(|s| {
                k.ks.iter()
                    .position(|kk| kk.as_be_bytes() == s.key.as_slice())
                    .expect("signer in key")
            })
            .collect();
        Key {
            xi: k.xi.clone(),
            share_id: k.share_id.clone(),
            ks: idx.iter().map(|&i| k.ks[i].clone()).collect(),
            big_xj: idx.iter().map(|&i| k.big_xj[i].clone()).collect(),
            eddsa_pub: k.eddsa_pub.clone(),
        }
    }
}
