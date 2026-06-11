//! Threshold-EdDSA distributed key generation over a `MessageBroker` (3 rounds).
//!
//! Port of Go `eddsatss/keygen.go`. Round 1 broadcasts a hash commitment to the
//! dealer's Feldman-VSS commitment points; round 2 unicasts each peer its Shamir
//! share and broadcasts the commitment opening plus a Schnorr proof of knowledge
//! of `u_i` (the secret behind `vs[0]`); the final step verifies every peer's
//! opening, proof, and share, then assembles this party's [`Key`].

#![allow(dead_code)]

use super::commit;
use super::ed;
use super::key::Key;
use super::schnorr::ZkProof;
use super::vss;
use super::{Error, ed::EcPointJson};
use crate::frost::hashing::sha512_256i;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "eddsa:keygen:round1";
const TYPE_R2_1: &str = "eddsa:keygen:round2-1";
const TYPE_R2_2: &str = "eddsa:keygen:round2-2";

/// A running threshold-EdDSA keygen session.
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
    ui: Option<Scalar>,
    vs: Vec<EdwardsPoint>,
    shares: Vec<Scalar>, // one per party index
    decommit: Vec<Vec<u8>>,

    kgcs: Vec<Option<Vec<u8>>>, // commitment C per party index

    r2m1: Vec<R2Msg1>,
    r2m1_from: Vec<PartyId>,
    r2m2: Vec<R2Msg2>,
    r2m2_from: Vec<PartyId>,
    r2_join: u8,
}

impl KeygenParty {
    /// Starts keygen for this party. Returns once round 1 is emitted.
    pub fn new(params: Parameters) -> Result<KeygenParty, Error> {
        let (tx, rx) = channel();
        let n = params.party_count();
        let ssid = compute_ssid(&params);
        let shared = Arc::new(Shared {
            params,
            ssid,
            state: Mutex::new(State {
                ui: None,
                vs: Vec::new(),
                shares: Vec::new(),
                decommit: Vec::new(),
                kgcs: (0..n).map(|_| None).collect(),
                r2m1: Vec::new(),
                r2m1_from: Vec::new(),
                r2m2: Vec::new(),
                r2m2_from: Vec::new(),
                r2_join: 0,
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(KeygenParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until keygen completes, returning the generated key.
    pub fn wait(&self) -> Result<Key, Error> {
        self.result_rx
            .recv()
            .unwrap_or_else(|_| Err(Error::Validation("keygen dropped without result".into())))
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

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let t = self.params.threshold();
        let ids: Vec<Scalar> = self
            .params
            .parties()
            .iter()
            .map(|p| ed::scalar_from_be(&p.key))
            .collect();

        let ui = vss::random_scalar(&mut rng);
        let (vs, share_objs) = vss::create(t, &ui, &ids, &mut rng);
        let shares: Vec<Scalar> = share_objs.iter().map(|s| s.value.clone()).collect();
        let (c, d) = commit::commit(&flatten_points(&vs), &mut rng);

        {
            let mut st = self.state.lock().unwrap();
            st.ui = Some(ui);
            st.vs = vs;
            st.shares = shares;
            st.decommit = d;
        }

        let others = self.params.other_parties();
        let msg = R1Msg {
            commitment: B64Bytes(c),
        };
        for p in &others {
            self.send_to(TYPE_R1, &msg, p)?;
        }
        self.connect(TYPE_R1, &others, {
            let me = Arc::clone(self);
            let others = others.clone();
            move |msgs| me.round2(&others, msgs)
        });
        Ok(())
    }

    fn round2(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let i = self.params.party_index();

        // Record peer commitments.
        for (k, m) in msgs.iter().enumerate() {
            let r1: R1Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let jidx = others[k].index as usize;
            self.state.lock().unwrap().kgcs[jidx] = Some(r1.commitment.0);
        }

        // Unicast each peer its Shamir share.
        let shares = self.state.lock().unwrap().shares.clone();
        for p in others {
            let jidx = p.index as usize;
            let r2m1 = R2Msg1 {
                share: B64Bytes(ed::scalar_to_be(&shares[jidx])),
            };
            if let Err(e) = self.send_to(TYPE_R2_1, &r2m1, p) {
                return self.deliver(Err(e));
            }
        }

        // Broadcast the opening + a Schnorr proof of knowledge of u_i.
        let (ui, vs0, decommit) = {
            let st = self.state.lock().unwrap();
            (st.ui.clone().unwrap(), st.vs[0], st.decommit.clone())
        };
        let context_i = context_bytes(&self.ssid, i);
        let pf = ZkProof::prove(&context_i, &ui, &vs0, &mut rng);
        let (ax, ay) = ed::coords_be(&pf.alpha);
        let r2m2 = R2Msg2 {
            de_commitment: decommit.into_iter().map(B64Bytes).collect(),
            schnorr_proof_alpha_x: B64Bytes(ax),
            schnorr_proof_alpha_y: B64Bytes(ay),
            schnorr_proof_t: B64Bytes(ed::scalar_to_be(&pf.t)),
        };
        for p in others {
            if let Err(e) = self.send_to(TYPE_R2_2, &r2m2, p) {
                return self.deliver(Err(e));
            }
        }

        self.connect(TYPE_R2_1, others, {
            let me = Arc::clone(self);
            let others = others.to_vec();
            move |msgs| me.on_r2_1(&others, msgs)
        });
        self.connect(TYPE_R2_2, others, {
            let me = Arc::clone(self);
            let others = others.to_vec();
            move |msgs| me.on_r2_2(&others, msgs)
        });
    }

    fn on_r2_1(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R2Msg1>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r2m1 = d,
                Err(e) => return self.deliver(Err(e.into())),
            }
            st.r2m1_from = others.to_vec();
            st.r2_join += 1;
            st.r2_join == 2
        };
        if ready {
            self.round3();
        }
    }

    fn on_r2_2(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R2Msg2>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r2m2 = d,
                Err(e) => return self.deliver(Err(e.into())),
            }
            st.r2m2_from = others.to_vec();
            st.r2_join += 1;
            st.r2_join == 2
        };
        if ready {
            self.round3();
        }
    }

    fn round3(self: &Arc<Self>) {
        let t = self.params.threshold();
        let i = self.params.party_index();
        let me_id = ed::scalar_from_be(&self.params.party_id().key);

        let (r2m1, r2m1_from, r2m2, r2m2_from, vs, my_share) = {
            let st = self.state.lock().unwrap();
            (
                st.r2m1.clone(),
                st.r2m1_from.clone(),
                st.r2m2.clone(),
                st.r2m2_from.clone(),
                st.vs.clone(),
                st.shares[i].clone(),
            )
        };

        let mut peer_vs: Vec<Vec<EdwardsPoint>> = Vec::new();
        let mut xi = my_share;

        for (k, oid) in r2m1_from.iter().enumerate() {
            let jidx = oid.index as usize;
            let m2pos = match r2m2_from.iter().position(|p| p.index == oid.index) {
                Some(p) => p,
                None => return self.fail("keygen: missing round2-2 from peer"),
            };
            let kgcj = match &self.state.lock().unwrap().kgcs[jidx] {
                Some(c) => c.clone(),
                None => return self.fail("keygen: missing commitment from peer"),
            };
            let d: Vec<Vec<u8>> = r2m2[m2pos]
                .de_commitment
                .iter()
                .map(|b| b.0.clone())
                .collect();
            let flat = match commit::decommit(&kgcj, &d) {
                Some(v) => v,
                None => return self.fail("keygen: decommitment verification failed"),
            };
            let pjvs = match unflatten_points(&flat) {
                Some(v) => v,
                None => return self.fail("keygen: bad VSS commitment points"),
            };

            // Schnorr proof of knowledge of vs[0].
            let context_j = context_bytes(&self.ssid, jidx);
            let alpha = match ed::point_from_affine_be(
                &r2m2[m2pos].schnorr_proof_alpha_x.0,
                &r2m2[m2pos].schnorr_proof_alpha_y.0,
            ) {
                Some(p) => p,
                None => return self.fail("keygen: Schnorr alpha off curve"),
            };
            let pf = ZkProof {
                alpha,
                t: ed::scalar_from_be(&r2m2[m2pos].schnorr_proof_t.0),
            };
            if !pf.verify(&context_j, &pjvs[0]) {
                return self.fail("keygen: Schnorr proof verification failed");
            }

            // VSS share dealt to me.
            let share = ed::scalar_from_be(&r2m1[k].share.0);
            if !vss::verify(&me_id, &share, t, &pjvs) {
                return self.fail("keygen: VSS share verification failed");
            }
            xi = xi.add(&share);
            peer_vs.push(pjvs);
        }

        // Vc[c] = own vs[c] + Σ peers' vs[c].
        let mut vc = vs.clone();
        for pjvs in &peer_vs {
            for (c, slot) in vc.iter_mut().enumerate().take(t + 1) {
                *slot = ed::add(slot, &pjvs[c]);
            }
        }

        // BigXj[j] = Vc[0] + Σ_{c=1..t} k_j^c · Vc[c].
        let parties = self.params.parties().to_vec();
        let mut big_xj = Vec::with_capacity(parties.len());
        for p in &parties {
            let kj = ed::scalar_from_be(&p.key);
            let mut bx = vc[0];
            let mut z = Scalar::ONE;
            for vcc in vc.iter().take(t + 1).skip(1) {
                z = z.mul(&kj);
                bx = ed::add(&bx, &ed::mul(vcc, &z));
            }
            big_xj.push(bx);
        }
        let eddsa_pub = vc[0];

        let key = Key {
            xi: BigUintDec::from_be_bytes(&ed::scalar_to_be(&xi)),
            share_id: BigUintDec::from_be_bytes(&self.params.party_id().key),
            ks: parties
                .iter()
                .map(|p| BigUintDec::from_be_bytes(&p.key))
                .collect(),
            big_xj: big_xj.iter().map(ec_point).collect(),
            eddsa_pub: ec_point(&eddsa_pub),
        };
        self.deliver(Ok(key));
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

fn compute_ssid(params: &Parameters) -> Vec<u8> {
    let (gx, gy) = ed::generator_coords_be();
    let mut list: Vec<Vec<u8>> = vec![ed::field_prime_be(), ed::order_be(), gx, gy];
    for p in params.parties() {
        list.push(p.key.clone());
    }
    list.push(vec![1]); // round number
    list.push(vec![]); // nonce = 0
    let refs: Vec<&[u8]> = list.iter().map(|b| b.as_slice()).collect();
    sha512_256i(&refs).to_vec()
}

fn context_bytes(ssid: &[u8], idx: usize) -> Vec<u8> {
    let mut c = ssid.to_vec();
    // big.Int(idx).Bytes(): empty for 0, else minimal big-endian.
    if idx != 0 {
        let b = (idx as u64).to_be_bytes();
        let off = b.iter().position(|&x| x != 0).unwrap();
        c.extend_from_slice(&b[off..]);
    }
    c
}

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
    ed::point_to_json(p)
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg {
    #[serde(rename = "commitment")]
    commitment: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg1 {
    #[serde(rename = "share")]
    share: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg2 {
    #[serde(rename = "de_commitment")]
    de_commitment: Vec<B64Bytes>,
    #[serde(rename = "schnorr_proof_alpha_x")]
    schnorr_proof_alpha_x: B64Bytes,
    #[serde(rename = "schnorr_proof_alpha_y")]
    schnorr_proof_alpha_y: B64Bytes,
    #[serde(rename = "schnorr_proof_t")]
    schnorr_proof_t: B64Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsatss::vss::Share;
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
    fn keygen_2_of_3_consistent_and_reconstructs() {
        let ids = party_ids(3);
        let keys = run_keygen(&ids, 1);

        for k in &keys {
            k.validate_basic().unwrap();
        }
        // Agreement on the group public key and BigXj.
        for k in &keys[1..] {
            assert_eq!(k.eddsa_pub.coords, keys[0].eddsa_pub.coords);
            for (a, b) in k.big_xj.iter().zip(keys[0].big_xj.iter()) {
                assert_eq!(a.coords, b.coords);
            }
        }
        // Xi shares Lagrange-reconstruct to a secret whose public key is EDDSAPub.
        let shares: Vec<Share> = keys
            .iter()
            .map(|k| Share {
                id: ed::scalar_from_be(k.share_id.as_be_bytes()),
                value: k.xi_scalar(),
            })
            .collect();
        let secret = crate::eddsatss::vss::reconstruct(&shares);
        let pk = ed::mul_base(&secret);
        assert!(ed::eq(&pk, &keys[0].eddsa_pub_point().unwrap()));
    }
}
