//! GG18 distributed key generation over a `MessageBroker` (4 rounds).
//!
//! Port of Go `ecdsatss/keygen.go`. Round 1 broadcasts a hash commitment to the
//! dealer's Feldman-VSS polynomial commitments plus this party's Paillier modulus
//! and ring-Pedersen parameters with two DLN proofs. Round 2 unicasts each peer
//! its Shamir share with a no-small-factor proof and broadcasts the commitment
//! opening with a Paillier-Blum modulus proof. Round 3 broadcasts a Paillier key
//! proof after verifying every peer's shares and proofs; the final round verifies
//! those proofs and assembles this party's [`Key`].
//!
//! Pre-parameters ([`LocalPreParams`]) are supplied by the caller because their
//! safe-prime generation is too slow to run inline.

#![allow(dead_code)]

use super::commit;
use super::dlnproof::{self, DlnProof};
use super::facproof::{self, ProofFac};
use super::key::{EcPointJson, Key, PaillierPkJson, PaillierSkJson};
use super::modproof::{self, ProofMod};
use super::paillier::{self, PublicKey};
use super::prepare::LocalPreParams;
use super::secp::{self, ProjectivePoint, Scalar};
use super::vss;
use super::{Error, bn};
use crate::frost::hashing::sha512_256i;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "ecdsa:keygen:round1";
const TYPE_R2_1: &str = "ecdsa:keygen:round2-1";
const TYPE_R2_2: &str = "ecdsa:keygen:round2-2";
const TYPE_R3: &str = "ecdsa:keygen:round3";

/// A running GG18 keygen session. Construct with [`KeygenParty::new`]; retrieve
/// the resulting [`Key`] with [`KeygenParty::wait`].
pub struct KeygenParty {
    result_rx: MpscReceiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    pre: LocalPreParams,
    ssid: Vec<u8>,
    state: Mutex<State>,
    finalize_data: Mutex<Option<Assembled>>,
    result_tx: Mutex<Option<MpscSender<Result<Key, Error>>>>,
}

struct State {
    // own round-1 secrets
    vs: Vec<ProjectivePoint>,
    shares: Vec<Scalar>, // one per party index
    decommit: Vec<BoxedUint>,

    // per-party public material, indexed by global party index
    paillier_pks: Vec<Option<PublicKey>>,
    ntildej: Vec<Option<BoxedUint>>,
    h1j: Vec<Option<BoxedUint>>,
    h2j: Vec<Option<BoxedUint>>,
    kgcs: Vec<Option<BoxedUint>>, // commitments C

    // round-2 collected messages (aligned to `others`)
    r2m1: Vec<R2Msg1>,
    r2m1_from: Vec<PartyId>,
    r2m2: Vec<R2Msg2>,
    r2m2_from: Vec<PartyId>,
    r2_join: u8,

    // finalize material
    ecdsa_pub: Option<ProjectivePoint>,
}

impl KeygenParty {
    /// Starts keygen for this party with caller-supplied pre-parameters. Returns
    /// once round 1 is emitted; the [`Key`] is delivered when all rounds finish.
    pub fn new(params: Parameters, pre: LocalPreParams) -> Result<KeygenParty, Error> {
        let (tx, rx) = channel();
        let n = params.party_count();
        let ssid = compute_ssid(&params);
        let shared = Arc::new(Shared {
            params,
            pre,
            ssid,
            state: Mutex::new(State {
                vs: Vec::new(),
                shares: Vec::new(),
                decommit: Vec::new(),
                paillier_pks: vec_none(n),
                ntildej: vec_none(n),
                h1j: vec_none(n),
                h2j: vec_none(n),
                kgcs: vec_none(n),
                r2m1: Vec::new(),
                r2m1_from: Vec::new(),
                r2m2: Vec::new(),
                r2m2_from: Vec::new(),
                r2_join: 0,
                ecdsa_pub: None,
            }),
            finalize_data: Mutex::new(None),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(KeygenParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until keygen completes, returning the generated key or an error.
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
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let t = self.params.threshold();
        let me = self.params.party_id().clone();
        let parties = self.params.parties().to_vec();
        let ids: Vec<Scalar> = parties
            .iter()
            .map(|p| secp::scalar_from_be(&p.key))
            .collect();

        let u = vss::random_scalar(&mut rng);
        let (vs, share_objs) = vss::create(t, &u, &ids, &mut rng);
        let shares: Vec<Scalar> = share_objs.iter().map(|s| s.value.clone()).collect();

        // Commit to the flattened VSS commitment points.
        let flat = flatten_points(&vs);
        let (c, d) = commit::commit(&flat, &mut rng);

        // Two DLN proofs binding (h1,h2) and (h2,h1).
        let pre = &self.pre;
        let dln1 = dlnproof::prove(
            &pre.h1i,
            &pre.h2i,
            &pre.alpha,
            &pre.p,
            &pre.q,
            &pre.ntilde_i,
            &mut rng,
        );
        let dln2 = dlnproof::prove(
            &pre.h2i,
            &pre.h1i,
            &pre.beta,
            &pre.p,
            &pre.q,
            &pre.ntilde_i,
            &mut rng,
        );

        let msg = R1Msg {
            commitment: B64Bytes(bn::to_be(&c)),
            paillier_n: B64Bytes(bn::to_be(&pre.paillier_sk.pk.n)),
            ntilde: B64Bytes(bn::to_be(&pre.ntilde_i)),
            h1: B64Bytes(bn::to_be(&pre.h1i)),
            h2: B64Bytes(bn::to_be(&pre.h2i)),
            dln1: parts_b64(&dln1.to_parts()),
            dln2: parts_b64(&dln2.to_parts()),
        };

        // Record own per-index material.
        let i = self.params.party_index();
        {
            let mut st = self.state.lock().unwrap();
            st.vs = vs;
            st.shares = shares;
            st.decommit = d;
            st.paillier_pks[i] = Some(pre.paillier_sk.pk.clone());
            st.ntildej[i] = Some(pre.ntilde_i.clone());
            st.h1j[i] = Some(pre.h1i.clone());
            st.h2j[i] = Some(pre.h2i.clone());
        }

        let others = self.params.other_parties();
        for p in &others {
            self.send_to(TYPE_R1, &msg, p)?;
        }
        let _ = me;
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
        let pre = &self.pre;

        // Decode + verify each peer's round-1 message.
        for (k, m) in msgs.iter().enumerate() {
            let r1: R1Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let jidx = others[k].index as usize;
            let paillier_n = bn::from_be(&r1.paillier_n.0);
            let ntildej = bn::from_be(&r1.ntilde.0);
            let h1jv = bn::from_be(&r1.h1.0);
            let h2jv = bn::from_be(&r1.h2.0);
            if bn::to_be(&h1jv) == bn::to_be(&h2jv) {
                return self.deliver(Err(Error::Validation("keygen: H1j == H2j".into())));
            }
            let (dln1, dln2) = match (
                DlnProof::from_parts(&parts_bytes(&r1.dln1)),
                DlnProof::from_parts(&parts_bytes(&r1.dln2)),
            ) {
                (Some(a), Some(b)) => (a, b),
                _ => return self.deliver(Err(Error::Validation("keygen: bad DLN proof".into()))),
            };
            if !dlnproof::verify(&dln1, &h1jv, &h2jv, &ntildej)
                || !dlnproof::verify(&dln2, &h2jv, &h1jv, &ntildej)
            {
                return self.deliver(Err(Error::Validation(
                    "keygen: DLN proof verification failed".into(),
                )));
            }
            let mut st = self.state.lock().unwrap();
            st.paillier_pks[jidx] = Some(PublicKey { n: paillier_n });
            st.ntildej[jidx] = Some(ntildej);
            st.h1j[jidx] = Some(h1jv);
            st.h2j[jidx] = Some(h2jv);
            st.kgcs[jidx] = Some(bn::from_be(&r1.commitment.0));
        }

        let context_i = context_bytes(&self.ssid, i);

        // Round-2 part 1: per-peer share + fac proof.
        let (shares, n0p, n0q, n0) = {
            let st = self.state.lock().unwrap();
            (
                st.shares.clone(),
                pre.paillier_sk.p.clone(),
                pre.paillier_sk.q.clone(),
                pre.paillier_sk.pk.n.clone(),
            )
        };
        for p in others {
            let jidx = p.index as usize;
            let (ntildej, h1jv, h2jv) = {
                let st = self.state.lock().unwrap();
                (
                    st.ntildej[jidx].clone().unwrap(),
                    st.h1j[jidx].clone().unwrap(),
                    st.h2j[jidx].clone().unwrap(),
                )
            };
            let fp = facproof::prove(
                &context_i, &n0, &ntildej, &h1jv, &h2jv, &n0p, &n0q, &mut rng,
            );
            let r2m1 = R2Msg1 {
                share: B64Bytes(secp::scalar_to_be(&shares[jidx])),
                fac_proof: parts_b64(&fp.to_parts()),
            };
            if let Err(e) = self.send_to(TYPE_R2_1, &r2m1, p) {
                return self.deliver(Err(e));
            }
        }

        // Round-2 part 2: commitment opening + mod proof (broadcast).
        let mp = match modproof::prove(&context_i, &n0, &n0p, &n0q, &mut rng) {
            Ok(p) => p,
            Err(e) => return self.deliver(Err(e)),
        };
        let decommit = self.state.lock().unwrap().decommit.clone();
        let r2m2 = R2Msg2 {
            decommitment: parts_b64(&decommit.iter().map(bn::to_be).collect::<Vec<_>>()),
            mod_proof: parts_b64(&mp.to_parts()),
        };
        for p in others {
            if let Err(e) = self.send_to(TYPE_R2_2, &r2m2, p) {
                return self.deliver(Err(e));
            }
        }

        // Expect both round-2 message types from all others.
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
                Err(e) => return self.deliver(Err(Error::from(e))),
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
                Err(e) => return self.deliver(Err(Error::from(e))),
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
        let mut rng = OsRng;
        let t = self.params.threshold();
        let i = self.params.party_index();
        let me_id = secp::scalar_from_be(&self.params.party_id().key);
        let q = bn::secp256k1_order();

        let (r2m1, r2m1_from, r2m2, r2m2_from) = {
            let st = self.state.lock().unwrap();
            (
                st.r2m1.clone(),
                st.r2m1_from.clone(),
                st.r2m2.clone(),
                st.r2m2_from.clone(),
            )
        };

        // Map round-2-part-2 (decommit/modproof) by party index.
        let mut peer_vs: Vec<(usize, Vec<ProjectivePoint>)> = Vec::new();
        for (k, oid) in r2m1_from.iter().enumerate() {
            let jidx = oid.index as usize;
            // matching part-2 message position
            let m2pos = match r2m2_from.iter().position(|p| p.index == oid.index) {
                Some(p) => p,
                None => {
                    return self.deliver(Err(Error::Validation(
                        "keygen: missing round2-2 message".into(),
                    )));
                }
            };
            let (kgcj, ntj, h1, h2, peer_n) = {
                let st = self.state.lock().unwrap();
                (
                    st.kgcs[jidx].clone().unwrap(),
                    st.ntildej[i].clone().unwrap(), // my own ring params (verifier side)
                    st.h1j[i].clone().unwrap(),
                    st.h2j[i].clone().unwrap(),
                    st.paillier_pks[jidx].clone().unwrap().n,
                )
            };

            // Open the commitment to recover the peer's VSS commitments.
            let d = parts_bytes(&r2m2[m2pos].decommitment)
                .iter()
                .map(|b| bn::from_be(b))
                .collect::<Vec<_>>();
            let flat = match commit::decommit(&kgcj, &d) {
                Some(v) => v,
                None => {
                    return self.deliver(Err(Error::Validation(
                        "keygen: decommitment verification failed".into(),
                    )));
                }
            };
            let pjvs = match unflatten_points(&flat) {
                Some(v) => v,
                None => {
                    return self.deliver(Err(Error::Validation(
                        "keygen: bad VSS commitment points".into(),
                    )));
                }
            };

            let context_j = context_bytes(&self.ssid, jidx);

            // Verify the peer's mod proof over its Paillier modulus.
            let mp = match ProofMod::from_parts(&parts_bytes(&r2m2[m2pos].mod_proof)) {
                Some(p) => p,
                None => {
                    return self.deliver(Err(Error::Validation("keygen: bad mod proof".into())));
                }
            };
            if !modproof::verify(&context_j, &peer_n, &mp, &mut rng) {
                return self.deliver(Err(Error::Validation(
                    "keygen: mod proof verification failed".into(),
                )));
            }

            // Verify the share this peer dealt to me.
            let share = secp::scalar_from_be(&r2m1[k].share.0);
            if !vss::verify(&me_id, &share, t, &pjvs) {
                return self.deliver(Err(Error::Validation(
                    "keygen: VSS share verification failed".into(),
                )));
            }

            // Verify the peer's fac proof against my ring-Pedersen params.
            let fp = match ProofFac::from_parts(&parts_bytes(&r2m1[k].fac_proof)) {
                Some(p) => p,
                None => {
                    return self.deliver(Err(Error::Validation("keygen: bad fac proof".into())));
                }
            };
            if !facproof::verify(&context_j, &peer_n, &ntj, &h1, &h2, &fp) {
                return self.deliver(Err(Error::Validation(
                    "keygen: fac proof verification failed".into(),
                )));
            }

            peer_vs.push((jidx, pjvs));
        }

        // xi = own share + Σ received shares (mod q).
        let (my_vs, my_share) = {
            let st = self.state.lock().unwrap();
            (st.vs.clone(), st.shares[i].clone())
        };
        let mut xi = my_share;
        for m in &r2m1 {
            xi = xi.add(&secp::scalar_from_be(&m.share.0));
        }

        // Vc = Σ over all parties of their VSS commitment vectors.
        let mut vc = my_vs.clone();
        for (_, pjvs) in &peer_vs {
            for c in 0..=t {
                vc[c] = vc[c].add(&pjvs[c]);
            }
        }

        // BigXj[j] = Vc[0] + Σ_{c=1..t} k_j^c · Vc[c].
        let parties = self.params.parties().to_vec();
        let mut big_xj: Vec<ProjectivePoint> = Vec::with_capacity(parties.len());
        for p in &parties {
            let kj = secp::scalar_from_be(&p.key);
            let mut bx = vc[0];
            let mut z = Scalar::ONE;
            for vcc in vc.iter().take(t + 1).skip(1) {
                z = z.mul(&kj);
                bx = bx.add(&vcc.mul(&z));
            }
            big_xj.push(bx);
        }

        let ecdsa_pub = vc[0];
        self.state.lock().unwrap().ecdsa_pub = Some(ecdsa_pub);

        // Paillier key proof over (my key int, ECDSAPub).
        let (ex, ey) = secp::coords(&ecdsa_pub);
        let ki = secp::scalar_to_uint(&me_id);
        let proof = match self.pre.paillier_sk.proof(&ki, &ex, &ey) {
            Ok(p) => p,
            Err(_) => {
                return self.deliver(Err(Error::Validation(
                    "keygen: failed to generate Paillier proof".into(),
                )));
            }
        };
        let proof_parts: Vec<Vec<u8>> = proof.iter().map(bn::to_be).collect();
        let _ = q;

        // Stash assembled data for finalize, then broadcast the proof.
        self.finalize_data.lock().unwrap().replace(Assembled {
            xi: secp::scalar_to_uint(&xi),
            big_xj,
            ecdsa_pub,
        });

        let r3 = R3Msg {
            paillier_proof: parts_b64(&proof_parts),
        };
        let others = self.params.other_parties();
        for p in &others {
            if let Err(e) = self.send_to(TYPE_R3, &r3, p) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R3, &others, {
            let me = Arc::clone(self);
            let others = others.clone();
            move |msgs| me.round4(&others, msgs)
        });
    }

    fn round4(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let ecdsa_pub = self.state.lock().unwrap().ecdsa_pub.unwrap();
        let (ex, ey) = secp::coords(&ecdsa_pub);
        let _ = &mut rng;

        for (k, m) in msgs.iter().enumerate() {
            let r3: R3Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let jidx = others[k].index as usize;
            let (peer_n, kj) = {
                let st = self.state.lock().unwrap();
                (
                    st.paillier_pks[jidx].clone().unwrap().n,
                    bn::from_be(&others[k].key),
                )
            };
            let parts = parts_bytes(&r3.paillier_proof);
            if parts.len() != paillier::PROOF_ITERS {
                return self.deliver(Err(Error::Validation(
                    "keygen: wrong Paillier proof length".into(),
                )));
            }
            let pi: Vec<BoxedUint> = parts.iter().map(|b| bn::from_be(b)).collect();
            if !paillier::verify_proof(&peer_n, &kj, &ex, &ey, &pi) {
                return self.deliver(Err(Error::Validation(
                    "keygen: Paillier proof verification failed".into(),
                )));
            }
        }

        // Assemble the save-data key.
        match self.assemble_key() {
            Ok(k) => self.deliver(Ok(k)),
            Err(e) => self.deliver(Err(e)),
        }
    }

    fn assemble_key(self: &Arc<Self>) -> Result<Key, Error> {
        let fin = self
            .finalize_data
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::Validation("keygen: missing finalize data".into()))?;
        let st = self.state.lock().unwrap();
        let parties = self.params.parties();
        let pre = &self.pre;

        let ks: Vec<BigUintDec> = parties.iter().map(|p| dec_be(&p.key)).collect();
        let ntilde_j = st
            .ntildej
            .iter()
            .map(|o| dec(o.as_ref().unwrap()))
            .collect();
        let h1j = st.h1j.iter().map(|o| dec(o.as_ref().unwrap())).collect();
        let h2j = st.h2j.iter().map(|o| dec(o.as_ref().unwrap())).collect();
        let big_xj = fin.big_xj.iter().map(ec_point).collect();
        let paillier_pks = st
            .paillier_pks
            .iter()
            .map(|o| PaillierPkJson {
                n: dec(&o.as_ref().unwrap().n),
            })
            .collect();

        Ok(Key {
            paillier_sk: PaillierSkJson {
                n: dec(&pre.paillier_sk.pk.n),
                lambda_n: dec(&pre.paillier_sk.lambda),
                phi_n: dec(&pre.paillier_sk.phi),
                p: dec(&pre.paillier_sk.p),
                q: dec(&pre.paillier_sk.q),
            },
            ntilde_i: dec(&pre.ntilde_i),
            h1i: dec(&pre.h1i),
            h2i: dec(&pre.h2i),
            alpha: dec(&pre.alpha),
            beta: dec(&pre.beta),
            p: dec(&pre.p),
            q: dec(&pre.q),
            xi: dec(&fin.xi),
            share_id: dec_be(&self.params.party_id().key),
            ks,
            ntilde_j,
            h1j,
            h2j,
            big_xj,
            paillier_pks,
            ecdsa_pub: ec_point(&fin.ecdsa_pub),
        })
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

#[derive(Clone)]
struct Assembled {
    xi: BoxedUint,
    big_xj: Vec<ProjectivePoint>,
    ecdsa_pub: ProjectivePoint,
}

// --- helpers ---------------------------------------------------------------

fn vec_none<T>(n: usize) -> Vec<Option<T>> {
    (0..n).map(|_| None).collect()
}

fn compute_ssid(params: &Parameters) -> Vec<u8> {
    let (gx, gy) = secp::generator_coords();
    let mut list: Vec<Vec<u8>> = vec![
        bn::to_be(&secp::field_prime()),
        bn::to_be(&bn::secp256k1_order()),
        bn::to_be(&gx),
        bn::to_be(&gy),
    ];
    for p in params.parties() {
        list.push(p.key.clone());
    }
    list.push(bn::to_be(&bn::u64(1))); // round number
    list.push(bn::to_be(&bn::u64(0))); // nonce
    let refs: Vec<&[u8]> = list.iter().map(|b| b.as_slice()).collect();
    sha512_256i(&refs).to_vec()
}

fn context_bytes(ssid: &[u8], idx: usize) -> Vec<u8> {
    let mut c = ssid.to_vec();
    c.extend_from_slice(&bn::to_be(&bn::u64(idx as u64)));
    c
}

fn flatten_points(vs: &[ProjectivePoint]) -> Vec<BoxedUint> {
    let mut out = Vec::with_capacity(vs.len() * 2);
    for p in vs {
        let (x, y) = secp::coords(p);
        out.push(x);
        out.push(y);
    }
    out
}

fn unflatten_points(flat: &[BoxedUint]) -> Option<Vec<ProjectivePoint>> {
    if flat.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(flat.len() / 2);
    for pair in flat.chunks(2) {
        out.push(secp::from_coords(&pair[0], &pair[1])?);
    }
    Some(out)
}

fn parts_b64(parts: &[Vec<u8>]) -> Vec<B64Bytes> {
    parts.iter().map(|p| B64Bytes(p.clone())).collect()
}

fn parts_bytes(parts: &[B64Bytes]) -> Vec<Vec<u8>> {
    parts.iter().map(|p| p.0.clone()).collect()
}

fn dec(n: &BoxedUint) -> BigUintDec {
    BigUintDec::from_be_bytes(&bn::to_be(n))
}

fn dec_be(be: &[u8]) -> BigUintDec {
    BigUintDec::from_be_bytes(be)
}

fn ec_point(p: &ProjectivePoint) -> EcPointJson {
    let (x, y) = secp::coords(p);
    EcPointJson {
        curve: "secp256k1".into(),
        coords: [dec(&x), dec(&y)],
    }
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg {
    #[serde(rename = "Commitment")]
    commitment: B64Bytes,
    #[serde(rename = "PaillierN")]
    paillier_n: B64Bytes,
    #[serde(rename = "NTilde")]
    ntilde: B64Bytes,
    #[serde(rename = "H1")]
    h1: B64Bytes,
    #[serde(rename = "H2")]
    h2: B64Bytes,
    #[serde(rename = "Dlnproof_1")]
    dln1: Vec<B64Bytes>,
    #[serde(rename = "Dlnproof_2")]
    dln2: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg1 {
    #[serde(rename = "Share")]
    share: B64Bytes,
    #[serde(rename = "FacProof")]
    fac_proof: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg2 {
    #[serde(rename = "DeCommitment")]
    decommitment: Vec<B64Bytes>,
    #[serde(rename = "ModProof")]
    mod_proof: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg {
    #[serde(rename = "PaillierProof")]
    paillier_proof: Vec<B64Bytes>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsatss::vss::Share;
    use crate::tss::testhub::TestHub;
    use purecrypto::ec::secp256k1::ProjectivePoint;

    fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    fn point_of(p: &EcPointJson) -> ProjectivePoint {
        let x = bn::from_dec(&p.coords[0]);
        let y = bn::from_dec(&p.coords[1]);
        secp::from_coords(&x, &y).expect("on curve")
    }

    #[test]
    #[ignore = "safe-prime generation + Paillier proofs are slow"]
    fn keygen_2_of_3_consistent_and_reconstructs() {
        let ids = party_ids(3);
        let t = 1;
        // Small (insecure) safe primes keep the test tractable.
        let pres: Vec<LocalPreParams> = (0..ids.len())
            .map(|_| LocalPreParams::generate(256, &mut OsRng))
            .collect();

        let hub = TestHub::new(&ids);
        let parties: Vec<KeygenParty> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                KeygenParty::new(params, pres[i].clone()).unwrap()
            })
            .collect();
        let keys: Vec<Key> = parties
            .iter()
            .map(|p| p.wait().expect("keygen succeeds"))
            .collect();

        // All parties agree on the public key and the BigXj vector.
        for k in &keys {
            k.validate_basic().unwrap();
        }
        for k in &keys[1..] {
            assert_eq!(k.ecdsa_pub.coords, keys[0].ecdsa_pub.coords);
            for (a, b) in k.big_xj.iter().zip(keys[0].big_xj.iter()) {
                assert_eq!(a.coords, b.coords);
            }
        }

        // The Xi shares Lagrange-reconstruct to a secret whose public key is ECDSAPub.
        let shares: Vec<Share> = keys
            .iter()
            .map(|k| Share {
                id: secp::scalar(&bn::from_dec(&k.share_id)),
                value: secp::scalar(&bn::from_dec(&k.xi)),
            })
            .collect();
        let secret = crate::ecdsatss::vss::reconstruct(&shares);
        let pk = ProjectivePoint::mul_generator(&secret);
        assert!(secp::eq(&pk, &point_of(&keys[0].ecdsa_pub)));
    }
}
