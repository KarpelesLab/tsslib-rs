//! FROST(ristretto255) Pedersen DKG, broker-driven. Mirrors frosttss keygen
//! over the Ristretto255 group, with a Schnorr-over-encoded-points PoK and no
//! chain code (this variant has no HD derivation).

use super::Error;
use super::key::Key;
use super::schnorr::ZkProof;
use crate::frost::aead;
use crate::frost::vss;
use crate::frost::{
    Ciphersuite, Ristretto255, Scalar, random_scalar, scalar_from_be_mod_l, scalar_to_be,
};
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::ec::ristretto255::RistrettoPoint;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const ROUND1_TYPE: &str = "frost:ristretto255:keygen:round1";
const ROUND2_TYPE: &str = "frost:ristretto255:keygen:round2";
const SESSION_NONCE_LEN: usize = 16;
const COMMITMENT_BYTES: usize = 32;
const AD_PREFIX: &[u8] = b"frostristretto255tss/keygen/r2/v1|";
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
    peer_eph_pubs: HashMap<Vec<u8>, [u8; 32]>,
    peer_session_nonces: HashMap<Vec<u8>, [u8; SESSION_NONCE_LEN]>,
    peer_vs: HashMap<Vec<u8>, Vec<RistrettoPoint>>,
}

impl Keygen {
    /// Starts the FROST(ristretto255) Pedersen DKG for this party.
    pub fn new(params: Parameters) -> Result<Keygen, Error> {
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
                peer_eph_pubs: HashMap::new(),
                peer_session_nonces: HashMap::new(),
                peer_vs: HashMap::new(),
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
    pub fn wait(&self) -> Result<Key, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("keygen dropped without result".into())),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) {
        let mut rng = OsRng;
        let threshold = self.params.threshold();
        let ks: Vec<Vec<u8>> = self
            .params
            .parties()
            .iter()
            .map(|p| p.key.clone())
            .collect();
        let me_idx = self.params.party_index();

        let a_i_0 = random_scalar(&mut rng);
        let (vs, shares) = vss::create::<Ristretto255>(threshold, &a_i_0, &ks, &mut rng);

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
            let mut st = self.state.lock().unwrap();
            st.vs = vs;
            st.shares = shares;
            st.eph_priv = eph_priv;
            st.eph_pub = eph_pub;
            st.my_session_nonce = session_nonce;
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

    fn round2(self: &Arc<Self>, others: &[PartyId], r1msgs: Vec<JsonMessage>) {
        let threshold = self.params.threshold();
        let mut rng = OsRng;

        for (pid, msg) in others.iter().zip(r1msgs.iter()) {
            let r1: KeygenRound1Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let vsj = match self.verify_peer_round1(pid, &r1, threshold) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e)),
            };
            let key = strip(&pid.key).to_vec();
            let mut st = self.state.lock().unwrap();
            st.peer_eph_pubs.insert(key.clone(), to_arr32(&r1.eph_pub));
            st.peer_session_nonces
                .insert(key.clone(), to_arr16(&r1.session_nonce));
            st.peer_vs.insert(key, vsj);
        }

        let (eph_priv, eph_pub, my_nonce, shares) = {
            let st = self.state.lock().unwrap();
            (
                st.eph_priv,
                st.eph_pub,
                st.my_session_nonce,
                st.shares.clone(),
            )
        };
        for pid in others {
            let share = match shares.iter().find(|s| cmp_eq(&s.id, &pid.key)) {
                Some(s) => s,
                None => {
                    return self
                        .deliver(Err(Error::Validation(format!("missing share for {pid}"))));
                }
            };
            let recipient_pub = {
                let st = self.state.lock().unwrap();
                *st.peer_eph_pubs
                    .get(strip(&pid.key))
                    .expect("peer eph pub present")
            };
            let ad = keygen_round2_ad(&my_nonce, &eph_pub, &recipient_pub);
            let ct = match aead::seal_share(
                &mut rng,
                &eph_priv,
                &recipient_pub,
                &ad,
                &scalar_to_be(&share.value),
            ) {
                Ok(ct) => ct,
                Err(e) => {
                    return self
                        .deliver(Err(Error::Validation(format!("seal share to {pid}: {e}"))));
                }
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

    fn finalize(self: &Arc<Self>, others: &[PartyId], r2msgs: Vec<JsonMessage>) {
        let threshold = self.params.threshold();
        let me_idx = self.params.party_index();
        let st = self.state.lock().unwrap();

        let mut xi = st.shares[me_idx].value.clone();
        let my_id = &st.ks[me_idx];

        for (pid, msg) in others.iter().zip(r2msgs.iter()) {
            let key = strip(&pid.key);
            let Some(vsj) = st.peer_vs.get(key) else {
                return self.deliver(Err(Error::Validation(format!(
                    "share from {pid} had no matching round-1 commitments"
                ))));
            };
            let r2: KeygenRound2Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let sender_nonce = st.peer_session_nonces.get(key).expect("peer nonce present");
            let sender_pub = st.peer_eph_pubs.get(key).expect("peer eph pub present");
            let ad = keygen_round2_ad(sender_nonce, sender_pub, &st.eph_pub);
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
        let msg = json_wrap(typ, body, Some(self.params.party_id().clone()), None)?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
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

fn keygen_round2_ad(sender_nonce: &[u8], sender_pub: &[u8], recipient_pub: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(
        AD_PREFIX.len() + sender_nonce.len() + sender_pub.len() + recipient_pub.len() + 2,
    );
    ad.extend_from_slice(AD_PREFIX);
    ad.extend_from_slice(sender_nonce);
    ad.push(b'|');
    ad.extend_from_slice(sender_pub);
    ad.push(b'|');
    ad.extend_from_slice(recipient_pub);
    ad
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
}
