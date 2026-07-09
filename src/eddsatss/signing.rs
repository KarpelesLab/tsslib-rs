//! Threshold-EdDSA signing over a `MessageBroker` (3 rounds + finalize).
//!
//! Port of Go `eddsatss/signing.go`. A commit/reveal threshold Schnorr: round 1
//! commits to the nonce point `R_i = r_i·G`; round 2 opens it with a Schnorr
//! proof of knowledge of `r_i`; round 3 reconstructs `R = Σ R_j`, computes the
//! standard Ed25519 challenge `λ = SHA-512(R‖A‖M) mod L` and the partial
//! `s_i = λ·w_i + r_i`, and finalize sums the partials into a stock Ed25519
//! signature `(R, S)` verifiable by any Ed25519 verifier.
//!
//! The committee is the parties of `params`; the supplied [`Key`] may still
//! carry the full keygen party set — [`SigningParty::new`] transparently
//! narrows it to the committee via [`Key::subset_for_parties`].

#![allow(dead_code)]

use super::ed;
use super::key::Key;
use super::schnorr::ZkProof;
use super::{Error, vss};
use crate::frost::hashing::sha512_256i;
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::ec::edwards25519::hazmat::{EdwardsPoint, Scalar};
use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};
use purecrypto::hash::sha512;
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "eddsa:sign:round1";
const TYPE_R2: &str = "eddsa:sign:round2";
const TYPE_R3: &str = "eddsa:sign:round3";

/// A completed Ed25519 signature.
#[derive(Clone, Debug)]
pub struct SignatureData {
    /// The 64-byte Ed25519 signature `R ‖ S` (RFC 8032 form).
    pub signature: Vec<u8>,
    /// The `R` component (32-byte compressed point, little-endian).
    pub r: Vec<u8>,
    /// The `S` component (32-byte scalar, little-endian).
    pub s: Vec<u8>,
    /// The signed message.
    pub m: Vec<u8>,
}

/// A running threshold-EdDSA signing session.
pub struct SigningParty {
    result_rx: MpscReceiver<Result<SignatureData, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    msg: Vec<u8>,
    ssid: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<SignatureData, Error>>>>,
}

struct State {
    wi: Scalar,
    ri: Scalar,
    point_ri: Option<EdwardsPoint>,
    decommit: Vec<Vec<u8>>,
    cjs: Vec<Option<Vec<u8>>>,
    encoded_r: [u8; 32],
    local_s: Scalar,
}

impl SigningParty {
    /// Starts signing `message` with this party's share.
    ///
    /// `key` may have been produced by a keygen with more parties than the
    /// current committee: the per-party slices (`Ks`, `BigXj`) are transparently
    /// reindexed to `params.parties()` via [`Key::subset_for_parties`], so
    /// callers can pass the full keygen key as-is.
    pub fn new(params: Parameters, key: Key, message: &[u8]) -> Result<SigningParty, Error> {
        let (tx, rx) = channel();
        let n = params.party_count();
        let key = key.subset_for_parties(params.parties())?;
        let ssid = compute_ssid(&params, &key)
            .ok_or_else(|| Error::Validation("signing: BigXj off curve".into()))?;
        let shared = Arc::new(Shared {
            params,
            key,
            msg: message.to_vec(),
            ssid,
            state: Mutex::new(State {
                wi: Scalar::ZERO,
                ri: Scalar::ZERO,
                point_ri: None,
                decommit: Vec::new(),
                cjs: (0..n).map(|_| None).collect(),
                encoded_r: [0u8; 32],
                local_s: Scalar::ZERO,
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(SigningParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Like [`SigningParty::new`], but signs under an additively-derived child
    /// key.
    ///
    /// `key_derivation_delta` (a big-endian scalar, reduced mod the group order
    /// `L`) shifts a clone of `key` by `delta·G` via [`Key::with_kdd`]; the
    /// master key is left untouched. The resulting threshold signature is a
    /// stock Ed25519 signature under the child public key
    /// `key.EDDSAPub + delta·G`. A `None` delta is identical to
    /// [`SigningParty::new`].
    pub fn new_with_kdd(
        params: Parameters,
        key: Key,
        message: &[u8],
        key_derivation_delta: Option<&[u8]>,
    ) -> Result<SigningParty, Error> {
        let key = match key_derivation_delta {
            Some(delta) => key.with_kdd(delta)?,
            None => key,
        };
        Self::new(params, key, message)
    }

    /// Blocks until signing completes.
    pub fn wait(&self) -> Result<SignatureData, Error> {
        self.result_rx
            .recv()
            .unwrap_or_else(|_| Err(Error::Validation("signing dropped without result".into())))
    }
}

impl Shared {
    fn deliver(&self, r: Result<SignatureData, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn fail(&self, m: impl Into<String>) {
        self.deliver(Err(Error::Validation(m.into())));
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let wi = self.prepare_wi()?;
        let ri = vss::random_scalar(&mut rng);
        let point_ri = ed::mul_base(&ri);
        let (rx, ry) = ed::coords_be(&point_ri);
        let (c, d) = super::commit::commit(&[rx, ry], &mut rng);

        {
            let mut st = self.state.lock().unwrap();
            st.wi = wi;
            st.ri = ri;
            st.point_ri = Some(point_ri);
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

        for (k, m) in msgs.iter().enumerate() {
            let r1: R1Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            self.state.lock().unwrap().cjs[others[k].index as usize] = Some(r1.commitment.0);
        }

        let (ri, point_ri, decommit) = {
            let st = self.state.lock().unwrap();
            (st.ri.clone(), st.point_ri.unwrap(), st.decommit.clone())
        };
        let context_i = context_bytes(&self.ssid, i);
        let pf = ZkProof::prove(&context_i, &ri, &point_ri, &mut rng);
        let (ax, ay) = ed::coords_be(&pf.alpha);
        let r2 = R2Msg {
            de_commitment: decommit.into_iter().map(B64Bytes).collect(),
            schnorr_proof_alpha_x: B64Bytes(ax),
            schnorr_proof_alpha_y: B64Bytes(ay),
            schnorr_proof_t: B64Bytes(ed::scalar_to_be(&pf.t)),
        };
        for p in others {
            if let Err(e) = self.send_to(TYPE_R2, &r2, p) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R2, others, {
            let me = Arc::clone(self);
            let others = others.to_vec();
            move |msgs| me.round3(&others, msgs)
        });
    }

    fn round3(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let (ri, point_ri, wi) = {
            let st = self.state.lock().unwrap();
            (st.ri.clone(), st.point_ri.unwrap(), st.wi.clone())
        };

        let mut r = point_ri;
        for (k, oid) in others.iter().enumerate() {
            let r2: R2Msg = match json_get(&msgs[k]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let jidx = oid.index as usize;
            let cj = match &self.state.lock().unwrap().cjs[jidx] {
                Some(c) => c.clone(),
                None => return self.fail("signing: missing round1 commitment"),
            };
            let d: Vec<Vec<u8>> = r2.de_commitment.iter().map(|b| b.0.clone()).collect();
            let opened = match super::commit::decommit(&cj, &d) {
                Some(v) if v.len() == 2 => v,
                _ => return self.fail("signing: R_j decommitment failed"),
            };
            let rj = match ed::point_from_affine_be(&opened[0], &opened[1]) {
                Some(p) => ed::eight_inv_eight(&p),
                None => return self.fail("signing: R_j off curve"),
            };
            let context_j = context_bytes(&self.ssid, jidx);
            let alpha = match ed::point_from_affine_be(
                &r2.schnorr_proof_alpha_x.0,
                &r2.schnorr_proof_alpha_y.0,
            ) {
                Some(p) => p,
                None => return self.fail("signing: Schnorr alpha off curve"),
            };
            let pf = ZkProof {
                alpha,
                t: ed::scalar_from_be(&r2.schnorr_proof_t.0),
            };
            if !pf.verify(&context_j, &rj) {
                return self.fail("signing: Schnorr proof for R_j failed");
            }
            r = ed::add(&r, &rj);
        }

        let encoded_r = ed::encode_point(&r);
        let eddsa_pub = match self.key.eddsa_pub_point() {
            Some(p) => p,
            None => return self.fail("signing: EDDSAPub off curve"),
        };
        let encoded_pub = ed::encode_point(&eddsa_pub);

        // Standard Ed25519 challenge: λ = SHA-512(R ‖ A ‖ M) mod L.
        let mut hin = Vec::with_capacity(64 + self.msg.len());
        hin.extend_from_slice(&encoded_r);
        hin.extend_from_slice(&encoded_pub);
        hin.extend_from_slice(&self.msg);
        let lambda = Scalar::from_bytes_mod_order(&sha512(&hin));

        // s_i = λ·w_i + r_i.
        let local_s = lambda.mul(&wi).add(&ri);

        {
            let mut st = self.state.lock().unwrap();
            st.encoded_r = encoded_r;
            st.local_s = local_s.clone();
        }
        let r3 = R3Msg {
            si: B64Bytes(local_s.to_bytes().to_vec()),
        };
        for p in others {
            if let Err(e) = self.send_to(TYPE_R3, &r3, p) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R3, others, {
            let me = Arc::clone(self);
            move |msgs| me.finalize(msgs)
        });
    }

    fn finalize(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let (encoded_r, local_s) = {
            let st = self.state.lock().unwrap();
            (st.encoded_r, st.local_s.clone())
        };
        let mut sum_s = local_s;
        for m in &msgs {
            let r3: R3Msg = match json_get(m) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let sj = match scalar_from_le(&r3.si.0) {
                Some(s) => s,
                None => return self.fail("signing: non-canonical s_j"),
            };
            sum_s = sum_s.add(&sj);
        }

        let s_le = sum_s.to_bytes();
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&encoded_r);
        signature.extend_from_slice(&s_le);

        // Verify as a stock Ed25519 signature against the group public key.
        let eddsa_pub = self.key.eddsa_pub_point().unwrap();
        let pk = Ed25519PublicKey::from_bytes(ed::encode_point(&eddsa_pub));
        let sig = Ed25519Signature::from_bytes(signature.clone().try_into().unwrap());
        if pk.verify(&self.msg, &sig).is_err() {
            return self.fail("signing: final signature verification failed");
        }

        self.deliver(Ok(SignatureData {
            signature,
            r: encoded_r.to_vec(),
            s: s_le.to_vec(),
            m: self.msg.clone(),
        }));
    }

    /// Lagrange-weighted share `w_i` over the signing committee.
    fn prepare_wi(&self) -> Result<Scalar, Error> {
        let i = self.params.party_index();
        let ks = self.key.ks_scalars();
        if self.params.threshold() + 1 > ks.len() {
            return Err(Error::Validation("signing: t+1 > parties".into()));
        }
        if i >= ks.len() {
            return Err(Error::Validation(
                "signing: party index out of range of key Ks".into(),
            ));
        }
        let mut wi = self.key.xi_scalar();
        for (j, ksj) in ks.iter().enumerate() {
            if j == i {
                continue;
            }
            let denom = ksj.sub(&ks[i]);
            wi = wi.mul(&ksj.mul(&denom.invert()));
        }
        Ok(wi)
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

fn compute_ssid(params: &Parameters, key: &Key) -> Option<Vec<u8>> {
    let (gx, gy) = ed::generator_coords_be();
    let mut list: Vec<Vec<u8>> = vec![ed::field_prime_be(), ed::order_be(), gx, gy];
    for p in params.parties() {
        list.push(p.key.clone());
    }
    for p in &key.big_xj_points()? {
        let (x, y) = ed::coords_be(p);
        list.push(x);
        list.push(y);
    }
    list.push(vec![1]);
    list.push(vec![]);
    let refs: Vec<&[u8]> = list.iter().map(|b| b.as_slice()).collect();
    Some(sha512_256i(&refs).to_vec())
}

fn context_bytes(ssid: &[u8], idx: usize) -> Vec<u8> {
    let mut c = ssid.to_vec();
    if idx != 0 {
        let b = (idx as u64).to_be_bytes();
        let off = b.iter().position(|&x| x != 0).unwrap();
        c.extend_from_slice(&b[off..]);
    }
    c
}

fn scalar_from_le(le: &[u8]) -> Option<Scalar> {
    if le.len() != 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(le);
    Scalar::from_bytes_canonical(&b)
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg {
    #[serde(rename = "commitment")]
    commitment: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg {
    #[serde(rename = "de_commitment")]
    de_commitment: Vec<B64Bytes>,
    #[serde(rename = "schnorr_proof_alpha_x")]
    schnorr_proof_alpha_x: B64Bytes,
    #[serde(rename = "schnorr_proof_alpha_y")]
    schnorr_proof_alpha_y: B64Bytes,
    #[serde(rename = "schnorr_proof_t")]
    schnorr_proof_t: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg {
    #[serde(rename = "si")]
    si: B64Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsatss::keygen::KeygenParty;
    use crate::eddsatss::testvec::fixtures;
    use crate::tss::testhub::TestHub;

    fn ids_from_keys(keys: &[Key]) -> Vec<PartyId> {
        PartyId::sort(
            (0..keys[0].ks.len())
                .map(|i| {
                    let be = keys[0].ks[i].as_be_bytes().to_vec();
                    PartyId::new((i + 1).to_string(), format!("P{i}"), be)
                })
                .collect(),
            0,
        )
    }

    fn sign(keys: &[Key], ids: &[PartyId], t: usize, msg: &[u8]) -> Vec<SignatureData> {
        let hub = TestHub::new(ids);
        let parties: Vec<SigningParty> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                SigningParty::new(params, keys[i].clone(), msg).unwrap()
            })
            .collect();
        parties
            .iter()
            .map(|p| p.wait().expect("signing succeeds"))
            .collect()
    }

    fn ed_verify(pub_pt: &EdwardsPoint, msg: &[u8], sig: &[u8]) -> bool {
        let pk = Ed25519PublicKey::from_bytes(ed::encode_point(pub_pt));
        let mut s = [0u8; 64];
        s.copy_from_slice(sig);
        pk.verify(msg, &Ed25519Signature::from_bytes(s)).is_ok()
    }

    #[test]
    fn keygen_then_sign_verifies() {
        let ids = PartyId::sort(
            (1..=2)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        );
        let t = 1;
        // Keygen.
        let hub = TestHub::new(&ids);
        let kparties: Vec<KeygenParty> = (0..ids.len())
            .map(|i| {
                KeygenParty::new(Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i))).unwrap()
            })
            .collect();
        let keys: Vec<Key> = kparties.iter().map(|p| p.wait().unwrap()).collect();

        let msg = b"hello threshold eddsa";
        let sigs = sign(&keys, &ids, t, msg);
        for s in &sigs[1..] {
            assert_eq!(s.signature, sigs[0].signature);
        }
        assert!(ed_verify(
            &keys[0].eddsa_pub_point().unwrap(),
            msg,
            &sigs[0].signature
        ));
    }

    #[test]
    fn kdd_sign_verifies_under_child_key() {
        let ids = PartyId::sort(
            (1..=2)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        );
        let t = 1;
        let hub = TestHub::new(&ids);
        let kparties: Vec<KeygenParty> = (0..ids.len())
            .map(|i| {
                KeygenParty::new(Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i))).unwrap()
            })
            .collect();
        let keys: Vec<Key> = kparties.iter().map(|p| p.wait().unwrap()).collect();

        let msg = b"child-key threshold eddsa";
        let delta: &[u8] = &[0x00, 0xde, 0xad, 0xbe, 0xef];

        // Sign with the derived child key on every party.
        let shub = TestHub::new(&ids);
        let sigs: Vec<SignatureData> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, shub.broker(i));
                SigningParty::new_with_kdd(params, keys[i].clone(), msg, Some(delta)).unwrap()
            })
            .collect::<Vec<_>>()
            .iter()
            .map(|p| p.wait().expect("KDD signing succeeds"))
            .collect();
        for s in &sigs[1..] {
            assert_eq!(s.signature, sigs[0].signature);
        }

        // Valid stock Ed25519 signature under the child key A + delta·G, and
        // not under the untouched master key.
        let master = keys[0].eddsa_pub_point().unwrap();
        let child = ed::add(&master, &ed::mul_base(&ed::scalar_from_be(delta)));
        assert!(ed_verify(&child, msg, &sigs[0].signature));
        assert!(!ed_verify(&master, msg, &sigs[0].signature));

        // A None delta behaves like plain signing: the result verifies under
        // the untouched master key. (Signatures use random nonces, so two runs
        // differ byte-for-byte; validity, not equality, is the invariant.)
        let shub2 = TestHub::new(&ids);
        let none_sig = {
            let parties: Vec<SigningParty> = (0..ids.len())
                .map(|i| {
                    let params = Parameters::new(ids.to_vec(), &ids[i], t, shub2.broker(i));
                    SigningParty::new_with_kdd(params, keys[i].clone(), msg, None).unwrap()
                })
                .collect();
            parties[0].wait().unwrap()
        };
        assert!(ed_verify(&master, msg, &none_sig.signature));
    }

    #[test]
    fn short_ks_returns_error_not_panic() {
        // A key whose Ks does not cover the whole committee must yield a
        // Validation error, not an out-of-bounds panic. The transparent
        // subset_for_parties reindex rejects the unknown committee member up
        // front (before any slice is indexed by party position).
        let f = fixtures();
        let key: Key =
            serde_json::from_value(f["signing_keys"].as_array().unwrap()[0].clone()).unwrap();
        assert_eq!(key.ks.len(), 2);

        // Committee of 3: the key's two share ids plus an extra id whose key
        // sorts last, so the extra party's index (2) is out of range of Ks.
        let extra_key = vec![0xffu8; 33];
        let mut ids: Vec<PartyId> = (0..key.ks.len())
            .map(|i| {
                let be = key.ks[i].as_be_bytes().to_vec();
                PartyId::new((i + 1).to_string(), format!("P{i}"), be)
            })
            .collect();
        ids.push(PartyId::new("3", "P-extra", extra_key.clone()));
        let ids = PartyId::sort(ids, 0);
        let me = ids.iter().position(|p| p.key == extra_key).unwrap();
        assert!(me >= key.ks.len());

        let hub = TestHub::new(&ids);
        // t+1 = 2 <= ks.len(), so only the new bounds check can reject this.
        let params = Parameters::new(ids.to_vec(), &ids[me], 1, hub.broker(me));
        match SigningParty::new(params, key, b"msg") {
            Err(Error::Validation(m)) => assert!(m.contains("not found"), "{m}"),
            Err(e) => panic!("unexpected error kind: {e:?}"),
            Ok(_) => panic!("expected validation error for short Ks"),
        }
    }

    #[test]
    fn go_keys_sign_and_verify() {
        let f = fixtures();
        let keys: Vec<Key> = f["signing_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .collect();
        let ids = ids_from_keys(&keys);
        let msg = b"migrated eddsa key signs";
        let sigs = sign(&keys, &ids, 1, msg);

        for s in &sigs[1..] {
            assert_eq!(s.signature, sigs[0].signature);
        }
        // Valid stock Ed25519 signature under the Go-generated group key.
        assert!(ed_verify(
            &keys[0].eddsa_pub_point().unwrap(),
            msg,
            &sigs[0].signature
        ));
    }
}
