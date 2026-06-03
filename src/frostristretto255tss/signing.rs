//! Two-round FROST(ristretto255) signing (RFC 9591 §5), broker-driven.
//!
//! Structurally identical to [`crate::frosttss`] signing over the Ristretto255
//! group, minus HD tweaks. The aggregate is self-verified with the Schnorr
//! check `z·G == R + c·A` (Ristretto255 has no stock external verifier).

use super::Error;
use super::key::Key;
use super::signature::SignatureData;
use crate::frost::binding::{
    NonceCommitment, compute_binding_factors, compute_group_challenge, compute_group_commitment,
    lagrange_coefficient, nonce_generate_labeled,
};
use crate::frost::{Ciphersuite, Ristretto255, Scalar, encode_scalar};
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::ec::ristretto255::RistrettoPoint;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const ROUND1_TYPE: &str = "frost:ristretto255:sign:round1";
const ROUND2_TYPE: &str = "frost:ristretto255:sign:round2";
const HIDING_LABEL: &[u8] = b"hiding";
const BINDING_LABEL: &[u8] = b"binding";

#[derive(Serialize, Deserialize)]
struct SignRound1Msg {
    #[serde(rename = "hiding", with = "crate::tss::b64::vec")]
    hiding: Vec<u8>,
    #[serde(rename = "binding", with = "crate::tss::b64::vec")]
    binding: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SignRound2Msg {
    #[serde(rename = "z", with = "crate::tss::b64::vec")]
    z: Vec<u8>,
}

/// A running FROST(ristretto255) signing session. Construct with
/// [`Key::new_signing`]; retrieve the result with [`Signing::wait`].
pub struct Signing {
    result_rx: Receiver<Result<SignatureData, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    msg: Vec<u8>,
    nonces: Mutex<Option<Nonces>>,
    result_tx: Mutex<Option<Sender<Result<SignatureData, Error>>>>,
}

struct Nonces {
    di: Scalar,
    ei: Scalar,
    big_d: RistrettoPoint,
    big_e: RistrettoPoint,
}

impl Key {
    /// Starts a FROST(ristretto255) signing session over `msg`. The key is
    /// reindexed to the signing committee; the committee must be at least
    /// `threshold + 1`.
    pub fn new_signing(&self, msg: Vec<u8>, params: Parameters) -> Result<Signing, Error> {
        if params.party_count() < params.threshold() + 1 {
            return Err(Error::Validation(format!(
                "signing committee size {} < threshold+1 ({})",
                params.party_count(),
                params.threshold() + 1
            )));
        }
        let subset = self.subset_for_parties(params.parties())?;
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key: subset,
            msg,
            nonces: Mutex::new(None),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1();
        Ok(Signing {
            result_rx: rx,
            _shared: shared,
        })
    }
}

impl Signing {
    /// Blocks until signing completes, returning the signature or first error.
    pub fn wait(&self) -> Result<SignatureData, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("signing dropped without result".into())),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<SignatureData, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) {
        let mut rng = OsRng;
        let mut rand = [0u8; 32];
        rng.fill_bytes(&mut rand);
        let di = nonce_generate_labeled::<Ristretto255>(&rand, &self.key.xi, HIDING_LABEL);
        rng.fill_bytes(&mut rand);
        let ei = nonce_generate_labeled::<Ristretto255>(&rand, &self.key.xi, BINDING_LABEL);
        let big_d = Ristretto255::mul_base(&di);
        let big_e = Ristretto255::mul_base(&ei);
        *self.nonces.lock().unwrap() = Some(Nonces {
            di,
            ei,
            big_d,
            big_e,
        });

        let r1 = SignRound1Msg {
            hiding: Ristretto255::encode_point(&big_d).to_vec(),
            binding: Ristretto255::encode_point(&big_e).to_vec(),
        };
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
        let nonces = self.nonces.lock().unwrap().take();
        let Some(nonces) = nonces else {
            return self.deliver(Err(Error::Validation(
                "round2 without round1 nonces".into(),
            )));
        };
        let me_id = self.params.party_id().key.clone();

        let mut commitments: Vec<NonceCommitment<Ristretto255>> =
            Vec::with_capacity(others.len() + 1);
        commitments.push(NonceCommitment {
            identifier: me_id.clone(),
            hiding: nonces.big_d,
            binding: nonces.big_e,
        });
        for (pid, msg) in others.iter().zip(r1msgs.iter()) {
            let r1: SignRound1Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let (Some(big_d), Some(big_e)) = (decode_point(&r1.hiding), decode_point(&r1.binding))
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent an invalid nonce commitment"
                ))));
            };
            commitments.push(NonceCommitment {
                identifier: pid.key.clone(),
                hiding: big_d,
                binding: big_e,
            });
        }

        let binding_factors = compute_binding_factors::<Ristretto255>(&self.msg, &commitments);
        let Some(r) = compute_group_commitment::<Ristretto255>(&commitments, &binding_factors)
        else {
            return self.deliver(Err(Error::Validation(
                "failed to compute group commitment".into(),
            )));
        };
        let c = compute_group_challenge::<Ristretto255>(&r, &self.key.group_public_key, &self.msg);

        let signer_ids: Vec<Vec<u8>> = commitments.iter().map(|cm| cm.identifier.clone()).collect();
        let Some(lambda_i) = lagrange_coefficient::<Ristretto255>(&me_id, &signer_ids) else {
            return self.deliver(Err(Error::Validation("duplicate signer identifier".into())));
        };
        let rho_i = binding_factors
            .get(strip(&me_id))
            .expect("self binding factor present");

        // z_i = λ_i·s_i·c + e_i·ρ_i + d_i  (mod L)
        let t1 = nonces.ei.mul(rho_i).add(&nonces.di);
        let zi = lambda_i.mul(&self.key.xi).mul(&c).add(&t1);

        let r2 = SignRound2Msg {
            z: encode_scalar(&zi).to_vec(),
        };
        if let Err(e) = self.broadcast(ROUND2_TYPE, &r2) {
            return self.deliver(Err(e));
        }

        let me = Arc::clone(self);
        let others_owned = others.to_vec();
        let expect = JsonExpect::new(
            ROUND2_TYPE,
            others_owned.clone(),
            Box::new(move |msgs| {
                me.finalize(&others_owned, commitments, binding_factors, r, c, zi, msgs)
            }),
        );
        self.params.broker().connect(ROUND2_TYPE, Arc::new(expect));
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize(
        self: &Arc<Self>,
        others: &[PartyId],
        commitments: Vec<NonceCommitment<Ristretto255>>,
        binding_factors: std::collections::HashMap<Vec<u8>, Scalar>,
        r: RistrettoPoint,
        c: Scalar,
        my_zi: Scalar,
        r2msgs: Vec<JsonMessage>,
    ) {
        let signer_ids: Vec<Vec<u8>> = commitments.iter().map(|cm| cm.identifier.clone()).collect();
        let big_x_by_id: std::collections::HashMap<&[u8], RistrettoPoint> = self
            .key
            .ks
            .iter()
            .zip(self.key.big_xj.iter())
            .map(|(k, p)| (strip(k.as_be_bytes()), *p))
            .collect();

        let mut z = my_zi;
        for (n, pid) in others.iter().enumerate() {
            let cm = &commitments[n + 1];
            let r2: SignRound2Msg = match json_get(&r2msgs[n]) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let Some(zj) = decode_scalar(&r2.z) else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent invalid z"
                ))));
            };
            let Some(&yj) = big_x_by_id.get(strip(&pid.key)) else {
                return self.deliver(Err(Error::Validation(format!(
                    "missing verification share for {pid}"
                ))));
            };
            let rho_j = binding_factors
                .get(strip(&cm.identifier))
                .expect("peer binding factor present");
            let commit_share =
                Ristretto255::add(&cm.hiding, &Ristretto255::scalar_mul(&cm.binding, rho_j));
            let Some(lambda_j) = lagrange_coefficient::<Ristretto255>(&cm.identifier, &signer_ids)
            else {
                return self.deliver(Err(Error::Validation("duplicate signer identifier".into())));
            };
            let clambda = c.mul(&lambda_j);
            let lhs = Ristretto255::mul_base(&zj);
            let rhs = Ristretto255::add(&commit_share, &Ristretto255::scalar_mul(&yj, &clambda));
            if !Ristretto255::eq(&lhs, &rhs) {
                return self.deliver(Err(Error::Validation(format!(
                    "partial signature from {pid} failed verification"
                ))));
            }
            z = z.add(&zj);
        }

        // Self-verify: z·G == R + c·A.
        let lhs = Ristretto255::mul_base(&z);
        let rhs = Ristretto255::add(
            &r,
            &Ristretto255::scalar_mul(&self.key.group_public_key, &c),
        );
        if !Ristretto255::eq(&lhs, &rhs) {
            return self.deliver(Err(Error::Validation(
                "aggregated signature failed Schnorr self-check".into(),
            )));
        }

        let r_enc = Ristretto255::encode_point(&r);
        let s_enc = encode_scalar(&z);
        self.deliver(Ok(SignatureData::new(
            r_enc.to_vec(),
            s_enc.to_vec(),
            self.msg.clone(),
        )));
    }

    fn broadcast<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        let msg = json_wrap(typ, body, Some(self.params.party_id().clone()), None)?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }
}

fn decode_point(b: &[u8]) -> Option<RistrettoPoint> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Ristretto255::decode_point(&arr)
}

fn decode_scalar(b: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = b.try_into().ok()?;
    crate::frost::decode_scalar(&arr)
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::scalar_from_be_mod_l;
    use crate::tss::bigint::BigUintDec;
    use crate::tss::testhub::TestHub;

    fn rand_scalar() -> Scalar {
        let mut b = [0u8; 64];
        OsRng.fill_bytes(&mut b);
        Scalar::from_bytes_mod_order(&b)
    }

    fn eval(coeffs: &[Scalar], x: &Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for c in coeffs.iter().rev() {
            acc = acc.mul(x).add(c);
        }
        acc
    }

    fn trusted_dealer(n: usize, t: usize) -> (Vec<PartyId>, Vec<Key>) {
        let coeffs: Vec<Scalar> = (0..=t).map(|_| rand_scalar()).collect();
        let group_pub = Ristretto255::mul_base(&coeffs[0]);
        let ids = PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        );
        let ks: Vec<BigUintDec> = ids
            .iter()
            .map(|p| BigUintDec::from_be_bytes(&p.key))
            .collect();
        let xs: Vec<Scalar> = ids
            .iter()
            .map(|p| eval(&coeffs, &scalar_from_be_mod_l(&p.key)))
            .collect();
        let big_xj: Vec<RistrettoPoint> = xs.iter().map(Ristretto255::mul_base).collect();
        let keys = (0..n)
            .map(|i| Key {
                xi: xs[i].clone(),
                share_id: ks[i].clone(),
                ks: ks.clone(),
                big_xj: big_xj.clone(),
                group_public_key: group_pub,
            })
            .collect();
        (ids, keys)
    }

    fn run_signing(n: usize, t: usize, committee: usize) {
        let (ids, keys) = trusted_dealer(n, t);
        for k in &keys {
            k.validate_basic().unwrap();
        }
        let committee_ids: Vec<PartyId> = ids[..committee].to_vec();
        let hub = TestHub::new(&committee_ids);
        let msg = b"ristretto FROST message".to_vec();
        let signings: Vec<Signing> = (0..committee)
            .map(|i| {
                let params =
                    Parameters::new(committee_ids.clone(), &committee_ids[i], t, hub.broker(i));
                keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();
        let mut first: Option<Vec<u8>> = None;
        for s in &signings {
            let sig = s.wait().expect("signing succeeds");
            assert_eq!(sig.signature.len(), 64);
            match &first {
                None => first = Some(sig.signature.clone()),
                Some(f) => assert_eq!(f, &sig.signature, "all signers agree"),
            }
        }
    }

    #[test]
    fn sign_2_of_3() {
        run_signing(3, 1, 2);
    }

    #[test]
    fn sign_3_of_5() {
        run_signing(5, 2, 3);
    }
}
