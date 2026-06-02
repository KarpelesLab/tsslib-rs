//! Two-round FROST(Ed25519) signing (RFC 9591 §5), broker-driven.

use super::Error;
use super::key::Key;
use super::signature::SignatureData;
use crate::frost::binding::{
    NonceCommitment, compute_binding_factors, compute_group_challenge, compute_group_commitment,
    lagrange_coefficient, nonce_generate_labeled,
};
use crate::frost::{Ciphersuite, Ed25519, Scalar, encode_scalar};
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const ROUND1_TYPE: &str = "frost:ed25519:sign:round1";
const ROUND2_TYPE: &str = "frost:ed25519:sign:round2";
const HIDING_LABEL: &[u8] = b"hiding";
const BINDING_LABEL: &[u8] = b"binding";

/// Round-1 broadcast: this signer's nonce commitments `D_i`, `E_i` (32-byte
/// canonical Ed25519 points). Byte fields are base64 (Go `[]byte`).
#[derive(Serialize, Deserialize)]
struct SignRound1Msg {
    #[serde(rename = "hiding", with = "crate::tss::b64::vec")]
    hiding: Vec<u8>,
    #[serde(rename = "binding", with = "crate::tss::b64::vec")]
    binding: Vec<u8>,
}

/// Round-2 broadcast: this signer's partial signature scalar `z_i` (32-byte LE).
#[derive(Serialize, Deserialize)]
struct SignRound2Msg {
    #[serde(rename = "z", with = "crate::tss::b64::vec")]
    z: Vec<u8>,
}

/// A running FROST(Ed25519) signing session. Construct with [`Key::new_signing`];
/// retrieve the result with [`Signing::wait`].
pub struct Signing {
    result_rx: Receiver<Result<SignatureData, Error>>,
    // Keep the shared state alive for as long as the handle lives (the broker
    // also holds it via the registered receivers).
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    msg: Vec<u8>,
    nonces: Mutex<Option<Nonces>>,
    tweak: Option<Scalar>,
    derived_pub: Option<EdwardsPoint>,
    result_tx: Mutex<Option<Sender<Result<SignatureData, Error>>>>,
}

struct Nonces {
    di: Scalar,
    ei: Scalar,
    big_d: EdwardsPoint,
    big_e: EdwardsPoint,
}

impl Key {
    /// Starts a FROST(Ed25519) signing session over `msg`. The key may come
    /// from a larger keygen; `Ks`/`BigXj` are reindexed to the signing
    /// committee via [`Key::subset_for_parties`]. The committee size must be at
    /// least `threshold + 1`.
    pub fn new_signing(&self, msg: Vec<u8>, params: Parameters) -> Result<Signing, Error> {
        self.new_signing_with_tweak(msg, params, None)
    }

    /// Like [`Key::new_signing`] but produces a signature verifiable under the
    /// child public key `group_public_key + tweak·G` (HD derivation). All
    /// signers must pass the same `tweak`. The signer at committee index 0
    /// absorbs the tweak into its `λ·s` term.
    pub fn new_signing_with_tweak(
        &self,
        msg: Vec<u8>,
        params: Parameters,
        tweak: Option<Scalar>,
    ) -> Result<Signing, Error> {
        if params.party_count() < params.threshold() + 1 {
            return Err(Error::Validation(format!(
                "signing committee size {} < threshold+1 ({})",
                params.party_count(),
                params.threshold() + 1
            )));
        }
        let subset = self.subset_for_parties(params.parties())?;

        // Resolve the (optional) HD tweak and derived public key.
        let (tweak, derived_pub) = match tweak {
            None => (None, None),
            Some(t) if bool::from(t.ct_eq(&Scalar::ZERO)) => (None, None),
            Some(t) => {
                let delta = Ed25519::mul_base(&t);
                let derived = Ed25519::add(&subset.group_public_key, &delta);
                if Ed25519::is_identity(&derived) {
                    return Err(Error::Validation(
                        "tweak collapses child key to the identity".into(),
                    ));
                }
                (Some(t), Some(derived))
            }
        };

        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key: subset,
            msg,
            nonces: Mutex::new(None),
            tweak,
            derived_pub,
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
    /// Blocks until the signing session completes, returning the signature or
    /// the first error encountered.
    pub fn wait(&self) -> Result<SignatureData, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "signing session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<SignatureData, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    /// Round 1: sample nonces `(d_i, e_i)`, commit `(D_i, E_i)`, broadcast.
    fn round1(self: &Arc<Self>) {
        let mut rng = OsRng;
        let mut rand = [0u8; 32];
        rng.fill_bytes(&mut rand);
        let di = nonce_generate_labeled::<Ed25519>(&rand, &self.key.xi, HIDING_LABEL);
        rng.fill_bytes(&mut rand);
        let ei = nonce_generate_labeled::<Ed25519>(&rand, &self.key.xi, BINDING_LABEL);
        let big_d = Ed25519::mul_base(&di);
        let big_e = Ed25519::mul_base(&ei);
        *self.nonces.lock().unwrap() = Some(Nonces {
            di: di.clone(),
            ei: ei.clone(),
            big_d,
            big_e,
        });

        let r1 = SignRound1Msg {
            hiding: Ed25519::encode_point(&big_d).to_vec(),
            binding: Ed25519::encode_point(&big_e).to_vec(),
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

    /// Round 2: assemble commitments, derive binding factors, compute the group
    /// commitment `R` and challenge `c`, emit the partial signature `z_i`.
    fn round2(self: &Arc<Self>, others: &[PartyId], r1msgs: Vec<JsonMessage>) {
        let nonces = self.nonces.lock().unwrap().take();
        let Some(nonces) = nonces else {
            return self.deliver(Err(Error::Validation(
                "round2 without round1 nonces".into(),
            )));
        };
        let me_id = self.params.party_id().key.clone();

        // commitments[0] = self, then peers in `others` order.
        let mut commitments: Vec<NonceCommitment<Ed25519>> = Vec::with_capacity(others.len() + 1);
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

        let binding_factors = compute_binding_factors::<Ed25519>(&self.msg, &commitments);
        let Some(r) = compute_group_commitment::<Ed25519>(&commitments, &binding_factors) else {
            return self.deliver(Err(Error::Validation(
                "failed to compute group commitment".into(),
            )));
        };
        let challenge_pub = self.derived_pub.unwrap_or(self.key.group_public_key);
        let c = compute_group_challenge::<Ed25519>(&r, &challenge_pub, &self.msg);

        let signer_ids: Vec<Vec<u8>> = commitments.iter().map(|cm| cm.identifier.clone()).collect();
        let Some(lambda_i) = lagrange_coefficient::<Ed25519>(&me_id, &signer_ids) else {
            return self.deliver(Err(Error::Validation("duplicate signer identifier".into())));
        };
        let rho_i = binding_factors
            .get(strip(&me_id))
            .expect("self binding factor present");

        // tweak term: only the committee's index-0 signer folds in the tweak.
        let tweak_term = match (&self.tweak, self.params.party_index() == 0) {
            (Some(t), true) => t.clone(),
            _ => Scalar::ZERO,
        };

        // z_i = (λ_i·s_i + tweak_term)·c + (e_i·ρ_i + d_i)   (mod L)
        let t1 = nonces.ei.mul(rho_i).add(&nonces.di);
        let t2 = lambda_i.mul(&self.key.xi).add(&tweak_term);
        let zi = t2.mul(&c).add(&t1);

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

    /// Finalize: verify each peer's partial, sum them, emit `(R, S)`.
    #[allow(clippy::too_many_arguments)]
    fn finalize(
        self: &Arc<Self>,
        others: &[PartyId],
        commitments: Vec<NonceCommitment<Ed25519>>,
        binding_factors: std::collections::HashMap<Vec<u8>, Scalar>,
        r: EdwardsPoint,
        c: Scalar,
        my_zi: Scalar,
        r2msgs: Vec<JsonMessage>,
    ) {
        let signer_ids: Vec<Vec<u8>> = commitments.iter().map(|cm| cm.identifier.clone()).collect();

        // Verification share Y_j by identifier.
        let big_x_by_id: std::collections::HashMap<&[u8], EdwardsPoint> = self
            .key
            .ks
            .iter()
            .zip(self.key.big_xj.iter())
            .map(|(k, p)| (strip(k.as_be_bytes()), *p))
            .collect();

        // HD: the augment point tweak·G, and committee signer-0's identifier.
        let tweak_delta = self.tweak.as_ref().map(Ed25519::mul_base);
        let signer0_id = self.params.parties()[0].key.clone();

        let mut z = my_zi;
        for (n, pid) in others.iter().enumerate() {
            // commitments[n+1] aligns with others[n].
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
            let commit_share = Ed25519::add(&cm.hiding, &Ed25519::scalar_mul(&cm.binding, rho_j));
            let Some(lambda_j) = lagrange_coefficient::<Ed25519>(&cm.identifier, &signer_ids)
            else {
                return self.deliver(Err(Error::Validation("duplicate signer identifier".into())));
            };
            let clambda = c.mul(&lambda_j);
            let lhs = Ed25519::mul_base(&zj);
            let mut rhs = Ed25519::add(&commit_share, &Ed25519::scalar_mul(&yj, &clambda));
            // HD augmentation for committee signer-0's partial.
            if let Some(td) = tweak_delta.as_ref() {
                if cmp_eq(&cm.identifier, &signer0_id) {
                    rhs = Ed25519::add(&rhs, &Ed25519::scalar_mul(td, &c));
                }
            }
            if !Ed25519::eq(&lhs, &rhs) {
                return self.deliver(Err(Error::Validation(format!(
                    "partial signature from {pid} failed verification"
                ))));
            }
            z = z.add(&zj);
        }

        let r_enc = Ed25519::encode_point(&r);
        let s_enc = encode_scalar(&z);
        let verify_pub = self.derived_pub.unwrap_or(self.key.group_public_key);

        // Local sanity check: the aggregate must verify as a stock Ed25519 sig.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_enc);
        sig_bytes[32..].copy_from_slice(&s_enc);
        let pk = Ed25519PublicKey::from_bytes(Ed25519::encode_point(&verify_pub));
        if pk
            .verify(&self.msg, &Ed25519Signature::from_bytes(sig_bytes))
            .is_err()
        {
            return self.deliver(Err(Error::Validation(
                "aggregated signature failed Ed25519 verification".into(),
            )));
        }

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

/// Decodes a 32-byte canonical Ed25519 point.
fn decode_point(b: &[u8]) -> Option<EdwardsPoint> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Ed25519::decode_point(&arr)
}

/// Decodes a 32-byte little-endian canonical scalar.
fn decode_scalar(b: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = b.try_into().ok()?;
    crate::frost::decode_scalar(&arr)
}

fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

fn cmp_eq(a: &[u8], b: &[u8]) -> bool {
    strip(a) == strip(b)
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

    /// Horner evaluation of `coeffs[0] + coeffs[1]·x + …` at `x` (mod L).
    fn eval(coeffs: &[Scalar], x: &Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for c in coeffs.iter().rev() {
            acc = acc.mul(x).add(c);
        }
        acc
    }

    /// Builds `n` consistent FROST keys with reconstruction threshold `t` via a
    /// trusted dealer (test-only; real keys come from the DKG). Party `i` has
    /// identifier `i+1`.
    fn trusted_dealer(n: usize, t: usize) -> (Vec<PartyId>, Vec<Key>) {
        let coeffs: Vec<Scalar> = (0..=t).map(|_| rand_scalar()).collect();
        let group_pub = Ed25519::mul_base(&coeffs[0]);
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
        let big_xj: Vec<EdwardsPoint> = xs.iter().map(Ed25519::mul_base).collect();
        let keys = (0..n)
            .map(|i| Key {
                xi: xs[i].clone(),
                share_id: ks[i].clone(),
                ks: ks.clone(),
                big_xj: big_xj.clone(),
                group_public_key: group_pub,
                chain_code: None,
            })
            .collect();
        (ids, keys)
    }

    /// Drives a full signing with the first `committee` parties and asserts the
    /// aggregate verifies under the group public key.
    fn run_signing(n: usize, t: usize, committee: usize) {
        let (ids, keys) = trusted_dealer(n, t);
        for k in &keys {
            k.validate_basic().unwrap();
        }
        let committee_ids: Vec<PartyId> = ids[..committee].to_vec();
        let hub = TestHub::new(&committee_ids);
        let msg = b"threshold FROST message".to_vec();

        let signings: Vec<Signing> = (0..committee)
            .map(|i| {
                let params =
                    Parameters::new(committee_ids.clone(), &committee_ids[i], t, hub.broker(i));
                keys[i].new_signing(msg.clone(), params).unwrap()
            })
            .collect();

        let group_pub = keys[0].group_public_key;
        let pk = Ed25519PublicKey::from_bytes(Ed25519::encode_point(&group_pub));
        let mut first: Option<Vec<u8>> = None;
        for s in &signings {
            let sig = s.wait().expect("signing succeeds");
            assert_eq!(sig.signature.len(), 64);
            let mut sb = [0u8; 64];
            sb.copy_from_slice(&sig.signature);
            pk.verify(&msg, &Ed25519Signature::from_bytes(sb))
                .expect("verifies under group public key");
            match &first {
                None => first = Some(sig.signature.clone()),
                Some(f) => assert_eq!(f, &sig.signature, "all signers agree on the signature"),
            }
        }
    }

    #[test]
    fn sign_2_of_3_committee_2() {
        run_signing(3, 1, 2);
    }

    #[test]
    fn sign_3_of_5_committee_3() {
        run_signing(5, 2, 3);
    }

    #[test]
    fn sign_full_committee_equals_keygen_set() {
        run_signing(3, 2, 3);
    }
}
