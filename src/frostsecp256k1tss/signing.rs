//! Two-round FROST signing (RFC 9591 §5) producing a BIP340 signature,
//! optionally under an HD child key and/or a BIP341 Taproot output key.
//!
//! The key actually signed for is
//! `Q = g2 · (g1 · (P + t·G) + h·G)`, where `t` is the HD tweak, `g1` makes
//! the (child) internal key's `Y` even, `h` is the BIP341 TapTweak of its
//! x-only form, and `g2` makes the output key's `Y` even. Its secret is
//! `sign · x + offset` with `sign = g1·g2` and `offset = g2·(g1·t + h)`:
//! every signer scales its share by `sign`, and the aggregate adds
//! `c · offset`. If the group commitment `R` has an odd `Y`, every signer
//! negates its nonces, so the final `R` is even as BIP340 requires.
//!
//! The binding factors commit to `Q`, so signers that disagree on the
//! options fail partial-signature verification instead of producing an
//! invalid signature.

use super::Error;
use super::key::{Key, strip};
use super::signature::SignatureData;
use super::suite::{
    NonceCommitment, Point, Scalar, TR, bip340_challenge, decode_point, decode_scalar,
    encode_point, even_y, group_commitment, id_scalar, is_identity, lagrange_coefficient, mul_base,
    point_eq, sign_scalar, tap_tweak, x_only,
};
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::sync::{Mutex, Receiver, Sender, channel};
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use alloc::sync::Arc;
use purecrypto::ec::secp256k1::schnorr;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};

const ROUND1_TYPE: &str = "frost:secp256k1-tr:sign:round1";
const ROUND2_TYPE: &str = "frost:secp256k1-tr:sign:round2";
const HIDING_LABEL: &[u8] = b"hiding";
const BINDING_LABEL: &[u8] = b"binding";

/// The BIP341 tweak to apply to the (x-only) internal key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaprootTweak {
    /// Key-path-only output with no script tree: `hash_TapTweak(x(P))`, as
    /// BIP86 wallets use.
    KeyPathOnly,
    /// Output committing to a script tree: `hash_TapTweak(x(P) || root)`.
    ScriptTree([u8; 32]),
}

impl TaprootTweak {
    fn merkle_root(&self) -> Option<&[u8; 32]> {
        match self {
            TaprootTweak::KeyPathOnly => None,
            TaprootTweak::ScriptTree(root) => Some(root),
        }
    }
}

/// What to sign for. The default is a plain BIP340 signature under the
/// group's x-only key.
#[derive(Clone, Default)]
pub struct SignOptions {
    /// Additive HD tweak (from [`Key::derive_child`]); the child key is
    /// `P + tweak·G`.
    pub tweak: Option<Scalar>,
    /// BIP341 tweak applied after the HD tweak, for a Taproot key-path spend.
    pub taproot: Option<TaprootTweak>,
}

/// The key a [`SignOptions`] signs for, and how each share maps onto it.
pub(crate) struct SigningKey {
    /// Even-`Y` key the signature verifies under.
    pub q: Point,
    pub q_x: [u8; 32],
    /// `±1` applied to every share.
    sign: Scalar,
    /// Public secret offset, added to the aggregate as `c · offset`.
    offset: Scalar,
}

impl SigningKey {
    pub(crate) fn new(group_public_key: &Point, opts: &SignOptions) -> Result<Self, Error> {
        let t = opts.tweak.clone().unwrap_or(Scalar::ZERO);
        let child = group_public_key.add(&mul_base(&t));
        if is_identity(&child) {
            return Err(Error::Validation("HD tweak collapses the key".into()));
        }
        let (internal, neg1) = even_y(&child);
        let (q0, h) = match &opts.taproot {
            None => (internal, Scalar::ZERO),
            Some(tw) => {
                let ix = x_only(&internal).expect("non-identity");
                let h = tap_tweak(&ix, tw.merkle_root()).ok_or_else(|| {
                    Error::Validation("TapTweak hash is not below the group order".into())
                })?;
                let q0 = internal.add(&mul_base(&h));
                if is_identity(&q0) {
                    return Err(Error::Validation("Taproot tweak collapses the key".into()));
                }
                (q0, h)
            }
        };
        let (q, neg2) = even_y(&q0);
        let (g1, g2) = (sign_scalar(neg1), sign_scalar(neg2));
        Ok(SigningKey {
            q,
            q_x: x_only(&q).expect("non-identity"),
            sign: g1.mul(&g2),
            offset: g2.mul(&g1.mul(&t).add(&h)),
        })
    }
}

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

/// A running signing session. Construct with [`Key::new_signing`] or
/// [`Key::new_signing_with`].
pub struct Signing {
    result_rx: Receiver<Result<SignatureData, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    msg: Vec<u8>,
    signing_key: SigningKey,
    nonces: Mutex<Option<Nonces>>,
    result_tx: Mutex<Option<Sender<Result<SignatureData, Error>>>>,
}

struct Nonces {
    d: Scalar,
    e: Scalar,
    big_d: Point,
    big_e: Point,
}

/// What round 2 hands to the final aggregation.
struct Round2 {
    commitments: Vec<NonceCommitment>,
    rho: Vec<Scalar>,
    r_x: [u8; 32],
    r_negated: bool,
    c: Scalar,
    my_z: Scalar,
}

impl Key {
    /// Starts a session producing a BIP340 signature over `msg` under the
    /// group's x-only key. The committee (`params.parties()`) needs at least
    /// `threshold + 1` members holding shares of this key.
    pub fn new_signing(&self, msg: Vec<u8>, params: Parameters) -> Result<Signing, Error> {
        self.new_signing_with(msg, params, SignOptions::default())
    }

    /// Like [`Key::new_signing`], signing for the key `opts` selects (HD
    /// child and/or Taproot output key). Every signer must pass the same
    /// options.
    pub fn new_signing_with(
        &self,
        msg: Vec<u8>,
        params: Parameters,
        opts: SignOptions,
    ) -> Result<Signing, Error> {
        if params.party_count() < params.threshold() + 1 {
            return Err(Error::Validation(format!(
                "signing committee size {} < threshold+1 ({})",
                params.party_count(),
                params.threshold() + 1
            )));
        }
        let ids: Vec<Vec<u8>> = params.parties().iter().map(|p| p.key.clone()).collect();
        super::vss::check_indexes(params.threshold(), &ids)
            .map_err(|e| Error::Validation(format!("signing committee: {e}")))?;
        let key = self.subset_for_parties(params.parties())?;
        let signing_key = SigningKey::new(&key.group_public_key, &opts)?;
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key,
            msg,
            signing_key,
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
    /// Non-blocking peek at the result: `Some(_)` once the signature (or an
    /// error) is ready, `None` while rounds are pending.
    pub fn try_result(&self) -> Option<Result<SignatureData, Error>> {
        self.result_rx.try_recv().ok()
    }

    /// Blocks until signing completes.
    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> Result<SignatureData, Error> {
        self.result_rx
            .recv()
            .unwrap_or_else(|_| Err(Error::Validation("signing dropped without result".into())))
    }
}

impl Shared {
    fn deliver(&self, r: Result<SignatureData, Error>) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    fn fail(&self, m: impl Into<String>) {
        self.deliver(Err(Error::Validation(m.into())));
    }

    fn round1(self: &Arc<Self>) {
        let mut rand = [0u8; 32];
        SystemRng.fill_bytes(&mut rand);
        let d = TR.nonce_generate_labeled(&rand, &self.key.xi, HIDING_LABEL);
        SystemRng.fill_bytes(&mut rand);
        let e = TR.nonce_generate_labeled(&rand, &self.key.xi, BINDING_LABEL);
        let (big_d, big_e) = (mul_base(&d), mul_base(&e));
        let (Some(hiding), Some(binding)) = (encode_point(&big_d), encode_point(&big_e)) else {
            return self.fail("zero signing nonce");
        };
        *self.nonces.lock() = Some(Nonces { d, e, big_d, big_e });

        let r1 = SignRound1Msg {
            hiding: hiding.to_vec(),
            binding: binding.to_vec(),
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
        let Some(nonces) = self.nonces.lock().take() else {
            return self.fail("round2 without round1 nonces");
        };
        let mut commitments = Vec::with_capacity(others.len() + 1);
        commitments.push(NonceCommitment {
            id: id_scalar(&self.params.party_id().key),
            hiding: nonces.big_d,
            binding: nonces.big_e,
        });
        for (pid, msg) in others.iter().zip(&r1msgs) {
            let r1: SignRound1Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let (Some(hiding), Some(binding)) =
                (decode_point(&r1.hiding), decode_point(&r1.binding))
            else {
                return self.fail(format!("party {pid} sent an invalid nonce commitment"));
            };
            commitments.push(NonceCommitment {
                id: id_scalar(&pid.key),
                hiding,
                binding,
            });
        }

        let sk = &self.signing_key;
        let Some(rho) = TR.binding_factors(&sk.q, &self.msg, &commitments) else {
            return self.fail("nonce commitment is the identity");
        };
        let r = group_commitment(&commitments, &rho);
        if is_identity(&r) {
            return self.fail("group commitment is the identity");
        }
        let (r_even, r_negated) = even_y(&r);
        let r_x = x_only(&r_even).expect("non-identity");
        let c = bip340_challenge(&r_x, &sk.q_x, &self.msg);

        let ids: Vec<Scalar> = commitments.iter().map(|cm| cm.id.clone()).collect();
        let Some(lambda) = lagrange_coefficient(&ids[0], &ids) else {
            return self.fail("duplicate signer identifier");
        };
        // z_i = ±(d_i + e_i·ρ_i) + λ_i · sign · s_i · c
        let nonce = sign_scalar(r_negated).mul(&nonces.d.add(&nonces.e.mul(&rho[0])));
        let my_z = nonce.add(&lambda.mul(&sk.sign).mul(&self.key.xi).mul(&c));

        let r2 = SignRound2Msg {
            z: my_z.to_bytes_be().to_vec(),
        };
        if let Err(e) = self.broadcast(ROUND2_TYPE, &r2) {
            return self.deliver(Err(e));
        }

        let round = Round2 {
            commitments,
            rho,
            r_x,
            r_negated,
            c,
            my_z,
        };
        let me = Arc::clone(self);
        let others = others.to_vec();
        let expect = JsonExpect::new(
            ROUND2_TYPE,
            others.clone(),
            Box::new(move |msgs| me.finalize(&others, round, msgs)),
        );
        self.params.broker().connect(ROUND2_TYPE, Arc::new(expect));
    }

    fn finalize(self: &Arc<Self>, others: &[PartyId], round: Round2, r2msgs: Vec<JsonMessage>) {
        let sk = &self.signing_key;
        let ids: Vec<Scalar> = round.commitments.iter().map(|cm| cm.id.clone()).collect();
        let nonce_sign = sign_scalar(round.r_negated);
        let mut z = round.my_z.clone();
        for (n, (pid, msg)) in others.iter().zip(&r2msgs).enumerate() {
            let r2: SignRound2Msg = match json_get(msg) {
                Ok(v) => v,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let Some(zj) = decode_scalar(&r2.z) else {
                return self.fail(format!("party {pid} sent an invalid z"));
            };
            let Some(yj) = self.verification_share(pid) else {
                return self.fail(format!("missing verification share for {pid}"));
            };
            let cm = &round.commitments[n + 1];
            let Some(lambda) = lagrange_coefficient(&cm.id, &ids) else {
                return self.fail("duplicate signer identifier");
            };
            // z_j·G == ±(D_j + ρ_j·E_j) + (c·λ_j·sign)·Y_j
            let commit = cm.hiding.add(&cm.binding.mul(&round.rho[n + 1]));
            let rhs = commit
                .mul(&nonce_sign)
                .add(&yj.mul(&round.c.mul(&lambda).mul(&sk.sign)));
            if !point_eq(&mul_base(&zj), &rhs) {
                return self.fail(format!("partial signature from {pid} failed verification"));
            }
            z = z.add(&zj);
        }
        let z = z.add(&round.c.mul(&sk.offset));

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&round.r_x);
        sig[32..].copy_from_slice(&z.to_bytes_be());
        if schnorr::verify(&sk.q_x, &self.msg, &sig).is_err() {
            return self.fail("aggregate signature failed BIP340 verification");
        }
        self.deliver(Ok(SignatureData {
            r: round.r_x.to_vec(),
            s: sig[32..].to_vec(),
            signature: sig.to_vec(),
            m: self.msg.clone(),
            public_key: sk.q_x.to_vec(),
        }));
    }

    fn verification_share(&self, pid: &PartyId) -> Option<Point> {
        let want = strip(&pid.key);
        let i = self.key.ks.iter().position(|k| k.as_be_bytes() == want)?;
        Some(self.key.big_xj[i])
    }

    fn broadcast<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        let msg = json_wrap(typ, body, Some(self.params.party_id().clone()), None)?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frostsecp256k1tss::hd::import_key;
    use crate::frostsecp256k1tss::keygen::tests::{party_ids, run_keygen};
    use crate::frostsecp256k1tss::resharing::Resharing;
    use crate::frostsecp256k1tss::suite::has_even_y;
    use crate::tss::ReSharingParameters;
    use crate::tss::testhub::{ReshareHub, TestHub};

    /// Signs `msg` with the first `signers` keys and returns the (agreed)
    /// signature, checked against a stock BIP340 verifier.
    fn sign(
        keys: &[Key],
        ids: &[PartyId],
        t: usize,
        msg: &[u8],
        opts: &SignOptions,
    ) -> SignatureData {
        let hub = TestHub::new(ids);
        let sessions: Vec<Signing> = (0..ids.len())
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                keys[i]
                    .new_signing_with(msg.to_vec(), params, opts.clone())
                    .unwrap()
            })
            .collect();
        let sigs: Vec<SignatureData> = sessions
            .iter()
            .map(|s| s.wait().expect("signing"))
            .collect();
        for s in &sigs[1..] {
            assert_eq!(s, &sigs[0], "all signers agree");
        }
        let pk: [u8; 32] = sigs[0].public_key.as_slice().try_into().unwrap();
        schnorr::verify(&pk, msg, &sigs[0].to_bytes()).expect("valid BIP340 signature");
        sigs[0].clone()
    }

    fn reshare(
        old_keys: &[Key],
        old_ids: &[PartyId],
        old_t: usize,
        new_ids: &[PartyId],
        new_t: usize,
    ) -> Vec<Key> {
        // One session per distinct party; members of both committees run a
        // single dual session.
        let same = |a: &PartyId, b: &PartyId| a.cmp_key(b) == core::cmp::Ordering::Equal;
        let mut all = old_ids.to_vec();
        all.extend(
            new_ids
                .iter()
                .filter(|n| !old_ids.iter().any(|o| same(o, n)))
                .cloned(),
        );
        let hub = ReshareHub::new(&all);
        let sessions: Vec<(PartyId, Resharing)> = all
            .iter()
            .map(|p| {
                let params = ReSharingParameters::new(
                    old_ids.to_vec(),
                    new_ids.to_vec(),
                    old_t,
                    new_t,
                    p.clone(),
                    hub.broker(p),
                );
                let input = old_ids
                    .iter()
                    .position(|o| same(o, p))
                    .map(|i| old_keys[i].clone());
                (p.clone(), Resharing::new(params, input).unwrap())
            })
            .collect();
        let mut out = Vec::new();
        for n in new_ids {
            let (_, s) = sessions.iter().find(|(p, _)| same(p, n)).unwrap();
            let k = s.wait().expect("reshare").expect("new member gets a key");
            k.validate_basic().unwrap();
            out.push(k);
        }
        for (p, s) in &sessions {
            if !new_ids.iter().any(|n| same(n, p)) {
                assert!(s.wait().expect("reshare").is_none());
            }
        }
        out
    }

    #[test]
    fn keygen_then_sign_every_mode() {
        let ids = party_ids(&[1, 2, 3]);
        let keys = run_keygen(&ids, 1);
        let committee = [ids[0].clone(), ids[2].clone()];
        let ckeys = [keys[0].clone(), keys[2].clone()];
        let (tweak, child, _) = keys[0].derive_child(&[0, 7]).unwrap();
        let modes = [
            SignOptions::default(),
            SignOptions {
                tweak: Some(tweak.clone()),
                taproot: None,
            },
            SignOptions {
                tweak: None,
                taproot: Some(TaprootTweak::KeyPathOnly),
            },
            SignOptions {
                tweak: None,
                taproot: Some(TaprootTweak::ScriptTree([9; 32])),
            },
            SignOptions {
                tweak: Some(tweak),
                taproot: Some(TaprootTweak::KeyPathOnly),
            },
        ];
        // Several messages per mode so both parities of R come up.
        for (m, opts) in modes.iter().enumerate() {
            for i in 0..4u8 {
                let sig = sign(&ckeys, &committee, 1, &[m as u8, i], opts);
                assert_eq!(sig.public_key, keys[1].signing_public_key(opts).unwrap());
            }
        }
        assert_eq!(
            keys[0].signing_public_key(&modes[1]).unwrap(),
            x_only(&child).unwrap()
        );
    }

    /// `k` and `-k` share an x coordinate with opposite `Y` parity, so this
    /// signs under both an even and an odd group key.
    #[test]
    fn both_group_key_parities() {
        let dealer = PartyId::new("9", "P9", vec![9]);
        let ids = party_ids(&[1, 2, 3]);
        let mut seen = [false; 2];
        let k = id_scalar(&[5]);
        for secret in [k.clone(), k.negate()] {
            let imported = import_key(&secret, None, &dealer).unwrap();
            seen[has_even_y(&imported.group_public_key) as usize] = true;
            let keys = reshare(&[imported], core::slice::from_ref(&dealer), 0, &ids, 1);
            for opts in [
                SignOptions::default(),
                SignOptions {
                    tweak: None,
                    taproot: Some(TaprootTweak::KeyPathOnly),
                },
            ] {
                sign(&keys[1..], &ids[1..], 1, b"parity", &opts);
            }
        }
        assert_eq!(seen, [true, true]);
    }

    #[test]
    fn mismatched_options_fail_cleanly() {
        let ids = party_ids(&[1, 2]);
        let keys = run_keygen(&ids, 1);
        let hub = TestHub::new(&ids);
        let opts = [
            SignOptions::default(),
            SignOptions {
                tweak: None,
                taproot: Some(TaprootTweak::KeyPathOnly),
            },
        ];
        let sessions: Vec<Signing> = (0..2)
            .map(|i| {
                let params = Parameters::new(ids.clone(), &ids[i], 1, hub.broker(i));
                keys[i]
                    .new_signing_with(b"m".to_vec(), params, opts[i].clone())
                    .unwrap()
            })
            .collect();
        for s in &sessions {
            assert!(s.wait().is_err());
        }
    }

    /// BIP86 end to end: import the published m/86'/0'/0'/0/0 private key,
    /// reshare it 2-of-3, and sign a key-path spend for the published output
    /// key.
    #[test]
    fn bip86_vector_threshold_signs_for_published_output_key() {
        let secret = crate::frostsecp256k1tss::suite::decode_scalar(
            &hex::decode("41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361")
                .unwrap(),
        )
        .unwrap();
        let dealer = PartyId::new("100", "dealer", vec![100]);
        let imported = import_key(&secret, None, &dealer).unwrap();
        let ids = party_ids(&[1, 2, 3]);
        let keys = reshare(&[imported], core::slice::from_ref(&dealer), 0, &ids, 1);
        let opts = SignOptions {
            tweak: None,
            taproot: Some(TaprootTweak::KeyPathOnly),
        };
        let sig = sign(&keys[..2], &ids[..2], 1, &[0x42; 32], &opts);
        assert_eq!(
            hex::encode(&sig.public_key),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
    }

    #[test]
    fn reshare_to_bigger_committee_keeps_key_and_chain_code() {
        let old_ids = party_ids(&[1, 2, 3]);
        let old_keys = run_keygen(&old_ids, 1);
        // Overlapping committees: 2 and 3 stay, 4 and 5 join, threshold 2.
        let new_ids = party_ids(&[2, 3, 4, 5]);
        let new_keys = reshare(&old_keys, &old_ids, 1, &new_ids, 2);
        for k in &new_keys {
            assert!(point_eq(&k.group_public_key, &old_keys[0].group_public_key));
            assert_eq!(k.chain_code, old_keys[0].chain_code);
        }
        let opts = SignOptions {
            tweak: None,
            taproot: Some(TaprootTweak::KeyPathOnly),
        };
        sign(&new_keys[1..], &new_ids[1..], 2, b"after reshare", &opts);
    }
}
