//! Threshold key images for FROST(Ed25519): a distributed PRF on the shared
//! secret `x`, in the style of a Monero key image.
//!
//! This is a **building block**, not a derivation scheme of its own. It gives
//! the committee a way to compute `secret = F_x(identifier)` — a value that
//! nobody can produce without `t+1` shares — which is the missing ingredient
//! for hardened derivation (BIP32's `HMAC(chain_code, priv)` is unavailable to
//! a threshold key, since no party holds `priv`). What the caller does with the
//! secret is up to them: use it as an additive tweak for a child signing key,
//! as a seed for a symmetric KDF, as a blinding factor.
//!
//! The ceremony is one round:
//!
//! 1. Hash the identifier to a curve point:
//!    `P = HashToPoint(identifier, group_public_key)` — public, deterministic.
//! 2. Each signer contributes its **partial key image** `W_i = w_i·P`, where
//!    `w_i = λ_i·s_i` is the same Lagrange-weighted share it uses when signing.
//! 3. Summing the partials gives the **key image** `V = Σ W_i = x·P`, without
//!    `x` ever existing in one place.
//! 4. The secret is `secret = HashToScalar(domain, identifier, V)`.
//!
//! Because `V = x·P` is a DDH-style PRF of the shared key, a party that never
//! held a share cannot compute it for a fresh identifier. The result also
//! carries `group_public_key + secret·G`: feed `secret` into
//! [`Key::new_signing_with_tweak`](super::key::Key::new_signing_with_tweak) and
//! the committee signs under that child key, which nobody can even *name*
//! without having run the ceremony.
//!
//! # Wire and confidentiality
//!
//! Partial key images are sent **point to point**, not broadcast: `t+1` of them
//! reconstruct `V`, so anyone who can read them learns the secret. This relies
//! on the per-recipient confidentiality the
//! [`MessageBroker`](crate::tss::MessageBroker) contract requires (the same
//! reliance as the `frosttss` resharing shares). Every participant in the
//! ceremony learns the secret; it is a committee-wide value, not a per-party
//! one.
//!
//! Each partial carries a Chaum–Pedersen DLEQ proof that
//! `log_G(λ_i·Y_i) = log_P(W_i)`, where `Y_i` is the signer's public
//! verification share. Without it a single malicious or buggy party could
//! silently steer the whole committee to a wrong (unusable) secret; with it the
//! offender is named and the ceremony aborts.
//!
//! # Choosing the hash
//!
//! Both hashes are the caller's [`HashAlgorithm`], not a constant of the
//! protocol: pick SHA-512, SHA3-512, Keccak-256, BLAKE3 or whatever the
//! surrounding stack already speaks. Legacy and under-32-byte digests are
//! rejected. The algorithm's canonical name is mixed into every domain string,
//! so one key and identifier under two digests give two unrelated secrets —
//! **pick one per deployment and never change it**, since a different digest
//! makes every previously derived child key unreachable. The choice is bound
//! into the DLEQ transcript too, so a committee that disagrees aborts on a
//! failed proof instead of producing an unusable key.
//!
//! This construction is **not** a standard: it interoperates with no wallet and
//! no other implementation. It is deterministic — the same key, identifier and
//! hash always yield the same secret, from any qualifying committee.

use super::Error;
use super::key::Key;
use super::point::point_to_affine_be;
use crate::frost::binding::lagrange_coefficient;
use crate::frost::hashing::sha512_256i_tagged;
use crate::frost::{Ciphersuite, Ed25519, Scalar, encode_scalar, random_scalar};
use crate::tss::expect::JsonExpect;
use crate::tss::keyimage_hash::{digest32, digest64, validate as validate_hash};
use crate::tss::{HashAlgorithm, JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::ec::edwards25519::hazmat::EdwardsPoint;
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const ROUND1_TYPE: &str = "frost:ed25519:keyimage:round1";

/// Domain separator for the identifier → curve point map.
const POINT_DOMAIN: &[u8] = b"FROST-Ed25519-keyimage-point-v1";
/// Domain separator for the key image → secret scalar map.
const SECRET_DOMAIN: &[u8] = b"FROST-Ed25519-keyimage-secret-v1";
/// Fiat-Shamir tag for the per-partial DLEQ proof.
const DLEQ_DOMAIN: &[u8] = b"FROST-Ed25519-keyimage-dleq-v1";

/// The output of a [`KeyImageParty`] ceremony: the PRF secret for one
/// identifier, plus the key image it came from and the child key it defines.
pub struct KeyImageSecret {
    /// The derived secret `HashToScalar(identifier, x·P)`. Sensitive: every
    /// participant holds the same value.
    pub secret: Scalar,
    /// `group_public_key + secret·G` — the child key the committee signs under
    /// when `secret` is passed to
    /// [`Key::new_signing_with_tweak`](super::key::Key::new_signing_with_tweak).
    pub public_key: EdwardsPoint,
    /// The key image `V = x·P`. Exposed for callers that want to bind the
    /// ceremony to an audit log; treat it as secret — it determines `secret`.
    pub key_image: EdwardsPoint,
}

impl KeyImageSecret {
    /// The secret as 32 canonical little-endian bytes (RFC 9591
    /// `EncodeScalar`), e.g. to seed a symmetric KDF.
    pub fn secret_bytes(&self) -> [u8; 32] {
        encode_scalar(&self.secret)
    }

    /// The child public key in the standard 32-byte Ed25519 encoding.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        Ed25519::encode_point(&self.public_key)
    }
}

/// Round-1 point-to-point message: this party's partial key image `W_i` and the
/// DLEQ proof tying it to its verification share. Byte fields are base64.
#[derive(Serialize, Deserialize)]
struct KeyImageRound1Msg {
    /// `W_i = w_i·P`, 32-byte canonical Ed25519 point.
    #[serde(rename = "w", with = "crate::tss::b64::vec")]
    w: Vec<u8>,
    /// DLEQ commitment `A₁ = r·G`.
    #[serde(rename = "a1", with = "crate::tss::b64::vec")]
    a1: Vec<u8>,
    /// DLEQ commitment `A₂ = r·P`.
    #[serde(rename = "a2", with = "crate::tss::b64::vec")]
    a2: Vec<u8>,
    /// DLEQ response `z = r + c·w_i`, 32-byte little-endian scalar.
    #[serde(rename = "z", with = "crate::tss::b64::vec")]
    z: Vec<u8>,
}

/// A running threshold key-image ceremony: a one-round distributed PRF that
/// turns an identifier into a secret only `t+1` share holders can compute —
/// the building block for hardened derivation, which BIP32's
/// `HMAC(chain_code, priv)` cannot provide to a threshold key.
///
/// Construct with [`Key::new_key_image`]; collect the result with
/// [`KeyImageParty::wait`] or [`KeyImageParty::try_result`]. Every committee
/// member runs one against the same identifier.
///
/// Each party contributes a partial key image `W_i = λ_i·s_i·P` over
/// `P = HashToPoint(identifier)`; the partials sum to `V = x·P` and the secret
/// is `HashToScalar(identifier, V)`. Partials are point-to-point, never
/// broadcast — `t+1` of them reveal the secret, so the ceremony relies on the
/// per-recipient confidentiality the
/// [`MessageBroker`](crate::tss::MessageBroker) contract requires. Every
/// participant learns the same secret. Each partial carries a DLEQ proof, so a
/// party that contributes a wrong one is named and the ceremony aborts.
///
/// The construction is deterministic but **non-standard**: it interoperates
/// with no wallet and no other implementation.
pub struct KeyImageParty {
    result_rx: Receiver<Result<KeyImageSecret, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key,
    identifier: Vec<u8>,
    hash: HashAlgorithm,
    point: EdwardsPoint,
    my_partial: EdwardsPoint,
    result_tx: Mutex<Option<Sender<Result<KeyImageSecret, Error>>>>,
}

impl Key {
    /// Starts a threshold key-image ceremony for `identifier` over the committee
    /// in `params` (at least `threshold + 1` parties, all of which must run it).
    ///
    /// The identifier is arbitrary caller-chosen bytes — a label, a BIP32-style
    /// path encoding, a customer id. Distinct identifiers give unlinkable
    /// secrets; the same identifier always gives the same one, whichever
    /// qualifying committee runs the ceremony. See [`KeyImageParty`] for what
    /// the secret is and how it is protected.
    pub fn new_key_image(
        &self,
        identifier: Vec<u8>,
        params: Parameters,
        hash: HashAlgorithm,
    ) -> Result<KeyImageParty, Error> {
        if params.party_count() < params.threshold() + 1 {
            return Err(Error::Validation(format!(
                "key-image committee size {} < threshold+1 ({})",
                params.party_count(),
                params.threshold() + 1
            )));
        }
        let subset = self.subset_for_parties(params.parties())?;

        let point = hash_to_point(&identifier, &subset.group_public_key, hash)?;
        let me_id = params.party_id().key.clone();
        let signer_ids: Vec<Vec<u8>> = params.parties().iter().map(|p| p.key.clone()).collect();
        let lambda = lagrange_coefficient::<Ed25519>(&me_id, &signer_ids)
            .ok_or_else(|| Error::Validation("duplicate party identifier".into()))?;

        // w_i = λ_i·s_i, the same weighted share used when signing.
        let w = lambda.mul(&subset.xi);
        let partial = Ed25519::scalar_mul(&point, &w);
        let statement = Ed25519::mul_base(&w);

        let session = dleq_session(
            &identifier,
            &subset.group_public_key,
            &signer_ids,
            &me_id,
            hash,
        );
        let proof = Dleq::prove(&session, &point, &w, &statement, &partial, &mut OsRng);

        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key: subset,
            identifier,
            hash,
            point,
            my_partial: partial,
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1(&proof)?;
        Ok(KeyImageParty {
            result_rx: rx,
            _shared: shared,
        })
    }
}

impl KeyImageParty {
    /// Non-blocking peek at the ceremony result: `Some(_)` once the result (or
    /// error) is ready, `None` while the round is still pending. Unlike
    /// [`wait`](Self::wait) it never blocks, so a single-threaded async driver
    /// (e.g. wasm/browser) can poll it after feeding each inbound message.
    pub fn try_result(&self) -> Option<Result<KeyImageSecret, Error>> {
        self.result_rx.try_recv().ok()
    }

    /// Blocks until the ceremony completes.
    pub fn wait(&self) -> Result<KeyImageSecret, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "key-image ceremony dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<KeyImageSecret, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    /// Round 1: send `(W_i, DLEQ)` to each peer, then wait for theirs.
    fn round1(self: &Arc<Self>, proof: &Dleq) -> Result<(), Error> {
        let msg = KeyImageRound1Msg {
            w: Ed25519::encode_point(&self.my_partial).to_vec(),
            a1: Ed25519::encode_point(&proof.a1).to_vec(),
            a2: Ed25519::encode_point(&proof.a2).to_vec(),
            z: encode_scalar(&proof.z).to_vec(),
        };
        let others = self.params.other_parties();
        for pid in &others {
            self.send_to(ROUND1_TYPE, &msg, pid)?;
        }

        let me = Arc::clone(self);
        let others_owned = others.clone();
        let expect = JsonExpect::new(
            ROUND1_TYPE,
            others,
            Box::new(move |msgs| me.finalize(&others_owned, msgs)),
        );
        self.params.broker().connect(ROUND1_TYPE, Arc::new(expect));
        Ok(())
    }

    /// Verifies every peer's partial, sums them into `V = x·P`, and derives the
    /// secret.
    fn finalize(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let signer_ids: Vec<Vec<u8>> = self
            .params
            .parties()
            .iter()
            .map(|p| p.key.clone())
            .collect();

        // Verification share Y_j by identifier.
        let big_x_by_id: std::collections::HashMap<&[u8], EdwardsPoint> = self
            .key
            .ks
            .iter()
            .zip(self.key.big_xj.iter())
            .map(|(k, p)| (strip(k.as_be_bytes()), *p))
            .collect();

        let mut v = self.my_partial;
        for (pid, jm) in others.iter().zip(msgs.iter()) {
            let r1: KeyImageRound1Msg = match json_get(jm) {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(e.into())),
            };
            let (Some(wj), Some(a1), Some(a2), Some(z)) = (
                decode_point(&r1.w),
                decode_point(&r1.a1),
                decode_point(&r1.a2),
                decode_scalar(&r1.z),
            ) else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent a malformed partial key image"
                ))));
            };
            let Some(&yj) = big_x_by_id.get(strip(&pid.key)) else {
                return self.deliver(Err(Error::Validation(format!(
                    "missing verification share for {pid}"
                ))));
            };
            let Some(lambda_j) = lagrange_coefficient::<Ed25519>(&pid.key, &signer_ids) else {
                return self.deliver(Err(Error::Validation("duplicate party identifier".into())));
            };
            let statement = Ed25519::scalar_mul(&yj, &lambda_j);
            let session = dleq_session(
                &self.identifier,
                &self.key.group_public_key,
                &signer_ids,
                &pid.key,
                self.hash,
            );
            let proof = Dleq { a1, a2, z };
            if !proof.verify(&session, &self.point, &statement, &wj) {
                return self.deliver(Err(Error::Validation(format!(
                    "partial key image from {pid} failed its DLEQ proof"
                ))));
            }
            v = Ed25519::add(&v, &wj);
        }

        if Ed25519::is_identity(&v) {
            return self.deliver(Err(Error::Validation(
                "key image is the identity point".into(),
            )));
        }
        let secret =
            secret_from_key_image(&self.identifier, &self.key.group_public_key, &v, self.hash);
        if bool::from(secret.ct_eq(&Scalar::ZERO)) {
            return self.deliver(Err(Error::Validation(
                "derived secret is zero; use a different identifier".into(),
            )));
        }
        let public_key = Ed25519::add(&self.key.group_public_key, &Ed25519::mul_base(&secret));
        if Ed25519::is_identity(&public_key) {
            return self.deliver(Err(Error::Validation(
                "derived child key is the identity point".into(),
            )));
        }
        self.deliver(Ok(KeyImageSecret {
            secret,
            public_key,
            key_image: v,
        }));
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

/// A Chaum–Pedersen proof that one witness `w` satisfies both `Y = w·G` and
/// `W = w·P`, i.e. that a partial key image was computed with the same share
/// the party signs with.
struct Dleq {
    a1: EdwardsPoint,
    a2: EdwardsPoint,
    z: Scalar,
}

impl Dleq {
    fn prove(
        session: &[u8],
        p: &EdwardsPoint,
        w: &Scalar,
        y: &EdwardsPoint,
        w_pt: &EdwardsPoint,
        rng: &mut impl RngCore,
    ) -> Dleq {
        let r = random_scalar(rng);
        let a1 = Ed25519::mul_base(&r);
        let a2 = Ed25519::scalar_mul(p, &r);
        let c = dleq_challenge(session, p, y, w_pt, &a1, &a2);
        let z = r.add(&c.mul(w));
        Dleq { a1, a2, z }
    }

    /// `z·G == A₁ + c·Y` and `z·P == A₂ + c·W`.
    fn verify(
        &self,
        session: &[u8],
        p: &EdwardsPoint,
        y: &EdwardsPoint,
        w_pt: &EdwardsPoint,
    ) -> bool {
        let c = dleq_challenge(session, p, y, w_pt, &self.a1, &self.a2);
        let lhs1 = Ed25519::mul_base(&self.z);
        let rhs1 = Ed25519::add(&self.a1, &Ed25519::scalar_mul(y, &c));
        let lhs2 = Ed25519::scalar_mul(p, &self.z);
        let rhs2 = Ed25519::add(&self.a2, &Ed25519::scalar_mul(w_pt, &c));
        Ed25519::eq(&lhs1, &rhs1) && Ed25519::eq(&lhs2, &rhs2)
    }
}

/// `c = SHA512_256i_TAGGED(session, P, Y, W, A₁, A₂) mod L`, each point as its
/// affine `(x, y)` big-endian pair (the tagged-hash shape used by
/// [`super::schnorr`]).
fn dleq_challenge(
    session: &[u8],
    p: &EdwardsPoint,
    y: &EdwardsPoint,
    w_pt: &EdwardsPoint,
    a1: &EdwardsPoint,
    a2: &EdwardsPoint,
) -> Scalar {
    let pts = [p, y, w_pt, a1, a2];
    let coords: Vec<Vec<u8>> = pts
        .iter()
        .flat_map(|pt| {
            let (x, y) = point_to_affine_be(pt);
            [x, y]
        })
        .collect();
    let operands: Vec<&[u8]> = coords.iter().map(|v| v.as_slice()).collect();
    let digest = sha512_256i_tagged(session, &operands);
    be32_to_scalar_mod_l(&digest)
}

/// Fiat-Shamir session bytes: the identifier, the group key, the committee, and
/// the prover's identifier — so a proof cannot be replayed into another
/// ceremony, committee, or party slot.
fn dleq_session(
    identifier: &[u8],
    group_public_key: &EdwardsPoint,
    signer_ids: &[Vec<u8>],
    prover: &[u8],
    hash: HashAlgorithm,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + identifier.len() + 8 * signer_ids.len());
    buf.extend_from_slice(DLEQ_DOMAIN);
    push_field(&mut buf, hash.name().as_bytes());
    buf.extend_from_slice(&Ed25519::encode_point(group_public_key));
    push_field(&mut buf, identifier);
    buf.extend_from_slice(&(signer_ids.len() as u64).to_be_bytes());
    for id in signer_ids {
        push_field(&mut buf, strip(id));
    }
    push_field(&mut buf, strip(prover));
    buf
}

/// Maps an identifier to a prime-order curve point, deterministically and
/// publicly: `hash(domain ‖ hash_name ‖ group_pub ‖ identifier ‖ counter)`
/// truncated to 32 bytes is tried as an Ed25519 point encoding, incrementing
/// `counter` until it decodes (~50% per try), then cofactor-cleared. The
/// algorithm name is part of the preimage, so each choice of `hash` gives an
/// unrelated point.
///
/// Errors if `hash` is a legacy or under-32-byte digest. Try-and-increment is
/// not constant time, but every input here is public, so the timing carries no
/// secret.
pub fn hash_to_point(
    identifier: &[u8],
    group_public_key: &EdwardsPoint,
    hash: HashAlgorithm,
) -> Result<EdwardsPoint, Error> {
    validate_hash(hash).map_err(Error::Validation)?;
    let mut base = Vec::with_capacity(64 + identifier.len());
    base.extend_from_slice(POINT_DOMAIN);
    push_field(&mut base, hash.name().as_bytes());
    base.extend_from_slice(&Ed25519::encode_point(group_public_key));
    push_field(&mut base, identifier);
    let prefix_len = base.len();
    base.extend_from_slice(&[0u8; 4]);

    for counter in 0u32..=u32::MAX {
        base[prefix_len..].copy_from_slice(&counter.to_be_bytes());
        let candidate = digest32(hash, &base);
        // decode_point cofactor-clears, so the result is in the prime-order
        // subgroup; identity (a small-order candidate) is rejected.
        if let Some(p) = Ed25519::decode_point(&candidate)
            && !Ed25519::is_identity(&p)
        {
            return Ok(p);
        }
    }
    unreachable!("no valid curve point in 2^32 hash-to-point attempts")
}

/// `secret = hash(domain ‖ hash_name ‖ group_pub ‖ identifier ‖ V) mod L`.
fn secret_from_key_image(
    identifier: &[u8],
    group_public_key: &EdwardsPoint,
    key_image: &EdwardsPoint,
    hash: HashAlgorithm,
) -> Scalar {
    let mut buf = Vec::with_capacity(96 + identifier.len());
    buf.extend_from_slice(SECRET_DOMAIN);
    push_field(&mut buf, hash.name().as_bytes());
    buf.extend_from_slice(&Ed25519::encode_point(group_public_key));
    push_field(&mut buf, identifier);
    buf.extend_from_slice(&Ed25519::encode_point(key_image));
    // A 64-byte digest keeps the reduction into the 255-bit scalar field
    // unbiased; narrower algorithms are counter-extended by `digest64`.
    Scalar::from_bytes_mod_order(&digest64(hash, &buf))
}

/// Appends a length-prefixed field, so concatenations stay unambiguous.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

fn be32_to_scalar_mod_l(be: &[u8; 32]) -> Scalar {
    let mut le = [0u8; 64];
    for (i, &b) in be.iter().rev().enumerate() {
        le[i] = b;
    }
    Scalar::from_bytes_mod_order(&le)
}

fn decode_point(b: &[u8]) -> Option<EdwardsPoint> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Ed25519::decode_point(&arr)
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
    use purecrypto::ec::{Ed25519PublicKey, Ed25519Signature};

    /// The digest the ceremony tests run under; the vectors cover the rest.
    const H: HashAlgorithm = HashAlgorithm::Sha512;

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

    /// Trusted-dealer `t`-of-`n` keys (test-only), plus the master secret `x`
    /// so tests can check the PRF against its centralized definition.
    fn trusted_dealer(n: usize, t: usize) -> (Vec<PartyId>, Vec<Key>, Scalar) {
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
        (ids, keys, coeffs[0].clone())
    }

    /// Runs the ceremony over `members` (indices into `ids`/`keys`) and returns
    /// each participant's result.
    fn run(
        ids: &[PartyId],
        keys: &[Key],
        members: &[usize],
        t: usize,
        identifier: &[u8],
    ) -> Vec<KeyImageSecret> {
        // Re-index the sub-committee from 0: TestHub routes by `PartyId::index`.
        let committee = PartyId::sort(members.iter().map(|&i| ids[i].clone()).collect(), 0);
        let hub = TestHub::new(&committee);
        let sessions: Vec<KeyImageParty> = members
            .iter()
            .enumerate()
            .map(|(pos, &i)| {
                let params =
                    Parameters::new(committee.clone(), &committee[pos], t, hub.broker(pos));
                keys[i]
                    .new_key_image(identifier.to_vec(), params, H)
                    .unwrap()
            })
            .collect();
        sessions
            .iter()
            .map(|s| s.wait().expect("key-image ceremony succeeds"))
            .collect()
    }

    #[test]
    fn key_image_equals_x_times_p_and_secret_matches_prf() {
        let (ids, keys, x) = trusted_dealer(3, 1);
        let out = run(&ids, &keys, &[0, 1], 1, b"customer/42");

        let p = hash_to_point(b"customer/42", &keys[0].group_public_key, H).unwrap();
        let want_v = Ed25519::scalar_mul(&p, &x);
        let want_secret =
            secret_from_key_image(b"customer/42", &keys[0].group_public_key, &want_v, H);
        for o in &out {
            assert!(Ed25519::eq(&o.key_image, &want_v), "V == x·P");
            assert!(bool::from(o.secret.ct_eq(&want_secret)));
            let want_pub =
                Ed25519::add(&keys[0].group_public_key, &Ed25519::mul_base(&want_secret));
            assert!(Ed25519::eq(&o.public_key, &want_pub));
        }
    }

    #[test]
    fn different_committees_derive_the_same_secret() {
        let (ids, keys, _) = trusted_dealer(3, 1);
        let a = run(&ids, &keys, &[0, 1], 1, b"same-id");
        let b = run(&ids, &keys, &[1, 2], 1, b"same-id");
        assert_eq!(a[0].secret_bytes(), b[0].secret_bytes());
        assert_eq!(a[0].public_key_bytes(), b[1].public_key_bytes());
    }

    #[test]
    fn larger_committee_than_threshold_agrees() {
        let (ids, keys, x) = trusted_dealer(5, 2);
        let out = run(&ids, &keys, &[0, 1, 2, 3], 2, b"wide");
        let p = hash_to_point(b"wide", &keys[0].group_public_key, H).unwrap();
        assert!(Ed25519::eq(&out[0].key_image, &Ed25519::scalar_mul(&p, &x)));
        for o in &out[1..] {
            assert_eq!(o.secret_bytes(), out[0].secret_bytes());
        }
    }

    #[test]
    fn different_identifiers_give_different_secrets() {
        let (ids, keys, _) = trusted_dealer(3, 1);
        let a = run(&ids, &keys, &[0, 1], 1, b"id-a");
        let b = run(&ids, &keys, &[0, 1], 1, b"id-b");
        assert_ne!(a[0].secret_bytes(), b[0].secret_bytes());
        assert_ne!(a[0].public_key_bytes(), b[0].public_key_bytes());
    }

    #[test]
    fn derived_secret_signs_as_child_key() {
        let (ids, keys, _) = trusted_dealer(3, 1);
        let derived = run(&ids, &keys, &[0, 1], 1, b"hardened/0");

        let committee: Vec<PartyId> = ids[..2].to_vec();
        let hub = TestHub::new(&committee);
        let msg = b"signed under a key-image-derived child key".to_vec();
        let signings: Vec<_> = (0..2)
            .map(|i| {
                let params = Parameters::new(committee.clone(), &committee[i], 1, hub.broker(i));
                keys[i]
                    .new_signing_with_tweak(msg.clone(), params, Some(derived[i].secret.clone()))
                    .unwrap()
            })
            .collect();

        let pk = Ed25519PublicKey::from_bytes(derived[0].public_key_bytes());
        for s in &signings {
            let sig = s.wait().expect("signing succeeds");
            let mut sb = [0u8; 64];
            sb.copy_from_slice(&sig.signature);
            pk.verify(&msg, &Ed25519Signature::from_bytes(sb))
                .expect("verifies under the derived child key");
        }
    }

    #[test]
    fn hash_to_point_is_deterministic_and_identifier_bound() {
        let group_pub = Ed25519::mul_base(&rand_scalar());
        let a = hash_to_point(b"x", &group_pub, H).unwrap();
        assert!(Ed25519::eq(
            &a,
            &hash_to_point(b"x", &group_pub, H).unwrap()
        ));
        assert!(!Ed25519::eq(
            &a,
            &hash_to_point(b"y", &group_pub, H).unwrap()
        ));
        assert!(!Ed25519::eq(
            &a,
            &hash_to_point(b"x", &Ed25519::mul_base(&rand_scalar()), H).unwrap()
        ));
        // A different digest is a different point, never a coincidence.
        assert!(!Ed25519::eq(
            &a,
            &hash_to_point(b"x", &group_pub, HashAlgorithm::Keccak256).unwrap()
        ));
        assert!(!Ed25519::is_identity(&a));
        // Already in the prime-order subgroup: a cofactor-clearing decode round
        // trip leaves it unchanged.
        let round = Ed25519::decode_point(&Ed25519::encode_point(&a)).unwrap();
        assert!(Ed25519::eq(&a, &round));
    }

    #[test]
    fn dleq_rejects_a_wrong_partial() {
        let w = rand_scalar();
        let p = hash_to_point(b"dleq", &Ed25519::mul_base(&rand_scalar()), H).unwrap();
        let y = Ed25519::mul_base(&w);
        let w_pt = Ed25519::scalar_mul(&p, &w);
        let proof = Dleq::prove(b"s", &p, &w, &y, &w_pt, &mut OsRng);
        assert!(proof.verify(b"s", &p, &y, &w_pt));
        // Same witness, wrong claimed partial.
        let bogus = Ed25519::scalar_mul(&p, &rand_scalar());
        assert!(!proof.verify(b"s", &p, &y, &bogus));
        // Right partial, wrong session (replay into another ceremony).
        assert!(!proof.verify(b"other", &p, &y, &w_pt));
    }

    /// Every accepted digest yields its own, self-consistent derivation.
    #[test]
    fn each_hash_gives_an_unrelated_secret() {
        let (ids, keys, _) = trusted_dealer(3, 1);
        let committee = PartyId::sort(ids[..2].to_vec(), 0);
        let mut seen = std::collections::HashSet::new();
        for alg in [
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Keccak256,
            HashAlgorithm::Blake3,
        ] {
            let hub = TestHub::new(&committee);
            let sessions: Vec<KeyImageParty> = (0..2)
                .map(|i| {
                    let params =
                        Parameters::new(committee.clone(), &committee[i], 1, hub.broker(i));
                    keys[i]
                        .new_key_image(b"same".to_vec(), params, alg)
                        .unwrap()
                })
                .collect();
            let out: Vec<_> = sessions.iter().map(|s| s.wait().unwrap()).collect();
            assert_eq!(out[0].secret_bytes(), out[1].secret_bytes());
            assert!(
                seen.insert(out[0].secret_bytes()),
                "{} collided",
                alg.name()
            );
        }
    }

    /// Legacy and short digests cannot key a derivation.
    #[test]
    fn unusable_hashes_are_rejected() {
        let (ids, keys, _) = trusted_dealer(3, 1);
        let committee = PartyId::sort(ids[..2].to_vec(), 0);
        for alg in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Md5,
            HashAlgorithm::Sha224,
        ] {
            let hub = TestHub::new(&committee);
            let params = Parameters::new(committee.clone(), &committee[0], 1, hub.broker(0));
            assert!(
                keys[0].new_key_image(b"id".to_vec(), params, alg).is_err(),
                "{} accepted",
                alg.name()
            );
            assert!(hash_to_point(b"id", &keys[0].group_public_key, alg).is_err());
        }
    }

    #[test]
    fn committee_smaller_than_threshold_is_rejected() {
        let (ids, keys, _) = trusted_dealer(3, 2);
        let committee: Vec<PartyId> = ids[..2].to_vec();
        let hub = TestHub::new(&committee);
        let params = Parameters::new(committee.clone(), &committee[0], 2, hub.broker(0));
        assert!(keys[0].new_key_image(b"id".to_vec(), params, H).is_err());
    }
}

/// Checked-in test vectors that freeze this construction for every digest it
/// accepts: the identifier → point map, the Lagrange-weighted partials, the key
/// image, the derived secret, and the round-1 wire encoding.
///
/// Nothing here interoperates with another implementation yet, so these vectors
/// are the only thing standing between a refactor and a silently different —
/// and therefore unrecoverable — child key.
///
/// Regenerate with
/// `cargo test --lib frosttss::keyimage::vectors::print -- --ignored --nocapture`,
/// writing the output to `testdata/keyimage_vectors.json`. A changed vector file
/// means every previously derived child key is gone: only ever regenerate for a
/// deliberate, versioned construction change.
#[cfg(test)]
mod vectors {
    use super::*;
    use crate::tss::bigint::BigUintDec;
    use crate::tss::keyimage_hash::validate as validate_hash;
    use crate::tss::testhub::TestHub;
    use purecrypto::hash::sha512;
    use serde::{Deserialize, Serialize};

    /// One (hash, identifier) pair and every value the construction derives
    /// from it. Byte strings are lower-case hex; scalars are 32-byte canonical
    /// little-endian (RFC 9591 `EncodeScalar`), points 32-byte Ed25519.
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Case {
        /// Canonical `HashAlgorithm` name, e.g. `"sha512"`, `"keccak256"`.
        hash: String,
        identifier: String,
        /// `P = HashToPoint(identifier, group_public_key, hash)`.
        point: String,
        /// `W_i = λ_i·s_i·P`, aligned with the top-level `committee`.
        partials: Vec<String>,
        /// `V = Σ W_i = x·P`.
        key_image: String,
        /// `HashToScalar(domain, hash, identifier, V)`.
        secret: String,
        /// `group_public_key + secret·G`.
        child_public_key: String,
        dleq: DleqCase,
    }

    /// A DLEQ proof pinned to a fixed nonce, freezing the Fiat-Shamir
    /// transcript and the round-1 JSON encoding along with it.
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct DleqCase {
        /// `SHA-512(session)[..32]`, pinning the session-binding encoding.
        session_digest: String,
        /// The fixed nonce `r` this vector proves with.
        nonce: String,
        /// `A₁ = r·G`.
        a1: String,
        /// `A₂ = r·P`.
        a2: String,
        /// The Fiat-Shamir challenge `c`.
        challenge: String,
        /// `z = r + c·w_i`.
        z: String,
        /// The exact round-1 message JSON for this proof.
        wire_json: String,
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Vectors {
        scheme: String,
        point_domain: String,
        secret_domain: String,
        dleq_domain: String,
        threshold: usize,
        /// Hex party keys of the full key set.
        party_keys: Vec<String>,
        /// Per-party secret shares `s_i`.
        shares: Vec<String>,
        /// The master secret `x`, for cross-checking `V = x·P`.
        master_secret: String,
        group_public_key: String,
        /// The committee the cases were produced by (hex party keys), and the
        /// prover of each case's DLEQ proof is its first member.
        committee: Vec<String>,
        cases: Vec<Case>,
    }

    fn hex_scalar(s: &Scalar) -> String {
        hex::encode(encode_scalar(s))
    }

    fn hex_point(p: &EdwardsPoint) -> String {
        hex::encode(Ed25519::encode_point(p))
    }

    fn scalar_from_hex(s: &str) -> Scalar {
        let b: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        crate::frost::decode_scalar(&b).expect("canonical scalar")
    }

    fn point_from_hex(s: &str) -> EdwardsPoint {
        let b: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        Ed25519::decode_point(&b).expect("valid point")
    }

    /// The fixed 1-of-3 key set the vectors are built on: deterministic Shamir
    /// coefficients, so the whole file is reproducible from these labels alone.
    fn vector_keys() -> (Vec<PartyId>, Vec<Key>, Scalar) {
        let coeffs: Vec<Scalar> = ["tsslib/keyimage/vector/a0", "tsslib/keyimage/vector/a1"]
            .iter()
            .map(|label| Scalar::from_bytes_mod_order(&sha512(label.as_bytes())))
            .collect();
        let ids = PartyId::sort(
            (1..=3u8)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i]))
                .collect(),
            0,
        );
        let ks: Vec<BigUintDec> = ids
            .iter()
            .map(|p| BigUintDec::from_be_bytes(&p.key))
            .collect();
        let xs: Vec<Scalar> = ids
            .iter()
            .map(|p| {
                let x = crate::frost::scalar_from_be_mod_l(&p.key);
                coeffs[1].mul(&x).add(&coeffs[0])
            })
            .collect();
        let big_xj: Vec<EdwardsPoint> = xs.iter().map(Ed25519::mul_base).collect();
        let group_pub = Ed25519::mul_base(&coeffs[0]);
        let keys = (0..3)
            .map(|i| Key {
                xi: xs[i].clone(),
                share_id: ks[i].clone(),
                ks: ks.clone(),
                big_xj: big_xj.clone(),
                group_public_key: group_pub,
                chain_code: None,
            })
            .collect();
        (ids, keys, coeffs[0].clone())
    }

    /// Identifiers covered: empty, ASCII, a path-shaped label, and raw bytes.
    fn vector_identifiers() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            b"abc".to_vec(),
            b"m/44'/501'/0'/0'".to_vec(),
            (0u8..=31).collect(),
        ]
    }

    /// Every digest the construction accepts, in `HashAlgorithm::ALL` order —
    /// so a purecrypto release that adds one makes this test fail until the
    /// vectors cover it.
    fn vector_hashes() -> Vec<HashAlgorithm> {
        HashAlgorithm::ALL
            .iter()
            .copied()
            .filter(|&a| validate_hash(a).is_ok())
            .collect()
    }

    /// Builds the vector document from the fixed key set — the same code path
    /// the assertion test re-runs, so `print` and the assertions cannot drift.
    fn build() -> Vectors {
        let (ids, keys, master) = vector_keys();
        let group_pub = keys[0].group_public_key;
        let committee: Vec<PartyId> = ids[..2].to_vec();
        let signer_ids: Vec<Vec<u8>> = committee.iter().map(|p| p.key.clone()).collect();

        let mut cases = Vec::new();
        for hash in vector_hashes() {
            for identifier in vector_identifiers() {
                let point = hash_to_point(&identifier, &group_pub, hash).unwrap();

                let mut partials = Vec::new();
                let mut v = Ed25519::identity();
                for (pos, pid) in committee.iter().enumerate() {
                    let lambda =
                        lagrange_coefficient::<Ed25519>(&pid.key, &signer_ids).expect("lambda");
                    let w = lambda.mul(&keys[pos].xi);
                    let partial = Ed25519::scalar_mul(&point, &w);
                    v = Ed25519::add(&v, &partial);
                    partials.push(hex_point(&partial));
                }

                let secret = secret_from_key_image(&identifier, &group_pub, &v, hash);
                let child = Ed25519::add(&group_pub, &Ed25519::mul_base(&secret));

                // DLEQ for the first committee member under a fixed nonce.
                let lambda =
                    lagrange_coefficient::<Ed25519>(&signer_ids[0], &signer_ids).expect("lambda");
                let w = lambda.mul(&keys[0].xi);
                let w_pt = Ed25519::scalar_mul(&point, &w);
                let statement = Ed25519::mul_base(&w);
                let session =
                    dleq_session(&identifier, &group_pub, &signer_ids, &signer_ids[0], hash);
                let r = Scalar::from_bytes_mod_order(&sha512(
                    &[
                        b"tsslib/keyimage/vector/nonce".as_slice(),
                        hash.name().as_bytes(),
                        &identifier,
                    ]
                    .concat(),
                ));
                let a1 = Ed25519::mul_base(&r);
                let a2 = Ed25519::scalar_mul(&point, &r);
                let c = dleq_challenge(&session, &point, &statement, &w_pt, &a1, &a2);
                let z = r.add(&c.mul(&w));
                let wire = KeyImageRound1Msg {
                    w: Ed25519::encode_point(&w_pt).to_vec(),
                    a1: Ed25519::encode_point(&a1).to_vec(),
                    a2: Ed25519::encode_point(&a2).to_vec(),
                    z: encode_scalar(&z).to_vec(),
                };

                cases.push(Case {
                    hash: hash.name().to_string(),
                    identifier: hex::encode(&identifier),
                    point: hex_point(&point),
                    partials,
                    key_image: hex_point(&v),
                    secret: hex_scalar(&secret),
                    child_public_key: hex_point(&child),
                    dleq: DleqCase {
                        session_digest: hex::encode(&sha512(&session)[..32]),
                        nonce: hex_scalar(&r),
                        a1: hex_point(&a1),
                        a2: hex_point(&a2),
                        challenge: hex_scalar(&c),
                        z: hex_scalar(&z),
                        wire_json: serde_json::to_string(&wire).unwrap(),
                    },
                });
            }
        }

        Vectors {
            scheme: "frosttss/keyimage/v1".into(),
            point_domain: String::from_utf8(POINT_DOMAIN.to_vec()).unwrap(),
            secret_domain: String::from_utf8(SECRET_DOMAIN.to_vec()).unwrap(),
            dleq_domain: String::from_utf8(DLEQ_DOMAIN.to_vec()).unwrap(),
            threshold: 1,
            party_keys: ids.iter().map(|p| hex::encode(&p.key)).collect(),
            shares: keys.iter().map(|k| hex_scalar(&k.xi)).collect(),
            master_secret: hex_scalar(&master),
            group_public_key: hex_point(&group_pub),
            committee: signer_ids.iter().map(hex::encode).collect(),
            cases,
        }
    }

    fn checked_in() -> Vectors {
        serde_json::from_str(include_str!("testdata/keyimage_vectors.json"))
            .expect("valid keyimage_vectors.json")
    }

    /// Prints a regenerated vector file. Ignored by default — read the module
    /// docs before ever using its output.
    #[test]
    #[ignore]
    fn print() {
        println!("{}", serde_json::to_string_pretty(&build()).unwrap());
    }

    /// The construction still produces exactly the checked-in values.
    #[test]
    fn recomputation_matches_checked_in_file() {
        let (got, want) = (build(), checked_in());
        assert_eq!(
            got.cases.len(),
            want.cases.len(),
            "case count changed (a new HashAlgorithm to cover?)"
        );
        for (g, w) in got.cases.iter().zip(want.cases.iter()) {
            assert_eq!(g, w, "derivation changed for hash {} ", w.hash);
        }
        assert_eq!(got, want, "key-image construction changed");
    }

    /// The checked-in file is internally consistent: partials sum to the key
    /// image, the key image is `x·P`, secret and child key follow, and the
    /// pinned DLEQ proof verifies.
    #[test]
    fn checked_in_file_is_self_consistent() {
        let f = checked_in();
        let group_pub = point_from_hex(&f.group_public_key);
        let master = scalar_from_hex(&f.master_secret);
        assert!(Ed25519::eq(&group_pub, &Ed25519::mul_base(&master)));

        let signer_ids: Vec<Vec<u8>> = f
            .committee
            .iter()
            .map(|h| hex::decode(h).unwrap())
            .collect();
        let share0 = scalar_from_hex(&f.shares[0]);
        let lambda0 = lagrange_coefficient::<Ed25519>(&signer_ids[0], &signer_ids).expect("lambda");

        for case in &f.cases {
            let hash = HashAlgorithm::from_name(&case.hash).expect("known hash name");
            let identifier = hex::decode(&case.identifier).unwrap();
            let point = point_from_hex(&case.point);
            assert!(Ed25519::eq(
                &point,
                &hash_to_point(&identifier, &group_pub, hash).unwrap()
            ));

            let mut v = Ed25519::identity();
            for p in &case.partials {
                v = Ed25519::add(&v, &point_from_hex(p));
            }
            assert!(Ed25519::eq(&v, &point_from_hex(&case.key_image)));
            // V == x·P, the property the whole construction rests on.
            assert!(Ed25519::eq(&v, &Ed25519::scalar_mul(&point, &master)));

            let secret = scalar_from_hex(&case.secret);
            assert!(bool::from(secret.ct_eq(&secret_from_key_image(
                &identifier,
                &group_pub,
                &v,
                hash
            ))));
            assert!(Ed25519::eq(
                &point_from_hex(&case.child_public_key),
                &Ed25519::add(&group_pub, &Ed25519::mul_base(&secret))
            ));

            // The pinned proof verifies against the pinned partial.
            let statement = Ed25519::mul_base(&lambda0.mul(&share0));
            let session = dleq_session(&identifier, &group_pub, &signer_ids, &signer_ids[0], hash);
            assert_eq!(
                hex::encode(&sha512(&session)[..32]),
                case.dleq.session_digest
            );
            let proof = Dleq {
                a1: point_from_hex(&case.dleq.a1),
                a2: point_from_hex(&case.dleq.a2),
                z: scalar_from_hex(&case.dleq.z),
            };
            assert!(proof.verify(
                &session,
                &point,
                &statement,
                &point_from_hex(&case.partials[0])
            ));

            // The wire encoding of that proof is byte-stable.
            let msg: KeyImageRound1Msg = serde_json::from_str(&case.dleq.wire_json).unwrap();
            assert_eq!(hex::encode(&msg.w), case.partials[0]);
            assert_eq!(hex::encode(&msg.a1), case.dleq.a1);
            assert_eq!(hex::encode(&msg.a2), case.dleq.a2);
            assert_eq!(hex::encode(&msg.z), case.dleq.z);
        }
    }

    /// The live broker ceremony reproduces the vectors — this pins the protocol
    /// path, not just the helper functions.
    #[test]
    fn ceremony_reproduces_vectors() {
        let f = checked_in();
        let (ids, keys, _) = vector_keys();
        let committee = PartyId::sort(ids[..2].to_vec(), 0);

        for case in &f.cases {
            let hash = HashAlgorithm::from_name(&case.hash).expect("known hash name");
            let identifier = hex::decode(&case.identifier).unwrap();
            let hub = TestHub::new(&committee);
            let parties: Vec<KeyImageParty> = (0..2)
                .map(|i| {
                    let params =
                        Parameters::new(committee.clone(), &committee[i], 1, hub.broker(i));
                    keys[i]
                        .new_key_image(identifier.clone(), params, hash)
                        .expect("ceremony starts")
                })
                .collect();
            for p in &parties {
                let out = p.wait().expect("ceremony succeeds");
                assert_eq!(hex_point(&out.key_image), case.key_image, "{}", case.hash);
                assert_eq!(hex::encode(out.secret_bytes()), case.secret);
                assert_eq!(hex::encode(out.public_key_bytes()), case.child_public_key);
            }
        }
    }
}
