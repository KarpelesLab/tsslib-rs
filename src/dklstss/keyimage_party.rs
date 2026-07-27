//! Threshold key images for DKLs23 (secp256k1): a distributed PRF on the shared
//! secret `x`, in the style of a Monero key image.
//!
//! This is a **building block**, not a derivation scheme of its own. It gives
//! the committee a way to compute `secret = F_x(identifier)` — a value nobody
//! can produce without `t+1` shares — which is the missing ingredient for
//! hardened derivation (BIP32's `HMAC(chain_code, priv)` is unavailable to a
//! threshold key, since no party holds `priv`). The `dklstss` counterpart of
//! [`crate::frosttss::KeyImageParty`], same construction, secp256k1 arithmetic.
//!
//! The ceremony is one round:
//!
//! 1. Hash the identifier to a curve point:
//!    `P = HashToPoint(identifier, ecdsa_pub)` — public, deterministic.
//! 2. Each party contributes its **partial key image** `W_i = w_i·P`, where
//!    `w_i = λ_i·x_i` is the same Lagrange-weighted share it signs with.
//! 3. Summing the partials gives the **key image** `V = Σ W_i = x·P`, without
//!    `x` ever existing in one place.
//! 4. The secret is `secret = HashToScalar(domain, identifier, V)`.
//!
//! The result also carries `ecdsa_pub + secret·G`: pass `secret` as the tweak to
//! [`SigningParty::new`](super::SigningParty::new) (or
//! [`sign_with_tweak`](super::sign_with_tweak)) and the committee signs under
//! that child key, which nobody can even *name* without having run the
//! ceremony. Unlike BIP32 non-hardened derivation ([`super::derive_child`]),
//! knowledge of the parent public key and chain code buys an outsider nothing.
//!
//! # Wire and confidentiality
//!
//! Partial key images are sent **point to point**, not broadcast: `t+1` of them
//! reconstruct `V`, so anyone who can read them learns the secret. This relies
//! on the per-recipient confidentiality the
//! [`MessageBroker`](crate::tss::MessageBroker) contract requires (the same
//! reliance as the `dklstss` resharing shares). Every participant learns the
//! secret; it is a committee-wide value, not a per-party one.
//!
//! Each partial carries a Chaum–Pedersen DLEQ proof that
//! `log_G(λ_i·X_i) = log_P(W_i)`, where `X_i` is the party's public share
//! commitment (`BigXj[i]`). Without it a single malicious or buggy party could
//! silently steer the committee to a wrong (unusable) secret; with it the
//! offender is named and the ceremony aborts.
//!
//! # Choosing the hash
//!
//! Both hashes are the caller's [`HashAlgorithm`], not a constant of the
//! protocol: pick SHA-256, Keccak-256 (the Ethereum-native choice), SHA3,
//! BLAKE3 or whatever the surrounding stack already speaks. Legacy and
//! under-32-byte digests are rejected. The algorithm's canonical name is mixed
//! into every domain string, so one key and identifier under two digests give
//! two unrelated secrets — **pick one per deployment and never change it**,
//! since a different digest makes every previously derived child key
//! unreachable. The choice is bound into the DLEQ transcript too, so a
//! committee that disagrees aborts on a failed proof instead of producing an
//! unusable key.
//!
//! This construction is **not** a standard: it interoperates with no wallet and
//! no other implementation. It is deterministic — the same key, identifier and
//! hash always yield the same secret, from any qualifying committee.

use super::Error;
use super::echo::{other_parties, strip};
use super::key::Key;
use super::secp::{self, ProjectivePoint, Scalar};
use super::signing::lagrange_coefficient;
use crate::frost::hashing::sha512_256i_tagged;
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::keyimage_hash::{digest32, validate as validate_hash};
use crate::tss::{HashAlgorithm, JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "dkls:keyimage:r1";

/// Domain separator for the identifier → curve point map.
const POINT_DOMAIN: &[u8] = b"DKLS23-keyimage-point-v1";
/// Domain separator for the key image → secret scalar map.
const SECRET_DOMAIN: &[u8] = b"DKLS23-keyimage-secret-v1";
/// Fiat-Shamir tag for the per-partial DLEQ proof.
const DLEQ_DOMAIN: &[u8] = b"DKLS23-keyimage-dleq-v1";

/// The output of a [`KeyImageParty`] ceremony: the PRF secret for one
/// identifier, plus the key image it came from and the child key it defines.
pub struct KeyImageSecret {
    /// The derived secret `HashToScalar(identifier, x·P)`. Sensitive: every
    /// participant holds the same value.
    pub secret: Scalar,
    /// `ecdsa_pub + secret·G` — the child key the committee signs under when
    /// `secret` is used as the signing tweak.
    pub public_key: ProjectivePoint,
    /// The key image `V = x·P`. Exposed for callers that want to bind the
    /// ceremony to an audit log; treat it as secret — it determines `secret`.
    pub key_image: ProjectivePoint,
}

impl KeyImageSecret {
    /// The secret as 32 big-endian bytes, e.g. to seed a symmetric KDF.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes_be()
    }

    /// The child public key, SEC1 compressed (33 bytes).
    pub fn public_key_sec1(&self) -> [u8; 33] {
        secp::to_sec1_compressed(&self.public_key).expect("child key is not the identity")
    }
}

/// Round-1 point-to-point message: this party's partial key image and the DLEQ
/// proof tying it to its public share commitment. Points are SEC1 compressed.
#[derive(Serialize, Deserialize)]
struct KeyImageR1 {
    /// `W_i = w_i·P`.
    #[serde(rename = "W")]
    w: B64Bytes,
    /// DLEQ commitment `A₁ = r·G`.
    #[serde(rename = "A1")]
    a1: B64Bytes,
    /// DLEQ commitment `A₂ = r·P`.
    #[serde(rename = "A2")]
    a2: B64Bytes,
    /// DLEQ response `z = r + c·w_i` (big-endian minimal).
    #[serde(rename = "Z")]
    z: B64Bytes,
}

/// A running threshold key-image ceremony: a one-round distributed PRF that
/// turns an identifier into a secret only `T+1` share holders can compute —
/// the building block for hardened derivation, which BIP32's
/// `HMAC(chain_code, priv)` cannot provide to a threshold key (the `dklstss`
/// counterpart of [`crate::frosttss::KeyImageParty`]).
///
/// Construct with [`KeyImageParty::new`]; collect the result with
/// [`KeyImageParty::wait`] or [`KeyImageParty::try_result`]. Every committee
/// member runs one against the same identifier.
///
/// Each party contributes a partial key image `W_i = λ_i·x_i·P` over
/// `P = HashToPoint(identifier)`; the partials sum to `V = x·P` and the secret
/// is `HashToScalar(identifier, V)`. Partials are point-to-point, never
/// broadcast — `T+1` of them reveal the secret, so the ceremony relies on the
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
    subset: Vec<PartyId>,
    other_subset: Vec<PartyId>,
    hash: HashAlgorithm,
    point: ProjectivePoint,
    my_partial: ProjectivePoint,
    result_tx: Mutex<Option<Sender<Result<KeyImageSecret, Error>>>>,
}

impl KeyImageParty {
    /// Starts a key-image ceremony for `identifier`. `subset` must be sorted by
    /// party key, contain this party, and hold at least `T+1` members — every
    /// member runs its own `KeyImageParty` against the same identifier.
    ///
    /// The identifier is arbitrary caller-chosen bytes — a label, a BIP32-style
    /// path encoding, a customer id. Distinct identifiers give unlinkable
    /// secrets; the same identifier always gives the same one, whichever
    /// qualifying committee runs the ceremony. See [`KeyImageParty`] for what
    /// the secret is and how it is protected.
    pub fn new(
        params: Parameters,
        key: Key,
        identifier: Vec<u8>,
        subset: Vec<PartyId>,
        hash: HashAlgorithm,
    ) -> Result<KeyImageParty, Error> {
        key.validate_basic()?;
        if subset.len() < key.t + 1 {
            return Err(Error::Validation(format!(
                "subset size {}, expected at least T+1={}",
                subset.len(),
                key.t + 1
            )));
        }
        validate_sorted_subset(&subset)?;

        let me = params.party_id().clone();
        let my_pos = subset
            .iter()
            .position(|p| p.cmp_key(&me) == std::cmp::Ordering::Equal)
            .ok_or_else(|| Error::Validation("self not in key-image subset".into()))?;

        let point = hash_to_point(&identifier, &key.ecdsa_pub, hash)?;
        let ids: Vec<Scalar> = subset
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();
        // w_i = λ_i·x_i, the same weighted share used when signing.
        let w = lagrange_coefficient(&ids, my_pos)?.mul(&key.xi);
        let partial = point.mul(&w);
        let statement = secp::mul_base(&w);

        let session = dleq_session(&identifier, &key.ecdsa_pub, &subset, &me.key, hash);
        let proof = Dleq::prove(&session, &point, &w, &statement, &partial, &mut OsRng);

        let other_subset = other_parties(&subset, &me);
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key,
            identifier,
            subset,
            other_subset,
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

    /// Round 1: send `(W_i, DLEQ)` to each peer in the subset, then wait.
    fn round1(self: &Arc<Self>, proof: &Dleq) -> Result<(), Error> {
        let (Some(w), Some(a1), Some(a2)) = (
            secp::to_sec1_compressed(&self.my_partial),
            secp::to_sec1_compressed(&proof.a1),
            secp::to_sec1_compressed(&proof.a2),
        ) else {
            return Err(Error::Validation(
                "partial key image or DLEQ commitment is the identity".into(),
            ));
        };
        let msg = KeyImageR1 {
            w: B64Bytes(w.to_vec()),
            a1: B64Bytes(a1.to_vec()),
            a2: B64Bytes(a2.to_vec()),
            z: B64Bytes(secp::scalar_to_be_min(&proof.z)),
        };
        for pid in &self.other_subset {
            self.send_to(TYPE_R1, &msg, pid)?;
        }

        let me = Arc::clone(self);
        let others = self.other_subset.clone();
        let exp = JsonExpect::new(
            TYPE_R1,
            self.other_subset.clone(),
            Box::new(move |msgs| me.finalize(&others, msgs)),
        );
        self.params.broker().connect(TYPE_R1, Arc::new(exp));
        Ok(())
    }

    /// Verifies every peer's partial, sums them into `V = x·P`, derives the
    /// secret and the child key.
    fn finalize(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let ids: Vec<Scalar> = self
            .subset
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();

        let mut v = self.my_partial;
        for (pid, jm) in others.iter().zip(msgs.iter()) {
            let r1: KeyImageR1 = match json_get(jm) {
                Ok(m) => m,
                Err(e) => return self.deliver(Err(Error::Serde(e))),
            };
            let (Some(wj), Some(a1), Some(a2)) = (
                secp::from_sec1(&r1.w.0),
                secp::from_sec1(&r1.a1.0),
                secp::from_sec1(&r1.a2.0),
            ) else {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent a malformed partial key image"
                ))));
            };
            if r1.z.0.len() > 32 {
                return self.deliver(Err(Error::Validation(format!(
                    "party {pid} sent an oversized DLEQ response"
                ))));
            }
            let z = secp::scalar_from_be_reduce(&r1.z.0);

            // Statement: λ_j·X_j, from the peer's public share commitment.
            let Some(pos) = self
                .subset
                .iter()
                .position(|p| p.cmp_key(pid) == std::cmp::Ordering::Equal)
            else {
                return self.deliver(Err(Error::Validation(format!("{pid} not in subset"))));
            };
            let Some(full_idx) = self
                .key
                .party_ids
                .iter()
                .position(|p| p.cmp_key(pid) == std::cmp::Ordering::Equal)
            else {
                return self.deliver(Err(Error::Validation(format!(
                    "missing public share for {pid}"
                ))));
            };
            let lambda_j = match lagrange_coefficient(&ids, pos) {
                Ok(l) => l,
                Err(e) => return self.deliver(Err(e)),
            };
            let statement = self.key.big_xj[full_idx].mul(&lambda_j);

            let session = dleq_session(
                &self.identifier,
                &self.key.ecdsa_pub,
                &self.subset,
                &pid.key,
                self.hash,
            );
            let proof = Dleq { a1, a2, z };
            if !proof.verify(&session, &self.point, &statement, &wj) {
                return self.deliver(Err(Error::Validation(format!(
                    "partial key image from {pid} failed its DLEQ proof"
                ))));
            }
            v = v.add(&wj);
        }

        if bool::from(v.is_identity()) {
            return self.deliver(Err(Error::Validation(
                "key image is the identity point".into(),
            )));
        }
        let secret =
            match secret_from_key_image(&self.identifier, &self.key.ecdsa_pub, &v, self.hash) {
                Ok(s) => s,
                Err(e) => return self.deliver(Err(e)),
            };
        let public_key = self.key.ecdsa_pub.add(&secp::mul_base(&secret));
        if bool::from(public_key.is_identity()) {
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
    a1: ProjectivePoint,
    a2: ProjectivePoint,
    z: Scalar,
}

impl Dleq {
    fn prove(
        session: &[u8],
        p: &ProjectivePoint,
        w: &Scalar,
        y: &ProjectivePoint,
        w_pt: &ProjectivePoint,
        rng: &mut impl RngCore,
    ) -> Dleq {
        let r = secp::random_scalar(rng);
        let a1 = secp::mul_base(&r);
        let a2 = p.mul(&r);
        let c = dleq_challenge(session, p, y, w_pt, &a1, &a2);
        let z = r.add(&c.mul(w));
        Dleq { a1, a2, z }
    }

    /// `z·G == A₁ + c·Y` and `z·P == A₂ + c·W`.
    fn verify(
        &self,
        session: &[u8],
        p: &ProjectivePoint,
        y: &ProjectivePoint,
        w_pt: &ProjectivePoint,
    ) -> bool {
        let c = dleq_challenge(session, p, y, w_pt, &self.a1, &self.a2);
        secp::point_eq(&secp::mul_base(&self.z), &self.a1.add(&y.mul(&c)))
            && secp::point_eq(&p.mul(&self.z), &self.a2.add(&w_pt.mul(&c)))
    }
}

/// `c = SHA512_256i_TAGGED(session, P, Y, W, A₁, A₂) mod n`, each point as its
/// affine `(x, y)` big-endian pair (the tagged-hash shape used by
/// [`super::schnorr`]).
fn dleq_challenge(
    session: &[u8],
    p: &ProjectivePoint,
    y: &ProjectivePoint,
    w_pt: &ProjectivePoint,
    a1: &ProjectivePoint,
    a2: &ProjectivePoint,
) -> Scalar {
    let coords: Vec<Vec<u8>> = [p, y, w_pt, a1, a2]
        .iter()
        .flat_map(|pt| {
            let (x, y) = secp::affine_be(pt);
            [x, y]
        })
        .collect();
    let operands: Vec<&[u8]> = coords.iter().map(|v| v.as_slice()).collect();
    Scalar::from_bytes_be_reduce(&sha512_256i_tagged(session, &operands))
}

/// Fiat-Shamir session bytes: the identifier, the joint public key, the
/// committee, and the prover's key — so a proof cannot be replayed into another
/// ceremony, committee, or party slot.
fn dleq_session(
    identifier: &[u8],
    ecdsa_pub: &ProjectivePoint,
    subset: &[PartyId],
    prover: &[u8],
    hash: HashAlgorithm,
) -> Vec<u8> {
    let (px, py) = secp::affine_be(ecdsa_pub);
    let mut buf = Vec::with_capacity(96 + identifier.len() + 8 * subset.len());
    buf.extend_from_slice(DLEQ_DOMAIN);
    push_field(&mut buf, hash.name().as_bytes());
    push_field(&mut buf, &px);
    push_field(&mut buf, &py);
    push_field(&mut buf, identifier);
    buf.extend_from_slice(&(subset.len() as u64).to_be_bytes());
    for p in subset {
        push_field(&mut buf, strip(&p.key));
    }
    push_field(&mut buf, strip(prover));
    buf
}

/// Maps an identifier to a secp256k1 point, deterministically and publicly:
/// `hash(domain ‖ hash_name ‖ pub ‖ identifier ‖ counter)` is tried as the `x`
/// coordinate of an even-`y` point, incrementing `counter` until it lies on the
/// curve (~50% per try). The algorithm name is part of the preimage, so each
/// choice of `hash` gives an unrelated point.
///
/// Errors if `hash` is a legacy or under-32-byte digest. Try-and-increment is
/// not constant time, but every input here is public, so the timing carries no
/// secret. secp256k1 has cofactor 1, so any on-curve point is already in the
/// prime-order group.
pub fn hash_to_point(
    identifier: &[u8],
    ecdsa_pub: &ProjectivePoint,
    hash: HashAlgorithm,
) -> Result<ProjectivePoint, Error> {
    validate_hash(hash).map_err(Error::Validation)?;
    let compressed = secp::to_sec1_compressed(ecdsa_pub)
        .ok_or_else(|| Error::Validation("public key is the identity".into()))?;
    let mut base = Vec::with_capacity(80 + identifier.len());
    base.extend_from_slice(POINT_DOMAIN);
    push_field(&mut base, hash.name().as_bytes());
    base.extend_from_slice(&compressed);
    push_field(&mut base, identifier);
    let prefix_len = base.len();
    base.extend_from_slice(&[0u8; 4]);

    let mut candidate = [0u8; 33];
    candidate[0] = 0x02; // even y
    for counter in 0u32..=u32::MAX {
        base[prefix_len..].copy_from_slice(&counter.to_be_bytes());
        candidate[1..].copy_from_slice(&digest32(hash, &base));
        if let Some(p) = secp::from_sec1(&candidate)
            && !bool::from(p.is_identity())
        {
            return Ok(p);
        }
    }
    unreachable!("no valid curve point in 2^32 hash-to-point attempts")
}

/// `secret = hash(domain ‖ hash_name ‖ pub ‖ identifier ‖ V) mod n`, rejecting
/// the (negligibly unlikely) zero result.
///
/// The digest is 32 bytes wide against a ~256-bit group order, so the modular
/// reduction is biased by at most ~2^-128 — the same margin as SEC1 §4.1.3
/// hash-to-scalar used throughout `dklstss` signing.
fn secret_from_key_image(
    identifier: &[u8],
    ecdsa_pub: &ProjectivePoint,
    key_image: &ProjectivePoint,
    hash: HashAlgorithm,
) -> Result<Scalar, Error> {
    let pub_c = secp::to_sec1_compressed(ecdsa_pub)
        .ok_or_else(|| Error::Validation("public key is the identity".into()))?;
    let v_c = secp::to_sec1_compressed(key_image)
        .ok_or_else(|| Error::Validation("key image is the identity".into()))?;
    let mut buf = Vec::with_capacity(96 + identifier.len());
    buf.extend_from_slice(SECRET_DOMAIN);
    push_field(&mut buf, hash.name().as_bytes());
    buf.extend_from_slice(&pub_c);
    push_field(&mut buf, identifier);
    buf.extend_from_slice(&v_c);
    let s = Scalar::from_bytes_be_reduce(&digest32(hash, &buf));
    if bool::from(s.is_zero()) {
        return Err(Error::Validation(
            "derived secret is zero; use a different identifier".into(),
        ));
    }
    Ok(s)
}

/// Appends a length-prefixed field, so concatenations stay unambiguous.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

fn validate_sorted_subset(subset: &[PartyId]) -> Result<(), Error> {
    for w in subset.windows(2) {
        if w[0].cmp_key(&w[1]) != std::cmp::Ordering::Less {
            return Err(Error::Validation(
                "key-image subset must be sorted and distinct by key".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::keygen::keygen;
    use super::super::signing::{ecdsa_verify, hash_to_scalar, sign_with_tweak};
    use super::*;
    use crate::tss::testhub::TestHub;
    use purecrypto::hash::sha256;

    /// The digest the ceremony tests run under; the vectors cover the rest.
    const H: HashAlgorithm = HashAlgorithm::Sha256;

    fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    /// Runs the ceremony over `members` (indices into `keys`) and returns each
    /// participant's result.
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
        let parties: Vec<KeyImageParty> = members
            .iter()
            .enumerate()
            .map(|(pos, &i)| {
                let params =
                    Parameters::new(committee.clone(), &committee[pos], t, hub.broker(pos));
                KeyImageParty::new(
                    params,
                    keys[i].clone(),
                    identifier.to_vec(),
                    committee.clone(),
                    H,
                )
                .unwrap()
            })
            .collect();
        parties
            .iter()
            .map(|p| p.wait().expect("key-image ceremony succeeds"))
            .collect()
    }

    #[test]
    fn key_image_equals_x_times_p() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let out = run(&ids, &keys, &[0, 1], 1, b"customer/42");

        // Reconstruct x from two shares to check V == x·P centrally.
        let subset: Vec<Scalar> = [0usize, 1]
            .iter()
            .map(|&i| secp::scalar_from_be_reduce(&ids[i].key))
            .collect();
        let mut x = Scalar::ZERO;
        for (pos, &i) in [0usize, 1].iter().enumerate() {
            x = x.add(&lagrange_coefficient(&subset, pos).unwrap().mul(&keys[i].xi));
        }
        let p = hash_to_point(b"customer/42", &keys[0].ecdsa_pub, H).unwrap();
        assert!(secp::point_eq(&out[0].key_image, &p.mul(&x)));
        for o in &out[1..] {
            assert_eq!(o.secret_bytes(), out[0].secret_bytes());
            assert_eq!(o.public_key_sec1(), out[0].public_key_sec1());
        }
        // The advertised child key is the group key plus the secret.
        let want_pub = keys[0].ecdsa_pub.add(&secp::mul_base(&out[0].secret));
        assert!(secp::point_eq(&out[0].public_key, &want_pub));
    }

    #[test]
    fn different_committees_derive_the_same_secret() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let a = run(&ids, &keys, &[0, 1], 1, b"same-id");
        let b = run(&ids, &keys, &[1, 2], 1, b"same-id");
        assert_eq!(a[0].secret_bytes(), b[0].secret_bytes());
        assert_eq!(a[0].public_key_sec1(), b[1].public_key_sec1());
    }

    #[test]
    fn different_identifiers_give_different_secrets() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let a = run(&ids, &keys, &[0, 1], 1, b"id-a");
        let b = run(&ids, &keys, &[0, 1], 1, b"id-b");
        assert_ne!(a[0].secret_bytes(), b[0].secret_bytes());
        assert_ne!(a[0].public_key_sec1(), b[0].public_key_sec1());
    }

    #[test]
    fn derived_secret_signs_as_child_key() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let derived = run(&ids, &keys, &[0, 1], 1, b"hardened/0");

        let msg = sha256(b"signed under a key-image-derived child key");
        let sig = sign_with_tweak(&keys, &[0, 1], &derived[0].secret, &msg, &mut OsRng).unwrap();
        let e = hash_to_scalar(&msg);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&derived[0].public_key, &e, &r, &s));
        // …and not under the parent key.
        assert!(!ecdsa_verify(&keys[0].ecdsa_pub, &e, &r, &s));
    }

    #[test]
    fn hash_to_point_is_deterministic_and_identifier_bound() {
        let ids = party_ids(2);
        let keys = keygen(2, 1, &ids, &mut OsRng).unwrap();
        let a = hash_to_point(b"x", &keys[0].ecdsa_pub, H).unwrap();
        assert!(secp::point_eq(
            &a,
            &hash_to_point(b"x", &keys[0].ecdsa_pub, H).unwrap()
        ));
        assert!(!secp::point_eq(
            &a,
            &hash_to_point(b"y", &keys[0].ecdsa_pub, H).unwrap()
        ));
        assert!(!bool::from(a.is_identity()));
    }

    #[test]
    fn dleq_rejects_a_wrong_partial() {
        let ids = party_ids(2);
        let keys = keygen(2, 1, &ids, &mut OsRng).unwrap();
        let p = hash_to_point(b"dleq", &keys[0].ecdsa_pub, H).unwrap();
        let w = secp::random_scalar(&mut OsRng);
        let y = secp::mul_base(&w);
        let w_pt = p.mul(&w);
        let proof = Dleq::prove(b"s", &p, &w, &y, &w_pt, &mut OsRng);
        assert!(proof.verify(b"s", &p, &y, &w_pt));
        let bogus = p.mul(&secp::random_scalar(&mut OsRng));
        assert!(!proof.verify(b"s", &p, &y, &bogus));
        assert!(!proof.verify(b"other", &p, &y, &w_pt));
    }

    /// A different digest is a different derivation, never a coincidence.
    #[test]
    fn each_hash_gives_an_unrelated_secret() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut OsRng).unwrap();
        let committee = PartyId::sort(ids[..2].to_vec(), 0);
        let mut seen = std::collections::HashSet::new();
        for alg in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Keccak256,
            HashAlgorithm::Blake3,
        ] {
            let hub = TestHub::new(&committee);
            let parties: Vec<KeyImageParty> = (0..2)
                .map(|i| {
                    let params =
                        Parameters::new(committee.clone(), &committee[i], 1, hub.broker(i));
                    KeyImageParty::new(
                        params,
                        keys[i].clone(),
                        b"same".to_vec(),
                        committee.clone(),
                        alg,
                    )
                    .unwrap()
                })
                .collect();
            let out: Vec<_> = parties.iter().map(|p| p.wait().unwrap()).collect();
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
        let ids = party_ids(2);
        let keys = keygen(2, 1, &ids, &mut OsRng).unwrap();
        let committee = PartyId::sort(ids.clone(), 0);
        for alg in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Md5,
            HashAlgorithm::Sha224,
        ] {
            let hub = TestHub::new(&committee);
            let params = Parameters::new(committee.clone(), &committee[0], 1, hub.broker(0));
            assert!(
                KeyImageParty::new(
                    params,
                    keys[0].clone(),
                    b"id".to_vec(),
                    committee.clone(),
                    alg
                )
                .is_err(),
                "{} accepted",
                alg.name()
            );
            assert!(hash_to_point(b"id", &keys[0].ecdsa_pub, alg).is_err());
        }
    }

    #[test]
    fn subset_smaller_than_threshold_is_rejected() {
        let ids = party_ids(3);
        let keys = keygen(3, 2, &ids, &mut OsRng).unwrap();
        let committee = PartyId::sort(ids[..2].to_vec(), 0);
        let hub = TestHub::new(&committee);
        let params = Parameters::new(committee.clone(), &committee[0], 2, hub.broker(0));
        assert!(KeyImageParty::new(params, keys[0].clone(), b"id".to_vec(), committee, H).is_err());
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
/// `cargo test --lib dklstss::keyimage_party::vectors::print -- --ignored --nocapture`,
/// writing the output to `testdata/keyimage_vectors.json`. A changed vector file
/// means every previously derived child key is gone: only ever regenerate for a
/// deliberate, versioned construction change.
#[cfg(test)]
mod vectors {
    use super::*;
    use crate::tss::keyimage_hash::validate as validate_hash;
    use crate::tss::testhub::TestHub;
    use purecrypto::hash::sha512;
    use serde::{Deserialize, Serialize};

    /// One (hash, identifier) pair and every value the construction derives
    /// from it. Byte strings are lower-case hex; scalars 32-byte big-endian,
    /// points SEC1 compressed (33 bytes).
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Case {
        /// Canonical `HashAlgorithm` name, e.g. `"sha256"`, `"keccak256"`.
        hash: String,
        identifier: String,
        /// `P = HashToPoint(identifier, ecdsa_pub, hash)`.
        point: String,
        /// `W_i = λ_i·x_i·P`, aligned with the top-level `committee`.
        partials: Vec<String>,
        /// `V = Σ W_i = x·P`.
        key_image: String,
        /// `HashToScalar(domain, hash, identifier, V)`.
        secret: String,
        /// `ecdsa_pub + secret·G`.
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
        /// Per-party secret shares `x_i`.
        shares: Vec<String>,
        /// The master secret `x`, for cross-checking `V = x·P`.
        master_secret: String,
        group_public_key: String,
        /// The committee the cases were produced by (hex party keys); the
        /// prover of each case's DLEQ proof is its first member.
        committee: Vec<String>,
        cases: Vec<Case>,
    }

    fn hex_scalar(s: &Scalar) -> String {
        hex::encode(s.to_bytes_be())
    }

    fn hex_point(p: &ProjectivePoint) -> String {
        hex::encode(secp::to_sec1_compressed(p).expect("non-identity point"))
    }

    fn scalar_from_hex(s: &str) -> Scalar {
        let b: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        Scalar::from_bytes_be(&b).expect("canonical scalar")
    }

    fn point_from_hex(s: &str) -> ProjectivePoint {
        secp::from_sec1(&hex::decode(s).unwrap()).expect("valid point")
    }

    /// The fixed 1-of-3 key set the vectors are built on: deterministic Shamir
    /// coefficients, so the whole file is reproducible from these labels alone.
    /// OT state is absent — the key-image ceremony never touches it.
    fn vector_keys() -> (Vec<PartyId>, Vec<Key>, Scalar) {
        let coeffs: Vec<Scalar> = ["tsslib/keyimage/vector/a0", "tsslib/keyimage/vector/a1"]
            .iter()
            .map(|label| {
                Scalar::from_bytes_be_reduce(&digest32(HashAlgorithm::Sha256, label.as_bytes()))
            })
            .collect();
        let ids = PartyId::sort(
            (1..=3u8)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i]))
                .collect(),
            0,
        );
        let xs: Vec<Scalar> = ids
            .iter()
            .map(|p| {
                let x = secp::scalar_from_be_reduce(&p.key);
                coeffs[1].mul(&x).add(&coeffs[0])
            })
            .collect();
        let big_xj: Vec<ProjectivePoint> = xs.iter().map(secp::mul_base).collect();
        let ecdsa_pub = secp::mul_base(&coeffs[0]);
        let keys = (0..3)
            .map(|i| Key {
                n: 3,
                t: 1,
                idx: i,
                party_ids: ids.clone(),
                xi: xs[i].clone(),
                big_xj: big_xj.clone(),
                ecdsa_pub,
                ot: vec![None, None, None],
                chain_code: [0u8; 32],
            })
            .collect();
        (ids, keys, coeffs[0].clone())
    }

    /// Identifiers covered: empty, ASCII, a path-shaped label, and raw bytes.
    fn vector_identifiers() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            b"abc".to_vec(),
            b"m/44'/60'/0'/0/0".to_vec(),
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
        let ecdsa_pub = keys[0].ecdsa_pub;
        let committee: Vec<PartyId> = ids[..2].to_vec();
        let lambda_ids: Vec<Scalar> = committee
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();

        let mut cases = Vec::new();
        for hash in vector_hashes() {
            for identifier in vector_identifiers() {
                let point = hash_to_point(&identifier, &ecdsa_pub, hash).unwrap();

                let mut partials = Vec::new();
                let mut v = ProjectivePoint::identity();
                for pos in 0..committee.len() {
                    let w = lagrange_coefficient(&lambda_ids, pos)
                        .unwrap()
                        .mul(&keys[pos].xi);
                    let partial = point.mul(&w);
                    v = v.add(&partial);
                    partials.push(hex_point(&partial));
                }

                let secret = secret_from_key_image(&identifier, &ecdsa_pub, &v, hash).unwrap();
                let child = ecdsa_pub.add(&secp::mul_base(&secret));

                // DLEQ for the first committee member under a fixed nonce.
                let w = lagrange_coefficient(&lambda_ids, 0)
                    .unwrap()
                    .mul(&keys[0].xi);
                let w_pt = point.mul(&w);
                let statement = secp::mul_base(&w);
                let session =
                    dleq_session(&identifier, &ecdsa_pub, &committee, &committee[0].key, hash);
                let r = Scalar::from_bytes_be_reduce(&digest32(
                    HashAlgorithm::Sha256,
                    &[
                        b"tsslib/keyimage/vector/nonce".as_slice(),
                        hash.name().as_bytes(),
                        &identifier,
                    ]
                    .concat(),
                ));
                let a1 = secp::mul_base(&r);
                let a2 = point.mul(&r);
                let c = dleq_challenge(&session, &point, &statement, &w_pt, &a1, &a2);
                let z = r.add(&c.mul(&w));
                let wire = KeyImageR1 {
                    w: B64Bytes(secp::to_sec1_compressed(&w_pt).unwrap().to_vec()),
                    a1: B64Bytes(secp::to_sec1_compressed(&a1).unwrap().to_vec()),
                    a2: B64Bytes(secp::to_sec1_compressed(&a2).unwrap().to_vec()),
                    z: B64Bytes(secp::scalar_to_be_min(&z)),
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
            scheme: "dklstss/keyimage/v1".into(),
            point_domain: String::from_utf8(POINT_DOMAIN.to_vec()).unwrap(),
            secret_domain: String::from_utf8(SECRET_DOMAIN.to_vec()).unwrap(),
            dleq_domain: String::from_utf8(DLEQ_DOMAIN.to_vec()).unwrap(),
            threshold: 1,
            party_keys: ids.iter().map(|p| hex::encode(&p.key)).collect(),
            shares: keys.iter().map(|k| hex_scalar(&k.xi)).collect(),
            master_secret: hex_scalar(&master),
            group_public_key: hex_point(&ecdsa_pub),
            committee: committee.iter().map(|p| hex::encode(&p.key)).collect(),
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
            assert_eq!(g, w, "derivation changed for hash {}", w.hash);
        }
        assert_eq!(got, want, "key-image construction changed");
    }

    /// The checked-in file is internally consistent: partials sum to the key
    /// image, the key image is `x·P`, secret and child key follow, and the
    /// pinned DLEQ proof verifies.
    #[test]
    fn checked_in_file_is_self_consistent() {
        let f = checked_in();
        let ecdsa_pub = point_from_hex(&f.group_public_key);
        let master = scalar_from_hex(&f.master_secret);
        assert!(secp::point_eq(&ecdsa_pub, &secp::mul_base(&master)));

        let (ids, _, _) = vector_keys();
        let committee: Vec<PartyId> = ids[..2].to_vec();
        assert_eq!(
            f.committee,
            committee
                .iter()
                .map(|p| hex::encode(&p.key))
                .collect::<Vec<_>>()
        );
        let lambda_ids: Vec<Scalar> = committee
            .iter()
            .map(|p| secp::scalar_from_be_reduce(&p.key))
            .collect();
        let statement = secp::mul_base(
            &lagrange_coefficient(&lambda_ids, 0)
                .unwrap()
                .mul(&scalar_from_hex(&f.shares[0])),
        );

        for case in &f.cases {
            let hash = HashAlgorithm::from_name(&case.hash).expect("known hash name");
            let identifier = hex::decode(&case.identifier).unwrap();
            let point = point_from_hex(&case.point);
            assert!(secp::point_eq(
                &point,
                &hash_to_point(&identifier, &ecdsa_pub, hash).unwrap()
            ));

            let mut v = ProjectivePoint::identity();
            for p in &case.partials {
                v = v.add(&point_from_hex(p));
            }
            assert!(secp::point_eq(&v, &point_from_hex(&case.key_image)));
            // V == x·P, the property the whole construction rests on.
            assert!(secp::point_eq(&v, &point.mul(&master)));

            let secret = scalar_from_hex(&case.secret);
            assert!(bool::from(secret.ct_eq(
                &secret_from_key_image(&identifier, &ecdsa_pub, &v, hash).unwrap()
            )));
            assert!(secp::point_eq(
                &point_from_hex(&case.child_public_key),
                &ecdsa_pub.add(&secp::mul_base(&secret))
            ));

            // The pinned proof verifies against the pinned partial.
            let session =
                dleq_session(&identifier, &ecdsa_pub, &committee, &committee[0].key, hash);
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
            let msg: KeyImageR1 = serde_json::from_str(&case.dleq.wire_json).unwrap();
            assert_eq!(hex::encode(&msg.w.0), case.partials[0]);
            assert_eq!(hex::encode(&msg.a1.0), case.dleq.a1);
            assert_eq!(hex::encode(&msg.a2.0), case.dleq.a2);
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
                    KeyImageParty::new(
                        params,
                        keys[i].clone(),
                        identifier.clone(),
                        committee.clone(),
                        hash,
                    )
                    .expect("ceremony starts")
                })
                .collect();
            for p in &parties {
                let out = p.wait().expect("ceremony succeeds");
                assert_eq!(hex_point(&out.key_image), case.key_image, "{}", case.hash);
                assert_eq!(hex::encode(out.secret_bytes()), case.secret);
                assert_eq!(hex::encode(out.public_key_sec1()), case.child_public_key);
            }
        }
    }
}
