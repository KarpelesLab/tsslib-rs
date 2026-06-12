//! Dealerless distributed key generation for threshold ML-DSA-44.
//!
//! **Experimental.** Threshold ML-DSA has no DKG in the paper or the Go
//! reference (both use a trusted dealer); this is an original "distribute the
//! dealer" protocol and has **not** received any independent review. Do not use
//! it for anything but experimentation.
//!
//! The trusted-dealer key replicates one `(s1_M, s2_M)` secret per honest-signer
//! mask `M` (popcount `n − t + 1`) to every party in `M`. Here each mask is
//! *dealt by its lowest-id member*: that party samples `(s1_M, s2_M)`,
//! broadcasts the public `t_M = A·s1_M + s2_M` and a commitment, and unicasts
//! the share to the other holders of `M`. Because `t = Σ_M t_M` is linear, every
//! party can aggregate `t` and round it to the FIPS-204 `t1` without a dealer —
//! and no single party knows every mask's secret (the all-honest-parties mask is
//! dealt by an honest party), so the trusted-dealer assumption is removed.
//!
//! Rounds: (1) broadcast a `rho` contribution → joint `rho = H(all)`; (2) deal
//! owned masks (broadcast `t_M`+commit, unicast shares); finalize verifies each
//! held mask against its commitment/bound and assembles this party's [`Key44`].

use super::Error;
use super::key::{Key44, Share44, expand_matrix};
use super::keygen::gosper_masks;
use super::packing::{PACK_POLYQ_SIZE, pack_polyq, unpack_polyq};
use super::params::ThresholdParams44;
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::hash::shake256;
use purecrypto::mldsa::MlDsa44PublicKey;
use purecrypto::mldsa::hazmat::{self, ML_DSA_44, N, Poly, pack_t1, power2_round};
use purecrypto::rng::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const L: usize = 4;
const K: usize = 4;

const TYPE_R1: &str = "mldsa44:dkg:round1";
const TYPE_R2BC: &str = "mldsa44:dkg:r2bc";
const TYPE_R2SH: &str = "mldsa44:dkg:r2sh";
const RHO_DOMAIN: &[u8] = b"mldsatss-dkg-rho-v1";
const COMMIT_DOMAIN: &[u8] = b"mldsatss-dkg-commit-v1";

type DkgResult = Result<Key44, Error>;

/// A running dealerless DKG session. Construct with [`DkgParty44::new`]; retrieve
/// this party's [`Key44`] with [`DkgParty44::wait`]. The group public key is
/// [`DkgParty44::public_key`] after completion (or recompute from any party's key).
pub struct DkgParty44 {
    result_rx: MpscReceiver<DkgResult>,
    shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    th: ThresholdParams44,
    id: u8,
    masks_deal: Vec<u8>,
    masks_hold: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<DkgResult>>>,
    pk: Mutex<Option<MlDsa44PublicKey>>,
}

struct State {
    own_contrib: [u8; 32],
    contribs: Vec<Option<[u8; 32]>>, // by committee slot (= id)
    dealt: HashMap<u8, ([Poly; L], [Poly; K])>,
    received: HashMap<u8, ([Poly; L], [Poly; K])>,
    t_by_mask: HashMap<u8, [Poly; K]>,
    commit_by_mask: HashMap<u8, [u8; 32]>,
    pending: u8,
}

impl DkgParty44 {
    /// Starts the dealerless DKG for this party. The committee `params.parties()`
    /// must be the full `n`-party set (sorted); this party's id is its index.
    pub fn new(params: Parameters, th: ThresholdParams44) -> Result<DkgParty44, Error> {
        let n = params.parties().len();
        if n != th.n as usize {
            return Err(Error::Validation(format!(
                "committee must have n={} members",
                th.n
            )));
        }
        let id = params.party_index() as u8;
        let popcount = (th.n - th.t + 1) as u32;
        let all_masks = gosper_masks(n, popcount);
        let masks_deal: Vec<u8> = all_masks
            .iter()
            .copied()
            .filter(|&m| m.trailing_zeros() as u8 == id)
            .collect();
        let masks_hold: Vec<u8> = all_masks
            .iter()
            .copied()
            .filter(|&m| (m >> id) & 1 == 1)
            .collect();

        let mut own_contrib = [0u8; 32];
        OsRng.fill_bytes(&mut own_contrib);

        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            th,
            id,
            masks_deal,
            masks_hold,
            state: Mutex::new(State {
                own_contrib,
                contribs: vec![None; n],
                dealt: HashMap::new(),
                received: HashMap::new(),
                t_by_mask: HashMap::new(),
                commit_by_mask: HashMap::new(),
                pending: 0,
            }),
            result_tx: Mutex::new(Some(tx)),
            pk: Mutex::new(None),
        });
        shared.round1()?;
        Ok(DkgParty44 {
            result_rx: rx,
            shared,
        })
    }

    /// Blocks until the DKG completes, returning this party's key.
    pub fn wait(&self) -> DkgResult {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("dkg dropped without result".into())),
        }
    }

    /// The group public key, available after [`wait`](DkgParty44::wait) succeeds.
    pub fn public_key(&self) -> Option<MlDsa44PublicKey> {
        self.shared.pk.lock().unwrap().clone()
    }
}

impl Shared {
    fn deliver(&self, r: DkgResult) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let contrib = {
            let mut st = self.state.lock().unwrap();
            st.contribs[self.id as usize] = Some(st.own_contrib);
            st.own_contrib
        };
        self.broadcast(
            TYPE_R1,
            &Dkg1 {
                contrib: B64Bytes(contrib.to_vec()),
            },
        )?;
        let me = Arc::clone(self);
        let others = self.params.other_parties();
        let exp = JsonExpect::new(
            TYPE_R1,
            others.clone(),
            Box::new(move |msgs| me.on_r1(&others, msgs)),
        );
        self.params.broker().connect(TYPE_R1, Arc::new(exp));
        Ok(())
    }

    fn on_r1(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let r1s: Vec<Dkg1> = match msgs.iter().map(|m| Ok(json_get(m)?)).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        let rho = {
            let mut st = self.state.lock().unwrap();
            for (pid, r1) in others.iter().zip(r1s.iter()) {
                let slot = self.committee_slot(pid);
                if r1.contrib.0.len() != 32 {
                    return self.deliver(Err(Error::Validation("bad rho contribution".into())));
                }
                let mut c = [0u8; 32];
                c.copy_from_slice(&r1.contrib.0);
                st.contribs[slot] = Some(c);
            }
            let mut input = RHO_DOMAIN.to_vec();
            for c in &st.contribs {
                match c {
                    Some(b) => input.extend_from_slice(b),
                    None => {
                        return self.deliver(Err(Error::Validation("missing contribution".into())));
                    }
                }
            }
            let mut rho = [0u8; 32];
            shake256(&input, &mut rho);
            rho
        };

        if let Err(e) = self.round2(&rho, others) {
            self.deliver(Err(e));
        }
    }

    fn round2(self: &Arc<Self>, rho: &[u8; 32], others: &[PartyId]) -> Result<(), Error> {
        let a = expand_matrix(rho);
        let eta = ML_DSA_44.params.eta;

        // Deal each owned mask: sample (s1,s2), compute t_M, commit.
        let mut bcast_entries = Vec::new();
        for &mask in &self.masks_deal {
            let mut sseed = [0u8; 64];
            OsRng.fill_bytes(&mut sseed);
            let mut s1 = [Poly::zero(); L];
            let mut s2 = [Poly::zero(); K];
            for (j, p) in s1.iter_mut().enumerate() {
                *p = hazmat::sample_bounded_poly(&sseed, eta, j as u16);
            }
            for (j, p) in s2.iter_mut().enumerate() {
                *p = hazmat::sample_bounded_poly(&sseed, eta, (j + L) as u16);
            }
            // The seed alone reproduces the whole share; wipe it as soon as
            // sampling is done (best-effort, Go `ZeroizeBytes(sSeed)`).
            zeroize::Zeroize::zeroize(&mut sseed);
            let t_m = compute_t_m(&a, &s1, &s2);
            let commit = commit_share(mask, &s1, &s2);
            {
                let mut st = self.state.lock().unwrap();
                st.dealt.insert(mask, (s1, s2));
                st.t_by_mask.insert(mask, t_m);
                st.commit_by_mask.insert(mask, commit);
            }
            bcast_entries.push(MaskT {
                mask,
                t: B64Bytes(pack_vec(&t_m)),
                commit: B64Bytes(commit.to_vec()),
            });
        }
        self.broadcast(
            TYPE_R2BC,
            &Dkg2Bcast {
                entries: bcast_entries,
            },
        )?;

        // Unicast shares to co-holders, grouped by recipient.
        for pj in others {
            let rid = self.committee_slot(pj) as u8;
            let mut entries = Vec::new();
            for &mask in &self.masks_deal {
                if (mask >> rid) & 1 == 1 {
                    let (s1, s2) = {
                        let st = self.state.lock().unwrap();
                        st.dealt[&mask]
                    };
                    entries.push(MaskShare {
                        mask,
                        s1: B64Bytes(pack_vec(&s1)),
                        s2: B64Bytes(pack_vec(&s2)),
                    });
                }
            }
            if !entries.is_empty() {
                self.send_to(TYPE_R2SH, &Dkg2Share { entries }, pj)?;
            }
        }

        // Senders we must receive shares from: dealers (≠ self) of masks we hold.
        let mut share_senders: Vec<PartyId> = Vec::new();
        let parties = self.params.parties();
        for &mask in &self.masks_hold {
            let dealer = mask.trailing_zeros() as usize;
            if dealer as u8 != self.id {
                let pid = parties[dealer].clone();
                if !share_senders
                    .iter()
                    .any(|p| p.cmp_key(&pid) == std::cmp::Ordering::Equal)
                {
                    share_senders.push(pid);
                }
            }
        }

        let expects = 1 + if share_senders.is_empty() { 0 } else { 1 };
        self.state.lock().unwrap().pending = expects;

        let me = Arc::clone(self);
        let exp_bc = JsonExpect::new(
            TYPE_R2BC,
            others.to_vec(),
            Box::new(move |msgs| me.on_r2bcast(msgs)),
        );
        self.params.broker().connect(TYPE_R2BC, Arc::new(exp_bc));

        if !share_senders.is_empty() {
            let me = Arc::clone(self);
            let exp_sh = JsonExpect::new(
                TYPE_R2SH,
                share_senders,
                Box::new(move |msgs| me.on_r2share(msgs)),
            );
            self.params.broker().connect(TYPE_R2SH, Arc::new(exp_sh));
        }
        Ok(())
    }

    fn on_r2bcast(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let bcs: Vec<(PartyId, Dkg2Bcast)> = match msgs
            .iter()
            .map(|m| Ok((m.from.clone().unwrap(), json_get(m)?)))
            .collect()
        {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock().unwrap();
            for (from, bc) in &bcs {
                let dealer = self.committee_slot(from) as u8;
                for e in &bc.entries {
                    // The sender must be the rightful (lowest-id) dealer of this mask.
                    if e.mask.trailing_zeros() as u8 != dealer {
                        return self.deliver(Err(Error::Validation(format!(
                            "party {dealer} dealt mask {} it does not own",
                            e.mask
                        ))));
                    }
                    let t_m = match unpack_vec_k(&e.t.0) {
                        Some(v) => v,
                        None => return self.deliver(Err(Error::Validation("bad t_M".into()))),
                    };
                    if e.commit.0.len() != 32 {
                        return self.deliver(Err(Error::Validation("bad commit".into())));
                    }
                    let mut c = [0u8; 32];
                    c.copy_from_slice(&e.commit.0);
                    st.t_by_mask.insert(e.mask, t_m);
                    st.commit_by_mask.insert(e.mask, c);
                }
            }
        }
        self.maybe_finalize();
    }

    fn on_r2share(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let shares: Vec<Dkg2Share> = match msgs.iter().map(|m| Ok(json_get(m)?)).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock().unwrap();
            for sh in &shares {
                for e in &sh.entries {
                    let s1 = match unpack_vec_l(&e.s1.0) {
                        Some(v) => v,
                        None => return self.deliver(Err(Error::Validation("bad s1 share".into()))),
                    };
                    let s2 = match unpack_vec_k(&e.s2.0) {
                        Some(v) => v,
                        None => return self.deliver(Err(Error::Validation("bad s2 share".into()))),
                    };
                    st.received.insert(e.mask, (s1, s2));
                }
            }
        }
        self.maybe_finalize();
    }

    fn maybe_finalize(self: &Arc<Self>) {
        let ready = {
            let mut st = self.state.lock().unwrap();
            st.pending = st.pending.saturating_sub(1);
            st.pending == 0
        };
        if ready {
            self.finalize();
        }
    }

    fn finalize(self: &Arc<Self>) {
        let st = self.state.lock().unwrap();
        let rho_input = {
            let mut input = RHO_DOMAIN.to_vec();
            for c in &st.contribs {
                input.extend_from_slice(c.as_ref().unwrap());
            }
            input
        };
        let mut rho = [0u8; 32];
        shake256(&rho_input, &mut rho);
        let a = expand_matrix(&rho);
        let eta = ML_DSA_44.params.eta;

        // Every mask must be present exactly once.
        let popcount = (self.th.n - self.th.t + 1) as u32;
        let all_masks = gosper_masks(self.th.n as usize, popcount);
        for &m in &all_masks {
            if !st.t_by_mask.contains_key(&m) {
                return self.deliver(Err(Error::Validation(format!("missing mask {m}"))));
            }
        }

        // Aggregate t = Σ_M t_M, then t1 = high bits.
        let mut t = [Poly::zero(); K];
        for &m in &all_masks {
            let t_m = &st.t_by_mask[&m];
            for i in 0..K {
                t[i] = t[i].add(&t_m[i]);
            }
        }
        let mut t1 = [Poly::zero(); K];
        for (i, t1i) in t1.iter_mut().enumerate() {
            for j in 0..N {
                let (hi, _) = power2_round(t[i].c[j]);
                t1i.c[j] = hi;
            }
        }

        // Assemble + verify this party's held shares.
        let mut shares: HashMap<u8, Share44> = HashMap::new();
        for &mask in &self.masks_hold {
            let (s1, s2) = if let Some(v) = st.dealt.get(&mask) {
                *v
            } else if let Some(v) = st.received.get(&mask) {
                *v
            } else {
                return self.deliver(Err(Error::Validation(format!(
                    "missing held share for mask {mask}"
                ))));
            };
            // Bound check: |coeff| ≤ η.
            for p in s1.iter().chain(s2.iter()) {
                if p.c.iter().any(|&c| hazmat::inf_norm(c) > eta) {
                    return self.deliver(Err(Error::Validation(format!(
                        "mask {mask} share exceeds η bound"
                    ))));
                }
            }
            // Commitment + t_M consistency (catches a cheating dealer).
            if commit_share(mask, &s1, &s2) != st.commit_by_mask[&mask] {
                return self.deliver(Err(Error::Validation(format!(
                    "mask {mask} share does not match its commitment"
                ))));
            }
            let t_recomputed = compute_t_m(&a, &s1, &s2);
            if poly_vec_ne(&t_recomputed, &st.t_by_mask[&mask]) {
                return self.deliver(Err(Error::Validation(format!(
                    "mask {mask} t_M inconsistent with its share"
                ))));
            }
            let mut s1h = s1;
            let mut s2h = s2;
            for p in s1h.iter_mut() {
                p.ntt();
            }
            for p in s2h.iter_mut() {
                p.ntt();
            }
            shares.insert(mask, Share44 { s1, s2, s1h, s2h });
        }

        // Public key + tr.
        let mut pk_bytes = Vec::with_capacity(32 + K * 320);
        pk_bytes.extend_from_slice(&rho);
        for t1i in &t1 {
            pk_bytes.extend_from_slice(&pack_t1(t1i));
        }
        let pk = match MlDsa44PublicKey::from_bytes(&pk_bytes) {
            Ok(p) => p,
            Err(e) => {
                return self.deliver(Err(Error::Validation(format!("pk assembly failed: {e:?}"))));
            }
        };
        let mut tr = [0u8; 64];
        shake256(&pk_bytes, &mut tr);

        *self.pk.lock().unwrap() = Some(pk);
        let key = Key44 {
            id: self.id,
            rho,
            tr,
            t1,
            shares,
        };
        drop(st);
        if let Err(e) = key.validate() {
            return self.deliver(Err(e));
        }
        self.deliver(Ok(key));
    }

    fn committee_slot(&self, p: &PartyId) -> usize {
        self.params
            .parties()
            .iter()
            .position(|q| q.cmp_key(p) == std::cmp::Ordering::Equal)
            .expect("sender in committee")
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

// --- wire types ------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Dkg1 {
    #[serde(rename = "contrib")]
    contrib: B64Bytes,
}

#[derive(Serialize, Deserialize)]
struct MaskT {
    #[serde(rename = "mask")]
    mask: u8,
    #[serde(rename = "t")]
    t: B64Bytes,
    #[serde(rename = "commit")]
    commit: B64Bytes,
}

#[derive(Serialize, Deserialize)]
struct Dkg2Bcast {
    #[serde(rename = "entries")]
    entries: Vec<MaskT>,
}

#[derive(Serialize, Deserialize)]
struct MaskShare {
    #[serde(rename = "mask")]
    mask: u8,
    #[serde(rename = "s1")]
    s1: B64Bytes,
    #[serde(rename = "s2")]
    s2: B64Bytes,
}

#[derive(Serialize, Deserialize)]
struct Dkg2Share {
    #[serde(rename = "entries")]
    entries: Vec<MaskShare>,
}

// --- helpers ---------------------------------------------------------------

/// `t_M = InvNTT(A · NTT(s1)) + s2` (the per-mask public contribution).
fn compute_t_m(a: &[Poly], s1: &[Poly; L], s2: &[Poly; K]) -> [Poly; K] {
    let mut s1h = *s1;
    for p in s1h.iter_mut() {
        p.ntt();
    }
    let mut out = [Poly::zero(); K];
    for (i, oi) in out.iter_mut().enumerate() {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&hazmat::ntt_mul(&a[i * L + j], &s1h[j]));
        }
        acc.inv_ntt();
        *oi = acc.add(&s2[i]);
    }
    out
}

/// SHAKE256(domain ‖ mask ‖ pack(s1) ‖ pack(s2)) → 32 bytes.
fn commit_share(mask: u8, s1: &[Poly; L], s2: &[Poly; K]) -> [u8; 32] {
    let mut input = COMMIT_DOMAIN.to_vec();
    input.push(mask);
    for p in s1.iter() {
        let mut b = [0u8; PACK_POLYQ_SIZE];
        pack_polyq(p, &mut b);
        input.extend_from_slice(&b);
    }
    for p in s2.iter() {
        let mut b = [0u8; PACK_POLYQ_SIZE];
        pack_polyq(p, &mut b);
        input.extend_from_slice(&b);
    }
    let mut out = [0u8; 32];
    shake256(&input, &mut out);
    out
}

/// Packs a poly vector with `pack_polyq` (one 736-byte block per poly).
fn pack_vec(v: &[Poly]) -> Vec<u8> {
    let mut out = vec![0u8; v.len() * PACK_POLYQ_SIZE];
    for (i, p) in v.iter().enumerate() {
        pack_polyq(p, &mut out[i * PACK_POLYQ_SIZE..(i + 1) * PACK_POLYQ_SIZE]);
    }
    out
}

fn unpack_vec_k(b: &[u8]) -> Option<[Poly; K]> {
    if b.len() != K * PACK_POLYQ_SIZE {
        return None;
    }
    let mut out = [Poly::zero(); K];
    for (i, oi) in out.iter_mut().enumerate() {
        *oi = unpack_polyq(&b[i * PACK_POLYQ_SIZE..(i + 1) * PACK_POLYQ_SIZE]);
    }
    Some(out)
}

fn unpack_vec_l(b: &[u8]) -> Option<[Poly; L]> {
    if b.len() != L * PACK_POLYQ_SIZE {
        return None;
    }
    let mut out = [Poly::zero(); L];
    for (i, oi) in out.iter_mut().enumerate() {
        *oi = unpack_polyq(&b[i * PACK_POLYQ_SIZE..(i + 1) * PACK_POLYQ_SIZE]);
    }
    Some(out)
}

fn poly_vec_ne(a: &[Poly; K], b: &[Poly; K]) -> bool {
    a.iter().zip(b.iter()).any(|(x, y)| x.c != y.c)
}

#[cfg(test)]
mod tests {
    use super::super::params::get_threshold_params44;
    use super::super::sign44;
    use super::*;
    use crate::tss::testhub::TestHub;

    fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (0..n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![(i + 1) as u8]))
                .collect(),
            0,
        )
    }

    fn run_dkg(t: usize, n: usize) -> (MlDsa44PublicKey, Vec<Key44>) {
        let th = get_threshold_params44(t, n).unwrap();
        let ids = party_ids(n);
        let hub = TestHub::new(&ids);
        let parties: Vec<DkgParty44> = (0..n)
            .map(|i| {
                let params = Parameters::new(ids.to_vec(), &ids[i], t, hub.broker(i));
                DkgParty44::new(params, th).unwrap()
            })
            .collect();
        let keys: Vec<Key44> = parties.iter().map(|p| p.wait().expect("dkg ok")).collect();
        let pk = parties[0].public_key().unwrap();
        (pk, keys)
    }

    #[test]
    fn dkg_2_of_3_keys_consistent() {
        let (pk, keys) = run_dkg(2, 3);
        assert_eq!(keys.len(), 3);
        // Every party agrees on rho / t1 / tr (same public key).
        for k in &keys {
            assert_eq!(k.rho, keys[0].rho);
            assert_eq!(k.tr, keys[0].tr);
            for i in 0..K {
                assert_eq!(k.t1[i].c, keys[0].t1[i].c);
            }
        }
        // tr must equal SHAKE256(pk bytes).
        let mut tr = [0u8; 64];
        shake256(pk.to_bytes(), &mut tr);
        assert_eq!(tr, keys[0].tr);
    }

    #[test]
    fn dkg_then_sign_verifies() {
        let (pk, keys) = run_dkg(2, 3);
        let th = get_threshold_params44(2, 3).unwrap();
        let signers: Vec<&Key44> = vec![&keys[0], &keys[1]];
        let msg = b"dealerless dkg then sign";
        let mut rng = OsRng;
        let sig = sign44(&signers, &th, msg, b"", &mut rng).expect("sign");
        assert!(
            pk.verify(&sig, msg, b""),
            "DKG key must produce verifying signatures"
        );
    }

    #[test]
    fn dkg_3_of_5_signs() {
        let (pk, keys) = run_dkg(3, 5);
        let th = get_threshold_params44(3, 5).unwrap();
        let signers: Vec<&Key44> = vec![&keys[0], &keys[2], &keys[4]];
        let msg = b"3 of 5 dkg";
        let mut rng = OsRng;
        let sig = sign44(&signers, &th, msg, b"", &mut rng).unwrap();
        assert!(pk.verify(&sig, msg, b""));
    }
}
