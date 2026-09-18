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
//! Rounds: (1) broadcast a `rho` contribution → joint `rho = H(all)`; (2a) deal
//! owned masks and broadcast only a hash commitment to the `t_M` payload; (2b)
//! once every commitment is in, reveal it (broadcast `t_M`+share commit, unicast
//! shares); (3) verify each held mask against its commitment/bound, assemble
//! this party's [`Key44`], and confirm every party derived the same public key.
//!
//! The commit-then-reveal on `t_M` matters: `t = Σ_M t_M` is a plain sum, so a
//! dealer who saw the honest `t_M` first could pick its own as `t* − Σ t_honest`
//! for a key `t*` it knows entirely (a rogue-key attack; any mask held only by
//! corrupt parties is never checked by an honest one). The round-3 confirmation
//! catches a dealer that reveals different `t_M` to different parties.

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
const TYPE_R2C: &str = "mldsa44:dkg:r2commit";
const TYPE_R2BC: &str = "mldsa44:dkg:r2bc";
const TYPE_R2SH: &str = "mldsa44:dkg:r2sh";
const TYPE_R3: &str = "mldsa44:dkg:r3confirm";
const RHO_DOMAIN: &[u8] = b"mldsatss-dkg-rho-v1";
const COMMIT_DOMAIN: &[u8] = b"mldsatss-dkg-commit-v1";
const T_COMMIT_DOMAIN: &[u8] = b"mldsatss-dkg-tcommit-v1";
const CONFIRM_DOMAIN: &[u8] = b"mldsatss-dkg-confirm-v1";

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
    /// Joint `rho`, fixed at the end of round 1.
    rho: [u8; 32],
    /// This party's round-2 reveal, held back until every commitment is in.
    own_reveal: Vec<MaskT>,
    /// Each party's commitment to its round-2 reveal, by committee slot.
    t_commits: Vec<Option<[u8; 32]>>,
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
                rho: [0u8; 32],
                own_reveal: Vec::new(),
                t_commits: vec![None; n],
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
    /// Non-blocking peek at the ceremony result: `Some(_)` once the result (or
    /// error) is ready, `None` while rounds are still pending. Unlike [`wait`](Self::wait)
    /// it never blocks, so a single-threaded async driver (e.g. wasm/browser) can
    /// poll it after feeding each inbound message.
    pub fn try_result(&self) -> Option<DkgResult> {
        self.result_rx.try_recv().ok()
    }

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
            st.rho = rho;
            rho
        };

        if let Err(e) = self.round2_commit(&rho, others) {
            self.deliver(Err(e));
        }
    }

    /// Round 2a: deal the owned masks, but broadcast only a commitment to the
    /// `t_M` payload.
    fn round2_commit(self: &Arc<Self>, rho: &[u8; 32], others: &[PartyId]) -> Result<(), Error> {
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
        let t_commit = commit_reveal(rho, self.id, &bcast_entries);
        {
            let mut st = self.state.lock().unwrap();
            st.own_reveal = bcast_entries;
            st.t_commits[self.id as usize] = Some(t_commit);
        }
        self.broadcast(
            TYPE_R2C,
            &Dkg2Commit {
                commit: B64Bytes(t_commit.to_vec()),
            },
        )?;
        let me = Arc::clone(self);
        let from = others.to_vec();
        let exp = JsonExpect::new(
            TYPE_R2C,
            others.to_vec(),
            Box::new(move |msgs| me.on_r2commit(&from, msgs)),
        );
        self.params.broker().connect(TYPE_R2C, Arc::new(exp));
        Ok(())
    }

    fn on_r2commit(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let cs: Vec<Dkg2Commit> = match msgs.iter().map(|m| Ok(json_get(m)?)).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock().unwrap();
            for (pid, c) in others.iter().zip(cs.iter()) {
                let Ok(commit) = <[u8; 32]>::try_from(c.commit.0.as_slice()) else {
                    return self.deliver(Err(Error::Validation("bad t_M commitment".into())));
                };
                st.t_commits[self.committee_slot(pid)] = Some(commit);
            }
        }
        if let Err(e) = self.round2_reveal(others) {
            self.deliver(Err(e));
        }
    }

    /// Round 2b: every commitment is in — reveal `t_M` and hand out the shares.
    fn round2_reveal(self: &Arc<Self>, others: &[PartyId]) -> Result<(), Error> {
        let entries = std::mem::take(&mut self.state.lock().unwrap().own_reveal);
        self.broadcast(TYPE_R2BC, &Dkg2Bcast { entries })?;

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
                // The reveal must be what this party committed to in round 2a.
                let rho = st.rho;
                if Some(commit_reveal(&rho, dealer, &bc.entries)) != st.t_commits[dealer as usize] {
                    return self.deliver(Err(Error::Validation(format!(
                        "party {dealer} revealed t_M that does not match its commitment"
                    ))));
                }
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
                    if st.t_by_mask.insert(e.mask, t_m).is_some() {
                        return self.deliver(Err(Error::Validation(format!(
                            "party {dealer} dealt mask {} twice",
                            e.mask
                        ))));
                    }
                    st.commit_by_mask.insert(e.mask, c);
                }
            }
        }
        self.maybe_finalize();
    }

    fn on_r2share(self: &Arc<Self>, msgs: Vec<JsonMessage>) {
        let shares: Vec<(PartyId, Dkg2Share)> = match msgs
            .iter()
            .map(|m| Ok((m.from.clone().unwrap(), json_get(m)?)))
            .collect()
        {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock().unwrap();
            for (from, sh) in &shares {
                let dealer = self.committee_slot(from) as u8;
                for e in &sh.entries {
                    // Only the rightful dealer may supply a mask's share, and
                    // only for a mask we hold — otherwise any share sender
                    // could overwrite an honest dealer's entry and get it
                    // blamed for the commitment mismatch.
                    if e.mask.trailing_zeros() as u8 != dealer
                        || !self.masks_hold.contains(&e.mask)
                        || st.received.contains_key(&e.mask)
                    {
                        return self.deliver(Err(Error::Validation(format!(
                            "party {dealer} sent an unexpected share for mask {}",
                            e.mask
                        ))));
                    }
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
        let mut st = self.state.lock().unwrap();
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

        let key = Key44 {
            id: self.id,
            rho,
            tr,
            t1,
            shares,
        };
        // The plaintext shares now live in `key` (which wipes itself on drop);
        // clear the session's copies.
        {
            let st = &mut *st;
            for (s1, s2) in st.dealt.values_mut().chain(st.received.values_mut()) {
                for p in s1.iter_mut().chain(s2.iter_mut()) {
                    zeroize::Zeroize::zeroize(&mut p.c);
                }
            }
            st.dealt.clear();
            st.received.clear();
        }
        drop(st);
        if let Err(e) = key.validate() {
            return self.deliver(Err(e));
        }

        // Round 3: all parties must have derived the same public key. The
        // round-2 broadcasts are not reliable broadcasts, so a dealer could
        // have revealed a different (committed) `t_M` to different parties.
        let mut input = CONFIRM_DOMAIN.to_vec();
        input.extend_from_slice(&pk_bytes);
        let mut digest = [0u8; 32];
        shake256(&input, &mut digest);
        if let Err(e) = self.broadcast(
            TYPE_R3,
            &Dkg3Confirm {
                digest: B64Bytes(digest.to_vec()),
            },
        ) {
            return self.deliver(Err(e));
        }
        let me = Arc::clone(self);
        let others = self.params.other_parties();
        let from = others.clone();
        let exp = JsonExpect::new(
            TYPE_R3,
            others,
            Box::new(move |msgs| {
                for (pid, m) in from.iter().zip(msgs.iter()) {
                    match json_get::<Dkg3Confirm>(m) {
                        Ok(c) if c.digest.0 == digest => {}
                        Ok(_) => {
                            return me.deliver(Err(Error::Validation(format!(
                                "party {} derived a different public key",
                                me.committee_slot(pid)
                            ))));
                        }
                        Err(e) => return me.deliver(Err(e.into())),
                    }
                }
                *me.pk.lock().unwrap() = Some(pk);
                me.deliver(Ok(key));
            }),
        );
        self.params.broker().connect(TYPE_R3, Arc::new(exp));
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
struct Dkg2Commit {
    #[serde(rename = "commit")]
    commit: B64Bytes,
}

#[derive(Serialize, Deserialize)]
struct Dkg3Confirm {
    #[serde(rename = "digest")]
    digest: B64Bytes,
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

/// Commitment to a party's whole round-2 reveal, bound to the session (`rho`)
/// and the dealer: SHAKE256(domain ‖ rho ‖ dealer ‖ count ‖ Σ (mask ‖ |t| ‖ t ‖
/// |commit| ‖ commit)) → 32 bytes.
fn commit_reveal(rho: &[u8; 32], dealer: u8, entries: &[MaskT]) -> [u8; 32] {
    let mut input = T_COMMIT_DOMAIN.to_vec();
    input.extend_from_slice(rho);
    input.push(dealer);
    input.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        input.push(e.mask);
        for field in [&e.t.0, &e.commit.0] {
            input.extend_from_slice(&(field.len() as u32).to_le_bytes());
            input.extend_from_slice(field);
        }
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
        // 23-bit fields can hold values ≥ q; `Poly` arithmetic requires < q.
        if oi.c.iter().any(|&c| c >= hazmat::Q) {
            return None;
        }
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
        // 23-bit fields can hold values ≥ q; `Poly` arithmetic requires < q.
        if oi.c.iter().any(|&c| c >= hazmat::Q) {
            return None;
        }
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

    /// Broker for one honest party facing a scripted adversary: records what
    /// the party sends, dispatches what the test injects.
    #[derive(Default)]
    struct Tap {
        me: Vec<u8>,
        out: Mutex<Vec<JsonMessage>>,
        handlers: Mutex<HashMap<String, Arc<dyn crate::tss::MessageReceiver + Send + Sync>>>,
        pending: Mutex<Vec<JsonMessage>>,
    }

    impl crate::tss::MessageReceiver for Tap {
        fn receive(&self, m: &JsonMessage) -> crate::tss::BrokerResult {
            if m.from.as_ref().map(|p| &p.key) == Some(&self.me) {
                self.out.lock().unwrap().push(m.clone());
                return Ok(());
            }
            let h = self.handlers.lock().unwrap().get(&m.typ).cloned();
            match h {
                Some(h) => h.receive(m),
                None => {
                    self.pending.lock().unwrap().push(m.clone());
                    Ok(())
                }
            }
        }
    }

    impl crate::tss::MessageBroker for Tap {
        fn connect(&self, typ: &str, dest: Arc<dyn crate::tss::MessageReceiver + Send + Sync>) {
            self.handlers
                .lock()
                .unwrap()
                .insert(typ.into(), dest.clone());
            let queued: Vec<JsonMessage> = {
                let mut p = self.pending.lock().unwrap();
                let (mine, rest) = p.drain(..).partition(|m| m.typ == typ);
                *p = rest;
                mine
            };
            for m in queued {
                let _ = dest.receive(&m);
            }
        }
    }

    /// The rogue-key attack: in a 2-of-2 DKG the second party waits for the
    /// honest `t_M` and answers with `t* − t_honest`, making the group key a
    /// key `t*` it holds alone. The commit round must deny it that view, and
    /// bind it to whatever it committed to blind.
    #[test]
    fn rushing_dealer_cannot_choose_t_after_seeing_honest_t() {
        let th = get_threshold_params44(2, 2).unwrap();
        let ids = party_ids(2);
        let (honest, evil) = (ids[0].clone(), ids[1].clone());
        let tap = Arc::new(Tap {
            me: honest.key.clone(),
            ..Default::default()
        });
        let party =
            DkgParty44::new(Parameters::new(ids.clone(), &honest, 2, tap.clone()), th).unwrap();
        let sent = |typ: &str| tap.out.lock().unwrap().iter().any(|m| m.typ == typ);
        let inject = |typ: &str, body: serde_json::Value| {
            let m = json_wrap(typ, &body, Some(evil.clone()), None).unwrap();
            crate::tss::MessageReceiver::receive(&*tap, &m).unwrap();
        };
        let b64 = |b: &[u8]| serde_json::to_value(B64Bytes(b.to_vec())).unwrap();

        inject(TYPE_R1, serde_json::json!({ "contrib": b64(&[0x42; 32]) }));
        // The honest party has committed, but revealed nothing to react to.
        assert!(sent(TYPE_R2C));
        assert!(
            !sent(TYPE_R2BC),
            "t_M revealed before the adversary committed"
        );

        // The adversary must commit blind; the honest reveal follows.
        inject(TYPE_R2C, serde_json::json!({ "commit": b64(&[0x13; 32]) }));
        assert!(sent(TYPE_R2BC));

        // Now it picks its t_M — which cannot match the blind commitment.
        let t_evil = pack_vec(&[Poly::zero(); K]);
        inject(
            TYPE_R2BC,
            serde_json::json!({ "entries": [{ "mask": 2, "t": b64(&t_evil), "commit": b64(&[0; 32]) }] }),
        );
        let err = party
            .try_result()
            .expect("finished")
            .err()
            .expect("rejected");
        assert!(
            err.to_string().contains("does not match its commitment"),
            "{err}"
        );
        assert!(party.public_key().is_none());
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
