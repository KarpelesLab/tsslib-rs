//! Dealerless distributed key generation for threshold ML-DSA-44.
//!
//! **Experimental.** Threshold ML-DSA has no DKG in the paper or its
//! reference implementation (both use a trusted dealer); this is an original "distribute the
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
//! Rounds: (1) broadcast a `rho` contribution and a fresh ephemeral X25519
//! public key → joint `rho = H(all)`; (2a) deal owned masks and broadcast only
//! a hash commitment to the `t_M` payload; (2b) once every commitment is in,
//! reveal it (broadcast `t_M`+share commit, unicast shares); (3) verify each
//! held mask against its commitment/bound, assemble this party's [`Key44`],
//! and confirm every party derived the same public key.
//!
//! The unicast shares are secret, so each is sealed (X25519 + HKDF-SHA256 +
//! ChaCha20-Poly1305) to the recipient's round-1 ephemeral key, with the
//! associated data binding `rho`, dealer, recipient, mask and both ephemeral
//! keys; a transport observer learns nothing about `(s1_M, s2_M)`. The
//! ephemeral keys are per-run and wiped once the shares are opened.
//!
//! The commit-then-reveal on `t_M` matters: `t = Σ_M t_M` is a plain sum, so a
//! dealer who saw the honest `t_M` first could pick its own as `t* − Σ t_honest`
//! for a key `t*` it knows entirely (a rogue-key attack; any mask held only by
//! corrupt parties is never checked by an honest one).
//!
//! None of the broadcasts is a reliable broadcast, and each party checks a
//! `t_M` only for masks it holds, so a dealer owning several masks could
//! reveal different `t_M` to different parties with equal sums: everyone
//! would derive the same public key, yet some honest `t`-subsets could never
//! sign. The round-3 confirmation therefore hashes the whole public
//! transcript — every round-1 contribution and ephemeral key, every round-2
//! commitment, and every mask's `(t_M, commitment)` in canonical order — plus
//! the public key, and aborts unless every party reports the same digest.

use super::Error;
use super::key::{Key44, PolyVec, Share44, expand_matrix, wipe_polys, zero_polys};
use super::keygen::gosper_masks;
use super::packing::{PACK_POLYQ_SIZE, pack_polyq, unpack_polyq};
use super::params::ThresholdParams44;
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::share_aead as aead;
use crate::sync::{Mutex, Receiver as MpscReceiver, Sender as MpscSender, channel};
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{Message, Parameters, PartyId, decode, encode};
use crate::vecmap::VecMap;
use alloc::sync::Arc;
use purecrypto::hash::shake256;
use purecrypto::mldsa::MlDsa44PublicKey;
use purecrypto::mldsa::hazmat::{self, ML_DSA_44, N, Poly, pack_t1, power2_round};
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const L: usize = 4;
const K: usize = 4;

// v2 (`dkg2`): round 1 carries an ephemeral X25519 key and round-2 shares are
// sealed; the bumped types make old and new peers fail cleanly.
const TYPE_R1: &str = "mldsa44:dkg2:round1";
const TYPE_R2C: &str = "mldsa44:dkg2:r2commit";
const TYPE_R2BC: &str = "mldsa44:dkg2:r2bc";
const TYPE_R2SH: &str = "mldsa44:dkg2:r2sh";
const TYPE_R3: &str = "mldsa44:dkg2:r3confirm";
const RHO_DOMAIN: &[u8] = b"mldsatss-dkg-rho-v1";
const COMMIT_DOMAIN: &[u8] = b"mldsatss-dkg-commit-v1";
const T_COMMIT_DOMAIN: &[u8] = b"mldsatss-dkg-tcommit-v1";
const CONFIRM_DOMAIN: &[u8] = b"mldsatss-dkg-confirm-v2";
const SHARE_AD_DOMAIN: &[u8] = b"mldsatss-dkg-share-v2";
/// A packed `(s1_M, s2_M)` share: `L + K` polynomials.
const SHARE_PLAINTEXT_LEN: usize = (L + K) * PACK_POLYQ_SIZE;

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

/// One mask's plaintext `(s1_M, s2_M)` during the DKG; wiped on drop.
#[derive(Clone)]
struct SecretShare {
    s1: PolyVec<L>,
    s2: PolyVec<K>,
}

impl Drop for SecretShare {
    fn drop(&mut self) {
        wipe_polys(&mut self.s1[..]);
        wipe_polys(&mut self.s2[..]);
    }
}

struct State {
    own_contrib: [u8; 32],
    contribs: Vec<Option<[u8; 32]>>, // by committee slot (= id)
    /// This run's ephemeral X25519 private key (opens the shares sent to us).
    eph_priv: Zeroizing<[u8; 32]>,
    /// Every party's round-1 ephemeral X25519 public key, by committee slot.
    eph_pubs: Vec<Option<[u8; 32]>>,
    dealt: VecMap<u8, SecretShare>,
    received: VecMap<u8, SecretShare>,
    t_by_mask: VecMap<u8, PolyVec<K>>,
    commit_by_mask: VecMap<u8, [u8; 32]>,
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
        th.validate()?;
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
        SystemRng.fill_bytes(&mut own_contrib);
        let (mut priv_raw, eph_pub) = aead::new_ephemeral_key(&mut SystemRng);
        let eph_priv = Zeroizing::new(priv_raw);
        priv_raw.zeroize();
        let mut eph_pubs = vec![None; n];
        eph_pubs[id as usize] = Some(eph_pub);

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
                eph_priv,
                eph_pubs,
                dealt: VecMap::new(),
                received: VecMap::new(),
                t_by_mask: VecMap::new(),
                commit_by_mask: VecMap::new(),
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

    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> DkgResult {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation("dkg dropped without result".into())),
        }
    }

    /// The group public key, available after [`wait`](DkgParty44::wait) succeeds.
    pub fn public_key(&self) -> Option<MlDsa44PublicKey> {
        self.shared.pk.lock().clone()
    }
}

impl Shared {
    fn deliver(&self, r: DkgResult) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let (contrib, eph) = {
            let mut st = self.state.lock();
            st.contribs[self.id as usize] = Some(st.own_contrib);
            (
                st.own_contrib,
                st.eph_pubs[self.id as usize].expect("own key"),
            )
        };
        self.broadcast(
            TYPE_R1,
            &Dkg1 {
                contrib: B64Bytes(contrib.to_vec()),
                eph: B64Bytes(eph.to_vec()),
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

    fn on_r1(self: &Arc<Self>, others: &[PartyId], msgs: Vec<Message>) {
        let r1s: Vec<Dkg1> = match msgs.iter().map(|m| Ok(decode(m)?)).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        let rho = {
            let mut st = self.state.lock();
            for (pid, r1) in others.iter().zip(r1s.iter()) {
                let slot = self.committee_slot(pid);
                if r1.contrib.0.len() != 32 {
                    return self.deliver(Err(Error::Validation("bad rho contribution".into())));
                }
                let Ok(eph) = <[u8; 32]>::try_from(r1.eph.0.as_slice()) else {
                    return self.deliver(Err(Error::Validation("bad ephemeral key".into())));
                };
                let mut c = [0u8; 32];
                c.copy_from_slice(&r1.contrib.0);
                st.contribs[slot] = Some(c);
                st.eph_pubs[slot] = Some(eph);
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
            SystemRng.fill_bytes(&mut sseed);
            let mut sh = SecretShare {
                s1: zero_polys::<L>(),
                s2: zero_polys::<K>(),
            };
            for (j, p) in sh.s1.iter_mut().enumerate() {
                *p = hazmat::sample_bounded_poly(&sseed, eta, j as u16);
            }
            for (j, p) in sh.s2.iter_mut().enumerate() {
                *p = hazmat::sample_bounded_poly(&sseed, eta, (j + L) as u16);
            }
            // The seed alone reproduces the whole share; wipe it as soon as
            // sampling is done (best-effort).
            sseed.zeroize();
            let t_m = compute_t_m(&a, &sh.s1, &sh.s2);
            let commit = commit_share(mask, &sh.s1, &sh.s2);
            let t_packed = pack_vec(t_m.as_slice());
            {
                let mut st = self.state.lock();
                st.dealt.insert(mask, sh);
                st.t_by_mask.insert(mask, t_m);
                st.commit_by_mask.insert(mask, commit);
            }
            bcast_entries.push(MaskT {
                mask,
                t: B64Bytes(t_packed),
                commit: B64Bytes(commit.to_vec()),
            });
        }
        let t_commit = commit_reveal(rho, self.id, &bcast_entries);
        {
            let mut st = self.state.lock();
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

    fn on_r2commit(self: &Arc<Self>, others: &[PartyId], msgs: Vec<Message>) {
        let cs: Vec<Dkg2Commit> = match msgs.iter().map(|m| Ok(decode(m)?)).collect() {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock();
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
        let entries = core::mem::take(&mut self.state.lock().own_reveal);
        self.broadcast(TYPE_R2BC, &Dkg2Bcast { entries })?;

        // Unicast shares to co-holders, grouped by recipient, each sealed to
        // the recipient's round-1 ephemeral key.
        for pj in others {
            let rid = self.committee_slot(pj) as u8;
            let mut entries = Vec::new();
            for &mask in &self.masks_deal {
                if (mask >> rid) & 1 == 1 {
                    let entry = {
                        let st = self.state.lock();
                        let sh = &st.dealt[&mask];
                        let my_pub = st.eph_pubs[self.id as usize].expect("own key");
                        let their_pub = st.eph_pubs[rid as usize]
                            .ok_or_else(|| Error::Validation("missing ephemeral key".into()))?;
                        let ad = share_ad(&st.rho, self.id, rid, mask, &my_pub, &their_pub);
                        let pt = pack_share(sh);
                        let ct =
                            aead::seal_share(&mut SystemRng, &st.eph_priv, &their_pub, &ad, &pt)
                                .map_err(|e| {
                                    Error::Validation(format!(
                                        "sealing share for party {rid} failed: {e}"
                                    ))
                                })?;
                        MaskShare {
                            mask,
                            ct: B64Bytes(ct),
                        }
                    };
                    entries.push(entry);
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
                    .any(|p| p.cmp_key(&pid) == core::cmp::Ordering::Equal)
                {
                    share_senders.push(pid);
                }
            }
        }

        let expects = 1 + if share_senders.is_empty() { 0 } else { 1 };
        self.state.lock().pending = expects;

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

    fn on_r2bcast(self: &Arc<Self>, msgs: Vec<Message>) {
        let bcs: Vec<(PartyId, Dkg2Bcast)> = match msgs
            .iter()
            .map(|m| Ok((m.from.clone().unwrap(), decode(m)?)))
            .collect()
        {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock();
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

    fn on_r2share(self: &Arc<Self>, msgs: Vec<Message>) {
        let shares: Vec<(PartyId, Dkg2Share)> = match msgs
            .iter()
            .map(|m| Ok((m.from.clone().unwrap(), decode(m)?)))
            .collect()
        {
            Ok(v) => v,
            Err(e) => return self.deliver(Err::<Key44, Error>(e)),
        };
        {
            let mut st = self.state.lock();
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
                    let (Some(their_pub), Some(my_pub)) =
                        (st.eph_pubs[dealer as usize], st.eph_pubs[self.id as usize])
                    else {
                        return self
                            .deliver(Err(Error::Validation("missing ephemeral key".into())));
                    };
                    let ad = share_ad(&st.rho, dealer, self.id, e.mask, &their_pub, &my_pub);
                    let pt = match aead::open_share(&st.eph_priv, &their_pub, &ad, &e.ct.0) {
                        Ok(pt) => pt,
                        Err(err) => {
                            return self.deliver(Err(Error::Validation(format!(
                                "party {dealer} sent an undecryptable share for mask {}: {err}",
                                e.mask
                            ))));
                        }
                    };
                    let Some(sh) = unpack_share(&pt) else {
                        return self.deliver(Err(Error::Validation(format!(
                            "party {dealer} sent a malformed share for mask {}",
                            e.mask
                        ))));
                    };
                    st.received.insert(e.mask, sh);
                }
            }
        }
        self.maybe_finalize();
    }

    fn maybe_finalize(self: &Arc<Self>) {
        let ready = {
            let mut st = self.state.lock();
            st.pending = st.pending.saturating_sub(1);
            st.pending == 0
        };
        if ready {
            self.finalize();
        }
    }

    fn finalize(self: &Arc<Self>) {
        let mut st = self.state.lock();
        // Move the plaintext shares out of the session: `SecretShare` wipes on
        // drop, so every return below (error or success) clears them. The
        // ephemeral key has opened every share it ever will; wipe it too.
        let dealt = core::mem::take(&mut st.dealt);
        let received = core::mem::take(&mut st.received);
        st.eph_priv.zeroize();
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
        let mut t = zero_polys::<K>();
        for &m in &all_masks {
            let t_m = &st.t_by_mask[&m];
            for i in 0..K {
                t[i] = t[i].add(&t_m[i]);
            }
        }
        let mut t1 = zero_polys::<K>();
        for (i, t1i) in t1.iter_mut().enumerate() {
            for j in 0..N {
                let (hi, _) = power2_round(t[i].c[j]);
                t1i.c[j] = hi;
            }
        }

        // Assemble + verify this party's held shares.
        let mut shares: alloc::collections::BTreeMap<u8, Share44> =
            alloc::collections::BTreeMap::new();
        for &mask in &self.masks_hold {
            let mut sh = if let Some(v) = dealt.get(&mask) {
                v.clone()
            } else if let Some(v) = received.get(&mask) {
                v.clone()
            } else {
                return self.deliver(Err(Error::Validation(format!(
                    "missing held share for mask {mask}"
                ))));
            };
            // Bound check: |coeff| ≤ η.
            for p in sh.s1.iter().chain(sh.s2.iter()) {
                if p.c.iter().any(|&c| hazmat::inf_norm(c) > eta) {
                    return self.deliver(Err(Error::Validation(format!(
                        "mask {mask} share exceeds η bound"
                    ))));
                }
            }
            // Commitment + t_M consistency (catches a cheating dealer).
            if commit_share(mask, &sh.s1, &sh.s2) != st.commit_by_mask[&mask] {
                return self.deliver(Err(Error::Validation(format!(
                    "mask {mask} share does not match its commitment"
                ))));
            }
            let t_recomputed = compute_t_m(&a, &sh.s1, &sh.s2);
            if poly_vec_ne(&t_recomputed, &st.t_by_mask[&mask]) {
                return self.deliver(Err(Error::Validation(format!(
                    "mask {mask} t_M inconsistent with its share"
                ))));
            }
            // Move the polynomials into a `Share44` (which wipes on drop),
            // leaving zeros behind in `sh`.
            let mut share = Share44 {
                s1: core::mem::replace(&mut sh.s1, zero_polys::<L>()),
                s2: core::mem::replace(&mut sh.s2, zero_polys::<K>()),
                s1h: zero_polys::<L>(),
                s2h: zero_polys::<K>(),
            };
            share.s1h.copy_from_slice(&share.s1[..]);
            share.s2h.copy_from_slice(&share.s2[..]);
            for p in share.s1h.iter_mut().chain(share.s2h.iter_mut()) {
                p.ntt();
            }
            shares.insert(mask, share);
        }

        // Public key + tr.
        let mut pk_bytes = Vec::with_capacity(32 + K * 320);
        pk_bytes.extend_from_slice(&rho);
        for t1i in t1.iter() {
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
        // Round-3 digest over the whole public transcript as this party saw it.
        let digest = transcript_digest(&st, &all_masks, &pk_bytes);
        // The plaintext shares now live in `key` (which wipes itself on drop);
        // the session's copies are wiped as `dealt` / `received` drop.
        drop(st);
        drop(dealt);
        drop(received);
        if let Err(e) = key.validate() {
            return self.deliver(Err(e));
        }

        // Round 3: all parties must have seen the same transcript. None of
        // the broadcasts is a reliable broadcast, so a dealer could reveal
        // different (separately committed) `t_M` to different parties —
        // with equal sums the public key alone would still agree.
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
                    match decode::<Dkg3Confirm>(m) {
                        Ok(c) if c.digest.0 == digest => {}
                        Ok(_) => {
                            return me.deliver(Err(Error::Validation(format!(
                                "party {} saw a different DKG transcript",
                                me.committee_slot(pid)
                            ))));
                        }
                        Err(e) => return me.deliver(Err(e.into())),
                    }
                }
                *me.pk.lock() = Some(pk);
                me.deliver(Ok(key));
            }),
        );
        self.params.broker().connect(TYPE_R3, Arc::new(exp));
    }

    fn committee_slot(&self, p: &PartyId) -> usize {
        self.params
            .parties()
            .iter()
            .position(|q| q.cmp_key(p) == core::cmp::Ordering::Equal)
            .expect("sender in committee")
    }

    fn broadcast<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        let msg = encode(
            self.params.wire_format(),
            typ,
            body,
            Some(self.params.party_id().clone()),
            None,
        )?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }

    fn send_to<T: Serialize>(&self, typ: &str, body: &T, to: &PartyId) -> Result<(), Error> {
        let msg = encode(
            self.params.wire_format(),
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
    /// This run's ephemeral X25519 public key (32 bytes).
    #[serde(rename = "eph")]
    eph: B64Bytes,
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
    /// `pack(s1) ‖ pack(s2)` sealed with `share_aead::seal_share` under
    /// [`share_ad`].
    #[serde(rename = "ct")]
    ct: B64Bytes,
}

#[derive(Serialize, Deserialize)]
struct Dkg2Share {
    #[serde(rename = "entries")]
    entries: Vec<MaskShare>,
}

// --- helpers ---------------------------------------------------------------

/// `t_M = InvNTT(A · NTT(s1)) + s2` (the per-mask public contribution).
fn compute_t_m(a: &[Poly], s1: &[Poly; L], s2: &[Poly; K]) -> PolyVec<K> {
    let mut s1h = zero_polys::<L>();
    s1h.copy_from_slice(s1);
    for p in s1h.iter_mut() {
        p.ntt();
    }
    let mut out = zero_polys::<K>();
    for (i, oi) in out.iter_mut().enumerate() {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&hazmat::ntt_mul(&a[i * L + j], &s1h[j]));
        }
        acc.inv_ntt();
        *oi = acc.add(&s2[i]);
    }
    // The NTT-domain copy of the secret is scratch; wipe it.
    wipe_polys(&mut s1h[..]);
    out
}

/// SHAKE256(domain ‖ mask ‖ pack(s1) ‖ pack(s2)) → 32 bytes.
fn commit_share(mask: u8, s1: &[Poly; L], s2: &[Poly; K]) -> [u8; 32] {
    // The hash input holds the packed secret; it is wiped on drop.
    let mut input = Zeroizing::new(Vec::with_capacity(
        COMMIT_DOMAIN.len() + 1 + SHARE_PLAINTEXT_LEN,
    ));
    input.extend_from_slice(COMMIT_DOMAIN);
    input.push(mask);
    for p in s1.iter().chain(s2.iter()) {
        let off = input.len();
        input.resize(off + PACK_POLYQ_SIZE, 0);
        pack_polyq(p, &mut input[off..]);
    }
    let mut out = [0u8; 32];
    shake256(&input, &mut out);
    out
}

/// The round-3 confirmation digest: SHAKE256 over the full public transcript
/// in canonical order — `domain ‖ n ‖ Σ_slot (contrib ‖ eph ‖ t_commit) ‖
/// #masks ‖ Σ_mask (mask ‖ pack(t_M) ‖ share commit) ‖ pk`, each optional
/// field prefixed by a presence byte. Two honest parties agree on it only if
/// they saw identical round-1 contributions, round-2 commitments and every
/// mask's `(t_M, commitment)` reveal.
fn transcript_digest(st: &State, all_masks: &[u8], pk_bytes: &[u8]) -> [u8; 32] {
    fn put(input: &mut Vec<u8>, v: Option<&[u8]>) {
        match v {
            Some(b) => {
                input.push(1);
                input.extend_from_slice(&(b.len() as u32).to_le_bytes());
                input.extend_from_slice(b);
            }
            None => input.push(0),
        }
    }
    let mut input = CONFIRM_DOMAIN.to_vec();
    input.push(st.contribs.len() as u8);
    for slot in 0..st.contribs.len() {
        put(&mut input, st.contribs[slot].as_ref().map(|b| &b[..]));
        put(&mut input, st.eph_pubs[slot].as_ref().map(|b| &b[..]));
        put(&mut input, st.t_commits[slot].as_ref().map(|b| &b[..]));
    }
    input.push(all_masks.len() as u8);
    for &m in all_masks {
        input.push(m);
        put(
            &mut input,
            st.t_by_mask
                .get(&m)
                .map(|t| pack_vec(t.as_slice()))
                .as_deref(),
        );
        put(&mut input, st.commit_by_mask.get(&m).map(|c| &c[..]));
    }
    put(&mut input, Some(pk_bytes));
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

/// Associated data for one sealed share (fixed width):
/// `domain ‖ rho ‖ dealer ‖ recipient ‖ mask ‖ dealer_eph ‖ recipient_eph`.
/// Binds the ciphertext to this session and to exactly one (dealer,
/// recipient, mask) slot, so it cannot be replayed or redirected.
fn share_ad(
    rho: &[u8; 32],
    dealer: u8,
    recipient: u8,
    mask: u8,
    dealer_eph: &[u8; 32],
    recipient_eph: &[u8; 32],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(SHARE_AD_DOMAIN.len() + 32 + 3 + 64);
    ad.extend_from_slice(SHARE_AD_DOMAIN);
    ad.extend_from_slice(rho);
    ad.push(dealer);
    ad.push(recipient);
    ad.push(mask);
    ad.extend_from_slice(dealer_eph);
    ad.extend_from_slice(recipient_eph);
    ad
}

/// `pack(s1) ‖ pack(s2)`, wiped on drop.
fn pack_share(sh: &SecretShare) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; SHARE_PLAINTEXT_LEN]);
    for (i, p) in sh.s1.iter().chain(sh.s2.iter()).enumerate() {
        pack_polyq(p, &mut out[i * PACK_POLYQ_SIZE..(i + 1) * PACK_POLYQ_SIZE]);
    }
    out
}

/// Inverse of [`pack_share`]; `None` on a bad length or non-canonical field.
fn unpack_share(b: &[u8]) -> Option<SecretShare> {
    if b.len() != SHARE_PLAINTEXT_LEN {
        return None;
    }
    let (b1, b2) = b.split_at(L * PACK_POLYQ_SIZE);
    // `SecretShare` wipes on drop, so a half-decoded share is cleared too.
    let mut sh = SecretShare {
        s1: zero_polys::<L>(),
        s2: zero_polys::<K>(),
    };
    if !unpack_into(b1, &mut sh.s1[..]) || !unpack_into(b2, &mut sh.s2[..]) {
        return None;
    }
    Some(sh)
}

/// Packs a poly vector with `pack_polyq` (one 736-byte block per poly).
fn pack_vec(v: &[Poly]) -> Vec<u8> {
    let mut out = vec![0u8; v.len() * PACK_POLYQ_SIZE];
    for (i, p) in v.iter().enumerate() {
        pack_polyq(p, &mut out[i * PACK_POLYQ_SIZE..(i + 1) * PACK_POLYQ_SIZE]);
    }
    out
}

/// Unpacks `out.len()` polys from `b` (exactly that many 736-byte blocks),
/// rejecting non-canonical coefficients. Returns `false` on any mismatch.
fn unpack_into(b: &[u8], out: &mut [Poly]) -> bool {
    if b.len() != out.len() * PACK_POLYQ_SIZE {
        return false;
    }
    for (oi, chunk) in out.iter_mut().zip(b.as_chunks::<PACK_POLYQ_SIZE>().0) {
        *oi = unpack_polyq(chunk);
        // 23-bit fields can hold values ≥ q; `Poly` arithmetic requires < q.
        if oi.c.iter().any(|&c| c >= hazmat::Q) {
            return false;
        }
    }
    true
}

fn unpack_vec_k(b: &[u8]) -> Option<PolyVec<K>> {
    let mut out = zero_polys::<K>();
    unpack_into(b, &mut out[..]).then_some(out)
}

fn poly_vec_ne(a: &[Poly; K], b: &[Poly; K]) -> bool {
    a.iter().zip(b.iter()).any(|(x, y)| x.c != y.c)
}

#[cfg(test)]
mod tests {
    use super::super::params::get_threshold_params44;
    use super::super::sign44;
    use super::*;
    use crate::tss::WireFormat;
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
        out: Mutex<Vec<Message>>,
        handlers: Mutex<VecMap<String, Arc<dyn crate::tss::MessageReceiver + Send + Sync>>>,
        pending: Mutex<Vec<Message>>,
    }

    impl crate::tss::MessageReceiver for Tap {
        fn receive(&self, m: &Message) -> crate::tss::BrokerResult {
            if m.from.as_ref().map(|p| &p.key) == Some(&self.me) {
                self.out.lock().push(m.clone());
                return Ok(());
            }
            let h = self.handlers.lock().get(&m.typ).cloned();
            match h {
                Some(h) => h.receive(m),
                None => {
                    self.pending.lock().push(m.clone());
                    Ok(())
                }
            }
        }
    }

    impl crate::tss::MessageBroker for Tap {
        fn connect(&self, typ: &str, dest: Arc<dyn crate::tss::MessageReceiver + Send + Sync>) {
            self.handlers.lock().insert(typ.into(), dest.clone());
            let queued: Vec<Message> = {
                let mut p = self.pending.lock();
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
        let sent = |typ: &str| tap.out.lock().iter().any(|m| m.typ == typ);
        fn inject<T: Serialize>(tap: &Tap, evil: &PartyId, typ: &str, body: &T) {
            let m = encode(WireFormat::default(), typ, body, Some(evil.clone()), None).unwrap();
            crate::tss::MessageReceiver::receive(tap, &m).unwrap();
        }
        let b64 = |b: &[u8]| B64Bytes(b.to_vec());

        inject(
            &tap,
            &evil,
            TYPE_R1,
            &Dkg1 {
                contrib: b64(&[0x42; 32]),
                eph: b64(&aead::new_ephemeral_key(&mut SystemRng).1),
            },
        );
        // The honest party has committed, but revealed nothing to react to.
        assert!(sent(TYPE_R2C));
        assert!(
            !sent(TYPE_R2BC),
            "t_M revealed before the adversary committed"
        );

        // The adversary must commit blind; the honest reveal follows.
        inject(
            &tap,
            &evil,
            TYPE_R2C,
            &Dkg2Commit {
                commit: b64(&[0x13; 32]),
            },
        );
        assert!(sent(TYPE_R2BC));

        // Now it picks its t_M — which cannot match the blind commitment.
        let t_evil = pack_vec(&[Poly::zero(); K]);
        inject(
            &tap,
            &evil,
            TYPE_R2BC,
            &Dkg2Bcast {
                entries: vec![MaskT {
                    mask: 2,
                    t: b64(&t_evil),
                    commit: b64(&[0; 32]),
                }],
            },
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

    /// Outbound rewriting hook: `(sender index, message)` → the messages to
    /// hand to the sender's hub broker instead. A returned message whose
    /// `from` is another party is delivered to the sender itself (a forgery
    /// "from" that party, as a network adversary controlling it could send).
    type Hook = Arc<dyn Fn(usize, &Message) -> Vec<Message> + Send + Sync>;

    /// Wraps one party's hub broker and lets a test rewrite what it sends.
    struct Intercept {
        me: usize,
        inner: Arc<dyn crate::tss::MessageBroker + Send + Sync>,
        hook: Hook,
    }

    impl crate::tss::MessageReceiver for Intercept {
        fn receive(&self, m: &Message) -> crate::tss::BrokerResult {
            for out in (self.hook)(self.me, m) {
                self.inner.receive(&out)?;
            }
            Ok(())
        }
    }

    impl crate::tss::MessageBroker for Intercept {
        fn connect(&self, typ: &str, dest: Arc<dyn crate::tss::MessageReceiver + Send + Sync>) {
            self.inner.connect(typ, dest);
        }
    }

    /// Runs a DKG where every party's outbound traffic passes through `hook`. Returns the
    /// parties (party 0's `Shared` is published to `slot0` before any round-2
    /// traffic, for hooks that need its session state).
    fn run_dkg_with_hook(
        t: usize,
        n: usize,
        slot0: Arc<std::sync::OnceLock<Arc<Shared>>>,
        hook: Hook,
    ) -> Vec<DkgParty44> {
        let th = get_threshold_params44(t, n).unwrap();
        let ids = party_ids(n);
        let hub = TestHub::new(&ids);
        let mut parties = Vec::new();
        for i in 0..n {
            let broker: Arc<dyn crate::tss::MessageBroker + Send + Sync> = Arc::new(Intercept {
                me: i,
                inner: hub.broker(i),
                hook: hook.clone(),
            });
            let params = Parameters::new(ids.to_vec(), &ids[i], t, broker);
            let p = DkgParty44::new(params, th).unwrap();
            if i == 0 {
                slot0.set(p.shared.clone()).ok();
            }
            parties.push(p);
        }
        parties
    }

    /// Round-2 shares travel sealed: what is on the wire is a ChaCha20-Poly1305
    /// envelope, never the packed `(s1, s2)` a holder ends up with.
    #[test]
    fn dkg_shares_are_sealed_on_the_wire() {
        let seen: Arc<Mutex<Vec<Message>>> = Arc::default();
        let rec = seen.clone();
        let hook: Hook = Arc::new(move |from, m| {
            if from == 0 && m.typ == TYPE_R2SH {
                rec.lock().push(m.clone());
            }
            vec![m.clone()]
        });
        let parties = run_dkg_with_hook(2, 3, Arc::default(), hook);
        let keys: Vec<Key44> = parties.iter().map(|p| p.wait().expect("dkg ok")).collect();
        let msgs = seen.lock();
        assert!(!msgs.is_empty(), "party 0 deals shares in a 2-of-3");
        for m in msgs.iter() {
            let to = m.to.as_ref().unwrap().index as usize;
            for e in decode::<Dkg2Share>(m).unwrap().entries {
                assert_eq!(e.ct.0.len(), 12 + SHARE_PLAINTEXT_LEN + 16);
                let share = &keys[to].shares[&e.mask];
                let plain = pack_share(&SecretShare {
                    s1: share.s1.clone(),
                    s2: share.s2.clone(),
                });
                // No 736-byte block of the packed share appears verbatim.
                for block in plain.chunks(PACK_POLYQ_SIZE) {
                    assert!(!e.ct.0.windows(block.len()).any(|w| w == block));
                }
            }
        }
    }

    /// A share whose ciphertext was altered in transit is rejected.
    #[test]
    fn dkg_rejects_tampered_share_ciphertext() {
        let hook: Hook = Arc::new(move |from, m| {
            if !(from == 0 && m.typ == TYPE_R2SH) {
                return vec![m.clone()];
            }
            let mut body: Dkg2Share = decode(m).unwrap();
            body.entries[0].ct.0[20] ^= 1;
            vec![
                encode(
                    WireFormat::default(),
                    &m.typ,
                    &body,
                    m.from.clone(),
                    m.to.clone(),
                )
                .unwrap(),
            ]
        });
        let parties = run_dkg_with_hook(2, 3, Arc::default(), hook);
        let Err(err) = parties[1].wait() else {
            panic!("tampered share accepted")
        };
        assert!(err.to_string().contains("undecryptable share"), "{err}");
    }

    /// A dealer owning several masks reveals different `t_M` to different
    /// parties, keeping the sums equal so every party derives the same public
    /// key, and checking out against each holder (each party is shown the
    /// true `t_M` only for masks it holds). It also answers every party's
    /// round-3 digest with that same digest. Some honest `t`-subsets could then never
    /// sign without it; the round-3 transcript check must abort the DKG.
    #[test]
    fn dkg_rejects_dealer_equivocating_on_t_m() {
        // 2-of-3: masks 0b011, 0b101, 0b110. Party 0 deals 3 and 5; party 1
        // holds {3, 6}, party 2 holds {5, 6}.
        let slot0: Arc<std::sync::OnceLock<Arc<Shared>>> = Arc::default();
        let s0 = slot0.clone();
        let ids = party_ids(3);
        let hook: Hook = Arc::new(move |from, m| {
            let fmt = WireFormat::default();
            let me = ids[0].clone();
            if from != 0 {
                if m.typ == TYPE_R3 {
                    // Party 0 "confirms" with the sender's own digest.
                    let body: Dkg3Confirm = decode(m).unwrap();
                    let echo = encode(fmt, TYPE_R3, &body, Some(me), m.from.clone()).unwrap();
                    return vec![m.clone(), echo];
                }
                return vec![m.clone()];
            }
            match m.typ.as_str() {
                // Withheld: replaced by per-recipient commitments below.
                TYPE_R2C | TYPE_R3 => vec![],
                TYPE_R2BC => {
                    let rho = s0.get().unwrap().state.lock().rho;
                    let honest: Dkg2Bcast = decode(m).unwrap();
                    let mut out = Vec::new();
                    // Party 1 gets a shifted t_5, party 2 a shifted t_3.
                    for (rid, shifted) in [(1usize, 5u8), (2, 3)] {
                        let entries: Vec<MaskT> = honest
                            .entries
                            .iter()
                            .map(|e| {
                                let mut t = e.t.0.clone();
                                if e.mask == shifted {
                                    let mut v = unpack_vec_k(&t).unwrap();
                                    v[0].c[0] = (v[0].c[0] + 1) % hazmat::Q;
                                    t = pack_vec(v.as_slice());
                                }
                                MaskT {
                                    mask: e.mask,
                                    t: B64Bytes(t),
                                    commit: B64Bytes(e.commit.0.clone()),
                                }
                            })
                            .collect();
                        let commit = Dkg2Commit {
                            commit: B64Bytes(commit_reveal(&rho, 0, &entries).to_vec()),
                        };
                        let to = Some(ids[rid].clone());
                        out.push(
                            encode(fmt, TYPE_R2C, &commit, Some(me.clone()), to.clone()).unwrap(),
                        );
                        let bc = Dkg2Bcast { entries };
                        out.push(encode(fmt, TYPE_R2BC, &bc, Some(me.clone()), to).unwrap());
                    }
                    out
                }
                _ => vec![m.clone()],
            }
        });
        let parties = run_dkg_with_hook(2, 3, slot0, hook);
        for p in &parties[1..] {
            let Err(err) = p.wait() else {
                panic!("equivocating dealer went undetected")
            };
            assert!(err.to_string().contains("transcript"), "{err}");
        }
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
        let mut rng = SystemRng;
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
        let mut rng = SystemRng;
        let sig = sign44(&signers, &th, msg, b"", &mut rng).unwrap();
        assert!(pk.verify(&sig, msg, b""));
    }
}
