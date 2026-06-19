//! Broker-driven threshold ML-DSA-44 signing.
//!
//! The distributed counterpart to the synchronous [`sign44`](super::sign44):
//! the 3-round commit / reveal / respond protocol of ePrint 2025/1166 over a
//! [`MessageBroker`]. Round 1 broadcasts a hash commitment to this party's `k`
//! parallel `w` vectors; round 2 reveals the packed `w`s (each verified against
//! its commitment); round 3 broadcasts the packed responses; combine aggregates
//! and emits a FIPS-204-verifiable signature. The per-phase lattice work is the
//! shared [`sample_w`]/[`compute_response`]/[`combine_try`] from
//! [`signing`](super::signing). Wire-compatible with Go `mldsatss`: round
//! message types are `mldsa44:sign:round{1,2,3}#<attempt_id>`, where
//! `attempt_id` (a u32, 0 by default; see [`SigningParty44::new_with_attempt_id`])
//! mirrors Go's `Parameters.SetAttemptID` and is also bound into the round-1
//! commitment.
//!
//! Each session is a single attempt: if every one of the `k` tries is rejected,
//! [`SigningParty44::wait`] returns an error and the caller retries with fresh
//! randomness (a new session).

use super::Error;
use super::hyperball::FVec;
use super::key::Key44;
use super::packing::{PACK_POLYQ_SIZE, pack_polyq, unpack_polyq};
use super::params::ThresholdParams44;
use super::signing::{K, L, combine_try, compute_mu, compute_response, sample_w};
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, Parameters, PartyId, json_get, json_wrap};
use purecrypto::hash::shake256;
use purecrypto::mldsa::hazmat::{ML_DSA_44, Poly, inf_norm, unpack_z};
use purecrypto::rng::{OsRng, RngCore};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "mldsa44:sign:round1";
const TYPE_R2: &str = "mldsa44:sign:round2";
const TYPE_R3: &str = "mldsa44:sign:round3";

/// The session result: FIPS 204 signature bytes, or an error.
type SignResult = Result<Vec<u8>, Error>;

/// A running threshold ML-DSA-44 signing session. Construct with
/// [`SigningParty44::new`]; retrieve the FIPS 204 signature bytes with
/// [`SigningParty44::wait`].
pub struct SigningParty44 {
    result_rx: MpscReceiver<SignResult>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    key: Key44,
    key_ids: Vec<u8>, // Key44.id of params.parties()[slot]
    attempt_id: u32,
    // Per-session message types: `TYPE_R{1,2,3}#<attempt_id>`, matching Go's
    // `Parameters.msgType` (`fmt.Sprintf("%s#%d", base, attemptID)`).
    type_r1: String,
    type_r2: String,
    type_r3: String,
    act: u8,
    my_rank: usize,
    mu: [u8; 64],
    a: Vec<Poly>,
    kk: usize,
    th: ThresholdParams44,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<SignResult>>>,
}

struct State {
    stws: Vec<FVec>, // k hyperball samples (one per try)
    wbuf: Vec<u8>,   // own packed w's
    r1commits: Vec<Option<Vec<u8>>>,
    r2wbufs: Vec<Option<Vec<u8>>>,
    r3resps: Vec<Option<Vec<u8>>>,
}

impl Drop for State {
    /// Best-effort wipe of the per-try hyperball masks (the secret nonces `y`)
    /// when the session ends — completed, failed, or abandoned before round 3.
    fn drop(&mut self) {
        for fv in self.stws.iter_mut() {
            fv.zeroize();
        }
    }
}

impl SigningParty44 {
    /// Starts a signing session for this party. `key_ids[i]` must be the
    /// `Key44.id` of the committee member at `params.parties()[i]`; the
    /// committee is the `t`-party signing set (sorted), and this party's own id
    /// (`key.id`) must match its slot. `ctx` is ≤ 255 bytes.
    pub fn new(
        params: Parameters,
        th: ThresholdParams44,
        key: Key44,
        key_ids: Vec<u8>,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<SigningParty44, Error> {
        Self::new_with_attempt_id(params, th, key, key_ids, msg, ctx, 0)
    }

    /// Like [`SigningParty44::new`] but with an explicit `attempt_id`, matching
    /// Go's `Parameters.SetAttemptID`. The id is appended to every round's
    /// message type (`mldsa44:sign:roundN#<attempt_id>`) and bound into the
    /// round-1 commitment, so several signing sessions can share one broker
    /// without message-type collisions. `new` (attempt_id 0) is wire-identical
    /// to a Go session that never calls `SetAttemptID`.
    pub fn new_with_attempt_id(
        params: Parameters,
        th: ThresholdParams44,
        key: Key44,
        key_ids: Vec<u8>,
        msg: &[u8],
        ctx: &[u8],
        attempt_id: u32,
    ) -> Result<SigningParty44, Error> {
        key.validate()?;
        if ctx.len() > 255 {
            return Err(Error::Validation("context longer than 255 bytes".into()));
        }
        if params.parties().len() != th.t as usize {
            return Err(Error::Validation(format!(
                "committee must have t={} members",
                th.t
            )));
        }
        if key_ids.len() != params.parties().len() {
            return Err(Error::Validation("key_ids length mismatch".into()));
        }
        // Go `NewParameters` requires key_ids strictly increasing, so they align
        // with the ascending-sorted committee (parties().IDs()). Reject otherwise.
        if key_ids.windows(2).any(|w| w[1] <= w[0]) {
            return Err(Error::Validation(
                "key_ids must be strictly increasing (aligned with the sorted committee)".into(),
            ));
        }
        let my_rank = params.party_index();
        if key_ids[my_rank] != key.id {
            return Err(Error::Validation(
                "key.id does not match this party's committee slot".into(),
            ));
        }
        let mut act = 0u8;
        for &kid in &key_ids {
            act |= 1 << kid;
        }

        let mu = compute_mu(&key.tr, ctx, msg);
        let a = key.matrix();
        let kk = th.k as usize;
        let t = params.parties().len();

        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            key,
            key_ids,
            attempt_id,
            type_r1: format!("{TYPE_R1}#{attempt_id}"),
            type_r2: format!("{TYPE_R2}#{attempt_id}"),
            type_r3: format!("{TYPE_R3}#{attempt_id}"),
            act,
            my_rank,
            mu,
            a,
            kk,
            th,
            state: Mutex::new(State {
                stws: Vec::new(),
                wbuf: Vec::new(),
                r1commits: vec![None; t],
                r2wbufs: vec![None; t],
                r3resps: vec![None; t],
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(SigningParty44 {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until signing completes, returning the FIPS 204 signature bytes or
    /// an error (including "all tries rejected", on which the caller retries).
    pub fn wait(&self) -> SignResult {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "signing session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: SignResult) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let mut rhop = [0u8; 64];
        rng.fill_bytes(&mut rhop);

        let mut stws = Vec::with_capacity(self.kk);
        let mut wbuf = vec![0u8; self.kk * K * PACK_POLYQ_SIZE];
        let mut off = 0;
        for tri in 0..self.kk {
            let (fv, wi) = sample_w(&self.a, self.th.rp, self.th.nu, &rhop, tri as u16);
            for wij in wi.iter() {
                pack_polyq(wij, &mut wbuf[off..off + PACK_POLYQ_SIZE]);
                off += PACK_POLYQ_SIZE;
            }
            stws.push(fv);
        }
        // The hyperball seed derives the secret masks; wipe it now that every
        // try has been sampled (best-effort, Go `defer ZeroizeBytes(rhop)`).
        rhop.zeroize();

        let commit = self.compute_commitment(self.key.id, &wbuf);
        {
            let mut st = self.state.lock().unwrap();
            st.stws = stws;
            st.wbuf = wbuf;
            st.r1commits[self.my_rank] = Some(commit.clone());
        }

        self.broadcast(
            &self.type_r1,
            &SignR1 {
                commit: B64Bytes(commit),
            },
        )?;

        let me = Arc::clone(self);
        let others = self.params.other_parties();
        let exp = JsonExpect::new(
            self.type_r1.clone(),
            others.clone(),
            Box::new(move |msgs| me.on_r1(&others, msgs)),
        );
        self.params.broker().connect(&self.type_r1, Arc::new(exp));
        Ok(())
    }

    fn on_r1(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<SignR1>, Error> = msgs.iter().map(|m| Ok(json_get(m)?)).collect();
        let r1s = match decoded {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(e)),
        };
        {
            let mut st = self.state.lock().unwrap();
            for (pid, r1) in others.iter().zip(r1s.iter()) {
                let slot = self.committee_slot(pid);
                if r1.commit.0.len() != 32 {
                    return self.deliver(Err(Error::Validation(
                        "round1 commitment size mismatch".into(),
                    )));
                }
                st.r1commits[slot] = Some(r1.commit.0.clone());
            }
        }
        self.round2(others);
    }

    fn round2(self: &Arc<Self>, others: &[PartyId]) {
        let wbuf = {
            let mut st = self.state.lock().unwrap();
            let wbuf = st.wbuf.clone();
            st.r2wbufs[self.my_rank] = Some(wbuf.clone());
            wbuf
        };
        if let Err(e) = self.broadcast(
            &self.type_r2,
            &SignR2 {
                wbuf: B64Bytes(wbuf),
            },
        ) {
            return self.deliver(Err(e));
        }
        let me = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            self.type_r2.clone(),
            others.to_vec(),
            Box::new(move |msgs| me.on_r2(&others_owned, msgs)),
        );
        self.params.broker().connect(&self.type_r2, Arc::new(exp));
    }

    fn on_r2(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<SignR2>, Error> = msgs.iter().map(|m| Ok(json_get(m)?)).collect();
        let r2s = match decoded {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(e)),
        };
        let expected_len = self.kk * K * PACK_POLYQ_SIZE;
        {
            let mut st = self.state.lock().unwrap();
            for (pid, r2) in others.iter().zip(r2s.iter()) {
                let slot = self.committee_slot(pid);
                if r2.wbuf.0.len() != expected_len {
                    return self
                        .deliver(Err(Error::Validation("round2 wbuf size mismatch".into())));
                }
                if let Err(e) = validate_canonical_wbuf(&r2.wbuf.0) {
                    return self.deliver(Err(e));
                }
                let have = self.compute_commitment(self.key_ids[slot], &r2.wbuf.0);
                if st.r1commits[slot].as_deref() != Some(have.as_slice()) {
                    return self.deliver(Err(Error::Validation(format!(
                        "round2 commitment mismatch for committee slot {slot}"
                    ))));
                }
                st.r2wbufs[slot] = Some(r2.wbuf.0.clone());
            }
        }
        self.round3(others);
    }

    fn round3(self: &Arc<Self>, others: &[PartyId]) {
        // Aggregate w per try over the whole committee.
        let wfinal = {
            let st = self.state.lock().unwrap();
            aggregate_wfinal(&st.r2wbufs, self.kk)
        };

        // Recover this party's NTT shares.
        let (mut s1h, mut s2h) = match self.key.recover_share(self.act, &self.th) {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(e)),
        };

        // Compute responses (zeros for rejected tries → caught in combine).
        let mut respbuf = vec![0u8; self.kk * L * encoding_z_size()];
        {
            let mut st = self.state.lock().unwrap();
            let mut off = 0;
            for tri in 0..self.kk {
                let z =
                    compute_response(&s1h, &s2h, &st.stws[tri], &wfinal[tri], &self.mu, &self.th);
                let zp = z.unwrap_or([Poly::zero(); L]);
                for zj in zp.iter() {
                    let packed = purecrypto::mldsa::hazmat::pack_z(zj, &ML_DSA_44.params);
                    respbuf[off..off + packed.len()].copy_from_slice(&packed);
                    off += packed.len();
                }
            }
            // The per-try hyperball masks (secret nonces y) are never needed
            // again — wipe them now (best-effort, Go zeroizes per-attempt).
            for fv in st.stws.iter_mut() {
                fv.zeroize();
            }
        }
        // Wipe the recovered secret-key material (Go zeroizeNttVec{L,K}44).
        for p in s1h.iter_mut() {
            p.c.zeroize();
        }
        for p in s2h.iter_mut() {
            p.c.zeroize();
        }
        {
            let mut st = self.state.lock().unwrap();
            st.r3resps[self.my_rank] = Some(respbuf.clone());
        }
        if let Err(e) = self.broadcast(
            &self.type_r3,
            &SignR3 {
                resp: B64Bytes(respbuf),
            },
        ) {
            return self.deliver(Err(e));
        }
        let me = Arc::clone(self);
        let others_owned = others.to_vec();
        let exp = JsonExpect::new(
            self.type_r3.clone(),
            others.to_vec(),
            Box::new(move |msgs| me.combine(&others_owned, msgs)),
        );
        self.params.broker().connect(&self.type_r3, Arc::new(exp));
    }

    fn combine(self: &Arc<Self>, others: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<SignR3>, Error> = msgs.iter().map(|m| Ok(json_get(m)?)).collect();
        let r3s = match decoded {
            Ok(v) => v,
            Err(e) => return self.deliver(Err(e)),
        };
        let expected_len = self.kk * L * encoding_z_size();
        {
            let mut st = self.state.lock().unwrap();
            for (pid, r3) in others.iter().zip(r3s.iter()) {
                let slot = self.committee_slot(pid);
                if r3.resp.0.len() != expected_len {
                    return self
                        .deliver(Err(Error::Validation("round3 resp size mismatch".into())));
                }
                st.r3resps[slot] = Some(r3.resp.0.clone());
            }
        }

        let (wfinal, zfinal) = {
            let st = self.state.lock().unwrap();
            // Per-party response validity (Go `validatePartyResponses`, FIX 2 —
            // identifiable abort). Before summing every party's z_i
            // unconditionally, range/bound-check each party's block. A
            // malicious party that submits garbage z_i (large coefficients)
            // would otherwise corrupt the aggregate and force "all tries
            // rejected" for the whole committee with no attribution (a silent
            // DoS). On failure we name the offending committee slot instead of
            // silently summing.
            if let Err(e) =
                validate_party_responses(&st.r3resps, self.kk, self.th.nu, self.th.rp, &self.key_ids)
            {
                return self.deliver(Err(e));
            }
            (
                aggregate_wfinal(&st.r2wbufs, self.kk),
                aggregate_zfinal(&st.r3resps, self.kk),
            )
        };
        let t1 = self.key.t1;
        for tri in 0..self.kk {
            if let Some(sig) = combine_try(&self.a, &t1, &self.mu, &wfinal[tri], &zfinal[tri]) {
                return self.deliver(Ok(sig));
            }
        }
        self.deliver(Err(Error::Validation(
            "all tries rejected; retry with a fresh signing session".into(),
        )));
    }

    /// SHAKE256(tr ‖ act ‖ attempt_id ‖ μ ‖ keyId ‖ wbuf) → 32 bytes.
    /// `attempt_id` is a big-endian u32 (Go `computeCommitment`), 0 by default.
    fn compute_commitment(&self, key_id: u8, wbuf: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(64 + 1 + 4 + 64 + 1 + wbuf.len());
        input.extend_from_slice(&self.key.tr);
        input.push(self.act);
        input.extend_from_slice(&self.attempt_id.to_be_bytes()); // big-endian u32
        input.extend_from_slice(&self.mu);
        input.push(key_id);
        input.extend_from_slice(wbuf);
        let mut out = vec![0u8; 32];
        shake256(&input, &mut out);
        out
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
}

// --- wire types ------------------------------------------------------------

/// Round-1 broadcast: the hash commitment to this party's `k` packed `w`s.
#[derive(Serialize, Deserialize)]
struct SignR1 {
    #[serde(rename = "commit")]
    commit: B64Bytes,
}

/// Round-2 broadcast: the revealed packed `w`s (verified against the commitment).
#[derive(Serialize, Deserialize)]
struct SignR2 {
    #[serde(rename = "wbuf")]
    wbuf: B64Bytes,
}

/// Round-3 broadcast: this party's packed responses `z_i`.
#[derive(Serialize, Deserialize)]
struct SignR3 {
    #[serde(rename = "resp")]
    resp: B64Bytes,
}

// --- aggregation + validation ----------------------------------------------

/// `wfinal[try][i] = Σ_slot unpack_polyq(wbuf_slot)` over the committee.
fn aggregate_wfinal(r2wbufs: &[Option<Vec<u8>>], kk: usize) -> Vec<[Poly; K]> {
    let mut wfinal: Vec<[Poly; K]> = (0..kk).map(|_| [Poly::zero(); K]).collect();
    for wbuf in r2wbufs.iter().flatten() {
        let mut off = 0;
        for wf in wfinal.iter_mut() {
            for wfi in wf.iter_mut() {
                let p = unpack_polyq(&wbuf[off..off + PACK_POLYQ_SIZE]);
                *wfi = wfi.add(&p);
                off += PACK_POLYQ_SIZE;
            }
        }
    }
    wfinal
}

/// `zfinal[try][j] = Σ_slot unpack_z(resp_slot)` over the committee.
fn aggregate_zfinal(r3resps: &[Option<Vec<u8>>], kk: usize) -> Vec<[Poly; L]> {
    let sz = encoding_z_size();
    let mut zfinal: Vec<[Poly; L]> = (0..kk).map(|_| [Poly::zero(); L]).collect();
    for resp in r3resps.iter().flatten() {
        let mut off = 0;
        for zf in zfinal.iter_mut() {
            for zfj in zf.iter_mut() {
                let p =
                    purecrypto::mldsa::hazmat::unpack_z(&resp[off..off + sz], &ML_DSA_44.params);
                *zfj = zfj.add(&p);
                off += sz;
            }
        }
    }
    zfinal
}

/// Checks every party's round-3 response block for per-party validity
/// *before* combine sums them, so a single malformed/malicious `z_i` is
/// attributed to its sender instead of silently corrupting the aggregate
/// (Go `validatePartyResponses`, "FIX 2 — identifiable abort").
///
/// Derivable check (strongest available from public values at combine time):
/// an honest party either rejects a try (sends an all-zero `z_i` block, which
/// passes trivially) or accepts it, in which case its `z_i` is the L-part of a
/// hyperball-masked response `zf` that passed the party's own gate
/// `!zf.excess(r, ν)`, i.e. `Σ_L (zf_L[j]/ν)² + Σ_K (zf_K[j])² ≤ r²`. The
/// L-part alone therefore satisfies `Σ_L (z_i[j]/ν)² ≤ r²`; integer rounding
/// adds at most `√(L·N)·0.5/ν ≈ 5.3` to the ν-scaled L2 norm, comfortably
/// inside the secondary radius `r′` (`r′ − r ≥ 55` across the whole parameter
/// table). So we reject any non-zero `z_i` block whose ν-scaled L2 norm
/// exceeds `r′` — an honest accepted block never does, while gross garbage
/// (the DoS vector) is caught and its sender named.
///
/// LIMITATION (partial identifiable abort): this is a structural bound, not a
/// full algebraic check. A full check would verify `HighBits(A·z_i − c·t_i) ==
/// HighBits(w_i)` against the party's committed `w_i`, but that needs each
/// party's public key share `t_i = A·s1_i + s2_i`, which this trusted-dealer
/// protocol never transmits or stores (only the aggregate `t1` is public). A
/// party can thus still submit a small but algebraically-wrong `z_i` that
/// passes this bound yet breaks the aggregate; such a case still surfaces as
/// "all tries rejected" (non-attributable).
fn validate_party_responses(
    r3resps: &[Option<Vec<u8>>],
    kk: usize,
    nu: f64,
    rp: f64,
    key_ids: &[u8],
) -> Result<(), Error> {
    let sz = encoding_z_size();
    let rp_sq = rp * rp;
    for (slot, resp) in r3resps.iter().enumerate() {
        let Some(resp) = resp else {
            return Err(Error::Validation(format!(
                "round3 response missing for committee slot {slot}"
            )));
        };
        let mut off = 0;
        for tri in 0..kk {
            let mut l2 = 0.0f64; // Σ_L (z_i[j]/ν)² for this try's block
            let mut non_zero = false;
            for _j in 0..L {
                let poly = unpack_z(&resp[off..off + sz], &ML_DSA_44.params);
                off += sz;
                for &c in poly.c.iter() {
                    // Recenter to a signed magnitude in [0, Q/2].
                    let mag = inf_norm(c) as f64;
                    if mag != 0.0 {
                        non_zero = true;
                    }
                    let scaled = mag / nu;
                    l2 += scaled * scaled;
                }
            }
            // An all-zero block is a legitimate "try rejected at party"; only
            // bound-check blocks that actually carry a response.
            if non_zero && l2 > rp_sq {
                return Err(Error::Validation(format!(
                    "invalid round-3 response from committee slot {slot} (keyId {kid}), \
                     try {tri}: z_i ν-scaled L2 norm² {l2:.0} exceeds Rp² {rp_sq:.0}",
                    kid = key_ids[slot],
                )));
            }
        }
    }
    Ok(())
}

/// Range-checks every packed coefficient of a peer wbuf is canonical (`< Q`);
/// non-canonical values would feed HighBits/Decompose out of range.
fn validate_canonical_wbuf(wbuf: &[u8]) -> Result<(), Error> {
    let mut off = 0;
    while off + PACK_POLYQ_SIZE <= wbuf.len() {
        let p = unpack_polyq(&wbuf[off..off + PACK_POLYQ_SIZE]);
        if p.c.iter().any(|&c| c >= purecrypto::mldsa::hazmat::Q) {
            return Err(Error::Validation(
                "round2 wbuf has a non-canonical coefficient (>= Q)".into(),
            ));
        }
        off += PACK_POLYQ_SIZE;
    }
    Ok(())
}

/// Packed size of one `z` polynomial (18 bits/coeff for ML-DSA-44).
fn encoding_z_size() -> usize {
    purecrypto::mldsa::hazmat::pack_z(&Poly::zero(), &ML_DSA_44.params).len()
}

#[cfg(test)]
mod tests {
    use super::super::keygen::trusted_dealer_keygen44;
    use super::super::params::get_threshold_params44;
    use super::*;
    use crate::tss::testhub::TestHub;

    fn committee_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (0..n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![(i + 1) as u8]))
                .collect(),
            0,
        )
    }

    #[test]
    fn broker_sign_2_of_3_verifies() {
        let params = get_threshold_params44(2, 3).unwrap();
        let (pk, keys) = trusted_dealer_keygen44(&[7u8; 32], &params).unwrap();
        // Signing set: parties with Key44.id 0 and 1.
        let signer_ids: Vec<u8> = vec![0, 1];
        let msg = b"broker threshold ml-dsa";
        let ctx = b"";

        // Build committee PartyIds keyed so sort order matches signer_ids order.
        let pids = committee_ids(3);
        let committee: Vec<PartyId> = signer_ids
            .iter()
            .map(|&i| pids[i as usize].clone())
            .collect();
        let committee = PartyId::sort(committee, 0);
        let key_ids: Vec<u8> = committee
            .iter()
            .map(|p| p.key[0] - 1) // recover Key44.id from the chosen key encoding
            .collect();

        // Retry whole sessions until one attempt's k tries succeed.
        let sig = loop {
            let hub = TestHub::new(&committee);
            let parties: Vec<SigningParty44> = committee
                .iter()
                .enumerate()
                .map(|(slot, _)| {
                    let kid = key_ids[slot];
                    let prm =
                        Parameters::new(committee.clone(), &committee[slot], 1, hub.broker(slot));
                    SigningParty44::new(
                        prm,
                        params,
                        keys[kid as usize].clone(),
                        key_ids.clone(),
                        msg,
                        ctx,
                    )
                    .unwrap()
                })
                .collect();
            let results: Vec<_> = parties.iter().map(|p| p.wait()).collect();
            if let Ok(s) = &results[0] {
                // All signers must agree on the signature.
                for r in &results[1..] {
                    assert_eq!(r.as_ref().unwrap(), s);
                }
                break s.clone();
            }
        };

        assert!(pk.verify(&sig, msg, ctx), "broker signature must verify");
    }

    /// Round message types must carry Go's `#<attempt_id>` suffix
    /// (`Parameters.msgType` = `fmt.Sprintf("%s#%d", base, attemptID)`). Without
    /// it a mixed Go↔Rust session mis-routes even at the default attempt 0. Pins
    /// the exact Go wire strings so the suffix can't be dropped again.
    #[test]
    fn message_types_carry_go_attempt_suffix() {
        assert_eq!(format!("{TYPE_R1}#{}", 0u32), "mldsa44:sign:round1#0");
        assert_eq!(format!("{TYPE_R2}#{}", 0u32), "mldsa44:sign:round2#0");
        assert_eq!(format!("{TYPE_R3}#{}", 0u32), "mldsa44:sign:round3#0");
        assert_eq!(format!("{TYPE_R1}#{}", 5u32), "mldsa44:sign:round1#5");
    }

    /// Go `NewParameters` rejects non-strictly-increasing key_ids; so must we.
    #[test]
    fn rejects_non_increasing_key_ids() {
        let params = get_threshold_params44(2, 3).unwrap();
        let (_pk, keys) = trusted_dealer_keygen44(&[7u8; 32], &params).unwrap();
        let pids = committee_ids(3);
        let committee = PartyId::sort(vec![pids[0].clone(), pids[1].clone()], 0);
        let hub = TestHub::new(&committee);
        let prm = Parameters::new(committee.clone(), &committee[0], 1, hub.broker(0));
        // key_ids descending → must be rejected, not silently accepted.
        let err = SigningParty44::new(prm, params, keys[0].clone(), vec![1, 0], b"m", b"");
        assert!(err.is_err(), "non-increasing key_ids must be rejected");
    }

    /// FIX 2 (identifiable abort): a garbage z_i block with grossly
    /// out-of-bound coefficients must be rejected, naming the offending
    /// committee slot, rather than silently summed into the aggregate.
    /// Packs `kk · L` copies of `poly` the way round 3 does.
    fn packed_resp_block(poly: &Poly, kk: usize) -> Vec<u8> {
        let packed = purecrypto::mldsa::hazmat::pack_z(poly, &ML_DSA_44.params);
        let mut out = Vec::with_capacity(kk * L * packed.len());
        for _ in 0..(kk * L) {
            out.extend_from_slice(&packed);
        }
        out
    }

    #[test]
    fn validate_party_responses_names_offending_slot() {
        let th = get_threshold_params44(2, 2).unwrap();
        let kk = th.k as usize;

        // Slot 0: zero polynomials — a legitimate "try rejected at party".
        let honest = packed_resp_block(&Poly::zero(), kk);

        // Slot 1: fully-saturated garbage — every coefficient = γ1, which
        // packs/unpacks cleanly but blows the ν-scaled L2 bound (matches the
        // Go TestSigning44_InvalidResponseIsAttributed payload).
        let gamma1 = ML_DSA_44.params.gamma1;
        let mut max_poly = Poly::zero();
        for c in max_poly.c.iter_mut() {
            *c = gamma1;
        }
        let garbage = packed_resp_block(&max_poly, kk);

        let r3resps = vec![Some(honest), Some(garbage)];
        let key_ids = vec![0u8, 1u8];
        let err = validate_party_responses(&r3resps, kk, th.nu, th.rp, &key_ids)
            .expect_err("garbage z_i must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("committee slot 1"),
            "error must name the offending slot: {msg}"
        );
        assert!(
            msg.contains("keyId 1"),
            "error must name the offending keyId: {msg}"
        );
    }

    /// All-zero response blocks ("try rejected at party") must pass.
    #[test]
    fn validate_party_responses_accepts_zero_blocks() {
        let th = get_threshold_params44(2, 3).unwrap();
        let kk = th.k as usize;
        let block = packed_resp_block(&Poly::zero(), kk);
        let r3resps = vec![Some(block.clone()), Some(block)];
        validate_party_responses(&r3resps, kk, th.nu, th.rp, &[0, 1])
            .expect("all-zero blocks are legitimate");
    }
}
