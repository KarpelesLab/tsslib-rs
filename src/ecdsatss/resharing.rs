//! GG18 key resharing over a `MessageBroker` (5 rounds, old + new committees).
//!
//! Port of Go `ecdsatss/resharing.go`. The old committee re-splits its secret to
//! a fresh `new_threshold`-of-`new_party_count` committee while preserving
//! `ECDSAPub`; the new committee generates fresh pre-parameters. A party may be
//! in both committees.
//!
//! Old-committee members' input key may still carry the full keygen party set:
//! [`ResharingParty::new`] transparently narrows it to the old committee via
//! [`Key::subset_for_parties`].
//!
//! Rounds: (old) round1 broadcasts `ECDSAPub` + a commitment to the re-sharing
//! VSS; (new) round2 broadcasts fresh Paillier/ring-Pedersen params with DLN +
//! mod proofs; (old) round3 unicasts each new party its Shamir share and opens
//! the VSS commitment; (new) round4 verifies everything, rebuilds the public key,
//! and sends no-small-factor proofs; (new) round5 verifies those and assembles
//! the new [`Key`]. Old-only parties retire their share.

#![allow(dead_code)]

use super::dlnproof::{self, DlnProof};
use super::facproof::{self, ProofFac};
use super::key::{EcPointJson, Key, PaillierPkJson, PaillierSkJson};
use super::modproof::{self, ProofMod};
use super::paillier::PublicKey;
use super::prepare::LocalPreParams;
use super::secp::{self, ProjectivePoint, Scalar};
use super::vss;
use super::{Error, bn};
use crate::frost::hashing::sha512_256i;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::BigUintDec;
use crate::tss::expect::JsonExpect;
use crate::tss::{JsonMessage, PartyId, ReSharingParameters, json_get, json_wrap};
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel};
use std::sync::{Arc, Mutex};

const TYPE_R1: &str = "ecdsa:resharing:round1";
const TYPE_R2_1: &str = "ecdsa:resharing:round2-1";
const TYPE_R2_2: &str = "ecdsa:resharing:round2-2";
const TYPE_R3_1: &str = "ecdsa:resharing:round3-1";
const TYPE_R3_2: &str = "ecdsa:resharing:round3-2";
const TYPE_R4_1: &str = "ecdsa:resharing:round4-1";
const TYPE_R4_2: &str = "ecdsa:resharing:round4-2";

/// A running GG18 resharing session.
pub struct ResharingParty {
    result_rx: MpscReceiver<Result<Key, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: ReSharingParameters,
    input: Key,
    pre: Option<LocalPreParams>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<Key, Error>>>>,
}

struct State {
    ssid: Vec<u8>,
    ecdsa_pub: Option<ProjectivePoint>,

    // old-committee side
    vd: Vec<BoxedUint>,
    new_shares: Vec<Scalar>, // aligned to new_parties

    // new-committee side: per new-party-index public material
    paillier_pks: Vec<Option<PublicKey>>,
    ntildej: Vec<Option<BoxedUint>>,
    h1j: Vec<Option<BoxedUint>>,
    h2j: Vec<Option<BoxedUint>>,

    // collected messages
    r1msgs: Vec<R1Msg>,
    r1_from: Vec<PartyId>,
    r2msg1: Vec<R2Msg1>,
    r2msg1_from: Vec<PartyId>,
    r3msg1: Vec<R3Msg1>,
    r3msg1_from: Vec<PartyId>,
    r3msg2: Vec<R3Msg2>,
    r3msg2_from: Vec<PartyId>,
    r4_join: u8,

    r4msg1: Vec<R4Msg1>,
    r4msg1_from: Vec<PartyId>,
    r5_join: u8,

    // results
    new_xi: BoxedUint,
    new_ks: Vec<BoxedUint>,
    new_big_xjs: Vec<ProjectivePoint>,
}

impl ResharingParty {
    /// Starts resharing. New-committee members must supply `pre` (their fresh
    /// pre-parameters); old-only members may pass `None`.
    pub fn new(
        params: ReSharingParameters,
        input: Key,
        pre: Option<LocalPreParams>,
    ) -> Result<ResharingParty, Error> {
        let (tx, rx) = channel();
        let nc = params.new_party_count();
        // Old-committee members reindex their input to the old committee so the
        // per-party lookups in SSID/w_i use old-committee indices rather than
        // keygen-party indices (mirrors Go round1Old's SubsetForParties). The
        // full keygen key may thus be passed as-is. New-only members never index
        // the input's per-party slices (they take ECDSAPub from round-1
        // messages), so their input is left untouched.
        let input = if params.is_old_committee() {
            input.subset_for_parties(params.old_parties())?
        } else {
            input
        };
        let shared = Arc::new(Shared {
            params,
            input,
            pre,
            state: Mutex::new(State {
                ssid: Vec::new(),
                ecdsa_pub: None,
                vd: Vec::new(),
                new_shares: Vec::new(),
                paillier_pks: vec_none(nc),
                ntildej: vec_none(nc),
                h1j: vec_none(nc),
                h2j: vec_none(nc),
                r1msgs: Vec::new(),
                r1_from: Vec::new(),
                r2msg1: Vec::new(),
                r2msg1_from: Vec::new(),
                r3msg1: Vec::new(),
                r3msg1_from: Vec::new(),
                r3msg2: Vec::new(),
                r3msg2_from: Vec::new(),
                r4_join: 0,
                r4msg1: Vec::new(),
                r4msg1_from: Vec::new(),
                r5_join: 0,
                new_xi: bn::u64(0),
                new_ks: Vec::new(),
                new_big_xjs: Vec::new(),
            }),
            result_tx: Mutex::new(Some(tx)),
        });
        if shared.params.is_old_committee() {
            shared.round1_old()?;
        }
        if shared.params.is_new_committee() {
            shared.round1_new();
        }
        Ok(ResharingParty {
            result_rx: rx,
            _shared: shared,
        })
    }

    /// Blocks until resharing completes, returning the new key (new committee) or
    /// the retired input key (old-only committee).
    pub fn wait(&self) -> Result<Key, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "resharing session dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<Key, Error>) {
        if let Some(tx) = self.result_tx.lock().unwrap().take() {
            let _ = tx.send(r);
        }
    }

    fn fail(&self, msg: impl Into<String>) {
        self.deliver(Err(Error::Validation(msg.into())));
    }

    // --- old committee ---

    fn round1_old(self: &Arc<Self>) -> Result<(), Error> {
        let mut rng = OsRng;
        let ssid = self.compute_ssid();
        let new_t = self.params.new_threshold();

        // w_i = Lagrange-weighted share over the OLD committee.
        let wi = self.prepare_wi()?;

        let new_ids = self.params.new_parties().to_vec();
        let new_ks: Vec<Scalar> = new_ids
            .iter()
            .map(|p| secp::scalar_from_be(&p.key))
            .collect();
        let (vi, shares) = vss::create(new_t, &wi, &new_ks, &mut rng);
        let flat = flatten_points(&vi);
        let (vc, vd) = super::commit::commit(&flat, &mut rng);

        let pub_pt = self
            .input
            .ecdsa_pub_point()
            .ok_or_else(|| Error::Validation("resharing: input ECDSAPub off curve".into()))?;
        let (px, py) = secp::coords(&pub_pt);

        {
            let mut st = self.state.lock().unwrap();
            st.ssid = ssid.clone();
            st.vd = vd;
            st.new_shares = shares.iter().map(|s| s.value.clone()).collect();
            st.ecdsa_pub = Some(pub_pt);
        }

        let r1 = R1Msg {
            ecdsa_pub_x: B64Bytes(bn::to_be(&px)),
            ecdsa_pub_y: B64Bytes(bn::to_be(&py)),
            v_commitment: B64Bytes(bn::to_be(&vc)),
            ssid: B64Bytes(ssid),
        };
        for pj in &new_ids {
            self.send_to(TYPE_R1, &r1, pj)?;
        }
        self.connect(TYPE_R2_2, &new_ids, {
            let me = Arc::clone(self);
            move |_msgs| me.round3_old()
        });
        Ok(())
    }

    fn round3_old(self: &Arc<Self>) {
        let new_ids = self.params.new_parties().to_vec();
        let (new_shares, vd) = {
            let st = self.state.lock().unwrap();
            (st.new_shares.clone(), st.vd.clone())
        };
        for (j, pj) in new_ids.iter().enumerate() {
            let r3m1 = R3Msg1 {
                share: B64Bytes(secp::scalar_to_be(&new_shares[j])),
            };
            if let Err(e) = self.send_to(TYPE_R3_1, &r3m1, pj) {
                return self.deliver(Err(e));
            }
        }
        let r3m2 = R3Msg2 {
            v_decommitment: parts_b64(&vd.iter().map(bn::to_be).collect::<Vec<_>>()),
        };
        for pj in &new_ids {
            if let Err(e) = self.send_to(TYPE_R3_2, &r3m2, pj) {
                return self.deliver(Err(e));
            }
        }
        self.connect(TYPE_R4_2, &new_ids, {
            let me = Arc::clone(self);
            move |_msgs| {
                // Old-only members retire their share here; hybrids deliver the
                // new key from round5_new instead.
                if !me.params.is_new_committee() {
                    let mut retired = me.input.clone();
                    retired.xi = BigUintDec::from_be_bytes(&[]);
                    me.deliver(Ok(retired));
                }
            }
        });
    }

    // --- new committee ---

    fn round1_new(self: &Arc<Self>) {
        let old_ids = self.params.old_parties().to_vec();
        self.connect(TYPE_R1, &old_ids, {
            let me = Arc::clone(self);
            let old_ids = old_ids.clone();
            move |msgs| me.on_r1_new(&old_ids, msgs)
        });
    }

    fn on_r1_new(self: &Arc<Self>, old_ids: &[PartyId], msgs: Vec<JsonMessage>) {
        let mut rng = OsRng;
        let decoded: Result<Vec<R1Msg>, _> = msgs.iter().map(json_get).collect();
        let r1msgs = match decoded {
            Ok(d) => d,
            Err(e) => return self.deliver(Err(Error::from(e))),
        };

        // SSID + ECDSAPub must agree across all old parties.
        let mut ssid: Option<Vec<u8>> = None;
        let mut ecdsa_pub: Option<ProjectivePoint> = None;
        for m in &r1msgs {
            match &ssid {
                None => ssid = Some(m.ssid.0.clone()),
                Some(s) if *s != m.ssid.0 => return self.fail("resharing: SSID mismatch"),
                _ => {}
            }
            let cand = match secp::from_coords(
                &bn::from_be(&m.ecdsa_pub_x.0),
                &bn::from_be(&m.ecdsa_pub_y.0),
            ) {
                Some(p) => p,
                None => return self.fail("resharing: ECDSAPub off curve"),
            };
            match &ecdsa_pub {
                None => ecdsa_pub = Some(cand),
                Some(p) if !secp::eq(p, &cand) => return self.fail("resharing: ECDSAPub mismatch"),
                _ => {}
            }
        }
        let ssid = ssid.unwrap();
        let i = self.new_index();
        let pre = match &self.pre {
            Some(p) => p.clone(),
            None => return self.fail("resharing: new committee member missing pre-params"),
        };

        let context_i = context_bytes(&ssid, i);
        let dln1 = dlnproof::prove(
            &pre.h1i,
            &pre.h2i,
            &pre.alpha,
            &pre.p,
            &pre.q,
            &pre.ntilde_i,
            &mut rng,
        );
        let dln2 = dlnproof::prove(
            &pre.h2i,
            &pre.h1i,
            &pre.beta,
            &pre.p,
            &pre.q,
            &pre.ntilde_i,
            &mut rng,
        );
        let mp = match modproof::prove(
            &context_i,
            &pre.paillier_sk.pk.n,
            &pre.paillier_sk.p,
            &pre.paillier_sk.q,
            &mut rng,
        ) {
            Ok(p) => p,
            Err(e) => return self.deliver(Err(e)),
        };

        {
            let mut st = self.state.lock().unwrap();
            st.ssid = ssid;
            st.ecdsa_pub = ecdsa_pub;
            st.r1msgs = r1msgs;
            st.r1_from = old_ids.to_vec();
            st.paillier_pks[i] = Some(pre.paillier_sk.pk.clone());
            st.ntildej[i] = Some(pre.ntilde_i.clone());
            st.h1j[i] = Some(pre.h1i.clone());
            st.h2j[i] = Some(pre.h2i.clone());
        }

        let r2m1 = R2Msg1 {
            paillier_n: B64Bytes(bn::to_be(&pre.paillier_sk.pk.n)),
            mod_proof: parts_b64(&mp.to_parts()),
            n_tilde: B64Bytes(bn::to_be(&pre.ntilde_i)),
            h1: B64Bytes(bn::to_be(&pre.h1i)),
            h2: B64Bytes(bn::to_be(&pre.h2i)),
            dlnproof_1: parts_b64(&dln1.to_parts()),
            dlnproof_2: parts_b64(&dln2.to_parts()),
        };
        let new_others = self.new_others();
        for pj in &new_others {
            if let Err(e) = self.send_to(TYPE_R2_1, &r2m1, pj) {
                return self.deliver(Err(e));
            }
        }
        for pj in old_ids {
            if let Err(e) = self.send_to(TYPE_R2_2, &R2Msg2 {}, pj) {
                return self.deliver(Err(e));
            }
        }

        self.connect(TYPE_R2_1, &new_others, {
            let me = Arc::clone(self);
            let new_others = new_others.clone();
            move |msgs| me.on_r2msg1_new(&new_others, msgs)
        });
        self.connect(TYPE_R3_1, old_ids, {
            let me = Arc::clone(self);
            let old_ids = old_ids.to_vec();
            move |msgs| me.on_r3msg1_new(&old_ids, msgs)
        });
        self.connect(TYPE_R3_2, old_ids, {
            let me = Arc::clone(self);
            let old_ids = old_ids.to_vec();
            move |msgs| me.on_r3msg2_new(&old_ids, msgs)
        });
    }

    fn on_r2msg1_new(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R2Msg1>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r2msg1 = d,
                Err(e) => return self.deliver(Err(Error::from(e))),
            }
            st.r2msg1_from = from.to_vec();
            st.r4_join += 1;
            st.r4_join == 3
        };
        if ready {
            self.round4_new();
        }
    }

    fn on_r3msg1_new(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R3Msg1>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r3msg1 = d,
                Err(e) => return self.deliver(Err(Error::from(e))),
            }
            st.r3msg1_from = from.to_vec();
            st.r4_join += 1;
            st.r4_join == 3
        };
        if ready {
            self.round4_new();
        }
    }

    fn on_r3msg2_new(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R3Msg2>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r3msg2 = d,
                Err(e) => return self.deliver(Err(Error::from(e))),
            }
            st.r3msg2_from = from.to_vec();
            st.r4_join += 1;
            st.r4_join == 3
        };
        if ready {
            self.round4_new();
        }
    }

    fn round4_new(self: &Arc<Self>) {
        let mut rng = OsRng;
        let new_t = self.params.new_threshold();
        let i = self.new_index();
        let new_ids = self.params.new_parties().to_vec();
        let old_ids = self.params.old_parties().to_vec();

        let (
            ssid,
            ecdsa_pub,
            r1msgs,
            r1_from,
            r2msg1,
            r2msg1_from,
            r3msg1,
            r3msg1_from,
            r3msg2,
            r3msg2_from,
        ) = {
            let st = self.state.lock().unwrap();
            (
                st.ssid.clone(),
                st.ecdsa_pub.unwrap(),
                st.r1msgs.clone(),
                st.r1_from.clone(),
                st.r2msg1.clone(),
                st.r2msg1_from.clone(),
                st.r3msg1.clone(),
                st.r3msg1_from.clone(),
                st.r3msg2.clone(),
                st.r3msg2_from.clone(),
            )
        };

        // Verify each new peer's DLN + mod proofs and record its public params.
        for (k, msg) in r2msg1.iter().enumerate() {
            let jidx = index_of(&new_ids, &r2msg1_from[k]);
            let ntj = bn::from_be(&msg.n_tilde.0);
            let h1 = bn::from_be(&msg.h1.0);
            let h2 = bn::from_be(&msg.h2.0);
            let pn = bn::from_be(&msg.paillier_n.0);
            // Mirror Go resharing (paillierModulusLen = 2048): reject short
            // peer moduli before storing/using them. A short Paillier N or
            // ring-Pedersen Ñ weakens the proofs and the encryption itself.
            if pn.bit_len() < super::prepare::MIN_PEER_MODULUS_BITS {
                return self.fail(format!(
                    "resharing: peer Paillier modulus bit length {} < {}",
                    pn.bit_len(),
                    super::prepare::MIN_PEER_MODULUS_BITS
                ));
            }
            if ntj.bit_len() < super::prepare::MIN_PEER_MODULUS_BITS {
                return self.fail(format!(
                    "resharing: peer NTilde bit length {} < {}",
                    ntj.bit_len(),
                    super::prepare::MIN_PEER_MODULUS_BITS
                ));
            }
            if bn::to_be(&h1) == bn::to_be(&h2) {
                return self.fail("resharing: H1 == H2");
            }
            let context_j = context_bytes(&ssid, jidx);
            let mp = match ProofMod::from_parts(&parts_bytes(&msg.mod_proof)) {
                Some(p) => p,
                None => return self.fail("resharing: bad mod proof"),
            };
            if !modproof::verify(&context_j, &pn, &mp, &mut rng) {
                return self.fail("resharing: mod proof failed");
            }
            let (d1, d2) = match (
                DlnProof::from_parts(&parts_bytes(&msg.dlnproof_1)),
                DlnProof::from_parts(&parts_bytes(&msg.dlnproof_2)),
            ) {
                (Some(a), Some(b)) => (a, b),
                _ => return self.fail("resharing: bad DLN proof"),
            };
            if !dlnproof::verify(&d1, &h1, &h2, &ntj) || !dlnproof::verify(&d2, &h2, &h1, &ntj) {
                return self.fail("resharing: DLN proof failed");
            }
            let mut st = self.state.lock().unwrap();
            st.ntildej[jidx] = Some(ntj);
            st.h1j[jidx] = Some(h1);
            st.h2j[jidx] = Some(h2);
            st.paillier_pks[jidx] = Some(PublicKey { n: pn });
        }

        // Verify each old party's VSS share against its committed polynomial.
        let my_id = secp::scalar_from_be(&self.params.party_id().key);
        let mut new_xi = Scalar::ZERO;
        let mut vjc: Vec<Option<Vec<ProjectivePoint>>> = (0..old_ids.len()).map(|_| None).collect();

        for (k, r3m1) in r3msg1.iter().enumerate() {
            let j_old = index_of(&old_ids, &r3msg1_from[k]);
            let r1_pos = match r1_from.iter().position(|p| p.index == r3msg1_from[k].index) {
                Some(p) => p,
                None => return self.fail("resharing: missing R1 for old party"),
            };
            let r3m2_pos = match r3msg2_from
                .iter()
                .position(|p| p.index == r3msg1_from[k].index)
            {
                Some(p) => p,
                None => return self.fail("resharing: missing R3 decommit for old party"),
            };
            let vc = bn::from_be(&r1msgs[r1_pos].v_commitment.0);
            let d = parts_bytes(&r3msg2[r3m2_pos].v_decommitment)
                .iter()
                .map(|b| bn::from_be(b))
                .collect::<Vec<_>>();
            let flat = match super::commit::decommit(&vc, &d) {
                Some(v) if v.len() == (new_t + 1) * 2 => v,
                _ => return self.fail("resharing: VSS decommitment failed"),
            };
            let vj = match unflatten_points(&flat) {
                Some(v) => v,
                None => return self.fail("resharing: VSS commitments off curve"),
            };
            let share = secp::scalar_from_be(&r3m1.share.0);
            if !vss::verify(&my_id, &share, new_t, &vj) {
                return self.fail("resharing: VSS share verification failed");
            }
            new_xi = new_xi.add(&share);
            vjc[j_old] = Some(vj);
        }

        // Vc[c] = Σ over old parties of v_j[c]; Vc[0] must equal ECDSAPub.
        let mut vc_agg: Vec<Option<ProjectivePoint>> = (0..=new_t).map(|_| None).collect();
        for vj in vjc.iter().flatten() {
            for (c, slot) in vc_agg.iter_mut().enumerate() {
                *slot = Some(match slot {
                    None => vj[c],
                    Some(acc) => acc.add(&vj[c]),
                });
            }
        }
        let vc0 = match vc_agg[0] {
            Some(p) => p,
            None => return self.fail("resharing: no old shares received"),
        };
        if !secp::eq(&vc0, &ecdsa_pub) {
            return self.fail("resharing: reconstructed public key != ECDSAPub");
        }

        // new BigXj for each new party.
        let mut new_ks = Vec::with_capacity(new_ids.len());
        let mut new_big_xjs = Vec::with_capacity(new_ids.len());
        for pj in &new_ids {
            let kj = secp::scalar_from_be(&pj.key);
            new_ks.push(secp::scalar_to_uint(&kj));
            let mut bx = vc0;
            let mut z = Scalar::ONE;
            for slot in vc_agg.iter().take(new_t + 1).skip(1) {
                z = z.mul(&kj);
                bx = bx.add(&slot.unwrap().mul(&z));
            }
            new_big_xjs.push(bx);
        }

        {
            let mut st = self.state.lock().unwrap();
            st.new_xi = secp::scalar_to_uint(&new_xi);
            st.new_ks = new_ks;
            st.new_big_xjs = new_big_xjs;
        }

        // No-small-factor proof to each other new party.
        let pre = self.pre.clone().unwrap();
        let new_others = self.new_others();
        for pj in &new_others {
            let jidx = index_of(&new_ids, pj);
            let (ntj, h1, h2) = {
                let st = self.state.lock().unwrap();
                (
                    st.ntildej[jidx].clone().unwrap(),
                    st.h1j[jidx].clone().unwrap(),
                    st.h2j[jidx].clone().unwrap(),
                )
            };
            let context_j = context_bytes(&ssid, jidx);
            let fp = facproof::prove(
                &context_j,
                &pre.paillier_sk.pk.n,
                &ntj,
                &h1,
                &h2,
                &pre.paillier_sk.p,
                &pre.paillier_sk.q,
                &mut rng,
            );
            let r4m1 = R4Msg1 {
                fac_proof: parts_b64(&fp.to_parts()),
            };
            if let Err(e) = self.send_to(TYPE_R4_1, &r4m1, pj) {
                return self.deliver(Err(e));
            }
        }
        // Round-4-2 ack to every other party (old and new).
        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        for pj in &all {
            if pj.index == self.params.party_id().index && pj.key == self.params.party_id().key {
                continue;
            }
            let _ = self.send_to(TYPE_R4_2, &R4Msg2 {}, pj);
        }

        let _ = i;
        self.connect(TYPE_R4_1, &new_others, {
            let me = Arc::clone(self);
            let new_others = new_others.clone();
            move |msgs| me.on_r4msg1_new(&new_others, msgs)
        });
        self.connect(TYPE_R4_2, &new_others, {
            let me = Arc::clone(self);
            move |_msgs| {
                let ready = {
                    let mut st = me.state.lock().unwrap();
                    st.r5_join += 1;
                    st.r5_join == 2
                };
                if ready {
                    me.round5_new();
                }
            }
        });
    }

    fn on_r4msg1_new(self: &Arc<Self>, from: &[PartyId], msgs: Vec<JsonMessage>) {
        let decoded: Result<Vec<R4Msg1>, _> = msgs.iter().map(json_get).collect();
        let ready = {
            let mut st = self.state.lock().unwrap();
            match decoded {
                Ok(d) => st.r4msg1 = d,
                Err(e) => return self.deliver(Err(Error::from(e))),
            }
            st.r4msg1_from = from.to_vec();
            st.r5_join += 1;
            st.r5_join == 2
        };
        if ready {
            self.round5_new();
        }
    }

    fn round5_new(self: &Arc<Self>) {
        let mut rng = OsRng;
        let i = self.new_index();
        let new_ids = self.params.new_parties().to_vec();
        let pre = self.pre.clone().unwrap();

        let (ssid, r4msg1, r4msg1_from, new_xi, new_ks, new_big_xjs) = {
            let st = self.state.lock().unwrap();
            (
                st.ssid.clone(),
                st.r4msg1.clone(),
                st.r4msg1_from.clone(),
                st.new_xi.clone(),
                st.new_ks.clone(),
                st.new_big_xjs.clone(),
            )
        };
        let context_i = context_bytes(&ssid, i);

        // Verify each peer's fac proof (made against MY ring-Pedersen params).
        for (k, msg) in r4msg1.iter().enumerate() {
            let jidx = index_of(&new_ids, &r4msg1_from[k]);
            let peer_n = {
                let st = self.state.lock().unwrap();
                st.paillier_pks[jidx].clone().unwrap().n
            };
            let fp = match ProofFac::from_parts(&parts_bytes(&msg.fac_proof)) {
                Some(p) => p,
                None => return self.fail("resharing: bad fac proof"),
            };
            if !facproof::verify(&context_i, &peer_n, &pre.ntilde_i, &pre.h1i, &pre.h2i, &fp) {
                return self.fail("resharing: fac proof failed");
            }
        }
        let _ = &mut rng;

        // Assemble the new save-data key.
        let st = self.state.lock().unwrap();
        let ntilde_j = st
            .ntildej
            .iter()
            .map(|o| dec(o.as_ref().unwrap()))
            .collect();
        let h1j = st.h1j.iter().map(|o| dec(o.as_ref().unwrap())).collect();
        let h2j = st.h2j.iter().map(|o| dec(o.as_ref().unwrap())).collect();
        let paillier_pks = st
            .paillier_pks
            .iter()
            .map(|o| PaillierPkJson {
                n: dec(&o.as_ref().unwrap().n),
            })
            .collect();
        let ecdsa_pub_pt = st.ecdsa_pub.unwrap();
        drop(st);

        let key = Key {
            paillier_sk: PaillierSkJson {
                n: dec(&pre.paillier_sk.pk.n),
                lambda_n: dec(&pre.paillier_sk.lambda),
                phi_n: dec(&pre.paillier_sk.phi),
                p: dec(&pre.paillier_sk.p),
                q: dec(&pre.paillier_sk.q),
            },
            ntilde_i: dec(&pre.ntilde_i),
            h1i: dec(&pre.h1i),
            h2i: dec(&pre.h2i),
            alpha: dec(&pre.alpha),
            beta: dec(&pre.beta),
            p: dec(&pre.p),
            q: dec(&pre.q),
            xi: dec(&new_xi),
            share_id: dec_be(&self.params.party_id().key),
            ks: new_ks.iter().map(dec).collect(),
            ntilde_j,
            h1j,
            h2j,
            big_xj: new_big_xjs.iter().map(ec_point).collect(),
            paillier_pks,
            ecdsa_pub: ec_point(&ecdsa_pub_pt),
        };
        self.deliver(Ok(key));
    }

    // --- helpers ---

    /// Lagrange-weighted share `w_i` over the OLD committee.
    fn prepare_wi(&self) -> Result<Scalar, Error> {
        let i = self
            .params
            .old_index()
            .ok_or_else(|| Error::Validation("resharing: not an old-committee member".into()))?;
        let ks: Vec<Scalar> = self.input.ks().iter().map(secp::scalar).collect();
        if self.params.old_threshold() + 1 > ks.len() {
            return Err(Error::Validation("resharing: old t+1 > parties".into()));
        }
        let mut wi = secp::scalar(&self.input.xi());
        for (j, ksj) in ks.iter().enumerate() {
            if j == i {
                continue;
            }
            let denom = ksj.sub(&ks[i]);
            let coef = ksj.mul(&denom.invert());
            wi = wi.mul(&coef);
        }
        Ok(wi)
    }

    fn compute_ssid(&self) -> Vec<u8> {
        let (gx, gy) = secp::generator_coords();
        let mut list: Vec<Vec<u8>> = vec![
            bn::to_be(&secp::field_prime()),
            bn::to_be(&bn::secp256k1_order()),
            bn::to_be(&bn::u64(7)),
            bn::to_be(&gx),
            bn::to_be(&gy),
        ];
        for p in self.params.old_parties() {
            list.push(p.key.clone());
        }
        if let Some(pts) = self.input.big_xj_points() {
            for p in &pts {
                let (x, y) = secp::coords(p);
                list.push(bn::to_be(&x));
                list.push(bn::to_be(&y));
            }
        }
        let n = self.input.ks.len();
        for j in 0..n {
            list.push(bn::to_be(&self.input.peer_params(j).0));
        }
        for j in 0..n {
            list.push(bn::to_be(&self.input.peer_params(j).1));
        }
        for j in 0..n {
            list.push(bn::to_be(&self.input.peer_params(j).2));
        }
        list.push(bn::to_be(&bn::u64(1)));
        list.push(bn::to_be(&bn::u64(0)));
        let refs: Vec<&[u8]> = list.iter().map(|b| b.as_slice()).collect();
        sha512_256i(&refs).to_vec()
    }

    /// This party's index within the new committee.
    fn new_index(&self) -> usize {
        let me = self.params.party_id();
        self.params
            .new_parties()
            .iter()
            .position(|p| p.key == me.key)
            .expect("party is in the new committee")
    }

    fn new_others(&self) -> Vec<PartyId> {
        let me = self.params.party_id();
        self.params
            .new_parties()
            .iter()
            .filter(|p| p.key != me.key)
            .cloned()
            .collect()
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

fn vec_none<T>(n: usize) -> Vec<Option<T>> {
    (0..n).map(|_| None).collect()
}

fn index_of(ids: &[PartyId], target: &PartyId) -> usize {
    ids.iter()
        .position(|p| p.key == target.key)
        .expect("party present")
}

fn context_bytes(ssid: &[u8], idx: usize) -> Vec<u8> {
    let mut c = ssid.to_vec();
    c.extend_from_slice(&bn::to_be(&bn::u64(idx as u64)));
    c
}

fn flatten_points(vs: &[ProjectivePoint]) -> Vec<BoxedUint> {
    let mut out = Vec::with_capacity(vs.len() * 2);
    for p in vs {
        let (x, y) = secp::coords(p);
        out.push(x);
        out.push(y);
    }
    out
}

fn unflatten_points(flat: &[BoxedUint]) -> Option<Vec<ProjectivePoint>> {
    if flat.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(flat.len() / 2);
    for pair in flat.chunks(2) {
        out.push(secp::from_coords(&pair[0], &pair[1])?);
    }
    Some(out)
}

fn parts_b64(parts: &[Vec<u8>]) -> Vec<B64Bytes> {
    parts.iter().map(|p| B64Bytes(p.clone())).collect()
}

fn parts_bytes(parts: &[B64Bytes]) -> Vec<Vec<u8>> {
    parts.iter().map(|p| p.0.clone()).collect()
}

fn dec(n: &BoxedUint) -> BigUintDec {
    BigUintDec::from_be_bytes(&bn::to_be(n))
}

fn dec_be(be: &[u8]) -> BigUintDec {
    BigUintDec::from_be_bytes(be)
}

fn ec_point(p: &ProjectivePoint) -> EcPointJson {
    let (x, y) = secp::coords(p);
    EcPointJson {
        curve: "secp256k1".into(),
        coords: [dec(&x), dec(&y)],
    }
}

// --- wire types ------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct R1Msg {
    #[serde(rename = "ecdsa_pub_x")]
    ecdsa_pub_x: B64Bytes,
    #[serde(rename = "ecdsa_pub_y")]
    ecdsa_pub_y: B64Bytes,
    #[serde(rename = "v_commitment")]
    v_commitment: B64Bytes,
    #[serde(rename = "ssid")]
    ssid: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg1 {
    #[serde(rename = "paillier_n")]
    paillier_n: B64Bytes,
    #[serde(rename = "mod_proof")]
    mod_proof: Vec<B64Bytes>,
    #[serde(rename = "n_tilde")]
    n_tilde: B64Bytes,
    #[serde(rename = "h1")]
    h1: B64Bytes,
    #[serde(rename = "h2")]
    h2: B64Bytes,
    #[serde(rename = "dlnproof_1")]
    dlnproof_1: Vec<B64Bytes>,
    #[serde(rename = "dlnproof_2")]
    dlnproof_2: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R2Msg2 {}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg1 {
    #[serde(rename = "share")]
    share: B64Bytes,
}

#[derive(Clone, Serialize, Deserialize)]
struct R3Msg2 {
    #[serde(rename = "v_decommitment")]
    v_decommitment: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R4Msg1 {
    #[serde(rename = "fac_proof")]
    fac_proof: Vec<B64Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
struct R4Msg2 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsatss::import::import_key;
    use crate::ecdsatss::prepare::LocalPreParams;
    use crate::ecdsatss::vss::Share;
    use crate::tss::testhub::ReshareHub;
    use purecrypto::rng::OsRng;

    fn pid(key: u8) -> PartyId {
        PartyId::new(key.to_string(), format!("P{key}"), vec![key])
    }

    #[test]
    #[ignore = "resharing generates fresh safe primes (slow)"]
    fn import_then_reshare_preserves_pubkey() {
        // Import a plain ECDSA key as a 1-of-1, then reshare to 2-of-3.
        let d = [0x42u8];
        let old = pid(5);
        let input = import_key(&d, &old.key).unwrap();
        let ecdsa_pub = input.ecdsa_pub_point().unwrap();

        let old_ids = vec![old.clone()];
        let new_ids = PartyId::sort(vec![pid(11), pid(12), pid(13)], 0);
        let (old_t, new_t) = (0usize, 1usize);

        let pres: Vec<LocalPreParams> = (0..new_ids.len())
            .map(|_| LocalPreParams::generate(256, &mut OsRng))
            .collect();

        let mut all = old_ids.clone();
        all.extend(new_ids.iter().cloned());
        let hub = ReshareHub::new(&all);

        let mut sessions: Vec<ResharingParty> = Vec::new();
        // Old committee member.
        sessions.push(
            ResharingParty::new(
                ReSharingParameters::new(
                    old_ids.clone(),
                    new_ids.clone(),
                    old_t,
                    new_t,
                    old.clone(),
                    hub.broker(&old),
                ),
                input.clone(),
                None,
            )
            .unwrap(),
        );
        // New committee members.
        for (k, p) in new_ids.iter().enumerate() {
            sessions.push(
                ResharingParty::new(
                    ReSharingParameters::new(
                        old_ids.clone(),
                        new_ids.clone(),
                        old_t,
                        new_t,
                        p.clone(),
                        hub.broker(p),
                    ),
                    input.clone(),
                    Some(pres[k].clone()),
                )
                .unwrap(),
            );
        }

        let results: Vec<Key> = sessions
            .iter()
            .map(|s| s.wait().expect("resharing succeeds"))
            .collect();

        // results[0] is the retired old key; results[1..] are the new shares.
        let new_keys = &results[1..];
        for k in new_keys {
            k.validate_basic().unwrap();
            assert_eq!(k.ecdsa_pub.coords, results[1].ecdsa_pub.coords);
            assert_eq!(k.ecdsa_pub.coords, new_keys[0].ecdsa_pub.coords);
        }
        // Public key preserved.
        let new_pub = new_keys[0].ecdsa_pub_point().unwrap();
        assert!(secp::eq(&new_pub, &ecdsa_pub));

        // Any t+1=2 new shares reconstruct to the original secret d.
        let shares: Vec<Share> = new_keys[..2]
            .iter()
            .map(|k| Share {
                id: secp::scalar(&bn::from_dec(&k.share_id)),
                value: secp::scalar(&bn::from_dec(&k.xi)),
            })
            .collect();
        let secret = vss::reconstruct(&shares);
        assert!(secp::eq(
            &ProjectivePoint::mul_generator(&secret),
            &ecdsa_pub
        ));
    }
}
