//! Broker-driven re-setup of one pair's OT-extension state.
//!
//! Signing needs, between every two signers, the pairwise OT-extension state
//! keygen established (a [`PairOTState`] on each side). That state does not
//! depend on the shares, so a pair can rebuild it on its own: the two members
//! re-run the base-OT exchange in both directions and each ends with a fresh
//! [`PairOTState`] for the other. Shares, the joint public key and every other
//! pair are unchanged; nobody else takes part.
//!
//! Uses: restoring a pair whose stored state was lost (a member keeps only the
//! key core, see [`Key::write_core_to`]), or rotating a pair that should no
//! longer be trusted, e.g. after a failed OT-extension consistency check
//! named that peer.
//!
//! Rounds (both unicast to the peer): (1) base-OT sender message `S` with its
//! proof of knowledge; (2) base-OT receiver response `R`. Like the other
//! sessions it relies on the broker to authenticate the peer.
//!
//! This session exists only in this crate; the Go implementation has no
//! counterpart, so both members must run tsslib-rs.

use super::Error;
use super::baseot;
use super::echo::{flatten_point_xy, pair_base_sid, point_from_be_xy, strip, unflatten_point_xy};
use super::key::{Key, PairOTState};
use super::otext::{self, ExtReceiver, ExtSender};
use super::schnorr::ZkProof;
use super::secp;
use crate::prelude::*;
use crate::rng::SystemRng;
use crate::sync::{Mutex, Receiver as MpscReceiver, Sender as MpscSender, channel};
use crate::tss::b64::B64Bytes;
use crate::tss::expect::JsonExpect;
use crate::tss::{Message, Parameters, PartyId, TssError, decode, encode};
use alloc::sync::Arc;
use purecrypto::hash::sha256;
use purecrypto::rng::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const TYPE_R1: &str = "dkls:pairsetup:r1";
const TYPE_R2: &str = "dkls:pairsetup:r2";
const SOURCE: &str = "dklstss-pairsetup";

/// A running re-setup of the pairwise OT-extension state between this party
/// and one peer. Construct with [`PairSetupParty::new`]; retrieve the new
/// [`PairOTState`] with [`PairSetupParty::wait`] (or
/// [`try_result`](Self::try_result)) and install it with [`Key::set_pair`].
///
/// A pair is usable only when **both** members hold the states from the same
/// run. If either side fails, or one side does not install its result,
/// discard the result and run the session again; until then signing with
/// that peer fails.
pub struct PairSetupParty {
    peer: PartyId,
    result_rx: MpscReceiver<Result<PairOTState, Error>>,
    _shared: Arc<Shared>,
}

struct Shared {
    params: Parameters,
    me: PartyId,
    peer: PartyId,
    ssid: Vec<u8>,
    state: Mutex<State>,
    result_tx: Mutex<Option<MpscSender<Result<PairOTState, Error>>>>,
}

#[derive(Default)]
struct State {
    base_snd: Option<baseot::Sender>,
    base_rcv: Option<baseot::Receiver>,
    delta: Zeroizing<Vec<u8>>,
}

impl PairSetupParty {
    /// Starts the session for this party. `params.parties()` must be exactly
    /// this party and the peer, both members of `key`; the threshold in
    /// `params` is not used. Only the key's public data is read.
    pub fn new(params: Parameters, key: &Key) -> Result<PairSetupParty, Error> {
        key.validate_basic()?;
        if params.party_count() != 2 {
            return Err(Error::Validation(format!(
                "pair setup needs exactly 2 parties, got {}",
                params.party_count()
            )));
        }
        let me = params.party_id().clone();
        let peer = params.other_parties().remove(0);
        if me.cmp_key(&key.party_ids[key.idx]) != core::cmp::Ordering::Equal {
            return Err(Error::Validation(
                "this party is not the key's owner".into(),
            ));
        }
        if !key
            .party_ids
            .iter()
            .any(|p| p.cmp_key(&peer) == core::cmp::Ordering::Equal)
        {
            return Err(Error::Validation(format!(
                "{peer} is not a member of this key"
            )));
        }

        let ssid = pair_setup_session(key, &me, &peer);
        let (tx, rx) = channel();
        let shared = Arc::new(Shared {
            params,
            me,
            peer: peer.clone(),
            ssid,
            state: Mutex::new(State::default()),
            result_tx: Mutex::new(Some(tx)),
        });
        shared.round1()?;
        Ok(PairSetupParty {
            peer,
            result_rx: rx,
            _shared: shared,
        })
    }

    /// The peer this session sets up the pair with (the key to pass to
    /// [`Key::set_pair`]).
    pub fn peer(&self) -> &PartyId {
        &self.peer
    }

    /// Non-blocking peek at the result: `Some(_)` once the new state (or an
    /// error) is ready, `None` while rounds are still pending. Unlike
    /// [`wait`](Self::wait) it never blocks, so a single-threaded driver can
    /// poll it after feeding each inbound message.
    pub fn try_result(&self) -> Option<Result<PairOTState, Error>> {
        self.result_rx.try_recv().ok()
    }

    /// Blocks until the session completes, returning the new pair state or an
    /// error.
    #[cfg(any(feature = "std", test))]
    pub fn wait(&self) -> Result<PairOTState, Error> {
        match self.result_rx.recv() {
            Ok(r) => r,
            Err(_) => Err(Error::Validation(
                "pair setup dropped without result".into(),
            )),
        }
    }
}

impl Shared {
    fn deliver(&self, r: Result<PairOTState, Error>) {
        if let Some(tx) = self.result_tx.lock().take() {
            tx.send(r);
        }
    }

    /// Fails the session, naming the peer whose message caused it.
    fn fail_peer(&self, cause: String) {
        self.deliver(Err(Error::Tss(Box::new(TssError::new(
            cause,
            SOURCE,
            0,
            None,
            vec![self.peer.clone()],
        )))));
    }

    /// Round 1: act as the base-OT sender towards the peer (this side's
    /// `as_alice` / the peer's `as_bob`).
    fn round1(self: &Arc<Self>) -> Result<(), Error> {
        let sid = pair_base_sid(&self.ssid, &self.me.key, &self.peer.key, &self.peer.key);
        let (snd, smsg) = baseot::Sender::new(&sid, otext::KAPPA, &mut SystemRng);
        self.state.lock().base_snd = Some(snd);

        let (sx, sy) = secp::affine_be(&smsg.s);
        let (ax, ay) = secp::affine_be(&smsg.pok.alpha);
        let r1 = PairSetupR1 {
            ot_sender_s_x: B64Bytes(sx),
            ot_sender_s_y: B64Bytes(sy),
            ot_sender_pok_alpha_x: B64Bytes(ax),
            ot_sender_pok_alpha_y: B64Bytes(ay),
            ot_sender_pok_t: B64Bytes(secp::scalar_to_be_min(&smsg.pok.t)),
        };
        self.send(TYPE_R1, &r1)?;

        let me = Arc::clone(self);
        let exp = JsonExpect::new(
            TYPE_R1,
            vec![self.peer.clone()],
            Box::new(move |msgs| me.on_r1(msgs)),
        );
        self.params.broker().connect(TYPE_R1, Arc::new(exp));
        Ok(())
    }

    /// Round 2: answer the peer's base-OT sender as the receiver, with fresh
    /// choice bits Δ (this side's `as_bob` / the peer's `as_alice`).
    fn on_r1(self: &Arc<Self>, msgs: Vec<Message>) {
        let r1: PairSetupR1 = match msgs.first().map(decode) {
            Some(Ok(m)) => m,
            Some(Err(e)) => return self.fail_peer(format!("malformed round-1 message: {e}")),
            None => return self.fail_peer("missing round-1 message".into()),
        };
        let Some(s) = point_from_be_xy(&r1.ot_sender_s_x.0, &r1.ot_sender_s_y.0) else {
            return self.fail_peer("base-OT sender S invalid".into());
        };
        let Some(alpha) =
            point_from_be_xy(&r1.ot_sender_pok_alpha_x.0, &r1.ot_sender_pok_alpha_y.0)
        else {
            return self.fail_peer("base-OT sender PoK alpha invalid".into());
        };
        if strip(&r1.ot_sender_pok_t.0).len() > 32 {
            return self.fail_peer("base-OT sender PoK t too long".into());
        }
        let smsg = baseot::SenderMsg1 {
            s,
            pok: ZkProof {
                alpha,
                t: secp::scalar_from_be_reduce(&r1.ot_sender_pok_t.0),
            },
        };

        let sid = pair_base_sid(&self.ssid, &self.peer.key, &self.me.key, &self.me.key);
        let mut delta = Zeroizing::new(vec![0u8; otext::DELTA_BYTES]);
        SystemRng.fill_bytes(&mut delta);
        let Some((rcv, rmsg)) =
            baseot::Receiver::new(&sid, otext::KAPPA, &delta, &smsg, &mut SystemRng)
        else {
            return self.fail_peer("base-OT sender proof rejected".into());
        };
        {
            let mut st = self.state.lock();
            st.base_rcv = Some(rcv);
            st.delta = delta;
        }
        let r2 = PairSetupR2 {
            ot_receiver_r: flatten_point_xy(&rmsg.r),
        };
        if let Err(e) = self.send(TYPE_R2, &r2) {
            return self.deliver(Err(e));
        }

        let me = Arc::clone(self);
        let exp = JsonExpect::new(
            TYPE_R2,
            vec![self.peer.clone()],
            Box::new(move |msgs| me.finalize(msgs)),
        );
        self.params.broker().connect(TYPE_R2, Arc::new(exp));
    }

    fn finalize(self: &Arc<Self>, msgs: Vec<Message>) {
        let r2: PairSetupR2 = match msgs.first().map(decode) {
            Some(Ok(m)) => m,
            Some(Err(e)) => return self.fail_peer(format!("malformed round-2 message: {e}")),
            None => return self.fail_peer("missing round-2 message".into()),
        };
        let r = match unflatten_point_xy(&r2.ot_receiver_r) {
            Ok(r) => r,
            Err(e) => return self.fail_peer(format!("base-OT receiver R invalid: {e}")),
        };

        let st = self.state.lock();
        let (Some(snd), Some(rcv)) = (st.base_snd.as_ref(), st.base_rcv.as_ref()) else {
            drop(st);
            return self.deliver(Err(Error::Validation(
                "pair setup rounds out of order".into(),
            )));
        };
        let Some((k0, k1)) = snd.finalize(&baseot::ReceiverMsg1 { r }) else {
            drop(st);
            return self.fail_peer("base-OT receiver R has the wrong length".into());
        };
        let (k0, k1) = (Zeroizing::new(k0), Zeroizing::new(k1));
        let chosen = Zeroizing::new(rcv.finalize());
        let state = ExtReceiver::from_base(&k0, &k1).and_then(|as_alice| {
            Ok(PairOTState {
                as_alice,
                as_bob: ExtSender::from_base(&st.delta, &chosen)?,
            })
        });
        drop(st);
        self.deliver(state);
    }

    fn send<T: Serialize>(&self, typ: &str, body: &T) -> Result<(), Error> {
        let msg = encode(
            self.params.wire_format(),
            typ,
            body,
            Some(self.me.clone()),
            Some(self.peer.clone()),
        )?;
        self.params
            .broker()
            .receive(&msg)
            .map_err(|e| Error::Validation(format!("broker delivery failed: {e}")))
    }
}

// --- wire types ------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct PairSetupR1 {
    ot_sender_s_x: B64Bytes,
    ot_sender_s_y: B64Bytes,
    ot_sender_pok_alpha_x: B64Bytes,
    ot_sender_pok_alpha_y: B64Bytes,
    ot_sender_pok_t: B64Bytes,
}

#[derive(Serialize, Deserialize)]
struct PairSetupR2 {
    ot_receiver_r: Vec<B64Bytes>,
}

/// Session id binding the protocol tag, the joint public key and both
/// members, in sorted order so the two sides agree.
fn pair_setup_session(key: &Key, a: &PartyId, b: &PartyId) -> Vec<u8> {
    let (px, py) = secp::affine_be(&key.ecdsa_pub);
    let (lo, hi) = if a.cmp_key(b) == core::cmp::Ordering::Greater {
        (b, a)
    } else {
        (a, b)
    };
    let mut data = b"DKLS23-pairsetup-party-v1-".to_vec();
    data.extend_from_slice(&px);
    data.extend_from_slice(&py);
    for p in [lo, hi] {
        data.extend_from_slice(strip(&p.key));
        data.push(0);
    }
    sha256(&data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::super::signing::{ecdsa_verify, hash_to_scalar};
    use super::super::signing_party::SigningParty;
    use super::super::{Signature, keygen, setup_pair, sign};
    use super::*;
    use crate::tss::testhub::TestHub;

    fn party_ids(n: usize) -> Vec<PartyId> {
        PartyId::sort(
            (1..=n)
                .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
                .collect(),
            0,
        )
    }

    fn verify(key: &Key, hash: &[u8], sig: &Signature) {
        let e = hash_to_scalar(hash);
        let r = secp::scalar_from_be_reduce(&sig.r);
        let s = secp::scalar_from_be_reduce(&sig.s);
        assert!(ecdsa_verify(&key.ecdsa_pub, &e, &r, &s));
    }

    /// Runs the broker session between `keys[a]` and `keys[b]`.
    fn run_pair_setup(keys: &[Key], a: usize, b: usize) -> (PairOTState, PairOTState) {
        let ids = PartyId::sort(
            vec![
                keys[a].party_ids[keys[a].idx].clone(),
                keys[b].party_ids[keys[b].idx].clone(),
            ],
            0,
        );
        let hub = TestHub::new(&ids);
        let owner = |p: &PartyId| {
            [a, b]
                .into_iter()
                .find(|&i| keys[i].party_ids[keys[i].idx].cmp_key(p) == core::cmp::Ordering::Equal)
                .unwrap()
        };
        let parties: Vec<(usize, PairSetupParty)> = ids
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let params = Parameters::new(ids.clone(), p, 1, hub.broker(i));
                (
                    owner(p),
                    PairSetupParty::new(params, &keys[owner(p)]).unwrap(),
                )
            })
            .collect();
        let mut out: Vec<(usize, PairOTState)> = parties
            .iter()
            .map(|(k, p)| (*k, p.wait().unwrap()))
            .collect();
        out.sort_by_key(|(k, _)| if *k == a { 0 } else { 1 });
        let (_, sb) = out.pop().unwrap();
        let (_, sa) = out.pop().unwrap();
        (sa, sb)
    }

    fn broker_sign(keys: &[Key], pick: &[usize], hash: &[u8]) -> Result<Vec<Signature>, Error> {
        let subset = PartyId::sort(
            pick.iter()
                .map(|&i| keys[i].party_ids[keys[i].idx].clone())
                .collect(),
            0,
        );
        let hub = TestHub::new(&subset);
        let mut signers = Vec::new();
        for (pos, p) in subset.iter().enumerate() {
            let key = pick
                .iter()
                .map(|&i| &keys[i])
                .find(|k| k.party_ids[k.idx].cmp_key(p) == core::cmp::Ordering::Equal)
                .unwrap();
            let params = Parameters::new(subset.clone(), p, key.t, hub.broker(pos));
            signers.push(SigningParty::new(
                params,
                key.clone(),
                hash.to_vec(),
                subset.clone(),
                None,
            )?);
        }
        signers.iter().map(SigningParty::wait).collect()
    }

    #[test]
    fn lost_pair_is_rebuilt_by_its_two_members() {
        let ids = party_ids(3);
        let mut keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        let other_pair = keys[1].pair(&ids[2]).unwrap().as_bob.to_bytes();

        // Party 0 lost its pair with party 2 (and its own copy is gone).
        keys[0].remove_pair(&ids[2]).unwrap();
        let hash = sha256(b"pair setup");
        match broker_sign(&keys, &[0, 2], &hash) {
            Err(Error::MissingPairs { party, peers }) => {
                assert_eq!(party.key, ids[0].key);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].key, ids[2].key);
            }
            Err(e) => panic!("expected MissingPairs, got {e}"),
            Ok(_) => panic!("expected MissingPairs, got a signature"),
        }

        let (s0, s2) = run_pair_setup(&keys, 0, 2);
        keys[0].set_pair(&ids[2], s0).unwrap();
        let old = keys[2].set_pair(&ids[0], s2).unwrap();
        assert!(old.is_some(), "party 2's stale state is replaced");

        for sig in broker_sign(&keys, &[0, 2], &hash).unwrap() {
            verify(&keys[0], &hash, &sig);
        }
        let sig = sign(&keys, &[2, 0], &hash, &mut SystemRng).unwrap();
        verify(&keys[0], &hash, &sig);
        // Other pairs are untouched and still work.
        assert_eq!(keys[1].pair(&ids[2]).unwrap().as_bob.to_bytes(), other_pair);
        for sig in broker_sign(&keys, &[1, 2], &hash).unwrap() {
            verify(&keys[0], &hash, &sig);
        }
    }

    #[test]
    fn sync_setup_pair_replaces_both_sides() {
        let ids = party_ids(3);
        let mut keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        let before = keys[0].pair(&ids[1]).unwrap().as_alice.to_bytes();
        let (a, rest) = keys.split_at_mut(1);
        setup_pair(&mut a[0], &mut rest[0], &mut SystemRng).unwrap();
        assert_ne!(keys[0].pair(&ids[1]).unwrap().as_alice.to_bytes(), before);
        let hash = sha256(b"sync pair setup");
        let sig = sign(&keys, &[0, 1], &hash, &mut SystemRng).unwrap();
        verify(&keys[0], &hash, &sig);

        let (a, rest) = keys.split_at_mut(1);
        let mut same = a[0].clone();
        assert!(setup_pair(&mut a[0], &mut same, &mut SystemRng).is_err());
        let other = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        assert!(setup_pair(&mut rest[0], &mut other[0].clone(), &mut SystemRng).is_err());
    }

    #[test]
    fn rejects_bad_party_sets() {
        let ids = party_ids(3);
        let keys = keygen(3, 1, &ids, &mut SystemRng).unwrap();
        let hub = TestHub::new(&ids);

        // Three parties.
        let params = Parameters::new(ids.clone(), &ids[0], 1, hub.broker(0));
        assert!(PairSetupParty::new(params, &keys[0]).is_err());

        // A peer outside the key.
        let stranger = PartyId::new("9", "P9", vec![9]);
        let pair = PartyId::sort(vec![ids[0].clone(), stranger], 0);
        let params = Parameters::new(pair.clone(), &pair[0], 1, hub.broker(0));
        assert!(PairSetupParty::new(params, &keys[0]).is_err());

        // Running as someone else's key.
        let pair = PartyId::sort(vec![ids[0].clone(), ids[1].clone()], 0);
        let params = Parameters::new(pair.clone(), &pair[0], 1, hub.broker(0));
        assert!(PairSetupParty::new(params, &keys[1]).is_err());
    }
}
