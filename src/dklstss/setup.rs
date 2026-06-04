//! In-process pairwise OT-extension setup for the synchronous DKLs API.

use super::baseot;
use super::key::PairOTState;
use super::otext::{self, ExtReceiver, ExtSender};
use purecrypto::rng::RngCore;

/// Runs one base-OT batch in-process, returning `(ExtReceiver, ExtSender)` where
/// the ExtReceiver is built from the base-OT *sender* (both keys) and the
/// ExtSender from the base-OT *receiver* (Δ + chosen keys).
fn run_base_ot_pair(sid: &[u8], rng: &mut impl RngCore) -> (ExtReceiver, ExtSender) {
    let mut delta = [0u8; otext::DELTA_BYTES];
    rng.fill_bytes(&mut delta);
    let (bo_sender, smsg) = baseot::Sender::new(sid, otext::KAPPA, rng);
    let (bo_receiver, rmsg) = baseot::Receiver::new(sid, otext::KAPPA, &delta, &smsg, rng)
        .expect("in-process base-OT receiver");
    let (k0, k1) = bo_sender.finalize(&rmsg).expect("base-OT sender finalize");
    let chosen = bo_receiver.finalize();
    (
        ExtReceiver::from_base(&k0, &k1).expect("ext receiver"),
        ExtSender::from_base(&delta, &chosen).expect("ext sender"),
    )
}

/// Establishes per-pair OT-extension state for all parties. `ot[i][j]` is the
/// state party `i` holds for the pair `(i, j)`; `ot[i][i]` is `None`.
#[allow(clippy::needless_range_loop)]
pub fn setup_pairs(
    n: usize,
    sid_prefix: &[u8],
    rng: &mut impl RngCore,
) -> Vec<Vec<Option<PairOTState>>> {
    let mut ot: Vec<Vec<Option<PairOTState>>> =
        (0..n).map(|_| (0..n).map(|_| None).collect()).collect();

    for i in 0..n {
        for j in (i + 1)..n {
            // Direction A: i = Alice (ExtReceiver), j = Bob (ExtSender).
            let mut sid_a = sid_prefix.to_vec();
            sid_a.extend_from_slice(&encode_pair(i, j, b'A'));
            let (rcv_a, snd_a) = run_base_ot_pair(&sid_a, rng);

            // Direction B: j = Alice (ExtReceiver), i = Bob (ExtSender).
            let mut sid_b = sid_prefix.to_vec();
            sid_b.extend_from_slice(&encode_pair(i, j, b'B'));
            let (rcv_b, snd_b) = run_base_ot_pair(&sid_b, rng);

            ot[i][j] = Some(PairOTState {
                as_alice: rcv_a,
                as_bob: snd_b,
            });
            ot[j][i] = Some(PairOTState {
                as_alice: rcv_b,
                as_bob: snd_a,
            });
        }
    }
    ot
}

/// Injective 9-byte encoding of `(i, j, dir)`.
fn encode_pair(i: usize, j: usize, dir: u8) -> [u8; 9] {
    let i = i as u32;
    let j = j as u32;
    let ib = i.to_be_bytes();
    let jb = j.to_be_bytes();
    [ib[0], ib[1], ib[2], ib[3], jb[0], jb[1], jb[2], jb[3], dir]
}
