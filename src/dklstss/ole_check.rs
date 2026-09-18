//! Mul-then-check (DKLs23 §5) — opt-in malicious-security wrapper around the
//! plain Gilboa multiplier in [`super::ole`]. Port of tss-lib
//! `crypto/ot/ole/mulcheck.go`.
//!
//! Two parties holding `α` (Alice) and `β` (Bob) end with additive shares
//! `u_A + u_B ≡ α·β (mod n)` exactly as in the unchecked ΠMul — but the
//! multiplication is run TWICE in parallel under sub-session-ids `sid|1` and
//! `sid|2` with the SAME `α`, and Bob attaches a cross-run consistency value
//! `Z = u_B1 − u_B2 (mod n)`. Alice verifies `Z_A + Z ≡ 0 (mod n)` where
//! `Z_A = u_A1 − u_A2`; on mismatch she rejects with [`MUL_CHECK_FAILED`].
//!
//! # What this catches (and what it does not)
//!
//! For an honest Bob, `(u_A1 + u_B1) = α·β = (u_A2 + u_B2)`, hence
//! `(u_A1 − u_A2) + (u_B1 − u_B2) = 0`, i.e. `Z_A + Z = 0`. If Bob uses
//! different `β` values across the two runs, the sum is `α·(β1 − β2) ≠ 0`
//! and the check fails. The check therefore catches **"Bob used inconsistent
//! β across the two runs"** — the lever a malicious co-signer pulls to mount
//! the per-bit selective-failure attack on Alice's secret `α`.
//!
//! It does **not** catch a deviation applied *identically to both runs*, and
//! that class still contains a selective-failure attack. Adding the same
//! offset `δ` to correction `i` in both runs shifts `u_A1` and `u_A2` by the
//! same `α_i·δ`, which cancels in `Z_A`; the check passes and Alice's share is
//! wrong exactly when bit `i` of `α` is set. The final ECDSA verification gate
//! then aborts or not depending on that bit — the same one-bit-per-abort
//! oracle as the unchecked path, with no culprit named (see the
//! `checked_does_not_detect_same_offset_in_both_runs` test). A *consistently
//! wrong* `β` (one wrong value used for every bit) is likewise only caught by
//! that gate, but leaks nothing. This mirrors Go's simplified check: the real
//! DKLs23 check (randomised encoding of `α` plus Bob's commitment and
//! check-vector equation, Go's task #17) is **not** ported here, so the
//! checked path narrows the attack surface but is **not** a substitute for
//! bounding retries and rotating keys after unexplained aborts.
//!
//! This module is **opt-in** and additive: the default unchecked
//! [`super::ole`] primitives and the default sign / `SigningParty` wire format
//! are left untouched and byte-identical to Go's default path.

use super::Error;
use super::ole::{self, AliceState, BobMsg};
use super::otext::{ExtReceiver, ExtSender, ExtendMsg1};
use super::secp::Scalar;

/// Error message returned when the cross-run consistency check rejects: Bob
/// used different `β` values in the two parallel ΠMul runs (or tampered with
/// the consistency value `Z`). Mirrors Go's `ole.ErrMulCheckFailed`.
pub const MUL_CHECK_FAILED: &str =
    "ole: Mul-then-check failed — Bob's β differs across parallel runs";

/// Bob's reply for a Mul-then-check session: the two parallel ΠMul corrections
/// (`msg1`, `msg2`) together with Bob's cross-run consistency value
/// `z = u_B1 − u_B2 (mod n)`. Mirrors Go `ole.CheckedBobMsg`.
pub struct CheckedBobMsg {
    pub msg1: BobMsg,
    pub msg2: BobMsg,
    pub z: Scalar,
}

/// Alice's state across the two parallel ΠMul flows. Mirrors Go
/// `ole.CheckedAliceState`.
pub struct CheckedAliceState {
    state1: AliceState,
    state2: AliceState,
}

/// `sid || '|' || tag` — the sub-session-id derivation. Byte-for-byte identical
/// to Go's `ole.subSid` (mulcheck.go) so a future Go↔Rust checked interop is
/// possible. `tag` is `b'1'` or `b'2'`.
fn sub_sid(sid: &[u8], tag: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(sid.len() + 2);
    out.extend_from_slice(sid);
    out.push(b'|');
    out.push(tag);
    out
}

/// Alice's first step of Mul-then-check: launches TWO parallel ΠMul instances
/// with the same `alpha`, under sub-sids `sid|1` and `sid|2`. Returns both OT
/// extension envelopes (to be sent to Bob) and Alice's combined state. Mirrors
/// Go `ole.CheckedAliceStep1`.
pub fn checked_alice_step1(
    sid: &[u8],
    ext_receiver: &ExtReceiver,
    alpha: &Scalar,
) -> Result<(ExtendMsg1, ExtendMsg1, CheckedAliceState), Error> {
    let sid1 = sub_sid(sid, b'1');
    let sid2 = sub_sid(sid, b'2');
    let (msg1, state1) = ole::alice_step1(&sid1, ext_receiver, alpha)?;
    let (msg2, state2) = ole::alice_step1(&sid2, ext_receiver, alpha)?;
    Ok((msg1, msg2, CheckedAliceState { state1, state2 }))
}

/// Bob's step of Mul-then-check: evaluates both ΠMul instances with the SAME
/// `beta` and computes the cross-run consistency value `z = u_B1 − u_B2`.
/// Returns the combined message and Bob's canonical share `u_B1` (the first
/// multiplication's share). Mirrors Go `ole.CheckedBobStep1`.
pub fn checked_bob_step1(
    sid: &[u8],
    ext_sender: &ExtSender,
    beta: &Scalar,
    alice_msg1: &ExtendMsg1,
    alice_msg2: &ExtendMsg1,
) -> Result<(CheckedBobMsg, Scalar), Error> {
    let sid1 = sub_sid(sid, b'1');
    let sid2 = sub_sid(sid, b'2');
    let (msg1, u_b1) = ole::bob_step1(&sid1, ext_sender, beta, alice_msg1)?;
    let (msg2, u_b2) = ole::bob_step1(&sid2, ext_sender, beta, alice_msg2)?;
    let z = u_b1.sub(&u_b2);
    Ok((CheckedBobMsg { msg1, msg2, z }, u_b1))
}

/// Alice's final step: verifies Bob's consistency value and returns Alice's
/// share `u_A1` with `u_A1 + u_B1 ≡ α·β (mod n)`. On check failure returns
/// `Error::Validation(MUL_CHECK_FAILED)` and no share. Mirrors Go
/// `ole.CheckedAliceStep2`.
pub fn checked_alice_step2(
    state: &CheckedAliceState,
    bob_msg: &CheckedBobMsg,
) -> Result<Scalar, Error> {
    let u_a1 = ole::alice_step2(&state.state1, &bob_msg.msg1)?;
    let u_a2 = ole::alice_step2(&state.state2, &bob_msg.msg2)?;

    // Honest Bob: (u_A1 + u_B1) = α·β = (u_A2 + u_B2)
    //          ⇒ (u_A1 − u_A2) + (u_B1 − u_B2) = 0
    //          ⇒ Z_A + Z = 0 (mod n).
    let z_a = u_a1.sub(&u_a2);
    let sum = z_a.add(&bob_msg.z);
    if !bool::from(sum.is_zero()) {
        return Err(Error::Validation(MUL_CHECK_FAILED.into()));
    }
    Ok(u_a1)
}

#[cfg(test)]
mod tests {
    use super::super::baseot;
    use super::super::otext;
    use super::super::secp;
    use super::*;
    use purecrypto::rng::{OsRng, RngCore as _};

    fn ot_setup() -> (ExtSender, ExtReceiver) {
        let sid = b"ole-check-base";
        let mut delta = [0u8; otext::DELTA_BYTES];
        OsRng.fill_bytes(&mut delta);
        let (bs, m1) = baseot::Sender::new(sid, otext::KAPPA, &mut OsRng);
        let (br, m2) = baseot::Receiver::new(sid, otext::KAPPA, &delta, &m1, &mut OsRng).unwrap();
        let (k0, k1) = bs.finalize(&m2).unwrap();
        let chosen = br.finalize();
        (
            ExtSender::from_base(&delta, &chosen).unwrap(),
            ExtReceiver::from_base(&k0, &k1).unwrap(),
        )
    }

    /// Positive: the checked variant reconstructs α·β for honest parties.
    #[test]
    fn checked_shares_reconstruct_product() {
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"checked-correctness";
        let alpha = secp::random_scalar(&mut OsRng);
        let beta = secp::random_scalar(&mut OsRng);

        let (m1, m2, state) = checked_alice_step1(sid, &ext_receiver, &alpha).unwrap();
        let (bmsg, u_b) = checked_bob_step1(sid, &ext_sender, &beta, &m1, &m2).unwrap();
        let u_a = checked_alice_step2(&state, &bmsg).unwrap();

        let lhs = u_a.add(&u_b);
        let rhs = alpha.mul(&beta);
        assert!(
            bool::from(lhs.ct_eq(&rhs)),
            "checked OLE must reconstruct α·β"
        );
    }

    /// Negative: a malicious Bob who uses a DIFFERENT β in the second run
    /// (inconsistent β across the two parallel ΠMul instances) must be
    /// rejected by `checked_alice_step2`. This is the selective-failure lever;
    /// the plain unchecked ΠMul would silently accept it.
    #[test]
    fn checked_detects_inconsistent_beta() {
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"checked-inconsistent";
        let alpha = secp::random_scalar(&mut OsRng);
        let beta1 = secp::random_scalar(&mut OsRng);
        let beta2 = secp::random_scalar(&mut OsRng);

        let (m1, m2, state) = checked_alice_step1(sid, &ext_receiver, &alpha).unwrap();

        // Bob deviates: β1 in run 1, β2 in run 2, then honestly reports
        // Z = u_B1 − u_B2 (he has no way to fake Z to pass the check).
        let sid1 = sub_sid(sid, b'1');
        let sid2 = sub_sid(sid, b'2');
        let (bmsg1, u_b1) = ole::bob_step1(&sid1, &ext_sender, &beta1, &m1).unwrap();
        let (bmsg2, u_b2) = ole::bob_step1(&sid2, &ext_sender, &beta2, &m2).unwrap();
        let z = u_b1.sub(&u_b2);
        let bad = CheckedBobMsg {
            msg1: bmsg1,
            msg2: bmsg2,
            z,
        };

        match checked_alice_step2(&state, &bad) {
            Err(Error::Validation(m)) => assert_eq!(m, MUL_CHECK_FAILED),
            Err(e) => panic!("expected MUL_CHECK_FAILED, got {e}"),
            Ok(_) => panic!("checked_alice_step2 must reject inconsistent β"),
        }
    }

    /// Documents the limit of this check: the SAME offset on one correction in
    /// both runs cancels in `Z_A`, so it is accepted, and Alice's share is then
    /// off by `α_i·δ` — wrong exactly when bit `i` of `α` is set. That is the
    /// per-bit selective-failure lever, surfacing only at the final ECDSA gate.
    #[test]
    fn checked_does_not_detect_same_offset_in_both_runs() {
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"checked-same-offset";
        let beta = secp::random_scalar(&mut OsRng);
        let delta = secp::random_scalar(&mut OsRng);
        let mut wrong = 0;
        for _ in 0..40 {
            let alpha = secp::random_scalar(&mut OsRng);
            let (m1, m2, state) = checked_alice_step1(sid, &ext_receiver, &alpha).unwrap();
            let (mut bmsg, u_b) = checked_bob_step1(sid, &ext_sender, &beta, &m1, &m2).unwrap();
            bmsg.msg1.corrections[0] = bmsg.msg1.corrections[0].add(&delta);
            bmsg.msg2.corrections[0] = bmsg.msg2.corrections[0].add(&delta);
            let u_a = checked_alice_step2(&state, &bmsg).expect("offset cancels in the check");
            if !bool::from(u_a.add(&u_b).ct_eq(&alpha.mul(&beta))) {
                wrong += 1;
            }
        }
        // Wrong for roughly half the random α (those with the targeted bit set).
        assert!(wrong > 0 && wrong < 40, "product wrong in {wrong}/40 runs");
    }

    /// Negative: tampering with Bob's consistency value `Z` (by one) also
    /// trips the check.
    #[test]
    fn checked_detects_tampered_z() {
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"checked-tampered-z";
        let alpha = secp::random_scalar(&mut OsRng);
        let beta = secp::random_scalar(&mut OsRng);

        let (m1, m2, state) = checked_alice_step1(sid, &ext_receiver, &alpha).unwrap();
        let (mut bmsg, _u_b) = checked_bob_step1(sid, &ext_sender, &beta, &m1, &m2).unwrap();

        bmsg.z = bmsg.z.add(&Scalar::ONE);

        match checked_alice_step2(&state, &bmsg) {
            Err(Error::Validation(m)) => assert_eq!(m, MUL_CHECK_FAILED),
            Err(e) => panic!("expected MUL_CHECK_FAILED, got {e}"),
            Ok(_) => panic!("checked_alice_step2 must reject a tampered Z"),
        }
    }
}
