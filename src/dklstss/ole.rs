//! Gilboa multiplication-to-additive (ΠMul) over OT extension. Two parties holding `α` (Alice) and `β`
//! (Bob) end with additive shares `u_A + u_B ≡ α·β (mod n)`.
//!
//! # SECURITY (known gap in the *default* path)
//!
//! These primitives are the *plain* Gilboa multiplier: Alice's OT choice bits
//! are the raw bits of her secret `α` (no randomized encoding / gadget
//! vector) — followed by a fresh random pad so the KOS check value hides them
//! (see [`PAD_BITS`]) — and Bob's correction values `c_i` are used without any consistency
//! verification. On their own they implement no πMul input-consistency check,
//! so a malicious counterparty can flip a chosen `m_1[i]`/correction such that
//! the multiplication output is correct iff a specific bit of `α` has a guessed
//! value; the resulting signature then verifies or aborts accordingly, giving
//! a selective-failure oracle of ~1 bit of the honest party's share/nonce per
//! aborted session. The KOS check in [`super::otext`] only protects the
//! *sender* from a malicious receiver; it does not authenticate the sender's
//! inputs here.
//!
//! The default [`super::sign`] / [`super::signing_party`] path uses these
//! primitives directly; its wire format is fixed (existing peers depend on it),
//! so it is not changed.
//!
//! ## Opt-in fix: Mul-then-check
//!
//! The opt-in **Mul-then-check** wrapper in [`super::ole_check`] composes these
//! exact primitives into a DKLs23 §5 consistency-checked multiplication (two
//! parallel runs under `sid|1`/`sid|2` with a cross-run check value `Z`). It
//! closes the selective-failure oracle for an *inconsistent-`β`* deviation and
//! is wired into [`super::sign_checked`] and
//! [`super::CheckedSigningParty`]. That wrapper requires no change to the
//! OT-extension message sizes — it simply runs the unchecked multiplication
//! twice — so the default wire format is untouched. It is a simplified check,
//! with a limitation: a deviation applied identically to both runs
//! (including a per-bit offset, which is still a selective-failure lever) is
//! caught only by the final ECDSA verification gate; the full DKLs23 check
//! changes the wire format and needs a versioned protocol change. See [`super`] (dklstss) module docs for operational guidance on the
//! signing paths: bound retries and rotate/reshare the key on repeated
//! unexplained signing aborts with the same participant set.

use super::Error;
use super::otext::{self, ExtReceiver, ExtSender, ExtendMsg1};
use super::secp::Scalar;
use crate::prelude::*;
use crate::rng::SystemRng;

/// Number of OT-extension rows consumed (secp256k1 scalar bit length).
const SCALAR_BITS: usize = 256;

/// Uniformly random choice bits appended to `α`'s bits on every extension.
///
/// The KOS consistency check makes Alice (the OT-extension receiver) reveal
/// `x_h = <χ_h, c>` for σ = 80 challenges `χ_h` derived from public data
/// (sid, U). If `c` were exactly the 256 bits of `α`, every envelope would
/// hand anyone who sees it (the peer, or an eavesdropper on the p2p channel)
/// 80 independent GF(2) linear equations in `α` — a handful of sessions with
/// the same `α`-holder recovers the weighted key share `λ_i·x_i`. Standard
/// KOS pads the choice vector: with `c = bits(α) || r`, `r` fresh and
/// uniform, `x = χ_α·α ⊕ χ_r·r`. When the 80 × PAD sub-matrix `χ_r` has full
/// row rank, `χ_r·r` is uniform on GF(2)^80 and `x` is statistically
/// independent of `α`. For a uniform `χ_r` the rank-deficiency probability is
/// below `2^(80 − PAD)`, so PAD = σ + 80 = 160 bounds it by ~2^-80 (and keeps
/// `L` a multiple of 8).
const PAD_BITS: usize = otext::SIGMA + 80;

/// Total OT-extension length per ΠMul (the `l` Bob requires): `α`'s bits
/// plus the random pad. Only the first [`SCALAR_BITS`] outputs feed the
/// multiplication; the pad outputs are discarded (and wiped) on both sides.
pub(crate) const EXT_BITS: usize = SCALAR_BITS + PAD_BITS;

/// Bob's reply: one correction value per bit, each in `[0, n)`.
pub struct BobMsg {
    pub corrections: Vec<Scalar>,
}

/// Alice's per-session state between [`alice_step1`] and [`alice_step2`].
pub struct AliceState {
    alpha_be: [u8; 32],
    keys: Vec<[u8; otext::KEY_LEN]>,
}

/// `alpha_be` is Alice's raw ΠMul input — a signing nonce `k_i` or the weighted
/// key share `λ·x_i` — and `keys` are her OT outputs; neither may outlive the
/// session.
impl Drop for AliceState {
    fn drop(&mut self) {
        use purecrypto::zeroize::Zeroize;
        self.alpha_be.zeroize();
        for k in self.keys.iter_mut() {
            k.zeroize();
        }
    }
}

/// Alice's first step: choice bits are the little-endian bits of `alpha`
/// followed by [`PAD_BITS`] fresh random bits (see [`PAD_BITS`] for why).
/// Returns the OT-extension message for Bob and Alice's session state.
pub fn alice_step1(
    sid: &[u8],
    ext_receiver: &ExtReceiver,
    alpha: &Scalar,
) -> Result<(ExtendMsg1, AliceState), Error> {
    use purecrypto::rng::RngCore as _;
    use purecrypto::zeroize::Zeroize;
    let alpha_be = alpha.to_bytes_be();
    // Choice bits: `alpha` (one bit per entry), then the random pad — fresh
    // on every call, so repeated runs with the same `alpha` (retries, the two
    // Mul-then-check runs) never share pad bits.
    let mut choice = purecrypto::zeroize::Zeroizing::new(vec![0u8; EXT_BITS / 8]);
    {
        let alpha_bits = purecrypto::zeroize::Zeroizing::new(bits_le(&alpha_be));
        choice[..SCALAR_BITS / 8].copy_from_slice(&alpha_bits);
    }
    SystemRng.fill_bytes(&mut choice[SCALAR_BITS / 8..]);
    let (msg, mut keys) = ext_receiver.extend(sid, &choice, EXT_BITS)?;
    // Only α's rows feed the multiplication; wipe and drop the pad outputs.
    for k in keys[SCALAR_BITS..].iter_mut() {
        k.zeroize();
    }
    keys.truncate(SCALAR_BITS);
    Ok((msg, AliceState { alpha_be, keys }))
}

/// Bob's step: runs the OT-extension sender, returns his message and his share
/// `u_B := −Σ_i m_0[i] (mod n)`.
pub fn bob_step1(
    sid: &[u8],
    ext_sender: &ExtSender,
    beta: &Scalar,
    alice_msg: &ExtendMsg1,
) -> Result<(BobMsg, Scalar), Error> {
    if alice_msg.l != EXT_BITS {
        return Err(Error::Validation("ole: unexpected L".into()));
    }
    // Rows SCALAR_BITS.. carry Alice's random pad (they exist only to hide α
    // in the KOS check): they are ignored here and wiped with the rest.
    let (m0, m1) = ext_sender.extend(sid, alice_msg)?;
    let (m0, m1) = (
        purecrypto::zeroize::Zeroizing::new(m0),
        purecrypto::zeroize::Zeroizing::new(m1),
    );

    let mut corrections = Vec::with_capacity(SCALAR_BITS);
    let mut u_b = Scalar::ZERO;
    let mut two_to_i = Scalar::ONE;
    for i in 0..SCALAR_BITS {
        let m0i = Scalar::from_bytes_be_reduce(&m0[i]);
        let m1i = Scalar::from_bytes_be_reduce(&m1[i]);
        // c_i = m0_i − m1_i + β·2^i
        let contrib = beta.mul(&two_to_i);
        corrections.push(m0i.sub(&m1i).add(&contrib));
        u_b = u_b.sub(&m0i);
        two_to_i = two_to_i.add(&two_to_i);
    }
    Ok((BobMsg { corrections }, u_b))
}

/// Alice's final step: combines Bob's corrections with her OT outputs into her
/// share `u_A` with `u_A + u_B ≡ α·β`.
pub fn alice_step2(state: &AliceState, bob_msg: &BobMsg) -> Result<Scalar, Error> {
    if bob_msg.corrections.len() != SCALAR_BITS {
        return Err(Error::Validation("ole: wrong correction count".into()));
    }
    // u_A = Σ_i (m_{α_i}[i] + α_i·c_i). Branchless: α_i·c_i, with α_i a 0/1 scalar.
    let mut u_a = Scalar::ZERO;
    for i in 0..SCALAR_BITS {
        let base = Scalar::from_bytes_be_reduce(&state.keys[i]);
        let bit = (state.alpha_be[31 - i / 8] >> (i & 7)) & 1;
        let mut bit_bytes = [0u8; 32];
        bit_bytes[31] = bit;
        let bit_scalar = Scalar::from_bytes_be_reduce(&bit_bytes);
        u_a = u_a.add(&base.add(&bob_msg.corrections[i].mul(&bit_scalar)));
    }
    Ok(u_a)
}

/// Little-endian bit packing of a big-endian 256-bit value (lowest bit first
/// within each byte), for use as OT choice bits.
fn bits_le(be: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; SCALAR_BITS / 8];
    for i in 0..SCALAR_BITS {
        let bit = (be[31 - i / 8] >> (i & 7)) & 1;
        out[i / 8] |= bit << (i & 7);
    }
    out
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::baseot;
    use super::super::secp;
    use super::*;
    use crate::rng::SystemRng;

    fn ot_setup() -> (ExtSender, ExtReceiver) {
        let sid = b"ole-base";
        let mut delta = [0u8; otext::DELTA_BYTES];
        SystemRng.fill_bytes(&mut delta);
        let (bs, m1) = baseot::Sender::new(sid, otext::KAPPA, &mut SystemRng);
        let (br, m2) =
            baseot::Receiver::new(sid, otext::KAPPA, &delta, &m1, &mut SystemRng).unwrap();
        let (k0, k1) = bs.finalize(&m2).unwrap();
        let chosen = br.finalize();
        (
            ExtSender::from_base(&delta, &chosen).unwrap(),
            ExtReceiver::from_base(&k0, &k1).unwrap(),
        )
    }

    use purecrypto::rng::RngCore as _;

    #[test]
    fn shares_reconstruct_product() {
        // Alice is the OT-extension receiver; Bob is the sender.
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"ole-session";
        let alpha = secp::random_scalar(&mut SystemRng);
        let beta = secp::random_scalar(&mut SystemRng);

        let (alice_msg, state) = alice_step1(sid, &ext_receiver, &alpha).unwrap();
        let (bob_msg, u_b) = bob_step1(sid, &ext_sender, &beta, &alice_msg).unwrap();
        let u_a = alice_step2(&state, &bob_msg).unwrap();

        // u_A + u_B == α·β.
        let lhs = u_a.add(&u_b);
        let rhs = alpha.mul(&beta);
        assert!(
            bool::from(lhs.ct_eq(&rhs)),
            "OLE shares must reconstruct α·β"
        );
    }

    #[test]
    fn small_known_values() {
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"ole-2";
        let alpha = secp::scalar_from_be_reduce(&[7]);
        let beta = secp::scalar_from_be_reduce(&[9]);
        let (m, st) = alice_step1(sid, &ext_receiver, &alpha).unwrap();
        let (bm, ub) = bob_step1(sid, &ext_sender, &beta, &m).unwrap();
        let ua = alice_step2(&st, &bm).unwrap();
        assert!(bool::from(
            ua.add(&ub).ct_eq(&secp::scalar_from_be_reduce(&[63]))
        )); // 7*9
    }

    #[test]
    fn bob_rejects_unpadded_length() {
        // A pre-fix peer extends with L = 256; that must fail cleanly.
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"ole-3";
        let beta = secp::random_scalar(&mut SystemRng);
        let mut c = [0u8; SCALAR_BITS / 8];
        SystemRng.fill_bytes(&mut c);
        let (msg, _) = ext_receiver.extend(sid, &c, SCALAR_BITS).unwrap();
        assert!(bob_step1(sid, &ext_sender, &beta, &msg).is_err());
    }

    /// `<χ_h restricted to the first 256 rows, α>` — the value the KOS check
    /// bit would equal if the choice vector were not padded.
    fn unpadded_x(chi: &[u8], alpha_le: &[u8]) -> u8 {
        let mut x = 0u8;
        for b in 0..SCALAR_BITS / 8 {
            x ^= ((chi[b] & alpha_le[b]).count_ones() & 1) as u8;
        }
        x
    }

    /// Gaussian elimination over GF(2) on rows `(256-bit mask, rhs)`; returns
    /// the unique solution if the system has full column rank.
    pub(crate) fn solve_gf2(mut rows: Vec<([u64; 4], u8)>) -> Option<[u8; 32]> {
        let mut piv = [usize::MAX; 256];
        let mut r = 0;
        for (col, piv_col) in piv.iter_mut().enumerate() {
            let hit = |k: &([u64; 4], u8)| (k.0[col / 64] >> (col % 64)) & 1 == 1;
            let Some(p) = (r..rows.len()).find(|&k| hit(&rows[k])) else {
                continue;
            };
            rows.swap(r, p);
            let (a, b) = rows[r];
            for (k, row) in rows.iter_mut().enumerate() {
                if k != r && hit(row) {
                    for (dst, src) in row.0.iter_mut().zip(a) {
                        *dst ^= src;
                    }
                    row.1 ^= b;
                }
            }
            *piv_col = r;
            r += 1;
        }
        if r < 256 {
            return None;
        }
        let mut be = [0u8; 32];
        for (i, &p) in piv.iter().enumerate() {
            be[31 - i / 8] |= rows[p].1 << (i & 7);
        }
        Some(be)
    }

    /// Regression for the KOS-check leak: before padding, a passive observer
    /// of four envelopes for the same `α` solved the 320 published check
    /// equations for `α`. With the random pad the same attack must fail.
    #[test]
    fn x_check_does_not_leak_alpha() {
        let (_, ext_receiver) = ot_setup();
        let alpha = secp::random_scalar(&mut SystemRng);
        let alpha_le = bits_le(&alpha.to_bytes_be());
        let mut rows: Vec<([u64; 4], u8)> = Vec::new();
        let mut mismatches = 0;
        for sess in 0..6u8 {
            let sid = [b's', b'e', b's', b's', sess];
            let (msg, _st) = alice_step1(&sid, &ext_receiver, &alpha).unwrap();
            assert_eq!(msg.l, EXT_BITS);
            // Observer's view: sid, U, X.
            let chi = otext::derive_challenges(&sid, &msg.u, msg.l);
            for (h, chi_h) in chi.iter().enumerate() {
                let mut m = [0u64; 4];
                for i in 0..SCALAR_BITS {
                    if (chi_h[i / 8] >> (i & 7)) & 1 == 1 {
                        m[i / 64] |= 1 << (i % 64);
                    }
                }
                let x = (msg.x[h / 8] >> (h & 7)) & 1;
                if x != unpadded_x(chi_h, &alpha_le) {
                    mismatches += 1;
                }
                rows.push((m, x));
            }
        }
        // The pad contributes ~uniform noise to every check bit (expected
        // mismatches: 240 of 480; all-equal has probability 2^-480).
        assert!(
            mismatches > 100,
            "x_check tracks α: {mismatches} mismatches"
        );
        let solved = solve_gf2(rows);
        assert_ne!(
            solved,
            Some(alpha.to_bytes_be()),
            "α recovered from KOS check values"
        );
    }

    /// Fixed `α` and sid: the check value must still vary run to run (fresh
    /// pad bits per call, so the two Mul-then-check runs and any retry never
    /// share a pad).
    #[test]
    fn pad_is_fresh_per_call() {
        let (_, ext_receiver) = ot_setup();
        let alpha = secp::random_scalar(&mut SystemRng);
        let (m1, _) = alice_step1(b"same", &ext_receiver, &alpha).unwrap();
        let (m2, _) = alice_step1(b"same", &ext_receiver, &alpha).unwrap();
        // Same sid and α: U's α-columns coincide, the pad columns must not.
        assert_eq!(m1.u[0][..SCALAR_BITS / 8], m2.u[0][..SCALAR_BITS / 8]);
        assert_ne!(m1.u[0][SCALAR_BITS / 8..], m2.u[0][SCALAR_BITS / 8..]);
        assert_ne!(m1.x, m2.x);
    }
}
