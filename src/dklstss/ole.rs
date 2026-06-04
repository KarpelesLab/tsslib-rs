//! Gilboa multiplication-to-additive (ΠMul) over OT extension. Port of
//! tss-lib `crypto/ot/ole` (mul). Two parties holding `α` (Alice) and `β`
//! (Bob) end with additive shares `u_A + u_B ≡ α·β (mod n)`.

use super::Error;
use super::otext::{self, ExtReceiver, ExtSender, ExtendMsg1};
use super::secp::Scalar;

/// Number of OT-extension rows consumed (secp256k1 scalar bit length).
const SCALAR_BITS: usize = 256;

/// Bob's reply: one correction value per bit, each in `[0, n)`.
pub struct BobMsg {
    pub corrections: Vec<Scalar>,
}

/// Alice's per-session state between [`alice_step1`] and [`alice_step2`].
pub struct AliceState {
    alpha_be: [u8; 32],
    keys: Vec<[u8; otext::KEY_LEN]>,
}

/// Alice's first step: choice bits are the little-endian bits of `alpha`. Returns
/// the OT-extension message for Bob and Alice's session state.
pub fn alice_step1(
    sid: &[u8],
    ext_receiver: &ExtReceiver,
    alpha: &Scalar,
) -> Result<(ExtendMsg1, AliceState), Error> {
    let alpha_be = alpha.to_bytes_be();
    let choice = bits_le(&alpha_be);
    let (msg, keys) = ext_receiver.extend(sid, &choice, SCALAR_BITS)?;
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
    if alice_msg.l != SCALAR_BITS {
        return Err(Error::Validation("ole: unexpected L".into()));
    }
    let (m0, m1) = ext_sender.extend(sid, alice_msg)?;

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
mod tests {
    use super::super::baseot;
    use super::super::secp;
    use super::*;
    use purecrypto::rng::OsRng;

    fn ot_setup() -> (ExtSender, ExtReceiver) {
        let sid = b"ole-base";
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

    use purecrypto::rng::RngCore as _;

    #[test]
    fn shares_reconstruct_product() {
        // Alice is the OT-extension receiver; Bob is the sender.
        let (ext_sender, ext_receiver) = ot_setup();
        let sid = b"ole-session";
        let alpha = secp::random_scalar(&mut OsRng);
        let beta = secp::random_scalar(&mut OsRng);

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
}
