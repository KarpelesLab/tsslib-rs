//! Chou-Orlandi 1-of-2 base oblivious transfer over secp256k1. Port of
//! tss-lib `crypto/ot/baseot`.
//!
//! A batch of `n` OT instances. The sender learns two keys `(k_{i,0}, k_{i,1})`
//! per instance; the receiver, holding a choice bit `c_i`, learns only
//! `k_{i,c_i}`. Keys seed the OT-extension PRG.

use super::schnorr::ZkProof;
use super::secp::{self, ProjectivePoint, Scalar};
use crate::frost::hashing::sha512_256i_tagged;
use purecrypto::ct::{Choice, ConditionallySelectable};
use purecrypto::rng::RngCore;

/// Per-instance output key length (PRG seed width).
pub const KEY_LEN: usize = 32;

const TAG_KEY: &[u8] = b"DKLS23-baseot-key-v1";
const TAG_POK: &[u8] = b"DKLS23-baseot-pok-v1";

/// The sender's two output keys per instance: `(k_0, k_1)`.
pub type SenderKeys = (Vec<[u8; KEY_LEN]>, Vec<[u8; KEY_LEN]>);

/// The sender's first-round message.
pub struct SenderMsg1 {
    /// Sender commitment `S = y·G`.
    pub s: ProjectivePoint,
    /// Schnorr PoK of `y` for `S`.
    pub pok: ZkProof,
}

/// The receiver's response: `R_i = x_i·G + c_i·S`.
pub struct ReceiverMsg1 {
    /// One response point per instance.
    pub r: Vec<ProjectivePoint>,
}

/// Chou-Orlandi sender state.
pub struct Sender {
    sid: Vec<u8>,
    n: usize,
    y: Scalar,
    s: ProjectivePoint,
}

/// Chou-Orlandi receiver state.
pub struct Receiver {
    sid: Vec<u8>,
    n: usize,
    bits: Vec<u8>,
    x: Vec<Scalar>,
    s: ProjectivePoint,
}

impl Sender {
    /// Starts a batch of `n` OT instances; returns the first-round message.
    pub fn new(sid: &[u8], n: usize, rng: &mut impl RngCore) -> (Sender, SenderMsg1) {
        let y = secp::random_scalar(rng);
        let s = secp::mul_base(&y);
        let pok = ZkProof::prove(&pok_session(sid), &y, &s, rng);
        (
            Sender {
                sid: sid.to_vec(),
                n,
                y,
                s,
            },
            SenderMsg1 { s, pok },
        )
    }

    /// Computes the two output keys per instance from the receiver's response.
    pub fn finalize(&self, msg: &ReceiverMsg1) -> Option<SenderKeys> {
        if msg.r.len() != self.n {
            return None;
        }
        // yS = y·S = y²·G; k_1 uses y·(R_i − S) = y·R_i − yS.
        let y_s = self.s.mul(&self.y);
        let neg_y_s = y_s.negate();

        let mut k0 = Vec::with_capacity(self.n);
        let mut k1 = Vec::with_capacity(self.n);
        for (i, r) in msg.r.iter().enumerate() {
            let y_r = r.mul(&self.y);
            k0.push(derive_key(&self.sid, i, 0, &y_r));
            k1.push(derive_key(&self.sid, i, 1, &y_r.add(&neg_y_s)));
        }
        Some((k0, k1))
    }

    /// Number of OT instances.
    pub fn n(&self) -> usize {
        self.n
    }
}

impl Receiver {
    /// Verifies the sender's message and produces the receiver's response. The
    /// `i`-th choice bit is `(bits[i/8] >> (i%8)) & 1`.
    pub fn new(
        sid: &[u8],
        n: usize,
        bits: &[u8],
        msg: &SenderMsg1,
        rng: &mut impl RngCore,
    ) -> Option<(Receiver, ReceiverMsg1)> {
        if bits.len() * 8 < n {
            return None;
        }
        if !msg.pok.verify(&pok_session(sid), &msg.s) {
            return None;
        }
        let mut x = Vec::with_capacity(n);
        let mut r = Vec::with_capacity(n);
        for i in 0..n {
            let xi = secp::random_scalar(rng);
            let c = (bits[i / 8] >> (i & 7)) & 1;
            let ra = secp::mul_base(&xi); // x_i·G (choice 0)
            let rb = ra.add(&msg.s); // x_i·G + S (choice 1)
            // purecrypto's conditional_select(a, b, choice) returns `a` when
            // choice is true, so pass (rb, ra) to select rb on c==1.
            r.push(ProjectivePoint::conditional_select(
                &rb,
                &ra,
                Choice::from(c),
            ));
            x.push(xi);
        }
        Some((
            Receiver {
                sid: sid.to_vec(),
                n,
                bits: bits.to_vec(),
                x,
                s: msg.s,
            },
            ReceiverMsg1 { r },
        ))
    }

    /// Computes the chosen-key output `k_{i, c_i}` per instance.
    pub fn finalize(&self) -> Vec<[u8; KEY_LEN]> {
        (0..self.n)
            .map(|i| {
                let c = (self.bits[i / 8] >> (i & 7)) & 1;
                let x_s = self.s.mul(&self.x[i]);
                derive_key(&self.sid, i, c as usize, &x_s)
            })
            .collect()
    }

    /// Number of OT instances.
    pub fn n(&self) -> usize {
        self.n
    }
}

fn pok_session(sid: &[u8]) -> Vec<u8> {
    [TAG_POK, sid].concat()
}

/// `SHA512_256i_TAGGED(tagKey||sid, [instance, bit, P.x, P.y])` (32 bytes).
fn derive_key(sid: &[u8], instance: usize, bit: usize, p: &ProjectivePoint) -> [u8; KEY_LEN] {
    let tag = [TAG_KEY, sid].concat();
    let (px, py) = secp::affine_be(p);
    let inst = int_be_min(instance as u64);
    let b = int_be_min(bit as u64);
    sha512_256i_tagged(
        &tag,
        &[inst.as_slice(), b.as_slice(), px.as_slice(), py.as_slice()],
    )
}

/// Minimal big-endian magnitude of `n` (empty for 0), matching `big.Int.Bytes()`.
fn int_be_min(n: u64) -> Vec<u8> {
    let be = n.to_be_bytes();
    let start = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    be[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    #[test]
    fn ot_correctness() {
        let n: usize = 20;
        let sid = b"test-sid".to_vec();
        // Random choice bits.
        let mut bits = vec![0u8; n.div_ceil(8)];
        OsRng.fill_bytes(&mut bits);

        let (sender, m1) = Sender::new(&sid, n, &mut OsRng);
        let (receiver, m2) = Receiver::new(&sid, n, &bits, &m1, &mut OsRng).unwrap();
        let (k0, k1) = sender.finalize(&m2).unwrap();
        let rk = receiver.finalize();

        for i in 0..n {
            let c = (bits[i / 8] >> (i & 7)) & 1;
            let expected = if c == 1 { k1[i] } else { k0[i] };
            assert_eq!(rk[i], expected, "instance {i} (bit {c})");
            // The non-chosen key must differ.
            let other = if c == 1 { k0[i] } else { k1[i] };
            assert_ne!(rk[i], other, "instance {i} non-chosen key leaked");
        }
    }

    #[test]
    fn rejects_bad_pok() {
        let sid = b"sid".to_vec();
        let (_s, mut m1) = Sender::new(&sid, 4, &mut OsRng);
        // Corrupt S so the PoK no longer matches.
        m1.s = secp::mul_base(&secp::random_scalar(&mut OsRng));
        let bits = vec![0u8; 1];
        assert!(Receiver::new(&sid, 4, &bits, &m1, &mut OsRng).is_none());
    }
}
