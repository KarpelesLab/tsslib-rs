//! SoftSpoken/KOS OT extension over the base OT. Port of tss-lib
//! `crypto/ot/otext`.
//!
//! One base-OT setup (κ instances) is reused across many `extend` calls. The
//! receiver supplies L choice bits and learns `m_{c_i}` per row; the sender
//! learns both `(m_0, m_1)`. A KOS-style consistency check (σ Fiat-Shamir
//! challenges) guards against a malicious receiver before any output is used.

use super::Error;
use super::baseot;
use purecrypto::cipher::{Aes128, Ctr};
use purecrypto::hash::sha512_256;
use zeroize::Zeroize;

/// Computational security parameter (bits).
pub const KAPPA: usize = 128;
/// Byte length of the sender's correlation Δ.
pub const DELTA_BYTES: usize = KAPPA / 8;
/// Statistical security parameter (bits) for the consistency check.
pub const SIGMA: usize = 80;
const SIGMA_BYTES: usize = SIGMA / 8;
/// PRG seed length (= base-OT key length).
pub const SEED_LEN: usize = baseot::KEY_LEN;
/// Output OT key length.
pub const KEY_LEN: usize = 32;

/// The sender's `(m_0, m_1)` outputs.
pub type MessagePair = (Vec<[u8; KEY_LEN]>, Vec<[u8; KEY_LEN]>);

/// OT-extension sender state (plays the base-OT *receiver* with choice bits Δ).
#[derive(Clone)]
pub struct ExtSender {
    delta: [u8; DELTA_BYTES],
    seeds: Vec<[u8; SEED_LEN]>, // length KAPPA; seeds[j] = base-OT key for Δ_j
}

/// OT-extension receiver state (plays the base-OT *sender*, knows both seeds).
#[derive(Clone)]
pub struct ExtReceiver {
    seeds0: Vec<[u8; SEED_LEN]>,
    seeds1: Vec<[u8; SEED_LEN]>,
}

/// The receiver's extension message: IKNP correction rows `U` plus the KOS
/// consistency-check fields `X`, `T`.
#[derive(Clone)]
pub struct ExtendMsg1 {
    pub l: usize,
    pub u: Vec<Vec<u8>>,           // KAPPA rows, each l/8 bytes
    pub x: [u8; SIGMA_BYTES],      // σ bits packed
    pub t: Vec<[u8; DELTA_BYTES]>, // SIGMA rows of κ bits
}

impl ExtSender {
    /// Builds from a κ-instance base-OT batch where this party was the base-OT
    /// receiver with choice bits `delta`, learning `keys[j]` per instance.
    pub fn from_base(delta: &[u8], keys: &[[u8; baseot::KEY_LEN]]) -> Result<ExtSender, Error> {
        if delta.len() != DELTA_BYTES || keys.len() != KAPPA {
            return Err(Error::Validation("otext: bad base-OT sender inputs".into()));
        }
        let mut d = [0u8; DELTA_BYTES];
        d.copy_from_slice(delta);
        Ok(ExtSender {
            delta: d,
            seeds: keys.to_vec(),
        })
    }

    /// The sender's secret correlation Δ (sensitive; for protocol composition).
    pub fn delta(&self) -> [u8; DELTA_BYTES] {
        self.delta
    }

    /// Serializes to `delta || seeds` (`DELTA_BYTES + KAPPA·SEED_LEN` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DELTA_BYTES + KAPPA * SEED_LEN);
        out.extend_from_slice(&self.delta);
        for s in &self.seeds {
            out.extend_from_slice(s);
        }
        out
    }

    /// Inverse of [`to_bytes`](ExtSender::to_bytes).
    pub fn from_bytes(b: &[u8]) -> Result<ExtSender, Error> {
        if b.len() != DELTA_BYTES + KAPPA * SEED_LEN {
            return Err(Error::Validation("otext: bad ExtSender length".into()));
        }
        let mut delta = [0u8; DELTA_BYTES];
        delta.copy_from_slice(&b[..DELTA_BYTES]);
        let seeds = chunk_seeds(&b[DELTA_BYTES..]);
        Ok(ExtSender { delta, seeds })
    }

    /// Overwrites the secret correlation Δ and all PRG seeds with zeros,
    /// rendering this state unusable. Best-effort scrubbing of long-lived key
    /// material; does not affect serialization of live states.
    pub fn zeroize(&mut self) {
        self.delta.zeroize();
        for s in &mut self.seeds {
            s.zeroize();
        }
    }

    /// Runs the OT-extension sender given the receiver's message, returning
    /// `(m_0, m_1)` after verifying the consistency check.
    #[allow(clippy::needless_range_loop)]
    pub fn extend(&self, sid: &[u8], msg: &ExtendMsg1) -> Result<MessagePair, Error> {
        validate_l(msg.l)?;
        if msg.u.len() != KAPPA {
            return Err(Error::Validation("otext: U has wrong length".into()));
        }
        let l = msg.l;
        let lb = l / 8;
        if msg.u.iter().any(|row| row.len() != lb) {
            return Err(Error::Validation("otext: U row has wrong length".into()));
        }

        // q_j = PRG(seed_{j,Δ_j}, sid) XOR (Δ_j · u_j).
        let mut q: Vec<Vec<u8>> = Vec::with_capacity(KAPPA);
        for j in 0..KAPPA {
            let delta_bit = (self.delta[j / 8] >> (j & 7)) & 1;
            let mask = mask_of(delta_bit);
            let expansion = prg_expand(&self.seeds[j], sid, lb);
            let mut row = vec![0u8; lb];
            for b in 0..lb {
                row[b] = expansion[b] ^ (msg.u[j][b] & mask);
            }
            q.push(row);
        }
        let q_t = transpose_bits(&q, KAPPA, l);

        // Consistency check.
        let chi = derive_challenges(sid, &msg.u, l);
        for h in 0..SIGMA {
            let mut t_prime = [0u8; DELTA_BYTES];
            xor_selected_rows(&chi[h], &q_t, l, &mut t_prime);
            let x_bit = (msg.x[h / 8] >> (h & 7)) & 1;
            let mut expected = msg.t[h];
            if x_bit == 1 {
                for b in 0..DELTA_BYTES {
                    expected[b] ^= self.delta[b];
                }
            }
            if expected != t_prime {
                return Err(Error::Validation(format!(
                    "otext: consistency check failed at h={h}"
                )));
            }
        }

        let mut m0 = Vec::with_capacity(l);
        let mut m1 = Vec::with_capacity(l);
        for i in 0..l {
            m0.push(hash_row(sid, i, &q_t[i]));
            let mut xored = vec![0u8; DELTA_BYTES];
            for b in 0..DELTA_BYTES {
                xored[b] = q_t[i][b] ^ self.delta[b];
            }
            m1.push(hash_row(sid, i, &xored));
        }
        Ok((m0, m1))
    }
}

impl ExtReceiver {
    /// Builds from a κ-instance base-OT batch where this party was the base-OT
    /// sender and knows both keys per instance.
    pub fn from_base(
        k0: &[[u8; baseot::KEY_LEN]],
        k1: &[[u8; baseot::KEY_LEN]],
    ) -> Result<ExtReceiver, Error> {
        if k0.len() != KAPPA || k1.len() != KAPPA {
            return Err(Error::Validation(
                "otext: bad base-OT receiver inputs".into(),
            ));
        }
        Ok(ExtReceiver {
            seeds0: k0.to_vec(),
            seeds1: k1.to_vec(),
        })
    }

    /// Serializes to `seeds0 || seeds1` (`2·KAPPA·SEED_LEN` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * KAPPA * SEED_LEN);
        for s in &self.seeds0 {
            out.extend_from_slice(s);
        }
        for s in &self.seeds1 {
            out.extend_from_slice(s);
        }
        out
    }

    /// Inverse of [`to_bytes`](ExtReceiver::to_bytes).
    pub fn from_bytes(b: &[u8]) -> Result<ExtReceiver, Error> {
        if b.len() != 2 * KAPPA * SEED_LEN {
            return Err(Error::Validation("otext: bad ExtReceiver length".into()));
        }
        Ok(ExtReceiver {
            seeds0: chunk_seeds(&b[..KAPPA * SEED_LEN]),
            seeds1: chunk_seeds(&b[KAPPA * SEED_LEN..]),
        })
    }

    /// Overwrites both PRG seed vectors with zeros, rendering this state
    /// unusable. Best-effort scrubbing of long-lived key material.
    pub fn zeroize(&mut self) {
        for s in &mut self.seeds0 {
            s.zeroize();
        }
        for s in &mut self.seeds1 {
            s.zeroize();
        }
    }

    /// Runs the OT-extension receiver. `c` packs L choice bits (LE within byte).
    /// Returns the message for the sender and the receiver's L output keys,
    /// where `keys[i] == m_{c_i}[i]`.
    #[allow(clippy::needless_range_loop)]
    pub fn extend(
        &self,
        sid: &[u8],
        c: &[u8],
        l: usize,
    ) -> Result<(ExtendMsg1, Vec<[u8; KEY_LEN]>), Error> {
        validate_l(l)?;
        if c.len() * 8 < l {
            return Err(Error::Validation("otext: choice buffer too small".into()));
        }
        let lb = l / 8;

        let mut t0: Vec<Vec<u8>> = Vec::with_capacity(KAPPA);
        let mut t1: Vec<Vec<u8>> = Vec::with_capacity(KAPPA);
        for j in 0..KAPPA {
            t0.push(prg_expand(&self.seeds0[j], sid, lb));
            t1.push(prg_expand(&self.seeds1[j], sid, lb));
        }

        // u_j = t0_j XOR t1_j XOR c.
        let mut u: Vec<Vec<u8>> = Vec::with_capacity(KAPPA);
        for j in 0..KAPPA {
            let mut row = vec![0u8; lb];
            for b in 0..lb {
                row[b] = t0[j][b] ^ t1[j][b] ^ c[b];
            }
            u.push(row);
        }

        let v = transpose_bits(&t0, KAPPA, l);
        let chi = derive_challenges(sid, &u, l);

        // x_h = XOR_i (c[i] & χ_h[i]); T_h = XOR_i (v[i] & χ_h[i]).
        let mut x_check = [0u8; SIGMA_BYTES];
        let mut t_check: Vec<[u8; DELTA_BYTES]> = vec![[0u8; DELTA_BYTES]; SIGMA];
        for h in 0..SIGMA {
            let mut xbit = 0u8;
            for byte_idx in 0..lb {
                xbit ^= popcount_byte(chi[h][byte_idx] & c[byte_idx]) & 1;
            }
            xor_selected_rows(&chi[h], &v, l, &mut t_check[h]);
            if xbit == 1 {
                x_check[h / 8] |= 1 << (h & 7);
            }
        }

        let keys: Vec<[u8; KEY_LEN]> = (0..l).map(|i| hash_row(sid, i, &v[i])).collect();
        Ok((
            ExtendMsg1 {
                l,
                u,
                x: x_check,
                t: t_check,
            },
            keys,
        ))
    }
}

/// `out ^= Σ_{i : χ[i]=1} rows[i]` for `i in [0, l)`.
fn xor_selected_rows(chi: &[u8], rows: &[Vec<u8>], l: usize, out: &mut [u8; DELTA_BYTES]) {
    for (byte_idx, &chi_byte) in chi.iter().enumerate() {
        if chi_byte == 0 {
            continue;
        }
        let base = byte_idx * 8;
        for bit in 0..8 {
            if (chi_byte >> bit) & 1 == 1 {
                let i = base + bit;
                if i >= l {
                    break;
                }
                for b in 0..DELTA_BYTES {
                    out[b] ^= rows[i][b];
                }
            }
        }
    }
}

fn validate_l(l: usize) -> Result<(), Error> {
    if l == 0 || l % 8 != 0 {
        return Err(Error::Validation(
            "otext: l must be a positive multiple of 8".into(),
        ));
    }
    Ok(())
}

fn mask_of(bit: u8) -> u8 {
    (-(bit as i8)) as u8 // 0xFF if 1, 0x00 if 0
}

/// AES-128-CTR PRG keyed by a SHA-512/256 derivation of (seed, sid).
fn prg_expand(seed: &[u8; SEED_LEN], sid: &[u8], n: usize) -> Vec<u8> {
    let tag = sha512_256(b"DKLS23-otext-prg-v2");
    let mut buf = Vec::with_capacity(64 + 16 + SEED_LEN + sid.len());
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&(sid.len() as u64).to_le_bytes());
    buf.extend_from_slice(sid);
    let derived = sha512_256(&buf);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&derived[0..16]);
    iv.copy_from_slice(&derived[16..32]);

    let mut out = vec![0u8; n];
    let mut ctr = Ctr::new(Aes128::new(&key), &iv);
    ctr.apply_keystream(&mut out);
    out
}

/// Random-oracle output for a κ-bit column vector `v`, byte-exact (unlike the
/// big.Int-framed `SHA512_256i_TAGGED`, leading zeros matter here).
fn hash_row(sid: &[u8], i: usize, v: &[u8]) -> [u8; KEY_LEN] {
    let tag = sha512_256(b"DKLS23-otext-row-v1");
    let mut buf = Vec::new();
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&(sid.len() as u64).to_le_bytes());
    buf.extend_from_slice(sid);
    buf.extend_from_slice(&(i as u64).to_le_bytes());
    buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    buf.extend_from_slice(v);
    sha512_256(&buf)
}

/// σ Fiat-Shamir challenge vectors χ_h ∈ {0,1}^L, bound to (sid, L, U).
fn derive_challenges(sid: &[u8], u: &[Vec<u8>], l: usize) -> Vec<Vec<u8>> {
    let tag = sha512_256(b"DKLS23-otext-coin-v1");
    let mut buf = Vec::new();
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&(sid.len() as u64).to_le_bytes());
    buf.extend_from_slice(sid);
    buf.extend_from_slice(&(l as u64).to_le_bytes());
    buf.extend_from_slice(&(u.len() as u64).to_le_bytes());
    for row in u {
        buf.extend_from_slice(&(row.len() as u64).to_le_bytes());
        buf.extend_from_slice(row);
    }
    let digest = sha512_256(&buf);
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&digest);

    let lb = l / 8;
    let expand = prg_expand(&seed, b"DKLS23-otext-challenges-v1", SIGMA * lb);
    (0..SIGMA)
        .map(|h| expand[h * lb..(h + 1) * lb].to_vec())
        .collect()
}

/// Transposes a packed-bit `rows × cols` matrix to `cols × rows`.
#[allow(clippy::needless_range_loop)]
fn transpose_bits(input: &[Vec<u8>], rows: usize, cols: usize) -> Vec<Vec<u8>> {
    assert!(
        rows % 8 == 0 && cols % 8 == 0,
        "transpose dims must be multiples of 8"
    );
    assert_eq!(input.len(), rows);
    let col_bytes = cols / 8;
    let row_bytes = rows / 8;
    let mut out: Vec<Vec<u8>> = vec![vec![0u8; row_bytes]; cols];
    for (r, in_row) in input.iter().enumerate() {
        let row_byte_idx = r / 8;
        let row_bit_mask = 1u8 << (r & 7);
        for c_byte in 0..col_bytes {
            let b = in_row[c_byte];
            let base = c_byte * 8;
            for c_bit in 0..8 {
                let bit = (b >> c_bit) & 1;
                out[base + c_bit][row_byte_idx] |= row_bit_mask & mask_of(bit);
            }
        }
    }
    out
}

fn popcount_byte(b: u8) -> u8 {
    b.count_ones() as u8
}

/// Splits a flat buffer into `KAPPA` 32-byte seeds.
fn chunk_seeds(b: &[u8]) -> Vec<[u8; SEED_LEN]> {
    b.chunks_exact(SEED_LEN)
        .map(|c| {
            let mut s = [0u8; SEED_LEN];
            s.copy_from_slice(c);
            s
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::{OsRng, RngCore};

    /// Wires a base-OT batch into an (ExtSender, ExtReceiver) pair.
    fn setup() -> (ExtSender, ExtReceiver) {
        let sid = b"otext-sid";
        // ExtSender is base-OT receiver (choice bits = Δ); ExtReceiver is base-OT sender.
        let mut delta = [0u8; DELTA_BYTES];
        OsRng.fill_bytes(&mut delta);
        let (b_sender, m1) = baseot::Sender::new(sid, KAPPA, &mut OsRng);
        let (b_receiver, m2) = baseot::Receiver::new(sid, KAPPA, &delta, &m1, &mut OsRng).unwrap();
        let (k0, k1) = b_sender.finalize(&m2).unwrap();
        let chosen = b_receiver.finalize();
        let ext_receiver = ExtReceiver::from_base(&k0, &k1).unwrap();
        let ext_sender = ExtSender::from_base(&delta, &chosen).unwrap();
        (ext_sender, ext_receiver)
    }

    #[test]
    fn extension_correctness() {
        let (es, er) = setup();
        let sid = b"session-1";
        let l = 256;
        let mut c = vec![0u8; l / 8];
        OsRng.fill_bytes(&mut c);

        let (msg, r_keys) = er.extend(sid, &c, l).unwrap();
        let (m0, m1) = es.extend(sid, &msg).unwrap();

        for i in 0..l {
            let bit = (c[i / 8] >> (i & 7)) & 1;
            let expected = if bit == 1 { m1[i] } else { m0[i] };
            assert_eq!(r_keys[i], expected, "row {i} (bit {bit})");
            let other = if bit == 1 { m0[i] } else { m1[i] };
            assert_ne!(r_keys[i], other, "row {i} non-chosen leaked");
        }
    }

    #[test]
    fn tampered_check_rejected() {
        let (es, er) = setup();
        let sid = b"session-2";
        let l = 128;
        let c = vec![0xABu8; l / 8];
        let (mut msg, _) = er.extend(sid, &c, l).unwrap();
        // Flip a bit of a correction row — the consistency check must catch it.
        msg.u[0][0] ^= 1;
        assert!(es.extend(sid, &msg).is_err());
    }
}
