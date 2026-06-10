//! Trusted-dealer key generation for threshold ML-DSA-44.
//!
//! Mirrors the reference `NewThresholdKeysFromSeed`: expand a seed into `rho`
//! and a replicated `(s1, s2)` secret shared over every honest-signer mask of
//! popcount `n − t + 1`, compute the FIPS 204 public key, and hand each party
//! the shares whose mask includes its id. No DKG.

use super::Error;
use super::key::{Key44, Share44};
use super::params::ThresholdParams44;
use purecrypto::hash::shake256;
use purecrypto::mldsa::MlDsa44PublicKey;
use purecrypto::mldsa::hazmat::{self, ML_DSA_44, N, Poly, pack_t1};
use std::collections::HashMap;

const K: usize = 4;
const L: usize = 4;

/// Derives a threshold ML-DSA-44 public key and `n` per-party key shares from a
/// 32-byte seed. The public key is byte-identical to stock FIPS 204.
pub fn trusted_dealer_keygen44(
    seed: &[u8; 32],
    params: &ThresholdParams44,
) -> Result<(MlDsa44PublicKey, Vec<Key44>), Error> {
    let n = params.n as usize;
    let t = params.t as usize;
    let eta = ML_DSA_44.params.eta;

    // Enumerate honest-signer masks of popcount (n − t + 1) via Gosper's hack.
    let masks = gosper_masks(n, (n - t + 1) as u32);

    // One SHAKE256 squeeze reproduces the reference's incremental stream:
    // input = seed || [K, L]; layout = rho(32) || n×discard(32) || masks×sSeed(64).
    let total = 32 + n * 32 + masks.len() * 64;
    let mut stream = vec![0u8; total];
    let mut input = seed.to_vec();
    input.push(K as u8);
    input.push(L as u8);
    shake256(&input, &mut stream);

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&stream[..32]);

    let mut keys: Vec<Key44> = (0..n)
        .map(|i| Key44 {
            id: i as u8,
            rho,
            tr: [0u8; 64],
            t1: [Poly::zero(); K],
            shares: HashMap::new(),
        })
        .collect();

    let a = super::key::expand_matrix(&rho);

    // Aggregate accumulators (dealer-only): s1 in NTT, s2 in plain domain.
    let mut s1h_total = [Poly::zero(); L];
    let mut s2_total = [Poly::zero(); K];

    let mut off = 32 + n * 32;
    for &mask in &masks {
        let sseed = &stream[off..off + 64];
        off += 64;

        let mut s1 = [Poly::zero(); L];
        let mut s2 = [Poly::zero(); K];
        let mut s1h = [Poly::zero(); L];
        let mut s2h = [Poly::zero(); K];
        for (j, p) in s1.iter_mut().enumerate() {
            *p = hazmat::sample_bounded_poly(sseed, eta, j as u16);
            let mut h = *p;
            h.ntt();
            s1h[j] = h;
            s1h_total[j] = s1h_total[j].add(&h);
        }
        for (j, p) in s2.iter_mut().enumerate() {
            *p = hazmat::sample_bounded_poly(sseed, eta, (j + L) as u16);
            let mut h = *p;
            h.ntt();
            s2h[j] = h;
            s2_total[j] = s2_total[j].add(p);
        }
        let share = Share44 { s1, s2, s1h, s2h };
        for (i, key) in keys.iter_mut().enumerate() {
            if mask & (1 << i) != 0 {
                key.shares.insert(mask, share.clone());
            }
        }
    }

    // t = A·s1 + s2 ; t1 = high bits of t (Power2Round).
    let mut t1 = [Poly::zero(); K];
    for (i, t1i) in t1.iter_mut().enumerate() {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&hazmat::ntt_mul(&a[i * L + j], &s1h_total[j]));
        }
        acc.inv_ntt();
        let tpoly = acc.add(&s2_total[i]);
        for jj in 0..N {
            let (hi, _) = hazmat::power2_round(tpoly.c[jj]);
            t1i.c[jj] = hi;
        }
    }

    // Pack the FIPS 204 public key: rho || pack_t1 per row.
    let mut pk_bytes = Vec::with_capacity(32 + K * 320);
    pk_bytes.extend_from_slice(&rho);
    for t1i in &t1 {
        pk_bytes.extend_from_slice(&pack_t1(t1i));
    }
    let pk = MlDsa44PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| Error::Validation(format!("public key assembly failed: {e:?}")))?;

    let mut tr = [0u8; 64];
    shake256(&pk_bytes, &mut tr);
    for key in &mut keys {
        key.tr = tr;
        key.t1 = t1;
    }

    Ok((pk, keys))
}

/// All masks over `n` bits with exactly `popcount` bits set (Gosper's hack).
pub(crate) fn gosper_masks(n: usize, popcount: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let end: u32 = 1u32 << n;
    let mut mask: u32 = (1u32 << popcount) - 1;
    while mask < end {
        out.push(mask as u8);
        let c = mask & mask.wrapping_neg();
        let r = mask + c;
        mask = (((r ^ mask) >> 2) / c) | r;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::params::get_threshold_params44;
    use super::*;

    /// Recompute t1 from the union of all distinct shares and confirm it
    /// matches every party's stored t1 — proving the shares carry the secret.
    fn check_secret_reconstructs(keys: &[Key44]) {
        let mut seen: HashMap<u8, Share44> = HashMap::new();
        for k in keys {
            for (m, s) in &k.shares {
                seen.entry(*m).or_insert_with(|| s.clone());
            }
        }
        let a = keys[0].matrix();
        let mut s1h_total = [Poly::zero(); L];
        let mut s2_total = [Poly::zero(); K];
        for s in seen.values() {
            for j in 0..L {
                s1h_total[j] = s1h_total[j].add(&s.s1h[j]);
            }
            for j in 0..K {
                s2_total[j] = s2_total[j].add(&s.s2[j]);
            }
        }
        for i in 0..K {
            let mut acc = Poly::zero();
            for j in 0..L {
                acc = acc.add(&hazmat::ntt_mul(&a[i * L + j], &s1h_total[j]));
            }
            acc.inv_ntt();
            let tpoly = acc.add(&s2_total[i]);
            for jj in 0..N {
                let (hi, _) = hazmat::power2_round(tpoly.c[jj]);
                assert_eq!(hi, keys[0].t1[i].c[jj], "t1[{i}][{jj}] mismatch");
            }
        }
    }

    #[test]
    fn keygen_2_of_3() {
        let params = get_threshold_params44(2, 3).unwrap();
        let (_pk, keys) = trusted_dealer_keygen44(&[7u8; 32], &params).unwrap();
        assert_eq!(keys.len(), 3);
        for k in &keys {
            k.validate().unwrap();
        }
        check_secret_reconstructs(&keys);
    }

    #[test]
    fn keygen_3_of_5() {
        let params = get_threshold_params44(3, 5).unwrap();
        let (_pk, keys) = trusted_dealer_keygen44(&[9u8; 32], &params).unwrap();
        assert_eq!(keys.len(), 5);
        check_secret_reconstructs(&keys);
    }

    #[test]
    fn deterministic_in_seed() {
        let params = get_threshold_params44(2, 2).unwrap();
        let (pk1, _) = trusted_dealer_keygen44(&[1u8; 32], &params).unwrap();
        let (pk2, _) = trusted_dealer_keygen44(&[1u8; 32], &params).unwrap();
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }
}
