//! Threshold ML-DSA-44 key material.

use super::Error;
use super::params::{MAX_PARTIES, ThresholdParams44, sharing_pattern};
use purecrypto::mldsa::hazmat::{self, Poly};
use std::collections::HashMap;

const K: usize = 4; // ML_DSA_44.k
const L: usize = 4; // ML_DSA_44.l

/// One `(s1, s2)` secret share, identified by the honest-signer subset mask it
/// was drawn for. Holds both plain (`s1`, `s2`) and cached NTT (`s1h`, `s2h`)
/// representations.
#[derive(Clone)]
pub struct Share44 {
    pub s1: [Poly; L],
    pub s2: [Poly; K],
    pub s1h: [Poly; L],
    pub s2h: [Poly; K],
}

/// One party's threshold ML-DSA-44 key: public material (`rho`, `tr`, `t1`) plus
/// the shares whose subset mask includes this party's `id`.
#[derive(Clone)]
pub struct Key44 {
    /// This party's 0-based id.
    pub id: u8,
    /// Public matrix seed.
    pub rho: [u8; 32],
    /// `SHAKE256(packed pk)` (the FIPS 204 `tr`).
    pub tr: [u8; 64],
    /// Public `t1` vector (high bits of `t = A·s1 + s2`).
    pub t1: [Poly; K],
    /// Shares keyed by honest-signer mask.
    pub shares: HashMap<u8, Share44>,
}

impl Key44 {
    /// Expands the public matrix `A` (row-major, NTT domain) from `rho`.
    /// `A[i*L + j] = sample_ntt_poly(rho, j, i)` (FIPS 204 ExpandA).
    pub fn matrix(&self) -> Vec<Poly> {
        expand_matrix(&self.rho)
    }

    /// Checks the key is well-formed: it holds at least one share, and every
    /// share's mask includes this party's id.
    pub fn validate(&self) -> Result<(), Error> {
        if self.shares.is_empty() {
            return Err(Error::Validation("key has no shares".into()));
        }
        for &mask in self.shares.keys() {
            if mask & (1 << self.id) == 0 {
                return Err(Error::Validation("share mask excludes own id".into()));
            }
        }
        Ok(())
    }

    /// Reconstructs this party's NTT-domain `(s1, s2)` contribution to the
    /// aggregated secret for the signing set `act` (a bitmask of participating
    /// party ids), per the replicated-sharing pattern.
    pub fn recover_share(
        &self,
        act: u8,
        params: &ThresholdParams44,
    ) -> Result<([Poly; L], [Poly; K]), Error> {
        let mut s1h = [Poly::zero(); L];
        let mut s2h = [Poly::zero(); K];

        // t == n: each party holds exactly the full-signer mask's share.
        if params.t == params.n {
            let sh = self
                .shares
                .values()
                .next()
                .ok_or_else(|| Error::Validation("recover_share(t==n): no shares".into()))?;
            return Ok((sh.s1h, sh.s2h));
        }

        let pattern = sharing_pattern(params.t, params.n)
            .ok_or_else(|| Error::Validation("no sharing pattern for (t,n)".into()))?;

        // perm: ids in `act` (low→high) at [0..t), then the rest at [t..n).
        let mut perm = [0u8; MAX_PARTIES];
        let (mut i1, mut i2) = (0u8, params.t);
        let mut currenti: i32 = -1;
        for j in 0..params.n {
            if j == self.id {
                currenti = i1 as i32;
            }
            if act & (1 << j) != 0 {
                perm[i1 as usize] = j;
                i1 += 1;
            } else {
                perm[i2 as usize] = j;
                i2 += 1;
            }
        }
        if currenti < 0 || currenti >= params.t as i32 {
            return Err(Error::Validation(
                "this key is not in the signing set".into(),
            ));
        }
        let pattern_for_me = pattern[currenti as usize];

        for &u in pattern_for_me {
            // Translate abstract mask u (permuted positions) → real mask (ids).
            let mut u_real = 0u8;
            for i in 0..params.n {
                if u & (1 << i) != 0 {
                    u_real |= 1 << perm[i as usize];
                }
            }
            let share = self
                .shares
                .get(&u_real)
                .ok_or_else(|| Error::Validation("missing share in sharing pattern".into()))?;
            for j in 0..L {
                s1h[j] = s1h[j].add(&share.s1h[j]);
            }
            for j in 0..K {
                s2h[j] = s2h[j].add(&share.s2h[j]);
            }
        }
        Ok((s1h, s2h))
    }
}

/// Expands matrix `A` (row-major `K×L`, NTT domain) from `rho`.
pub fn expand_matrix(rho: &[u8; 32]) -> Vec<Poly> {
    let mut a = Vec::with_capacity(K * L);
    for i in 0..K {
        for j in 0..L {
            a.push(hazmat::sample_ntt_poly(rho, j as u8, i as u8));
        }
    }
    a
}
