//! `LocalPreParams` generation — the per-party Paillier key and ring-Pedersen
//! parameters (`Ñ, h1, h2`) that GG18 keygen consumes. Port of Go
//! `ecdsatss/prepare.go`.
//!
//! Generation needs four safe primes (two for the Paillier modulus, two for `Ñ`)
//! and is very slow at the production 1024-bit safe-prime size; tests pass a small
//! bit length or load cached params.

#![allow(dead_code)]

use super::bn::{self, Modulus};
use super::paillier::PrivateKey;
use purecrypto::bignum::BoxedUint;
use purecrypto::rng::RngCore;

/// Production safe-prime bit length (so `Ñ` and the Paillier modulus are 2048-bit).
pub const SAFE_PRIME_BITS: usize = 1024;

/// One party's pre-parameters: Paillier secret key plus ring-Pedersen setup.
#[derive(Clone)]
pub struct LocalPreParams {
    pub paillier_sk: PrivateKey,
    pub ntilde_i: BoxedUint,
    pub h1i: BoxedUint,
    pub h2i: BoxedUint,
    pub alpha: BoxedUint,
    pub beta: BoxedUint,
    /// Sophie-Germain factor of the first `Ñ` safe prime (a dlnproof witness).
    pub p: BoxedUint,
    /// Sophie-Germain factor of the second `Ñ` safe prime.
    pub q: BoxedUint,
}

impl LocalPreParams {
    /// Generates fresh pre-parameters. `safe_prime_bits` is the safe-prime size
    /// (use [`SAFE_PRIME_BITS`] in production, a small value in tests).
    pub fn generate<R: RngCore>(safe_prime_bits: usize, rng: &mut R) -> LocalPreParams {
        // Paillier modulus N = (safe prime)·(safe prime).
        let pai_p = bn::generate_safe_prime(safe_prime_bits, rng);
        let pai_q = bn::generate_safe_prime(safe_prime_bits, rng);
        let paillier_sk = PrivateKey::from_primes(pai_p, pai_q);

        // Ñ = SafeP·SafeQ; the QR subgroup has order p·q (the Germain factors).
        let (p, safe_p) = bn::generate_germain(safe_prime_bits, rng);
        let (q, safe_q) = bn::generate_germain(safe_prime_bits, rng);
        let ntilde_i = bn::mul(&safe_p, &safe_q);
        let ord = bn::mul(&p, &q);

        let modn = Modulus::new(&ntilde_i);
        let f1 = bn::rand_unit(&ntilde_i, rng);
        let (alpha, beta) = loop {
            let a = bn::rand_unit(&ntilde_i, rng);
            if let Some(b) = bn::mod_inv(&a, &ord) {
                break (a, b);
            }
        };
        let h1i = modn.mul(&f1, &f1);
        let h2i = modn.pow(&h1i, &alpha);

        LocalPreParams {
            paillier_sk,
            ntilde_i,
            h1i,
            h2i,
            alpha,
            beta,
            p,
            q,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsatss::dlnproof;
    use purecrypto::rng::OsRng;

    #[test]
    #[ignore = "safe-prime generation is slow"]
    fn generate_yields_valid_dln_setup() {
        let mut rng = OsRng;
        let pp = LocalPreParams::generate(256, &mut rng);
        // h2 = h1^alpha and the dlnproof (witness = Germain factors) verifies.
        let proof = dlnproof::prove(
            &pp.h1i,
            &pp.h2i,
            &pp.alpha,
            &pp.p,
            &pp.q,
            &pp.ntilde_i,
            &mut rng,
        );
        assert!(dlnproof::verify(&proof, &pp.h1i, &pp.h2i, &pp.ntilde_i));
    }
}
