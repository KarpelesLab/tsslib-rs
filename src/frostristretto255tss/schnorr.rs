//! Schnorr proof of knowledge over Ristretto255, with a Fiat-Shamir challenge
//! `SHA-512(ctx || "schnorr-pok" || session || X || R) mod L`. Port of the
//! `schnorrProof` helpers in frostristretto255tss/internal.go.

use super::Error;
use crate::frost::{Ciphersuite, Ristretto255, Scalar, scalar_from_be_mod_l, scalar_to_be};
use purecrypto::ec::ristretto255::RistrettoPoint;
use purecrypto::hash::sha512;
use purecrypto::rng::RngCore;

/// A Schnorr proof of knowledge of `x` with `X = x·G`.
pub struct ZkProof {
    /// Announcement `R = k·G`.
    pub r: RistrettoPoint,
    /// Response `t = k + c·x` (mod `L`).
    pub t: Scalar,
}

impl ZkProof {
    /// Proves knowledge of `x` (with `x_pub = x·G`), bound to `session`.
    pub fn prove(
        session: &[u8],
        x: &Scalar,
        x_pub: &RistrettoPoint,
        rng: &mut impl RngCore,
    ) -> Self {
        let mut kb = [0u8; 64];
        rng.fill_bytes(&mut kb);
        let k = Scalar::from_bytes_mod_order(&kb);
        let r = Ristretto255::mul_base(&k);
        let c = challenge(session, x_pub, &r);
        let t = k.add(&c.mul(x));
        ZkProof { r, t }
    }

    /// Verifies the proof for `x_pub`, bound to `session`: `t·G == R + c·X`.
    pub fn verify(&self, session: &[u8], x_pub: &RistrettoPoint) -> bool {
        let c = challenge(session, x_pub, &self.r);
        let lhs = Ristretto255::mul_base(&self.t);
        let rhs = Ristretto255::add(&self.r, &Ristretto255::scalar_mul(x_pub, &c));
        Ristretto255::eq(&lhs, &rhs)
    }

    /// Wire encoding: `(R as 32-byte canonical, t as big-endian minimal)`.
    pub fn to_wire(&self) -> (Vec<u8>, Vec<u8>) {
        (
            Ristretto255::encode_point(&self.r).to_vec(),
            scalar_to_be(&self.t),
        )
    }

    /// Decodes a proof from its wire form.
    pub fn from_wire(r_bytes: &[u8], t_bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 32] = r_bytes
            .try_into()
            .map_err(|_| Error::Validation("Schnorr R must be 32 bytes".into()))?;
        let r = Ristretto255::decode_point(&arr)
            .ok_or_else(|| Error::Validation("invalid Schnorr R".into()))?;
        Ok(ZkProof {
            r,
            t: scalar_from_be_mod_l(t_bytes),
        })
    }
}

fn challenge(session: &[u8], x_pub: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
    let mut buf = Vec::new();
    buf.extend_from_slice(Ristretto255::context_string());
    buf.extend_from_slice(b"schnorr-pok");
    buf.extend_from_slice(session);
    buf.extend_from_slice(&Ristretto255::encode_point(x_pub));
    buf.extend_from_slice(&Ristretto255::encode_point(r));
    Scalar::from_bytes_mod_order(&sha512(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::rng::OsRng;

    fn rand_scalar() -> Scalar {
        let mut b = [0u8; 64];
        OsRng.fill_bytes(&mut b);
        Scalar::from_bytes_mod_order(&b)
    }

    #[test]
    fn prove_then_verify() {
        let x = rand_scalar();
        let xp = Ristretto255::mul_base(&x);
        let pf = ZkProof::prove(b"session", &x, &xp, &mut OsRng);
        assert!(pf.verify(b"session", &xp));
        assert!(!pf.verify(b"other", &xp));
    }

    #[test]
    fn wire_roundtrip() {
        let x = rand_scalar();
        let xp = Ristretto255::mul_base(&x);
        let pf = ZkProof::prove(b"s", &x, &xp, &mut OsRng);
        let (r, t) = pf.to_wire();
        assert!(ZkProof::from_wire(&r, &t).unwrap().verify(b"s", &xp));
    }
}
