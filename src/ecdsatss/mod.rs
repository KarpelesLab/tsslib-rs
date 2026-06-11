//! Legacy threshold ECDSA (GG18/GG20) — Paillier + MtA — for migrating keys from
//! the Go `tss-lib/ecdsatss`.
//!
//! This port aims for **byte-for-byte save-data and wire compatibility** with the
//! Go implementation so existing serialized keys load here and signatures
//! interoperate. The cryptographic core (Paillier homomorphic encryption, MtA
//! multiplicative-to-additive share conversion with range proofs, and the
//! dlog-N / no-small-factor / Paillier-Blum ZK proofs) is built on
//! `purecrypto::bignum::BoxedUint`.
//!
//! # Warning
//!
//! **Experimental and not independently audited.** Paillier + MtA range proofs
//! are the threshold-ECDSA family with a notorious history of catastrophic
//! implementation bugs (TSSHOCK, Alpha-Rays). This code is provided to enable
//! migration off the legacy protocol; new deployments should prefer the
//! OT-based [`dklstss`](crate::dklstss), which avoids Paillier entirely.

pub(crate) mod bn;
pub(crate) mod commit;
pub(crate) mod dlnproof;
pub(crate) mod facproof;
pub mod import;
pub mod key;
pub mod keygen;
pub(crate) mod modproof;
pub(crate) mod mta;
pub mod paillier;
pub mod prepare;
pub mod resharing;
pub(crate) mod schnorr;
pub(crate) mod secp;
pub mod signing;
#[cfg(test)]
mod testvec;
pub(crate) mod vss;

/// Errors raised by the `ecdsatss` protocol.
#[derive(Debug)]
pub enum Error {
    /// A value failed an internal consistency or proof check.
    Validation(String),
    /// A JSON (de)serialization error.
    Serde(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "ecdsatss: {m}"),
            Error::Serde(e) => write!(f, "ecdsatss: json: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}
