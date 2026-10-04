//! Legacy threshold ECDSA (GG18/GG20) — Paillier + MtA — for migrating keys
//! saved in the legacy GG18/GG20 save format.
//!
//! The save data and wire messages follow that format **byte for byte**, so
//! existing serialized keys load here and keep signing. The cryptographic core (Paillier homomorphic encryption, MtA
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
#[cfg(all(test, feature = "json"))]
mod testvec;

use crate::prelude::*;
pub use import::import_key;
pub use key::Key;
pub use keygen::KeygenParty;
pub use prepare::LocalPreParams;
pub use resharing::ResharingParty;
pub use signing::{SignatureData, SigningParty};
pub(crate) mod vss;

/// Errors raised by the `ecdsatss` protocol.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A value failed an internal consistency or proof check.
    Validation(String),
    /// A key or message failed to encode or decode (JSON or binary).
    Serde(crate::tss::CodecError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "ecdsatss: {m}"),
            Error::Serde(e) => write!(f, "ecdsatss: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::tss::CodecError> for Error {
    fn from(e: crate::tss::CodecError) -> Self {
        Error::Serde(e)
    }
}

impl From<crate::wire::Error> for Error {
    fn from(e: crate::wire::Error) -> Self {
        Error::Serde(e.into())
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.into())
    }
}
