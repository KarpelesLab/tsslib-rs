//! Legacy threshold EdDSA (GG18-style) on Ed25519 — Feldman VSS + threshold
//! Schnorr — for migrating existing keys in the legacy GG18-style format.
//!
//! Unlike [`ecdsatss`](crate::ecdsatss) this scheme needs no Paillier or MtA:
//! keygen is a Feldman-VSS DKG with Schnorr proofs of knowledge, and signing is a
//! commit/reveal threshold Schnorr producing a standard Ed25519 signature
//! (verifiable by any stock Ed25519 verifier). The wire and save-data formats
//! are fixed so existing serialized keys load directly.
//!
//! # Warning
//!
//! Experimental and not independently audited. Provided to enable migration off
//! the legacy protocol.

pub(crate) mod commit;
pub(crate) mod ed;
pub mod import;
pub mod key;
pub mod keygen;
pub mod resharing;
pub(crate) mod schnorr;
pub mod signing;
#[cfg(all(test, feature = "json"))]
mod testvec;
pub(crate) mod vss;

use crate::prelude::*;
pub use import::import_key;
pub use key::Key;
pub use keygen::KeygenParty;
pub use resharing::ResharingParty;
pub use signing::{SignatureData, SigningParty};

/// Errors raised by the `eddsatss` protocol.
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
            Error::Validation(m) => write!(f, "eddsatss: {m}"),
            Error::Serde(e) => write!(f, "eddsatss: {e}"),
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
