//! Legacy threshold EdDSA (GG18-style) on Ed25519 — Feldman VSS + threshold
//! Schnorr — for migrating keys from the Go `tss-lib/eddsatss`.
//!
//! Unlike [`ecdsatss`](crate::ecdsatss) this scheme needs no Paillier or MtA:
//! keygen is a Feldman-VSS DKG with Schnorr proofs of knowledge, and signing is a
//! commit/reveal threshold Schnorr producing a standard Ed25519 signature
//! (verifiable by any stock Ed25519 verifier). Wire and save-data formats match
//! the Go implementation so existing serialized keys load directly.
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
#[cfg(test)]
mod testvec;
pub(crate) mod vss;

pub use import::import_key;
pub use key::Key;
pub use keygen::KeygenParty;
pub use resharing::ResharingParty;
pub use signing::{SignatureData, SigningParty};

/// Errors raised by the `eddsatss` protocol.
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
            Error::Validation(m) => write!(f, "eddsatss: {m}"),
            Error::Serde(e) => write!(f, "eddsatss: json: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}
