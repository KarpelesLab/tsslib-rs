//! Threshold ECDSA on secp256k1 — DKLs23 (ePrint 2023/765).
//!
//! Implements threshold ECDSA following the DKLs23 protocol (Doerner, Kondi,
//! Lee, Shelat, "Threshold ECDSA in Three Rounds"). Built on oblivious-transfer
//! extension rather than Paillier/MtA, sidestepping the RSA/Paillier-proof
//! attack surface (TSSHOCK, Alpha-Rays, …) of GG18 implementations.
//!
//! Planned surface:
//! - n-party t-of-n distributed key generation (Feldman VSS based)
//! - (t+1)-party threshold signing producing standard ECDSA signatures
//! - Pre-signing as a separate offline phase with single-use online sign
//! - Proactive share + OT-extension refresh
//! - Resharing to a new committee preserving the public key
//! - HD wallet derivation (BIP32 non-hardened) at sign time
//! - Malicious-secure signing (Mul-then-check) with identifiable abort
//! - Versioned key save/load for persistence
//!
//! Peer **authentication** is out of scope (the broker is trusted to
//! authenticate message origin). Peer **equivocation** is caught
//! cryptographically by an echo-broadcast phase in keygen/refresh/reshare:
//! disagreeing SHA-256 digests abort with the offending dealer in
//! [`crate::tss::TssError::culprits`].
//!
//! # Status
//!
//! In progress. The secp256k1 group layer and OT stack are built on
//! `purecrypto`'s secp256k1 primitives; higher protocol layers follow.

// dklstss is under active construction: lower layers (secp/OT) are exercised by
// tests and by the not-yet-landed protocol layers. Remove once keygen/signing
// wire everything together.
#![allow(dead_code)]

pub(crate) mod baseot;
mod echo;
mod hd;
mod key;
mod keygen;
mod keygen_party;
pub(crate) mod ole;
pub(crate) mod otext;
mod resharing;
mod resharing_party;
pub(crate) mod schnorr;
pub(crate) mod secp;
mod serialize;
mod setup;
mod signing;
mod signing_party;
pub(crate) mod vss;

pub use hd::{HARDENED_KEY_START, derive_and_sign, derive_child, import_key};
pub use key::{Key, PairOTState, Signature};
pub use keygen::{derive_chain_code, keygen};
pub use keygen_party::KeygenParty;
pub use resharing::{refresh, reshare};
pub use resharing_party::ResharingParty;
pub use signing::{sign, sign_with_tweak};
pub use signing_party::SigningParty;

/// Errors raised by the `dklstss` protocols.
#[derive(Debug)]
pub enum Error {
    /// A value failed an internal consistency check.
    Validation(String),
    /// A JSON (de)serialization error.
    Serde(serde_json::Error),
    /// A protocol-round error (carries victim / culprits).
    Tss(Box<crate::tss::TssError>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "dklstss: {m}"),
            Error::Serde(e) => write!(f, "dklstss: json: {e}"),
            Error::Tss(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<crate::tss::TssError> for Error {
    fn from(e: crate::tss::TssError) -> Self {
        Error::Tss(Box::new(e))
    }
}
