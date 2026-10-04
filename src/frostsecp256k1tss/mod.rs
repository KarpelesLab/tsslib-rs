//! FROST(secp256k1, SHA-256) threshold Schnorr signatures for Bitcoin
//! Taproot (BIP340 / BIP341).
//!
//! A broker-based keygen, signing and resharing whose output is a standard
//! 64-byte BIP340 signature, verifiable by any BIP340 verifier (e.g. Bitcoin
//! Core for a Taproot key-path spend). Signing can target:
//!
//! - the group's x-only key (plain BIP340),
//! - a non-hardened BIP32 child of it ([`Key::derive_child`]; standard
//!   `CKDpub`, so the group key plus [`Key::chain_code`] acts as an xpub),
//! - the BIP341 output key for either of those, with or without a script
//!   tree ([`TaprootTweak`]; [`Key::taproot_output_key`] gives the key that
//!   goes in the `scriptPubKey`).
//!
//! [`import_key`] turns an existing secp256k1 private key (optionally with
//! its BIP32 chain code) into a 1-of-1 key to reshare from.
//!
//! The FROST core follows RFC 9591's FROST(secp256k1, SHA-256) ciphersuite
//! under its own context string (`FROST-secp256k1-SHA256-TR-v1`) and swaps
//! the challenge hash for BIP340's, as the Zcash Foundation's
//! `frost-secp256k1-tr` does; even-`Y` handling happens at signing time (see
//! [`signing`](self#signing)). Its wire messages are this crate's own format and
//! are not shared with other FROST implementations.
//!
//! # Signing
//!
//! Signing is two rounds. Shares stay as dealt; the key being signed for is
//! fixed per session from the [`SignOptions`], and every signer scales its
//! share and nonces by the needed signs. The binding factors commit to that
//! key, so signers that disagree on the options fail partial-signature
//! verification rather than producing a bad signature, and every aggregate is
//! checked with a BIP340 verifier before it is returned.

mod hd;
mod key;
mod keygen;
mod resharing;
mod signature;
mod signing;
mod suite;
mod vss;

use crate::prelude::*;
pub use hd::{HARDENED_KEY_START, derive_chain_code, import_key};
pub use key::{KEY_VERSION, Key};
pub use keygen::Keygen;
pub use purecrypto::ec::secp256k1::{ProjectivePoint, Scalar};
pub use resharing::Resharing;
pub use signature::SignatureData;
pub use signing::{SignOptions, Signing, TaprootTweak};

/// Errors raised by the `frostsecp256k1tss` protocols.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A [`Key`] or message failed a consistency check.
    Validation(String),
    /// A key or message failed to encode or decode (JSON or binary).
    Serde(crate::tss::CodecError),
    /// A protocol-round error (carries victim / culprits).
    Tss(Box<crate::tss::TssError>),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "frostsecp256k1tss: {m}"),
            Error::Serde(e) => write!(f, "frostsecp256k1tss: {e}"),
            Error::Tss(e) => write!(f, "{e}"),
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

impl From<crate::tss::TssError> for Error {
    fn from(e: crate::tss::TssError) -> Self {
        Error::Tss(Box::new(e))
    }
}
