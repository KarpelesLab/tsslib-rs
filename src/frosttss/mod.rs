//! FROST(Ed25519, SHA-512) threshold signatures — RFC 9591.
//!
//! A broker-based implementation providing keygen, signing, and resharing that
//! produce signatures verifiable by any standard Ed25519 verifier.
//!
//! FROST is a Schnorr-based threshold scheme: keygen uses a Pedersen DKG
//! (RFC 9591 Appendix D) and signing uses two preprocessing+signing rounds with
//! a binding-factor mechanism that prevents nonce-reuse attacks.
//!
//! Keys produced here are **not** interchangeable with the GG18-style
//! `eddsatss` keys of the Go library: the DKG procedure differs and signatures
//! use FROST's binding-factor aggregation.
//!
//! # Broker contract
//!
//! All transport responsibilities are delegated to the [`crate::tss::MessageBroker`]
//! supplied by the caller. The broker MUST provide confidentiality on
//! per-recipient messages, authenticity on per-sender messages (peer
//! authentication is out of scope here), and reliable ordered delivery within
//! a single protocol instance. Round-2 DKG shares are additionally encrypted at
//! the application layer (X25519 + ChaCha20-Poly1305).
//!
//! # Status
//!
//! Not yet implemented — this is a scaffold. Group and scalar arithmetic will
//! be provided by `purecrypto`'s Edwards25519 primitives.
//!
//! References:
//! - RFC 9591: <https://www.rfc-editor.org/rfc/rfc9591.html>
//! - FROST paper: <https://eprint.iacr.org/2020/852>

mod hd;
mod key;
mod keygen;
mod point;
mod schnorr;
mod signature;
mod signing;

pub use hd::{HARDENED_KEY_START, derive_chain_code, import_key};
pub use key::{KEY_VERSION, Key};
pub use keygen::Keygen;
pub use point::PointError;
pub use signature::SignatureData;
pub use signing::Signing;

/// Errors raised by the `frosttss` protocols.
#[derive(Debug)]
pub enum Error {
    /// A [`Key`] failed an internal consistency check.
    Validation(String),
    /// A curve point could not be decoded.
    Point(PointError),
    /// A JSON (de)serialization error.
    Serde(serde_json::Error),
    /// A protocol-round error (carries victim / culprits). Boxed because
    /// [`crate::tss::TssError`] is large relative to the other variants.
    Tss(Box<crate::tss::TssError>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "frosttss: {m}"),
            Error::Point(e) => write!(f, "{e}"),
            Error::Serde(e) => write!(f, "frosttss: json: {e}"),
            Error::Tss(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<PointError> for Error {
    fn from(e: PointError) -> Self {
        Error::Point(e)
    }
}

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
