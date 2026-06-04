//! FROST(ristretto255, SHA-512) threshold signatures — RFC 9591 §6.2.
//!
//! A broker-based implementation providing keygen, signing, and resharing that
//! produce signatures in the natural Ristretto255 format (32-byte `R` || 32-byte
//! `S`). These are **not** Ed25519-compatible — use [`crate::frosttss`] for that.
//!
//! The protocol shape mirrors [`crate::frosttss`] over the Ristretto255
//! prime-order group (RFC 9496); the shared FROST math lives in [`crate::frost`]
//! and the scalar field is identical. The differences from the Ed25519 variant:
//! points encode as 32-byte canonical Ristretto255 (no affine coordinates), the
//! keygen proof-of-knowledge is a Schnorr proof over encoded points, and there
//! is no HD derivation.

mod commit;
mod key;
mod keygen;
mod resharing;
mod schnorr;
mod signature;
mod signing;

pub use key::{KEY_VERSION, Key};
pub use keygen::Keygen;
pub use resharing::Resharing;
pub use signature::SignatureData;
pub use signing::Signing;

/// Errors raised by the `frostristretto255tss` protocols.
#[derive(Debug)]
pub enum Error {
    /// A [`Key`] or message failed an internal consistency check.
    Validation(String),
    /// A JSON (de)serialization error.
    Serde(serde_json::Error),
    /// A protocol-round error (carries victim / culprits).
    Tss(Box<crate::tss::TssError>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "frostristretto255tss: {m}"),
            Error::Serde(e) => write!(f, "frostristretto255tss: json: {e}"),
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
