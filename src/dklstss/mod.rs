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
//! - Versioned key save/load for persistence
//!
//! Peer **authentication** is out of scope (the broker is trusted to
//! authenticate message origin). Peer **equivocation** is caught
//! cryptographically by an echo-broadcast phase in keygen/refresh/reshare:
//! disagreeing SHA-256 digests abort with the offending dealer in
//! [`crate::tss::TssError::culprits`].
//!
//! # Security: malicious signers and selective-failure aborts
//!
//! Signing is **not yet fully malicious-secure**. The OT-based Gilboa
//! multiplication in [`ole`] uses Alice's raw secret bits as OT choice bits
//! and does **not** implement the πMul input-consistency / multiplication
//! check from DKLs23 (ePrint 2023/765); Bob's correction values are
//! unverified. A malicious co-signer can therefore mount a
//! **selective-failure attack**: by corrupting a single chosen OT row or
//! correction value, the session either produces a valid signature or aborts
//! at the final `ecdsa_verify` gate depending on one bit of the victim's
//! secret share/nonce — leaking roughly one bit per aborted signing session.
//!
//! Mitigations that *are* in place: echo-broadcast consistency checks in
//! keygen/refresh/reshare, single-use enforcement of presignatures, the KOS
//! consistency check against a malicious OT-extension *receiver*, and the
//! final verification gate (no invalid signature is ever released).
//!
//! Until the πMul check lands — it requires a coordinated wire-format change
//! with the Go implementation, so it is deferred — operators MUST:
//! - treat **repeated signing failures with the same participant set as a
//!   potential attack**, not a transient error;
//! - **not retry indefinitely**: bound retries, and after a small number of
//!   unexplained aborts stop signing with that set;
//! - rotate the key (reshare to exclude the suspect, or generate a fresh key)
//!   once an attack is suspected, since each abort may have leaked a share
//!   bit.
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
mod presign;
mod refresh_party;
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
pub use presign::{
    InMemoryPresignStore, PresignOutput, UsedPresignStore, presign, sign_with_presign,
    sign_with_presign_durable,
};
pub use refresh_party::RefreshParty;
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
