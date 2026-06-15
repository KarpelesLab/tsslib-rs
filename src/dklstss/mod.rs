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
//! The **default** signing path ([`sign`] / [`SigningParty`]) uses the *plain*
//! OT-based Gilboa multiplication in [`ole`]: Alice's raw secret bits are the
//! OT choice bits and Bob's correction values are unverified. It implements no
//! πMul input-consistency check, so a malicious co-signer can mount a
//! **selective-failure attack**: by corrupting a single chosen OT row or
//! correction value, the session either produces a valid signature or aborts
//! at the final `ecdsa_verify` gate depending on one bit of the victim's
//! secret share/nonce — leaking roughly one bit per aborted signing session.
//! This default path is kept **byte-compatible with Go tss-lib's default
//! (unchecked) signing** on purpose, so it is not changed.
//!
//! ## Opt-in malicious-security: the *checked* signing path
//!
//! An **opt-in** Mul-then-check variant (DKLs23 §5) is now available and
//! **SHOULD be used whenever co-signers are not mutually trusted**:
//! - [`sign_checked`] / [`sign_checked_with_tweak`] — synchronous in-process;
//! - [`CheckedSigningParty`] — broker-driven, the security-relevant one
//!   (a genuinely remote malicious peer can only deviate over the wire).
//!
//! Each cross-term ΠMul is run **twice in parallel** under sub-session-ids
//! `sid|1` and `sid|2` with the same `α`; Bob attaches a cross-run consistency
//! value `Z = u_B1 − u_B2` and Alice rejects unless `Z_A + Z ≡ 0 (mod n)`
//! (see [`ole_check`]). A peer who uses inconsistent `β` across the two runs —
//! the lever of the selective-failure attack — is caught, and in
//! [`CheckedSigningParty`] the offending peer is named in
//! [`crate::tss::TssError::culprits`] (identifiable abort). Cost is roughly
//! 2× the wire/CPU of the default path.
//!
//! **Inherited limitation (matches Go):** this simplified check catches an
//! *inconsistent* `β` across the two runs but **not** a *consistently wrong*
//! `β` (same wrong value in both runs); that residual class is caught only at
//! the signing layer by the final ECDSA verification gate. The full
//! identifiable-abort variant with a Pedersen-style `β` commitment is Go's
//! task #17 and is intentionally not ported.
//!
//! Mitigations that apply to **both** paths: echo-broadcast consistency checks
//! in keygen/refresh/reshare, single-use enforcement of presignatures, the KOS
//! consistency check against a malicious OT-extension *receiver*, and the
//! final verification gate (no invalid signature is ever released).
//!
//! When the **default** (unchecked) path is used with untrusted peers,
//! operators MUST:
//! - treat **repeated signing failures with the same participant set as a
//!   potential attack**, not a transient error;
//! - **not retry indefinitely**: bound retries, and after a small number of
//!   unexplained aborts stop signing with that set;
//! - rotate the key (reshare to exclude the suspect, or generate a fresh key)
//!   once an attack is suspected, since each abort may have leaked a share
//!   bit;
//! - or switch to the opt-in checked path above, which closes the
//!   selective-failure oracle for the inconsistent-`β` case.
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
pub(crate) mod ole_check;
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
pub use signing::{sign, sign_checked, sign_checked_with_tweak, sign_with_tweak};
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
