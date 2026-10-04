//! Threshold ML-DSA (FIPS 204) signing.
//!
//! Implements the ML-DSA variant from "Threshold Signatures Reloaded: ML-DSA
//! and Enhanced Raccoon with Identifiable Aborts" (Borin, Celi, del Pino,
//! Espitau, Niot, Prest — ePrint 2025/1166). It produces byte-identical FIPS 204
//! signatures that verify against a stock ML-DSA public key.
//!
//! The target is ML-DSA-44 with any `(threshold t, parties n)` where
//! `2 ≤ t ≤ n ≤ 6`. Key generation uses a trusted dealer (matching the paper's
//! reference); distributed key generation is future work.
//!
//! # Warning
//!
//! This is an academic-grade prototype. It has not received independent
//! cryptanalytic review and is **not** suitable for production use.
//!
//! # Status
//!
//! Trusted-dealer keygen ([`trusted_dealer_keygen44`]) and threshold signing
//! ([`sign44`]) are implemented and produce FIPS-204-verifiable signatures.
//! Built on `purecrypto`'s `mldsa::hazmat` lattice primitives; the hyperball
//! rejection sampler and full-range `w` packing live in this module. Distributed
//! key generation (no trusted dealer) is future work.

// Index-paired loops over polynomial vectors (`for j in 0..L { v[j]... }`) are
// idiomatic here and read closer to the FIPS 204 / reference math than iterator
// adapters would; allow them module-wide.
#![allow(clippy::needless_range_loop)]

mod hyperball;
mod key;
mod keygen;
mod keygen_party;
mod packing;
mod params;
mod signing;
mod signing_party;

use crate::prelude::*;
pub use key::{Key44, PolyVec, Share44};
pub use keygen::trusted_dealer_keygen44;
pub use keygen_party::DkgParty44;
pub use params::{GetThresholdParams44Error, ThresholdParams44, get_threshold_params44};
pub use purecrypto::mldsa::MlDsa44PublicKey as PublicKey;
pub use signing::{sign44, sign44_checked};
pub use signing_party::SigningParty44;

/// Errors raised by the `mldsatss` protocol.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A value failed an internal consistency check.
    Validation(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Validation(m) => write!(f, "mldsatss: {m}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::tss::CodecError> for Error {
    fn from(e: crate::tss::CodecError) -> Self {
        Error::Validation(format!("{e}"))
    }
}

impl From<crate::wire::Error> for Error {
    fn from(e: crate::wire::Error) -> Self {
        Error::Validation(format!("{e}"))
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Validation(format!("json: {e}"))
    }
}
