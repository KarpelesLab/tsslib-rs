//! # tsslib
//!
//! Easy-to-use threshold signature schemes in pure Rust. This crate is a port
//! of the broker-based protocols from the Go [`tss-lib`] and aims to be **wire-
//! and save-data-compatible** with it: messages serialized by one
//! implementation are consumed by the other, and persisted key shares
//! round-trip across both.
//!
//! [`tss-lib`]: https://github.com/KarpelesLab/tss-lib
//!
//! ## Protocols
//!
//! | Module                     | Scheme                                   | Output                  |
//! |----------------------------|------------------------------------------|-------------------------|
//! | [`frosttss`]               | FROST(Ed25519, SHA-512), RFC 9591        | Ed25519 signatures      |
//! | [`frostristretto255tss`]   | FROST(ristretto255, SHA-512), RFC 9591   | Ristretto255 signatures |
//! | [`mldsatss`]               | Threshold ML-DSA-44 (FIPS 204)           | ML-DSA signatures       |
//! | [`dklstss`]                | Threshold ECDSA / secp256k1 (DKLs23)     | ECDSA signatures        |
//!
//! Each protocol is gated behind a like-named cargo feature (all enabled by
//! default).
//!
//! ## Core
//!
//! The [`tss`] module holds the transport-agnostic core shared by every
//! protocol: [`tss::PartyId`], the rich [`tss::TssError`], and the JSON
//! message/broker plumbing ([`tss::JsonMessage`], [`tss::MessageBroker`]).
//!
//! ## Cryptography
//!
//! Low-level group, scalar, and lattice arithmetic is provided by the
//! [`purecrypto`](https://github.com/KarpelesLab/purecrypto) crate. This crate
//! contains no hand-rolled field arithmetic of its own.

#![forbid(unsafe_code)]

pub mod tss;

#[cfg(feature = "frosttss")]
pub mod frosttss;

#[cfg(feature = "frostristretto255tss")]
pub mod frostristretto255tss;

#[cfg(feature = "mldsatss")]
pub mod mldsatss;

#[cfg(feature = "dklstss")]
pub mod dklstss;
