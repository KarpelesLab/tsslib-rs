//! # tsslib
//!
//! Easy-to-use threshold signature schemes in pure Rust. The broker-based
//! protocols exchange messages through a transport the caller supplies, and
//! key shares persist to bytes; both formats are stable across releases.
//!
//! ## Encodings
//!
//! Keys and messages have two encodings:
//!
//! - **JSON** (`json` feature, on by default): the format earlier releases
//!   used, unchanged. Keys: `to_json` / `from_json`; messages:
//!   [`tss::Message::to_json`] / [`tss::Message::from_json`].
//! - **Binary** (always available): the compact [`wire`] format, read and
//!   written as a stream through [`wire::Read`] / [`wire::Write`], with no
//!   serde_json. Keys: `write_to` / `read_from` (or `to_bytes` /
//!   `from_bytes`); messages: [`tss::Message::write_to`] /
//!   [`tss::Message::read_from`]. Typically 2–3.5× smaller than JSON.
//!
//! A session's message encoding is fixed in its [`tss::Parameters`] (or
//! [`tss::ReSharingParameters`]) with `with_wire_format`; all parties of a
//! session must use the same one. The default is JSON when the `json` feature
//! is enabled and binary otherwise. For embedded targets, disable default
//! features and leave out `json` and `error-messages` (the latter keeps
//! serde's text in [`wire::Error::Message`]; without it a refused value is
//! reported as [`wire::Error::Invalid`]).
//!
//! ## Protocols
//!
//! | Module                     | Scheme                                   | Output                  |
//! |----------------------------|------------------------------------------|-------------------------|
//! | [`frosttss`]               | FROST(Ed25519, SHA-512), RFC 9591        | Ed25519 signatures      |
//! | [`frostristretto255tss`]   | FROST(ristretto255, SHA-512), RFC 9591   | Ristretto255 signatures |
//! | [`frostsecp256k1tss`]      | FROST(secp256k1, SHA-256), RFC 9591      | BIP340 / Taproot        |
//! | [`mldsatss`]               | Threshold ML-DSA-44 (FIPS 204)           | ML-DSA signatures       |
//! | [`dklstss`]                | Threshold ECDSA / secp256k1 (DKLs23)     | ECDSA signatures        |
//! | [`ecdsatss`]               | Legacy threshold ECDSA (GG18/GG20)       | ECDSA signatures        |
//! | [`eddsatss`]               | Legacy threshold EdDSA (GG18-style)      | Ed25519 signatures      |
//!
//! Each protocol is gated behind a like-named cargo feature (all enabled by
//! default).
//!
//! ## Core
//!
//! The [`tss`] module holds the transport-agnostic core shared by every
//! protocol: [`tss::PartyId`], the rich [`tss::TssError`], and the
//! message/broker plumbing ([`tss::Message`], [`tss::MessageBroker`]).
//!
//! ## Cryptography
//!
//! Low-level group, scalar, and lattice arithmetic is provided by the
//! [`purecrypto`](https://github.com/KarpelesLab/purecrypto) crate. This crate
//! contains no hand-rolled field arithmetic of its own.
//!
//! ## `no_std`
//!
//! The crate is `#![no_std]` and needs only `alloc`. The default `std` feature
//! adds:
//!
//! - OS randomness. Without `std` (outside `wasm32-unknown-unknown`, where the
//!   host supplies entropy), register a CSPRNG with
//!   [`rng::set_entropy_source`] before starting any session.
//! - The blocking `wait()` on every session type. Without `std`, poll
//!   `try_result()` after feeding each inbound message instead.
//! - OS-backed locks; the `no_std` build uses spin locks.

#![no_std]
#![forbid(unsafe_code)]
// The shared `tss` helpers are only partly reachable when a subset of the
// protocols is enabled; dead-code analysis stays on for the full build.
#![cfg_attr(
    not(all(
        feature = "frosttss",
        feature = "frostristretto255tss",
        feature = "frostsecp256k1tss",
        feature = "mldsatss",
        feature = "dklstss",
        feature = "ecdsatss",
        feature = "eddsatss"
    )),
    allow(dead_code)
)]

#[macro_use]
extern crate alloc;

// Tests always link `std` (threads, the in-process test hub, `f64::exp`).
#[cfg(any(feature = "std", test))]
extern crate std;

mod prelude;
pub mod rng;
#[cfg(any(
    feature = "frosttss",
    feature = "frostristretto255tss",
    feature = "frostsecp256k1tss"
))]
mod share_aead;
mod sync;
pub mod tss;
mod vecmap;
pub mod wire;

/// Shared FROST core (RFC 9591), used by the Ed25519 and ristretto255 variants.
#[cfg(any(feature = "frosttss", feature = "frostristretto255tss"))]
pub mod frost;

#[cfg(feature = "frosttss")]
pub mod frosttss;

#[cfg(feature = "frostristretto255tss")]
pub mod frostristretto255tss;

#[cfg(feature = "frostsecp256k1tss")]
pub mod frostsecp256k1tss;

#[cfg(feature = "mldsatss")]
pub mod mldsatss;

#[cfg(feature = "dklstss")]
pub mod dklstss;

#[cfg(feature = "ecdsatss")]
pub mod ecdsatss;

#[cfg(feature = "eddsatss")]
pub mod eddsatss;
