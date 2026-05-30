//! FROST(ristretto255, SHA-512) threshold signatures — RFC 9591 §6.2.
//!
//! A broker-based implementation providing keygen, signing, and resharing that
//! produce signatures in the natural Ristretto255 format (32-byte `R` || 32-byte
//! `S`).
//!
//! Ristretto255 signatures from this module are **not** Ed25519-compatible; use
//! [`crate::frosttss`] for Ed25519-compatible output.
//!
//! The protocol shape is identical to [`crate::frosttss`] but operates over the
//! Ristretto255 prime-order group (RFC 9496) rather than Edwards25519. Scalars
//! are interchangeable between the two groups (both use Curve25519's scalar
//! field), so much of the surface is structurally shared.
//!
//! # Status
//!
//! Not yet implemented — this is a scaffold. It depends on a ristretto255 group
//! implementation in `purecrypto`, which does not yet exist (see the crate
//! README's "purecrypto requirements").
