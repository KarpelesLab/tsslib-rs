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
