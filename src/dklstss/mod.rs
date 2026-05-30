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
//! - Malicious-secure signing (Mul-then-check) with identifiable abort
//! - Versioned key save/load for persistence
//!
//! Peer **authentication** is out of scope (the broker is trusted to
//! authenticate message origin). Peer **equivocation** is caught
//! cryptographically by an echo-broadcast phase in keygen/refresh/reshare:
//! disagreeing SHA-256 digests abort with the offending dealer in
//! [`crate::tss::TssError::culprits`].
//!
//! # Status
//!
//! Not yet implemented — this is a scaffold. It depends on secp256k1 scalar /
//! point arithmetic and an oblivious-transfer stack in `purecrypto` (see the
//! crate README's "purecrypto requirements").
