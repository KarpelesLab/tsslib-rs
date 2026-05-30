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
//! Not yet implemented — this is a scaffold. Lattice arithmetic (NTT,
//! polynomial sampling, packing) will be provided by `purecrypto`'s `mldsa`
//! module.
