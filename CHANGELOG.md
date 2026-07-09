# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.5](https://github.com/KarpelesLab/tsslib-rs/compare/v0.2.4...v0.2.5) - 2026-07-09

### Other

- add SigningParty::new_with_kdd for additive child-key signing
- add SigningParty::new_with_kdd for BIP32 child-key signing

## [0.2.4](https://github.com/KarpelesLab/tsslib-rs/compare/v0.2.3...v0.2.4) - 2026-07-09

### Other

- transparently subset the old-committee key in resharing
- transparently subset the key in SigningParty::new
- add Key::subset_for_parties and public_key

## [0.2.3](https://github.com/KarpelesLab/tsslib-rs/compare/v0.2.2...v0.2.3) - 2026-06-19

### Fixed

- fix CI: rustfmt + rustdoc private-intra-doc-link errors

### Other

- append Go's #<attempt_id> suffix to round message types
- match Go's echo digest tags in CheckedSigningParty
- add broker-driven CheckedSigningParty + selective-failure negative test
- add synchronous sign_checked / sign_checked_with_tweak
- port opt-in Mul-then-check (CheckedAliceStep2) from Go
- use constant-time modexp for secret exponents
- document plaintext resharing shares require broker confidentiality
- document missing piMul check / selective-failure abort risk
- zeroize secret share and OT seed material on demand
- bounds-check party index in prepare_wi (audit finding 2)
- wipe transient share byte copies in keygen/resharing (audit finding 1)
- zeroize secret share Xi on Key drop (audit finding 1)
- harden parse_secrets length handling
- enforce minimum peer modulus bit length (Go parity)
- reject U-less ProofBob in MtA "with check" verification
- sample signing nonces in [1, q) like Go's GetRandomPositiveInt
- validate per-party round-3 responses before combine
- best-effort zeroization of key/keygen secret material
- zeroize raw X25519 shared secret in share AEAD
- cap decimal_to_be input length to prevent save-data DoS

## [0.2.2](https://github.com/KarpelesLab/tsslib-rs/compare/v0.2.1...v0.2.2) - 2026-06-11

### Other

- Go↔Rust save-data round-trip test
- Go byte-compatible save format (Save/Load v4)
- eddsatss P-final: public API, README, interop coverage
- eddsatss P3: resharing (5 rounds) + legacy key import
- eddsatss P2: signing (3 rounds) → standard Ed25519 signature
- eddsatss P1: keygen (3 rounds) + supporting modules
- eddsatss P0: scaffold + key save-data format (Go-compatible)

## [0.2.1](https://github.com/KarpelesLab/tsslib-rs/compare/v0.2.0...v0.2.1) - 2026-06-11

### Other

- use RELEASE_PLZ_TOKEN for release-plz instead of GITHUB_TOKEN
- Go/Rust interop workflow for ecdsatss (GG18) ([#3](https://github.com/KarpelesLab/tsslib-rs/pull/3))
- ecdsatss public API re-exports, docs, README
- GG18 resharing (5 rounds) + legacy key import
- GG18 signing (9 rounds) → standard ECDSA
- GG18 keygen 4-round state machine + supporting modules
- ecdsatss P4a: GG18 key save-data format (Go-compatible, migration linchpin)
- ecdsatss P3: MtA (multiplicative-to-additive) + range proofs
- ecdsatss P2b/c: facproof + modproof (GG18 ZK proofs complete)
- ecdsatss P2a: DLN proof (dlog over safe-prime product)
- ecdsatss P1: Paillier cryptosystem + GG18 key-correctness proof
- ecdsatss P0: scaffold + bn big-int helpers + Go fixture harness

## [0.2.0](https://github.com/KarpelesLab/tsslib-rs/compare/v0.1.0...v0.2.0) - 2026-06-10

### Other

- README — mldsatss broker sign + DKG, dklstss presign
- dealerless distributed key generation (DkgParty44, experimental)
- broker-driven threshold signing (SigningParty44)
- add presign + sign_with_presign (offline/online split)
- update README — all four protocols implemented
- implement threshold ML-DSA-44 signing — 4th protocol complete
- add 23-bit full-range polynomial packing (pack_polyq)
- broker-driven proactive refresh (RefreshParty)
- broker-driven distributed resharing (ResharingParty)
- broker-driven distributed signing (SigningParty)
- broker-driven distributed keygen + echo-broadcast layer
- trusted-dealer keygen for threshold ML-DSA-44
- bump purecrypto to v0.6.1 — unblocks mldsatss
- resharing + proactive refresh (synchronous)
- Key save/load (JSON persistence)
- BIP32 HD derivation + key import
- working DKLs23 threshold ECDSA (keygen + signing)
- OLE / Gilboa multiply-to-additive (ΠMul)
- SoftSpoken/KOS OT extension (otext)
- secp256k1 group + Schnorr PoK + Chou-Orlandi base-OT
- resharing — completes the protocol
- keygen (Pedersen DKG) + Schnorr PoK
- ciphersuite + Key + signing
- resharing (old->new committee, key-preserving)
- HD derivation (BIP32 non-hardened) + key import
- FROST Pedersen DKG (keygen) with encrypted shares
- two-round FROST(Ed25519) signing + broker plumbing
- Go-compatible Key + SignatureData
- shared FROST core (RFC 9591) generic over the group
- bump purecrypto to v0.5.1 + serde_json arbitrary_precision
- wire up purecrypto (git) with per-protocol feature mapping
