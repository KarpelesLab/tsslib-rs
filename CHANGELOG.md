# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
