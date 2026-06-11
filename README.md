# tsslib

[![CI](https://github.com/KarpelesLab/tsslib-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/tsslib-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/tsslib.svg)](https://crates.io/crates/tsslib)
[![docs.rs](https://img.shields.io/docsrs/tsslib)](https://docs.rs/tsslib)

Easy-to-use threshold signature schemes (TSS) in pure Rust.

`tsslib` is a Rust port of the broker-based protocols in the Go
[`tss-lib`](https://github.com/KarpelesLab/tss-lib). The goal is to be **wire-
and save-data-compatible** with the Go implementation: messages serialized by
one side are consumed by the other, and persisted key shares round-trip across
both languages. All low-level cryptography is provided by
[`purecrypto`](https://github.com/KarpelesLab/purecrypto) — this crate adds no
hand-rolled field arithmetic.

> **Status: all six protocols implemented.** Every scheme below produces
> signatures that verify under the corresponding stock verifier (Ed25519,
> ristretto255 Schnorr, secp256k1 ECDSA, FIPS-204 ML-DSA-44). See the per-module
> notes for which operations are broker-driven vs. in-process.

## Protocols

| Module                   | Scheme                                  | Output                  | Curve / field   |
|--------------------------|-----------------------------------------|-------------------------|-----------------|
| `frosttss`               | FROST(Ed25519, SHA-512) — RFC 9591      | Ed25519 signatures      | Edwards25519    |
| `frostristretto255tss`   | FROST(ristretto255, SHA-512) — RFC 9591 | Ristretto255 signatures | ristretto255    |
| `mldsatss`               | Threshold ML-DSA-44 — FIPS 204          | ML-DSA signatures       | ML-DSA-44       |
| `dklstss`                | Threshold ECDSA — DKLs23                | ECDSA signatures        | secp256k1       |
| `ecdsatss`               | Threshold ECDSA — GG18/GG20             | ECDSA signatures        | secp256k1       |
| `eddsatss`               | Threshold EdDSA — GG18-style            | Ed25519 signatures      | Edwards25519    |

The FROST protocols and `dklstss` provide keygen, signing, resharing/refresh,
and HD derivation routed through a caller-supplied [`tss::MessageBroker`];
`dklstss` also offers a synchronous in-process API plus offline pre-signing
(`presign` / `sign_with_presign` with single-use enforcement). `mldsatss`
(`2 ≤ t ≤ n ≤ 6`) provides trusted-dealer keygen, sync + broker-driven threshold
signing, and an **experimental** dealerless DKG (`DkgParty44` — no trusted
dealer; not independently reviewed). `ecdsatss` is a broker-driven port of the
legacy GG18/GG20 Paillier+MtA protocol (keygen, 9-round signing, resharing, and
1-of-1 `import_key`) provided for **migrating existing Go `tss-lib/ecdsatss` keys**
— it loads those save files byte-for-byte and signs with them; new deployments
should prefer `dklstss`. `eddsatss` is the EdDSA counterpart — a broker-driven
port of the legacy GG18-style threshold Ed25519 (Feldman VSS + threshold Schnorr,
no Paillier): keygen, 3-round signing, resharing, and 1-of-1 `import_key`, for
migrating existing Go `tss-lib/eddsatss` keys (it loads them and emits standard
Ed25519 signatures). Each module is gated behind a like-named
cargo feature, all enabled by default:

```toml
[dependencies]
tsslib = { version = "0.1", default-features = false, features = ["frosttss"] }
```

## Layout

```
src/
  tss/        core: PartyId, TssError, JsonMessage, MessageBroker
  frost/      shared FROST core: ciphersuite, binding, VSS, AEAD, commitments
  frosttss/                FROST(Ed25519)            keygen · sign · reshare · HD
  frostristretto255tss/    FROST(ristretto255)       keygen · sign · reshare
  mldsatss/                Threshold ML-DSA-44       dealer + DKG keygen · sync/broker sign (+ hyperball)
  dklstss/                 Threshold ECDSA (DKLs23)  sync + broker keygen/sign/reshare/refresh · presign
  ecdsatss/                Threshold ECDSA (GG18)    broker keygen/sign/reshare · import · Go save-data compat
  eddsatss/                Threshold EdDSA (GG18)    broker keygen/sign/reshare · import · standard Ed25519 out
```

## Security

Peer **authentication** is out of scope: the broker is trusted to authenticate
message origin (pin peer identities, sign transport messages, reject tampered
bytes). Peer **equivocation** is caught cryptographically where the protocol
provides an echo-broadcast phase (DKLs keygen/refresh/reshare). The `mldsatss`
protocol is an academic-grade prototype and is **not** production-ready. The
`ecdsatss` (GG18/GG20) port is **experimental and not independently audited** —
the Paillier + MtA range-proof family has a history of catastrophic
implementation bugs (TSSHOCK, Alpha-Rays); it exists to migrate legacy keys, and
new deployments should use `dklstss`. The `eddsatss` (threshold Ed25519) port is
likewise **experimental and not independently audited**, provided for migrating
legacy keys; new deployments should prefer `frosttss`.

## Cryptography

All low-level cryptography is delegated to `purecrypto`: the ristretto255 and
Edwards25519 groups + Curve25519 scalar field (FROST), secp256k1 scalar/point
ops (DKLs), and the ML-DSA-44 lattice primitives (`mldsa::hazmat`: NTT, polynomial
sampling, challenge sampling, bit-packing). `tsslib` adds no field arithmetic.

Two pieces of protocol logic that are *not* field arithmetic live here: the
DKLs23 oblivious-transfer stack (Chou-Orlandi base-OT + SoftSpoken/KOS
OT-extension + Gilboa OLE, in `dklstss`), and the threshold-ML-DSA constant-time
hyperball rejection sampler (a SHAKE256-seeded discrete Gaussian, in
`mldsatss/hyperball.rs`).

## License

MIT — see [LICENSE](LICENSE). Portions © 2019 Binance, © 2024 Karpeles Lab Inc.
