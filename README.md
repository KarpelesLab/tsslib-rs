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

> ⚠️ **Status: early scaffolding.** The core message/identity/error plumbing is
> in place and tested. The four protocols below are stubs pending the
> `purecrypto` additions listed at the end of this README.

## Protocols

| Module                   | Scheme                                  | Output                  | Curve / field   |
|--------------------------|-----------------------------------------|-------------------------|-----------------|
| `frosttss`               | FROST(Ed25519, SHA-512) — RFC 9591      | Ed25519 signatures      | Edwards25519    |
| `frostristretto255tss`   | FROST(ristretto255, SHA-512) — RFC 9591 | Ristretto255 signatures | ristretto255    |
| `mldsatss`               | Threshold ML-DSA-44 — FIPS 204          | ML-DSA signatures       | ML-DSA-44       |
| `dklstss`                | Threshold ECDSA — DKLs23                | ECDSA signatures        | secp256k1       |

Each protocol provides keygen, signing, and (where applicable) resharing,
routed through a caller-supplied [`tss::MessageBroker`]. Each is gated behind a
like-named cargo feature, all enabled by default:

```toml
[dependencies]
tsslib = { version = "0.1", default-features = false, features = ["frosttss"] }
```

## Layout

```
src/
  tss/        core: PartyId, TssError, JsonMessage, MessageBroker  (implemented)
  frosttss/                FROST(Ed25519)            (stub)
  frostristretto255tss/    FROST(ristretto255)       (stub)
  mldsatss/                Threshold ML-DSA-44       (stub)
  dklstss/                 Threshold ECDSA (DKLs23)  (stub)
```

## Security

Peer **authentication** is out of scope: the broker is trusted to authenticate
message origin (pin peer identities, sign transport messages, reject tampered
bytes). Peer **equivocation** is caught cryptographically where the protocol
provides an echo-broadcast phase (DKLs keygen/refresh/reshare). The `mldsatss`
protocol is an academic-grade prototype and is **not** production-ready.

## purecrypto requirements

The protocols here need primitives that `purecrypto` does not yet expose. These
are the changes to request from the `purecrypto` maintainer, roughly in
dependency order:

1. **ristretto255 group** (RFC 9496) — entirely missing. Needs group element
   encode/decode (32-byte canonical), point add/sub, scalar·point and
   scalar·basepoint, identity/equality checks, and `hash-to-group` /
   wide-reduce-from-64-bytes. Required by `frostristretto255tss`.
2. **Exposed Edwards25519 group + scalar arithmetic.** Today `ec::ed25519` only
   exposes signing; FROST needs public point ops (add, scalar mul, basepoint
   mul, compressed encode/decode, identity check) and Curve25519 scalar-field
   ops (add/sub/mul/invert, reduce-from-64-bytes, canonical 32-byte
   serialization). Required by `frosttss` (and shared with the ristretto work —
   both groups use the same scalar field).
3. **Exposed secp256k1 scalar + point arithmetic.** `ec` has the secp256k1
   curve internally; DKLs needs public scalar field ops and point add/scalar-mul
   plus compressed SEC1 encode/decode. Required by `dklstss`.
4. **Oblivious-transfer building blocks** (base-OT + OT-extension) or agreement
   that these live in `tsslib`. DKLs23 builds its multiplication from OT
   extension; if `purecrypto` won't host them, they will be implemented here on
   top of the secp256k1 primitives.
5. **Low-level ML-DSA-44 primitives** for threshold use: access to the NTT,
   polynomial/vector types, coefficient sampling, and bit-packing used by FIPS
   204, so partial signatures can be combined. Required by `mldsatss`.

When in doubt, prefer exposing existing internal arithmetic over re-implementing
it here, to keep a single audited implementation.

## License

MIT — see [LICENSE](LICENSE). Portions © 2019 Binance, © 2024 Karpeles Lab Inc.
