# tsslib

[![CI](https://github.com/KarpelesLab/tsslib-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/tsslib-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/tsslib.svg)](https://crates.io/crates/tsslib)
[![docs.rs](https://img.shields.io/docsrs/tsslib)](https://docs.rs/tsslib)

Easy-to-use threshold signature schemes (TSS) in pure Rust.

The broker-based protocols exchange JSON messages through a transport you
supply, and key shares persist as JSON; both formats are stable across
releases. All low-level cryptography is provided by
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
| `frostsecp256k1tss`      | FROST(secp256k1, SHA-256) — RFC 9591    | BIP340 / Taproot        | secp256k1       |
| `mldsatss`               | Threshold ML-DSA-44 — FIPS 204          | ML-DSA signatures       | ML-DSA-44       |
| `dklstss`                | Threshold ECDSA — DKLs23                | ECDSA signatures        | secp256k1       |
| `ecdsatss`               | Threshold ECDSA — GG18/GG20             | ECDSA signatures        | secp256k1       |
| `eddsatss`               | Threshold EdDSA — GG18-style            | Ed25519 signatures      | Edwards25519    |

The FROST protocols and `dklstss` provide keygen, signing, resharing/refresh,
and HD derivation routed through a caller-supplied [`tss::MessageBroker`];
`dklstss` also offers a synchronous in-process API plus offline pre-signing
(`presign` / `sign_with_presign` with single-use enforcement). `frosttss` and
`dklstss` additionally expose `KeyImageParty`, a one-round threshold PRF
(`V = x·P` from per-party key-image shares) whose output is a secret only
`t+1` share holders can compute — the building block for **hardened**
derivation, which BIP32's `HMAC(chain_code, priv)` cannot give a threshold key.
The digest is the caller's (`purecrypto::hash::HashAlgorithm`: SHA-2, SHA-3,
Keccak-256, BLAKE2/3, …), mixed into the domain separation and frozen by
checked-in test vectors covering every accepted algorithm. `mldsatss`
(`2 ≤ t ≤ n ≤ 6`) provides trusted-dealer keygen, sync + broker-driven threshold
signing, and an **experimental** dealerless DKG (`DkgParty44` — no trusted
dealer; not independently reviewed). `ecdsatss` is a broker-driven port of the
legacy GG18/GG20 Paillier+MtA protocol (keygen, 9-round signing, resharing, and
1-of-1 `import_key`) provided for **migrating existing GG18/GG20 keys** — it
loads those save files byte-for-byte and signs with them; new deployments
should prefer `dklstss`. `frostsecp256k1tss` is FROST for Bitcoin Taproot: it
outputs standard 64-byte BIP340 signatures, optionally under a BIP341 output key
(key-path only or committing to a script tree) and/or a non-hardened BIP32
child, and `import_key` brings in an existing secp256k1 key (with its chain
code) to reshare. `eddsatss` is the EdDSA counterpart — a broker-driven
port of the legacy GG18-style threshold Ed25519 (Feldman VSS + threshold Schnorr,
no Paillier): keygen, 3-round signing, resharing, and 1-of-1 `import_key`, for
migrating existing GG18-style EdDSA keys (it loads them and emits standard
Ed25519 signatures). Each module is gated behind a like-named
cargo feature, all enabled by default:

```toml
[dependencies]
tsslib = { version = "0.3", default-features = false, features = ["std", "json", "frosttss"] }
```

### Encodings

Keys and messages encode either as **JSON** (the `json` feature, on by default;
the same format as earlier releases) or in the compact **binary** format of
`tsslib::wire`, which is always available, streams through small
`wire::Read`/`wire::Write` traits, and needs no serde_json. Binary is typically
2–3.5× smaller (a DKLs23 key: 90 KB as JSON, 26 KB binary), and leaving out
`json` trims roughly 20–30% of code size on bare-metal builds.

- Keys: `to_json`/`from_json`, or `write_to`/`read_from` (`to_bytes`/`from_bytes`).
- A `dklstss::Key` is mostly pairwise OT state (~12.8 KB binary per other
  member). `write_core_to` writes the rest (share, public data, parties: a few
  hundred bytes), and `PairOTState::write_to` writes each pair, so devices can
  keep the core and store the pairs elsewhere (`Key::set_pair` loads one).
  Signing needs only the pairs among the signers and fails with
  `Error::MissingPairs` naming any that are missing. A lost pair is rebuilt by
  its two members alone with `PairSetupParty` (a tsslib-rs-only session; shares
  and other pairs are unchanged).
- Messages: each session's encoding is fixed by
  `Parameters::with_wire_format(WireFormat::Binary)` (all parties must agree);
  the broker moves `tss::Message` envelopes with `to_json`/`from_json` or
  `write_to`/`read_from`.

Binary-decoding errors carry serde's message text only with the default-on
`error-messages` feature; without it a refused value is still refused, just
without the text, which keeps serde's message formatting (including the `f64`
formatter) out of firmware — about 20 KB with dklstss on thumbv7em.

```toml
# Embedded: no std, no JSON, no error text.
tsslib = { version = "0.3", default-features = false, features = ["frostsecp256k1tss"] }
```

### `no_std`

The crate is `#![no_std]` and needs only `alloc`. The default `std` feature
adds OS randomness, the blocking `wait()` on every session (without it, poll
`try_result()` after feeding each inbound message), and OS-backed locks in
place of spin locks. On a bare-metal target, register a CSPRNG with
`tsslib::rng::set_entropy_source` before starting any session;
`wasm32-unknown-unknown` draws from the host and needs no setup.

## Layout

```
src/
  tss/        core: PartyId, TssError, Message, MessageBroker
  wire.rs     compact streaming binary encoding for keys and messages
  frost/      shared FROST core: ciphersuite, binding, VSS, AEAD, commitments
  frosttss/                FROST(Ed25519)            keygen · sign · reshare · HD
  frostristretto255tss/    FROST(ristretto255)       keygen · sign · reshare
  frostsecp256k1tss/       FROST(secp256k1) Taproot  keygen · BIP340/341 sign · reshare · BIP32 · import
  mldsatss/                Threshold ML-DSA-44       dealer + DKG keygen · sync/broker sign (+ hyperball)
  dklstss/                 Threshold ECDSA (DKLs23)  sync + broker keygen/sign/reshare/refresh/pair-setup · presign
  ecdsatss/                Threshold ECDSA (GG18)    broker keygen/sign/reshare · import · legacy save format
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
