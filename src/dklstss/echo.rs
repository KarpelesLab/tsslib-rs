//! Echo-broadcast (reliable-broadcast) layer + shared helpers for the
//! broker-driven DKLs party protocols (keygen / refresh / resharing).
//!
//! Each recipient broadcasts `H(received Vᴰ)` for every dealer `D ≠ self`; once
//! everyone's echoes are in, each party cross-checks them against its own view.
//! A digest mismatch identifies the equivocating dealer (or the lying echoer
//! when the disagreement is over the recipient's own commitments). This catches
//! a peer-code equivocation that the broker contract alone cannot detect (a
//! malicious dealer handing the broker different bytes per recipient under a
//! `To == nil` broadcast). Port of Go `dklstss/echo.go`.

use super::Error;
use super::secp::{self, ProjectivePoint};
use crate::tss::PartyId;
use crate::tss::TssError;
use crate::tss::b64::B64Bytes;
use crate::tss::bigint::be_to_decimal;
use purecrypto::hash::sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `PartyID.KeyInt().String()` — the decimal string of a party's key, used as
/// the map key in [`EchoMsg`] and for internal per-peer maps.
pub(crate) fn peer_key_str(p: &PartyId) -> String {
    be_to_decimal(strip(&p.key))
}

/// Big-endian magnitude with leading zeros stripped (Go `big.Int.Bytes()`).
pub(crate) fn strip(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

/// Hashes a dealer's VSS commitments into a stable fingerprint for the echo
/// phase. The encoding is length-prefixed so distinct commitment slices cannot
/// collide by byte-alignment coincidence.
pub(crate) fn commit_digest(tag: &str, dealer: &PartyId, vs_bytes: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(tag.as_bytes());
    data.push(b'|');
    data.extend_from_slice(strip(&dealer.key));
    data.push(b'|');
    data.extend_from_slice(&(vs_bytes.len() as u64).to_le_bytes());
    for c in vs_bytes {
        data.extend_from_slice(&(c.len() as u64).to_le_bytes());
        data.extend_from_slice(c);
    }
    sha256(&data).to_vec()
}

/// Wire form of the echo phase: the echoer's digest of every dealer's
/// commitments it received in round 1. Keys are [`peer_key_str`]; values are
/// [`commit_digest`] outputs. Sent once per echoer as a `To == nil` broadcast.
#[derive(Serialize, Deserialize)]
pub(crate) struct EchoMsg {
    #[serde(rename = "digests")]
    pub digests: HashMap<String, B64Bytes>,
}

/// Cross-checks every echoer's reported digest against the recipient's own view.
///
/// On any mismatch, returns an [`Error::Tss`] naming the most likely culprit:
/// the dealer for a peer-as-dealer disagreement (dealer equivocation is the
/// primary threat), or the echoer when it disagrees with the recipient's own
/// canonical commitments. Missing / unexpected / self entries are treated as
/// protocol violations attributed to the echoer.
///
/// `my_digests` must hold an entry for every party EXCEPT self (peer-as-dealer
/// cross-checks) plus an entry under `self_key` (the "echoer disagrees with my
/// own V" path). `echoers[n]` is the sender of `msgs[n]`. `all_parties` is the
/// dealer set from the echoer's perspective.
pub(crate) fn verify_echoes(
    my_digests: &HashMap<String, Vec<u8>>,
    self_key: &str,
    echoers: &[PartyId],
    msgs: &[EchoMsg],
    all_parties: &[PartyId],
    source: &str,
) -> Result<(), Error> {
    let by_key: HashMap<String, &PartyId> =
        all_parties.iter().map(|p| (peer_key_str(p), p)).collect();
    let max_digests = all_parties.len();

    let fail = |cause: String, culprit: &PartyId| -> Error {
        Error::Tss(Box::new(TssError::new(
            cause,
            source,
            0,
            None,
            vec![culprit.clone()],
        )))
    };

    for (n, echoer) in echoers.iter().enumerate() {
        let ec = &msgs[n];
        if ec.digests.is_empty() {
            return Err(fail(
                format!("{source} echo from {echoer} is empty"),
                echoer,
            ));
        }
        if ec.digests.len() > max_digests {
            return Err(fail(
                format!(
                    "{source} echo from {echoer} has {} digests (max {max_digests})",
                    ec.digests.len()
                ),
                echoer,
            ));
        }
        let echoer_key = peer_key_str(echoer);

        // Coverage: every echoer must report a digest for every dealer in
        // `all_parties` except itself. A missing entry would let a malicious
        // dealer + one colluding peer equivocate to a peer who never receives a
        // contradicting echo.
        for p in all_parties {
            let k = peer_key_str(p);
            if k == echoer_key {
                continue;
            }
            if !ec.digests.contains_key(&k) {
                return Err(fail(
                    format!(
                        "echo from {echoer} omitted dealer {p} — would enable an equivocation cover-up"
                    ),
                    echoer,
                ));
            }
        }

        for (dealer_key, their_digest) in &ec.digests {
            if *dealer_key == echoer_key {
                return Err(fail(
                    format!("echo from {echoer} contains a self-entry (protocol violation)"),
                    echoer,
                ));
            }
            let Some(mine) = my_digests.get(dealer_key) else {
                let dealer = by_key.get(dealer_key).copied();
                return Err(fail(
                    format!(
                        "echo from {echoer} mentions unknown dealer (key={dealer_key}){}",
                        dealer.map(|d| format!(" {d}")).unwrap_or_default()
                    ),
                    echoer,
                ));
            };
            if mine == &their_digest.0 {
                continue;
            }
            // Disagreement: choose a culprit.
            if *dealer_key == self_key {
                return Err(fail(
                    format!("echo from {echoer} disagrees with my canonical commitments"),
                    echoer,
                ));
            }
            match by_key.get(dealer_key).copied() {
                Some(dealer) => {
                    return Err(fail(
                        format!(
                            "echo from {echoer} reports a different commitment for {dealer} than I received"
                        ),
                        dealer,
                    ));
                }
                None => {
                    return Err(Error::Validation(format!(
                        "{source} echo from {echoer} disagrees on unmapped dealer {dealer_key}"
                    )));
                }
            }
        }
    }
    Ok(())
}

// --- shared point / party helpers (used by every *_party state machine) ----

/// Flattens points to alternating `x`, `y` big-endian-minimal magnitudes
/// (Go `flattenPointXY`). A nil/identity point contributes two empty entries.
pub(crate) fn flatten_point_xy(pts: &[ProjectivePoint]) -> Vec<B64Bytes> {
    let mut out = Vec::with_capacity(2 * pts.len());
    for p in pts {
        let (x, y) = secp::affine_be(p);
        out.push(B64Bytes(x));
        out.push(B64Bytes(y));
    }
    out
}

/// Inverse of [`flatten_point_xy`]: parses `(x, y)` pairs into curve points,
/// rejecting odd-length input and off-curve coordinates.
pub(crate) fn unflatten_point_xy(flat: &[B64Bytes]) -> Result<Vec<ProjectivePoint>, Error> {
    if flat.len() % 2 != 0 {
        return Err(Error::Validation(format!(
            "flat point slice length {} not even",
            flat.len()
        )));
    }
    let mut out = Vec::with_capacity(flat.len() / 2);
    for (i, pair) in flat.chunks_exact(2).enumerate() {
        let p = point_from_be_xy(&pair[0].0, &pair[1].0)
            .ok_or_else(|| Error::Validation(format!("point [{i}] off-curve")))?;
        out.push(p);
    }
    Ok(out)
}

/// Builds a point from big-endian-minimal affine `(x, y)` magnitudes via an
/// uncompressed SEC1 encoding. `None` on off-curve / malformed input.
pub(crate) fn point_from_be_xy(x_be: &[u8], y_be: &[u8]) -> Option<ProjectivePoint> {
    let x = strip(x_be);
    let y = strip(y_be);
    if x.len() > 32 || y.len() > 32 {
        return None;
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1 + (32 - x.len())..33].copy_from_slice(x);
    sec1[33 + (32 - y.len())..65].copy_from_slice(y);
    secp::from_sec1(&sec1)
}

/// The committee excluding this party, in `parties` order.
pub(crate) fn other_parties(parties: &[PartyId], self_id: &PartyId) -> Vec<PartyId> {
    parties
        .iter()
        .filter(|p| p.cmp_key(self_id) != std::cmp::Ordering::Equal)
        .cloned()
        .collect()
}

/// Per-pair base-OT session id: `SHA256(ssid || '|' || min || '|' || max ||
/// '|' || extSenderKey)` over big-endian-minimal party keys (Go `pairBaseSid`).
pub(crate) fn pair_base_sid(ssid: &[u8], a: &[u8], b: &[u8], ext_sender: &[u8]) -> Vec<u8> {
    let (a, b, ext) = (strip(a), strip(b), strip(ext_sender));
    let mut data = Vec::new();
    data.extend_from_slice(ssid);
    data.push(b'|');
    // Order the pair by big-endian-magnitude so both sides agree.
    let (lo, hi) = if be_le(a, b) { (a, b) } else { (b, a) };
    data.extend_from_slice(lo);
    data.push(b'|');
    data.extend_from_slice(hi);
    data.push(b'|');
    data.extend_from_slice(ext);
    sha256(&data).to_vec()
}

/// `a <= b` as non-negative big-endian-minimal magnitudes.
fn be_le(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return a.len() < b.len();
    }
    a <= b
}
