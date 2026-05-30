//! Participant identity.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;

/// A participant in the TSS protocol rounds.
///
/// `id` and `moniker` are conveniences for tracking participants. `id` is
/// intended to be a unique string representation of `key`; `moniker` can be
/// anything (even empty). `key` is the canonical big-endian, unsigned integer
/// identifier — the value protocols actually order and index parties by.
///
/// `index` is `-1` until the party has been placed into a sorted set via
/// [`PartyId::sort`], after which it is the party's position in that ordering.
///
/// # Wire compatibility
///
/// The JSON shape matches the Go `tss.PartyID`: the embedded protobuf
/// `MessageWrapper_PartyID` fields are promoted to the top level, `key` is
/// standard-base64 encoded (Go marshals `[]byte` that way), and `id` /
/// `moniker` / `key` are omitted when empty (`omitempty`). `index` is always
/// present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyId {
    /// Unique string representation of `key`.
    pub id: String,
    /// Human-friendly label; may be empty.
    pub moniker: String,
    /// Big-endian, unsigned integer identifier.
    pub key: Vec<u8>,
    /// Position in the sorted set, or `-1` if not yet sorted.
    pub index: i32,
}

impl PartyId {
    /// Constructs a new `PartyId`. `key` is the big-endian unsigned identifier
    /// and should remain consistent between runs for each party. `index` is
    /// initialised to `-1` (unknown until sorted).
    pub fn new(id: impl Into<String>, moniker: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            moniker: moniker.into(),
            key: into_canonical(key.into()),
            index: -1,
        }
    }

    /// Returns true if the party has a non-empty key and a non-negative index.
    pub fn validate_basic(&self) -> bool {
        !self.key.is_empty() && self.index >= 0
    }

    /// Numerically compares this party's `key` to another's, treating both as
    /// big-endian unsigned integers.
    pub fn cmp_key(&self, other: &PartyId) -> Ordering {
        cmp_be_unsigned(&self.key, &other.key)
    }

    /// Sorts `ids` by `key` ascending and assigns each party its `index`
    /// (`start_at + position`). Mirrors Go's `SortPartyIDs`.
    pub fn sort(mut ids: Vec<PartyId>, start_at: i32) -> Vec<PartyId> {
        ids.sort_by(|a, b| cmp_be_unsigned(&a.key, &b.key));
        for (i, id) in ids.iter_mut().enumerate() {
            id.index = start_at + i as i32;
        }
        ids
    }
}

impl PartialOrd for PartyId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PartyId {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_be_unsigned(&self.key, &other.key)
    }
}

impl std::fmt::Display for PartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{},{}}}", self.index, self.moniker)
    }
}

/// Strips leading zero bytes so equal integers compare equal byte-for-byte.
/// An all-zero (or empty) input canonicalises to a single zero byte, matching
/// the representation of the integer 0.
fn into_canonical(mut key: Vec<u8>) -> Vec<u8> {
    let nonzero = key.iter().position(|&b| b != 0);
    match nonzero {
        Some(0) => key,
        Some(n) => key.split_off(n),
        None => vec![0],
    }
}

/// Compares two big-endian unsigned integers given as byte slices, ignoring
/// leading zeroes.
fn cmp_be_unsigned(a: &[u8], b: &[u8]) -> Ordering {
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        other => other,
    }
}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

// --- Serde: match the Go JSON shape exactly. ---

#[derive(Serialize, Deserialize)]
struct PartyIdWire {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    moniker: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "ser_b64",
        deserialize_with = "de_b64"
    )]
    key: Vec<u8>,
    index: i32,
}

fn ser_b64<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&BASE64.encode(bytes))
}

fn de_b64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    BASE64.decode(s.as_bytes()).map_err(D::Error::custom)
}

impl Serialize for PartyId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        PartyIdWire {
            id: self.id.clone(),
            moniker: self.moniker.clone(),
            key: self.key.clone(),
            index: self.index,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for PartyId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = PartyIdWire::deserialize(d)?;
        Ok(PartyId {
            id: w.id,
            moniker: w.moniker,
            key: into_canonical(w.key),
            index: w.index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_assigns_indexes_ascending() {
        let ids = vec![
            PartyId::new("c", "C", vec![3]),
            PartyId::new("a", "A", vec![1]),
            PartyId::new("b", "B", vec![2]),
        ];
        let sorted = PartyId::sort(ids, 0);
        assert_eq!(
            sorted.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            sorted.iter().map(|p| p.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn cmp_ignores_leading_zeros() {
        let a = PartyId::new("a", "", vec![0, 0, 5]);
        let b = PartyId::new("b", "", vec![5]);
        assert_eq!(a.cmp_key(&b), Ordering::Equal);
    }

    #[test]
    fn json_roundtrip_and_shape() {
        let p = PartyId {
            id: "1".into(),
            moniker: "P[1]".into(),
            key: vec![0xde, 0xad, 0xbe, 0xef],
            index: 0,
        };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["id"], "1");
        assert_eq!(j["moniker"], "P[1]");
        assert_eq!(j["key"], "3q2+7w=="); // base64 std of deadbeef
        assert_eq!(j["index"], 0);
        let back: PartyId = serde_json::from_value(j).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn empty_fields_are_omitted() {
        let p = PartyId {
            id: String::new(),
            moniker: String::new(),
            key: Vec::new(),
            index: 2,
        };
        let j = serde_json::to_value(&p).unwrap();
        let obj = j.as_object().unwrap();
        assert!(!obj.contains_key("id"));
        assert!(!obj.contains_key("moniker"));
        assert!(!obj.contains_key("key"));
        assert_eq!(obj["index"], 2);
    }
}
