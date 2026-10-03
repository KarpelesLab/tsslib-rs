//! Standard-base64 serde helpers for byte-string fields (a base64 std string,
//! or `null` for an absent value).

use crate::prelude::*;
#[cfg(feature = "json")]
use base64::Engine as _;
#[cfg(feature = "json")]
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A byte string that (de)serializes as a single base64 std string. Use inside
/// a `Vec` for a list of byte strings.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct B64Bytes(pub Vec<u8>);

impl Serialize for B64Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for B64Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        deserialize_bytes(d).map(B64Bytes)
    }
}

/// A base64 string in human-readable formats (JSON), raw bytes in the binary
/// [`crate::wire`] format. Without the `json` feature it is always raw bytes.
pub(crate) fn serialize_bytes<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    #[cfg(feature = "json")]
    if s.is_human_readable() {
        return s.serialize_str(&BASE64.encode(bytes));
    }
    s.serialize_bytes(bytes)
}

/// Inverse of [`serialize_bytes`].
pub(crate) fn deserialize_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    #[cfg(feature = "json")]
    if d.is_human_readable() {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        return BASE64.decode(s.as_bytes()).map_err(D::Error::custom);
    }
    d.deserialize_byte_buf(crate::wire::ByteBufVisitor)
}

/// `#[serde(with = "crate::tss::b64::vec")]` for a `Vec<u8>` field.
pub mod vec {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(bytes, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        deserialize_bytes(d)
    }
}

/// `#[serde(with = "crate::tss::b64::opt_array32", default)]` for an
/// `Option<[u8; 32]>` field: `Some` → byte string, `None` → `null` / absent.
pub mod opt_array32 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        v.map(|b| B64Bytes(b.to_vec())).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        use serde::de::Error as _;
        match Option::<B64Bytes>::deserialize(d)? {
            None => Ok(None),
            Some(B64Bytes(bytes)) => bytes
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("chain code must be 32 bytes")),
        }
    }
}
