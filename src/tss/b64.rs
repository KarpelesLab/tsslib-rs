//! Standard-base64 serde helpers, matching Go's `encoding/json` treatment of
//! `[]byte` (base64 std string, or `null` for a nil slice).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A byte string that (de)serializes as a single base64 std string — Go's
/// `[]byte` JSON form. Use inside a `Vec` for a `[][]byte` field.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct B64Bytes(pub Vec<u8>);

impl Serialize for B64Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        Ok(B64Bytes(
            BASE64.decode(s.as_bytes()).map_err(D::Error::custom)?,
        ))
    }
}

/// `#[serde(with = "crate::tss::b64::vec")]` for a `Vec<u8>` field.
pub mod vec {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        BASE64.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

/// `#[serde(with = "crate::tss::b64::opt_array32", default)]` for an
/// `Option<[u8; 32]>` field: `Some` → base64 string, `None` → `null`.
pub mod opt_array32 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&BASE64.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        use serde::de::Error as _;
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = BASE64.decode(s.as_bytes()).map_err(D::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| D::Error::custom("chain code must be 32 bytes"))?;
                Ok(Some(arr))
            }
        }
    }
}
