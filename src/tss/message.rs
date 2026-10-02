//! Protocol message and broker plumbing.
//!
//! The broker-style protocols don't manage channels or routing themselves —
//! they hand every outgoing message to a [`MessageBroker`] the caller supplies,
//! and register typed handlers ([`MessageReceiver`]) for incoming messages.
//!
//! A [`Message`] carries its payload already encoded in the session's
//! [`WireFormat`] (fixed per session in [`Parameters`](super::Parameters)):
//! JSON, or the compact binary [`crate::wire`] encoding. The envelope itself
//! serializes in the matching format — [`Message::to_json`] for JSON sessions,
//! [`Message::write_to`] / [`Message::to_bytes`] for binary ones.

use super::PartyId;
use crate::prelude::*;
use crate::wire;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Boxed error returned by transport callbacks.
pub type BrokerResult = Result<(), Box<dyn core::error::Error + Send + Sync>>;

/// How a session encodes its messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFormat {
    /// JSON, as earlier releases exchanged (requires the `json` feature).
    #[cfg(feature = "json")]
    Json,
    /// The compact binary [`crate::wire`] encoding.
    Binary,
}

impl Default for WireFormat {
    /// [`WireFormat::Json`] when the `json` feature is enabled, otherwise
    /// [`WireFormat::Binary`].
    fn default() -> Self {
        #[cfg(feature = "json")]
        {
            WireFormat::Json
        }
        #[cfg(not(feature = "json"))]
        {
            WireFormat::Binary
        }
    }
}

/// A message payload, encoded in its session's [`WireFormat`].
#[derive(Clone, Debug, PartialEq)]
pub enum Payload {
    /// A JSON value.
    #[cfg(feature = "json")]
    Json(serde_json::Value),
    /// [`crate::wire`]-encoded bytes.
    Binary(Vec<u8>),
}

/// A protocol message: type discriminator, sender, recipient (`None` for a
/// broadcast) and payload.
///
/// In JSON the envelope is `{"type", "from", "to", "data"}`, exactly as
/// earlier releases sent it.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// Message type discriminator used for handler dispatch.
    pub typ: String,
    /// Sender, or `None`.
    pub from: Option<PartyId>,
    /// Recipient, or `None` for a broadcast.
    pub to: Option<PartyId>,
    /// Encoded payload; decode it with [`Message::decode`].
    pub data: Payload,
}

/// The message type's former name, from when only JSON was supported.
#[deprecated(note = "renamed to `Message`")]
pub type JsonMessage = Message;

/// A failure encoding or decoding a key or message.
#[derive(Debug)]
pub enum CodecError {
    /// The binary [`crate::wire`] encoding.
    Wire(wire::Error),
    /// JSON.
    #[cfg(feature = "json")]
    Json(serde_json::Error),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodecError::Wire(e) => write!(f, "{e}"),
            #[cfg(feature = "json")]
            CodecError::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl core::error::Error for CodecError {}

impl From<wire::Error> for CodecError {
    fn from(e: wire::Error) -> Self {
        CodecError::Wire(e)
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for CodecError {
    fn from(e: serde_json::Error) -> Self {
        CodecError::Json(e)
    }
}

impl Message {
    /// Builds a message with `data` encoded in `format`.
    pub fn encode<T: Serialize + ?Sized>(
        format: WireFormat,
        typ: impl Into<String>,
        data: &T,
        from: Option<PartyId>,
        to: Option<PartyId>,
    ) -> Result<Message, CodecError> {
        let data = match format {
            #[cfg(feature = "json")]
            WireFormat::Json => Payload::Json(serde_json::to_value(data)?),
            WireFormat::Binary => Payload::Binary(wire::to_vec(data)?),
        };
        Ok(Message {
            typ: typ.into(),
            from,
            to,
            data,
        })
    }

    /// Decodes the payload into a concrete type `T`.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, CodecError> {
        match &self.data {
            #[cfg(feature = "json")]
            Payload::Json(v) => Ok(T::deserialize(v)?),
            Payload::Binary(b) => Ok(wire::from_slice(b)?),
        }
    }

    /// The payload's encoding.
    pub fn format(&self) -> WireFormat {
        match self.data {
            #[cfg(feature = "json")]
            Payload::Json(_) => WireFormat::Json,
            Payload::Binary(_) => WireFormat::Binary,
        }
    }

    /// Writes the binary envelope (for a [`WireFormat::Binary`] message).
    pub fn write_to<W: wire::Write>(&self, w: &mut W) -> Result<(), wire::Error> {
        wire::to_writer(self, w)
    }

    /// Reads one binary envelope, leaving `r` just after it.
    pub fn read_from<R: wire::Read>(r: &mut R) -> Result<Message, wire::Error> {
        wire::from_reader(r)
    }

    /// The binary envelope as bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, wire::Error> {
        wire::to_vec(self)
    }

    /// Parses a binary envelope that spans all of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, wire::Error> {
        wire::from_slice(bytes)
    }

    /// The JSON envelope (for a [`WireFormat::Json`] message).
    #[cfg(feature = "json")]
    pub fn to_json(&self) -> Result<String, CodecError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parses a JSON envelope.
    #[cfg(feature = "json")]
    pub fn from_json(s: &str) -> Result<Message, CodecError> {
        Ok(serde_json::from_str(s)?)
    }
}

/// The JSON envelope. Field names match earlier releases.
#[cfg(feature = "json")]
#[derive(Serialize, Deserialize)]
struct JsonEnvelope {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    from: Option<PartyId>,
    #[serde(default)]
    to: Option<PartyId>,
    #[serde(default)]
    data: serde_json::Value,
}

/// The binary envelope.
#[derive(Serialize, Deserialize)]
struct BinaryEnvelope {
    typ: String,
    from: Option<PartyId>,
    to: Option<PartyId>,
    data: super::b64::B64Bytes,
}

/// The JSON envelope in human-readable formats, the binary one otherwise. A
/// message only serializes in its own payload's format.
impl Serialize for Message {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        match (&self.data, s.is_human_readable()) {
            #[cfg(feature = "json")]
            (Payload::Json(v), true) => JsonEnvelope {
                typ: self.typ.clone(),
                from: self.from.clone(),
                to: self.to.clone(),
                data: v.clone(),
            }
            .serialize(s),
            (Payload::Binary(b), false) => BinaryEnvelope {
                typ: self.typ.clone(),
                from: self.from.clone(),
                to: self.to.clone(),
                data: super::b64::B64Bytes(b.clone()),
            }
            .serialize(s),
            _ => Err(S::Error::custom(
                "message payload format does not match the serializer",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            #[cfg(feature = "json")]
            {
                let e = JsonEnvelope::deserialize(d)?;
                Ok(Message {
                    typ: e.typ,
                    from: e.from,
                    to: e.to,
                    data: Payload::Json(e.data),
                })
            }
            #[cfg(not(feature = "json"))]
            {
                use serde::de::Error as _;
                Err(D::Error::custom(
                    "human-readable messages need the `json` feature",
                ))
            }
        } else {
            let e = BinaryEnvelope::deserialize(d)?;
            Ok(Message {
                typ: e.typ,
                from: e.from,
                to: e.to,
                data: Payload::Binary(e.data.0),
            })
        }
    }
}

/// Receives a [`Message`] from the transport.
pub trait MessageReceiver {
    /// Handles an incoming message. Implementations route by `msg.typ`.
    fn receive(&self, msg: &Message) -> BrokerResult;
}

/// A [`MessageReceiver`] that can also register typed handlers.
///
/// The protocol calls [`MessageBroker::connect`] to register a handler for each
/// message type it expects, and [`MessageReceiver::receive`] to emit outgoing
/// messages, which the broker routes to the destination party's broker.
pub trait MessageBroker: MessageReceiver {
    /// Registers `dest` as the handler for messages of type `typ`.
    fn connect(&self, typ: &str, dest: alloc::sync::Arc<dyn MessageReceiver + Send + Sync>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Body {
        round: u32,
        commitment: String,
        #[serde(with = "crate::tss::b64::vec")]
        blob: Vec<u8>,
    }

    fn body() -> Body {
        Body {
            round: 1,
            commitment: "abc".into(),
            blob: vec![0, 1, 2, 255],
        }
    }

    #[test]
    fn binary_message_roundtrips_through_its_envelope() {
        let from = PartyId::new("1", "P[1]", vec![1]);
        let msg =
            Message::encode(WireFormat::Binary, "keygen.r1", &body(), Some(from), None).unwrap();
        let bytes = msg.to_bytes().unwrap();
        let back = Message::from_bytes(&bytes).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.decode::<Body>().unwrap(), body());
        // Streams: two envelopes back to back.
        let mut buf = Vec::new();
        msg.write_to(&mut buf).unwrap();
        msg.write_to(&mut buf).unwrap();
        let mut r = buf.as_slice();
        assert_eq!(Message::read_from(&mut r).unwrap(), msg);
        assert_eq!(Message::read_from(&mut r).unwrap(), msg);
        assert!(r.is_empty());
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_envelope_shape_is_unchanged() {
        let from = PartyId::new("1", "P[1]", vec![1]);
        let msg = Message::encode(WireFormat::Json, "t", &42u32, Some(from), None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&msg.to_json().unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert_eq!(v["type"], "t");
        assert_eq!(v["data"], 42);
        assert_eq!(v["to"], serde_json::Value::Null);
        assert_eq!(v["from"]["key"], "AQ==");
        let back = Message::from_json(&msg.to_json().unwrap()).unwrap();
        assert_eq!(back, msg);
        assert_eq!(back.decode::<u32>().unwrap(), 42);
    }

    #[cfg(feature = "json")]
    #[test]
    fn envelope_refuses_the_other_format() {
        let bin = Message::encode(WireFormat::Binary, "t", &1u8, None, None).unwrap();
        assert!(bin.to_json().is_err());
        let json = Message::encode(WireFormat::Json, "t", &1u8, None, None).unwrap();
        assert!(json.to_bytes().is_err());
    }
}
