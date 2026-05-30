//! JSON message and broker plumbing.
//!
//! The broker-style protocols don't manage channels or routing themselves —
//! they hand every outgoing message to a [`MessageBroker`] the caller supplies,
//! and register typed handlers ([`MessageReceiver`]) for incoming messages. The
//! wire envelope is [`JsonMessage`], whose JSON shape matches the Go
//! `tss.JsonMessage`.

use super::PartyId;
use serde::{Deserialize, Serialize};

/// Boxed error returned by transport callbacks, matching Go's generic `error`.
pub type BrokerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// An envelope carrying an arbitrary payload for JSON transmission.
///
/// `data` is kept as a raw [`serde_json::Value`] so a received message can be
/// decoded into its concrete type on demand via [`json_get`]. Field names
/// (`type`, `from`, `to`, `data`) match the Go `tss.JsonMessage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonMessage {
    /// Message type discriminator used for handler dispatch.
    #[serde(rename = "type")]
    pub typ: String,
    /// Sender, or `None`.
    #[serde(default)]
    pub from: Option<PartyId>,
    /// Recipient, or `None` for a broadcast.
    #[serde(default)]
    pub to: Option<PartyId>,
    /// Opaque payload.
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Decodes the `data` payload of `msg` into a concrete type `T`.
pub fn json_get<T: for<'de> Deserialize<'de>>(msg: &JsonMessage) -> Result<T, serde_json::Error> {
    T::deserialize(&msg.data)
}

/// Wraps an arbitrary serializable payload into a [`JsonMessage`].
pub fn json_wrap<T: Serialize>(
    typ: impl Into<String>,
    data: &T,
    from: Option<PartyId>,
    to: Option<PartyId>,
) -> Result<JsonMessage, serde_json::Error> {
    Ok(JsonMessage {
        typ: typ.into(),
        from,
        to,
        data: serde_json::to_value(data)?,
    })
}

/// Receives a [`JsonMessage`] from the transport.
pub trait MessageReceiver {
    /// Handles an incoming message. Implementations route by `msg.typ`.
    fn receive(&self, msg: &JsonMessage) -> BrokerResult;
}

/// A [`MessageReceiver`] that can also register typed handlers.
///
/// The protocol calls [`MessageBroker::connect`] to register a handler for each
/// message type it expects, and [`MessageReceiver::receive`] to emit outgoing
/// messages, which the broker routes to the destination party's broker.
pub trait MessageBroker: MessageReceiver {
    /// Registers `dest` as the handler for messages of type `typ`.
    fn connect(&self, typ: &str, dest: std::sync::Arc<dyn MessageReceiver + Send + Sync>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Payload {
        round: u32,
        commitment: String,
    }

    #[test]
    fn wrap_then_get_roundtrips() {
        let p = Payload {
            round: 1,
            commitment: "abc".into(),
        };
        let msg = json_wrap("keygen.r1", &p, None, None).unwrap();
        assert_eq!(msg.typ, "keygen.r1");
        let back: Payload = json_get(&msg).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn json_field_names_match_go() {
        let from = PartyId::new("1", "P[1]", vec![1]);
        let msg = json_wrap("t", &42u32, Some(from), None).unwrap();
        let v = serde_json::to_value(&msg).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("from"));
        assert!(obj.contains_key("to"));
        assert!(obj.contains_key("data"));
        assert_eq!(v["data"], 42);
        assert_eq!(v["to"], serde_json::Value::Null);
    }
}
