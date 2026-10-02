//! Transport-agnostic core shared by every threshold protocol.
//!
//! Participant identity ([`PartyId`]), the rich protocol error type
//! ([`TssError`]), and the JSON-based message/broker plumbing the broker-style
//! protocols route their rounds through.

pub(crate) mod b64;
pub(crate) mod bigint;
mod error;
pub(crate) mod expect;
pub mod hashing;
pub(crate) mod keyimage_hash;
mod message;
mod params;
mod party_id;

pub use error::TssError;
pub use keyimage_hash::HashAlgorithm;
#[allow(deprecated)]
pub use message::JsonMessage;
pub use message::{
    BrokerResult, CodecError, Message, MessageBroker, MessageReceiver, Payload, WireFormat,
};

/// Decodes a message payload (crate-internal shorthand for [`Message::decode`]).
pub(crate) fn decode<T: serde::de::DeserializeOwned>(msg: &Message) -> Result<T, CodecError> {
    msg.decode()
}

/// Builds a message (crate-internal shorthand for [`Message::encode`]).
pub(crate) fn encode<T: serde::Serialize + ?Sized>(
    format: WireFormat,
    typ: impl Into<alloc::string::String>,
    data: &T,
    from: Option<PartyId>,
    to: Option<PartyId>,
) -> Result<Message, CodecError> {
    Message::encode(format, typ, data, from, to)
}
pub use params::{Parameters, ReSharingParameters};
pub use party_id::PartyId;

#[cfg(test)]
pub(crate) mod testhub;
