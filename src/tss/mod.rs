//! Transport-agnostic core shared by every threshold protocol.
//!
//! This mirrors the `tss` package of the Go tss-lib: participant identity
//! ([`PartyId`]), the rich protocol error type ([`TssError`]), and the
//! JSON-based message/broker plumbing the broker-style protocols route their
//! rounds through.

pub(crate) mod b64;
pub(crate) mod bigint;
mod error;
pub(crate) mod expect;
mod message;
mod params;
mod party_id;

pub use error::TssError;
pub use message::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, json_get, json_wrap};
pub use params::{Parameters, ReSharingParameters};
pub use party_id::PartyId;

#[cfg(test)]
pub(crate) mod testhub;
