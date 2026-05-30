//! Transport-agnostic core shared by every threshold protocol.
//!
//! This mirrors the `tss` package of the Go tss-lib: participant identity
//! ([`PartyId`]), the rich protocol error type ([`TssError`]), and the
//! JSON-based message/broker plumbing the broker-style protocols route their
//! rounds through.

mod error;
mod message;
mod party_id;

pub use error::TssError;
pub use message::{JsonMessage, MessageBroker, MessageReceiver, json_get, json_wrap};
pub use party_id::PartyId;
