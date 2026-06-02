//! A [`MessageReceiver`] that collects one message from each expected sender
//! and fires a callback once all have arrived (port of Go `NewJsonExpect`).

use super::{JsonMessage, MessageReceiver, PartyId};
use std::sync::Mutex;

/// Collects messages of a single type from a fixed set of senders, then invokes
/// a one-shot callback with the messages in sender order.
pub(crate) struct JsonExpect {
    typ: String,
    from: Vec<PartyId>,
    state: Mutex<State>,
}

struct State {
    packets: Vec<Option<JsonMessage>>,
    missing: usize,
    cb: Option<Box<dyn FnOnce(Vec<JsonMessage>) + Send>>,
}

impl JsonExpect {
    /// Expects one `typ` message from each party in `from`; calls `cb` with the
    /// collected messages (in `from` order) once the last one arrives.
    pub(crate) fn new(
        typ: impl Into<String>,
        from: Vec<PartyId>,
        cb: Box<dyn FnOnce(Vec<JsonMessage>) + Send>,
    ) -> Self {
        let n = from.len();
        JsonExpect {
            typ: typ.into(),
            from,
            state: Mutex::new(State {
                packets: (0..n).map(|_| None).collect(),
                missing: n,
                cb: Some(cb),
            }),
        }
    }
}

impl MessageReceiver for JsonExpect {
    fn receive(&self, msg: &JsonMessage) -> super::BrokerResult {
        if msg.typ != self.typ {
            return Err(format!(
                "unexpected message type {} while expecting {}",
                msg.typ, self.typ
            )
            .into());
        }
        let from = msg
            .from
            .as_ref()
            .ok_or_else(|| "message has no sender".to_string())?;

        // Locate the sender's slot; ignore duplicates of an already-filled slot.
        let cb = {
            let mut st = self.state.lock().unwrap();
            if st.missing == 0 {
                return Err("collection already complete".into());
            }
            let idx = self
                .from
                .iter()
                .position(|p| p.cmp_key(from) == std::cmp::Ordering::Equal)
                .ok_or_else(|| "message from an unexpected sender".to_string())?;
            if st.packets[idx].is_some() {
                return Ok(()); // duplicate; keep the first
            }
            st.packets[idx] = Some(msg.clone());
            st.missing -= 1;
            if st.missing == 0 { st.cb.take() } else { None }
        };

        // Fire the callback outside the lock so it may re-enter the broker.
        if let Some(cb) = cb {
            let mut st = self.state.lock().unwrap();
            let packets: Vec<JsonMessage> =
                st.packets.iter_mut().map(|p| p.take().unwrap()).collect();
            drop(st);
            cb(packets);
        }
        Ok(())
    }
}
