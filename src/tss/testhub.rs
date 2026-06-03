//! In-process multi-party transport for tests.
//!
//! Port of the Go `hubBroker`/`testHub`: each party gets a [`MessageBroker`]
//! that routes its outbound messages to the other parties' brokers (honoring
//! `To` for point-to-point, broadcasting to all others when `To` is `None`) and
//! dispatches inbound messages to the registered handler — buffering them until
//! a handler for that type is connected.

use super::{JsonMessage, MessageBroker, MessageReceiver, PartyId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// A set of interconnected in-process brokers, one per party.
pub(crate) struct TestHub {
    brokers: Vec<Arc<HubBroker>>,
}

impl TestHub {
    /// Builds a hub wiring `parties.len()` brokers together. `parties` must be
    /// sorted; broker `i` serves `parties[i]`.
    pub(crate) fn new(parties: &[PartyId]) -> Arc<TestHub> {
        let brokers: Vec<Arc<HubBroker>> = parties
            .iter()
            .enumerate()
            .map(|(i, _)| {
                Arc::new(HubBroker {
                    party_index: i,
                    peers: OnceLock::new(),
                    inner: Mutex::new(HubInner {
                        handlers: HashMap::new(),
                        pending: HashMap::new(),
                    }),
                })
            })
            .collect();
        // Wire each broker to the full broker list (sibling Arcs form a cycle;
        // acceptable for short-lived test runs).
        for b in &brokers {
            b.peers.set(brokers.clone()).ok();
        }
        Arc::new(TestHub { brokers })
    }

    /// The broker for party index `i`.
    pub(crate) fn broker(&self, i: usize) -> Arc<dyn MessageBroker + Send + Sync> {
        self.brokers[i].clone()
    }
}

pub(crate) struct HubBroker {
    party_index: usize,
    peers: OnceLock<Vec<Arc<HubBroker>>>,
    inner: Mutex<HubInner>,
}

struct HubInner {
    handlers: HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>,
    pending: HashMap<String, Vec<JsonMessage>>,
}

impl HubBroker {
    fn peers(&self) -> &[Arc<HubBroker>] {
        self.peers.get().expect("peers wired").as_slice()
    }

    /// Dispatches an inbound message to its handler, or buffers it.
    fn deliver_inbound(&self, msg: &JsonMessage) -> super::BrokerResult {
        let handler = {
            let mut inner = self.inner.lock().unwrap();
            match inner.handlers.get(&msg.typ) {
                Some(h) => Some(h.clone()),
                None => {
                    inner
                        .pending
                        .entry(msg.typ.clone())
                        .or_default()
                        .push(msg.clone());
                    None
                }
            }
        };
        match handler {
            Some(h) => h.receive(msg),
            None => Ok(()),
        }
    }
}

impl MessageReceiver for HubBroker {
    fn receive(&self, msg: &JsonMessage) -> super::BrokerResult {
        let from_index = msg.from.as_ref().map(|p| p.index).unwrap_or(-1);
        if from_index == self.party_index as i32 {
            // Outbound from this party: route to the destination(s).
            match &msg.to {
                Some(to) => {
                    let idx = to.index as usize;
                    self.peers()[idx].deliver_inbound(msg)
                }
                None => {
                    for (j, peer) in self.peers().iter().enumerate() {
                        if j == self.party_index {
                            continue;
                        }
                        peer.deliver_inbound(msg)?;
                    }
                    Ok(())
                }
            }
        } else {
            // Inbound from a peer.
            self.deliver_inbound(msg)
        }
    }
}

impl MessageBroker for HubBroker {
    fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
        let queued = {
            let mut inner = self.inner.lock().unwrap();
            inner.handlers.insert(typ.to_string(), dest.clone());
            inner.pending.remove(typ).unwrap_or_default()
        };
        for msg in queued {
            let _ = dest.receive(&msg);
        }
    }
}

// --- key-routed hub for resharing (old + new committees share no index space) ---

fn key_of(p: &PartyId) -> Vec<u8> {
    let start = p.key.iter().position(|&x| x != 0).unwrap_or(p.key.len());
    p.key[start..].to_vec()
}

/// A hub that routes by participant key rather than index, so the disjoint
/// index spaces of a resharing's old and new committees coexist. Port of the Go
/// `resharingHub`.
pub(crate) struct ReshareHub {
    brokers: Mutex<HashMap<Vec<u8>, Arc<ReshareBroker>>>,
}

impl ReshareHub {
    pub(crate) fn new(parties: &[PartyId]) -> Arc<ReshareHub> {
        let hub = Arc::new(ReshareHub {
            brokers: Mutex::new(HashMap::new()),
        });
        for p in parties {
            let broker = Arc::new(ReshareBroker {
                party_key: key_of(p),
                hub: Arc::downgrade(&hub),
                inner: Mutex::new(HubInner {
                    handlers: HashMap::new(),
                    pending: HashMap::new(),
                }),
            });
            hub.brokers.lock().unwrap().insert(key_of(p), broker);
        }
        hub
    }

    pub(crate) fn broker(&self, p: &PartyId) -> Arc<dyn MessageBroker + Send + Sync> {
        self.brokers
            .lock()
            .unwrap()
            .get(&key_of(p))
            .expect("party registered")
            .clone()
    }

    fn get(&self, key: &[u8]) -> Option<Arc<ReshareBroker>> {
        self.brokers.lock().unwrap().get(key).cloned()
    }

    fn all(&self) -> Vec<Arc<ReshareBroker>> {
        self.brokers.lock().unwrap().values().cloned().collect()
    }
}

pub(crate) struct ReshareBroker {
    party_key: Vec<u8>,
    hub: std::sync::Weak<ReshareHub>,
    inner: Mutex<HubInner>,
}

impl ReshareBroker {
    fn deliver_inbound(&self, msg: &JsonMessage) -> super::BrokerResult {
        let handler = {
            let mut inner = self.inner.lock().unwrap();
            match inner.handlers.get(&msg.typ) {
                Some(h) => Some(h.clone()),
                None => {
                    inner
                        .pending
                        .entry(msg.typ.clone())
                        .or_default()
                        .push(msg.clone());
                    None
                }
            }
        };
        match handler {
            Some(h) => h.receive(msg),
            None => Ok(()),
        }
    }
}

impl MessageReceiver for ReshareBroker {
    fn receive(&self, msg: &JsonMessage) -> super::BrokerResult {
        let from = msg.from.as_ref().map(key_of).unwrap_or_default();
        let hub = self.hub.upgrade().ok_or("reshare hub dropped")?;
        if from == self.party_key {
            match &msg.to {
                Some(to) => {
                    let dest = hub.get(&key_of(to)).ok_or("no broker for recipient")?;
                    dest.deliver_inbound(msg)
                }
                None => {
                    for dest in hub.all() {
                        if dest.party_key == self.party_key {
                            continue;
                        }
                        dest.deliver_inbound(msg)?;
                    }
                    Ok(())
                }
            }
        } else {
            self.deliver_inbound(msg)
        }
    }
}

impl MessageBroker for ReshareBroker {
    fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
        let queued = {
            let mut inner = self.inner.lock().unwrap();
            inner.handlers.insert(typ.to_string(), dest.clone());
            inner.pending.remove(typ).unwrap_or_default()
        };
        for msg in queued {
            let _ = dest.receive(&msg);
        }
    }
}
