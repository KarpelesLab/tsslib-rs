//! Protocol parameters: the party set, this party, the threshold, and the
//! transport broker.

use super::{MessageBroker, PartyId};
use std::sync::Arc;

/// Shared configuration for a single run of a threshold protocol.
///
/// Mirrors the role of Go `tss.Parameters` for the broker-based protocols: it
/// names the (sorted) participant set, identifies this party within it, carries
/// the reconstruction threshold `t` (a `t`-of-`n` key needs `t+1` signers), and
/// holds the [`MessageBroker`] the protocol routes its rounds through.
#[derive(Clone)]
pub struct Parameters {
    parties: Vec<PartyId>,
    self_index: usize,
    threshold: usize,
    broker: Arc<dyn MessageBroker + Send + Sync>,
}

impl Parameters {
    /// Builds parameters from a sorted party set, this party's id, the
    /// threshold, and a broker. `parties` must be sorted (see
    /// [`PartyId::sort`]) and contain `self_id`.
    ///
    /// # Panics
    /// If `self_id` is not present in `parties`.
    pub fn new(
        parties: Vec<PartyId>,
        self_id: &PartyId,
        threshold: usize,
        broker: Arc<dyn MessageBroker + Send + Sync>,
    ) -> Self {
        let self_index = parties
            .iter()
            .position(|p| p.cmp_key(self_id) == std::cmp::Ordering::Equal)
            .expect("self_id must be one of the parties");
        Parameters {
            parties,
            self_index,
            threshold,
            broker,
        }
    }

    /// This party's id.
    pub fn party_id(&self) -> &PartyId {
        &self.parties[self.self_index]
    }

    /// This party's index within the sorted set.
    pub fn party_index(&self) -> usize {
        self.self_index
    }

    /// The full sorted party set.
    pub fn parties(&self) -> &[PartyId] {
        &self.parties
    }

    /// Number of participants in this run.
    pub fn party_count(&self) -> usize {
        self.parties.len()
    }

    /// The reconstruction threshold `t` (a `t`-of-`n` key needs `t+1` signers).
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The transport broker.
    pub fn broker(&self) -> &Arc<dyn MessageBroker + Send + Sync> {
        &self.broker
    }

    /// The other parties (everyone except this one), in sorted order.
    pub fn other_parties(&self) -> Vec<PartyId> {
        self.parties
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.self_index)
            .map(|(_, p)| p.clone())
            .collect()
    }
}
