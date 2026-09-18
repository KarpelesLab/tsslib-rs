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

/// Sets every party's `index` to its position in `parties`.
fn reindex(parties: &mut [PartyId]) {
    for (i, p) in parties.iter_mut().enumerate() {
        p.index = i as i32;
    }
}

impl Parameters {
    /// Builds parameters from a sorted party set, this party's id, the
    /// threshold, and a broker. `parties` must be sorted (see
    /// [`PartyId::sort`]) and contain `self_id`.
    ///
    /// Each party's `index` is reset to its position in `parties`: the
    /// protocols index per-party state by it, and a committee picked out of a
    /// larger sorted set (e.g. signers 0 and 2 of 3) would otherwise carry
    /// stale indices that run past the end of that state.
    ///
    /// # Panics
    /// If `self_id` is not present in `parties`.
    pub fn new(
        mut parties: Vec<PartyId>,
        self_id: &PartyId,
        threshold: usize,
        broker: Arc<dyn MessageBroker + Send + Sync>,
    ) -> Self {
        reindex(&mut parties);
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

/// Parameters for a resharing run: an old committee (threshold `t`) reshares to
/// a new committee (threshold `t'`) while preserving the group public key.
///
/// `self_id` may belong to the old committee, the new committee, or both
/// (dual membership). Mirrors Go `tss.ReSharingParameters`.
#[derive(Clone)]
pub struct ReSharingParameters {
    old_parties: Vec<PartyId>,
    new_parties: Vec<PartyId>,
    old_threshold: usize,
    new_threshold: usize,
    self_id: PartyId,
    broker: Arc<dyn MessageBroker + Send + Sync>,
}

impl ReSharingParameters {
    /// Builds resharing parameters. Both committees must be sorted; `self_id`
    /// must belong to at least one of them. As in [`Parameters::new`], each
    /// party's `index` is reset to its position within its own committee.
    pub fn new(
        mut old_parties: Vec<PartyId>,
        mut new_parties: Vec<PartyId>,
        old_threshold: usize,
        new_threshold: usize,
        self_id: PartyId,
        broker: Arc<dyn MessageBroker + Send + Sync>,
    ) -> Self {
        reindex(&mut old_parties);
        reindex(&mut new_parties);
        ReSharingParameters {
            old_parties,
            new_parties,
            old_threshold,
            new_threshold,
            self_id,
            broker,
        }
    }

    /// This party's id.
    pub fn party_id(&self) -> &PartyId {
        &self.self_id
    }
    /// The old committee (sorted).
    pub fn old_parties(&self) -> &[PartyId] {
        &self.old_parties
    }
    /// The new committee (sorted).
    pub fn new_parties(&self) -> &[PartyId] {
        &self.new_parties
    }
    /// Old reconstruction threshold `t`.
    pub fn old_threshold(&self) -> usize {
        self.old_threshold
    }
    /// New reconstruction threshold `t'`.
    pub fn new_threshold(&self) -> usize {
        self.new_threshold
    }
    /// Number of new-committee participants.
    pub fn new_party_count(&self) -> usize {
        self.new_parties.len()
    }
    /// The transport broker.
    pub fn broker(&self) -> &Arc<dyn MessageBroker + Send + Sync> {
        &self.broker
    }
    /// Whether this party is in the old committee.
    pub fn is_old_committee(&self) -> bool {
        self.old_parties
            .iter()
            .any(|p| p.cmp_key(&self.self_id) == std::cmp::Ordering::Equal)
    }
    /// Whether this party is in the new committee.
    pub fn is_new_committee(&self) -> bool {
        self.new_parties
            .iter()
            .any(|p| p.cmp_key(&self.self_id) == std::cmp::Ordering::Equal)
    }
    /// This party's index within the old committee, if a member.
    pub fn old_index(&self) -> Option<usize> {
        self.old_parties
            .iter()
            .position(|p| p.cmp_key(&self.self_id) == std::cmp::Ordering::Equal)
    }
    /// The old committee followed by the new-only parties: every participant
    /// once. (Go concatenates the two lists; a member of both would then be
    /// messaged twice.)
    pub fn old_and_new_parties(&self) -> Vec<PartyId> {
        let mut v = self.old_parties.clone();
        for p in &self.new_parties {
            if !v.iter().any(|q| q.cmp_key(p) == std::cmp::Ordering::Equal) {
                v.push(p.clone());
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tss::testhub::TestHub;

    /// A signing committee picked out of a larger sorted set keeps its keygen
    /// indices (0 and 2 here); protocols index per-party state by `index`, so
    /// the constructor must renumber to positions.
    #[test]
    fn subset_committee_is_reindexed_by_position() {
        let all = PartyId::sort(
            (1u8..=3)
                .map(|k| PartyId::new(k.to_string(), format!("P{k}"), vec![k]))
                .collect(),
            0,
        );
        let subset = vec![all[0].clone(), all[2].clone()];
        assert_eq!(subset[1].index, 2);
        let hub = TestHub::new(&subset);
        let params = Parameters::new(subset.clone(), &subset[1], 1, hub.broker(1));
        let idx: Vec<i32> = params.parties().iter().map(|p| p.index).collect();
        assert_eq!(idx, [0, 1]);
        assert_eq!(params.party_id().index, 1);
    }
}
