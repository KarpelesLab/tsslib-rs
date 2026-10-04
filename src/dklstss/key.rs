//! DKLs key material and signature types (in-memory).

use super::otext::{ExtReceiver, ExtSender};
use super::secp::{ProjectivePoint, Scalar};
use crate::prelude::*;
use crate::tss::PartyId;

/// The two directions of OT-extension state between this party and one peer,
/// established at keygen and reused (under distinct sids) across signings.
#[derive(Clone)]
pub struct PairOTState {
    /// OT-extension receiver, used when this party is Alice in a ΠMul.
    pub as_alice: ExtReceiver,
    /// OT-extension sender, used when this party is Bob in a ΠMul.
    pub as_bob: ExtSender,
}

impl PairOTState {
    /// Overwrites both directions' OT seeds and correlation Δ with zeros,
    /// rendering this pair state unusable.
    pub fn zeroize(&mut self) {
        self.as_alice.zeroize();
        self.as_bob.zeroize();
    }
}

/// One party's output of the DKLs DKG: public material (joint key, per-party
/// commitments) and private material (Shamir share, per-pair OT state).
#[derive(Clone)]
pub struct Key {
    /// Total number of parties.
    pub n: usize,
    /// Threshold (signing needs `t + 1` parties).
    pub t: usize,
    /// This party's 0-based index.
    pub idx: usize,
    /// All participants, sorted.
    pub party_ids: Vec<PartyId>,
    /// This party's Shamir secret share.
    pub xi: Scalar,
    /// Public commitments `BigXj[i] = x_i·G`.
    pub big_xj: Vec<ProjectivePoint>,
    /// Joint ECDSA public key `X`.
    pub ecdsa_pub: ProjectivePoint,
    /// Per-pair OT-extension state; `None` at `idx` (no self-pair).
    pub ot: Vec<Option<PairOTState>>,
    /// BIP32 master chain code (deterministic from the public key).
    pub chain_code: [u8; 32],
}

impl Key {
    /// Validates basic internal consistency.
    pub fn validate_basic(&self) -> Result<(), super::Error> {
        use super::Error::Validation;
        if self.n == 0 || self.t >= self.n {
            return Err(Validation(format!("invalid (N={}, T={})", self.n, self.t)));
        }
        if self.idx >= self.n {
            return Err(Validation(format!("Idx={} out of range", self.idx)));
        }
        if self.party_ids.len() != self.n || self.big_xj.len() != self.n || self.ot.len() != self.n
        {
            return Err(Validation("inconsistent N-length fields".into()));
        }
        if bool::from(self.xi.is_zero()) {
            return Err(Validation("Xi is zero".into()));
        }
        // A dealer can steer Σ V_i[0] to the identity (V = −Σ others); no
        // signature verifies under it, so the key is unusable.
        if bool::from(self.ecdsa_pub.is_identity()) {
            return Err(Validation("ECDSAPub is the identity".into()));
        }
        // Xi·G must equal BigXj[idx].
        if !super::secp::point_eq(&super::secp::mul_base(&self.xi), &self.big_xj[self.idx]) {
            return Err(Validation("Xi·G != BigXj[idx]".into()));
        }
        Ok(())
    }

    /// Position of `peer` in [`Self::party_ids`], matched by party key.
    fn position_of(&self, peer: &PartyId) -> Option<usize> {
        self.party_ids
            .iter()
            .position(|p| p.cmp_key(peer) == core::cmp::Ordering::Equal)
    }

    /// The pairwise OT-extension state shared with `peer`, if loaded.
    pub fn pair(&self, peer: &PartyId) -> Option<&PairOTState> {
        self.ot.get(self.position_of(peer)?)?.as_ref()
    }

    /// Installs the pairwise OT-extension state shared with `peer` (from
    /// [`PairOTState::read_from`] or a
    /// `PairSetupParty` run), returning the state it
    /// replaces. Fails when `peer` is not a member of this key or is this
    /// party itself.
    pub fn set_pair(
        &mut self,
        peer: &PartyId,
        state: PairOTState,
    ) -> Result<Option<PairOTState>, super::Error> {
        let pos = self.peer_position(peer)?;
        Ok(self.ot[pos].replace(state))
    }

    /// Removes the pairwise OT-extension state shared with `peer`, returning
    /// it. The key stays usable for signing with every peer whose state is
    /// still loaded.
    pub fn remove_pair(&mut self, peer: &PartyId) -> Option<PairOTState> {
        let pos = self.position_of(peer)?;
        self.ot.get_mut(pos)?.take()
    }

    /// The members of `signers` (other than this party) whose pairwise state
    /// is not loaded. Signing with `signers` needs this to be empty; pairs
    /// with parties outside `signers` are never needed. Parties that are not
    /// members of this key are ignored here.
    pub fn missing_pairs(&self, signers: &[PartyId]) -> Vec<PartyId> {
        signers
            .iter()
            .filter(|p| match self.position_of(p) {
                Some(pos) => pos != self.idx && self.ot.get(pos).is_none_or(|o| o.is_none()),
                None => false,
            })
            .cloned()
            .collect()
    }

    /// Checks that this key holds the pairwise state for every other member
    /// of `signers` (all of which must be members), failing with [`Error::MissingPairs`](super::Error::MissingPairs)
    /// naming the peers it lacks.
    pub(crate) fn require_pairs(&self, signers: &[PartyId]) -> Result<(), super::Error> {
        if let Some(p) = signers.iter().find(|p| self.position_of(p).is_none()) {
            return Err(super::Error::Validation(format!(
                "signer {p} is not a member of this key"
            )));
        }
        let peers = self.missing_pairs(signers);
        if peers.is_empty() {
            return Ok(());
        }
        Err(super::Error::MissingPairs {
            party: self.party_ids[self.idx].clone(),
            peers,
        })
    }

    /// Position of a member other than this party, or a validation error.
    fn peer_position(&self, peer: &PartyId) -> Result<usize, super::Error> {
        match self.position_of(peer) {
            Some(pos) if pos == self.idx => Err(super::Error::Validation(
                "a party has no pairwise state with itself".into(),
            )),
            Some(pos) if pos < self.ot.len() => Ok(pos),
            _ => Err(super::Error::Validation(format!(
                "{peer} is not a member of this key"
            ))),
        }
    }

    /// Overwrites the secret share with zero and scrubs every per-pair OT
    /// state (PRG seeds and correlation Δ), rendering the key unusable for
    /// signing or resharing. The chain code (public, but consistent with the
    /// "unusable after zeroize" contract) is also cleared. Mirrors
    /// [`crate::frosttss::Key::zeroize`].
    ///
    /// Note: `purecrypto`'s secp256k1 `Scalar` wipes its limbs on drop, so the
    /// old `xi` value is scrubbed when it is replaced here (and whenever a
    /// `Key` is dropped); the OT byte arrays have no such drop behavior, hence
    /// the explicit overwrite.
    pub fn zeroize(&mut self) {
        self.xi = Scalar::ZERO;
        for pair in self.ot.iter_mut().flatten() {
            pair.zeroize();
        }
        self.chain_code = [0u8; 32];
    }
}

#[cfg(test)]
mod tests {
    use super::super::{keygen, otext};
    use crate::prelude::*;
    use crate::rng::SystemRng;

    #[test]
    fn zeroize_clears_share_and_ot_state() {
        let ids = crate::tss::PartyId::sort(
            (1..=2u8)
                .map(|i| crate::tss::PartyId::new(i.to_string(), format!("P{i}"), vec![i]))
                .collect(),
            0,
        );
        let mut keys = keygen(2, 1, &ids, &mut SystemRng).unwrap();
        let mut key = keys.remove(0);
        assert!(!bool::from(key.xi.is_zero()));
        key.zeroize();
        assert!(bool::from(key.xi.is_zero()));
        assert_eq!(key.chain_code, [0u8; 32]);
        for pair in key.ot.iter().flatten() {
            assert_eq!(
                pair.as_alice.to_bytes(),
                vec![0u8; 2 * otext::KAPPA * otext::SEED_LEN]
            );
            assert_eq!(
                pair.as_bob.to_bytes(),
                vec![0u8; otext::DELTA_BYTES + otext::KAPPA * otext::SEED_LEN]
            );
        }
    }
}

/// A DKLs ECDSA signature. `(r, s)` is canonical (low-S); `v` is the recovery
/// parity bit of `R.y`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Signature `r` component (big-endian 32 bytes).
    pub r: Vec<u8>,
    /// Signature `s` component (big-endian 32 bytes).
    pub s: Vec<u8>,
    /// Recovery parity bit.
    pub v: u8,
}
