//! Rich protocol error type.

use super::PartyId;

/// An error raised during a protocol round.
///
/// Mirrors the Go `tss.Error`: it carries the failing `task`, the `round`
/// number, the `victim` (the party that observed the failure), and any
/// `culprits` — the parties cryptographically identified as responsible
/// (identifiable abort). The underlying `cause` is kept as a message string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TssError {
    cause: String,
    task: String,
    round: i32,
    victim: Option<PartyId>,
    culprits: Vec<PartyId>,
}

impl TssError {
    /// Creates a new error with the given cause, task name, round number,
    /// victim, and culprits.
    pub fn new(
        cause: impl Into<String>,
        task: impl Into<String>,
        round: i32,
        victim: Option<PartyId>,
        culprits: Vec<PartyId>,
    ) -> Self {
        Self {
            cause: cause.into(),
            task: task.into(),
            round,
            victim,
            culprits,
        }
    }

    /// The underlying cause message.
    pub fn cause(&self) -> &str {
        &self.cause
    }

    /// The name of the task during which the error occurred.
    pub fn task(&self) -> &str {
        &self.task
    }

    /// The round number during which the error occurred.
    pub fn round(&self) -> i32 {
        self.round
    }

    /// The party that observed the error, if known.
    pub fn victim(&self) -> Option<&PartyId> {
        self.victim.as_ref()
    }

    /// The parties identified as responsible for the error, if any.
    pub fn culprits(&self) -> &[PartyId] {
        &self.culprits
    }
}

impl std::fmt::Display for TssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let victim = match &self.victim {
            Some(v) => v.to_string(),
            None => "<nil>".to_string(),
        };
        if self.culprits.is_empty() {
            write!(
                f,
                "task {}, party {}, round {}: {}",
                self.task, victim, self.round, self.cause
            )
        } else {
            let culprits: Vec<String> = self.culprits.iter().map(|c| c.to_string()).collect();
            write!(
                f,
                "task {}, party {}, round {}, culprits [{}]: {}",
                self.task,
                victim,
                self.round,
                culprits.join(" "),
                self.cause
            )
        }
    }
}

impl std::error::Error for TssError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_without_culprits() {
        let v = PartyId {
            id: "1".into(),
            moniker: "P[1]".into(),
            key: vec![1],
            index: 0,
        };
        let e = TssError::new("boom", "keygen", 2, Some(v), vec![]);
        assert_eq!(e.to_string(), "task keygen, party {0,P[1]}, round 2: boom");
    }

    #[test]
    fn display_with_culprits() {
        let c = PartyId {
            id: "2".into(),
            moniker: "P[2]".into(),
            key: vec![2],
            index: 1,
        };
        let e = TssError::new("cheated", "signing", 3, None, vec![c]);
        assert_eq!(
            e.to_string(),
            "task signing, party <nil>, round 3, culprits [{1,P[2]}]: cheated"
        );
    }
}
