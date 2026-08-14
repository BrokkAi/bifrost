//! ICFG input quality and malformed-input errors.

use std::{cmp::Ordering, error::Error, fmt};

use crate::analyzer::semantic::{
    IcfgNodeId, IcfgSnapshot, SemanticBudgetExceeded, SemanticCapability, SemanticOutcome,
};

/// Quality retained from the semantic outcome that produced an ICFG snapshot.
///
/// The snapshot itself does not retain this envelope, so callers must keep it
/// beside the graph to prevent a partial input from becoming a complete
/// data-flow result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticInputStatus {
    #[default]
    Complete,
    Ambiguous,
    Unknown,
    Unsupported {
        capability: SemanticCapability,
    },
    Unproven,
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
    },
    Cancelled,
}

impl SemanticInputStatus {
    pub fn from_outcome<T>(outcome: &SemanticOutcome<T>) -> Self {
        match outcome {
            SemanticOutcome::Complete { .. } => Self::Complete,
            SemanticOutcome::Ambiguous { .. } => Self::Ambiguous,
            SemanticOutcome::Unknown { .. } => Self::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => Self::Unsupported {
                capability: *capability,
            },
            SemanticOutcome::Unproven { .. } => Self::Unproven,
            SemanticOutcome::ExceededBudget { exceeded, .. } => Self::ExceededBudget {
                exceeded: *exceeded,
            },
            SemanticOutcome::Cancelled { .. } => Self::Cancelled,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
            Self::Unsupported { .. } => "unsupported",
            Self::Unproven => "unproven",
            Self::ExceededBudget { .. } => "exceeded_budget",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn unsupported_capability(self) -> Option<SemanticCapability> {
        match self {
            Self::Unsupported { capability } => Some(capability),
            _ => None,
        }
    }

    pub const fn budget_exceeded(self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::ExceededBudget { exceeded } => Some(exceeded),
            _ => None,
        }
    }

    /// Merge statuses independently of provider traversal order.
    pub fn merge(self, incoming: Self) -> Self {
        use SemanticInputStatus::{
            Ambiguous, Cancelled, Complete, ExceededBudget, Unknown, Unproven, Unsupported,
        };

        match (self, incoming) {
            (Cancelled, _) | (_, Cancelled) => Cancelled,
            (ExceededBudget { exceeded: left }, ExceededBudget { exceeded: right }) => {
                ExceededBudget {
                    exceeded: min_budget_exceeded(left, right),
                }
            }
            (ExceededBudget { exceeded }, _) | (_, ExceededBudget { exceeded }) => {
                ExceededBudget { exceeded }
            }
            (Unsupported { capability: left }, Unsupported { capability: right }) => Unsupported {
                capability: left.min(right),
            },
            (Unsupported { capability }, _) | (_, Unsupported { capability }) => {
                Unsupported { capability }
            }
            (Unknown, _) | (_, Unknown) => Unknown,
            (Unproven, _) | (_, Unproven) => Unproven,
            (Ambiguous, _) | (_, Ambiguous) => Ambiguous,
            (Complete, Complete) => Complete,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Ambiguous => 1,
            Self::Unproven => 2,
            Self::Unknown => 3,
            Self::Unsupported { .. } => 4,
            Self::ExceededBudget { .. } => 5,
            Self::Cancelled => 6,
        }
    }
}

impl Ord for SemanticInputStatus {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank()
            .cmp(&other.rank())
            .then_with(|| match (*self, *other) {
                (
                    Self::Unsupported { capability: left },
                    Self::Unsupported { capability: right },
                ) => left.cmp(&right),
                (
                    Self::ExceededBudget { exceeded: left },
                    Self::ExceededBudget { exceeded: right },
                ) => (left.dimension(), left.limit(), left.attempted()).cmp(&(
                    right.dimension(),
                    right.limit(),
                    right.attempted(),
                )),
                _ => Ordering::Equal,
            })
    }
}

impl PartialOrd for SemanticInputStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Direct ICFG solve terminology for the shared semantic input status.
pub type IcfgInputStatus = SemanticInputStatus;

fn min_budget_exceeded(
    left: SemanticBudgetExceeded,
    right: SemanticBudgetExceeded,
) -> SemanticBudgetExceeded {
    if (left.dimension(), left.limit(), left.attempted())
        <= (right.dimension(), right.limit(), right.attempted())
    {
        left
    } else {
        right
    }
}

/// One traversable ICFG snapshot paired with its construction status.
#[derive(Debug, Clone, Copy)]
pub struct IcfgSolveInput<'graph> {
    snapshot: &'graph IcfgSnapshot,
    status: IcfgInputStatus,
}

impl<'graph> IcfgSolveInput<'graph> {
    const fn new(snapshot: &'graph IcfgSnapshot, status: IcfgInputStatus) -> Self {
        Self { snapshot, status }
    }

    pub fn from_outcome(
        outcome: &'graph SemanticOutcome<IcfgSnapshot>,
    ) -> Result<Self, DataflowError> {
        Self::try_from(outcome)
    }

    pub const fn snapshot(self) -> &'graph IcfgSnapshot {
        self.snapshot
    }

    pub const fn status(self) -> IcfgInputStatus {
        self.status
    }
}

impl<'graph> TryFrom<&'graph SemanticOutcome<IcfgSnapshot>> for IcfgSolveInput<'graph> {
    type Error = DataflowError;

    fn try_from(outcome: &'graph SemanticOutcome<IcfgSnapshot>) -> Result<Self, Self::Error> {
        let status = IcfgInputStatus::from_outcome(outcome);
        let snapshot = outcome
            .available_value()
            .ok_or(DataflowError::MissingIcfgSnapshot { status })?;
        Ok(Self::new(snapshot, status))
    }
}

/// Stable malformed-input errors; cancellation and budgets are normal results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowError {
    MissingIcfgSnapshot { status: IcfgInputStatus },
    InvalidSeedNode { node: IcfgNodeId, node_count: usize },
    FactIdOverflow { index: usize },
}

impl fmt::Display for DataflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingIcfgSnapshot { status } => write!(
                formatter,
                "ICFG outcome {} does not contain a traversable snapshot",
                status.label()
            ),
            Self::InvalidSeedNode { node, node_count } => write!(
                formatter,
                "data-flow seed node {node} is outside the {node_count}-node ICFG"
            ),
            Self::FactIdOverflow { index } => {
                write!(formatter, "data-flow fact index {index} exceeds u32")
            }
        }
    }
}

impl Error for DataflowError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{SemanticBudget, SemanticWork};

    fn source_budget_error(limit: usize, attempted: usize) -> SemanticBudgetExceeded {
        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = limit;
        SemanticBudget::new(limits)
            .expect("positive budget")
            .check(SemanticWork {
                source_bytes: attempted,
                ..SemanticWork::default()
            })
            .expect_err("source budget should be exceeded")
    }

    fn procedure_budget_error(limit: usize, attempted: usize) -> SemanticBudgetExceeded {
        let mut limits = SemanticBudget::default().limits();
        limits.procedures = limit;
        SemanticBudget::new(limits)
            .expect("positive budget")
            .check(SemanticWork {
                procedures: attempted,
                ..SemanticWork::default()
            })
            .expect_err("procedure budget should be exceeded")
    }

    #[test]
    fn semantic_input_status_merge_is_a_deterministic_join() {
        let statuses = [
            SemanticInputStatus::Complete,
            SemanticInputStatus::Ambiguous,
            SemanticInputStatus::Unproven,
            SemanticInputStatus::Unknown,
            SemanticInputStatus::Unsupported {
                capability: SemanticCapability::Assignments,
            },
            SemanticInputStatus::Unsupported {
                capability: SemanticCapability::Calls,
            },
            SemanticInputStatus::ExceededBudget {
                exceeded: source_budget_error(1, 2),
            },
            SemanticInputStatus::ExceededBudget {
                exceeded: procedure_budget_error(2, 3),
            },
            SemanticInputStatus::Cancelled,
        ];

        for &left in &statuses {
            assert_eq!(left.merge(left), left, "merge must be idempotent");
            for &right in &statuses {
                assert_eq!(
                    left.merge(right),
                    right.merge(left),
                    "merge must be commutative for {left:?} and {right:?}"
                );
                assert_eq!(
                    left.cmp(&right) == Ordering::Equal,
                    left == right,
                    "ordering must distinguish unequal payloads"
                );
                for &third in &statuses {
                    assert_eq!(
                        left.merge(right).merge(third),
                        left.merge(right.merge(third)),
                        "merge must be associative for {left:?}, {right:?}, and {third:?}"
                    );
                }
            }
        }
    }
}
