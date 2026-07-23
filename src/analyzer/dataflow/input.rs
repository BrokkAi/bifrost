//! ICFG input quality and malformed-input errors.

use std::{error::Error, fmt};

use crate::analyzer::semantic::{
    IcfgNodeId, IcfgSnapshot, SemanticBudgetExceeded, SemanticCapability, SemanticOutcome,
};

/// Quality retained from the semantic outcome that produced an ICFG snapshot.
///
/// The snapshot itself does not retain this envelope, so callers must keep it
/// beside the graph to prevent a partial input from becoming a complete
/// data-flow result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgInputStatus {
    Complete,
    Ambiguous,
    Unknown,
    Unsupported { capability: SemanticCapability },
    Unproven,
    ExceededBudget { exceeded: SemanticBudgetExceeded },
    Cancelled,
}

impl IcfgInputStatus {
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
        let status = match outcome {
            SemanticOutcome::Complete { .. } => IcfgInputStatus::Complete,
            SemanticOutcome::Ambiguous { .. } => IcfgInputStatus::Ambiguous,
            SemanticOutcome::Unknown { .. } => IcfgInputStatus::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => IcfgInputStatus::Unsupported {
                capability: *capability,
            },
            SemanticOutcome::Unproven { .. } => IcfgInputStatus::Unproven,
            SemanticOutcome::ExceededBudget { exceeded, .. } => IcfgInputStatus::ExceededBudget {
                exceeded: *exceeded,
            },
            SemanticOutcome::Cancelled { .. } => IcfgInputStatus::Cancelled,
        };
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
