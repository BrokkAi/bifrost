//! Provider outcomes, finite budgets, and the language-neutral adapter boundary.

use std::fmt;
use std::sync::Arc;

use crate::analyzer::ProjectFile;

use super::capabilities::{SemanticCapabilities, SemanticCapability};
use super::ids::{SemanticArtifactKey, SemanticLanguage};
use super::ir::SemanticArtifact;

/// One independently bounded semantic-materialization dimension.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SemanticBudgetDimension {
    SourceBytes,
    Procedures,
    Blocks,
    ProgramPoints,
    Values,
    Allocations,
    CallSites,
    MemoryLocations,
    Captures,
    SourceMappings,
    Evidence,
    Gaps,
}

impl SemanticBudgetDimension {
    pub const ALL: [Self; 12] = [
        Self::SourceBytes,
        Self::Procedures,
        Self::Blocks,
        Self::ProgramPoints,
        Self::Values,
        Self::Allocations,
        Self::CallSites,
        Self::MemoryLocations,
        Self::Captures,
        Self::SourceMappings,
        Self::Evidence,
        Self::Gaps,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::SourceBytes => "source_bytes",
            Self::Procedures => "procedures",
            Self::Blocks => "blocks",
            Self::ProgramPoints => "program_points",
            Self::Values => "values",
            Self::Allocations => "allocations",
            Self::CallSites => "call_sites",
            Self::MemoryLocations => "memory_locations",
            Self::Captures => "captures",
            Self::SourceMappings => "source_mappings",
            Self::Evidence => "evidence",
            Self::Gaps => "gaps",
        }
    }
}

/// Work performed or limits applied while materializing semantic facts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticWork {
    pub source_bytes: usize,
    pub procedures: usize,
    pub blocks: usize,
    pub program_points: usize,
    pub values: usize,
    pub allocations: usize,
    pub call_sites: usize,
    pub memory_locations: usize,
    pub captures: usize,
    pub source_mappings: usize,
    pub evidence: usize,
    pub gaps: usize,
}

impl SemanticWork {
    pub const fn uniform(value: usize) -> Self {
        Self {
            source_bytes: value,
            procedures: value,
            blocks: value,
            program_points: value,
            values: value,
            allocations: value,
            call_sites: value,
            memory_locations: value,
            captures: value,
            source_mappings: value,
            evidence: value,
            gaps: value,
        }
    }

    pub const fn get(self, dimension: SemanticBudgetDimension) -> usize {
        match dimension {
            SemanticBudgetDimension::SourceBytes => self.source_bytes,
            SemanticBudgetDimension::Procedures => self.procedures,
            SemanticBudgetDimension::Blocks => self.blocks,
            SemanticBudgetDimension::ProgramPoints => self.program_points,
            SemanticBudgetDimension::Values => self.values,
            SemanticBudgetDimension::Allocations => self.allocations,
            SemanticBudgetDimension::CallSites => self.call_sites,
            SemanticBudgetDimension::MemoryLocations => self.memory_locations,
            SemanticBudgetDimension::Captures => self.captures,
            SemanticBudgetDimension::SourceMappings => self.source_mappings,
            SemanticBudgetDimension::Evidence => self.evidence,
            SemanticBudgetDimension::Gaps => self.gaps,
        }
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            source_bytes: self.source_bytes.checked_add(other.source_bytes)?,
            procedures: self.procedures.checked_add(other.procedures)?,
            blocks: self.blocks.checked_add(other.blocks)?,
            program_points: self.program_points.checked_add(other.program_points)?,
            values: self.values.checked_add(other.values)?,
            allocations: self.allocations.checked_add(other.allocations)?,
            call_sites: self.call_sites.checked_add(other.call_sites)?,
            memory_locations: self.memory_locations.checked_add(other.memory_locations)?,
            captures: self.captures.checked_add(other.captures)?,
            source_mappings: self.source_mappings.checked_add(other.source_mappings)?,
            evidence: self.evidence.checked_add(other.evidence)?,
            gaps: self.gaps.checked_add(other.gaps)?,
        })
    }

    fn saturating_sub(self, other: Self) -> Self {
        Self {
            source_bytes: self.source_bytes.saturating_sub(other.source_bytes),
            procedures: self.procedures.saturating_sub(other.procedures),
            blocks: self.blocks.saturating_sub(other.blocks),
            program_points: self.program_points.saturating_sub(other.program_points),
            values: self.values.saturating_sub(other.values),
            allocations: self.allocations.saturating_sub(other.allocations),
            call_sites: self.call_sites.saturating_sub(other.call_sites),
            memory_locations: self.memory_locations.saturating_sub(other.memory_locations),
            captures: self.captures.saturating_sub(other.captures),
            source_mappings: self.source_mappings.saturating_sub(other.source_mappings),
            evidence: self.evidence.saturating_sub(other.evidence),
            gaps: self.gaps.saturating_sub(other.gaps),
        }
    }
}

/// A positive finite set of semantic materialization limits and its used work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticBudget {
    limits: SemanticWork,
    used: SemanticWork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSemanticBudget {
    dimension: SemanticBudgetDimension,
}

impl InvalidSemanticBudget {
    pub const fn dimension(self) -> SemanticBudgetDimension {
        self.dimension
    }
}

impl fmt::Display for InvalidSemanticBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic budget limit `{}` must be positive",
            self.dimension.label()
        )
    }
}

impl std::error::Error for InvalidSemanticBudget {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticBudgetExceeded {
    dimension: SemanticBudgetDimension,
    limit: usize,
    attempted: usize,
}

impl SemanticBudgetExceeded {
    pub const fn dimension(self) -> SemanticBudgetDimension {
        self.dimension
    }

    pub const fn limit(self) -> usize {
        self.limit
    }

    pub const fn attempted(self) -> usize {
        self.attempted
    }
}

impl fmt::Display for SemanticBudgetExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic work `{}` attempted {} against limit {}",
            self.dimension.label(),
            self.attempted,
            self.limit
        )
    }
}

impl std::error::Error for SemanticBudgetExceeded {}

impl SemanticBudget {
    pub fn new(limits: SemanticWork) -> Result<Self, InvalidSemanticBudget> {
        for dimension in SemanticBudgetDimension::ALL {
            if limits.get(dimension) == 0 {
                return Err(InvalidSemanticBudget { dimension });
            }
        }
        Ok(Self {
            limits,
            used: SemanticWork::default(),
        })
    }

    pub fn uniform(limit: usize) -> Result<Self, InvalidSemanticBudget> {
        Self::new(SemanticWork::uniform(limit))
    }

    pub const fn limits(&self) -> SemanticWork {
        self.limits
    }

    pub const fn used(&self) -> SemanticWork {
        self.used
    }

    pub fn remaining(&self) -> SemanticWork {
        self.limits.saturating_sub(self.used)
    }

    /// Atomically charge work; a failed charge leaves the budget unchanged.
    pub fn charge(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        for dimension in SemanticBudgetDimension::ALL {
            let attempted = self
                .used
                .get(dimension)
                .checked_add(work.get(dimension))
                .unwrap_or(usize::MAX);
            let limit = self.limits.get(dimension);
            if attempted > limit {
                return Err(SemanticBudgetExceeded {
                    dimension,
                    limit,
                    attempted,
                });
            }
        }
        self.used = self
            .used
            .checked_add(work)
            .expect("validated semantic budget charge cannot overflow");
        Ok(())
    }
}

impl Default for SemanticBudget {
    fn default() -> Self {
        Self::new(SemanticWork {
            source_bytes: 16 * 1024 * 1024,
            procedures: 10_000,
            blocks: 100_000,
            program_points: 1_000_000,
            values: 1_000_000,
            allocations: 100_000,
            call_sites: 100_000,
            memory_locations: 250_000,
            captures: 100_000,
            source_mappings: 1_000_000,
            evidence: 250_000,
            gaps: 100_000,
        })
        .expect("default semantic budgets are positive")
    }
}

/// A semantic result whose uncertainty, partial value, and work remain explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticOutcome<T> {
    Complete {
        value: T,
        work: SemanticWork,
    },
    Ambiguous {
        candidates: T,
        work: SemanticWork,
    },
    Unknown {
        partial: Option<T>,
        work: SemanticWork,
    },
    Unsupported {
        capability: SemanticCapability,
        partial: Option<T>,
        work: SemanticWork,
    },
    Unproven {
        partial: T,
        work: SemanticWork,
    },
    ExceededBudget {
        partial: Option<T>,
        limit: SemanticBudgetDimension,
        work: SemanticWork,
    },
}

impl<T> SemanticOutcome<T> {
    pub const fn work(&self) -> SemanticWork {
        match self {
            Self::Complete { work, .. }
            | Self::Ambiguous { work, .. }
            | Self::Unknown { work, .. }
            | Self::Unsupported { work, .. }
            | Self::Unproven { work, .. }
            | Self::ExceededBudget { work, .. } => *work,
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    pub fn available_value(&self) -> Option<&T> {
        match self {
            Self::Complete { value, .. } => Some(value),
            Self::Ambiguous { candidates, .. } => Some(candidates),
            Self::Unknown { partial, .. }
            | Self::Unsupported { partial, .. }
            | Self::ExceededBudget { partial, .. } => partial.as_ref(),
            Self::Unproven { partial, .. } => Some(partial),
        }
    }

    pub fn map<U>(self, mapper: impl FnOnce(T) -> U) -> SemanticOutcome<U> {
        match self {
            Self::Complete { value, work } => SemanticOutcome::Complete {
                value: mapper(value),
                work,
            },
            Self::Ambiguous { candidates, work } => SemanticOutcome::Ambiguous {
                candidates: mapper(candidates),
                work,
            },
            Self::Unknown { partial, work } => SemanticOutcome::Unknown {
                partial: partial.map(mapper),
                work,
            },
            Self::Unsupported {
                capability,
                partial,
                work,
            } => SemanticOutcome::Unsupported {
                capability,
                partial: partial.map(mapper),
                work,
            },
            Self::Unproven { partial, work } => SemanticOutcome::Unproven {
                partial: mapper(partial),
                work,
            },
            Self::ExceededBudget {
                partial,
                limit,
                work,
            } => SemanticOutcome::ExceededBudget {
                partial: partial.map(mapper),
                limit,
                work,
            },
        }
    }
}

/// A standalone per-language adapter boundary for immutable semantic artifacts.
pub trait ProgramSemanticsProvider: Send + Sync {
    fn language(&self) -> SemanticLanguage;

    fn capabilities(&self) -> &SemanticCapabilities;

    fn artifact_key(&self, file: &ProjectFile) -> SemanticOutcome<SemanticArtifactKey>;

    fn artifact(
        &self,
        key: &SemanticArtifactKey,
        budget: &mut SemanticBudget,
    ) -> SemanticOutcome<Arc<SemanticArtifact>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_budget_requires_every_limit_to_be_positive() {
        assert_eq!(
            SemanticBudget::uniform(0),
            Err(InvalidSemanticBudget {
                dimension: SemanticBudgetDimension::SourceBytes,
            })
        );
        assert!(SemanticBudget::uniform(1).is_ok());
    }

    #[test]
    fn failed_budget_charge_is_atomic_and_identifies_the_limit() {
        let mut budget = SemanticBudget::uniform(2).unwrap();
        budget
            .charge(SemanticWork {
                procedures: 2,
                ..SemanticWork::default()
            })
            .unwrap();
        let before = budget.used();
        let error = budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(error.dimension(), SemanticBudgetDimension::Procedures);
        assert_eq!(error.limit(), 2);
        assert_eq!(error.attempted(), 3);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn outcome_mapping_preserves_variant_partial_data_and_work() {
        let work = SemanticWork {
            program_points: 3,
            ..SemanticWork::default()
        };
        let outcomes = [
            SemanticOutcome::Complete { value: 1, work },
            SemanticOutcome::Ambiguous {
                candidates: 2,
                work,
            },
            SemanticOutcome::Unknown {
                partial: Some(3),
                work,
            },
            SemanticOutcome::Unsupported {
                capability: SemanticCapability::ExceptionalControlFlow,
                partial: Some(4),
                work,
            },
            SemanticOutcome::Unproven { partial: 5, work },
            SemanticOutcome::ExceededBudget {
                partial: Some(6),
                limit: SemanticBudgetDimension::ProgramPoints,
                work,
            },
        ];

        let mapped = outcomes.map(|outcome| outcome.map(|value| value.to_string()));
        for (index, outcome) in mapped.iter().enumerate() {
            let expected = (index + 1).to_string();
            assert_eq!(outcome.work(), work);
            assert_eq!(
                outcome.available_value().map(String::as_str),
                Some(expected.as_str())
            );
        }
        assert!(mapped[0].is_complete());
        assert!(!mapped[1].is_complete());
    }
}
