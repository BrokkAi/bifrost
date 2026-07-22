//! Provider outcomes, finite budgets, and the language-neutral adapter boundary.

use std::fmt;
use std::sync::Arc;

use crate::analyzer::ProjectFile;
use crate::cancellation::CancellationToken;

use super::capabilities::SemanticCapability;
use super::ids::SemanticArtifactKey;
use super::ir::{SemanticArtifact, SemanticIrError};

/// Declare every independently bounded semantic-materialization dimension once.
///
/// The registry generates the public dimension enum and its stable order together
/// with every field-wise [`SemanticWork`] operation, preventing a newly added
/// dimension from silently escaping validation, accounting, or remaining-work
/// calculations.
macro_rules! semantic_budget_dimensions {
    ($($dimension:ident => $field:ident = $default_limit:expr),+ $(,)?) => {
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum SemanticBudgetDimension {
            $($dimension),+
        }

        impl SemanticBudgetDimension {
            pub const ALL: [Self; count_idents!($($dimension),+)] = [
                $(Self::$dimension),+
            ];

            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$dimension => stringify!($field)),+
                }
            }
        }

        /// Work performed or limits applied while materializing semantic facts.
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct SemanticWork {
            $(pub $field: usize),+
        }

        impl SemanticWork {
            pub const fn uniform(value: usize) -> Self {
                Self {
                    $($field: value),+
                }
            }

            pub const fn get(self, dimension: SemanticBudgetDimension) -> usize {
                match dimension {
                    $(SemanticBudgetDimension::$dimension => self.$field),+
                }
            }

            const fn default_limits() -> Self {
                Self {
                    $($field: $default_limit),+
                }
            }

            pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
                Some(Self {
                    $($field: self.$field.checked_add(other.$field)?),+
                })
            }

            /// Add work conservatively, using a uniformly maximal sentinel if
            /// any dimension overflows.
            ///
            /// Budget accounting treats overflow as an unconditional stop. A
            /// single shared operation keeps that policy consistent across
            /// lowering, CFG/ICFG construction, and oracle materialization.
            pub(crate) fn conservative_add(self, other: Self) -> Self {
                self.checked_add(other)
                    .unwrap_or_else(|| Self::uniform(usize::MAX))
            }

            pub(crate) fn component_max(self, other: Self) -> Self {
                Self {
                    $($field: self.$field.max(other.$field)),+
                }
            }

            fn saturating_sub(self, other: Self) -> Self {
                Self {
                    $($field: self.$field.saturating_sub(other.$field)),+
                }
            }
        }
    };
}

semantic_budget_dimensions! {
    SourceBytes => source_bytes = 16 * 1024 * 1024,
    Procedures => procedures = 10_000,
    Blocks => blocks = 100_000,
    ProgramPoints => program_points = 1_000_000,
    Values => values = 1_000_000,
    Allocations => allocations = 100_000,
    CallSites => call_sites = 100_000,
    MemoryLocations => memory_locations = 250_000,
    Captures => captures = 100_000,
    SourceMappings => source_mappings = 1_000_000,
    Evidence => evidence = 250_000,
    Gaps => gaps = 100_000,
    Events => events = 4_000_000,
    ControlEdges => control_edges = 2_000_000,
    NestedEntries => nested_entries = 8_000_000,
    OwnedTextBytes => owned_text_bytes = 32 * 1024 * 1024,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    /// Check one atomic charge without mutating this budget.
    pub fn check(&self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        for dimension in SemanticBudgetDimension::ALL {
            let limit = self.limits.get(dimension);
            let Some(attempted) = self.used.get(dimension).checked_add(work.get(dimension)) else {
                return Err(SemanticBudgetExceeded {
                    dimension,
                    limit,
                    attempted: usize::MAX,
                });
            };
            if attempted > limit {
                return Err(SemanticBudgetExceeded {
                    dimension,
                    limit,
                    attempted,
                });
            }
        }
        Ok(())
    }

    /// Atomically charge work; a failed charge leaves the budget unchanged.
    pub fn charge(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.check(work)?;
        self.used = self
            .used
            .checked_add(work)
            .expect("validated semantic budget charge cannot overflow");
        Ok(())
    }
}

impl Default for SemanticBudget {
    fn default() -> Self {
        Self::new(SemanticWork::default_limits()).expect("default semantic budgets are positive")
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
        exceeded: SemanticBudgetExceeded,
        work: SemanticWork,
    },
    Cancelled {
        partial: Option<T>,
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
            | Self::ExceededBudget { work, .. }
            | Self::Cancelled { work, .. } => *work,
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    pub const fn budget_exceeded(&self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::ExceededBudget { exceeded, .. } => Some(*exceeded),
            Self::Complete { .. }
            | Self::Ambiguous { .. }
            | Self::Unknown { .. }
            | Self::Unsupported { .. }
            | Self::Unproven { .. }
            | Self::Cancelled { .. } => None,
        }
    }

    pub fn available_value(&self) -> Option<&T> {
        match self {
            Self::Complete { value, .. } => Some(value),
            Self::Ambiguous { candidates, .. } => Some(candidates),
            Self::Unknown { partial, .. }
            | Self::Unsupported { partial, .. }
            | Self::ExceededBudget { partial, .. }
            | Self::Cancelled { partial, .. } => partial.as_ref(),
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
                exceeded,
                work,
            } => SemanticOutcome::ExceededBudget {
                partial: partial.map(mapper),
                exceeded,
                work,
            },
            Self::Cancelled { partial, work } => SemanticOutcome::Cancelled {
                partial: partial.map(mapper),
                work,
            },
        }
    }
}

/// Request-local controls for one semantic materialization.
///
/// The provider borrows both values so cancellation and retained-payload
/// accounting remain owned by the caller rather than hidden in an adapter.
pub struct SemanticRequest<'a> {
    pub budget: &'a mut SemanticBudget,
    pub cancellation: &'a CancellationToken,
}

impl<'a> SemanticRequest<'a> {
    pub fn new(budget: &'a mut SemanticBudget, cancellation: &'a CancellationToken) -> Self {
        Self {
            budget,
            cancellation,
        }
    }
}

/// Operational failure while a provider reads source, derives identity, or
/// validates a materialized artifact.  Semantic uncertainty remains in
/// [`SemanticOutcome`] and must not be used to disguise these failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticProviderError {
    SourceAccess(Box<str>),
    InvalidIdentity(Box<str>),
    InvalidArtifact(SemanticIrError),
    Internal(Box<str>),
}

impl SemanticProviderError {
    pub fn source_access(detail: impl Into<String>) -> Self {
        Self::SourceAccess(detail.into().into_boxed_str())
    }

    pub fn invalid_identity(detail: impl Into<String>) -> Self {
        Self::InvalidIdentity(detail.into().into_boxed_str())
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::Internal(detail.into().into_boxed_str())
    }
}

impl From<SemanticIrError> for SemanticProviderError {
    fn from(error: SemanticIrError) -> Self {
        Self::InvalidArtifact(error)
    }
}

impl fmt::Display for SemanticProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceAccess(detail) => {
                write!(formatter, "semantic source access failed: {detail}")
            }
            Self::InvalidIdentity(detail) => {
                write!(formatter, "semantic artifact identity is invalid: {detail}")
            }
            Self::InvalidArtifact(error) => write!(formatter, "{error}"),
            Self::Internal(detail) => write!(formatter, "semantic provider failed: {detail}"),
        }
    }
}

impl std::error::Error for SemanticProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidArtifact(error) => Some(error),
            Self::SourceAccess(_) | Self::InvalidIdentity(_) | Self::Internal(_) => None,
        }
    }
}

/// One current source snapshot and the complete semantic artifact identity
/// derived from that same atomic project read.
///
/// This is not a materialized artifact and does not retain syntax or IR. It is
/// the source-bearing freshness proof used when a semantic handle crosses
/// provider calls and its exact source must be consumed by a downstream
/// resolver without a second, racing read.
#[derive(Debug, Clone)]
pub struct SemanticArtifactSourceSnapshot {
    key: SemanticArtifactKey,
    source: Arc<str>,
}

impl SemanticArtifactSourceSnapshot {
    pub(crate) fn new(key: SemanticArtifactKey, source: Arc<str>) -> Self {
        Self { key, source }
    }

    /// Complete artifact identity for this exact source snapshot.
    pub const fn key(&self) -> &SemanticArtifactKey {
        &self.key
    }

    /// Exact disk or overlay source used to derive [`Self::key`].
    pub fn source(&self) -> &str {
        &self.source
    }

    pub(crate) fn into_parts(self) -> (SemanticArtifactKey, Arc<str>) {
        (self.key, self.source)
    }
}

/// A standalone per-language adapter boundary for immutable semantic artifacts.
pub trait ProgramSemanticsProvider: Send + Sync {
    /// Capture the file's current atomic source snapshot and derive its complete
    /// semantic artifact identity without parsing or lowering procedures.
    ///
    /// `None` means the current snapshot exceeds `max_source_bytes`; source
    /// access and identity failures remain operational errors.
    fn current_artifact_source(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactSourceSnapshot>, SemanticProviderError>;

    /// Derive the complete identity of the file's current atomic source
    /// snapshot without parsing, lowering procedures, or charging semantic
    /// work.
    ///
    /// This is the generation check for handles that cross provider calls. It
    /// uses the same adapter, IR, configuration, and dependency identity as
    /// [`Self::materialize`].
    /// `None` means the current snapshot exceeds `max_source_bytes`; source
    /// access and identity failures remain operational errors.
    fn current_artifact_key(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        self.current_artifact_source(file, max_source_bytes)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.key().clone()))
    }

    /// Prepare one exact file snapshot, derive its identity, and lower it as
    /// one linearized operation. Implementations cache only complete artifacts.
    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingProgramSemanticsProvider(SemanticProviderError);

    impl ProgramSemanticsProvider for FailingProgramSemanticsProvider {
        fn current_artifact_source(
            &self,
            _file: &ProjectFile,
            _max_source_bytes: usize,
        ) -> Result<Option<SemanticArtifactSourceSnapshot>, SemanticProviderError> {
            Err(self.0.clone())
        }

        fn materialize(
            &self,
            _file: &ProjectFile,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
            Err(self.0.clone())
        }
    }

    fn mock_file() -> ProjectFile {
        ProjectFile::new(std::env::temp_dir(), "src/mock.ts")
    }

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
    fn dimension_registry_drives_uniform_work_labels_and_defaults() {
        let uniform = SemanticWork::uniform(7);
        for dimension in SemanticBudgetDimension::ALL {
            assert_eq!(uniform.get(dimension), 7, "{}", dimension.label());
            assert!(!dimension.label().is_empty());
        }

        let defaults = SemanticBudget::default().limits();
        assert_eq!(defaults.events, 4_000_000);
        assert_eq!(defaults.control_edges, 2_000_000);
        assert_eq!(defaults.nested_entries, 8_000_000);
        assert_eq!(defaults.owned_text_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn total_payload_dimensions_are_charged_atomically() {
        let mut budget = SemanticBudget::uniform(10).unwrap();
        budget
            .charge(SemanticWork {
                events: 7,
                control_edges: 8,
                nested_entries: 9,
                owned_text_bytes: 10,
                ..SemanticWork::default()
            })
            .unwrap();

        let remaining = budget.remaining();
        assert_eq!(remaining.events, 3);
        assert_eq!(remaining.control_edges, 2);
        assert_eq!(remaining.nested_entries, 1);
        assert_eq!(remaining.owned_text_bytes, 0);

        let before = budget.used();
        let error = budget
            .charge(SemanticWork {
                owned_text_bytes: 1,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(error.dimension(), SemanticBudgetDimension::OwnedTextBytes);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn provider_trait_object_round_trips_operational_error() {
        let expected = SemanticProviderError::source_access("mock source is unavailable");
        let provider_impl = FailingProgramSemanticsProvider(expected.clone());
        let provider: &dyn ProgramSemanticsProvider = &provider_impl;
        let mut budget = SemanticBudget::uniform(10).unwrap();
        let cancellation = CancellationToken::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);

        let actual = provider
            .materialize(&mock_file(), &mut request)
            .expect_err("source access failure is operational, not semantic unknown");

        assert_eq!(actual, expected);
        assert_eq!(
            actual.to_string(),
            "semantic source access failed: mock source is unavailable"
        );
        assert_eq!(budget.used(), SemanticWork::default());
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
    fn overflowing_budget_charge_is_rejected_even_at_the_maximum_limit() {
        let mut budget = SemanticBudget::uniform(usize::MAX).unwrap();
        budget
            .charge(SemanticWork {
                procedures: usize::MAX,
                ..SemanticWork::default()
            })
            .unwrap();
        let before = budget.used();

        let error = budget
            .charge(SemanticWork {
                procedures: 1,
                ..SemanticWork::default()
            })
            .expect_err("overflow must be a budget error, not a panic");

        assert_eq!(error.dimension(), SemanticBudgetDimension::Procedures);
        assert_eq!(error.limit(), usize::MAX);
        assert_eq!(error.attempted(), usize::MAX);
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
                exceeded: SemanticBudgetExceeded {
                    dimension: SemanticBudgetDimension::ProgramPoints,
                    limit: 2,
                    attempted: 3,
                },
                work,
            },
            SemanticOutcome::Cancelled {
                partial: Some(7),
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

    #[test]
    fn exceeded_budget_mapping_preserves_full_measurement() {
        let exceeded = SemanticBudgetExceeded {
            dimension: SemanticBudgetDimension::NestedEntries,
            limit: 8,
            attempted: 13,
        };
        let work = SemanticWork {
            nested_entries: 8,
            ..SemanticWork::default()
        };
        let mapped = SemanticOutcome::ExceededBudget {
            partial: Some(21_u32),
            exceeded,
            work,
        }
        .map(|value| value.to_string());

        assert_eq!(mapped.budget_exceeded(), Some(exceeded));
        assert_eq!(mapped.work(), work);
        assert_eq!(mapped.available_value().map(String::as_str), Some("21"));
    }
}
