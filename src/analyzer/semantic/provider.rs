//! Provider outcomes, finite budgets, and the language-neutral adapter boundary.

use std::fmt;
use std::sync::Arc;

use crate::analyzer::ProjectFile;

use super::capabilities::{SemanticCapabilities, SemanticCapability};
use super::ids::{SemanticArtifactKey, SemanticLanguage};
use super::ir::{SemanticArtifact, SemanticIrError};

macro_rules! count_budget_dimensions {
    ($($dimension:ident),* $(,)?) => {
        <[()]>::len(&[$(count_budget_dimensions!(@unit $dimension)),*])
    };
    (@unit $dimension:ident) => { () };
}

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
            pub const ALL: [Self; count_budget_dimensions!($($dimension),+)] = [
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

            fn checked_add(self, other: Self) -> Option<Self> {
                Some(Self {
                    $($field: self.$field.checked_add(other.$field)?),+
                })
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

    /// Atomically charge work; a failed charge leaves the budget unchanged.
    pub fn charge(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
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

    pub const fn budget_exceeded(&self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::ExceededBudget { exceeded, .. } => Some(*exceeded),
            Self::Complete { .. }
            | Self::Ambiguous { .. }
            | Self::Unknown { .. }
            | Self::Unsupported { .. }
            | Self::Unproven { .. } => None,
        }
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
                exceeded,
                work,
            } => SemanticOutcome::ExceededBudget {
                partial: partial.map(mapper),
                exceeded,
                work,
            },
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

/// A standalone per-language adapter boundary for immutable semantic artifacts.
pub trait ProgramSemanticsProvider: Send + Sync {
    fn language(&self) -> SemanticLanguage;

    fn capabilities(&self) -> &SemanticCapabilities;

    /// Derive the immutable snapshot identity while charging source reads,
    /// hashing, and other key-materialization work to `budget`.
    fn artifact_key(
        &self,
        file: &ProjectFile,
        budget: &mut SemanticBudget,
    ) -> Result<SemanticOutcome<SemanticArtifactKey>, SemanticProviderError>;

    /// Materialize semantic rows and their nested payload while charging every
    /// retained fact, edge, event, nested entry, and owned byte to `budget`.
    fn artifact(
        &self,
        key: &SemanticArtifactKey,
        budget: &mut SemanticBudget,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;

    use super::super::ids::{
        AdapterSemanticsVersion, ConfigurationFingerprint, ContentIdentity, DependencyFingerprint,
        SemanticIrVersion, SourceRevision, WorkspaceMountId, WorkspaceRelativePath,
    };

    const KEY_WORK: SemanticWork = SemanticWork {
        source_bytes: 3,
        owned_text_bytes: 5,
        procedures: 0,
        blocks: 0,
        program_points: 0,
        values: 0,
        allocations: 0,
        call_sites: 0,
        memory_locations: 0,
        captures: 0,
        source_mappings: 0,
        evidence: 0,
        gaps: 0,
        events: 0,
        control_edges: 0,
        nested_entries: 0,
    };

    struct MockProgramSemanticsProvider {
        capabilities: SemanticCapabilities,
        key_error: Option<SemanticProviderError>,
    }

    impl MockProgramSemanticsProvider {
        fn successful() -> Self {
            Self {
                capabilities: SemanticCapabilities::default(),
                key_error: None,
            }
        }

        fn failing(error: SemanticProviderError) -> Self {
            Self {
                capabilities: SemanticCapabilities::default(),
                key_error: Some(error),
            }
        }

        fn key_for(file: &ProjectFile) -> Result<SemanticArtifactKey, SemanticProviderError> {
            let path = WorkspaceRelativePath::try_from_path(file.rel_path())
                .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
            Ok(SemanticArtifactKey::new(
                WorkspaceMountId::hash_bytes(b"mock mount"),
                path,
                SemanticLanguage::Standard(Language::TypeScript),
                SourceRevision::Disk {
                    content: ContentIdentity::hash_bytes(b"mock content"),
                },
                AdapterSemanticsVersion::hash_bytes("mock-typescript", b"adapter-v1")
                    .expect("mock adapter name is non-empty"),
                SemanticIrVersion::current(),
                ConfigurationFingerprint::hash_bytes(b"mock configuration"),
                DependencyFingerprint::hash_bytes(b"mock dependencies"),
            ))
        }
    }

    impl ProgramSemanticsProvider for MockProgramSemanticsProvider {
        fn language(&self) -> SemanticLanguage {
            SemanticLanguage::Standard(Language::TypeScript)
        }

        fn capabilities(&self) -> &SemanticCapabilities {
            &self.capabilities
        }

        fn artifact_key(
            &self,
            file: &ProjectFile,
            budget: &mut SemanticBudget,
        ) -> Result<SemanticOutcome<SemanticArtifactKey>, SemanticProviderError> {
            if let Err(exceeded) = budget.charge(KEY_WORK) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: budget.used(),
                });
            }
            if let Some(error) = &self.key_error {
                return Err(error.clone());
            }
            Ok(SemanticOutcome::Complete {
                value: Self::key_for(file)?,
                work: KEY_WORK,
            })
        }

        fn artifact(
            &self,
            _key: &SemanticArtifactKey,
            _budget: &mut SemanticBudget,
        ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
            Err(SemanticProviderError::internal(
                "mock artifact materialization is not configured",
            ))
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
    fn provider_trait_object_charges_key_work_and_returns_semantics_inside_result() {
        let provider_impl = MockProgramSemanticsProvider::successful();
        let provider: &dyn ProgramSemanticsProvider = &provider_impl;
        let mut budget = SemanticBudget::uniform(10).unwrap();

        let outcome = provider
            .artifact_key(&mock_file(), &mut budget)
            .expect("operational key derivation succeeds");

        let SemanticOutcome::Complete { value, work } = outcome else {
            panic!("semantic unknown/unsupported/budget outcomes remain inside operational Ok")
        };
        assert_eq!(value.path().as_str(), "src/mock.ts");
        assert_eq!(work, KEY_WORK);
        assert_eq!(budget.used(), KEY_WORK);
        assert_eq!(provider.language(), value.language());
        assert_eq!(provider.capabilities(), &SemanticCapabilities::default());
    }

    #[test]
    fn provider_trait_object_round_trips_operational_error() {
        let expected = SemanticProviderError::source_access("mock source is unavailable");
        let provider_impl = MockProgramSemanticsProvider::failing(expected.clone());
        let provider: &dyn ProgramSemanticsProvider = &provider_impl;
        let mut budget = SemanticBudget::uniform(10).unwrap();

        let actual = provider
            .artifact_key(&mock_file(), &mut budget)
            .expect_err("source access failure is operational, not semantic unknown");

        assert_eq!(actual, expected);
        assert_eq!(
            actual.to_string(),
            "semantic source access failed: mock source is unavailable"
        );
        assert_eq!(budget.used(), KEY_WORK);
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
