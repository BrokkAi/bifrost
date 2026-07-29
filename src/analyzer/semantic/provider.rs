//! Provider outcomes, finite budgets, and the language-neutral adapter boundary.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::analyzer::ProjectFile;
use crate::cancellation::CancellationToken;

use super::capabilities::SemanticCapability;
use super::ids::SemanticArtifactKey;
use super::ir::{SemanticArtifact, SemanticIrError};
use crate::analyzer::work_budget::{BudgetLedger, WorkBudgetExceeded, define_work_dimensions};

define_work_dimensions! {
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SemanticBudgetDimension;
    /// Work performed or limits applied while materializing semantic facts.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SemanticWork;
    all: pub [16];
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

impl SemanticWork {
    /// Add work conservatively, using a uniformly maximal sentinel if any
    /// dimension overflows.
    pub(crate) fn conservative_add(self, other: Self) -> Self {
        self.checked_add(other)
            .unwrap_or_else(|| Self::uniform(usize::MAX))
    }

    pub(crate) fn component_max(self, other: Self) -> Self {
        Self {
            source_bytes: self.source_bytes.max(other.source_bytes),
            procedures: self.procedures.max(other.procedures),
            blocks: self.blocks.max(other.blocks),
            program_points: self.program_points.max(other.program_points),
            values: self.values.max(other.values),
            allocations: self.allocations.max(other.allocations),
            call_sites: self.call_sites.max(other.call_sites),
            memory_locations: self.memory_locations.max(other.memory_locations),
            captures: self.captures.max(other.captures),
            source_mappings: self.source_mappings.max(other.source_mappings),
            evidence: self.evidence.max(other.evidence),
            gaps: self.gaps.max(other.gaps),
            events: self.events.max(other.events),
            control_edges: self.control_edges.max(other.control_edges),
            nested_entries: self.nested_entries.max(other.nested_entries),
            owned_text_bytes: self.owned_text_bytes.max(other.owned_text_bytes),
        }
    }
}

/// A positive finite set of semantic materialization limits and its used work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticBudget {
    ledger: BudgetLedger<SemanticWork>,
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

impl From<WorkBudgetExceeded<SemanticBudgetDimension>> for SemanticBudgetExceeded {
    fn from(exceeded: WorkBudgetExceeded<SemanticBudgetDimension>) -> Self {
        Self {
            dimension: exceeded.dimension(),
            limit: exceeded.limit(),
            attempted: exceeded.attempted(),
        }
    }
}

impl SemanticBudget {
    pub fn new(limits: SemanticWork) -> Result<Self, InvalidSemanticBudget> {
        for dimension in SemanticBudgetDimension::ALL {
            if limits.get(dimension) == 0 {
                return Err(InvalidSemanticBudget { dimension });
            }
        }
        Ok(Self {
            ledger: BudgetLedger::new(limits, SemanticWork::default()),
        })
    }

    pub fn uniform(limit: usize) -> Result<Self, InvalidSemanticBudget> {
        Self::new(SemanticWork::uniform(limit))
    }

    pub const fn limits(&self) -> SemanticWork {
        self.ledger.limits()
    }

    pub const fn used(&self) -> SemanticWork {
        self.ledger.used()
    }

    pub const fn remaining(&self) -> SemanticWork {
        self.limits().saturating_sub(self.used())
    }

    /// Check one atomic charge without mutating this budget.
    pub fn check(&self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.ledger.check(work).map_err(Into::into)
    }

    /// Atomically charge work; a failed charge leaves the budget unchanged.
    pub fn charge(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        self.ledger.charge(work).map_err(Into::into)
    }
}

impl Default for SemanticBudget {
    fn default() -> Self {
        Self::new(SemanticWork::default_limits()).expect("default semantic budgets are positive")
    }
}

/// Cross-provider limits for semantic work that is not represented by
/// [`SemanticWork`]: distinct workspace files entered and bounded traversal
/// steps performed while resolving them.
///
/// The shared ledger is deliberately request-scoped. Nested oracle requests
/// clone the handle, not the allowance, so dispatch cannot reset the caller's
/// file or traversal cap when it materializes candidate targets.
#[derive(Debug, Clone)]
pub struct SemanticExecutionBudget {
    state: Arc<Mutex<SemanticExecutionBudgetState>>,
}

#[derive(Debug)]
struct SemanticExecutionBudgetState {
    max_materialized_files: usize,
    max_traversal_steps: usize,
    materialized_files: HashSet<ProjectFile>,
    externally_materialized_files: usize,
    traversal_steps: usize,
    exhausted: bool,
}

/// Exact in-process identity of the provider work already charged to one
/// request-scoped execution budget.
///
/// The materialized file identities are retained instead of being collapsed
/// to a count: files already admitted can be revisited without consuming
/// another slot, so two ledgers with equal remaining counts are not
/// behaviorally interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SemanticExecutionBudgetSnapshot {
    max_materialized_files: usize,
    max_traversal_steps: usize,
    materialized_files: Box<[ProjectFile]>,
    externally_materialized_files: usize,
    traversal_steps: usize,
    exhausted: bool,
}

impl SemanticExecutionBudgetSnapshot {
    fn from_state(state: &SemanticExecutionBudgetState) -> Self {
        let mut materialized_files = state.materialized_files.iter().cloned().collect::<Vec<_>>();
        materialized_files.sort_unstable_by(|left, right| {
            left.root()
                .cmp(right.root())
                .then_with(|| left.rel_path().cmp(right.rel_path()))
        });
        Self {
            max_materialized_files: state.max_materialized_files,
            max_traversal_steps: state.max_traversal_steps,
            materialized_files: materialized_files.into_boxed_slice(),
            externally_materialized_files: state.externally_materialized_files,
            traversal_steps: state.traversal_steps,
            exhausted: state.exhausted,
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(std::mem::size_of_val(self.materialized_files.as_ref()))
    }
}

/// Provider-execution work that an exact cached result must replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticExecutionBudgetCharge {
    materialized_files: Box<[ProjectFile]>,
    externally_materialized_files: usize,
    traversal_steps: usize,
    exhausted: bool,
}

impl SemanticExecutionBudgetCharge {
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(std::mem::size_of_val(self.materialized_files.as_ref()))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SemanticExecutionWork {
    pub materialized_files: usize,
    pub traversal_steps: usize,
    pub exhausted: bool,
}

impl SemanticExecutionBudget {
    pub fn new(max_materialized_files: usize, max_traversal_steps: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(SemanticExecutionBudgetState {
                max_materialized_files,
                max_traversal_steps,
                materialized_files: HashSet::new(),
                externally_materialized_files: 0,
                traversal_steps: 0,
                exhausted: max_materialized_files == 0 || max_traversal_steps == 0,
            })),
        }
    }

    pub fn work(&self) -> SemanticExecutionWork {
        let state = self.state.lock().expect("semantic execution budget lock");
        SemanticExecutionWork {
            materialized_files: state
                .externally_materialized_files
                .saturating_add(state.materialized_files.len()),
            traversal_steps: state.traversal_steps,
            exhausted: state.exhausted,
        }
    }

    pub(crate) fn snapshot(&self) -> SemanticExecutionBudgetSnapshot {
        let state = self.state.lock().expect("semantic execution budget lock");
        SemanticExecutionBudgetSnapshot::from_state(&state)
    }

    pub(crate) fn charge_since(
        &self,
        before: &SemanticExecutionBudgetSnapshot,
    ) -> Option<SemanticExecutionBudgetCharge> {
        let state = self.state.lock().expect("semantic execution budget lock");
        if state.max_materialized_files != before.max_materialized_files
            || state.max_traversal_steps != before.max_traversal_steps
            || state.externally_materialized_files < before.externally_materialized_files
            || state.traversal_steps < before.traversal_steps
            || before
                .materialized_files
                .iter()
                .any(|file| !state.materialized_files.contains(file))
        {
            return None;
        }
        let before_files = before
            .materialized_files
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let mut materialized_files = state
            .materialized_files
            .difference(&before_files)
            .cloned()
            .collect::<Vec<_>>();
        materialized_files.sort_unstable_by(|left, right| {
            left.root()
                .cmp(right.root())
                .then_with(|| left.rel_path().cmp(right.rel_path()))
        });
        Some(SemanticExecutionBudgetCharge {
            materialized_files: materialized_files.into_boxed_slice(),
            externally_materialized_files: state
                .externally_materialized_files
                .saturating_sub(before.externally_materialized_files),
            traversal_steps: state.traversal_steps.saturating_sub(before.traversal_steps),
            exhausted: state.exhausted && !before.exhausted,
        })
    }

    /// Atomically reproduce provider work from an exact cached solve.
    pub(crate) fn replay_charge(
        &self,
        expected_before: &SemanticExecutionBudgetSnapshot,
        charge: &SemanticExecutionBudgetCharge,
    ) -> bool {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        if SemanticExecutionBudgetSnapshot::from_state(&state) != *expected_before
            || charge
                .materialized_files
                .iter()
                .any(|file| state.materialized_files.contains(file))
        {
            return false;
        }
        let attempted_files = state
            .externally_materialized_files
            .saturating_add(state.materialized_files.len())
            .saturating_add(charge.externally_materialized_files)
            .saturating_add(charge.materialized_files.len());
        let attempted_traversal = state.traversal_steps.saturating_add(charge.traversal_steps);
        if attempted_files > state.max_materialized_files
            || attempted_traversal > state.max_traversal_steps
        {
            return false;
        }
        state
            .materialized_files
            .extend(charge.materialized_files.iter().cloned());
        state.externally_materialized_files = state
            .externally_materialized_files
            .saturating_add(charge.externally_materialized_files);
        state.traversal_steps = attempted_traversal;
        state.exhausted |= charge.exhausted;
        true
    }

    pub fn remaining_materialized_files(&self) -> usize {
        let state = self.state.lock().expect("semantic execution budget lock");
        state.max_materialized_files.saturating_sub(
            state
                .externally_materialized_files
                .saturating_add(state.materialized_files.len()),
        )
    }

    pub fn remaining_traversal_steps(&self) -> usize {
        let state = self.state.lock().expect("semantic execution budget lock");
        state
            .max_traversal_steps
            .saturating_sub(state.traversal_steps)
    }

    pub(crate) fn admit_materialization(&self, file: &ProjectFile) -> bool {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        if state.materialized_files.contains(file) {
            return true;
        }
        let used = state
            .externally_materialized_files
            .saturating_add(state.materialized_files.len());
        if used >= state.max_materialized_files {
            state.exhausted = true;
            return false;
        }
        state.materialized_files.insert(file.clone());
        true
    }

    pub(crate) fn charge_external_query_work(
        &self,
        materialized_files: usize,
        traversal_steps: usize,
    ) -> bool {
        // CodeQuery currently reports only a count, not the identities, of
        // semantic materializations. Keep those slots anonymous: associating
        // them with final result paths would be unsound for branches that
        // materialize one file while producing evidence from another.
        self.charge_external_work(materialized_files, traversal_steps)
    }

    fn charge_external_work(&self, materialized_files: usize, traversal_steps: usize) -> bool {
        let mut state = self.state.lock().expect("semantic execution budget lock");
        let attempted_files = state
            .externally_materialized_files
            .saturating_add(state.materialized_files.len())
            .saturating_add(materialized_files);
        let attempted_traversal = state.traversal_steps.saturating_add(traversal_steps);
        if attempted_files > state.max_materialized_files
            || attempted_traversal > state.max_traversal_steps
        {
            state.exhausted = true;
            return false;
        }
        state.externally_materialized_files = state
            .externally_materialized_files
            .saturating_add(materialized_files);
        state.traversal_steps = attempted_traversal;
        true
    }

    pub(crate) fn charge_traversal(&self, steps: usize) -> bool {
        self.charge_external_work(0, steps)
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
    execution: Option<SemanticExecutionBudget>,
}

impl<'a> SemanticRequest<'a> {
    pub fn new(budget: &'a mut SemanticBudget, cancellation: &'a CancellationToken) -> Self {
        Self {
            budget,
            cancellation,
            execution: None,
        }
    }

    pub fn with_execution_budget(
        budget: &'a mut SemanticBudget,
        cancellation: &'a CancellationToken,
        execution: &SemanticExecutionBudget,
    ) -> Self {
        Self {
            budget,
            cancellation,
            execution: Some(execution.clone()),
        }
    }

    pub(crate) fn staged<'b>(&self, budget: &'b mut SemanticBudget) -> SemanticRequest<'b>
    where
        'a: 'b,
    {
        SemanticRequest {
            budget,
            cancellation: self.cancellation,
            execution: self.execution.clone(),
        }
    }

    pub(crate) fn execution_budget(&self) -> Option<&SemanticExecutionBudget> {
        self.execution.as_ref()
    }

    pub(crate) fn admit_materialization(&self, file: &ProjectFile) -> bool {
        self.execution
            .as_ref()
            .is_none_or(|execution| execution.admit_materialization(file))
    }

    pub(crate) fn charge_execution_traversal(&self, steps: usize) -> bool {
        self.execution
            .as_ref()
            .is_none_or(|execution| execution.charge_traversal(steps))
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

/// A [`ProgramSemanticsProvider`] for languages whose lowering is not
/// implemented yet.
///
/// Every capability is reported as explicitly [`SemanticOutcome::Unsupported`]
/// rather than left absent, so callers can distinguish "this language cannot do
/// it" from "nothing was materialized". Zero-sized, so a language delegate can
/// hand out `&UNSUPPORTED_PROGRAM_SEMANTICS` without owning a value.
pub struct UnsupportedProgramSemantics;

/// The shared [`UnsupportedProgramSemantics`] instance.
pub static UNSUPPORTED_PROGRAM_SEMANTICS: UnsupportedProgramSemantics = UnsupportedProgramSemantics;

impl ProgramSemanticsProvider for UnsupportedProgramSemantics {
    fn current_artifact_source(
        &self,
        _file: &ProjectFile,
        _max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactSourceSnapshot>, SemanticProviderError> {
        Ok(None)
    }

    fn materialize(
        &self,
        _file: &ProjectFile,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        Ok(SemanticOutcome::Unsupported {
            capability: SemanticCapability::Procedures,
            partial: None,
            work: SemanticWork::default(),
        })
    }
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
    fn execution_budget_unifies_external_and_nested_provider_work() {
        let first = mock_file();
        let second = ProjectFile::new(std::env::temp_dir(), "src/second.ts");
        let third = ProjectFile::new(std::env::temp_dir(), "src/third.ts");
        let execution = SemanticExecutionBudget::new(3, 3);
        assert!(execution.charge_external_query_work(1, 1));
        assert!(execution.admit_materialization(&first));
        assert!(execution.admit_materialization(&second));

        let mut budget = SemanticBudget::uniform(10).unwrap();
        let mut staged_budget = budget.clone();
        let cancellation = CancellationToken::default();
        let request =
            SemanticRequest::with_execution_budget(&mut budget, &cancellation, &execution);
        let staged = request.staged(&mut staged_budget);
        assert!(staged.charge_execution_traversal(2));
        assert!(!staged.admit_materialization(&third));

        assert_eq!(
            execution.work(),
            SemanticExecutionWork {
                materialized_files: 3,
                traversal_steps: 3,
                exhausted: true,
            }
        );
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

    #[test]
    fn execution_budget_snapshot_replays_exact_file_and_traversal_work() {
        let first = mock_file();
        let second = ProjectFile::new(first.root(), "src/second.rs");
        let source = SemanticExecutionBudget::new(4, 10);
        assert!(source.admit_materialization(&first));
        assert!(source.charge_external_work(1, 2));
        let before = source.snapshot();
        assert!(source.admit_materialization(&second));
        assert!(source.charge_external_work(1, 3));
        let after = source.snapshot();
        let charge = source.charge_since(&before).expect("monotonic charge");

        let replay = SemanticExecutionBudget::new(4, 10);
        assert!(replay.admit_materialization(&first));
        assert!(replay.charge_external_work(1, 2));
        assert_eq!(replay.snapshot(), before);
        assert!(replay.replay_charge(&before, &charge));
        assert_eq!(replay.snapshot(), after);

        let already_replayed = replay.snapshot();
        assert!(!replay.replay_charge(&before, &charge));
        assert_eq!(replay.snapshot(), already_replayed);
    }
}
