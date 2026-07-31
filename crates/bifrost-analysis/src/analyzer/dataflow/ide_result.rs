//! Deterministic public results for IDE summary propagation.

use std::{error::Error, fmt, mem::size_of_val};

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::semantic::{ProgramPointHandle, SemanticWork};

use super::{
    FactId, PathQualityFrontier, SolverTermination, SolverWork, SummaryCoverage,
    SummaryDataflowError, SummaryDataflowResult, SummaryEntry, SummaryReachedFact,
    TabulationEndSummary,
};

define_dense_id! {
    /// A result-local dense identifier for one canonical edge function.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IdeEdgeFunctionId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    /// A result-local dense identifier for one canonical client value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IdeValueId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

/// One deterministic final value at a root-relative `(point, fact)` state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdePointValue {
    entry: SummaryEntry,
    point: ProgramPointHandle,
    fact: FactId,
    value: IdeValueId,
    path_qualities: PathQualityFrontier,
}

impl IdePointValue {
    pub(crate) const fn new(
        entry: SummaryEntry,
        point: ProgramPointHandle,
        fact: FactId,
        value: IdeValueId,
        path_qualities: PathQualityFrontier,
    ) -> Self {
        Self {
            entry,
            point,
            fact,
            value,
            path_qualities,
        }
    }

    pub const fn entry(&self) -> &SummaryEntry {
        &self.entry
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn fact(&self) -> FactId {
        self.fact
    }

    pub const fn value(&self) -> IdeValueId {
        self.value
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }
}

/// One symbolic transfer from a caller-relative summary entry to a callee entry.
///
/// The edge function is relative to `source`: it includes the caller jump to the
/// call state and the call-flow function entering `target`. Clients can compose
/// these rows with callee-relative observations without materializing a concrete
/// IDE value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdeEntryTransfer {
    source: SummaryEntry,
    target: SummaryEntry,
    path_qualities: PathQualityFrontier,
    edge_function: IdeEdgeFunctionId,
}

impl IdeEntryTransfer {
    pub(crate) const fn new(
        source: SummaryEntry,
        target: SummaryEntry,
        path_qualities: PathQualityFrontier,
        edge_function: IdeEdgeFunctionId,
    ) -> Self {
        Self {
            source,
            target,
            path_qualities,
            edge_function,
        }
    }

    pub const fn source(&self) -> &SummaryEntry {
        &self.source
    }

    pub const fn target(&self) -> &SummaryEntry {
        &self.target
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }

    pub(crate) const fn edge_function_id(&self) -> IdeEdgeFunctionId {
        self.edge_function
    }

    pub(crate) fn remap_edge_function(&mut self, id: IdeEdgeFunctionId) {
        self.edge_function = id;
    }
}

/// Deterministic IDE-only work and reuse counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdeMetrics {
    pub captured_relations: usize,
    pub direct_relations: usize,
    pub summary_relations: usize,
    pub entry_value_relations: usize,
    pub jump_updates: usize,
    pub composition_cache_hits: usize,
    pub composition_cache_misses: usize,
    pub meet_cache_hits: usize,
    pub meet_cache_misses: usize,
    pub summary_function_applications: usize,
    pub reused_summary_functions: usize,
}

/// Stable malformed-input or internal IDE publication errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdeDataflowError {
    Summary(SummaryDataflowError),
    EdgeFunctionIdOverflow { index: usize },
    ValueIdOverflow { index: usize },
    MissingRootSeedValue { fact: FactId },
    Invariant(&'static str),
}

impl fmt::Display for IdeDataflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Summary(error) => error.fmt(formatter),
            Self::EdgeFunctionIdOverflow { index } => {
                write!(formatter, "IDE edge-function index {index} exceeds u32")
            }
            Self::ValueIdOverflow { index } => {
                write!(formatter, "IDE value index {index} exceeds u32")
            }
            Self::MissingRootSeedValue { fact } => {
                write!(formatter, "IDE root entry fact {fact:?} has no seed value")
            }
            Self::Invariant(reason) => write!(formatter, "IDE solver invariant failed: {reason}"),
        }
    }
}

impl Error for IdeDataflowError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Summary(error) => Some(error),
            Self::EdgeFunctionIdOverflow { .. }
            | Self::ValueIdOverflow { .. }
            | Self::MissingRootSeedValue { .. }
            | Self::Invariant(_) => None,
        }
    }
}

impl From<SummaryDataflowError> for IdeDataflowError {
    fn from(error: SummaryDataflowError) -> Self {
        Self::Summary(error)
    }
}

/// Deterministic result of one IDE solve layered over fact summary tabulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdeSummaryDataflowResult<Fact, Value, EdgeFunction> {
    fact_result: SummaryDataflowResult<Fact>,
    edge_functions: Box<[EdgeFunction]>,
    values: Box<[Value]>,
    reached_jump_functions: Box<[Option<IdeEdgeFunctionId>]>,
    end_summary_jump_functions: Box<[Option<IdeEdgeFunctionId>]>,
    entry_transfers: Box<[IdeEntryTransfer]>,
    point_values: Box<[IdePointValue]>,
    termination: SolverTermination,
    work: SolverWork,
    semantic_work: SemanticWork,
    metrics: IdeMetrics,
}

impl<Fact, Value, EdgeFunction> IdeSummaryDataflowResult<Fact, Value, EdgeFunction> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        fact_result: SummaryDataflowResult<Fact>,
        edge_functions: Vec<EdgeFunction>,
        values: Vec<Value>,
        reached_jump_functions: Vec<Option<IdeEdgeFunctionId>>,
        end_summary_jump_functions: Vec<Option<IdeEdgeFunctionId>>,
        entry_transfers: Vec<IdeEntryTransfer>,
        point_values: Vec<IdePointValue>,
        termination: SolverTermination,
        work: SolverWork,
        semantic_work: SemanticWork,
        metrics: IdeMetrics,
    ) -> Self {
        debug_assert_eq!(reached_jump_functions.len(), fact_result.reached().len());
        debug_assert_eq!(
            end_summary_jump_functions.len(),
            fact_result.end_summaries().len()
        );
        Self {
            fact_result,
            edge_functions: edge_functions.into_boxed_slice(),
            values: values.into_boxed_slice(),
            reached_jump_functions: reached_jump_functions.into_boxed_slice(),
            end_summary_jump_functions: end_summary_jump_functions.into_boxed_slice(),
            entry_transfers: entry_transfers.into_boxed_slice(),
            point_values: point_values.into_boxed_slice(),
            termination,
            work,
            semantic_work,
            metrics,
        }
    }

    pub const fn fact_result(&self) -> &SummaryDataflowResult<Fact> {
        &self.fact_result
    }

    pub fn edge_functions(&self) -> &[EdgeFunction] {
        &self.edge_functions
    }

    pub fn edge_function(&self, id: IdeEdgeFunctionId) -> Option<&EdgeFunction> {
        self.edge_functions.get(id.index())
    }

    pub fn values(&self) -> &[Value] {
        &self.values
    }

    pub fn value(&self, id: IdeValueId) -> Option<&Value> {
        self.values.get(id.index())
    }

    pub fn point_values(&self) -> &[IdePointValue] {
        &self.point_values
    }

    pub fn reached_jump_functions(
        &self,
    ) -> impl Iterator<Item = (&SummaryReachedFact, &EdgeFunction)> {
        self.fact_result
            .reached()
            .iter()
            .zip(self.reached_jump_functions.iter().copied())
            .filter_map(|(reached, function)| Some((reached, self.edge_function(function?)?)))
    }

    pub fn end_summary_jump_functions(
        &self,
    ) -> impl Iterator<Item = (&TabulationEndSummary, &EdgeFunction)> {
        self.fact_result
            .end_summaries()
            .iter()
            .zip(self.end_summary_jump_functions.iter().copied())
            .filter_map(|(summary, function)| Some((summary, self.edge_function(function?)?)))
    }

    pub fn entry_transfers(&self) -> impl Iterator<Item = (&IdeEntryTransfer, &EdgeFunction)> {
        self.entry_transfers.iter().filter_map(|transfer| {
            self.edge_function(transfer.edge_function)
                .map(|function| (transfer, function))
        })
    }

    pub const fn coverage(&self) -> &SummaryCoverage {
        self.fact_result.coverage()
    }

    pub const fn termination(&self) -> SolverTermination {
        self.termination
    }

    pub const fn work(&self) -> SolverWork {
        self.work
    }

    pub const fn semantic_work(&self) -> SemanticWork {
        self.semantic_work
    }

    pub const fn metrics(&self) -> IdeMetrics {
        self.metrics
    }

    pub fn is_complete(&self) -> bool {
        self.termination.is_fixed_point() && self.fact_result.coverage().is_complete()
    }

    /// Conservative bytes owned directly by this immutable IDE result.
    /// Shared semantic artifacts behind handles and `Arc`s are excluded and
    /// must be charged separately by the owner retaining those artifacts.
    pub(crate) fn retained_bytes_with(
        &self,
        value_heap_bytes: impl Fn(&Value) -> usize,
        edge_function_heap_bytes: impl Fn(&EdgeFunction) -> usize,
    ) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.fact_result.retained_bytes())
            .saturating_add(size_of_val(&*self.edge_functions))
            .saturating_add(size_of_val(&*self.values))
            .saturating_add(size_of_val(&*self.reached_jump_functions))
            .saturating_add(size_of_val(&*self.end_summary_jump_functions))
            .saturating_add(size_of_val(&*self.entry_transfers))
            .saturating_add(size_of_val(&*self.point_values))
            .saturating_add(
                self.values
                    .iter()
                    .map(value_heap_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.edge_functions
                    .iter()
                    .map(edge_function_heap_bytes)
                    .fold(0usize, usize::saturating_add),
            )
    }
}
