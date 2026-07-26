//! Deterministic public results for IDE summary propagation.

use std::{error::Error, fmt};

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::semantic::{ProgramPointHandle, SemanticWork};

use super::{
    FactId, PathQualityFrontier, SolverTermination, SolverWork, SummaryCoverage,
    SummaryDataflowError, SummaryDataflowResult, SummaryReachedFact, TabulationEndSummary,
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
    point: ProgramPointHandle,
    fact: FactId,
    value: IdeValueId,
    path_qualities: PathQualityFrontier,
}

impl IdePointValue {
    pub(crate) const fn new(
        point: ProgramPointHandle,
        fact: FactId,
        value: IdeValueId,
        path_qualities: PathQualityFrontier,
    ) -> Self {
        Self {
            point,
            fact,
            value,
            path_qualities,
        }
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

/// Deterministic IDE-only work and reuse counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdeMetrics {
    pub captured_relations: usize,
    pub direct_relations: usize,
    pub summary_relations: usize,
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
}
