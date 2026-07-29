//! Deterministic distributive data-flow propagation over semantic ICFGs.
//!
//! One runner consumes context-expanded nodes and edges already published by an
//! `IcfgSnapshot`. A second runner starts from a procedure and converges through
//! query-local entry-to-exit summaries, including recursive calls. Both retain
//! input uncertainty, solver termination, budgets, and concrete path quality.
//! Summary witnesses are an opt-in query-local layer; IDE edge functions and
//! domain-specific clients remain separate follow-up work.

mod budget;
mod call_model;
mod direct;
mod ide;
mod ide_result;
mod input;
mod problem;
mod quality;
mod result;
mod reusable_summary;
mod summary;
mod summary_result;
mod tabulation;
mod transfer;
mod witness;

pub use budget::{
    DataflowRequest, SolverBudget, SolverBudgetDimension, SolverBudgetExceeded, SolverWork,
};
pub use call_model::UnmodeledCallBehavior;
pub use direct::{DirectFact, DirectFlowProblem};
pub use ide::{
    IdeDataflowProblem, IdeDataflowSeed, IdeSummarySolveInput, IdeTransition,
    ReusableIdeEndSummary, ReusableIdeProcedureSummary, ReusableIdeReachedFact,
    ReusableIdeSummaryProvider, solve_ide_with_reusable_summaries, solve_ide_with_summaries,
};
pub use ide_result::{
    IdeDataflowError, IdeEdgeFunctionId, IdeEntryTransfer, IdeMetrics, IdePointValue,
    IdeSummaryDataflowResult, IdeValueId,
};
pub use input::{DataflowError, IcfgInputStatus, IcfgSolveInput, SemanticInputStatus};
pub use problem::{
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowOutput, DataflowSeed,
    DistributiveDataflowProblem, FactId,
};
pub use quality::{PathQuality, PathQualityFrontier};
pub use result::{DataflowCoverage, DataflowResult, ReachedFact, SolverTermination};
pub use reusable_summary::{
    CompleteSummaryRepository, CuratedCallModel, CuratedCallModelFingerprint,
    DEFAULT_SUMMARY_REPOSITORY_BYTES, DEFAULT_SUMMARY_REPOSITORY_ENTRIES,
    ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey, ExternalSummaryContentHash,
    ExternalSummaryModelId, ExternalSummaryOrigin, ExternalSummarySetError,
    ExternalSummarySetFingerprint, ExternalSummaryTarget, MAX_AMBIGUOUS_SUMMARY_CALLEES,
    MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES, MAX_SUMMARY_BOUNDARY_BINDINGS,
    MAX_SUMMARY_COMPOSITION_STEPS, MAX_SUMMARY_DEPENDENCIES, MAX_SUMMARY_EFFECT_REFERENCES,
    MAX_SUMMARY_EFFECTS, MAX_SUMMARY_EVIDENCE_REASONS, MAX_SUMMARY_REASON_BYTES,
    MAX_SUMMARY_RECURSIVE_MEMBERS, MAX_SUMMARY_TRANSFERS, ProcedureSummaryIdentity,
    ProcedureSummaryKey, SUMMARY_SCHEMA_VERSION, SemanticProcedureSummary, SummaryBehaviorKey,
    SummaryBoundaryBinding, SummaryBoundaryMap, SummaryCompleteness, SummaryCompositionError,
    SummaryCompositionRootFingerprint, SummaryContextKey, SummaryDependencyFingerprint,
    SummaryDependencyKey, SummaryEffect, SummaryEffectKey, SummaryEventKey, SummaryEvidence,
    SummaryEvidenceAlternative, SummaryExit, SummaryExitKind, SummaryIncompleteReason,
    SummaryLocationKey, SummaryOrigin, SummaryPort, SummaryPublicationError,
    SummaryPublicationOutcome, SummaryRecursiveEdge, SummaryRecursiveGroupFingerprint,
    SummaryRecursiveGroupKey, SummaryRepositoryLimits, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryTransfer, SummaryValidationError,
};
pub(crate) use reusable_summary::{
    SemanticSummarySetValidationError, canonicalize_semantic_summary_items,
    validate_recursive_summary_batch,
};
pub use summary::{
    ReusableEndSummary, ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryProvider,
    SummaryPointSeed, SummarySolveInput, solve_with_reusable_end_summaries, solve_with_summaries,
};
pub use summary_result::{
    SummaryBoundary, SummaryBoundaryKind, SummaryCoverage, SummaryDataflowError,
    SummaryDataflowResult, SummaryEdge, SummaryEntry, SummaryMetrics, SummaryReachedFact,
    SummarySemanticStatus, TabulationEndSummary,
};
pub use tabulation::solve;
pub use witness::{
    MAX_WITNESS_ALTERNATIVES_PER_QUALITY, SummaryWitness, SummaryWitnessError, SummaryWitnessStep,
    SummaryWitnessStepKind, WitnessLimitError, WitnessReconstructionLimits,
    WitnessReconstructionWork, WitnessRetentionLimits,
};
