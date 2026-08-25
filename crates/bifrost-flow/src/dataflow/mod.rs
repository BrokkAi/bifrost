//! Deterministic distributive data-flow propagation over semantic ICFGs.
//!
//! One runner consumes context-expanded nodes and edges already published by an
//! `IcfgSnapshot`. A second runner starts from a procedure and converges through
//! query-local entry-to-exit summaries, including recursive calls. Both retain
//! input uncertainty, solver termination, budgets, and concrete path quality.
//! Summary witnesses are an opt-in query-local layer; IDE edge functions and
//! domain-specific clients remain separate follow-up work.

mod backward_snapshot;
mod budget;
mod call_model;
mod direct;
mod direction;
mod direction_estimate;
mod ide;
mod ide_result;
mod input;
mod planned_result;
mod problem;
mod quality;
mod result;
mod reusable_summary;
mod snapshot_replay;
mod summary;
mod summary_result;
mod tabulation;
mod transfer;
mod witness;

pub use backward_snapshot::{
    BackwardCallIndex, BackwardSnapshotDataflowError, BackwardSnapshotDataflowResult,
    BackwardSnapshotDemand, BackwardSnapshotProblem, solve_backward_demands_on_snapshot,
    solve_backward_with_snapshot,
};
pub use budget::{
    DataflowRequest, SolverBudget, SolverBudgetDimension, SolverBudgetExceeded, SolverWork,
};
pub use call_model::UnmodeledCallBehavior;
pub use direct::{DirectFact, DirectFlowProblem};
pub use direction::{
    DEFAULT_MINIMUM_BACKWARD_SAVINGS_PERCENT, DataflowDirection, DataflowDirectionCapabilities,
    DataflowDirectionCapability, DataflowDirectionEstimate, DataflowDirectionExecutionMetrics,
    DataflowDirectionPlan, DataflowDirectionPlanningError, DataflowDirectionRequest,
    DataflowDirectionRequirements, DataflowDirectionSelectionReason, DataflowQueryPlanConfig,
    plan_dataflow_direction,
};
pub use direction_estimate::{
    estimate_snapshot_reachable_slices, plan_snapshot_dataflow_direction,
    snapshot_node_ids_for_points,
};
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
pub use planned_result::{
    NormalizedWitnessAvailability, NormalizedWitnessUnavailableReason, PlannedDataflowCompletion,
    PlannedDataflowResult,
};
pub use problem::{
    BackwardDistributiveDataflowProblem, BoundedSnapshotBackwardDataflowProblem,
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowOutput, DataflowSeed,
    DistributiveDataflowProblem, FactId,
};
pub use quality::{PathQuality, PathQualityFrontier};
pub use result::{DataflowCoverage, DataflowResult, ReachedFact, SolverTermination};
pub use reusable_summary::{
    CompleteSummaryRepository, CuratedCallModel, CuratedCallModelFingerprint,
    DEFAULT_SUMMARY_REPOSITORY_BYTES, DEFAULT_SUMMARY_REPOSITORY_ENTRIES, DependentVerdict,
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
    SummaryRecursiveGroupKey, SummaryRepositoryLimits, SummaryReverseDependencyIndex,
    SummarySchemaVersion, SummarySemanticsVersion, SummaryTransfer, SummaryValidationError,
};
pub(crate) use reusable_summary::{
    SemanticSummarySetValidationError, canonicalize_semantic_summary_items,
    validate_recursive_summary_batch,
};
pub(crate) use snapshot_replay::SnapshotReplayProvider;
pub use summary::{
    ReusableEndSummary, ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryProvider,
    SummaryCallCycle, SummaryCalledProcedures, SummaryPointSeed, SummarySolveInput,
    solve_with_reusable_end_summaries, solve_with_summaries,
};
pub use summary_result::{
    SummaryBoundary, SummaryBoundaryKind, SummaryCoverage, SummaryDataflowError,
    SummaryDataflowResult, SummaryEdge, SummaryEntry, SummaryIncomingCall, SummaryMetrics,
    SummaryReachedFact, SummarySemanticStatus, TabulationEndSummary,
};
pub use tabulation::{solve, solve_backward, solve_backward_on_snapshot, solve_on_snapshot};
pub use witness::{
    MAX_WITNESS_ALTERNATIVES_PER_QUALITY, SummaryWitness, SummaryWitnessError, SummaryWitnessStep,
    SummaryWitnessStepKind, WitnessLimitError, WitnessReconstructionLimits,
    WitnessReconstructionWork, WitnessRetentionLimits, WitnessTruncationCause,
};
