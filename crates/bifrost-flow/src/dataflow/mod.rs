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

pub(crate) fn sorted_equal_range_by<T, K: Ord>(
    values: &[T],
    key: &K,
    mut compare: impl FnMut(&T, &K) -> std::cmp::Ordering,
) -> std::ops::Range<usize> {
    let start = values.partition_point(|value| compare(value, key).is_lt());
    let end = start + values[start..].partition_point(|value| compare(value, key).is_eq());
    start..end
}

pub(crate) fn should_continue(
    cancellation: &crate::analyzer::semantic::CancellationToken,
    invalid_output: bool,
    exceeded: bool,
) -> bool {
    !cancellation.is_cancelled() && !invalid_output && !exceeded
}

pub(crate) fn emit_bounded_callback_output<T>(
    values: &mut crate::hash::HashSet<T>,
    value: T,
    budget: &SolverBudget,
) -> Result<(), SolverBudgetExceeded>
where
    T: Copy + Eq + std::hash::Hash,
{
    if values.contains(&value) {
        return Ok(());
    }
    let callback_rows = values.len().saturating_add(1);
    budget.check(SolverWork {
        callback_rows,
        ..SolverWork::uniform(0)
    })?;
    values.insert(value);
    Ok(())
}

pub(crate) fn is_procedure_exit_kind(
    point: &crate::analyzer::semantic::ProgramPointHandle,
    kind: crate::analyzer::semantic::ReturnTransferKind,
) -> bool {
    let semantics = point.procedure().semantics();
    match kind {
        crate::analyzer::semantic::ReturnTransferKind::Normal => {
            point.id() == semantics.normal_exit_point()
        }
        crate::analyzer::semantic::ReturnTransferKind::Exceptional => {
            point.id() == semantics.exceptional_exit_point()
        }
    }
}

pub(crate) fn retained_evidence_bytes(
    proof: Option<&crate::analyzer::semantic::ProofStatus>,
    completeness: Option<&crate::analyzer::semantic::EvidenceCompleteness>,
) -> usize {
    proof
        .map_or(
            0,
            crate::analyzer::semantic::ProofStatus::retained_heap_bytes,
        )
        .saturating_add(completeness.map_or(
            0,
            crate::analyzer::semantic::EvidenceCompleteness::retained_heap_bytes,
        ))
}

pub(crate) fn summary_capacity_totals(
    entries: usize,
    bytes: usize,
    added_entries: usize,
    added_bytes: usize,
) -> (usize, usize) {
    (
        entries.saturating_add(added_entries),
        bytes.saturating_add(added_bytes),
    )
}

pub(super) fn reusable_summary_rows_are_valid<'a>(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    exits: impl IntoIterator<Item = &'a [PathQuality]>,
    reached: impl IntoIterator<
        Item = (
            &'a [PathQuality],
            &'a crate::analyzer::semantic::ProcedureHandle,
        ),
    >,
) -> bool {
    exits.into_iter().all(|qualities| !qualities.is_empty())
        && reached
            .into_iter()
            .all(|(qualities, owner)| !qualities.is_empty() && owner == procedure)
}

pub(crate) use backward_snapshot::acquire_backward_snapshot;
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
pub(crate) use ide::{
    RecordedIdeRelations, TransferKey, solve_ide_with_recorded_relations,
    solve_ide_with_reusable_summaries_with_call_context,
    solve_ide_with_summaries_with_call_context,
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
pub(crate) use quality::{
    path_evidence_from_frontier, path_evidence_frontier, path_evidence_has_complete_path,
    path_evidence_has_proven_complete_path, path_evidence_has_proven_path, path_evidence_qualities,
};
pub use result::{DataflowCoverage, DataflowResult, ReachedFact, SolverTermination};

fn fact_by_id<Fact>(facts: &[Fact], id: FactId) -> Option<&Fact> {
    facts.get(id.index())
}
pub use reusable_summary::{
    CompleteSummaryRepository, CuratedCallModel, CuratedCallModelFingerprint,
    DEFAULT_SUMMARY_REPOSITORY_BYTES, DEFAULT_SUMMARY_REPOSITORY_ENTRIES, DependentVerdict,
    ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey, ExternalSummaryContentHash,
    ExternalSummaryModelId, ExternalSummaryOrigin, ExternalSummarySetError,
    ExternalSummarySetFingerprint, ExternalSummaryTarget, MAX_AMBIGUOUS_SUMMARY_CALLEES,
    MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES, MAX_SUMMARY_BOUNDARY_BINDINGS,
    MAX_SUMMARY_COMPOSITION_STEPS, MAX_SUMMARY_DEPENDENCIES, MAX_SUMMARY_EFFECT_REFERENCES,
    MAX_SUMMARY_EFFECTS, MAX_SUMMARY_EVIDENCE_REASONS, MAX_SUMMARY_REASON_BYTES,
    MAX_SUMMARY_RECURSIVE_MEMBERS, MAX_SUMMARY_TRANSFERS, NoSummaryReadObserver,
    ProcedureSummaryIdentity, ProcedureSummaryKey, ProductionSemanticSummaryRepository,
    RetainedSemanticSummaryClosure, SUMMARY_SCHEMA_VERSION, SemanticProcedureSummary,
    SummaryBehaviorKey, SummaryBoundaryBinding, SummaryBoundaryMap, SummaryCallSourceWitness,
    SummaryCompleteness, SummaryCompositionError, SummaryCompositionRootFingerprint,
    SummaryConcurrencyAccessMode, SummaryConcurrencyAccessPath, SummaryConcurrencyAccessSelector,
    SummaryConcurrencyAtomicOperation, SummaryConcurrencyCallable, SummaryConcurrencyCondWaiters,
    SummaryConcurrencyEffect, SummaryConcurrencyEffectKind, SummaryConcurrencyExecution,
    SummaryConcurrencyExecutionCardinality, SummaryConcurrencyInteger, SummaryConcurrencyLockMode,
    SummaryConcurrencyLockOperation, SummaryConcurrencyLockRequirement,
    SummaryConcurrencySourceWitness, SummaryConcurrencySubjectIdentity,
    SummaryConcurrencySyncMapOperation, SummaryConcurrencySynchronizationOperation,
    SummaryConcurrencyTargetCoverage, SummaryConcurrencyTaskGroup, SummaryContextKey,
    SummaryDependencyFingerprint, SummaryDependencyKey, SummaryDimension, SummaryDimensionClaim,
    SummaryDimensionCoverage, SummaryDimensionState, SummaryDimensionStatus, SummaryEffect,
    SummaryEffectKey, SummaryEventKey, SummaryEvidence, SummaryEvidenceAlternative, SummaryExit,
    SummaryExitKind, SummaryIncompleteReason, SummaryLocationKey, SummaryLockAcquisition,
    SummaryOrigin, SummaryPort, SummaryProcedureSemanticsKey, SummaryProcedureSourceKey,
    SummaryPublicationError, SummaryPublicationOutcome, SummaryReadObserver, SummaryReadRecorder,
    SummaryRecursiveEdge, SummaryRecursiveGroupFingerprint, SummaryRecursiveGroupKey,
    SummaryRepositoryLimits, SummaryReverseDependencyIndex, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryTaskSpawnCondition, SummaryTransfer, SummaryValidationError,
};
pub(crate) use reusable_summary::{
    SemanticSummaryArtifactIndex, SemanticSummarySetValidationError,
    canonical_semantic_summaries_by_artifact, declaration_locator_heap_bytes,
    validate_recursive_summary_batch,
};
pub(crate) use snapshot_replay::SnapshotReplayProvider;
pub(crate) use summary::NoReusableSummaries;
pub use summary::{
    ReusableEndSummary, ReusableProcedureSummary, ReusableReachedFact, ReusableSummaryError,
    ReusableSummaryProvider, SummaryCallCycle, SummaryCalledProcedures, SummaryPointSeed,
    SummarySolveInput, solve_with_reusable_end_summaries,
    solve_with_reusable_root_and_end_summaries, solve_with_summaries,
};
pub use summary_result::{
    SummaryBoundary, SummaryBoundaryKind, SummaryCoverage, SummaryDataflowError,
    SummaryDataflowResult, SummaryEdge, SummaryEntry, SummaryEntryTransfer, SummaryIncomingCall,
    SummaryMetrics, SummaryReachedFact, SummarySemanticStatus, TabulationEndSummary,
};
pub use tabulation::{solve, solve_backward, solve_backward_on_snapshot, solve_on_snapshot};
pub(crate) use witness::WitnessArena;
pub use witness::{
    MAX_WITNESS_ALTERNATIVES_PER_QUALITY, SummaryWitness, SummaryWitnessError, SummaryWitnessStep,
    SummaryWitnessStepKind, WitnessLimitError, WitnessReconstructionLimits,
    WitnessReconstructionWork, WitnessRetentionLimits, WitnessTruncationCause,
};
