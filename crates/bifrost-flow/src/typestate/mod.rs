//! Language-neutral finite-state protocol compilation and typestate analysis.
//!
//! Public policy authoring and reporting live in the `brokk-bifrost-policy` crate.
//! This module owns only diagnostic-neutral executable protocol semantics and
//! the client-side analysis contracts that consume them.

mod binding;
mod client;
mod finding;
mod hash;
mod planned;
mod production;
mod protocol;
mod summary;

pub use binding::{
    BINDING_PLAN_SCHEMA_VERSION, BoundTypestateEvent, BoundTypestateInitialSeed,
    BoundTypestateSubject, BoundTypestateSubjectSpec, BoundTypestateTerminal,
    MAX_TYPESTATE_CALL_NONINTERFERENCE_BINDINGS, MAX_TYPESTATE_CONTEXT_DEPTH,
    MAX_TYPESTATE_EVENT_BINDINGS, MAX_TYPESTATE_INITIAL_SEEDS, MAX_TYPESTATE_SUBJECT_CLASS_BYTES,
    MAX_TYPESTATE_SUBJECTS, MAX_TYPESTATE_TERMINAL_BINDINGS, TypestateBindingContext,
    TypestateBindingMultiplicity, TypestateBindingPlan, TypestateBindingPlanError,
    TypestateBindingQuality, TypestateCallNonInterferenceSpec, TypestateContextKey,
    TypestateEventBindingId, TypestateEventBindingSpec, TypestateInitialSeedSpec,
    TypestateObjectKey, TypestateObjectRole, TypestateObservationSite, TypestateProcedurePortKey,
    TypestateSubjectClassError, TypestateSubjectClassKey, TypestateSubjectId, TypestateSubjectKey,
    TypestateTerminalBindingId, TypestateTerminalBindingSpec,
};
pub use client::{
    TypestateBackwardDemand, TypestateBackwardResult, TypestateBackwardSolveError, TypestateFact,
    TypestateFlowProblem, TypestateFlowProblemError, TypestateSolveError, TypestateSummaryResult,
    TypestateUncertainty, TypestateUncertaintySet, TypestateViolation, plan_typestate_query,
    solve_typestate_backward_on_snapshot, solve_typestate_backward_with_snapshot,
    solve_typestate_with_summaries,
};
pub use finding::{
    MAX_TYPESTATE_FINDING_CANDIDATES, MAX_TYPESTATE_FINDING_REACHED_ROWS,
    MAX_TYPESTATE_FINDING_WITNESS_BYTES, MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
    MAX_TYPESTATE_FINDINGS, MAX_TYPESTATE_WITNESS_EXPANSIONS, MAX_TYPESTATE_WITNESS_STEPS,
    TypestateFinding, TypestateFindingCertainty, TypestateFindingEvidence, TypestateFindingKind,
    TypestateFindingLimits, TypestateFindingReport, TypestateFindingWitness, TypestateFindingWork,
    TypestateWitness, TypestateWitnessStep, collect_summary_findings,
    collect_summary_findings_with_limits,
};
pub use hash::{TypestateBindingPlanHash, TypestateBindingSummaryHash, TypestateProtocolHash};
pub use planned::{
    TypestateCanonicalObservation, TypestatePlannedEvidence, TypestatePlannedResult,
    TypestatePlannedSolveError, solve_typestate_planned,
};
pub use production::{
    ProductionSemanticSummarySet, ProductionSummaryLifecycleCounters,
    ProductionSummaryProjectionError, ProductionTypestateExecutionContext,
    ProductionTypestateSolveError, ProductionTypestateSolveResult,
    ProductionTypestateSummaryRepository, TypestateProductionCacheStatus,
    TypestateSummaryRepositoryLimits, project_production_semantic_summaries,
    solve_typestate_with_production_summaries,
};
pub use protocol::{
    CompiledProtocol, CompiledProtocolEvent, CompiledProtocolGuard, CompiledProtocolTransition,
    CompiledTerminalExpectation, MAX_PROTOCOL_EVENTS, MAX_PROTOCOL_EXPECTATIONS,
    MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS, MAX_PROTOCOL_SOURCE_BYTES, MAX_PROTOCOL_STATES,
    MAX_PROTOCOL_TRANSITIONS, PROTOCOL_SCHEMA_VERSION, ProtocolAnalysisMode, ProtocolCompileError,
    ProtocolDiagnostic, ProtocolDiagnosticCode, ProtocolEventId, ProtocolEventKey,
    ProtocolEventOccurrence, ProtocolEventSpec, ProtocolExpectationId, ProtocolExpectationKey,
    ProtocolGuardSpec, ProtocolKeyError, ProtocolObjectCardinality, ProtocolObservationPhase,
    ProtocolObservationSpec, ProtocolProcedureExitKind, ProtocolSemantics, ProtocolSpec,
    ProtocolSpecParseError, ProtocolStateId, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintyCause, ProtocolUncertaintyResolution, ProtocolUncertaintySemantics,
    ProtocolUncertaintyStateSet, ProtocolUncertaintyViolation, ProtocolUnmatchedEventBehavior,
};
pub use summary::{
    CompleteProtocolSummaryRepository, DEFAULT_PROTOCOL_SUMMARY_REPOSITORY_BYTES,
    DEFAULT_PROTOCOL_SUMMARY_REPOSITORY_ENTRIES, MAX_PROTOCOL_SUMMARY_EFFECTS,
    MAX_PROTOCOL_SUMMARY_ROWS, PROTOCOL_SUMMARY_SCHEMA_VERSION, ProtocolAppliedEffect,
    ProtocolEventBindingKey, ProtocolFactKey, ProtocolObservedEffect, ProtocolPathEvidence,
    ProtocolSemanticSummarySet, ProtocolSummary, ProtocolSummaryApplication,
    ProtocolSummaryCacheStatus, ProtocolSummaryError, ProtocolSummaryKey, ProtocolSummaryOutcome,
    ProtocolSummaryPublicationError, ProtocolSummaryPublicationOutcome,
    ProtocolSummaryRepositoryLimits, ProtocolSummaryRow, ProtocolSummarySolveError,
    ProtocolSummarySolveResult, ProtocolTerminalBindingKey, ProtocolUncertaintyKey,
    solve_typestate_with_reusable_summaries,
};
