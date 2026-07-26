//! Language-neutral finite-state protocol compilation and typestate analysis.
//!
//! Public policy authoring and reporting live in [`crate::analyzer::policy`].
//! This module owns only diagnostic-neutral executable protocol semantics and
//! the client-side analysis contracts that consume them.

mod binding;
mod client;
mod finding;
mod hash;
mod protocol;

pub use binding::{
    BINDING_PLAN_SCHEMA_VERSION, BoundTypestateEvent, BoundTypestateInitialSeed,
    BoundTypestateSubject, BoundTypestateSubjectSpec, BoundTypestateTerminal,
    MAX_TYPESTATE_CONTEXT_DEPTH, MAX_TYPESTATE_EVENT_BINDINGS, MAX_TYPESTATE_INITIAL_SEEDS,
    MAX_TYPESTATE_SUBJECT_CLASS_BYTES, MAX_TYPESTATE_SUBJECTS, MAX_TYPESTATE_TERMINAL_BINDINGS,
    TypestateBindingContext, TypestateBindingMultiplicity, TypestateBindingPlan,
    TypestateBindingPlanError, TypestateBindingQuality, TypestateContextKey,
    TypestateEventBindingId, TypestateEventBindingSpec, TypestateInitialSeedSpec,
    TypestateObjectKey, TypestateObjectRole, TypestateObservationSite, TypestateProcedurePortKey,
    TypestateSubjectClassError, TypestateSubjectClassKey, TypestateSubjectId, TypestateSubjectKey,
    TypestateTerminalBindingId, TypestateTerminalBindingSpec,
};
pub use client::{
    TypestateFact, TypestateFlowProblem, TypestateFlowProblemError, TypestateSolveError,
    TypestateSummaryResult, TypestateUncertainty, TypestateUncertaintySet, TypestateViolation,
    solve_typestate_with_summaries,
};
pub use finding::{
    MAX_TYPESTATE_FINDING_CANDIDATES, MAX_TYPESTATE_FINDING_REACHED_ROWS, MAX_TYPESTATE_FINDINGS,
    MAX_TYPESTATE_WITNESS_EXPANSIONS, MAX_TYPESTATE_WITNESS_STEPS, TypestateFinding,
    TypestateFindingCertainty, TypestateFindingEvidence, TypestateFindingKind,
    TypestateFindingLimits, TypestateFindingReport, TypestateFindingWitness, TypestateWitness,
    TypestateWitnessStep, collect_summary_findings, collect_summary_findings_with_limits,
};
pub use hash::{TypestateBindingPlanHash, TypestateProtocolHash};
pub use protocol::{
    CompiledProtocol, CompiledProtocolEvent, CompiledProtocolGuard, CompiledProtocolTransition,
    CompiledTerminalExpectation, MAX_PROTOCOL_EVENTS, MAX_PROTOCOL_EXPECTATIONS,
    MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS, MAX_PROTOCOL_SOURCE_BYTES, MAX_PROTOCOL_STATES,
    MAX_PROTOCOL_TRANSITIONS, ProtocolAnalysisMode, ProtocolCompileError, ProtocolDiagnostic,
    ProtocolDiagnosticCode, ProtocolEventId, ProtocolEventKey, ProtocolEventOccurrence,
    ProtocolEventSpec, ProtocolExpectationId, ProtocolExpectationKey, ProtocolGuardSpec,
    ProtocolKeyError, ProtocolObjectCardinality, ProtocolObservationPhase, ProtocolObservationSpec,
    ProtocolProcedureExitKind, ProtocolSemantics, ProtocolSpec, ProtocolSpecParseError,
    ProtocolStateId, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintyCause, ProtocolUncertaintyResolution, ProtocolUncertaintySemantics,
    ProtocolUncertaintyStateSet, ProtocolUncertaintyViolation, ProtocolUnmatchedEventBehavior,
};
