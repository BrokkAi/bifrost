//! Language-neutral finite-state protocol compilation and typestate analysis.
//!
//! Public policy authoring and reporting live in [`crate::analyzer::policy`].
//! This module owns only diagnostic-neutral executable protocol semantics and
//! the client-side analysis contracts that consume them.

mod hash;
mod protocol;

pub use hash::TypestateProtocolHash;
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
    ProtocolUnmatchedEventBehavior,
};
