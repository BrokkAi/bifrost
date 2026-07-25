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
    CompiledTerminalExpectation, ObjectBindingRole, ProtocolAnalysisMode, ProtocolCompileError,
    ProtocolDiagnostic, ProtocolDiagnosticCode, ProtocolEventId, ProtocolEventKey,
    ProtocolEventSpec, ProtocolExpectationId, ProtocolExpectationKey, ProtocolGuardSpec,
    ProtocolKeyError, ProtocolObjectCardinality, ProtocolObservationPhase, ProtocolSemanticAction,
    ProtocolSemantics, ProtocolSpec, ProtocolSpecParseError, ProtocolStateId, ProtocolStateKey,
    ProtocolTerminalExpectationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior, ProtocolViolationKey,
    TerminalExitKind,
};
