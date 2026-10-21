//! Per-procedure partial flows: which input ports of one procedure can reach
//! which output ports without passing through a call.
//!
//! The relations come from the same projection the workspace oracle runs,
//! [`project_procedure_relations`]. [`FileLocalProjectionHost`] gives that
//! projection the answers it would otherwise take from the workspace, using
//! only what one file proves.

pub use brokk_bifrost_semantic::analyzer::semantic::partial_flow::*;
pub use fixpoint::{
    CrossedCalls, ExtendedPartialFlows, ExtraFlow, ExtraObservation, ExtraPhase, ExtraSeed,
    ExtraTarget, ImplicitHeapRead, MAX_CROSSED_CLASSES, ObservationFilter, PartialFlow,
    PartialFlowOutcome, ProcedurePartialFlows, SEED_EVENT, WitnessStep, caller_exact_read_location,
    caller_location_carriers, compute_partial_flows, compute_partial_flows_filtered,
    compute_partial_flows_with, compute_partial_flows_with_implicit_reads,
    exact_location_covers_read, input_port_seed, join_crossed, observation_value,
};
pub use ports::{HeapSelector, PartialFlowPort, PortId, call_input_value, heap_selectors};
/// The relation snapshot of `procedure` projected from its file alone, with
/// the prepared syntax of `file`. This is the parse-time host of the host
/// differential, exposed for that differential only.
#[cfg(any(test, feature = "test-support"))]
pub fn parse_time_procedure_relations(
    workspace: &crate::analyzer::WorkspaceAnalyzer,
    file: &crate::analyzer::ProjectFile,
    procedure: &ProcedureHandle,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<SemanticOutcome<crate::analyzer::semantic::ValueFlowSnapshot>, SemanticProviderError> {
    use crate::analyzer::semantic::workspace_oracle::project_procedure_relations;
    use crate::analyzer::semantic::{OracleLimits, SemanticBudget};

    let syntax = workspace.prepared_syntax_for_test(file);
    let host = FileLocalProjectionHost {
        syntax: syntax.as_deref(),
    };
    let mut budget = SemanticBudget::default();
    project_procedure_relations(
        &host,
        procedure,
        &OracleCallContext::empty(),
        OracleLimits::default(),
        &mut SemanticRequest::new(&mut budget, cancellation),
    )
}

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::semantic::{
    OracleCallContext, ProcedureHandle, SemanticOutcome, SemanticProviderError, SemanticRequest,
};
