//! Direct checks of the partial-flow fixpoint over small Rust procedures, with
//! the relation snapshot taken from the workspace oracle.

use super::fixpoint::{
    PartialFlowOutcome, ProcedurePartialFlows, compute_partial_flows, parse_time_partial_flows,
};
use super::ports::{HeapSelector, PartialFlowPort};
use crate::analyzer::semantic::{
    AccessPathTail, OracleCallContext, ProcedureHandle, SemanticBudget, SemanticRequest,
    ValueFlowOracle, ValueFlowSnapshot,
};
use crate::analyzer::{AnalyzerConfig, Language};
use crate::cancellation::CancellationToken;
use crate::inline_project::InlineTestProject;

fn procedure_and_snapshot(source: &str, name: &str) -> (ProcedureHandle, ValueFlowSnapshot) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let file = project.file("lib.rs");
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let artifact = analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
        )
        .expect("Rust semantic materialization runs")
        .available_value()
        .cloned()
        .expect("Rust semantic artifact is available");
    let procedure = artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(name)
        })
        .and_then(|procedure| artifact.procedure_handle(procedure.id()))
        .expect("the named procedure");
    let oracle = analyzer.semantic_oracle_provider();
    let mut budget = SemanticBudget::default();
    let snapshot = oracle
        .procedure_relations(
            &procedure,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("value-flow relation query runs")
        .available_value()
        .cloned()
        .expect("value-flow relation query retains its snapshot");
    (procedure, snapshot)
}

/// Every flow as `(from, to)` ports, so that assertions name ports rather
/// than their table positions.
fn port_flows(result: &ProcedurePartialFlows) -> Vec<(&PartialFlowPort, &PartialFlowPort)> {
    result
        .flows
        .iter()
        .map(|flow| {
            (
                &result.ports[flow.from.index()],
                &result.ports[flow.to.index()],
            )
        })
        .collect()
}

/// The head of the named procedure, projected by the parse-time writer's path:
/// the projection's own outcome decides whether the snapshot is used.
fn parse_time_flows(source: &str, name: &str) -> ProcedurePartialFlows {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let file = project.file("lib.rs");
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let artifact = analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
        )
        .expect("Rust semantic materialization runs")
        .available_value()
        .cloned()
        .expect("Rust semantic artifact is available");
    let source: std::sync::Arc<str> = std::sync::Arc::from(source);
    let prepared = crate::analyzer::store::semantic_ir::tests::prepare(&file, &source);
    let mut flows = parse_time_partial_flows(&artifact, &prepared, &cancellation)
        .expect("the projection is not cancelled");
    let index = artifact
        .procedures()
        .iter()
        .position(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(name)
        })
        .expect("the named procedure");
    flows.swap_remove(index)
}

fn partial_flows(source: &str, name: &str) -> ProcedurePartialFlows {
    let (procedure, snapshot) = procedure_and_snapshot(source, name);
    compute_partial_flows(&procedure, &snapshot)
}

#[test]
fn parameter_returned_reaches_the_normal_return_port() {
    let result = partial_flows(
        "pub fn identity(value: u32) -> u32 {\n    value\n}\n",
        "identity",
    );
    assert!(
        port_flows(&result).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && **to == PartialFlowPort::NormalReturn
        }),
        "a returned parameter flows to the normal return port: {result:?}"
    );
}

#[test]
fn parameter_passed_to_a_call_reaches_the_argument_port() {
    let result = partial_flows(
        "pub fn forward(value: u32) {\n    sink(value);\n}\n\nfn sink(_value: u32) {}\n",
        "forward",
    );
    assert!(
        port_flows(&result).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && matches!(to, PartialFlowPort::CallArgument { ordinal: 0, .. })
        }),
        "a parameter passed to a call flows to that argument port: {result:?}"
    );
}

#[test]
fn value_stored_into_self_field_reaches_a_heap_port_rooted_at_the_receiver() {
    let result = partial_flows(
        "pub struct Holder {\n    field: u32,\n}\n\nimpl Holder {\n    pub fn store(&mut self, value: u32) {\n        self.field = value;\n    }\n}\n",
        "store",
    );
    assert!(
        port_flows(&result).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && matches!(
                    to,
                    PartialFlowPort::Heap { root, selectors, tail: AccessPathTail::Exact }
                        if **root == PartialFlowPort::Receiver
                            && matches!(selectors.as_ref(), [HeapSelector::Field(_)])
                )
        }),
        "a value stored into self.field flows to the receiver's field port: {result:?}"
    );
}

#[test]
fn parameter_captured_by_a_move_closure_reaches_a_capture_out_port() {
    let result = partial_flows(
        "pub fn capture(value: u32) -> impl Fn() -> u32 {\n    move || value\n}\n",
        "capture",
    );
    assert!(
        port_flows(&result).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && matches!(to, PartialFlowPort::CaptureOut { .. })
        }),
        "a parameter captured by a move closure reaches the capture-out port: {result:?}"
    );
}

#[test]
fn loaded_parameter_field_is_an_entry_seed_of_its_heap_port() {
    let result = partial_flows(
        "pub struct Holder {\n    field: u32,\n}\n\npub fn read(holder: Holder) -> u32 {\n    holder.field\n}\n",
        "read",
    );
    assert!(
        port_flows(&result).iter().any(|(from, to)| {
            matches!(from, PartialFlowPort::Heap { root, selectors, .. }
                if **root == PartialFlowPort::Parameter { ordinal: 0 }
                    && matches!(selectors.as_ref(), [HeapSelector::Field(_)]))
                && **to == PartialFlowPort::NormalReturn
        }),
        "a loaded parameter field flows from its heap port to the return: {result:?}"
    );
}

#[test]
fn field_written_then_read_keeps_the_entry_value_under_a_weak_store() {
    let result = partial_flows(
        "pub struct Holder {\n    field: u32,\n}\n\npub fn rewrite(mut holder: Holder, value: u32) -> u32 {\n    holder.field = value;\n    holder.field\n}\n",
        "rewrite",
    );
    let flows = port_flows(&result);
    assert!(
        flows.iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 1 }
                && **to == PartialFlowPort::NormalReturn
        }),
        "the stored value reaches the return through the load: {result:?}"
    );
    // The file-local host answers "no strong update", so the store is a weak
    // update and the caller's value of the field stays live past it. The entry
    // seed for the loaded location is what carries it to the return.
    assert!(
        flows.iter().any(|(from, to)| {
            matches!(from, PartialFlowPort::Heap { root, .. }
                if **root == PartialFlowPort::Parameter { ordinal: 0 })
                && **to == PartialFlowPort::NormalReturn
        }),
        "a weak store keeps the entry value of the field live to the load: {result:?}"
    );
}

#[test]
fn unresolved_call_projection_keeps_its_flows_and_is_open() {
    // An unresolved dispatch gap makes the projection `Unknown`, with the
    // snapshot attached: the arm that writes flows with outcome 0 and open = 1.
    let result = parse_time_flows(
        "pub fn keep(value: u32) -> u32 {\n    missing_helper();\n    value\n}\n",
        "keep",
    );
    assert_eq!(result.outcome, PartialFlowOutcome::Complete, "{result:?}");
    assert!(
        result.open,
        "an unresolved call leaves the procedure open: {result:?}"
    );
    assert_eq!(
        result.detail.as_deref(),
        Some("unknown"),
        "the head names the projection outcome that carried the snapshot: {result:?}"
    );
    assert!(
        port_flows(&result).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && **to == PartialFlowPort::NormalReturn
        }),
        "the flow past the open call is still recorded: {result:?}"
    );
}

#[test]
fn comparison_guard_kills_the_value_on_its_barrier_arm() {
    let guarded = partial_flows(
        "pub fn clamp(value: i64) -> i64 {\n    if value < 10 {\n        return value;\n    }\n    0\n}\n",
        "clamp",
    );
    assert!(
        !port_flows(&guarded).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && **to == PartialFlowPort::NormalReturn
        }),
        "the guard's barrier arm removes the parameter before its return: {guarded:?}"
    );
    let unguarded = partial_flows(
        "pub fn direct(value: i64) -> i64 {\n    return value;\n}\n",
        "direct",
    );
    assert!(
        port_flows(&unguarded).iter().any(|(from, to)| {
            **from == PartialFlowPort::Parameter { ordinal: 0 }
                && **to == PartialFlowPort::NormalReturn
        }),
        "the same return without a guard keeps the flow: {unguarded:?}"
    );
}
