mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::semantic::{
    AbstractObjectIdentity, AllocationKind, ArgumentDomain, CallArgumentExpansion,
    CancellationToken, CandidateCoverage, DispatchExtensibility, ProcedureKind, ProcedurePortKind,
    ProcedureSemantics, SemanticBudget, SemanticEffect, SemanticRequest, SemanticValueKind,
    ValueFlowKind,
};

use common::{
    InlineTestProject,
    semantic_graph::{SemanticGraph, mapped_source},
};

fn procedure_named<'artifact>(
    graph: &'artifact SemanticGraph,
    name: &str,
    kind: ProcedureKind,
) -> &'artifact ProcedureSemantics {
    graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == kind
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
        })
        .unwrap_or_else(|| panic!("missing {kind:?} procedure {name}"))
}

#[test]
fn python_publishes_receiver_parameter_local_allocation_and_return_identity() {
    const SOURCE: &str = r#"
class Service:
    def handle(self, other: "Service") -> "Service":
        self.accept(other)
        made: Service = Service()
        alias: Service = other
        return alias

    def accept(self, other: "Service") -> None:
        pass
"#;

    let project = InlineTestProject::new()
        .file("values/service.py", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/service.py");
    let handle = procedure_named(&graph, "handle", ProcedureKind::Method);
    let accept_declaration = analyzer
        .analyzer()
        .declarations(&project.file("values/service.py"))
        .into_iter()
        .find(|unit| unit.identifier() == "accept")
        .expect("indexed Python method");
    assert!(
        analyzer
            .analyzer()
            .signature_metadata(&accept_declaration)
            .iter()
            .all(|metadata| {
                metadata.dispatch_extensibility() == Some(DispatchExtensibility::Open)
            })
    );

    assert_eq!(
        handle.properties().dispatch_extensibility,
        DispatchExtensibility::Open,
        "Python methods must retain an open monkeypatching and descriptor boundary"
    );
    let formal_receiver = handle
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("Python instance method receiver");
    assert_eq!(
        mapped_source(handle, SOURCE, formal_receiver.source),
        "self"
    );
    let other = handle
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("Python typed parameter");
    assert_eq!(mapped_source(handle, SOURCE, other.source), "other");

    for local_name in ["made", "alias"] {
        assert!(
            handle.values().iter().any(|value| {
                value.kind == SemanticValueKind::Local
                    && mapped_source(handle, SOURCE, value.source) == local_name
            }),
            "missing Python local {local_name}"
        );
    }

    let construction = handle
        .call_sites()
        .iter()
        .find(|call| mapped_source(handle, SOURCE, call.source) == "Service()")
        .expect("Python construction call");
    assert!(handle.allocations().iter().any(|allocation| {
        allocation.kind == AllocationKind::Object && Some(allocation.result) == construction.result
    }));

    let member_call = handle
        .call_sites()
        .iter()
        .find(|call| mapped_source(handle, SOURCE, call.source) == "self.accept(other)")
        .expect("Python bound-method call");
    let call_receiver = handle
        .value(member_call.receiver.expect("bound call receiver"))
        .expect("receiver value");
    assert_eq!(mapped_source(handle, SOURCE, call_receiver.source), "self");
    assert!(
        handle
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    target,
                } if source == formal_receiver.id && target == call_receiver.id
            ))
    );
    assert_eq!(member_call.arguments.len(), 1);
    assert_eq!(
        member_call.arguments[0].expansion,
        CallArgumentExpansion::Direct(ArgumentDomain::Positional)
    );
    let argument = handle
        .value(member_call.arguments[0].value)
        .expect("argument value");
    assert_eq!(mapped_source(handle, SOURCE, argument.source), "other");

    let returned = handle
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source,
                ..
            } => Some(source),
            _ => None,
        })
        .expect("Python return flow");
    assert_eq!(
        mapped_source(
            handle,
            SOURCE,
            handle.value(returned).expect("returned value").source
        ),
        "alias"
    );

    let receiver_start = SOURCE.find("self.accept").expect("receiver source");
    let receiver_line = SOURCE[..receiver_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let receiver_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &project.file("values/service.py"),
            brokk_bifrost::analyzer::Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "self".len(),
                start_line: receiver_line,
                end_line: receiver_line,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Python current receiver points-to query");
    let receiver_points_to = receiver_outcome
        .available_value()
        .expect("Python receiver query must retain its value");
    assert_eq!(
        receiver_points_to.coverage(),
        CandidateCoverage::Exhaustive,
        "{receiver_outcome:#?}"
    );
    assert!(receiver_points_to.object_candidates().all(|candidate| {
        matches!(
            candidate.value().identity(),
            AbstractObjectIdentity::ProcedurePort(port)
                if port.kind() == ProcedurePortKind::Receiver
        )
    }));
}
