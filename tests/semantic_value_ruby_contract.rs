mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::semantic::{
    AbstractObjectIdentity, AllocationKind, ArgumentDomain, CallArgumentExpansion,
    CallableTargetResolution, CancellationToken, CandidateCoverage, DispatchExtensibility,
    ProcedureKind, ProcedurePortKind, ProcedureSemantics, SemanticBudget, SemanticCapability,
    SemanticEffect, SemanticGapKind, SemanticGapSubject, SemanticRequest, SemanticValueKind,
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
fn ruby_publishes_receiver_parameter_local_allocation_and_return_identity() {
    const SOURCE: &str = r#"
class Box
  def initialize(value)
    @value = value
  end
end

class Service
  def current(input)
    made = Box.new(input)
    self.sink(input, made)
    made
  end

  def sink(input, made)
    made
  end

  def self.factory(input)
    Box.new(input)
  end

  def boundaries(other)
    other&.sink
    send(:sink)
  end
end
"#;

    let project = InlineTestProject::new()
        .file("values/service.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/service.rb");
    let current = procedure_named(&graph, "current", ProcedureKind::Method);
    let sink_declaration = analyzer
        .analyzer()
        .declarations(&project.file("values/service.rb"))
        .into_iter()
        .find(|unit| unit.identifier() == "sink")
        .expect("indexed Ruby method");
    assert!(
        analyzer
            .analyzer()
            .signature_metadata(&sink_declaration)
            .iter()
            .all(|metadata| {
                metadata.dispatch_extensibility() == Some(DispatchExtensibility::Open)
            }),
        "Ruby method signature metadata must retain its open dispatch boundary"
    );

    assert_eq!(
        current.properties().dispatch_extensibility,
        DispatchExtensibility::Open,
        "Ruby methods retain an open monkeypatching and method_missing boundary"
    );
    let formal_receiver = current
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("Ruby method receiver");
    let input = current
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("Ruby method parameter");
    assert_eq!(mapped_source(current, SOURCE, input.source), "input");

    let local = current
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(current, SOURCE, value.source) == "made"
        })
        .expect("Ruby assignment must publish a stable local identity");
    assert!(
        current
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    target,
                    ..
                } if target == local.id
            ))
    );

    let call = current
        .call_sites()
        .iter()
        .find(|call| mapped_source(current, SOURCE, call.source) == "self.sink(input, made)")
        .expect("Ruby member call");
    let receiver = current
        .value(call.receiver.expect("member call receiver"))
        .expect("receiver value");
    assert_eq!(mapped_source(current, SOURCE, receiver.source), "self");
    assert!(
        current
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    target,
                } if source == formal_receiver.id && target == receiver.id
            ))
    );
    assert_eq!(call.arguments.len(), 2);
    assert!(call.arguments.iter().all(|argument| {
        argument.expansion == CallArgumentExpansion::Direct(ArgumentDomain::Positional)
    }));
    let argument_sources = call
        .arguments
        .iter()
        .map(|argument| {
            let value = current.value(argument.value).expect("argument value");
            mapped_source(current, SOURCE, value.source)
        })
        .collect::<Vec<_>>();
    assert_eq!(argument_sources, ["input", "made"]);

    let construction = current
        .call_sites()
        .iter()
        .find(|call| mapped_source(current, SOURCE, call.source) == "Box.new(input)")
        .expect("Ruby construction call");
    assert!(current.allocations().iter().any(|allocation| {
        allocation.kind == AllocationKind::Object && Some(allocation.result) == construction.result
    }));
    let returned = current
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
        .expect("Ruby implicit result must publish a return flow");
    assert_eq!(
        mapped_source(
            current,
            SOURCE,
            current.value(returned).expect("returned value").source
        ),
        "made"
    );

    let receiver_start = SOURCE.find("self.sink").expect("receiver source");
    let receiver_line = SOURCE[..receiver_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let receiver_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &project.file("values/service.rb"),
            brokk_bifrost::analyzer::Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "self".len(),
                start_line: receiver_line,
                end_line: receiver_line,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Ruby current-receiver points-to query");
    let receiver_points_to = receiver_outcome
        .available_value()
        .expect("Ruby receiver query must retain its value");
    assert_ne!(
        receiver_points_to.coverage(),
        CandidateCoverage::Truncated,
        "{receiver_outcome:#?}"
    );
    assert!(receiver_points_to.object_candidates().all(|candidate| {
        matches!(
            candidate.value().identity(),
            AbstractObjectIdentity::ProcedurePort(port)
                if port.kind() == ProcedurePortKind::Receiver
        )
    }));

    let factory = procedure_named(&graph, "factory", ProcedureKind::Method);
    assert!(factory.properties().is_static);
    assert_eq!(
        factory.properties().dispatch_extensibility,
        DispatchExtensibility::Open
    );
    assert!(
        factory
            .allocations()
            .iter()
            .any(|allocation| allocation.kind == AllocationKind::Object),
        "Ruby singleton factory construction must retain allocation identity"
    );

    let boundaries = procedure_named(&graph, "boundaries", ProcedureKind::Method);
    let safe_call = boundaries
        .call_sites()
        .iter()
        .find(|call| mapped_source(boundaries, SOURCE, call.source) == "other&.sink")
        .expect("Ruby safe-navigation call");
    let safe_result = safe_call.result.expect("safe-navigation result");
    assert!(boundaries.gaps().iter().any(|gap| {
        gap.subject == SemanticGapSubject::Value(safe_result)
            && gap.capability == SemanticCapability::Values
            && gap.kind == SemanticGapKind::Unknown
    }));
    let dynamic_call = boundaries
        .call_sites()
        .iter()
        .find(|call| mapped_source(boundaries, SOURCE, call.source) == "send(:sink)")
        .expect("Ruby dynamic send call");
    assert_eq!(
        dynamic_call.declared_targets,
        CallableTargetResolution::Unsupported
    );
    assert!(boundaries.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::CallableReferences
            && gap.kind == SemanticGapKind::Unsupported
            && gap.detail.contains("dynamic send")
    }));
}
