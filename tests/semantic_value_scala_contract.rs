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
fn scala_publishes_receiver_local_argument_allocation_and_return_identity() {
    const SOURCE: &str = r#"
package values

final class Box(val value: Any)

class Sample {
  def instance(input: Any) = {
    val made = new Box(input)
    this.sink(input, made)
    made
  }

  def sink(input: Any, made: Box): Unit = ()
}

object Sample {
  def factory(input: Any): Box = new Box(input)
}
"#;

    let project = InlineTestProject::new()
        .file("values/Sample.scala", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/Sample.scala");
    let instance = procedure_named(&graph, "instance", ProcedureKind::Method);

    assert_eq!(
        instance.properties().dispatch_extensibility,
        DispatchExtensibility::Open,
        "ordinary Scala class methods retain an open override boundary"
    );
    let formal_receiver = instance
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("Scala instance methods must publish their current receiver");
    let input = instance
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("Scala method parameter");
    assert!(mapped_source(instance, SOURCE, input.source).contains("input"));

    let local = instance
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(instance, SOURCE, value.source) == "made"
        })
        .expect("Scala val must publish a stable local identity");
    assert!(
        instance
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

    let call = instance
        .call_sites()
        .iter()
        .find(|call| mapped_source(instance, SOURCE, call.source) == "this.sink(input, made)")
        .expect("Scala member application");
    let receiver = instance
        .value(call.receiver.expect("member application receiver"))
        .expect("receiver value");
    assert_eq!(mapped_source(instance, SOURCE, receiver.source), "this");
    assert!(
        instance
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
            let value = instance.value(argument.value).expect("argument value");
            mapped_source(instance, SOURCE, value.source)
        })
        .collect::<Vec<_>>();
    assert_eq!(argument_sources, ["input", "made"]);

    let construction = instance
        .call_sites()
        .iter()
        .find(|call| mapped_source(instance, SOURCE, call.source) == "new Box(input)")
        .expect("Scala construction call");
    assert!(instance.allocations().iter().any(|allocation| {
        allocation.kind == AllocationKind::Object && Some(allocation.result) == construction.result
    }));
    let returned = instance
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
        .expect("Scala implicit result must publish a return flow");
    assert_eq!(
        mapped_source(
            instance,
            SOURCE,
            instance.value(returned).expect("returned value").source
        ),
        "made"
    );

    let receiver_start = SOURCE.find("this.sink").expect("receiver source");
    let receiver_line = SOURCE[..receiver_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let receiver_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &project.file("values/Sample.scala"),
            brokk_bifrost::analyzer::Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "this".len(),
                start_line: receiver_line,
                end_line: receiver_line,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Scala current-receiver points-to query");
    let receiver_points_to = receiver_outcome
        .available_value()
        .expect("Scala receiver query must retain its value");
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
    assert_eq!(
        factory.properties().dispatch_extensibility,
        DispatchExtensibility::Closed,
        "Scala singleton-object methods have closed dispatch"
    );
    assert!(
        factory
            .allocations()
            .iter()
            .any(|allocation| allocation.kind == AllocationKind::Object),
        "factory construction must retain allocation identity"
    );
}
