mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::semantic::{
    AbstractObjectIdentity, AllocationKind, ArgumentDomain, CallArgumentExpansion,
    CancellationToken, CandidateCoverage, DispatchExtensibility, ProcedureKind, ProcedurePortKind,
    ProcedureSemantics, SemanticBudget, SemanticCapability, SemanticEffect, SemanticGapSubject,
    SemanticRequest, SemanticValueKind, ValueFlowKind,
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
fn php_publishes_receiver_parameter_local_allocation_argument_and_return_identity() {
    const SOURCE: &str = r#"<?php
namespace Values;

final class Boxed {
    public function __construct(public mixed $value) {}
}

class Sample {
    public function instance(mixed $input): Boxed {
        $made = new Boxed($input);
        $this->sink($input, $made);
        return $made;
    }

    private function sink(mixed $input, Boxed $made): void {}

    public static function factory(mixed $input): Boxed {
        return new Boxed($input);
    }

    public function dynamic(object $target, string $name): mixed {
        return $target->$name();
    }
}
"#;

    let project = InlineTestProject::new()
        .file("values/Sample.php", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/Sample.php");
    let instance = procedure_named(&graph, "instance", ProcedureKind::Method);

    assert_eq!(
        instance.properties().dispatch_extensibility,
        DispatchExtensibility::Open,
        "ordinary PHP methods retain an open inheritance and runtime-dispatch boundary"
    );
    let formal_receiver = instance
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("PHP instance method receiver");
    let input = instance
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("PHP method parameter");
    assert_eq!(mapped_source(instance, SOURCE, input.source), "$input");

    let local = instance
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(instance, SOURCE, value.source) == "$made"
        })
        .expect("PHP assignment must publish a stable local identity");
    let construction = instance
        .call_sites()
        .iter()
        .find(|call| mapped_source(instance, SOURCE, call.source) == "new Boxed($input)")
        .expect("PHP construction call");
    let construction_result = construction.result.expect("constructor result");
    assert!(instance.allocations().iter().any(|allocation| {
        allocation.kind == AllocationKind::Object && allocation.result == construction_result
    }));
    assert!(
        instance
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::Assignment { target, value }
                    if target == local.id && value == construction_result
            )),
        "local assignment must preserve the constructor result identity"
    );

    let call = instance
        .call_sites()
        .iter()
        .find(|call| mapped_source(instance, SOURCE, call.source) == "$this->sink($input, $made)")
        .expect("PHP member call");
    let receiver = instance
        .value(call.receiver.expect("member call receiver"))
        .expect("receiver value");
    assert_eq!(mapped_source(instance, SOURCE, receiver.source), "$this");
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
    assert_eq!(argument_sources, ["$input", "$made"]);

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
        .expect("PHP return flow");
    assert_eq!(
        mapped_source(
            instance,
            SOURCE,
            instance.value(returned).expect("returned value").source
        ),
        "$made"
    );

    let receiver_start = SOURCE.find("$this->sink").expect("receiver source");
    let receiver_line = SOURCE[..receiver_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let receiver_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &project.file("values/Sample.php"),
            brokk_bifrost::analyzer::Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "$this".len(),
                start_line: receiver_line,
                end_line: receiver_line,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("PHP current-receiver points-to query");
    let receiver_points_to = receiver_outcome
        .available_value()
        .expect("PHP receiver query must retain its value");
    assert_ne!(
        receiver_points_to.coverage(),
        CandidateCoverage::Truncated,
        "{receiver_outcome:#?}"
    );
    assert!(
        receiver_points_to.object_candidates().any(|candidate| {
            matches!(
                candidate.value().identity(),
                AbstractObjectIdentity::ProcedurePort(port)
                    if port.kind() == ProcedurePortKind::Receiver
            )
        }),
        "{receiver_outcome:#?}"
    );

    let factory = procedure_named(&graph, "factory", ProcedureKind::Method);
    assert!(
        factory
            .values()
            .iter()
            .all(|value| value.kind != SemanticValueKind::Receiver),
        "static PHP methods must not publish a current receiver"
    );
    assert!(
        factory
            .allocations()
            .iter()
            .any(|allocation| allocation.kind == AllocationKind::Object),
        "static factory construction must retain allocation identity"
    );

    let dynamic = procedure_named(&graph, "dynamic", ProcedureKind::Method);
    let dynamic_call = dynamic
        .call_sites()
        .iter()
        .find(|call| mapped_source(dynamic, SOURCE, call.source) == "$target->$name()")
        .expect("dynamic PHP member call");
    assert!(
        dynamic.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::CallSite(dynamic_call.id)
                && gap.capability == SemanticCapability::DynamicDispatch
        }),
        "dynamic PHP member selection must remain explicitly uncertain"
    );
}
