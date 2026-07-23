mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::Range;
use brokk_bifrost::analyzer::semantic::{
    AbstractObjectIdentity, AllocationKind, ArgumentDomain, CallArgumentExpansion,
    CancellationToken, CandidateCoverage, ProcedureKind, ProcedurePortKind, ProcedureSemantics,
    SemanticBudget, SemanticEffect, SemanticOutcome, SemanticRequest, SemanticValueKind,
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

fn source_range(source: &str, text: &str) -> Range {
    let start_byte = source
        .find(text)
        .unwrap_or_else(|| panic!("missing {text:?}"));
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    Range {
        start_byte,
        end_byte: start_byte + text.len(),
        start_line,
        end_line: start_line,
    }
}

#[test]
fn cpp_publishes_receiver_parameter_local_allocation_call_and_return_identity() {
    const SOURCE: &str = r#"
struct Other {
    void run() {}
};

struct Service {
    virtual void run() {}

    Service* passthrough(Service* input) {
        return input;
    }

    Service* allocate() {
        return new Service();
    }

    void use(Service* input) {
        Service local;
        Service* made = new Service();
        this->run();
        input->run();
        local.run();
        made->run();
        passthrough(input)->run();
        allocate()->run();
    }
};
"#;

    let project = InlineTestProject::new()
        .file("values/service.cpp", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/service.cpp");
    let use_procedure = procedure_named(&graph, "use", ProcedureKind::Method);

    let formal_receiver = use_procedure
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("C++ instance method receiver");
    let input = use_procedure
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("C++ pointer parameter");
    assert_eq!(mapped_source(use_procedure, SOURCE, input.source), "input");

    let local = use_procedure
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(use_procedure, SOURCE, value.source) == "local"
        })
        .expect("C++ stack object identity");
    let made = use_procedure
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(use_procedure, SOURCE, value.source) == "made"
        })
        .expect("C++ pointer local identity");
    assert!(use_procedure.allocations().iter().any(|allocation| {
        allocation.kind == AllocationKind::Object && allocation.result == local.id
    }));
    assert!(
        use_procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    target,
                    ..
                } if target == made.id
            ))
    );

    for (call_source, receiver_source) in [
        ("this->run()", "this"),
        ("input->run()", "input"),
        ("local.run()", "local"),
        ("made->run()", "made"),
        ("passthrough(input)->run()", "passthrough(input)"),
        ("allocate()->run()", "allocate()"),
    ] {
        let call = use_procedure
            .call_sites()
            .iter()
            .find(|call| mapped_source(use_procedure, SOURCE, call.source) == call_source)
            .unwrap_or_else(|| panic!("missing C++ call {call_source}"));
        let receiver = use_procedure
            .value(call.receiver.expect("member-call receiver"))
            .expect("receiver value");
        assert_eq!(
            mapped_source(use_procedure, SOURCE, receiver.source),
            receiver_source
        );
    }
    assert!(
        use_procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    ..
                } if source == formal_receiver.id
            ))
    );
    assert!(
        use_procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Parameter,
                    source,
                    ..
                } if source == input.id
            ))
    );

    let passthrough_call = use_procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(use_procedure, SOURCE, call.source) == "passthrough(input)")
        .expect("passthrough call");
    assert_eq!(passthrough_call.arguments.len(), 1);
    assert_eq!(
        passthrough_call.arguments[0].expansion,
        CallArgumentExpansion::Direct(ArgumentDomain::Positional)
    );
    assert_eq!(
        mapped_source(
            use_procedure,
            SOURCE,
            use_procedure
                .value(passthrough_call.arguments[0].value)
                .expect("argument value")
                .source
        ),
        "input"
    );

    for (procedure_name, returned_source) in
        [("passthrough", "input"), ("allocate", "new Service()")]
    {
        let procedure = procedure_named(&graph, procedure_name, ProcedureKind::Method);
        let source = procedure
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
            .unwrap_or_else(|| panic!("missing return flow for {procedure_name}"));
        assert_eq!(
            mapped_source(
                procedure,
                SOURCE,
                procedure.value(source).expect("return source").source
            ),
            returned_source
        );
    }

    let file = project.file("values/service.cpp");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let receiver_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &file,
            source_range(SOURCE, "this"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("C++ current-receiver points-to query");
    let receiver_points_to = receiver_outcome
        .available_value()
        .expect("C++ current receiver retains neutral value");
    assert_ne!(receiver_points_to.coverage(), CandidateCoverage::Truncated);
    assert!(receiver_points_to.object_candidates().all(|candidate| {
        matches!(
            candidate.value().identity(),
            AbstractObjectIdentity::ProcedurePort(port)
                if port.kind() == ProcedurePortKind::Receiver
        )
    }));

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SemanticBudget::default();
    let cancelled_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &file,
            source_range(SOURCE, "made"),
            &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
        )
        .expect("pre-cancelled C++ points-to query");
    assert!(matches!(
        cancelled_outcome,
        SemanticOutcome::Cancelled { partial: None, .. }
    ));

    let mut tiny_budget = SemanticBudget::uniform(1).expect("positive semantic budget");
    let tiny_outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &file,
            source_range(SOURCE, "made"),
            &mut SemanticRequest::new(&mut tiny_budget, &cancellation),
        )
        .expect("tiny-budget C++ points-to query");
    assert!(matches!(
        tiny_outcome,
        SemanticOutcome::ExceededBudget { .. }
    ));
}
