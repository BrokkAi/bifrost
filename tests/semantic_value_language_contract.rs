mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::semantic::{
    AllocationKind, ArgumentDomain, CallArgumentExpansion, CaptureMode, CaptureSource,
    MemoryAccessKind, MemoryLocationKind, ProcedureKind, ProcedureSemantics, SemanticEffect,
    SemanticValueKind, ValueFlowKind,
};

use common::{InlineTestProject, semantic_graph::SemanticGraph};

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

fn mapped_source<'source>(
    procedure: &ProcedureSemantics,
    source: &'source str,
    mapping: brokk_bifrost::analyzer::semantic::SourceMappingId,
) -> &'source str {
    let span = procedure
        .source_mapping(mapping)
        .expect("semantic row must retain a source mapping")
        .locator
        .anchor()
        .span();
    source
        .get(span.start_byte() as usize..span.end_byte() as usize)
        .expect("semantic source span must index the fixture")
}

fn assert_value_contract(
    graph: &SemanticGraph,
    source: &str,
    method_name: &str,
    call_source: &str,
) {
    let procedure = procedure_named(graph, method_name, ProcedureKind::Method);
    let parameter = procedure
        .values()
        .iter()
        .find(|value| {
            value.kind
                == SemanticValueKind::Parameter {
                    ordinal: 0,
                    multiplicity: Default::default(),
                }
        })
        .expect("instance method must publish its first formal parameter");
    assert!(mapped_source(procedure, source, parameter.source).contains("input"));

    let receiver = procedure
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("instance method must publish a receiver port");
    let call = procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, source, call.source) == call_source)
        .unwrap_or_else(|| panic!("missing call site {call_source:?}"));

    assert_eq!(call.arguments.len(), 2);
    assert_eq!(
        call.arguments[0].expansion,
        CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword)
    );
    assert_eq!(
        call.arguments[1].expansion,
        CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword)
    );
    let argument_sources = call
        .arguments
        .iter()
        .map(|argument| {
            let value = procedure
                .value(argument.value)
                .expect("call argument must reference a semantic value");
            mapped_source(procedure, source, value.source)
        })
        .collect::<Vec<_>>();
    assert_eq!(argument_sources, ["input", "made"]);

    let call_receiver = procedure
        .value(
            call.receiver
                .expect("member call must publish its receiver"),
        )
        .expect("call receiver must reference a semantic value");
    assert_eq!(
        mapped_source(procedure, source, call_receiver.source),
        "this"
    );
    assert!(
        procedure
            .value(call.result.expect("call must publish its result"))
            .is_some()
    );
    assert!(
        procedure
            .value(call.thrown.expect("call must publish its thrown value"))
            .is_some()
    );

    let return_flow = procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source,
                target,
            } => Some((source, target)),
            _ => None,
        })
        .expect("explicit return must publish a return flow");
    assert_eq!(
        mapped_source(
            procedure,
            source,
            procedure.value(return_flow.0).unwrap().source
        ),
        "made"
    );
    assert_eq!(
        procedure.value(return_flow.1).unwrap().kind,
        SemanticValueKind::Return
    );

    let construction = procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, source, call.source).starts_with("new Box"))
        .expect("object construction must publish a call site");
    let allocation = procedure
        .allocations()
        .iter()
        .find(|allocation| allocation.result == construction.result.unwrap())
        .expect("object construction result must own an allocation site");
    assert_eq!(allocation.kind, AllocationKind::Object);

    let local = procedure
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(procedure, source, value.source) == "made"
        })
        .expect("local declaration must publish a stable local value");
    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::Assignment { target, value }
                    if target == local.id && value == construction.result.unwrap()
            )),
        "local initializer must assign the construction result"
    );
    for read in [call.arguments[1].value, return_flow.0] {
        assert!(
            procedure
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    } if source == local.id && target == read
                )),
            "every local read used by a call or return must flow from its declaration"
        );
    }

    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Receiver,
                    source,
                    ..
                } if source == receiver.id
            )),
        "this expression must flow from the receiver port"
    );
}

fn assert_index_load(graph: &SemanticGraph, source: &str) {
    let procedure = procedure_named(graph, "first", ProcedureKind::Method);
    let (location, result) = procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match event.effect {
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Index,
                location,
                result,
            } => Some((location, result)),
            _ => None,
        })
        .expect("indexed access must publish a memory load");
    let location = procedure
        .memory_location(location)
        .expect("memory load must reference a location row");
    let MemoryLocationKind::Index {
        base,
        index: Some(index),
    } = location.kind
    else {
        panic!("indexed load must publish its base and index values");
    };
    assert_eq!(
        mapped_source(procedure, source, procedure.value(base).unwrap().source),
        "items"
    );
    assert_eq!(
        mapped_source(procedure, source, procedure.value(index).unwrap().source),
        "index"
    );
    assert_eq!(
        mapped_source(procedure, source, procedure.value(result).unwrap().source),
        "items[index]"
    );
}

fn assert_assignment_and_index_store(graph: &SemanticGraph, source: &str) {
    let procedure = procedure_named(graph, "rewrite", ProcedureKind::Method);
    let local = procedure
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(procedure, source, value.source) == "current"
        })
        .expect("rewrite must publish its local binding");
    let assignments = procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter(|event| {
            matches!(
                event.effect,
                SemanticEffect::Assignment { target, .. } if target == local.id
            )
        })
        .count();
    assert_eq!(
        assignments, 2,
        "initializer and reassignment must both target the local"
    );

    let (location, value) = procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match event.effect {
            SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Index,
                location,
                value,
            } => Some((location, value)),
            _ => None,
        })
        .expect("indexed assignment must publish a memory store");
    let MemoryLocationKind::Index {
        base,
        index: Some(index),
    } = procedure.memory_location(location).unwrap().kind
    else {
        panic!("indexed store must preserve base and index values");
    };
    assert_eq!(
        mapped_source(procedure, source, procedure.value(base).unwrap().source),
        "items"
    );
    assert_eq!(
        mapped_source(procedure, source, procedure.value(index).unwrap().source),
        "index"
    );
    assert_eq!(
        mapped_source(procedure, source, procedure.value(value).unwrap().source),
        "replacement"
    );
}

fn assert_receiver_capture(graph: &SemanticGraph) {
    let parent = procedure_named(graph, "capture", ProcedureKind::Method);
    let capture = parent
        .captures()
        .first()
        .expect("capturing lambda must publish a capture binding");
    assert_eq!(capture.mode, CaptureMode::Value);
    let CaptureSource::Value(captured) = capture.captured else {
        panic!("lexical receiver capture must use a value source");
    };
    assert_eq!(
        parent.value(captured).unwrap().kind,
        SemanticValueKind::Receiver
    );
    assert_eq!(
        parent.allocations()[capture.environment.index()].kind,
        AllocationKind::ClosureEnvironment
    );

    let child = graph
        .artifact()
        .procedure(capture.target)
        .expect("capture target must be a materialized child procedure");
    assert_eq!(child.kind(), ProcedureKind::Lambda);
    assert_eq!(child.lexical_parent(), Some(parent.id()));
    assert!(matches!(
        child.memory_location(capture.destination).unwrap().kind,
        MemoryLocationKind::Capture { lexical_parent } if lexical_parent == parent.id()
    ));
    assert!(
        child
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Capture,
                    location,
                    ..
                } if location == capture.destination
            )),
        "child procedure must load its capture slot"
    );
}

fn assert_branch_ambiguous_local(graph: &SemanticGraph, source: &str) {
    let procedure = procedure_named(graph, "branch", ProcedureKind::Method);
    let local = procedure
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(procedure, source, value.source) == "choice"
        })
        .expect("branch fixture must publish its local binding");
    let definitions = procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| match event.effect {
            SemanticEffect::Assignment { target, value } if target == local.id => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        definitions.len(),
        2,
        "both branch definitions must remain visible to later value-flow analysis"
    );
    assert_ne!(definitions[0], definitions[1]);
    let return_source = procedure
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
        .expect("branch fixture must publish a return flow");
    assert!(
        procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source,
                    target,
                } if source == local.id && target == return_source
            )),
        "the post-branch read must flow from the shared local binding"
    );
}

fn flow_source(
    procedure: &ProcedureSemantics,
    target: brokk_bifrost::analyzer::semantic::ValueId,
    kind: ValueFlowKind,
) -> brokk_bifrost::analyzer::semantic::ValueId {
    procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind: candidate,
                source,
                target: candidate_target,
            } if candidate == kind && candidate_target == target => Some(source),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {kind:?} flow into {target}"))
}

fn assert_typescript_shadowing(graph: &SemanticGraph, source: &str) {
    let procedure = procedure_named(graph, "shadow", ProcedureKind::Method);
    let parameter = procedure
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .unwrap();
    let local = procedure
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(procedure, source, value.source) == "input"
        })
        .expect("inner declaration must publish a distinct local");
    let call = procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, source, call.source) == "this.sink(1, input)")
        .unwrap();
    assert_eq!(
        flow_source(procedure, call.arguments[1].value, ValueFlowKind::Local),
        local.id
    );
    let returned_read = procedure
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
        .unwrap();
    assert_eq!(
        flow_source(procedure, returned_read, ValueFlowKind::Parameter),
        parameter.id,
        "the inner local must not escape its block and shadow the returned parameter"
    );
}

fn assert_java_sibling_scopes(graph: &SemanticGraph, source: &str) {
    let procedure = procedure_named(graph, "siblings", ProcedureKind::Method);
    let calls = procedure
        .call_sites()
        .iter()
        .filter(|call| mapped_source(procedure, source, call.source) == "this.sink(input, value)")
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    let first = flow_source(procedure, calls[0].arguments[1].value, ValueFlowKind::Local);
    let second = flow_source(procedure, calls[1].arguments[1].value, ValueFlowKind::Local);
    assert_ne!(
        first, second,
        "same-name locals in sibling blocks must retain distinct identities"
    );
}

#[test]
fn typescript_and_java_publish_expression_backed_call_and_return_facts() {
    const TYPESCRIPT: &str = r#"class Box {}
class Sample {
    instance(input: number) {
        const made = new Box(input);
        this.sink(input, made);
        return made;
    }
    sink(_input: number, _made: Box) {}
    static factory(input: number) { return new Box(input); }
    first(items: Box[], index: number) { return items[index]; }
    rewrite(items: Box[], index: number, replacement: Box) {
        let current = items[index];
        items[index] = replacement;
        current = replacement;
        return current;
    }
    capture() { return () => this.instance(1); }
    branch(flag: boolean, input: Box) {
        let choice: Box;
        if (flag) choice = new Box(); else choice = input;
        return choice;
    }
    shadow(input: Box) {
        { const input = new Box(); this.sink(1, input); }
        return input;
    }
}
"#;
    const JAVA: &str = r#"class Box {}
class Sample {
    Object instance(int input) {
        Object made = new Box(input);
        this.sink(input, made);
        return made;
    }
    void sink(int input, Object made) {}
    static Object factory(int input) { return new Box(input); }
    Object first(Object[] items, int index) { return items[index]; }
    Object rewrite(Object[] items, int index, Object replacement) {
        Object current = items[index];
        items[index] = replacement;
        current = replacement;
        return current;
    }
    java.util.function.Supplier<Object> capture() { return () -> this.instance(1); }
    Object branch(boolean flag, Object input) {
        Object choice;
        if (flag) choice = new Box(); else choice = input;
        return choice;
    }
    void siblings(int input) {
        { Object value = new Box(input); this.sink(input, value); }
        { Object value = new Box(input); this.sink(input, value); }
    }
}
"#;

    let project = InlineTestProject::new()
        .file("values/Sample.ts", TYPESCRIPT)
        .file("values/Sample.java", JAVA)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let typescript = SemanticGraph::materialize(&project, &analyzer, "values/Sample.ts");
    let java = SemanticGraph::materialize(&project, &analyzer, "values/Sample.java");

    assert_value_contract(
        &typescript,
        TYPESCRIPT,
        "instance",
        "this.sink(input, made)",
    );
    assert_value_contract(&java, JAVA, "instance", "this.sink(input, made)");
    assert_index_load(&typescript, TYPESCRIPT);
    assert_index_load(&java, JAVA);
    assert_assignment_and_index_store(&typescript, TYPESCRIPT);
    assert_assignment_and_index_store(&java, JAVA);
    assert_receiver_capture(&typescript);
    assert_receiver_capture(&java);
    assert_branch_ambiguous_local(&typescript, TYPESCRIPT);
    assert_branch_ambiguous_local(&java, JAVA);
    assert_typescript_shadowing(&typescript, TYPESCRIPT);
    assert_java_sibling_scopes(&java, JAVA);

    for graph in [&typescript, &java] {
        let factory = procedure_named(graph, "factory", ProcedureKind::Method);
        assert!(
            factory
                .values()
                .iter()
                .all(|value| value.kind != SemanticValueKind::Receiver),
            "static methods must not manufacture receiver ports"
        );
    }

    for graph in [&typescript, &java] {
        let instance = procedure_named(graph, "instance", ProcedureKind::Method);
        let parameter = instance
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
            .unwrap();
        assert!(
            instance
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Parameter,
                        source,
                        ..
                    } if source == parameter.id
                )),
            "parameter reads must flow from the formal port"
        );
    }
}
