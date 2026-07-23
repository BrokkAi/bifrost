mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::semantic::{
    AbstractObjectIdentity, AccessPath, AccessPathAtPoint, AccessPathRoot, AccessPathTail,
    AccessSelector, AliasQuery, AliasRelation, AllocationKind, ArgumentDomain,
    CallArgumentExpansion, CallBinding, CallBindings, CancellationToken, CandidateCoverage,
    CaptureMode, CaptureSource, DispatchCandidate, DispatchExtensibility, DispatchOracle,
    FormalMultiplicity, HeapOracle, IndexSelector, MemoryAccessKind, MemoryLocationKind,
    MemoryStoreHandle, ObjectCardinality, ObservationPhase, OracleCallContext, OracleContractError,
    OracleLimitValues, OracleLimits, ProcedureHandle, ProcedureKind, ProcedurePortHandle,
    ProcedurePortKind, ProcedureSemantics, ScopedSemanticLocator, SemanticBudget,
    SemanticBudgetDimension, SemanticCapability, SemanticEffect, SemanticGapImpact,
    SemanticGapSubject, SemanticOutcome, SemanticRequest, SemanticValueKind, StoreAtPoint,
    UpdateEligibility, ValueAtPoint, ValueFlowEndpoint, ValueFlowKind, ValueFlowOracle,
    ValueFlowRelationKind, ValueFlowSnapshot, WeakUpdateReason, WorkspaceSemanticOracle,
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

fn procedure_handle_named(
    graph: &SemanticGraph,
    name: &str,
    kind: ProcedureKind,
) -> ProcedureHandle {
    let procedure = procedure_named(graph, name, kind);
    graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("selected procedure must have a scoped handle")
}

fn available<T>(outcome: &SemanticOutcome<T>) -> &T {
    outcome
        .available_value()
        .expect("source-backed oracle outcome must retain its partial value")
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
        CallArgumentExpansion::Direct(ArgumentDomain::Positional)
    );
    assert_eq!(
        call.arguments[1].expansion,
        CallArgumentExpansion::Direct(ArgumentDomain::Positional)
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
        !child.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::MemoryLocation(capture.destination)
                && gap.capability == SemanticCapability::Captures
        }),
        "an emitted parent binding must keep the child capture exact"
    );
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

fn assert_nested_receiver_capture_relay(graph: &SemanticGraph) {
    let parent = procedure_named(graph, "nestedCapture", ProcedureKind::Method);
    let outer_capture = parent
        .captures()
        .first()
        .expect("method must bind the outer lexical callable");
    let outer = graph
        .artifact()
        .procedure(outer_capture.target)
        .expect("outer lexical callable procedure");
    assert_eq!(outer.kind(), ProcedureKind::Lambda);
    assert!(matches!(
        outer
            .memory_location(outer_capture.destination)
            .expect("outer receiver capture slot")
            .kind,
        MemoryLocationKind::Capture { lexical_parent } if lexical_parent == parent.id()
    ));

    let inner_capture = outer
        .captures()
        .first()
        .expect("outer callable must relay its receiver to the inner callable");
    let CaptureSource::Value(relayed_receiver) = inner_capture.captured else {
        panic!("nested receiver relay must use the outer capture value");
    };
    assert_eq!(
        outer
            .value(relayed_receiver)
            .expect("relayed receiver value")
            .kind,
        SemanticValueKind::Local
    );
    let inner = graph
        .artifact()
        .procedure(inner_capture.target)
        .expect("inner lexical callable procedure");
    assert_eq!(inner.kind(), ProcedureKind::Lambda);
    assert!(matches!(
        inner
            .memory_location(inner_capture.destination)
            .expect("inner receiver capture slot")
            .kind,
        MemoryLocationKind::Capture { lexical_parent } if lexical_parent == outer.id()
    ));
    for (procedure, destination) in [
        (outer, outer_capture.destination),
        (inner, inner_capture.destination),
    ] {
        assert!(
            !procedure.gaps().iter().any(|gap| {
                gap.subject == SemanticGapSubject::MemoryLocation(destination)
                    && gap.capability == SemanticCapability::Captures
            }),
            "a fully relayed receiver capture must remain exact"
        );
    }
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

fn assert_value_flow_oracle(analyzer: &brokk_bifrost::WorkspaceAnalyzer, graph: &SemanticGraph) {
    let oracle = analyzer.semantic_oracle_provider();
    let instance = procedure_handle_named(graph, "instance", ProcedureKind::Method);
    let mut budget = SemanticBudget::default();
    let cancellation = CancellationToken::default();
    let outcome = oracle
        .procedure_relations(
            &instance,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("value-flow snapshot should materialize");
    let snapshot = available(&outcome);
    assert_ne!(
        snapshot.coverage(),
        CandidateCoverage::Truncated,
        "adapter gaps may keep the whole-procedure relation set open, but the bounded query must retain every published row"
    );
    for expected in [
        ValueFlowRelationKind::Assignment,
        ValueFlowRelationKind::Parameter,
        ValueFlowRelationKind::Receiver,
        ValueFlowRelationKind::NormalReturn,
        ValueFlowRelationKind::Allocation,
    ] {
        assert!(
            snapshot
                .relations()
                .iter()
                .any(|relation| relation.kind == expected),
            "instance snapshot must publish {expected:?}"
        );
    }
    assert!(snapshot.relations().iter().any(|relation| matches!(
        (&relation.kind, &relation.source),
        (
            ValueFlowRelationKind::Parameter,
            ValueFlowEndpoint::Port(port)
        ) if port.kind() == ProcedurePortKind::Parameter { ordinal: 0 }
    )));
    assert!(snapshot.relations().iter().any(|relation| matches!(
        (&relation.kind, &relation.source),
        (
            ValueFlowRelationKind::Receiver,
            ValueFlowEndpoint::Port(port)
        ) if port.kind() == ProcedurePortKind::Receiver
    )));
    assert_eq!(
        budget.used(),
        outcome.work(),
        "complete oracle work must be committed exactly once"
    );

    let first = procedure_handle_named(graph, "first", ProcedureKind::Method);
    let mut budget = SemanticBudget::default();
    let first_outcome = oracle
        .procedure_relations(
            &first,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("indexed-load snapshot should materialize");
    assert!(
        available(&first_outcome)
            .relations()
            .iter()
            .any(|relation| {
                matches!(
                    (&relation.kind, &relation.source),
                    (
                        ValueFlowRelationKind::MemoryLoad,
                        ValueFlowEndpoint::Location(location)
                    ) if location.path().is_exact()
                )
            })
    );

    let capture = procedure_handle_named(graph, "capture", ProcedureKind::Method);
    let mut budget = SemanticBudget::default();
    let capture_outcome = oracle
        .procedure_relations(
            &capture,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("capture snapshot should materialize");
    let capture_relation = available(&capture_outcome)
        .relations()
        .iter()
        .find(|relation| {
            matches!(
                (&relation.kind, &relation.target),
                (
                    ValueFlowRelationKind::Capture,
                    ValueFlowEndpoint::Port(port)
                ) if matches!(port.kind(), ProcedurePortKind::Capture { .. })
                    && port.procedure().semantics().lexical_parent() == Some(capture.id())
            )
        })
        .expect("capture source must bind the exact child-procedure capture port")
        .clone();
    let ValueFlowEndpoint::Port(child_capture) = &capture_relation.target else {
        unreachable!("capture relation target was selected above")
    };
    let mut invalid_cross_procedure = capture_relation.clone();
    invalid_cross_procedure.target = ValueFlowEndpoint::Port(ProcedurePortHandle::normal_return(
        child_capture.procedure().clone(),
    ));
    assert_eq!(
        ValueFlowSnapshot::new(
            capture.clone(),
            OracleCallContext::empty(),
            vec![invalid_cross_procedure],
            CandidateCoverage::Open,
            OracleLimits::default(),
        ),
        Err(OracleContractError::CrossProcedure),
        "only an exact parent capture row may cross into its lexical child"
    );

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut budget = SemanticBudget::default();
    assert!(matches!(
        oracle
            .procedure_relations(
                &instance,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancelled),
            )
            .unwrap(),
        SemanticOutcome::Cancelled {
            partial: None,
            work
        } if work == Default::default()
    ));

    let bounded = WorkspaceSemanticOracle::with_limits(analyzer, OracleLimits::uniform(1).unwrap());
    let mut budget = SemanticBudget::default();
    let bounded_outcome = bounded
        .procedure_relations(
            &instance,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("bounded snapshot should retain a prefix");
    assert!(matches!(bounded_outcome, SemanticOutcome::Unproven { .. }));
    assert_eq!(
        available(&bounded_outcome).coverage(),
        CandidateCoverage::Truncated
    );
    assert_eq!(available(&bounded_outcome).relations().len(), 1);
}

fn call_named(
    graph: &SemanticGraph,
    source: &str,
    procedure_name: &str,
    call_source: &str,
) -> brokk_bifrost::analyzer::semantic::CallSiteHandle {
    let procedure = procedure_handle_named(graph, procedure_name, ProcedureKind::Method);
    let call = procedure
        .semantics()
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure.semantics(), source, call.source) == call_source)
        .unwrap_or_else(|| panic!("missing call {call_source:?} in {procedure_name}"));
    procedure
        .call_site_handle(call.id)
        .expect("selected call must have a scoped handle")
}

fn dispatch_candidate_named(
    oracle: &WorkspaceSemanticOracle<'_>,
    call: &brokk_bifrost::analyzer::semantic::CallSiteHandle,
    name: &str,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> DispatchCandidate {
    let dispatch = oracle
        .resolve_call(call, &mut SemanticRequest::new(budget, cancellation))
        .expect("fixture dispatch should run");
    available(&dispatch)
        .candidates()
        .iter()
        .find(|candidate| {
            candidate
                .target()
                .semantics()
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(name)
        })
        .unwrap_or_else(|| panic!("fixture call must retain the local {name} candidate"))
        .clone()
}

fn assert_java_dispatch_closure(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
) {
    for closed in ["consume", "privateTarget", "finalTarget", "target"] {
        assert_eq!(
            procedure_named(graph, closed, ProcedureKind::Method)
                .properties()
                .dispatch_extensibility,
            DispatchExtensibility::Closed,
            "{closed} must publish declaration-backed closed dispatch"
        );
    }
    assert_eq!(
        procedure_named(graph, "sink", ProcedureKind::Method)
            .properties()
            .dispatch_extensibility,
        DispatchExtensibility::Open,
        "ordinary overridable methods must remain open"
    );
    assert_eq!(
        procedure_named(graph, "enumTarget", ProcedureKind::Method)
            .properties()
            .dispatch_extensibility,
        DispatchExtensibility::Open,
        "enum methods remain overridable by constant-specific class bodies"
    );

    let oracle = analyzer.semantic_oracle_provider();
    let cancellation = CancellationToken::default();
    for (procedure, call_source) in [
        ("staticCall", "consume(input)"),
        ("closedCalls", "privateTarget(input)"),
        ("closedCalls", "finalTarget(input)"),
        ("closedCalls", "service.target(input)"),
    ] {
        let call = call_named(graph, source, procedure, call_source);
        let mut budget = SemanticBudget::default();
        let dispatch = oracle
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .unwrap_or_else(|error| panic!("dispatch {call_source:?} failed: {error}"));
        assert_eq!(
            available(&dispatch).coverage(),
            CandidateCoverage::Exhaustive,
            "declaration-closed Java dispatch must be exhaustive for {call_source:?}"
        );
        assert!(
            available(&dispatch).boundaries().is_empty(),
            "closed Java dispatch must not retain a dynamic boundary for {call_source:?}"
        );
    }

    let open_call = call_named(graph, source, "instance", "this.sink(input, made)");
    let mut budget = SemanticBudget::default();
    let open_dispatch = oracle
        .resolve_call(
            &open_call,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("ordinary Java virtual dispatch should materialize");
    assert_eq!(
        available(&open_dispatch).coverage(),
        CandidateCoverage::Open,
        "ordinary Java virtual dispatch must stay open"
    );
}

fn bindings_for_call(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
    procedure_name: &str,
    call_source: &str,
    target_name: &str,
) -> CallBindings {
    let oracle = analyzer.semantic_oracle_provider();
    let call = call_named(graph, source, procedure_name, call_source);
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let candidate =
        dispatch_candidate_named(&oracle, &call, target_name, &mut budget, &cancellation);
    let outcome = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("candidate-specific bindings should materialize");
    available(&outcome).clone()
}

fn assert_call_bindings(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
    expected_coverage: CandidateCoverage,
) {
    let oracle = analyzer.semantic_oracle_provider();
    let call = call_named(graph, source, "instance", "this.sink(input, made)");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let candidate = dispatch_candidate_named(&oracle, &call, "sink", &mut budget, &cancellation);

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SemanticBudget::default();
    assert!(matches!(
        oracle
            .call_bindings(
                &call,
                &candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
            )
            .unwrap(),
        SemanticOutcome::Cancelled {
            partial: None,
            work
        } if work == Default::default()
    ));

    let mut bounded_budget = SemanticBudget::uniform(1).unwrap();
    let bounded = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut bounded_budget, &cancellation),
        )
        .expect("bounded call binding should retain an explicit partial");
    assert!(matches!(
        bounded,
        SemanticOutcome::ExceededBudget {
            partial: Some(_),
            ..
        }
    ));

    let bindings = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("candidate-specific bindings should materialize");
    let bindings = available(&bindings);
    assert_eq!(
        bindings.coverage(),
        expected_coverage,
        "caller gaps: {:?}; callee gaps: {:?}",
        call.procedure().semantics().gaps(),
        candidate.target().semantics().gaps()
    );
    assert!(
        bindings
            .bindings()
            .iter()
            .any(|binding| matches!(binding, CallBinding::Receiver { .. }))
    );
    let groups = bindings
        .bindings()
        .iter()
        .filter_map(|binding| match binding {
            CallBinding::ArgumentGroup(group) => Some(group),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().all(|group| {
        group.coverage() == CandidateCoverage::Exhaustive && group.mappings().len() == 1
    }));
    assert!(
        bindings
            .bindings()
            .iter()
            .any(|binding| matches!(binding, CallBinding::NormalReturn { .. }))
    );
    assert!(
        bindings
            .bindings()
            .iter()
            .any(|binding| matches!(binding, CallBinding::ExceptionalReturn { .. }))
    );
}

fn assert_variadic_and_static_receiver_bindings(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
) {
    let variadic = bindings_for_call(
        analyzer,
        graph,
        source,
        "variadic",
        "this.collect(input, input)",
        "collect",
    );
    assert_ne!(variadic.coverage(), CandidateCoverage::Truncated);
    let groups = variadic
        .bindings()
        .iter()
        .filter_map(|binding| match binding {
            CallBinding::ArgumentGroup(group) => Some(group),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(groups.len(), 2);
    let observed_formals = groups
        .iter()
        .map(|group| {
            group.mappings().first().map(|mapping| {
                let formal = mapping.value().formal();
                (formal.kind(), formal.formal_multiplicity().cloned())
            })
        })
        .collect::<Vec<_>>();
    assert!(
        observed_formals.iter().all(|formal| {
            matches!(
                formal,
                Some((
                    ProcedurePortKind::Parameter { ordinal: 0 },
                    Some(FormalMultiplicity::Rest(
                        ArgumentDomain::Positional | ArgumentDomain::PositionalOrKeyword
                    )),
                ))
            )
        }),
        "variadic bindings mapped to {observed_formals:?}"
    );

    let static_call = bindings_for_call(
        analyzer,
        graph,
        source,
        "staticCall",
        "consume(input)",
        "consume",
    );
    assert_ne!(static_call.coverage(), CandidateCoverage::Truncated);
    assert!(
        static_call
            .bindings()
            .iter()
            .all(|binding| !matches!(binding, CallBinding::Receiver { .. })),
        "a call to a receiverless target must not manufacture a callee receiver binding"
    );
}

fn assert_open_spread_bindings(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
) {
    let oracle = analyzer.semantic_oracle_provider();
    let call = call_named(graph, source, "spread", "this.sink(...values)");
    let call_site = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("scoped call handle must resolve its semantic row");
    assert_eq!(
        call_site.arguments[0].expansion,
        CallArgumentExpansion::Spread(ArgumentDomain::Positional),
        "JavaScript and TypeScript spread syntax expands a positional argument sequence"
    );
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let candidate = dispatch_candidate_named(&oracle, &call, "sink", &mut budget, &cancellation);
    let outcome = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    assert!(matches!(outcome, SemanticOutcome::Unknown { .. }));
    let bindings = available(&outcome);
    assert_eq!(bindings.coverage(), CandidateCoverage::Open);
    let group = bindings
        .bindings()
        .iter()
        .find_map(|binding| match binding {
            CallBinding::ArgumentGroup(group) => Some(group),
            _ => None,
        })
        .expect("spread source must remain visible as an argument group");
    assert_eq!(group.sources(), [0]);
    assert!(group.mappings().is_empty());
    assert_eq!(group.coverage(), CandidateCoverage::Open);
}

fn assert_open_default_bindings(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
) {
    let bindings = bindings_for_call(
        analyzer,
        graph,
        source,
        "defaultCall",
        "this.defaults()",
        "defaults",
    );
    assert_eq!(bindings.coverage(), CandidateCoverage::Open);
    assert!(
        bindings
            .bindings()
            .iter()
            .all(|binding| !matches!(binding, CallBinding::ArgumentGroup(_))),
        "an omitted default must remain an unbound formal until its callee-side value is modeled"
    );
}

fn assert_heap_oracle(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    graph: &SemanticGraph,
    source: &str,
) {
    let oracle = analyzer.semantic_oracle_provider();
    let cancellation = CancellationToken::default();
    let factory = procedure_handle_named(graph, "factory", ProcedureKind::Method);
    let allocation = factory
        .semantics()
        .allocations()
        .first()
        .expect("factory must publish its allocation");
    let allocation_point = factory.point_handle(allocation.point).unwrap();
    let allocation_value = factory.value_handle(allocation.result).unwrap();
    let value_query = ValueAtPoint::new(
        allocation_value.clone(),
        allocation_point.clone(),
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let points_to = oracle
        .pointees(
            &value_query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("allocation points-to query should materialize");
    let objects = available(&points_to).objects();
    assert_eq!(objects.candidates().len(), 1);
    assert!(matches!(
        objects.candidates()[0].value().identity(),
        AbstractObjectIdentity::Allocation(handle) if handle.id() == allocation.id
    ));
    assert_eq!(
        objects.candidates()[0].value().cardinality(),
        ObjectCardinality::Unknown,
        "an acyclic allocation-site identity is not by itself a runtime singleton"
    );
    assert_eq!(budget.used(), points_to.work());

    let instance = procedure_handle_named(graph, "instance", ProcedureKind::Method);
    let (return_point, return_source) = instance
        .semantics()
        .points()
        .iter()
        .find_map(|point| {
            point.events.iter().find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source,
                    ..
                } => Some((point.id, source)),
                _ => None,
            })
        })
        .expect("instance fixture must publish its return transfer");
    let returned_value = ValueAtPoint::new(
        instance.value_handle(return_source).unwrap(),
        instance.point_handle(return_point).unwrap(),
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let returned_points_to = oracle
        .pointees(
            &returned_value,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("transitive return points-to query should materialize");
    assert!(
        available(&returned_points_to)
            .objects()
            .candidates()
            .iter()
            .any(|candidate| matches!(
                candidate.value().identity(),
                AbstractObjectIdentity::Allocation(_)
            )),
        "the default summary depth must reach through the return read and local binding"
    );

    let shallow_limits = OracleLimits::new(OracleLimitValues {
        summary_depth: 1,
        ..OracleLimits::default().values()
    })
    .unwrap();
    let shallow_oracle = WorkspaceSemanticOracle::with_limits(analyzer, shallow_limits);
    let mut shallow_budget = SemanticBudget::default();
    let shallow_points_to = shallow_oracle
        .pointees(
            &returned_value,
            &mut SemanticRequest::new(&mut shallow_budget, &cancellation),
        )
        .expect("depth-bounded return points-to query should retain a typed partial");
    assert_eq!(
        available(&shallow_points_to).objects().coverage(),
        CandidateCoverage::Truncated,
        "omitting the allocation behind a deeper producer chain must be explicit"
    );
    assert!(
        available(&shallow_points_to)
            .objects()
            .candidates()
            .is_empty(),
        "a depth cap must not replace an omitted producer with a fabricated symbolic object"
    );
    assert_eq!(
        shallow_budget.used(),
        shallow_points_to.work(),
        "a depth-truncated query must commit exactly the states it actually visited"
    );

    let path = AccessPath::exact(
        AccessPathRoot::Value(allocation_value),
        Vec::new(),
        OracleLimits::default(),
    )
    .unwrap();
    let access = AccessPathAtPoint::new(
        path,
        allocation_point,
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let locations = oracle
        .locations(
            &access,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("allocation location query should materialize");
    assert!(matches!(
        available(&locations).locations().candidates()[0]
            .value()
            .path()
            .root(),
        AccessPathRoot::Allocation(_)
    ));

    let before_allocation = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Allocation(factory.allocation_handle(allocation.id).unwrap()),
            Vec::new(),
            OracleLimits::default(),
        )
        .unwrap(),
        factory.point_handle(allocation.point).unwrap(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let before_locations = oracle
        .locations(
            &before_allocation,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("pre-allocation location query should remain explicit");
    assert!(matches!(before_locations, SemanticOutcome::Unknown { .. }));
    assert!(
        available(&before_locations)
            .locations()
            .candidates()
            .is_empty()
    );

    let query = AliasQuery::new(access.clone(), access).unwrap();
    let mut budget = SemanticBudget::default();
    let alias = oracle
        .alias(
            &query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("reflexive alias query should materialize");
    assert_eq!(
        *available(&alias).answer().value(),
        AliasRelation::MustAlias
    );

    let loop_method = procedure_handle_named(graph, "looping", ProcedureKind::Method);
    let loop_allocation = loop_method
        .semantics()
        .allocations()
        .first()
        .expect("loop fixture must publish an allocation");
    let loop_query = ValueAtPoint::new(
        loop_method.value_handle(loop_allocation.result).unwrap(),
        loop_method.point_handle(loop_allocation.point).unwrap(),
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let loop_points_to = oracle
        .pointees(
            &loop_query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("loop allocation points-to query should materialize");
    assert_eq!(
        available(&loop_points_to).objects().candidates()[0]
            .value()
            .cardinality(),
        ObjectCardinality::Summary,
        "one allocation handle in a CFG cycle must summarize repeated runtime objects"
    );

    let recursive = procedure_handle_named(graph, "recursive", ProcedureKind::Method);
    let recursive_allocation = recursive.semantics().allocations().first().unwrap();
    let recursive_call = recursive
        .semantics()
        .call_sites()
        .iter()
        .find(|call| {
            mapped_source(recursive.semantics(), source, call.source).contains("recursive")
        })
        .and_then(|call| recursive.call_site_handle(call.id))
        .expect("recursive fixture must retain its self-call context");
    let recursive_query = ValueAtPoint::new(
        recursive.value_handle(recursive_allocation.result).unwrap(),
        recursive.point_handle(recursive_allocation.point).unwrap(),
        ObservationPhase::AfterEffects,
        OracleCallContext::bounded(vec![recursive_call], OracleLimits::default()),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let recursive_points_to = oracle
        .pointees(
            &recursive_query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("recursive allocation points-to query should materialize");
    assert_eq!(
        available(&recursive_points_to).objects().candidates()[0]
            .value()
            .cardinality(),
        ObjectCardinality::Summary,
        "a recursive call context must not treat one allocation handle as a singleton"
    );

    let branch = procedure_handle_named(graph, "branch", ProcedureKind::Method);
    let (branch_point, branch_source) = branch
        .semantics()
        .points()
        .iter()
        .find_map(|point| {
            point.events.iter().find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source,
                    ..
                } => Some((point.id, source)),
                _ => None,
            })
        })
        .expect("branch fixture must publish its return transfer");
    let branch_query = ValueAtPoint::new(
        branch.value_handle(branch_source).unwrap(),
        branch.point_handle(branch_point).unwrap(),
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let branch_points_to = oracle
        .pointees(
            &branch_query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("branch join points-to query should materialize");
    let branch_objects = available(&branch_points_to).objects();
    assert_eq!(
        branch_objects.candidates().len(),
        2,
        "both branch-reaching definitions must survive the point-sensitive join"
    );
    assert!(branch_objects.candidates().iter().any(|candidate| matches!(
        candidate.value().identity(),
        AbstractObjectIdentity::Allocation(_)
    )));
    assert!(branch_objects.candidates().iter().any(|candidate| matches!(
        candidate.value().identity(),
        AbstractObjectIdentity::ProcedurePort(_)
    )));
    let candidate_limits = OracleLimits::new(OracleLimitValues {
        objects_per_value: 1,
        ..OracleLimits::default().values()
    })
    .unwrap();
    let bounded = WorkspaceSemanticOracle::with_limits(analyzer, candidate_limits);
    let mut budget = SemanticBudget::default();
    let bounded_branch = bounded
        .pointees(
            &branch_query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("bounded branch query should retain a prefix");
    assert_eq!(
        available(&bounded_branch).objects().coverage(),
        CandidateCoverage::Truncated
    );
    assert_eq!(available(&bounded_branch).objects().candidates().len(), 1);

    let two = procedure_handle_named(graph, "two", ProcedureKind::Method);
    let two_point = two
        .semantics()
        .points()
        .last()
        .expect("two-allocation fixture must have an exit point")
        .id;
    let allocations = two.semantics().allocations();
    assert_eq!(allocations.len(), 2);
    let at_exit = |allocation: &brokk_bifrost::analyzer::semantic::AllocationSite| {
        AccessPathAtPoint::new(
            AccessPath::exact(
                AccessPathRoot::Value(two.value_handle(allocation.result).unwrap()),
                Vec::new(),
                OracleLimits::default(),
            )
            .unwrap(),
            two.point_handle(two_point).unwrap(),
            ObservationPhase::AfterEffects,
            OracleCallContext::empty(),
        )
        .unwrap()
    };
    let disjoint_query =
        AliasQuery::new(at_exit(&allocations[0]), at_exit(&allocations[1])).unwrap();
    let mut budget = SemanticBudget::default();
    let disjoint = oracle
        .alias(
            &disjoint_query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("distinct allocation-site alias query should materialize");
    assert_eq!(
        *available(&disjoint).answer().value(),
        AliasRelation::Disjoint,
        "distinct allocation sites should remain disjoint; allocations: {allocations:?}; calls: {:?}; procedure gaps: {:?}",
        two.semantics().call_sites(),
        two.semantics().gaps(),
    );
    let bounded_alias_oracle =
        WorkspaceSemanticOracle::with_limits(analyzer, OracleLimits::uniform(1).unwrap());
    let mut budget = SemanticBudget::default();
    assert!(matches!(
        bounded_alias_oracle
            .alias(
                &disjoint_query,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("bounded alias query must return a typed partial"),
        SemanticOutcome::Unproven { .. }
    ));

    let capture_parent = procedure_named(graph, "capture", ProcedureKind::Method);
    let capture = capture_parent.captures().first().unwrap();
    let capture_child = graph
        .artifact()
        .procedure_handle(capture.target)
        .expect("capture child must have a scoped handle");
    let capture_port = ProcedurePortHandle::capture(capture_child.clone(), capture.destination)
        .expect("capture row must define a child slot");
    let capture_point = capture_child
        .point_handle(capture_child.semantics().entry_point())
        .unwrap();
    let capture_access = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::CaptureSlot(capture_port),
            Vec::new(),
            OracleLimits::default(),
        )
        .unwrap(),
        capture_point,
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let capture_locations = oracle
        .locations(
            &capture_access,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("capture-slot location query should materialize");
    assert!(matches!(
        available(&capture_locations).locations().candidates()[0]
            .value()
            .object()
            .identity(),
        AbstractObjectIdentity::CaptureSlot(_)
    ));

    let field_reader = procedure_handle_named(graph, "readField", ProcedureKind::Method);
    let (field_point, field_location) = field_reader
        .semantics()
        .points()
        .iter()
        .find_map(|point| {
            point.events.iter().find_map(|event| match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    location,
                    ..
                } => Some((point.id, location)),
                _ => None,
            })
        })
        .expect("field reader must publish a structured field load");
    let MemoryLocationKind::Field { base, ref member } = field_reader
        .semantics()
        .memory_location(field_location)
        .unwrap()
        .kind
    else {
        unreachable!("field load selected above")
    };
    let scoped_member = ScopedSemanticLocator::new(
        std::sync::Arc::clone(field_reader.artifact()),
        member.clone(),
    )
    .unwrap();
    let field_access = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Value(field_reader.value_handle(base).unwrap()),
            vec![AccessSelector::Field(scoped_member.clone())],
            OracleLimits::default(),
        )
        .unwrap(),
        field_reader.point_handle(field_point).unwrap(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let field_locations = oracle
        .locations(
            &field_access,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("field location query should materialize");
    let field_location = available(&field_locations).locations().candidates()[0].value();
    assert!(matches!(
        field_location.object().identity(),
        AbstractObjectIdentity::ProcedurePort(_)
    ));
    assert!(matches!(
        field_location.path().selectors(),
        [AccessSelector::Field(_)]
    ));
    let static_access = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Static(scoped_member),
            Vec::new(),
            OracleLimits::default(),
        )
        .unwrap(),
        field_reader.point_handle(field_point).unwrap(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let static_locations = oracle
        .locations(
            &static_access,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("static-root location query should materialize");
    assert!(matches!(
        available(&static_locations).locations().candidates()[0]
            .value()
            .object()
            .identity(),
        AbstractObjectIdentity::Static(_)
    ));
    let field_writer = procedure_named(graph, "writeField", ProcedureKind::Method);
    assert!(
        field_writer
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    ..
                }
            ))
    );

    let rewrite = procedure_handle_named(graph, "rewrite", ProcedureKind::Method);
    let (store_point, store_index, location_id, stored_id) = rewrite
        .semantics()
        .points()
        .iter()
        .find_map(|point| {
            point
                .events
                .iter()
                .enumerate()
                .find_map(|(index, event)| match event.effect {
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => Some((point.id, index, location, value)),
                    _ => None,
                })
        })
        .expect("rewrite must publish its indexed store");
    let location = rewrite.semantics().memory_location(location_id).unwrap();
    let MemoryLocationKind::Index {
        base,
        index: Some(index),
    } = location.kind
    else {
        panic!("rewrite store must retain its exact base and index")
    };
    let point = rewrite.point_handle(store_point).unwrap();
    let base = ValueAtPoint::new(
        rewrite.value_handle(base).unwrap(),
        point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let target = AccessPathAtPoint::new(
        AccessPath::exact(
            AccessPathRoot::Value(base.value().clone()),
            vec![AccessSelector::Index(IndexSelector::Exact(
                rewrite.value_handle(index).unwrap(),
            ))],
            OracleLimits::default(),
        )
        .unwrap(),
        point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let stored = ValueAtPoint::new(
        rewrite.value_handle(stored_id).unwrap(),
        point.clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let store = StoreAtPoint::new(
        MemoryStoreHandle::new(point.clone(), store_index).unwrap(),
        target.clone(),
        stored,
        Some(base),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let eligibility = oracle
        .update_eligibility(
            &store,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("indexed store update query should materialize");
    let UpdateEligibility::Weak(reasons) = available(&eligibility) else {
        panic!("parameter-rooted indexed stores cannot justify a strong update")
    };
    assert!(
        reasons.contains(&WeakUpdateReason::UnknownObjectCardinality)
            || reasons.contains(&WeakUpdateReason::SummaryPath)
            || reasons.contains(&WeakUpdateReason::EscapingObject)
    );
    let bounded_update_oracle =
        WorkspaceSemanticOracle::with_limits(analyzer, OracleLimits::uniform(1).unwrap());
    let mut budget = SemanticBudget::default();
    assert!(matches!(
        bounded_update_oracle
            .update_eligibility(
                &store,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("bounded update query must return typed weak reasons"),
        SemanticOutcome::Unproven { .. }
    ));

    let wildcard = AccessPathAtPoint::new(
        AccessPath::bounded(
            target.path().root().clone(),
            vec![AccessSelector::Index(IndexSelector::Any)],
            AccessPathTail::Exact,
            OracleLimits::default(),
        )
        .unwrap(),
        point,
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let mut budget = SemanticBudget::default();
    let wildcard_locations = oracle
        .locations(
            &wildcard,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("wildcard index location query should materialize");
    assert!(
        available(&wildcard_locations)
            .locations()
            .candidates()
            .iter()
            .all(|candidate| !candidate.value().path().is_exact()),
        "wildcard selectors must preserve a summary path tail"
    );
    let deep = AccessPathAtPoint::new(
        AccessPath::exact(
            target.path().root().clone(),
            vec![
                AccessSelector::Index(IndexSelector::Exact(rewrite.value_handle(index).unwrap())),
                AccessSelector::Index(IndexSelector::Exact(rewrite.value_handle(index).unwrap())),
            ],
            OracleLimits::default(),
        )
        .unwrap(),
        target.point().clone(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let shallow_limits = OracleLimits::new(brokk_bifrost::analyzer::semantic::OracleLimitValues {
        access_path_length: 1,
        ..OracleLimits::default().values()
    })
    .unwrap();
    let shallow = WorkspaceSemanticOracle::with_limits(analyzer, shallow_limits);
    let mut budget = SemanticBudget::default();
    let shallow_locations = shallow
        .locations(&deep, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("depth-capped location query should materialize");
    let shallow_path = available(&shallow_locations).locations().candidates()[0]
        .value()
        .path();
    assert_eq!(shallow_path.selectors().len(), 1);
    assert_eq!(shallow_path.tail(), AccessPathTail::Summary);

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut budget = SemanticBudget::default();
    assert!(matches!(
        oracle
            .pointees(
                &value_query,
                &mut SemanticRequest::new(&mut budget, &cancelled),
            )
            .unwrap(),
        SemanticOutcome::Cancelled {
            partial: None,
            work
        } if work == Default::default()
    ));

    let mut budget = SemanticBudget::uniform(1).unwrap();
    assert!(matches!(
        oracle
            .pointees(
                &value_query,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap(),
        SemanticOutcome::ExceededBudget {
            partial: Some(_),
            ..
        }
    ));

    let branch = procedure_named(graph, "branch", ProcedureKind::Method);
    assert!(
        branch.allocations().iter().any(|allocation| mapped_source(
            branch,
            source,
            allocation.source
        )
        .contains("new Box")),
        "heap fixture must retain its branch allocation"
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
    spread(values: Box[]) { this.sink(...values); }
    collect(...values: Box[]) {}
    variadic(input: Box) { this.collect(input, input); }
    defaults(input: Box = new Box()) {}
    defaultCall() { this.defaults(); }
    looping(flag: boolean) { while (flag) { new Box(); flag = false; } }
    recursive(flag: boolean): Box { const made = new Box(); if (flag) return this.recursive(false); return made; }
    two() { const first = new Box(); const second = new Box(); return first; }
    readField(box: Box) { return box.value; }
    writeField(box: Box, replacement: Box) { box.value = replacement; }
    static staticCall(input: Box) { consume(input); return input; }
}

function consume(input: Box) {}
"#;
    const JAVA: &str = r#"class Box {}
final class FinalService { Object target(Object input) { return input; } }
enum ExtensibleEnum { INSTANCE; Object enumTarget(Object input) { return input; } }
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
    void collect(Object... values) {}
    void variadic(Object input) { this.collect(input, input); }
    static void consume(Object input) {}
    private Object privateTarget(Object input) { return input; }
    final Object finalTarget(Object input) { return input; }
    Object closedCalls(FinalService service, Object input) {
        privateTarget(input);
        finalTarget(input);
        return service.target(input);
    }
    void looping(boolean flag) { while (flag) { new Box(); flag = false; } }
    Object recursive(boolean flag) { Object made = new Box(); if (flag) return this.recursive(false); return made; }
    Object two() { Object first = new Box(); Object second = new Box(); return first; }
    Object readField(Box box) { return box.value; }
    void writeField(Box box, Object replacement) { box.value = replacement; }
    static Object staticCall(Object input) { consume(input); return input; }
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
    assert_value_flow_oracle(&analyzer, &typescript);
    assert_value_flow_oracle(&analyzer, &java);
    assert_call_bindings(&analyzer, &typescript, TYPESCRIPT, CandidateCoverage::Open);
    assert_call_bindings(&analyzer, &java, JAVA, CandidateCoverage::Open);
    assert_variadic_and_static_receiver_bindings(&analyzer, &typescript, TYPESCRIPT);
    assert_variadic_and_static_receiver_bindings(&analyzer, &java, JAVA);
    assert_java_dispatch_closure(&analyzer, &java, JAVA);
    assert_open_spread_bindings(&analyzer, &typescript, TYPESCRIPT);
    assert_open_default_bindings(&analyzer, &typescript, TYPESCRIPT);
    assert_heap_oracle(&analyzer, &typescript, TYPESCRIPT);
    assert_heap_oracle(&analyzer, &java, JAVA);

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

#[test]
fn source_points_to_preserves_path_specialized_finally_observations() {
    const SOURCE: &str = r#"class Service { void run() {} }
class Sample {
    void caller(Service service, boolean fail) {
        try {
            if (fail) throw new RuntimeException();
            return;
        } finally {
            service.run();
        }
    }
}
"#;
    let project = InlineTestProject::new()
        .file("Specialized.java", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("Specialized.java");
    let start_byte = SOURCE.rfind("service.run").expect("finally receiver");
    let start_line = SOURCE[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let range = brokk_bifrost::analyzer::Range {
        start_byte,
        end_byte: start_byte + "service".len(),
        start_line,
        end_line: start_line,
    };
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .semantic_oracle_provider()
        .pointees_at_source(
            &file,
            range,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("source points-to query");
    let points_to = available(&outcome);
    assert!(
        points_to.observations().len() >= 2,
        "the duplicated finally body must retain every point-specialized observation: {outcome:#?}"
    );
    let point_ids = points_to
        .observations()
        .iter()
        .map(|result| result.query().point().id())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(point_ids.len(), points_to.observations().len());
    assert!(
        points_to
            .observations()
            .windows(2)
            .all(|pair| pair[0].query().value().id() == pair[1].query().value().id()),
        "path specialization should retain one static value at distinct program points"
    );
    assert!(
        points_to
            .observations()
            .iter()
            .all(|result| result.query().context().calls().is_empty()),
        "source observations start context-free; a zero receiver context depth retains no calls"
    );

    let limits = OracleLimits::new(OracleLimitValues {
        alias_breadth: 8,
        source_observations: 1,
        ..OracleLimits::default().values()
    })
    .unwrap();
    let bounded = WorkspaceSemanticOracle::with_limits(&analyzer, limits);
    let mut budget = SemanticBudget::default();
    let bounded_outcome = bounded
        .pointees_at_source(
            &file,
            range,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("bounded source points-to query");
    let bounded_points_to = available(&bounded_outcome);
    assert_eq!(bounded_points_to.observations().len(), 1);
    assert_eq!(bounded_points_to.coverage(), CandidateCoverage::Truncated);
    assert!(matches!(bounded_outcome, SemanticOutcome::Unproven { .. }));
}

#[test]
fn source_points_to_projection_is_pre_cancellable_and_budget_staged() {
    let mut source = String::from(
        "class Service { void run() {} }\nclass Sample { void caller(Service service) {\n",
    );
    for index in 0..128 {
        source.push_str(&format!("Object local{index} = new Object();\n"));
    }
    source.push_str("service.run();\n}\n}\n");
    let start_byte = source.rfind("service.run").expect("receiver call");
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let range = brokk_bifrost::analyzer::Range {
        start_byte,
        end_byte: start_byte + "service".len(),
        start_line,
        end_line: start_line,
    };
    let project = InlineTestProject::new()
        .file("LargeProjection.java", source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("LargeProjection.java");
    let oracle = analyzer.semantic_oracle_provider();

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SemanticBudget::default();
    let cancelled_outcome = oracle
        .pointees_at_source(
            &file,
            range,
            &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
        )
        .expect("pre-cancellation is a semantic outcome");
    assert!(matches!(
        cancelled_outcome,
        SemanticOutcome::Cancelled {
            partial: None,
            work,
        } if work == Default::default()
    ));
    assert_eq!(cancelled_budget.used(), Default::default());

    let cancellation = CancellationToken::default();
    let mut materialization_budget = SemanticBudget::default();
    let materialized = analyzer
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
        )
        .expect("large fixture materialization");
    assert!(materialized.available_value().is_some());
    let materialization_work = materialization_budget.used();

    let mut limits = SemanticBudget::default().limits();
    limits.values = materialization_work.values + 4;
    let mut projection_budget = SemanticBudget::new(limits).unwrap();
    let outcome = oracle
        .pointees_at_source(
            &file,
            range,
            &mut SemanticRequest::new(&mut projection_budget, &cancellation),
        )
        .expect("projection exhaustion is a semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        } if exceeded.dimension() == SemanticBudgetDimension::Values
            && exceeded.limit() == materialization_work.values + 4
            && exceeded.attempted() == materialization_work.values + 5
            && work.values == materialization_work.values + 5
    ));
    assert_eq!(
        projection_budget.used(),
        materialization_work,
        "failed projection work must not be committed to the caller budget"
    );

    let mut limits = SemanticBudget::default().limits();
    limits.nested_entries = materialization_work.nested_entries + 1;
    let mut nested_entry_budget = SemanticBudget::new(limits).unwrap();
    let outcome = oracle
        .pointees_at_source(
            &file,
            range,
            &mut SemanticRequest::new(&mut nested_entry_budget, &cancellation),
        )
        .expect("candidate traversal exhaustion is a semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        } if exceeded.dimension() == SemanticBudgetDimension::NestedEntries
            && exceeded.limit() == materialization_work.nested_entries + 1
            && exceeded.attempted() == materialization_work.nested_entries + 2
            && work.nested_entries == materialization_work.nested_entries + 2
    ));
    assert_eq!(
        nested_entry_budget.used(),
        materialization_work,
        "failed candidate traversal work must remain staged"
    );
}

#[test]
fn logical_assignment_arrow_without_parent_binding_retains_an_explicit_capture_gap() {
    let project = InlineTestProject::new()
        .file(
            "event.ts",
            "class Event { private listener?: () => void; get event() { this.listener ??= () => this.fire(); return this.listener; } fire() {} }\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "event.ts");
    let lambda = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| procedure.kind() == ProcedureKind::Lambda)
        .expect("logical-assignment arrow procedure");
    let capture = lambda
        .memory_locations()
        .iter()
        .find(|location| matches!(location.kind, MemoryLocationKind::Capture { .. }))
        .expect("lexical receiver capture slot");
    assert!(lambda.gaps().iter().any(|gap| {
        gap.subject == SemanticGapSubject::MemoryLocation(capture.id)
            && gap.capability == SemanticCapability::Captures
    }));

    let lambda = graph
        .artifact()
        .procedure_handle(lambda.id())
        .expect("logical-assignment arrow procedure handle");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .semantic_oracle_provider()
        .procedure_relations(
            &lambda,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("capture-gapped value-flow snapshot");
    assert_eq!(
        available(&outcome).coverage(),
        CandidateCoverage::Open,
        "an explicit capture gap must keep downstream value flow open"
    );
}

#[test]
fn traced_call_gap_keeps_a_dependent_heap_value_open() {
    const SOURCE: &str = r#"
class Sample {
    consume(_value: Sample) {}
    forward(input: Sample): Sample { this.consume(input); return input; }
}
"#;
    let project = InlineTestProject::new().file("forward.ts", SOURCE).build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "forward.ts");
    let call = call_named(&graph, SOURCE, "forward", "this.consume(input)");
    let call_row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("forwarding call row");
    assert!(call.procedure().semantics().gaps().iter().any(|gap| {
        gap.subject == SemanticGapSubject::CallSite(call.id())
            && gap.capability == SemanticCapability::Calls
            && gap.impacts.contains(SemanticGapImpact::Aliasing)
    }));

    let argument = call_row.arguments[0].value;
    let parameter = flow_source(
        call.procedure().semantics(),
        argument,
        ValueFlowKind::Parameter,
    );
    assert!(matches!(
        call.procedure().semantics().value(parameter).unwrap().kind,
        SemanticValueKind::Parameter { ordinal: 0, .. }
    ));
    let continuation = call_row
        .normal_continuation
        .target()
        .expect("forwarding call normal continuation");
    let query = ValueAtPoint::new(
        call.procedure().value_handle(argument).unwrap(),
        call.procedure().point_handle(continuation).unwrap(),
        ObservationPhase::BeforeEffects,
        OracleCallContext::empty(),
    )
    .unwrap();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .semantic_oracle_provider()
        .pointees(
            &query,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("call-dependent parameter points-to query");
    assert_eq!(
        available(&outcome).objects().coverage(),
        CandidateCoverage::Open,
        "a call gap reached by the parameter trace must keep the heap result open"
    );
}

#[test]
fn nested_lexical_callables_relay_receiver_captures() {
    const TYPESCRIPT: &str = r#"
class Capture {
    nestedCapture() { return () => { return () => this; }; }
}
"#;
    const JAVA: &str = r#"
class Capture {
    java.util.function.Supplier<java.util.function.Supplier<Object>> nestedCapture() {
        return () -> { return () -> this; };
    }
}
"#;
    let project = InlineTestProject::new()
        .file("nested/Capture.ts", TYPESCRIPT)
        .file("nested/Capture.java", JAVA)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let typescript = SemanticGraph::materialize(&project, &analyzer, "nested/Capture.ts");
    let java = SemanticGraph::materialize(&project, &analyzer, "nested/Capture.java");

    assert_nested_receiver_capture_relay(&typescript);
    assert_nested_receiver_capture_relay(&java);
}

#[test]
fn javascript_typescript_class_initializers_own_receivers() {
    const SOURCE: &str = r#"
class Host {
    Base = class {};
    key = "member";

    makeNested() {
        class Nested extends this.Base {
            [this.key] = this;
            instanceDirect = this;
            instanceArrow = () => this;
            parameterArrow = (value) => value;
            static staticDirect = this;
            static staticArrow = () => this;
            [(() => this.key)()]() {}
            static {
                const staticBlockDirect = this;
                const staticBlockArrow = () => this;
                const staticBlockHelper = (value) => value;
            }
        }
        return Nested;
    }
}
"#;
    let project = InlineTestProject::new()
        .file("initializers/receivers.js", SOURCE)
        .file("initializers/receivers.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());

    for path in ["initializers/receivers.js", "initializers/receivers.ts"] {
        let graph = SemanticGraph::materialize(&project, &analyzer, path);
        let procedures = graph.artifact().procedures();
        let procedure_source = |procedure: &ProcedureSemantics| {
            let span = procedure.locator().anchor().span();
            SOURCE
                .get(span.start_byte() as usize..span.end_byte() as usize)
                .expect("procedure locator must remain inside the shared fixture")
        };
        let initializer = |source_fragment: &str| {
            procedures
                .iter()
                .find(|procedure| {
                    procedure.kind() == ProcedureKind::Initializer
                        && procedure_source(procedure).contains(source_fragment)
                })
                .unwrap_or_else(|| panic!("{path} missing initializer for {source_fragment:?}"))
        };
        let receiver = |procedure: &ProcedureSemantics| {
            procedure
                .values()
                .iter()
                .find(|value| value.kind == SemanticValueKind::Receiver)
                .map(|value| value.id)
                .unwrap_or_else(|| {
                    panic!(
                        "{path} initializer {:?} should own a receiver",
                        procedure.locator().declaration()
                    )
                })
        };
        let receiver_flow_count = |procedure: &ProcedureSemantics| {
            let receiver = receiver(procedure);
            procedure
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .filter(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Receiver,
                            source,
                            ..
                        } if source == receiver
                    )
                })
                .count()
        };
        let assert_receiver_capture = |procedure: &ProcedureSemantics| {
            let receiver = receiver(procedure);
            let capture = procedure.captures().first().unwrap_or_else(|| {
                panic!(
                    "{path} initializer {:?} should bind its arrow receiver",
                    procedure.locator().declaration()
                )
            });
            assert_eq!(procedure.captures().len(), 1);
            assert_eq!(capture.captured, CaptureSource::Value(receiver));
            let lambda = graph
                .artifact()
                .procedure(capture.target)
                .expect("initializer capture target should be materialized");
            assert_eq!(lambda.kind(), ProcedureKind::Lambda);
            assert_eq!(lambda.lexical_parent(), Some(procedure.id()));
            assert!(matches!(
                lambda
                    .memory_location(capture.destination)
                    .expect("lambda receiver capture slot")
                    .kind,
                MemoryLocationKind::Capture { lexical_parent }
                    if lexical_parent == procedure.id()
            ));
            assert!(
                !lambda.gaps().iter().any(|gap| {
                    gap.subject == SemanticGapSubject::MemoryLocation(capture.destination)
                        && gap.capability == SemanticCapability::Captures
                }),
                "{path} initializer-owned receiver capture should remain exact"
            );
        };

        for source_fragment in [
            "[this.key] = this",
            "instanceDirect = this",
            "static staticDirect = this",
        ] {
            assert_eq!(
                receiver_flow_count(initializer(source_fragment)),
                1,
                "{path} direct field `this` should flow only from the initializer receiver"
            );
        }
        for source_fragment in [
            "instanceArrow = () => this",
            "static staticArrow = () => this",
        ] {
            assert_receiver_capture(initializer(source_fragment));
        }

        let static_block = initializer("const staticBlockDirect = this");
        assert!(static_block.properties().is_static);
        assert_eq!(receiver_flow_count(static_block), 1);
        assert_receiver_capture(static_block);
        assert!(
            static_block
                .values()
                .iter()
                .all(|value| !matches!(value.kind, SemanticValueKind::Parameter { .. })),
            "{path} static-block initializer must not absorb nested lambda parameters"
        );
        assert!(!initializer("instanceDirect = this").properties().is_static);
        assert!(
            initializer("static staticDirect = this")
                .properties()
                .is_static
        );

        let parameter_initializer = initializer("parameterArrow = (value) => value");
        assert!(
            parameter_initializer
                .values()
                .iter()
                .all(|value| !matches!(value.kind, SemanticValueKind::Parameter { .. })),
            "{path} field initializer must not absorb nested lambda parameters"
        );
        let parameter_lambdas = procedures
            .iter()
            .filter(|procedure| {
                procedure.kind() == ProcedureKind::Lambda
                    && procedure_source(procedure).contains("(value) => value")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            parameter_lambdas.len(),
            2,
            "{path} should materialize field and static-block helper lambdas"
        );
        for lambda in parameter_lambdas {
            let parameters = lambda
                .values()
                .iter()
                .filter(|value| matches!(value.kind, SemanticValueKind::Parameter { .. }))
                .count();
            assert_eq!(
                parameters, 1,
                "{path} lambda should retain its own parameter"
            );
        }

        let outer = procedure_named(&graph, "makeNested", ProcedureKind::Method);
        let outer_receiver = outer
            .values()
            .iter()
            .find(|value| value.kind == SemanticValueKind::Receiver)
            .expect("outer instance method receiver");
        let outer_receiver_flows = outer
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Receiver,
                        source,
                        ..
                    } if source == outer_receiver.id
                )
            })
            .count();
        assert_eq!(
            outer_receiver_flows, 2,
            "{path} outer method should evaluate only heritage and the direct computed field name"
        );
        let computed_name_capture = outer
            .captures()
            .first()
            .expect("computed method-name arrow should capture the outer receiver");
        assert_eq!(outer.captures().len(), 1);
        assert_eq!(
            computed_name_capture.captured,
            CaptureSource::Value(outer_receiver.id)
        );
        let computed_name_lambda = graph
            .artifact()
            .procedure(computed_name_capture.target)
            .expect("computed method-name arrow procedure");
        assert_eq!(computed_name_lambda.lexical_parent(), Some(outer.id()));
        assert!(
            procedure_source(computed_name_lambda).contains("() => this.key"),
            "{path} computed-name arrow must stay in the surrounding class-definition context"
        );
    }
}

#[test]
fn nested_type_execution_does_not_leak_receiver_or_local_facts() {
    const TYPESCRIPT: &str = r#"
class Boundary {
    key = "computed";
    Base = class {};
    nestedType() {
        return () => class Nested {
            field = this;
            static { var hidden = this; }
        };
    }
    heritage() {
        return () => class Nested extends this.Base {
            field = this;
        };
    }
    computedMethodName() {
        return () => class Nested {
            [this.key]() {}
        };
    }
}
"#;
    const JAVASCRIPT: &str = r#"
class Boundary {
    key = "computed";
    Base = class {};
    nestedType() {
        return () => class Nested {
            field = this;
            static { var hidden = this; }
        };
    }
    heritage() {
        return () => class Nested extends this.Base {
            field = this;
        };
    }
    computedMethodName() {
        return () => class Nested {
            [this.key]() {}
        };
    }
}
"#;
    const JAVA: &str = r#"
class Boundary {
    java.util.function.Supplier<Object> nestedType() {
        return () -> new Object() {
            Object hidden = this;
        };
    }
}
"#;
    let project = InlineTestProject::new()
        .file("nested/Boundary.ts", TYPESCRIPT)
        .file("nested/Boundary.js", JAVASCRIPT)
        .file("nested/Boundary.java", JAVA)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let typescript = SemanticGraph::materialize(&project, &analyzer, "nested/Boundary.ts");
    let javascript = SemanticGraph::materialize(&project, &analyzer, "nested/Boundary.js");
    let java = SemanticGraph::materialize(&project, &analyzer, "nested/Boundary.java");

    for (graph, source) in [
        (&typescript, TYPESCRIPT),
        (&javascript, JAVASCRIPT),
        (&java, JAVA),
    ] {
        let method = procedure_named(graph, "nestedType", ProcedureKind::Method);
        assert!(
            method.captures().is_empty(),
            "a nested type's receiver must not create an outer capture binding"
        );
        let lambda = graph
            .artifact()
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == ProcedureKind::Lambda
                    && procedure.lexical_parent() == Some(method.id())
            })
            .expect("nestedType lambda");
        assert!(
            lambda
                .memory_locations()
                .iter()
                .all(|location| !matches!(location.kind, MemoryLocationKind::Capture { .. })),
            "a lambda that only constructs a nested type must not capture the outer receiver"
        );
        assert!(
            lambda.values().iter().all(|value| {
                value.kind != SemanticValueKind::Local
                    || mapped_source(lambda, source, value.source) != "hidden"
            }),
            "nested type locals must not be indexed in the enclosing lambda"
        );
    }

    assert!(
        java.artifact().procedures().iter().any(|procedure| {
            procedure.kind() == ProcedureKind::Initializer
                && procedure
                    .values()
                    .iter()
                    .any(|value| value.kind == SemanticValueKind::Receiver)
        }),
        "the anonymous Java field initializer must own its receiver"
    );
    for (graph, source) in [(&typescript, TYPESCRIPT), (&javascript, JAVASCRIPT)] {
        assert!(
            graph.artifact().procedures().iter().any(|procedure| {
                procedure.kind() == ProcedureKind::Initializer
                    && procedure.values().iter().any(|value| {
                        value.kind == SemanticValueKind::Local
                            && mapped_source(procedure, source, value.source) == "hidden"
                    })
            }),
            "the JS/TS class static initializer must own its var-scoped local"
        );
        assert!(
            !procedure_named(graph, "heritage", ProcedureKind::Method)
                .captures()
                .is_empty(),
            "class heritage expressions must retain the enclosing lexical receiver"
        );
        assert!(
            !procedure_named(graph, "computedMethodName", ProcedureKind::Method)
                .captures()
                .is_empty(),
            "computed method names must retain the enclosing lexical receiver"
        );
    }
}

#[test]
fn local_binding_preindex_uses_source_preorder() {
    const TYPESCRIPT: &str =
        "function ordered() { let first = 1; let second = 2; return second; }\n";
    const JAVA: &str = r#"
class Ordered {
    void ordered() { Object first = new Object(); Object second = new Object(); }
}
"#;
    let project = InlineTestProject::new()
        .file("ordered/ordered.ts", TYPESCRIPT)
        .file("ordered/Ordered.java", JAVA)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());

    for (path, source, kind) in [
        ("ordered/ordered.ts", TYPESCRIPT, ProcedureKind::Function),
        ("ordered/Ordered.java", JAVA, ProcedureKind::Method),
    ] {
        let graph = SemanticGraph::materialize(&project, &analyzer, path);
        let procedure = procedure_named(&graph, "ordered", kind);
        let locals = procedure
            .values()
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Local)
            .map(|value| mapped_source(procedure, source, value.source))
            .collect::<Vec<_>>();
        assert_eq!(locals, ["first", "second"]);
    }
}

#[test]
fn parameter_assignment_projects_the_parameter_port_as_the_flow_target() {
    let project = InlineTestProject::new()
        .file(
            "parameter.ts",
            "function overwrite(input: number) { input = 1; return input; }\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "parameter.ts");
    let procedure = procedure_handle_named(&graph, "overwrite", ProcedureKind::Function);
    let oracle = analyzer.semantic_oracle_provider();
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = oracle
        .procedure_relations(
            &procedure,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("parameter assignment value-flow projection");
    let snapshot = available(&outcome);
    assert!(snapshot.relations().iter().any(|relation| matches!(
        (&relation.kind, &relation.source, &relation.target),
        (
            ValueFlowRelationKind::Parameter,
            ValueFlowEndpoint::Value(_),
            ValueFlowEndpoint::Port(port),
        ) if port.kind() == ProcedurePortKind::Parameter { ordinal: 0 }
    )));
}
