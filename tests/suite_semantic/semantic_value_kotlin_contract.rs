use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::semantic::{
    AbstractObjectIdentity, AllocationKind, ArgumentDomain, CallArgumentExpansion,
    CancellationToken, CandidateCoverage, DispatchExtensibility, ProcedureKind, ProcedurePortKind,
    ProcedureSemantics, SemanticBudget, SemanticCapability, SemanticEffect, SemanticGapSubject,
    SemanticRequest, SemanticValueKind, ValueFlowKind,
};

use crate::common::{
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
fn kotlin_publishes_receiver_local_argument_allocation_and_return_identity() {
    const SOURCE: &str = r#"
package values

class Box(val value: Any)

open class Sample {
    fun instance(input: Any): Any {
        val made = Box(input)
        this.sink(input, made)
        this.labelled(made = made, input = input)
        return made
    }

    open fun sink(input: Any, made: Box) {}

    open fun labelled(input: Any, made: Any) {}
}

object Factory {
    fun factory(input: Any): Box = Box(input)
}
"#;

    let project = InlineTestProject::new()
        .file("values/Sample.kt", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/Sample.kt");
    let instance = procedure_named(&graph, "instance", ProcedureKind::Method);

    assert_eq!(
        instance.properties().dispatch_extensibility,
        DispatchExtensibility::Open,
        "a method of an `open` Kotlin class retains an open override boundary"
    );
    let formal_receiver = instance
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("Kotlin instance methods must publish their current receiver");
    let input = instance
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("Kotlin method parameter");
    assert!(mapped_source(instance, SOURCE, input.source).contains("input"));

    let local = instance
        .values()
        .iter()
        .find(|value| {
            value.kind == SemanticValueKind::Local
                && mapped_source(instance, SOURCE, value.source) == "made"
        })
        .expect("a Kotlin `val` must publish a stable local identity");
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
        .expect("Kotlin member application");
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

    // Kotlin binds a labelled argument by name, so the source order of a named
    // call says nothing about which parameter each value reaches.
    let labelled = instance
        .call_sites()
        .iter()
        .find(|call| {
            mapped_source(instance, SOURCE, call.source)
                == "this.labelled(made = made, input = input)"
        })
        .expect("Kotlin named-argument application");
    assert!(
        labelled.arguments.iter().all(|argument| {
            argument.expansion == CallArgumentExpansion::Direct(ArgumentDomain::Keyword)
        }),
        "Kotlin named arguments must publish the keyword domain: {:#?}",
        labelled.arguments
    );
    let labelled_sources = labelled
        .arguments
        .iter()
        .map(|argument| {
            let value = instance.value(argument.value).expect("argument value");
            mapped_source(instance, SOURCE, value.source)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        labelled_sources,
        ["made", "input"],
        "a labelled argument must map to the value it spells, not to its label"
    );

    let construction = instance
        .call_sites()
        .iter()
        .find(|call| mapped_source(instance, SOURCE, call.source) == "Box(input)")
        .expect("Kotlin construction call");
    assert!(
        instance.allocations().iter().any(|allocation| {
            allocation.kind == AllocationKind::Object
                && Some(allocation.result) == construction.result
        }),
        "a bare Kotlin constructor call must retain allocation identity: {:#?}",
        instance.allocations()
    );
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
        .expect("a Kotlin `return` must publish a return flow");
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
            &project.file("values/Sample.kt"),
            brokk_bifrost::analyzer::Range {
                start_byte: receiver_start,
                end_byte: receiver_start + "this".len(),
                start_line: receiver_line,
                end_line: receiver_line,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Kotlin current-receiver points-to query");
    let receiver_points_to = receiver_outcome
        .available_value()
        .expect("Kotlin receiver query must retain its value");
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
        "a Kotlin `object` member cannot be overridden"
    );
    assert!(
        factory
            .allocations()
            .iter()
            .any(|allocation| allocation.kind == AllocationKind::Object),
        "factory construction must retain allocation identity"
    );
}

#[test]
fn kotlin_lowers_primary_constructor_parameter_defaults_with_a_scheduling_gap() {
    const SOURCE: &str = r#"
package values

class Defaults(val eager: Int = compute(), val lazyish: String = describe()) {
    init {
        record(eager)
    }
}

fun compute(): Int = 1

fun describe(): String = "d"

fun record(value: Int) {}
"#;

    let project = InlineTestProject::new()
        .file("values/Defaults.kt", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/Defaults.kt");

    for (name, call) in [("eager", "compute()"), ("lazyish", "describe()")] {
        let procedure = procedure_named(&graph, name, ProcedureKind::Initializer);
        assert!(
            procedure
                .call_sites()
                .iter()
                .any(|site| mapped_source(procedure, SOURCE, site.source) == call),
            "the default of `{name}` must lower `{call}` as a call site: {:#?}",
            procedure.call_sites()
        );
        assert!(
            procedure.gaps().iter().any(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::DeferredExecution
                    && gap.detail.contains("primary-constructor parameter default")
            }),
            "the default of `{name}` must retain a procedure-scoped scheduling gap: {:#?}",
            procedure.gaps()
        );
    }

    // The gap is about *when* a default runs, so an `init` block that observes
    // the same construction keeps its own scheduling gap rather than inheriting
    // an ordering claim from the parameter defaults.
    let initializer = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Initializer
                && procedure
                    .call_sites()
                    .iter()
                    .any(|site| mapped_source(procedure, SOURCE, site.source) == "record(eager)")
        })
        .expect("the init block must be lowered");
    assert!(
        initializer.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.capability == SemanticCapability::DeferredExecution
        }),
        "the init block must retain its own scheduling gap: {:#?}",
        initializer.gaps()
    );
}

#[test]
fn kotlin_publishes_extension_receivers_on_both_sides_of_a_call() {
    const SOURCE: &str = r#"
package values

class Service {
    fun run() {}
}

fun Service.extended(flag: Int) {
    this.run()
}

fun caller(service: Service) {
    service.extended(1)
}
"#;

    let project = InlineTestProject::new()
        .file("values/Extensions.kt", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "values/Extensions.kt");

    // The declaration side: the extension receiver occupies a receiver slot
    // rather than an ordinary parameter ordinal, so `flag` is still parameter
    // zero.
    let extended = procedure_named(&graph, "extended", ProcedureKind::Function);
    let receiver = extended
        .values()
        .iter()
        .find(|value| value.kind == SemanticValueKind::Receiver)
        .expect("a Kotlin extension must publish its receiver as a receiver value");
    assert!(
        mapped_source(extended, SOURCE, receiver.source).contains("Service"),
        "the extension receiver maps to the type it extends"
    );
    let flag = extended
        .values()
        .iter()
        .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
        .expect("extension parameter zero");
    assert!(mapped_source(extended, SOURCE, flag.source).contains("flag"));

    // The call side: the extension receiver argument binds as the call's
    // receiver, exactly as a member application's does.
    let caller = procedure_named(&graph, "caller", ProcedureKind::Function);
    let call = caller
        .call_sites()
        .iter()
        .find(|call| mapped_source(caller, SOURCE, call.source) == "service.extended(1)")
        .expect("extension application");
    let bound = caller
        .value(call.receiver.expect("extension call receiver"))
        .expect("receiver value");
    assert_eq!(mapped_source(caller, SOURCE, bound.source), "service");
    assert!(
        caller
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Parameter,
                    target,
                    ..
                } if target == bound.id
            )),
        "the extension receiver argument must flow from the parameter it reads"
    );
}
