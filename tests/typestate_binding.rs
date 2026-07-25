mod common;

use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, EvidenceCompleteness, ObjectCardinality,
    ProcedureKind, ProofStatus, SemanticCallSite,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, ProtocolEventKey, ProtocolExpectationKey, ProtocolSpec,
    ProtocolStateKey, TypestateBindingContext, TypestateBindingMultiplicity, TypestateBindingPlan,
    TypestateBindingPlanError, TypestateBindingQuality, TypestateEventBindingSpec,
    TypestateInitialSeedSpec, TypestateObjectRole, TypestateObservationSite,
    TypestateSubjectClassKey, TypestateSubjectKey, TypestateTerminalBindingSpec,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    semantic_graph::{SemanticGraph, mapped_source},
};

const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("fixtures/typestate/resource-lifecycle.protocol.json");
const SOURCE: &str = r#"
function lifecycle() {
  const resource = acquire();
  use(resource);
  close(resource);
}
"#;

struct BindingFixture {
    subject: TypestateSubjectKey,
    class: TypestateSubjectClassKey,
    object: AbstractObject,
    seed_site: TypestateObservationSite,
    use_site: TypestateObservationSite,
    close_site: TypestateObservationSite,
    exit_site: TypestateObservationSite,
}

fn protocol() -> brokk_bifrost::analyzer::typestate::CompiledProtocol {
    ProtocolSpec::from_json(RESOURCE_LIFECYCLE)
        .expect("protocol fixture should parse")
        .compile()
        .expect("protocol fixture should compile")
}

fn call_named<'procedure>(
    procedure: &'procedure brokk_bifrost::analyzer::semantic::ProcedureSemantics,
    source: &str,
    name: &str,
) -> &'procedure SemanticCallSite {
    procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, source, call.source).contains(name))
        .unwrap_or_else(|| panic!("missing call containing {name:?}"))
}

fn binding_fixture() -> BindingFixture {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/main.ts");
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Function
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("lifecycle")
        })
        .expect("lifecycle procedure");
    let procedure_handle = graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("scoped lifecycle handle");
    let use_call = call_named(procedure, SOURCE, "use(resource)");
    let close_call = call_named(procedure, SOURCE, "close(resource)");
    let subject_value = use_call.arguments[0].value;
    let object = AbstractObject::new(
        AccessPathRoot::Value(
            procedure_handle
                .value_handle(subject_value)
                .expect("scoped subject value"),
        ),
        ObjectCardinality::Singleton,
    )
    .expect("valid abstract subject");
    let class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject = TypestateSubjectKey::for_object(class.clone(), &object);

    let point_site = |point_id| {
        TypestateObservationSite::program_point(
            procedure_handle
                .point_handle(point_id)
                .expect("scoped fixture point"),
            TypestateBindingContext::root(),
        )
    };
    let call_site = |call: &SemanticCallSite| {
        TypestateObservationSite::call_site(
            procedure_handle
                .call_site_handle(call.id)
                .expect("scoped fixture call"),
            TypestateBindingContext::root(),
        )
    };

    BindingFixture {
        subject,
        class,
        object,
        seed_site: point_site(procedure.entry_point()),
        use_site: call_site(use_call),
        close_site: call_site(close_call),
        exit_site: point_site(procedure.normal_exit_point()),
    }
}

fn build_plan(
    protocol: &brokk_bifrost::analyzer::typestate::CompiledProtocol,
    fixture: &BindingFixture,
    quality: TypestateBindingQuality,
    reverse_events: bool,
) -> Result<TypestateBindingPlan, TypestateBindingPlanError> {
    let subjects = vec![BoundTypestateSubjectSpec::new(
        fixture.class.clone(),
        fixture.object.clone(),
        quality.clone(),
    )];
    let seeds = vec![TypestateInitialSeedSpec::new(
        fixture.subject.clone(),
        ProtocolStateKey::new("open").unwrap(),
        fixture.seed_site.clone(),
        TypestateObjectRole::MatchedValue,
        quality.clone(),
    )];
    let mut events = vec![
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new("use").unwrap(),
            fixture.subject.clone(),
            fixture.use_site.clone(),
            TypestateObjectRole::Argument,
            quality.clone(),
        ),
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            fixture.subject.clone(),
            fixture.close_site.clone(),
            TypestateObjectRole::Argument,
            quality.clone(),
        ),
    ];
    if reverse_events {
        events.reverse();
    }
    let terminals = vec![TypestateTerminalBindingSpec::new(
        ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
        fixture.subject.clone(),
        fixture.exit_site.clone(),
        TypestateObjectRole::CurrentObject,
        quality,
    )];
    TypestateBindingPlan::try_new(protocol, subjects, seeds, events, terminals)
}

#[test]
fn binding_plan_is_canonical_and_alias_preserving() {
    let protocol = protocol();
    let fixture = binding_fixture();
    let first = build_plan(
        &protocol,
        &fixture,
        TypestateBindingQuality::proven_unique(),
        false,
    )
    .expect("binding plan should compile");
    let reordered = build_plan(
        &protocol,
        &fixture,
        TypestateBindingQuality::proven_unique(),
        true,
    )
    .expect("reordered binding plan should compile");

    assert_eq!(first.canonical_bytes(), reordered.canonical_bytes());
    assert_eq!(first.canonical_rendering(), reordered.canonical_rendering());
    assert_eq!(first.hash(), reordered.hash());
    assert_eq!(
        first.subject_for_object(&fixture.class, &fixture.object),
        Some(first.subjects()[0].id())
    );

    let use_call = fixture.use_site.call_site_handle().unwrap();
    let use_bindings = first
        .event_bindings_at_call_site(use_call, &Default::default())
        .collect::<Vec<_>>();
    assert_eq!(use_bindings.len(), 1);
    assert_eq!(
        protocol
            .event(use_bindings[0].event())
            .unwrap()
            .key()
            .as_str(),
        "use"
    );
    assert_eq!(use_bindings[0].subject(), first.subjects()[0].id());

    let terminal_point = fixture.exit_site.program_point_handle().unwrap();
    assert_eq!(
        first
            .terminal_bindings_at_program_point(terminal_point, &Default::default())
            .count(),
        1
    );
    assert!(!first.canonical_rendering().contains("source_index"));
}

#[test]
fn diagnostic_reason_text_does_not_change_binding_identity() {
    let protocol = protocol();
    let fixture = binding_fixture();
    let multiplicity = TypestateBindingMultiplicity::new(CandidateCoverage::Open, 2).unwrap();
    let first_quality = TypestateBindingQuality::new(
        ProofStatus::Unproven("first diagnostic reason".into()),
        EvidenceCompleteness::Partial("first completeness reason".into()),
        multiplicity,
    );
    let second_quality = TypestateBindingQuality::new(
        ProofStatus::Unproven("different diagnostic reason".into()),
        EvidenceCompleteness::Partial("different completeness reason".into()),
        multiplicity,
    );
    let first = build_plan(&protocol, &fixture, first_quality, false).unwrap();
    let second = build_plan(&protocol, &fixture, second_quality, false).unwrap();

    assert_eq!(first.hash(), second.hash());
    assert!(first.subjects()[0].quality().multiplicity().is_ambiguous());
    assert_eq!(first.subjects()[0].quality().multiplicity().retained(), 2);
}

#[test]
fn incompatible_event_site_is_rejected_before_propagation() {
    let protocol = protocol();
    let fixture = binding_fixture();
    let error = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.class.clone(),
            fixture.object.clone(),
            TypestateBindingQuality::proven_unique(),
        )],
        Vec::new(),
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            fixture.subject,
            fixture.seed_site,
            TypestateObjectRole::Argument,
            TypestateBindingQuality::proven_unique(),
        )],
        Vec::new(),
    )
    .expect_err("call endpoint bound to a program point must fail");

    assert!(matches!(
        error,
        TypestateBindingPlanError::InvalidObservationShape
    ));
}
