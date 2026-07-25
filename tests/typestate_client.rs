mod common;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DistributiveDataflowProblem,
};
use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, EvidenceCompleteness, IcfgEdgeKind,
    ObjectCardinality, ProcedureKind, ProofStatus, SemanticCallSite,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, ProtocolEventKey, ProtocolSpec, ProtocolStateKey,
    TypestateBindingContext, TypestateBindingMultiplicity, TypestateBindingPlan,
    TypestateBindingQuality, TypestateEventBindingSpec, TypestateFact, TypestateFlowProblem,
    TypestateFlowProblemError, TypestateInitialSeedSpec, TypestateObjectRole,
    TypestateObservationSite, TypestateSubjectClassKey, TypestateSubjectKey, TypestateUncertainty,
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

struct ClientFixture {
    protocol: CompiledProtocol,
    bindings: TypestateBindingPlan,
    subject: brokk_bifrost::analyzer::typestate::TypestateSubjectId,
    entry: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    use_point: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    close_point: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    exit: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
    use_call: brokk_bifrost::analyzer::semantic::CallSiteHandle,
    close_call: brokk_bifrost::analyzer::semantic::CallSiteHandle,
}

fn call_named<'procedure>(
    procedure: &'procedure brokk_bifrost::analyzer::semantic::ProcedureSemantics,
    name: &str,
) -> &'procedure SemanticCallSite {
    procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, SOURCE, call.source).contains(name))
        .unwrap_or_else(|| panic!("missing call containing {name:?}"))
}

fn protocol() -> CompiledProtocol {
    ProtocolSpec::from_json(RESOURCE_LIFECYCLE)
        .expect("protocol fixture should parse")
        .compile()
        .expect("protocol fixture should compile")
}

fn fixture(close_quality: TypestateBindingQuality) -> ClientFixture {
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
    let use_call = call_named(procedure, "use(resource)");
    let close_call = call_named(procedure, "close(resource)");
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
    let subject_key = TypestateSubjectKey::for_object(class.clone(), &object);
    let entry = procedure_handle
        .point_handle(procedure.entry_point())
        .expect("entry point");
    let exit = procedure_handle
        .point_handle(procedure.normal_exit_point())
        .expect("normal exit");
    let use_point = procedure_handle
        .point_handle(use_call.point)
        .expect("use point");
    let close_point = procedure_handle
        .point_handle(close_call.point)
        .expect("close point");
    let use_call_handle = procedure_handle
        .call_site_handle(use_call.id)
        .expect("use call handle");
    let close_call_handle = procedure_handle
        .call_site_handle(close_call.id)
        .expect("close call handle");
    let entry_site =
        TypestateObservationSite::program_point(entry.clone(), TypestateBindingContext::root());
    let use_site = TypestateObservationSite::call_site(
        use_call_handle.clone(),
        TypestateBindingContext::root(),
    );
    let close_site = TypestateObservationSite::call_site(
        close_call_handle.clone(),
        TypestateBindingContext::root(),
    );
    let exact = TypestateBindingQuality::proven_unique();
    let protocol = protocol();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(class, object, exact.clone())],
        vec![TypestateInitialSeedSpec::new(
            subject_key.clone(),
            ProtocolStateKey::new("unallocated").unwrap(),
            entry_site.clone(),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("acquire").unwrap(),
                subject_key.clone(),
                entry_site,
                0,
                TypestateObjectRole::AllocationResult,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("use").unwrap(),
                subject_key.clone(),
                use_site,
                0,
                TypestateObjectRole::Argument,
                exact,
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("close").unwrap(),
                subject_key,
                close_site,
                0,
                TypestateObjectRole::Argument,
                close_quality,
            ),
        ],
        Vec::new(),
    )
    .expect("client binding plan");
    let subject = bindings.subjects()[0].id();

    ClientFixture {
        protocol,
        bindings,
        subject,
        entry,
        use_point,
        close_point,
        exit,
        use_call: use_call_handle,
        close_call: close_call_handle,
    }
}

#[derive(Default)]
struct FactOutput(Vec<TypestateFact>);

impl DataflowOutput<TypestateFact> for FactOutput {
    fn emit(&mut self, fact: TypestateFact) -> bool {
        self.0.push(fact);
        true
    }
}

fn transfer(
    problem: &TypestateFlowProblem<'_>,
    edge: DataflowEdge<'_>,
    fact: TypestateFact,
    family: TestTransfer,
) -> Vec<TypestateFact> {
    let mut output = FactOutput::default();
    match family {
        TestTransfer::Normal => problem.normal_flow(edge, fact, &mut output),
        TestTransfer::Call => problem.call_flow(edge, fact, &mut output),
        TestTransfer::Return => problem.return_flow(edge, fact, &mut output),
    }
    output.0
}

enum TestTransfer {
    Normal,
    Call,
    Return,
}

#[test]
fn bound_events_execute_in_their_dataflow_phase() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let problem = TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings).unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;

    let opened = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::Intraprocedural(
                brokk_bifrost::analyzer::semantic::ControlEdgeKind::Normal,
            ),
            None,
            &fixture.entry,
            &fixture.use_point,
            &proven,
            &complete,
        ),
        TypestateFact::Zero,
        TestTransfer::Normal,
    );
    let open = fixture
        .protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();
    assert_eq!(opened, vec![TypestateFact::state(fixture.subject, open)]);

    let used = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::Call,
            Some(&fixture.use_call),
            &fixture.use_point,
            &fixture.exit,
            &proven,
            &complete,
        ),
        opened[0],
        TestTransfer::Call,
    );
    assert_eq!(used, opened);

    let closed = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::NormalReturn,
            Some(&fixture.close_call),
            &fixture.exit,
            &fixture.close_point,
            &proven,
            &complete,
        ),
        used[0],
        TestTransfer::Return,
    );
    let closed_state = fixture
        .protocol
        .state_id(&ProtocolStateKey::new("closed").unwrap())
        .unwrap();
    assert_eq!(
        closed,
        vec![TypestateFact::state(fixture.subject, closed_state)]
    );

    let violated = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::Call,
            Some(&fixture.use_call),
            &fixture.use_point,
            &fixture.exit,
            &proven,
            &complete,
        ),
        closed[0],
        TestTransfer::Call,
    );
    let violated_state = fixture
        .protocol
        .state_id(&ProtocolStateKey::new("violated").unwrap())
        .unwrap();
    assert_eq!(
        violated,
        vec![TypestateFact::state(fixture.subject, violated_state)]
    );
}

#[test]
fn ambiguous_call_binding_preserves_explicit_uncertainty() {
    let multiplicity = TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 2).unwrap();
    let ambiguous = TypestateBindingQuality::new(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        multiplicity,
    );
    let fixture = fixture(ambiguous);
    let problem = TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings).unwrap();
    let open = fixture
        .protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;

    let result = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::NormalReturn,
            Some(&fixture.close_call),
            &fixture.exit,
            &fixture.close_point,
            &proven,
            &complete,
        ),
        TypestateFact::state(fixture.subject, open),
        TestTransfer::Return,
    );

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].protocol_state(), Some(open));
    assert!(
        result[0]
            .uncertainty()
            .contains(TypestateUncertainty::AmbiguousDispatch)
    );
    assert!(!result[0].abstained());
}

#[test]
fn flow_problem_rejects_a_plan_for_another_protocol() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let changed_source = String::from_utf8(RESOURCE_LIFECYCLE.to_vec())
        .unwrap()
        .replace("\"analysis_mode\": \"may\"", "\"analysis_mode\": \"must\"");
    let changed = ProtocolSpec::from_json(changed_source.as_bytes())
        .unwrap()
        .compile()
        .unwrap();

    assert!(matches!(
        TypestateFlowProblem::try_new(&changed, &fixture.bindings),
        Err(TypestateFlowProblemError::ProtocolMismatch)
    ));
}
