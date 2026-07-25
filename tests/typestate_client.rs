mod common;

use std::cell::Cell;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem, PathQuality,
    SolverBudget, WitnessReconstructionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, EvidenceCompleteness, IcfgEdgeKind,
    ObjectCardinality, OracleCallContext, OracleLimits, ProcedureKind, ProofStatus, SemanticBudget,
    SemanticCallSite,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, ProtocolAnalysisMode, ProtocolEventKey,
    ProtocolEventOccurrence, ProtocolEventSpec, ProtocolExpectationKey, ProtocolGuardSpec,
    ProtocolObservationPhase, ProtocolObservationSpec, ProtocolProcedureExitKind,
    ProtocolSemantics, ProtocolSpec, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior, TypestateBindingContext,
    TypestateBindingMultiplicity, TypestateBindingPlan, TypestateBindingQuality,
    TypestateEventBindingSpec, TypestateFact, TypestateFindingCertainty, TypestateFindingKind,
    TypestateFindingLimits, TypestateFlowProblem, TypestateFlowProblemError,
    TypestateInitialSeedSpec, TypestateObjectRole, TypestateObservationSite,
    TypestateSubjectClassKey, TypestateSubjectKey, TypestateSummaryResult,
    TypestateTerminalBindingSpec, TypestateUncertainty, collect_summary_findings,
    collect_summary_findings_with_limits, solve_typestate_with_summaries,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};

use common::{
    BuiltInlineTestProject, InlineTestProject,
    semantic_graph::{SemanticGraph, mapped_source},
};

const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("fixtures/typestate/resource-lifecycle.protocol.json");
const SOURCE: &str = r#"
function acquire() {
  return {};
}

function use(resource: object) {}

function close(resource: object) {}

function lifecycle() {
  const resource = acquire();
  use(resource);
  close(resource);
}
"#;

const TYPE_SCRIPT_CONFORMANCE_SOURCE: &str = r#"
function acquire(): object {
  return {};
}

function use(resource: object): void {}

function close(resource: object): void {}

function lifecycle(): void {
  const resource = acquire();
  const alias = resource;
  use(alias);
  close(alias);
  return;
}
"#;

const JAVA_CONFORMANCE_SOURCE: &str = r#"
final class LifecycleFixture {
  static int acquire() {
    return 1;
  }

  static void use(int resource) {}

  static void close(int resource) {}

  static void lifecycle() {
    int resource = acquire();
    int alias = resource;
    use(alias);
    close(alias);
    return;
  }
}
"#;

struct ClientFixture {
    protocol: CompiledProtocol,
    bindings: TypestateBindingPlan,
    subject_key: TypestateSubjectKey,
    subject_class: TypestateSubjectClassKey,
    subject_object: AbstractObject,
    root: brokk_bifrost::analyzer::semantic::ProcedureHandle,
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
    call_containing(procedure, SOURCE, name)
}

fn call_containing<'procedure>(
    procedure: &'procedure brokk_bifrost::analyzer::semantic::ProcedureSemantics,
    source: &str,
    text: &str,
) -> &'procedure SemanticCallSite {
    procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, source, call.source).contains(text))
        .unwrap_or_else(|| panic!("missing call containing {text:?}"))
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
    fixture_from(
        &project,
        &analyzer,
        close_quality,
        TypestateBindingQuality::proven_unique(),
        false,
        false,
    )
}

fn fixture_from(
    project: &BuiltInlineTestProject,
    analyzer: &WorkspaceAnalyzer,
    close_quality: TypestateBindingQuality,
    terminal_quality: TypestateBindingQuality,
    swap_use_and_close: bool,
    contextual: bool,
) -> ClientFixture {
    let graph = SemanticGraph::materialize(project, analyzer, "src/main.ts");
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
    let context = if contextual {
        TypestateBindingContext::try_new(OracleCallContext::bounded(
            vec![use_call_handle.clone()],
            OracleLimits::default(),
        ))
        .unwrap()
    } else {
        TypestateBindingContext::root()
    };
    let entry_site = TypestateObservationSite::program_point(entry.clone(), context.clone());
    let use_site = TypestateObservationSite::call_site(use_call_handle.clone(), context.clone());
    let close_site =
        TypestateObservationSite::call_site(close_call_handle.clone(), context.clone());
    let exact = TypestateBindingQuality::proven_unique();
    let (use_site, close_site) = if swap_use_and_close {
        (close_site, use_site)
    } else {
        (use_site, close_site)
    };
    let protocol = protocol();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            class.clone(),
            object.clone(),
            exact.clone(),
        )],
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
                subject_key.clone(),
                close_site,
                0,
                TypestateObjectRole::Argument,
                close_quality,
            ),
        ],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
            subject_key.clone(),
            TypestateObservationSite::program_point(exit.clone(), context),
            TypestateObjectRole::CurrentObject,
            terminal_quality,
        )],
    )
    .expect("client binding plan");
    ClientFixture {
        protocol,
        bindings,
        subject_key,
        subject_class: class,
        subject_object: object,
        root: procedure_handle,
        entry,
        use_point,
        close_point,
        exit,
        use_call: use_call_handle,
        close_call: close_call_handle,
    }
}

fn exit_protocol() -> CompiledProtocol {
    ProtocolSpec::from_json(
        br#"{
          "schema_version": 1,
          "states": ["open", "closed"],
          "initial_state": "open",
          "accepting_states": ["closed"],
          "error_states": [],
          "events": [{
            "id": "finish",
            "observation": {
              "occurrence": {"type": "procedure_exit", "kind": "normal"}
            }
          }],
          "transitions": [{"from": "open", "on": "finish", "to": "closed"}],
          "terminal_expectations": [],
          "semantics": {
            "analysis_mode": "may",
            "unmatched_event": "preserve_state",
            "uncertainty": {
              "ambiguous_dispatch": "preserve_uncertainty",
              "unknown_call": "preserve_uncertainty",
              "external_call": "preserve_uncertainty",
              "escape": "abstain",
              "incomplete_analysis": "abstain"
            }
          }
        }"#,
    )
    .unwrap()
    .compile()
    .unwrap()
}

fn expansion_protocol(state_count: usize) -> CompiledProtocol {
    let states = (0..state_count)
        .map(|index| format!("s{index}"))
        .collect::<Vec<_>>();
    let transitions = (0..state_count - 1)
        .map(|index| ProtocolTransitionSpec {
            from: format!("s{index}"),
            on: "tick".into(),
            to: format!("s{}", index + 1),
            guard: ProtocolGuardSpec::Always,
        })
        .collect();
    ProtocolSpec {
        schema_version: 1,
        states,
        initial_state: "s0".into(),
        accepting_states: vec![format!("s{}", state_count - 1)],
        error_states: Vec::new(),
        events: vec![ProtocolEventSpec {
            id: "tick".into(),
            observation: ProtocolObservationSpec {
                occurrence: ProtocolEventOccurrence::Endpoint {
                    phase: ProtocolObservationPhase::AtMatch,
                },
            },
        }],
        transitions,
        terminal_expectations: Vec::new(),
        semantics: ProtocolSemantics {
            analysis_mode: ProtocolAnalysisMode::May,
            unmatched_event: ProtocolUnmatchedEventBehavior::PreserveState,
            uncertainty: ProtocolUncertaintySemantics {
                ambiguous_dispatch: ProtocolUncertaintyBehavior::ConservativeTransition,
                unknown_call: ProtocolUncertaintyBehavior::ConservativeTransition,
                external_call: ProtocolUncertaintyBehavior::ConservativeTransition,
                escape: ProtocolUncertaintyBehavior::Abstain,
                incomplete_analysis: ProtocolUncertaintyBehavior::ConservativeTransition,
            },
        },
    }
    .compile()
    .unwrap()
}

fn error_expansion_protocol(state_count: usize) -> CompiledProtocol {
    ProtocolSpec {
        schema_version: 1,
        states: (0..state_count).map(|index| format!("s{index}")).collect(),
        initial_state: "s0".into(),
        accepting_states: vec!["s0".into()],
        error_states: (1..state_count).map(|index| format!("s{index}")).collect(),
        events: vec![ProtocolEventSpec {
            id: "tick".into(),
            observation: ProtocolObservationSpec {
                occurrence: ProtocolEventOccurrence::Endpoint {
                    phase: ProtocolObservationPhase::BeforeCall,
                },
            },
        }],
        transitions: (0..state_count - 1)
            .map(|index| ProtocolTransitionSpec {
                from: format!("s{index}"),
                on: "tick".into(),
                to: format!("s{}", index + 1),
                guard: ProtocolGuardSpec::Always,
            })
            .collect(),
        terminal_expectations: Vec::new(),
        semantics: ProtocolSemantics {
            analysis_mode: ProtocolAnalysisMode::May,
            unmatched_event: ProtocolUnmatchedEventBehavior::PreserveState,
            uncertainty: ProtocolUncertaintySemantics {
                ambiguous_dispatch: ProtocolUncertaintyBehavior::ConservativeTransition,
                unknown_call: ProtocolUncertaintyBehavior::ConservativeTransition,
                external_call: ProtocolUncertaintyBehavior::ConservativeTransition,
                escape: ProtocolUncertaintyBehavior::Abstain,
                incomplete_analysis: ProtocolUncertaintyBehavior::ConservativeTransition,
            },
        },
    }
    .compile()
    .unwrap()
}

fn solve_summary(fixture: &ClientFixture, analyzer: &WorkspaceAnalyzer) -> TypestateSummaryResult {
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_typestate_with_summaries(
        &fixture.root,
        &[],
        &analyzer.icfg_provider(),
        &fixture.protocol,
        &fixture.bindings,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("typestate summary solve")
}

#[derive(Default)]
struct FactOutput(Vec<TypestateFact>);

impl DataflowOutput<TypestateFact> for FactOutput {
    fn emit(&mut self, fact: TypestateFact) -> bool {
        self.0.push(fact);
        true
    }
}

#[derive(Default)]
struct StoppedOutput {
    emitted: usize,
}

impl DataflowOutput<TypestateFact> for StoppedOutput {
    fn should_continue(&self) -> bool {
        false
    }

    fn emit(&mut self, _fact: TypestateFact) -> bool {
        self.emitted += 1;
        false
    }
}

struct PollingOutput {
    polls: Cell<usize>,
    stop_after: usize,
    emitted: usize,
}

impl DataflowOutput<TypestateFact> for PollingOutput {
    fn should_continue(&self) -> bool {
        let polls = self.polls.get().saturating_add(1);
        self.polls.set(polls);
        polls <= self.stop_after
    }

    fn emit(&mut self, _fact: TypestateFact) -> bool {
        self.emitted = self.emitted.saturating_add(1);
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
        TestTransfer::CallToReturn => problem.call_to_return_flow(edge, fact, &mut output),
    }
    output.0
}

enum TestTransfer {
    Normal,
    Call,
    Return,
    CallToReturn,
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
        TypestateFact::zero(),
        TestTransfer::Normal,
    );
    assert!(
        opened.contains(
            &problem
                .state_fact(
                    &fixture.subject_key,
                    &ProtocolStateKey::new("open").unwrap(),
                )
                .unwrap()
        )
    );
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
    assert!(
        used.contains(
            &problem
                .state_fact(
                    &fixture.subject_key,
                    &ProtocolStateKey::new("open").unwrap(),
                )
                .unwrap()
        )
    );
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
    assert!(
        closed.contains(
            &problem
                .state_fact(
                    &fixture.subject_key,
                    &ProtocolStateKey::new("closed").unwrap(),
                )
                .unwrap()
        )
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
    assert_eq!(violated.len(), 2);
    assert!(
        violated.contains(
            &problem
                .state_fact(
                    &fixture.subject_key,
                    &ProtocolStateKey::new("violated").unwrap(),
                )
                .unwrap()
        )
    );
    let violation = violated
        .iter()
        .find_map(|fact| fact.violation())
        .expect("error transition emits a violation marker");
    assert_eq!(violation.from(), closed_state);
    assert_eq!(violation.to(), violated_state);
}

#[test]
fn procedure_exit_events_execute_when_control_enters_the_exit() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let protocol = exit_protocol();
    let exact = TypestateBindingQuality::proven_unique();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact.clone(),
        )],
        vec![TypestateInitialSeedSpec::new(
            fixture.subject_key.clone(),
            ProtocolStateKey::new("open").unwrap(),
            TypestateObservationSite::program_point(
                fixture.entry.clone(),
                TypestateBindingContext::root(),
            ),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("finish").unwrap(),
            fixture.subject_key.clone(),
            TypestateObservationSite::program_point(
                fixture.exit.clone(),
                TypestateBindingContext::root(),
            ),
            0,
            TypestateObjectRole::CurrentObject,
            exact,
        )],
        Vec::new(),
    )
    .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;

    let result = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::Intraprocedural(
                brokk_bifrost::analyzer::semantic::ControlEdgeKind::Normal,
            ),
            None,
            &fixture.entry,
            &fixture.exit,
            &proven,
            &complete,
        ),
        TypestateFact::zero(),
        TestTransfer::Normal,
    );
    assert!(
        result.contains(
            &problem
                .state_fact(
                    &fixture.subject_key,
                    &ProtocolStateKey::new("closed").unwrap(),
                )
                .unwrap()
        )
    );
}

#[test]
fn exit_terminal_observes_the_post_return_state() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let mut spec = ProtocolSpec::from_json(RESOURCE_LIFECYCLE).unwrap();
    spec.terminal_expectations = vec![ProtocolTerminalExpectationSpec {
        id: "exit-observation".into(),
        on: ProtocolTerminalObservationSpec::Event {
            observation: ProtocolObservationSpec {
                occurrence: ProtocolEventOccurrence::ProcedureExit {
                    kind: ProtocolProcedureExitKind::Normal,
                },
            },
        },
        expected_states: vec!["closed".into()],
    }];
    let protocol = spec.compile().unwrap();
    let exact = TypestateBindingQuality::proven_unique();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact.clone(),
        )],
        Vec::new(),
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            fixture.subject_key.clone(),
            TypestateObservationSite::call_site(
                fixture.close_call.clone(),
                TypestateBindingContext::root(),
            ),
            0,
            TypestateObjectRole::Argument,
            exact.clone(),
        )],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("exit-observation").unwrap(),
            fixture.subject_key.clone(),
            TypestateObservationSite::program_point(
                fixture.exit.clone(),
                TypestateBindingContext::root(),
            ),
            TypestateObjectRole::CurrentObject,
            exact,
        )],
    )
    .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let open = protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();
    let closed = protocol
        .state_id(&ProtocolStateKey::new("closed").unwrap())
        .unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;

    let result = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::NormalReturn,
            Some(&fixture.close_call),
            &fixture.close_point,
            &fixture.exit,
            &proven,
            &complete,
        ),
        problem
            .state_fact(
                &fixture.subject_key,
                &ProtocolStateKey::new("open").unwrap(),
            )
            .unwrap(),
        TestTransfer::Return,
    );

    assert!(
        result.iter().any(|fact| {
            fact.terminal_observation()
                .is_some_and(|(_, state)| state == closed)
        }),
        "{result:#?}"
    );
    assert!(!result.iter().any(|fact| {
        fact.terminal_observation()
            .is_some_and(|(_, state)| state == open)
    }));
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
        problem
            .state_fact(
                &fixture.subject_key,
                &ProtocolStateKey::new("open").unwrap(),
            )
            .unwrap(),
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
fn conservative_uncertainty_retains_error_transition_provenance() {
    let multiplicity = TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 2).unwrap();
    let ambiguous = TypestateBindingQuality::new(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        multiplicity,
    );
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let source = String::from_utf8(RESOURCE_LIFECYCLE.to_vec())
        .unwrap()
        .replace(
            "\"ambiguous_dispatch\": \"preserve_uncertainty\"",
            "\"ambiguous_dispatch\": \"conservative_transition\"",
        );
    let protocol = ProtocolSpec::from_json(source.as_bytes())
        .unwrap()
        .compile()
        .unwrap();
    let exact = TypestateBindingQuality::proven_unique();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact.clone(),
        )],
        Vec::new(),
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            fixture.subject_key.clone(),
            TypestateObservationSite::call_site(
                fixture.close_call.clone(),
                TypestateBindingContext::root(),
            ),
            0,
            TypestateObjectRole::Argument,
            ambiguous,
        )],
        Vec::new(),
    )
    .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let violated = protocol
        .state_id(&ProtocolStateKey::new("violated").unwrap())
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
        problem
            .state_fact(
                &fixture.subject_key,
                &ProtocolStateKey::new("closed").unwrap(),
            )
            .unwrap(),
        TestTransfer::Return,
    );

    let violation = result
        .iter()
        .find(|fact| fact.violation().is_some())
        .expect("conservative error reachability remains reportable");
    assert_eq!(violation.protocol_state(), Some(violated));
    assert!(
        violation
            .uncertainty()
            .contains(TypestateUncertainty::AmbiguousDispatch)
    );
}

#[test]
fn callback_expansion_limit_collapses_to_an_explicit_inconclusive_state() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let protocol = expansion_protocol(400);
    let exact = TypestateBindingQuality::proven_unique();
    let partial = TypestateBindingQuality::new(
        ProofStatus::Unproven("adversarial binding".into()),
        EvidenceCompleteness::Partial("adversarial binding".into()),
        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1).unwrap(),
    );
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact,
        )],
        Vec::new(),
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("tick").unwrap(),
            fixture.subject_key.clone(),
            TypestateObservationSite::program_point(
                fixture.entry.clone(),
                TypestateBindingContext::root(),
            ),
            0,
            TypestateObjectRole::MatchedValue,
            partial,
        )],
        Vec::new(),
    )
    .unwrap();
    let initial = protocol
        .state_id(&ProtocolStateKey::new("s0").unwrap())
        .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let unproven = ProofStatus::Unproven("adversarial edge".into());
    let partial = EvidenceCompleteness::Partial("adversarial edge".into());

    let result = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::Intraprocedural(
                brokk_bifrost::analyzer::semantic::ControlEdgeKind::Normal,
            ),
            None,
            &fixture.entry,
            &fixture.use_point,
            &unproven,
            &partial,
        ),
        problem
            .state_fact(&fixture.subject_key, &ProtocolStateKey::new("s0").unwrap())
            .unwrap(),
        TestTransfer::Normal,
    );

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].protocol_state(), Some(initial));
    assert!(result[0].abstained());
    assert!(
        result[0]
            .uncertainty()
            .contains(TypestateUncertainty::IncompleteAnalysis)
    );
}

#[test]
fn retained_safe_outcomes_do_not_consume_quadratic_expansion_work() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let protocol = expansion_protocol(2);
    let exact = TypestateBindingQuality::proven_unique();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact.clone(),
        )],
        Vec::new(),
        (0..512)
            .map(|order| {
                TypestateEventBindingSpec::new(
                    ProtocolEventKey::new("tick").unwrap(),
                    fixture.subject_key.clone(),
                    TypestateObservationSite::program_point(
                        fixture.entry.clone(),
                        TypestateBindingContext::root(),
                    ),
                    order,
                    TypestateObjectRole::MatchedValue,
                    exact.clone(),
                )
            })
            .collect(),
        Vec::new(),
    )
    .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;
    let final_state = protocol
        .state_id(&ProtocolStateKey::new("s1").unwrap())
        .unwrap();

    let result = transfer(
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
        problem
            .state_fact(&fixture.subject_key, &ProtocolStateKey::new("s0").unwrap())
            .unwrap(),
        TestTransfer::Normal,
    );

    assert!(result.iter().any(|fact| {
        fact.protocol_state() == Some(final_state)
            && !fact.abstained()
            && fact.uncertainty().is_empty()
    }));
}

#[test]
fn conservative_witness_products_observe_mid_expansion_cancellation() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let protocol = error_expansion_protocol(400);
    let exact = TypestateBindingQuality::proven_unique();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact.clone(),
        )],
        Vec::new(),
        (0..400)
            .map(|order| {
                TypestateEventBindingSpec::new(
                    ProtocolEventKey::new("tick").unwrap(),
                    fixture.subject_key.clone(),
                    TypestateObservationSite::call_site(
                        fixture.close_call.clone(),
                        TypestateBindingContext::root(),
                    ),
                    order,
                    TypestateObjectRole::Argument,
                    exact.clone(),
                )
            })
            .collect(),
        Vec::new(),
    )
    .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;
    let boundary = brokk_bifrost::analyzer::semantic::DispatchBoundaryKind::Unresolved;
    let mut output = PollingOutput {
        polls: Cell::new(0),
        stop_after: 405,
        emitted: 0,
    };

    problem.call_to_return_flow(
        DataflowEdge::new(
            IcfgEdgeKind::CallToNormalContinuation,
            Some(&fixture.close_call),
            &fixture.use_point,
            &fixture.close_point,
            &proven,
            &complete,
        )
        .with_boundary(&boundary),
        problem
            .state_fact(&fixture.subject_key, &ProtocolStateKey::new("s0").unwrap())
            .unwrap(),
        &mut output,
    );

    assert!(output.polls.get() > 400);
    assert!(output.polls.get() <= output.stop_after + 2);
    assert_eq!(output.emitted, 0);
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

#[test]
fn public_state_facts_resolve_durable_plan_keys() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let problem = TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings).unwrap();
    let unknown_subject = TypestateSubjectKey::for_object(
        TypestateSubjectClassKey::new("other-resource").unwrap(),
        &fixture.subject_object,
    );

    assert!(
        problem
            .state_fact(
                &fixture.subject_key,
                &ProtocolStateKey::new("open").unwrap()
            )
            .is_ok()
    );
    assert!(matches!(
        problem.state_fact(&unknown_subject, &ProtocolStateKey::new("open").unwrap()),
        Err(TypestateFlowProblemError::InvalidFactIdentity)
    ));
    assert!(matches!(
        problem.state_fact(
            &fixture.subject_key,
            &ProtocolStateKey::new("not-a-state").unwrap()
        ),
        Err(TypestateFlowProblemError::InvalidFactIdentity)
    ));
}

#[test]
fn typestate_callbacks_stop_before_expansion_when_output_is_cancelled() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let problem = TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings).unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;
    let mut output = StoppedOutput::default();

    problem.normal_flow(
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
        TypestateFact::zero(),
        &mut output,
    );

    assert_eq!(output.emitted, 0);
}

#[test]
fn flow_problem_rejects_context_specific_plans_instead_of_flattening_them() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        false,
        true,
    );

    assert!(matches!(
        TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings),
        Err(TypestateFlowProblemError::ContextSensitiveBindingsUnsupported)
    ));
}

#[test]
fn structured_external_boundary_uses_external_call_semantics() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let problem = TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings).unwrap();
    let open = fixture
        .protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;
    let boundary = brokk_bifrost::analyzer::semantic::DispatchBoundaryKind::External(None);

    let result = transfer(
        &problem,
        DataflowEdge::new(
            IcfgEdgeKind::CallToNormalContinuation,
            Some(&fixture.close_call),
            &fixture.close_point,
            &fixture.exit,
            &proven,
            &complete,
        )
        .with_boundary(&boundary),
        problem
            .state_fact(
                &fixture.subject_key,
                &ProtocolStateKey::new("open").unwrap(),
            )
            .unwrap(),
        TestTransfer::CallToReturn,
    );

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].protocol_state(), Some(open));
    assert!(
        result[0]
            .uncertainty()
            .contains(TypestateUncertainty::ExternalCall)
    );
}

#[test]
fn real_summary_solver_executes_the_same_client_contract() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        false,
        false,
    );
    let result = solve_summary(&fixture, &analyzer);
    let raw = result.result();
    assert!(raw.reached_at(&fixture.exit).any(|reached| {
        raw.fact(reached.fact())
            == Some(
                &TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings)
                    .unwrap()
                    .state_fact(
                        &fixture.subject_key,
                        &ProtocolStateKey::new("closed").unwrap(),
                    )
                    .unwrap(),
            )
    }));
    let report = collect_summary_findings(&fixture.protocol, &fixture.bindings, &result).unwrap();
    assert!(!report.analysis_complete());
    assert_eq!(report.findings().len(), 1);
    assert_eq!(
        report.findings()[0].certainty(),
        TypestateFindingCertainty::Inconclusive
    );
    assert!(matches!(
        report.findings()[0].kind(),
        TypestateFindingKind::TerminalExpectation { .. }
    ));
    assert!(!report.findings()[0].evidence().analysis_complete());
    assert_eq!(report.findings()[0].witnesses().len(), 1);
    assert_eq!(
        report.findings()[0].witnesses()[0].witness().quality(),
        PathQuality::PROVEN_COMPLETE
    );
}

#[test]
fn one_protocol_runs_equivalent_typescript_and_java_lifecycles() {
    let mut spec = ProtocolSpec::from_json(RESOURCE_LIFECYCLE).unwrap();
    for event in &mut spec.events {
        if matches!(event.id.as_str(), "use" | "close") {
            event.observation.occurrence = ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AtMatch,
            };
        }
    }
    let protocol = spec.compile().unwrap();
    let expected_hash = protocol.hash();

    for (language, path, source) in [
        (
            Language::TypeScript,
            "src/main.ts",
            TYPE_SCRIPT_CONFORMANCE_SOURCE,
        ),
        (
            Language::Java,
            "src/LifecycleFixture.java",
            JAVA_CONFORMANCE_SOURCE,
        ),
    ] {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let graph = SemanticGraph::materialize(&project, &analyzer, path);
        let procedure = |name: &str| {
            graph
                .artifact()
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("{language:?} fixture missing {name}"))
        };
        let lifecycle = procedure("lifecycle");
        let lifecycle_handle = graph
            .artifact()
            .procedure_handle(lifecycle.id())
            .expect("lifecycle handle");
        let use_call = call_containing(lifecycle, source, "use(alias)");
        let close_call = call_containing(lifecycle, source, "close(alias)");
        let subject_object = AbstractObject::new(
            AccessPathRoot::Value(
                lifecycle_handle
                    .value_handle(close_call.arguments[0].value)
                    .expect("aliased close argument"),
            ),
            ObjectCardinality::Singleton,
        )
        .expect("conformance subject");
        let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
        let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &subject_object);
        let context = TypestateBindingContext::root();
        let exact = TypestateBindingQuality::proven_unique();
        let entry = lifecycle_handle
            .point_handle(lifecycle.entry_point())
            .expect("lifecycle entry");
        let exit = lifecycle_handle
            .point_handle(lifecycle.normal_exit_point())
            .expect("lifecycle normal exit");
        let close_point = lifecycle_handle
            .point_handle(close_call.point)
            .expect("close point");
        let use_point = lifecycle_handle
            .point_handle(use_call.point)
            .expect("use point");
        let event_binding = |event: &str,
                             point: brokk_bifrost::analyzer::semantic::ProgramPointHandle,
                             phase_order: u32| {
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new(event).unwrap(),
                subject_key.clone(),
                TypestateObservationSite::program_point(point, context.clone()),
                phase_order,
                TypestateObjectRole::MatchedValue,
                exact.clone(),
            )
        };
        let bindings = TypestateBindingPlan::try_new(
            &protocol,
            vec![BoundTypestateSubjectSpec::new(
                subject_class,
                subject_object,
                exact.clone(),
            )],
            vec![TypestateInitialSeedSpec::new(
                subject_key.clone(),
                ProtocolStateKey::new("unallocated").unwrap(),
                TypestateObservationSite::program_point(entry.clone(), context.clone()),
                TypestateObjectRole::MatchedValue,
                exact.clone(),
            )],
            vec![
                TypestateEventBindingSpec::new(
                    ProtocolEventKey::new("acquire").unwrap(),
                    subject_key.clone(),
                    TypestateObservationSite::program_point(entry.clone(), context.clone()),
                    0,
                    TypestateObjectRole::AllocationResult,
                    exact.clone(),
                ),
                event_binding("use", use_point, 0),
                event_binding("close", close_point.clone(), 0),
            ],
            vec![TypestateTerminalBindingSpec::new(
                ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
                subject_key.clone(),
                TypestateObservationSite::program_point(exit.clone(), context),
                TypestateObjectRole::CurrentObject,
                exact,
            )],
        )
        .expect("language-neutral lifecycle binding plan");
        let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        let summary = solve_typestate_with_summaries(
            &lifecycle_handle,
            &[],
            &analyzer.icfg_provider(),
            &protocol,
            &bindings,
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("language-neutral lifecycle summary solve");
        let closed = protocol
            .state_id(&ProtocolStateKey::new("closed").unwrap())
            .unwrap();
        assert!(
            summary.result().reached_at(&exit).any(|reached| {
                summary
                    .result()
                    .fact(reached.fact())
                    .is_some_and(|fact| fact.protocol_state() == Some(closed))
            }),
            "{language:?} summary solve did not carry the aliased lifecycle to closed: {:#?}",
            summary.result().reached_at(&exit).collect::<Vec<_>>()
        );
        assert_eq!(protocol.hash(), expected_hash);
    }
}

#[test]
fn incomplete_terminal_binding_cannot_support_a_definitive_finding() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let partial_terminal = TypestateBindingQuality::new(
        ProofStatus::Unproven("terminal resolution".into()),
        EvidenceCompleteness::Partial("terminal resolution".into()),
        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1).unwrap(),
    );
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        partial_terminal,
        false,
        false,
    );
    let result = solve_summary(&fixture, &analyzer);
    let report = collect_summary_findings(&fixture.protocol, &fixture.bindings, &result).unwrap();

    assert!(!result.bindings_complete());
    assert!(!report.analysis_complete());
    assert!(
        report
            .findings()
            .iter()
            .all(|finding| { finding.certainty() == TypestateFindingCertainty::Inconclusive })
    );
}

#[test]
fn must_mode_does_not_promote_event_specific_markers_without_universal_proof() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        false,
        false,
    );
    let source = String::from_utf8(RESOURCE_LIFECYCLE.to_vec())
        .unwrap()
        .replace("\"analysis_mode\": \"may\"", "\"analysis_mode\": \"must\"");
    let protocol = ProtocolSpec::from_json(source.as_bytes())
        .unwrap()
        .compile()
        .unwrap();
    let exact = TypestateBindingQuality::proven_unique();
    let entry_site = TypestateObservationSite::program_point(
        fixture.entry.clone(),
        TypestateBindingContext::root(),
    );
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            exact.clone(),
        )],
        vec![TypestateInitialSeedSpec::new(
            fixture.subject_key.clone(),
            ProtocolStateKey::new("unallocated").unwrap(),
            entry_site.clone(),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("acquire").unwrap(),
                fixture.subject_key.clone(),
                entry_site,
                0,
                TypestateObjectRole::AllocationResult,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("use").unwrap(),
                fixture.subject_key.clone(),
                TypestateObservationSite::call_site(
                    fixture.close_call.clone(),
                    TypestateBindingContext::root(),
                ),
                0,
                TypestateObjectRole::Argument,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("close").unwrap(),
                fixture.subject_key.clone(),
                TypestateObservationSite::call_site(
                    fixture.use_call.clone(),
                    TypestateBindingContext::root(),
                ),
                0,
                TypestateObjectRole::Argument,
                exact,
            ),
        ],
        Vec::new(),
    )
    .unwrap();
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_typestate_with_summaries(
        &fixture.root,
        &[],
        &analyzer.icfg_provider(),
        &protocol,
        &bindings,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap();
    let report = collect_summary_findings(&protocol, &bindings, &result).unwrap();
    let error_findings = report
        .findings()
        .iter()
        .filter(|finding| matches!(finding.kind(), TypestateFindingKind::ErrorTransition { .. }))
        .collect::<Vec<_>>();

    assert!(!error_findings.is_empty());
    assert!(
        error_findings
            .iter()
            .all(|finding| { finding.certainty() == TypestateFindingCertainty::Inconclusive })
    );
}

#[test]
fn summary_findings_retain_error_and_terminal_semantics() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        true,
        false,
    );
    let result = solve_summary(&fixture, &analyzer);
    let report = collect_summary_findings(&fixture.protocol, &fixture.bindings, &result).unwrap();

    assert!(report.findings().iter().any(|finding| {
        finding.certainty() == TypestateFindingCertainty::May
            && matches!(finding.kind(), TypestateFindingKind::ErrorTransition { .. })
    }));
    assert!(report.findings().iter().any(|finding| {
        finding.certainty() == TypestateFindingCertainty::May
            && matches!(
                finding.kind(),
                TypestateFindingKind::TerminalExpectation { .. }
            )
    }));
    assert!(report.findings().iter().all(|finding| {
        !finding.witnesses().is_empty()
            && finding.witnesses().iter().all(|finding_witness| {
                let witness = finding_witness.witness();
                witness.step_count() > 0
                    && witness.quality().is_proven()
                    && !witness.truncated()
                    && witness.omitted_steps_lower_bound() == 0
            })
    }));
}

#[test]
fn typestate_witness_budget_exhaustion_preserves_findings_and_reachability() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        true,
        false,
    );
    let baseline = solve_summary(&fixture, &analyzer);
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut limits = SolverBudget::default().limits();
    limits.witness_relations = 0;
    let mut solver_budget = SolverBudget::new(limits);
    let mut semantic_budget = SemanticBudget::default();
    let exhausted = solve_typestate_with_summaries(
        &fixture.root,
        &[],
        &analyzer.icfg_provider(),
        &fixture.protocol,
        &fixture.bindings,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("best-effort witnesses cannot stop a typestate solve");

    assert_eq!(exhausted.result().facts(), baseline.result().facts());
    assert_eq!(exhausted.result().reached(), baseline.result().reached());
    assert_eq!(
        exhausted.result().end_summaries(),
        baseline.result().end_summaries()
    );
    assert_eq!(
        exhausted.result().coverage().semantic_status(),
        baseline.result().coverage().semantic_status()
    );
    assert_eq!(
        exhausted.result().coverage().unproven_edges().len(),
        baseline.result().coverage().unproven_edges().len()
    );
    assert_eq!(
        exhausted.result().coverage().partial_edges().len(),
        baseline.result().coverage().partial_edges().len()
    );
    assert_eq!(
        exhausted.result().coverage().boundaries().len(),
        baseline.result().coverage().boundaries().len()
    );
    assert_eq!(
        exhausted.result().termination(),
        baseline.result().termination()
    );
    let mut baseline_work = baseline.result().work();
    baseline_work.witness_relations = 0;
    assert_eq!(exhausted.result().work(), baseline_work);
    assert!(exhausted.result().witness_retention_truncated());

    let report =
        collect_summary_findings(&fixture.protocol, &fixture.bindings, &exhausted).unwrap();
    assert!(!report.findings().is_empty());
    assert!(report.findings().iter().all(|finding| {
        !finding.witnesses().is_empty()
            && finding
                .witnesses()
                .iter()
                .all(|witness| witness.witness().retention_truncated())
    }));
}

#[test]
fn finding_collection_rejects_a_result_from_another_binding_plan() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let first = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        false,
        false,
    );
    let second = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        true,
        false,
    );
    let result = solve_summary(&first, &analyzer);

    assert!(matches!(
        collect_summary_findings(&second.protocol, &second.bindings, &result),
        Err(TypestateFlowProblemError::BindingPlanMismatch)
    ));
}

#[test]
fn finding_collection_observes_its_budget_and_cancellation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = fixture_from(
        &project,
        &analyzer,
        TypestateBindingQuality::proven_unique(),
        TypestateBindingQuality::proven_unique(),
        true,
        false,
    );
    let result = solve_summary(&fixture, &analyzer);
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();

    assert!(matches!(
        collect_summary_findings_with_limits(
            &fixture.protocol,
            &fixture.bindings,
            &result,
            TypestateFindingLimits::new(1, 1).unwrap(),
            &cancellation,
        ),
        Err(TypestateFlowProblemError::FindingBudgetExceeded)
    ));

    assert!(matches!(
        collect_summary_findings_with_limits(
            &fixture.protocol,
            &fixture.bindings,
            &result,
            TypestateFindingLimits::new(1_000_000, 1).unwrap(),
            &cancellation,
        ),
        Err(TypestateFlowProblemError::FindingBudgetExceeded)
    ));

    assert!(matches!(
        collect_summary_findings_with_limits(
            &fixture.protocol,
            &fixture.bindings,
            &result,
            TypestateFindingLimits::with_witness_limits(
                1_000_000,
                8_192,
                WitnessReconstructionLimits::new(64, 4_096).unwrap(),
                1_000_000,
                1,
            )
            .unwrap(),
            &cancellation,
        ),
        Err(TypestateFlowProblemError::FindingBudgetExceeded)
    ));

    assert!(matches!(
        TypestateFindingLimits::with_witness_limits(
            1_000_000,
            8_192,
            WitnessReconstructionLimits::new(65, 4_096).unwrap(),
            1_000_000,
            64 * 1024 * 1024,
        ),
        Err(TypestateFlowProblemError::InvalidFindingLimits)
    ));
    assert!(matches!(
        TypestateFindingLimits::with_witness_limits(
            1_000_000,
            8_192,
            WitnessReconstructionLimits::new(64, 4_097).unwrap(),
            1_000_000,
            64 * 1024 * 1024,
        ),
        Err(TypestateFlowProblemError::InvalidFindingLimits)
    ));

    cancellation.cancel();
    assert!(matches!(
        collect_summary_findings_with_limits(
            &fixture.protocol,
            &fixture.bindings,
            &result,
            TypestateFindingLimits::default(),
            &cancellation,
        ),
        Err(TypestateFlowProblemError::FindingCancelled)
    ));
}
