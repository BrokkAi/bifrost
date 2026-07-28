mod common;

use std::cell::Cell;

use brokk_bifrost::analyzer::dataflow::{
    DataflowEdge, DataflowOutput, DataflowRequest, DistributiveDataflowProblem, PathQuality,
    ProcedureSummaryIdentity, ProcedureSummaryKey, SemanticProcedureSummary, SolverBudget,
    SolverTermination, SummaryBehaviorKey, SummaryCompleteness, SummaryContextKey,
    SummaryDependencyKey, SummaryEffect, SummaryEffectKey, SummaryEventKey, SummaryEvidence,
    SummaryOrigin, SummaryRecursiveEdge, SummaryRecursiveGroupKey, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryWitnessStepKind, UnmodeledCallBehavior,
    WitnessReconstructionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, EvidenceCompleteness, IcfgEdgeKind,
    ObjectCardinality, OracleCallContext, OracleLimits, ProcedureKind, ProcedurePortHandle,
    ProofStatus, SemanticBudget, SemanticCallSite,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, CompleteProtocolSummaryRepository,
    ProtocolAnalysisMode, ProtocolEventKey, ProtocolEventOccurrence, ProtocolEventSpec,
    ProtocolExpectationKey, ProtocolFactKey, ProtocolGuardSpec, ProtocolObservationPhase,
    ProtocolObservationSpec, ProtocolProcedureExitKind, ProtocolSemanticSummarySet,
    ProtocolSemantics, ProtocolSpec, ProtocolStateKey, ProtocolSummaryCacheStatus,
    ProtocolSummaryError, ProtocolSummaryKey, ProtocolSummaryRepositoryLimits,
    ProtocolSummarySolveError, ProtocolSummarySolveResult, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior, TypestateBindingContext,
    TypestateBindingMultiplicity, TypestateBindingPlan, TypestateBindingQuality,
    TypestateEventBindingSpec, TypestateFact, TypestateFindingCertainty, TypestateFindingKind,
    TypestateFindingLimits, TypestateFlowProblem, TypestateFlowProblemError,
    TypestateInitialSeedSpec, TypestateObjectRole, TypestateObservationSite,
    TypestateSubjectClassKey, TypestateSubjectKey, TypestateSummaryResult,
    TypestateTerminalBindingSpec, TypestateUncertainty, collect_summary_findings,
    collect_summary_findings_with_limits, solve_typestate_with_reusable_summaries,
    solve_typestate_with_summaries,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};

use common::{
    BuiltInlineTestProject, InlineTestProject,
    semantic_graph::{SemanticGraph, mapped_source},
};

#[test]
fn unmodeled_call_profiles_map_to_typestate_uncertainty_behavior() {
    let base = ProtocolUncertaintySemantics {
        ambiguous_dispatch: ProtocolUncertaintyBehavior::PreserveUncertainty,
        unknown_call: ProtocolUncertaintyBehavior::PreserveUncertainty,
        external_call: ProtocolUncertaintyBehavior::PreserveUncertainty,
        escape: ProtocolUncertaintyBehavior::Abstain,
        incomplete_analysis: ProtocolUncertaintyBehavior::PreserveUncertainty,
    };
    for (profile, expected) in [
        (
            UnmodeledCallBehavior::Paranoid,
            ProtocolUncertaintyBehavior::ConservativeTransition,
        ),
        (
            UnmodeledCallBehavior::Optimistic,
            ProtocolUncertaintyBehavior::PreserveUncertainty,
        ),
        (
            UnmodeledCallBehavior::RequireModel,
            ProtocolUncertaintyBehavior::Abstain,
        ),
    ] {
        let mapped = base.with_unmodeled_call_behavior(profile);
        assert_eq!(mapped.unknown_call, expected);
        assert_eq!(mapped.external_call, expected);
        assert_eq!(mapped.escape, base.escape);
        assert_eq!(mapped.ambiguous_dispatch, base.ambiguous_dispatch);
        assert_eq!(mapped.incomplete_analysis, base.incomplete_analysis);
    }
}

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
final class Resource {}

final class LifecycleFixture {
  static Resource acquire() {
    return null;
  }

  static void use(Resource resource) {}

  static void close(Resource resource) {}

  static void lifecycle() {
    Resource resource = acquire();
    Resource alias = resource;
    use(alias);
    close(alias);
    return;
  }
}
"#;

const RECURSIVE_HELPER_SOURCE: &str = r#"
final class RecursiveResource {}

final class RecursiveFixture {
  static RecursiveResource acquire() {
    return null;
  }

  static void use(RecursiveResource resource) {}

  static void close(RecursiveResource resource) {}

  static void walk(RecursiveResource resource, int depth) {
    if (depth <= 0) {
      use(resource);
      return;
    }
    walk(resource, depth - 1);
    close(resource);
  }

  static void lifecycle() {
    RecursiveResource resource = acquire();
    walk(resource, 1);
  }
}
"#;

const EXCEPTIONAL_RETURN_SOURCE: &str = r#"
function fail(resource: object): never {
  throw resource;
}

function lifecycle(resource: object): void {
  try {
    fail(resource);
  } catch {
    return;
  }
}
"#;

const BRANCHING_LIFECYCLE_SOURCE: &str = r#"
final class BranchResource {}

final class BranchFixture {
  static BranchResource acquire() {
    return null;
  }

  static void close(BranchResource resource) {}

  static void lifecycle(boolean shouldClose) {
    BranchResource resource = acquire();
    if (shouldClose) {
      close(resource);
    }
  }
}
"#;

const TWO_CALLER_HELPER_SOURCE: &str = r#"
final class SharedResource {}

final class SharedHelperFixture {
  static void use(SharedResource resource) {}
  static void close(SharedResource resource) {}

  static void helper(SharedResource resource) {
    use(resource);
    close(resource);
  }

  static void callerOne() {
    helper(null);
  }

  static void callerTwo() {
    helper(null);
  }
}
"#;

const SUMMARY_RECURSIVE_HELPER_SOURCE: &str = r#"
package fixture

var recurse bool

func helper() {
    if recurse {
        helper()
    }
}

func callerOne() { helper() }
func callerTwo() { helper() }
"#;

const MUTUAL_RECURSIVE_HELPER_SOURCE: &str = r#"
package fixture

var recurse bool

func even() {
    if recurse {
        odd()
    }
}

func odd() {
    if recurse {
        even()
    }
}

func callerOne() { even() }
func callerTwo() { even() }
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

fn procedure_handle_named(
    graph: &SemanticGraph,
    name: &str,
) -> brokk_bifrost::analyzer::semantic::ProcedureHandle {
    let procedure = graph
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
        .unwrap_or_else(|| panic!("fixture missing procedure {name}"));
    graph
        .artifact()
        .procedure_handle(procedure.id())
        .unwrap_or_else(|| panic!("fixture procedure {name} has no live handle"))
}

fn protocol() -> CompiledProtocol {
    ProtocolSpec::from_json(RESOURCE_LIFECYCLE)
        .expect("protocol fixture should parse")
        .compile()
        .expect("protocol fixture should compile")
}

fn observable_lifecycle_protocol() -> CompiledProtocol {
    observable_lifecycle_protocol_with_incomplete_analysis(ProtocolUncertaintyBehavior::Abstain)
}

fn observable_lifecycle_protocol_with_incomplete_analysis(
    incomplete_analysis: ProtocolUncertaintyBehavior,
) -> CompiledProtocol {
    observable_lifecycle_spec_with_incomplete_analysis(incomplete_analysis)
        .compile()
        .unwrap()
}

fn observable_lifecycle_spec_with_incomplete_analysis(
    incomplete_analysis: ProtocolUncertaintyBehavior,
) -> ProtocolSpec {
    let mut spec = ProtocolSpec::from_json(RESOURCE_LIFECYCLE).unwrap();
    spec.states.push("used".to_owned());
    for transition in &mut spec.transitions {
        if transition.from == "open" && transition.on == "use" {
            transition.to = "used".to_owned();
        } else if transition.from == "open" && transition.on == "close" {
            transition.from = "used".to_owned();
        }
    }
    for event in &mut spec.events {
        if matches!(event.id.as_str(), "use" | "close") {
            event.observation.occurrence = ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AtMatch,
            };
        }
    }
    spec.semantics.uncertainty.incomplete_analysis = incomplete_analysis;
    spec
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

fn complete_java_fixture(
    project: &BuiltInlineTestProject,
    analyzer: &WorkspaceAnalyzer,
    swap_use_and_close: bool,
) -> ClientFixture {
    complete_java_fixture_with_close_quality(
        project,
        analyzer,
        swap_use_and_close,
        TypestateBindingQuality::proven_unique(),
    )
}

fn complete_java_fixture_with_close_quality(
    project: &BuiltInlineTestProject,
    analyzer: &WorkspaceAnalyzer,
    swap_use_and_close: bool,
    close_quality: TypestateBindingQuality,
) -> ClientFixture {
    let graph = SemanticGraph::materialize(project, analyzer, "src/LifecycleFixture.java");
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Method
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("lifecycle")
        })
        .expect("Java lifecycle procedure");
    let root = graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("Java lifecycle handle");
    let use_call = call_containing(procedure, JAVA_CONFORMANCE_SOURCE, "use(alias)");
    let close_call = call_containing(procedure, JAVA_CONFORMANCE_SOURCE, "close(alias)");
    let use_call_handle = root.call_site_handle(use_call.id).expect("Java use call");
    let close_call_handle = root
        .call_site_handle(close_call.id)
        .expect("Java close call");
    let subject_object = AbstractObject::new(
        AccessPathRoot::Value(
            root.value_handle(close_call.arguments[0].value)
                .expect("Java aliased close argument"),
        ),
        ObjectCardinality::Singleton,
    )
    .expect("Java lifecycle subject");
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &subject_object);
    let entry = root
        .point_handle(procedure.entry_point())
        .expect("Java lifecycle entry");
    let exit = root
        .point_handle(procedure.normal_exit_point())
        .expect("Java lifecycle exit");
    let use_point = root.point_handle(use_call.point).expect("Java use point");
    let close_point = root
        .point_handle(close_call.point)
        .expect("Java close point");
    let context = TypestateBindingContext::root();
    let exact = TypestateBindingQuality::proven_unique();
    let protocol = if close_quality.multiplicity().is_ambiguous() {
        let mut spec = observable_lifecycle_spec_with_incomplete_analysis(
            ProtocolUncertaintyBehavior::Abstain,
        );
        spec.events
            .iter_mut()
            .find(|event| event.id == "close")
            .expect("close event")
            .observation
            .occurrence = ProtocolEventOccurrence::Endpoint {
            phase: ProtocolObservationPhase::BeforeCall,
        };
        spec.compile().expect("ambiguous Java protocol")
    } else {
        observable_lifecycle_protocol()
    };
    let (use_site, close_site) = if swap_use_and_close {
        (close_point.clone(), use_point.clone())
    } else {
        (use_point.clone(), close_point.clone())
    };
    let event = |name: &str, point| {
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new(name).unwrap(),
            subject_key.clone(),
            TypestateObservationSite::program_point(point, context.clone()),
            0,
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )
    };
    let close_binding = if close_quality.multiplicity().is_ambiguous() {
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            subject_key.clone(),
            TypestateObservationSite::call_site(close_call_handle.clone(), context.clone()),
            0,
            TypestateObjectRole::Argument,
            close_quality,
        )
    } else {
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            subject_key.clone(),
            TypestateObservationSite::program_point(close_site, context.clone()),
            0,
            TypestateObjectRole::MatchedValue,
            close_quality,
        )
    };
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            subject_class.clone(),
            subject_object.clone(),
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
            event("use", use_site),
            close_binding,
        ],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
            subject_key.clone(),
            TypestateObservationSite::program_point(exit.clone(), context),
            TypestateObjectRole::CurrentObject,
            exact,
        )],
    )
    .expect("complete Java lifecycle binding plan");
    ClientFixture {
        protocol,
        bindings,
        subject_key,
        subject_class,
        subject_object,
        root,
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

fn reusable_semantic_summary_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
) -> SemanticProcedureSummary {
    let procedure = ProcedureSummaryKey::try_new(reusable_semantic_identity_for(root), &[], None)
        .expect("typestate summary fixture key is valid");
    SemanticProcedureSummary::try_new(
        procedure,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        SummaryCompleteness::Complete,
    )
    .expect("typestate fixture semantic summary is valid")
}

fn reusable_semantic_identity_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
) -> ProcedureSummaryIdentity {
    reusable_semantic_identity_with_behavior_for(
        root,
        SummaryBehaviorKey::hash_bytes(b"compiled-protocol-semantics"),
    )
}

fn reusable_semantic_identity_with_behavior_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    behavior: SummaryBehaviorKey,
) -> ProcedureSummaryIdentity {
    reusable_semantic_identity_with_context_and_behavior_for(
        root,
        SummaryContextKey::hash_bytes(b"root-context"),
        behavior,
    )
}

fn reusable_semantic_identity_with_context_and_behavior_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    context: SummaryContextKey,
    behavior: SummaryBehaviorKey,
) -> ProcedureSummaryIdentity {
    ProcedureSummaryIdentity::new(
        root.artifact().key().clone(),
        root.semantics().locator().declaration().clone(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"typestate-summary-client-v1"),
        context,
        behavior,
        SummaryOrigin::Inferred,
    )
}

fn reusable_semantic_summary_with_behavior_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    behavior: SummaryBehaviorKey,
) -> SemanticProcedureSummary {
    let key = ProcedureSummaryKey::try_new(
        reusable_semantic_identity_with_behavior_for(root, behavior),
        &[],
        None,
    )
    .unwrap();
    SemanticProcedureSummary::try_new(
        key,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        SummaryCompleteness::Complete,
    )
    .unwrap()
}

fn reusable_semantic_summary_with_context_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    context: SummaryContextKey,
) -> SemanticProcedureSummary {
    let key = ProcedureSummaryKey::try_new(
        reusable_semantic_identity_with_context_and_behavior_for(
            root,
            context,
            SummaryBehaviorKey::hash_bytes(b"compiled-protocol-semantics"),
        ),
        &[],
        None,
    )
    .unwrap();
    SemanticProcedureSummary::try_new(
        key,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        SummaryCompleteness::Complete,
    )
    .unwrap()
}

fn reusable_semantic_summary_with_dependencies_for(
    root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
    dependencies: &[&SemanticProcedureSummary],
) -> SemanticProcedureSummary {
    let dependencies = dependencies
        .iter()
        .map(|summary| SummaryDependencyKey::complete(summary.key().clone()))
        .collect::<Vec<_>>();
    let key =
        ProcedureSummaryKey::try_new(reusable_semantic_identity_for(root), &dependencies, None)
            .unwrap();
    let effects = dependencies
        .iter()
        .enumerate()
        .map(|(index, dependency)| {
            SummaryEffect::new(
                SummaryEffectKey::Call {
                    event: SummaryEventKey::hash_bytes(index.to_le_bytes()),
                    callee: Box::new(dependency.clone()),
                },
                SummaryEvidence::proven_complete(),
            )
        })
        .collect();
    SemanticProcedureSummary::try_new(
        key,
        Vec::new(),
        effects,
        dependencies,
        SummaryCompleteness::Complete,
    )
    .unwrap()
}

fn reusable_recursive_semantic_summaries_for(
    procedures: &[brokk_bifrost::analyzer::semantic::ProcedureHandle],
    edges: &[(usize, usize)],
) -> Vec<SemanticProcedureSummary> {
    let identities = procedures
        .iter()
        .map(reusable_semantic_identity_for)
        .collect::<Vec<_>>();
    let recursive_edges = edges
        .iter()
        .map(|(source, target)| {
            SummaryRecursiveEdge::new(identities[*source].clone(), identities[*target].clone())
        })
        .collect::<Vec<_>>();
    let group = SummaryRecursiveGroupKey::from_closure(&identities, &recursive_edges, &[])
        .expect("recursive typestate fixture forms an exact SCC");
    procedures
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let dependencies = edges
                .iter()
                .filter(|(source, _)| *source == index)
                .map(|(_, target)| SummaryDependencyKey::recursive(identities[*target].clone()))
                .collect::<Vec<_>>();
            let effects = edges
                .iter()
                .filter(|(source, _)| *source == index)
                .zip(dependencies.iter())
                .map(|((source, target), dependency)| {
                    SummaryEffect::new(
                        SummaryEffectKey::Call {
                            event: SummaryEventKey::hash_bytes([
                                u8::try_from(*source).unwrap(),
                                u8::try_from(*target).unwrap(),
                            ]),
                            callee: Box::new(dependency.clone()),
                        },
                        SummaryEvidence::proven_complete(),
                    )
                })
                .collect::<Vec<_>>();
            let key =
                ProcedureSummaryKey::try_new(identities[index].clone(), &dependencies, Some(group))
                    .expect("recursive typestate key");
            SemanticProcedureSummary::try_new(
                key,
                Vec::new(),
                effects,
                dependencies,
                SummaryCompleteness::Complete,
            )
            .expect("recursive typestate semantic summary")
        })
        .collect()
}

fn reusable_semantic_summary(fixture: &ClientFixture) -> SemanticProcedureSummary {
    reusable_semantic_summary_for(&fixture.root)
}

fn reusable_protocol_key(fixture: &ClientFixture) -> ProtocolSummaryKey {
    let semantic_summary = reusable_semantic_summary(fixture);
    ProtocolSummaryKey::try_from_semantic_summary(
        &semantic_summary,
        fixture.protocol.hash(),
        fixture.bindings.summary_hash_for(
            fixture.root.artifact().key(),
            fixture.root.semantics().locator().declaration(),
        ),
        Vec::new(),
    )
    .expect("complete semantic summary can brand the protocol relation")
}

fn reusable_solve(
    fixture: &ClientFixture,
    analyzer: &WorkspaceAnalyzer,
    repository: &mut CompleteProtocolSummaryRepository,
) -> Result<ProtocolSummarySolveResult, ProtocolSummarySolveError> {
    let semantic_summary = reusable_semantic_summary(fixture);
    let semantic_summaries = ProtocolSemanticSummarySet::try_new(vec![&semantic_summary])
        .expect("fixture semantic set is exact");
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_typestate_with_reusable_summaries(
        &fixture.root,
        &[],
        &analyzer.icfg_provider(),
        &fixture.protocol,
        &fixture.bindings,
        &semantic_summaries,
        repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
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
    edge: DataflowEdge<'_, TypestateFact>,
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
fn complete_protocol_summary_reuses_canonical_outcomes_and_effects() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/LifecycleFixture.java", JAVA_CONFORMANCE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = complete_java_fixture(&project, &analyzer, false);
    let mut repository = CompleteProtocolSummaryRepository::default();

    let computed = reusable_solve(&fixture, &analyzer, &mut repository)
        .expect("complete typestate solve should publish a protocol summary");
    assert!(!computed.was_reused());
    assert!(computed.computed_result().is_complete());
    assert_eq!(repository.len(), 1);
    let computed_application = computed
        .application()
        .expect("complete solve has a projected application");
    assert!(computed_application.outcomes().iter().all(|outcome| {
        outcome.evidence().has_proven_complete_path()
            && ProtocolFactKey::from_live(outcome.fact(), &fixture.protocol, &fixture.bindings)
                .is_ok_and(|fact| &fact == outcome.stable_fact())
    }));
    assert!(
        computed_application
            .effects()
            .iter()
            .any(|effect| { matches!(effect.stable_fact(), ProtocolFactKey::NonViolation { .. }) })
    );

    let expected = computed_application.clone();
    let reused = reusable_solve(&fixture, &analyzer, &mut repository)
        .expect("the exact complete protocol summary should remain valid");
    assert!(!reused.was_reused());
    assert!(reused.computed_result().is_complete());
    assert_eq!(reused.application(), Some(&expected));
    assert_eq!(repository.len(), 1);
}

#[test]
fn two_callers_reuse_one_helper_protocol_summary_inside_tabulation() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/SharedHelperFixture.java", TWO_CALLER_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/SharedHelperFixture.java");
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
            .unwrap_or_else(|| panic!("two-caller fixture missing {name}"))
    };
    let helper = procedure("helper");
    let caller_one = procedure("callerOne");
    let caller_two = procedure("callerTwo");
    let helper_handle = graph
        .artifact()
        .procedure_handle(helper.id())
        .expect("helper handle");
    let caller_one_handle = graph
        .artifact()
        .procedure_handle(caller_one.id())
        .expect("caller one handle");
    let caller_two_handle = graph
        .artifact()
        .procedure_handle(caller_two.id())
        .expect("caller two handle");
    let use_call = call_containing(helper, TWO_CALLER_HELPER_SOURCE, "use(resource)");
    let close_call = call_containing(helper, TWO_CALLER_HELPER_SOURCE, "close(resource)");
    let helper_entry = helper_handle
        .point_handle(helper.entry_point())
        .expect("helper entry");
    let helper_exit = helper_handle
        .point_handle(helper.normal_exit_point())
        .expect("helper normal exit");
    let helper_port =
        ProcedurePortHandle::parameter(helper_handle.clone(), 0).expect("helper parameter port");
    let subject_object = AbstractObject::new(
        AccessPathRoot::ProcedurePort(helper_port),
        ObjectCardinality::Singleton,
    )
    .expect("helper formal subject");
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &subject_object);
    let context = TypestateBindingContext::root();
    let exact = TypestateBindingQuality::proven_unique();
    let mut protocol_spec =
        observable_lifecycle_spec_with_incomplete_analysis(ProtocolUncertaintyBehavior::Abstain);
    protocol_spec.terminal_expectations = vec![ProtocolTerminalExpectationSpec {
        id: "helper-exit-unallocated".into(),
        on: ProtocolTerminalObservationSpec::Event {
            observation: ProtocolObservationSpec {
                occurrence: ProtocolEventOccurrence::ProcedureExit {
                    kind: ProtocolProcedureExitKind::Normal,
                },
            },
        },
        expected_states: vec!["unallocated".into()],
    }];
    let protocol = protocol_spec.compile().expect("helper terminal protocol");
    let event = |name: &str, point: brokk_bifrost::analyzer::semantic::ProgramPointHandle| {
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new(name).unwrap(),
            subject_key.clone(),
            TypestateObservationSite::program_point(point, context.clone()),
            0,
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )
    };
    let subjects = vec![BoundTypestateSubjectSpec::new(
        subject_class,
        subject_object,
        exact.clone(),
    )];
    let seeds = vec![TypestateInitialSeedSpec::new(
        subject_key.clone(),
        ProtocolStateKey::new("open").unwrap(),
        TypestateObservationSite::program_point(helper_entry.clone(), context.clone()),
        TypestateObjectRole::FormalArgument { ordinal: 0 },
        exact.clone(),
    )];
    let events = vec![
        event(
            "use",
            helper_handle
                .point_handle(use_call.point)
                .expect("helper use point"),
        ),
        event(
            "close",
            helper_handle
                .point_handle(close_call.point)
                .expect("helper close point"),
        ),
    ];
    let terminals = vec![TypestateTerminalBindingSpec::new(
        ProtocolExpectationKey::new("helper-exit-unallocated").unwrap(),
        subject_key.clone(),
        TypestateObservationSite::program_point(helper_exit, context),
        TypestateObjectRole::CurrentObject,
        exact.clone(),
    )];
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        subjects.clone(),
        seeds.clone(),
        events.clone(),
        terminals.clone(),
    )
    .expect("two-caller helper bindings");
    let unrelated_object = AbstractObject::new(
        AccessPathRoot::ProcedurePort(ProcedurePortHandle::normal_return(
            caller_two_handle.clone(),
        )),
        ObjectCardinality::Singleton,
    )
    .unwrap();
    let mut extended_subjects = subjects;
    extended_subjects.push(BoundTypestateSubjectSpec::new(
        TypestateSubjectClassKey::new("unrelated-caller-two").unwrap(),
        unrelated_object,
        exact,
    ));
    let bindings_with_unrelated_caller_subject =
        TypestateBindingPlan::try_new(&protocol, extended_subjects, seeds, events, terminals)
            .expect("caller-only subjects do not alter helper propagation bindings");
    assert_ne!(
        bindings.hash(),
        bindings_with_unrelated_caller_subject.hash(),
        "the full live binding layout changes"
    );
    assert_eq!(
        bindings.summary_hash_for(
            helper_handle.artifact().key(),
            helper_handle.semantics().locator().declaration(),
        ),
        bindings_with_unrelated_caller_subject.summary_hash_for(
            helper_handle.artifact().key(),
            helper_handle.semantics().locator().declaration(),
        ),
        "caller-only subjects must not invalidate the helper contract"
    );
    let helper_semantic = reusable_semantic_summary_for(&helper_handle);
    let caller_one_semantic =
        reusable_semantic_summary_with_dependencies_for(&caller_one_handle, &[&helper_semantic]);
    let caller_two_semantic =
        reusable_semantic_summary_with_dependencies_for(&caller_two_handle, &[&helper_semantic]);
    let semantic_summaries = ProtocolSemanticSummarySet::try_new(vec![
        &helper_semantic,
        &caller_one_semantic,
        &caller_two_semantic,
    ])
    .expect("two-caller semantic summaries are exact");
    let mut repository = CompleteProtocolSummaryRepository::default();

    let solve = |root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
                 bindings: &TypestateBindingPlan,
                 semantic_summaries: &ProtocolSemanticSummarySet<'_>,
                 repository: &mut CompleteProtocolSummaryRepository| {
        let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        solve_typestate_with_reusable_summaries(
            root,
            &[],
            &analyzer.icfg_provider(),
            &protocol,
            bindings,
            semantic_summaries,
            repository,
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .expect("two-caller reusable solve")
    };

    let first = solve(
        &caller_one_handle,
        &bindings,
        &semantic_summaries,
        &mut repository,
    );
    assert!(!first.was_reused());
    assert!(
        first.published_summaries() == 1,
        "status={:?} published={} entries={}",
        first.cache_status(),
        first.published_summaries(),
        repository.len()
    );
    assert!(
        first.application().is_none(),
        "a caller artifact is not published until nested effects can be flattened exactly"
    );
    let mut first_outcomes = first
        .computed_result()
        .result()
        .end_summaries()
        .iter()
        .filter(|summary| summary.entry().procedure() == &caller_one_handle)
        .map(|summary| {
            let fact = first
                .computed_result()
                .result()
                .fact(summary.exit_fact())
                .unwrap();
            ProtocolFactKey::from_live(*fact, &protocol, &bindings).unwrap()
        })
        .collect::<Vec<_>>();
    first_outcomes.sort_unstable();
    first_outcomes.dedup();
    let first_findings = collect_summary_findings(&protocol, &bindings, first.computed_result())
        .expect("first caller findings");
    assert_eq!(first_findings.findings().len(), 1);

    let helper_alternate_context = reusable_semantic_summary_with_context_for(
        &helper_handle,
        SummaryContextKey::hash_bytes(b"alternate-helper-context"),
    );
    assert_eq!(
        ProtocolSemanticSummarySet::try_new(vec![
            &helper_semantic,
            &helper_alternate_context,
            &caller_two_semantic,
        ])
        .unwrap_err(),
        ProtocolSummaryError::AmbiguousSemanticSummary,
        "context-sensitive summaries fail closed until invocations carry an exact context key"
    );
    let second = solve(
        &caller_two_handle,
        &bindings_with_unrelated_caller_subject,
        &semantic_summaries,
        &mut repository,
    );
    assert!(second.was_reused());
    assert!(
        second
            .computed_result()
            .result()
            .metrics()
            .reusable_summary_hits
            > 0
    );
    assert!(
        second
            .computed_result()
            .result()
            .witness_retention_truncated(),
        "reused protocol rows never retain fabricated witness paths"
    );
    assert!(second.application().is_none());
    let mut second_outcomes = second
        .computed_result()
        .result()
        .end_summaries()
        .iter()
        .filter(|summary| summary.entry().procedure() == &caller_two_handle)
        .map(|summary| {
            let fact = second
                .computed_result()
                .result()
                .fact(summary.exit_fact())
                .unwrap();
            ProtocolFactKey::from_live(*fact, &protocol, &bindings_with_unrelated_caller_subject)
                .unwrap()
        })
        .collect::<Vec<_>>();
    second_outcomes.sort_unstable();
    second_outcomes.dedup();
    assert_eq!(second_outcomes, first_outcomes);
    let second_findings = collect_summary_findings(
        &protocol,
        &bindings_with_unrelated_caller_subject,
        second.computed_result(),
    )
    .expect("reused helper findings");
    assert_eq!(second_findings.findings().len(), 1);
    let first_finding = &first_findings.findings()[0];
    let second_finding = &second_findings.findings()[0];
    assert_eq!(second_finding.kind(), first_finding.kind());
    assert_eq!(second_finding.certainty(), first_finding.certainty());
    assert_eq!(second_finding.evidence(), first_finding.evidence());
    assert_eq!(second_finding.site(), first_finding.site());
    assert!(
        second_finding
            .witnesses()
            .iter()
            .all(|witness| witness.witness().retention_truncated()),
        "cached callee effects expose explicit omission markers, not fabricated paths"
    );
    let root_end = second
        .computed_result()
        .result()
        .end_summaries()
        .iter()
        .find(|summary| summary.entry().procedure() == &caller_two_handle)
        .expect("second caller has a query-local end summary");
    let root_quality = root_end
        .path_qualities()
        .iter()
        .next()
        .expect("root end summary retains a path quality");
    let root_witness = second
        .computed_result()
        .result()
        .witness_for_end_summary(
            root_end,
            root_quality,
            WitnessReconstructionLimits::default(),
        )
        .expect("caller-local witness survives helper reuse");
    assert!(!root_witness.steps().is_empty());
    assert!(root_witness.truncated());
    assert!(!root_witness.retention_truncated());
    assert!(root_witness.omitted_steps_lower_bound() > 0);

    let changed_helper = reusable_semantic_summary_with_behavior_for(
        &helper_handle,
        SummaryBehaviorKey::hash_bytes(b"changed-protocol-call-semantics"),
    );
    let changed_caller_two =
        reusable_semantic_summary_with_dependencies_for(&caller_two_handle, &[&changed_helper]);
    let changed_semantics =
        ProtocolSemanticSummarySet::try_new(vec![&changed_helper, &changed_caller_two]).unwrap();
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let invalidated = solve_typestate_with_reusable_summaries(
        &caller_two_handle,
        &[],
        &analyzer.icfg_provider(),
        &protocol,
        &bindings_with_unrelated_caller_subject,
        &changed_semantics,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap();
    assert!(
        !invalidated.was_reused(),
        "changed semantic-summary behavior must miss the old helper artifact"
    );
}

#[test]
fn direct_recursive_protocol_summary_projects_and_reuses_after_atomic_publication() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("src/direct_recursive.go", SUMMARY_RECURSIVE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/direct_recursive.go");
    let helper = procedure_handle_named(&graph, "helper");
    let caller_one = procedure_handle_named(&graph, "callerOne");
    let caller_two = procedure_handle_named(&graph, "callerTwo");
    let recursive =
        reusable_recursive_semantic_summaries_for(std::slice::from_ref(&helper), &[(0, 0)]);
    let caller_one_semantic =
        reusable_semantic_summary_with_dependencies_for(&caller_one, &[&recursive[0]]);
    let caller_two_semantic =
        reusable_semantic_summary_with_dependencies_for(&caller_two, &[&recursive[0]]);
    let semantic_summaries = ProtocolSemanticSummarySet::try_new(vec![
        &recursive[0],
        &caller_one_semantic,
        &caller_two_semantic,
    ])
    .unwrap();
    let protocol = exit_protocol();
    let bindings =
        TypestateBindingPlan::try_new(&protocol, Vec::new(), Vec::new(), Vec::new(), Vec::new())
            .unwrap();
    let mut repository = CompleteProtocolSummaryRepository::default();
    let solve = |root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
                 repository: &mut CompleteProtocolSummaryRepository| {
        let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        solve_typestate_with_reusable_summaries(
            root,
            &[],
            &analyzer.icfg_provider(),
            &protocol,
            &bindings,
            &semantic_summaries,
            repository,
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .unwrap()
    };
    let first = solve(&caller_one, &mut repository);
    assert!(!first.was_reused());
    assert!(
        first.published_summaries() == 1,
        "status={:?} published={} entries={} bindings={} complete={} termination={:?} coverage={:?}",
        first.cache_status(),
        first.published_summaries(),
        repository.len(),
        first.computed_result().bindings_summary_complete(),
        first.computed_result().result().is_complete(),
        first.computed_result().result().termination(),
        first.computed_result().result().coverage()
    );
    assert_eq!(
        first.computed_result().result().termination(),
        SolverTermination::FixedPoint
    );
    let second = solve(&caller_two, &mut repository);
    assert!(second.was_reused());
    assert_eq!(
        second.computed_result().result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(
        first.computed_result().result().facts(),
        second.computed_result().result().facts()
    );
    assert_eq!(repository.len(), 1);
}

#[test]
fn mutual_recursive_protocol_summaries_project_and_reuse_atomically() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("src/mutual_recursive.go", MUTUAL_RECURSIVE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/mutual_recursive.go");
    let even = procedure_handle_named(&graph, "even");
    let odd = procedure_handle_named(&graph, "odd");
    let caller_one = procedure_handle_named(&graph, "callerOne");
    let caller_two = procedure_handle_named(&graph, "callerTwo");
    let recursive =
        reusable_recursive_semantic_summaries_for(&[even.clone(), odd.clone()], &[(0, 1), (1, 0)]);
    let caller_one_semantic =
        reusable_semantic_summary_with_dependencies_for(&caller_one, &[&recursive[0]]);
    let caller_two_semantic =
        reusable_semantic_summary_with_dependencies_for(&caller_two, &[&recursive[0]]);
    let semantic_summaries = ProtocolSemanticSummarySet::try_new(vec![
        &recursive[0],
        &recursive[1],
        &caller_one_semantic,
        &caller_two_semantic,
    ])
    .unwrap();
    let protocol = exit_protocol();
    let exact = TypestateBindingQuality::proven_unique();
    let even_object = AbstractObject::new(
        AccessPathRoot::ProcedurePort(ProcedurePortHandle::normal_return(even.clone())),
        ObjectCardinality::Singleton,
    )
    .unwrap();
    let odd_object = AbstractObject::new(
        AccessPathRoot::ProcedurePort(ProcedurePortHandle::normal_return(odd.clone())),
        ObjectCardinality::Singleton,
    )
    .unwrap();
    let even_class = TypestateSubjectClassKey::new("even-state").unwrap();
    let odd_class = TypestateSubjectClassKey::new("odd-state").unwrap();
    let even_subject = TypestateSubjectKey::for_object(even_class.clone(), &even_object);
    let odd_subject = TypestateSubjectKey::for_object(odd_class.clone(), &odd_object);
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![
            BoundTypestateSubjectSpec::new(even_class, even_object, exact.clone()),
            BoundTypestateSubjectSpec::new(odd_class, odd_object, exact.clone()),
        ],
        vec![
            TypestateInitialSeedSpec::new(
                even_subject,
                ProtocolStateKey::new("open").unwrap(),
                TypestateObservationSite::program_point(
                    even.point_handle(even.semantics().entry_point()).unwrap(),
                    TypestateBindingContext::root(),
                ),
                TypestateObjectRole::CurrentObject,
                exact.clone(),
            ),
            TypestateInitialSeedSpec::new(
                odd_subject,
                ProtocolStateKey::new("open").unwrap(),
                TypestateObservationSite::program_point(
                    odd.point_handle(odd.semantics().entry_point()).unwrap(),
                    TypestateBindingContext::root(),
                ),
                TypestateObjectRole::CurrentObject,
                exact,
            ),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    assert_ne!(
        bindings.summary_hash_for(
            even.artifact().key(),
            even.semantics().locator().declaration(),
        ),
        bindings.summary_hash_for(
            odd.artifact().key(),
            odd.semantics().locator().declaration(),
        ),
        "the SCC fixture must exercise distinct member-local binding contracts"
    );
    let mut repository = CompleteProtocolSummaryRepository::default();
    let solve = |root: &brokk_bifrost::analyzer::semantic::ProcedureHandle,
                 repository: &mut CompleteProtocolSummaryRepository| {
        let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
        let mut solver_budget = SolverBudget::default();
        let mut semantic_budget = SemanticBudget::default();
        solve_typestate_with_reusable_summaries(
            root,
            &[],
            &analyzer.icfg_provider(),
            &protocol,
            &bindings,
            &semantic_summaries,
            repository,
            &mut semantic_budget,
            &mut DataflowRequest::new(&mut solver_budget, &cancellation),
        )
        .unwrap()
    };
    let first = solve(&caller_one, &mut repository);
    assert!(!first.was_reused());
    assert!(
        first.published_summaries() == 2,
        "status={:?} published={} entries={}",
        first.cache_status(),
        first.published_summaries(),
        repository.len()
    );
    let entries_after_first = repository.len();
    assert_eq!(entries_after_first, 2);
    let second = solve(&caller_two, &mut repository);
    assert!(second.was_reused());
    assert_eq!(
        second.computed_result().result().termination(),
        SolverTermination::FixedPoint
    );
    assert_eq!(repository.len(), entries_after_first);
}

#[test]
fn protocol_summary_key_misses_when_binding_semantics_change() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/LifecycleFixture.java", JAVA_CONFORMANCE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let first = complete_java_fixture(&project, &analyzer, false);
    let changed = complete_java_fixture(&project, &analyzer, true);
    assert_ne!(
        reusable_protocol_key(&first),
        reusable_protocol_key(&changed)
    );

    let mut repository = CompleteProtocolSummaryRepository::default();
    let first_result = reusable_solve(&first, &analyzer, &mut repository).unwrap();
    let changed_result = reusable_solve(&changed, &analyzer, &mut repository).unwrap();
    assert!(!first_result.was_reused());
    assert!(!changed_result.was_reused());
    assert_eq!(repository.len(), 2);
}

#[test]
fn protocol_summary_requires_the_exact_entry_fact_manifest() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/LifecycleFixture.java", JAVA_CONFORMANCE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = complete_java_fixture(&project, &analyzer, false);
    let key = reusable_protocol_key(&fixture);
    let mut repository = CompleteProtocolSummaryRepository::default();
    reusable_solve(&fixture, &analyzer, &mut repository).unwrap();
    let summary = repository.get(&key).expect("root summary was published");
    let semantic = reusable_semantic_summary(&fixture);
    let semantic_summaries = ProtocolSemanticSummarySet::try_new(vec![&semantic]).unwrap();
    let problem = TypestateFlowProblem::try_new(&fixture.protocol, &fixture.bindings).unwrap();
    let explicit_open = problem
        .state_fact(
            &fixture.subject_key,
            &ProtocolStateKey::new("open").unwrap(),
        )
        .unwrap();

    assert!(matches!(
        summary.apply(
            &[explicit_open],
            &fixture.protocol,
            &fixture.bindings,
            &semantic_summaries,
        ),
        Err(ProtocolSummaryError::EntryFactCoverageMismatch)
    ));

    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let expanded_manifest = solve_typestate_with_reusable_summaries(
        &fixture.root,
        &[explicit_open],
        &analyzer.icfg_provider(),
        &fixture.protocol,
        &fixture.bindings,
        &semantic_summaries,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("an overlapping optional-cache manifest cannot fail the analysis");
    assert!(expanded_manifest.computed_result().is_complete());
}

#[test]
fn protocol_and_repository_limits_fail_closed_for_reuse_but_not_analysis() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/LifecycleFixture.java", JAVA_CONFORMANCE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let fixture = complete_java_fixture(&project, &analyzer, false);
    let mut repository =
        CompleteProtocolSummaryRepository::with_limits(ProtocolSummaryRepositoryLimits {
            max_entries: 0,
            max_bytes: usize::MAX,
        });
    let result = reusable_solve(&fixture, &analyzer, &mut repository).unwrap();
    assert!(result.computed_result().is_complete());
    assert_eq!(
        result.cache_status(),
        ProtocolSummaryCacheStatus::CapacityExceeded
    );
    assert!(repository.is_empty());

    let mut changed_spec =
        observable_lifecycle_spec_with_incomplete_analysis(ProtocolUncertaintyBehavior::Abstain);
    changed_spec.semantics.analysis_mode = ProtocolAnalysisMode::Must;
    let changed_protocol = changed_spec.compile().unwrap();
    let key = reusable_protocol_key(&fixture);
    let mut normal_repository = CompleteProtocolSummaryRepository::default();
    reusable_solve(&fixture, &analyzer, &mut normal_repository).unwrap();
    let summary = normal_repository.get(&key).unwrap();
    let semantic = reusable_semantic_summary(&fixture);
    let semantic_summaries = ProtocolSemanticSummarySet::try_new(vec![&semantic]).unwrap();
    assert!(matches!(
        summary.apply(
            &[],
            &changed_protocol,
            &fixture.bindings,
            &semantic_summaries,
        ),
        Err(ProtocolSummaryError::KeyProtocolMismatch)
    ));
}

#[test]
fn modeled_uncertainty_remains_publishable_and_canonical() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/LifecycleFixture.java", JAVA_CONFORMANCE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let ambiguous = TypestateBindingQuality::new(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 2).unwrap(),
    );
    let fixture = complete_java_fixture_with_close_quality(&project, &analyzer, false, ambiguous);
    let mut repository = CompleteProtocolSummaryRepository::default();
    let result = reusable_solve(&fixture, &analyzer, &mut repository).unwrap();

    assert!(!result.computed_result().is_complete());
    assert!(result.computed_result().is_summary_publication_complete());
    assert_eq!(result.cache_status(), ProtocolSummaryCacheStatus::Published);
    assert_eq!(repository.len(), 1);
    assert!(result.application().is_some_and(|application| {
        application
            .effects()
            .iter()
            .any(|effect| match effect.stable_fact() {
                ProtocolFactKey::State { uncertainty, .. } => !uncertainty.values().is_empty(),
                _ => false,
            })
    }));
}

#[test]
fn incomplete_bindings_never_publish_a_protocol_summary() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let partial = TypestateBindingQuality::new(
        ProofStatus::Proven,
        EvidenceCompleteness::Partial("fixture binding is incomplete".into()),
        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1).unwrap(),
    );
    let fixture = fixture_from(
        &project,
        &analyzer,
        partial,
        TypestateBindingQuality::proven_unique(),
        false,
        false,
    );
    let mut repository = CompleteProtocolSummaryRepository::default();

    let result = reusable_solve(&fixture, &analyzer, &mut repository)
        .expect("incomplete analysis remains a valid uncached result");
    assert!(!result.was_reused());
    assert!(!result.computed_result().is_complete());
    assert!(result.application().is_none());
    assert!(repository.is_empty());
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
fn exceptional_return_event_executes_on_matched_return_flow() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/ExceptionalReturn.ts", EXCEPTIONAL_RETURN_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ExceptionalReturn.ts");
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
            .unwrap_or_else(|| panic!("exceptional-return fixture missing {name}"))
    };
    let lifecycle = procedure("lifecycle");
    let fail = procedure("fail");
    let lifecycle_handle = graph
        .artifact()
        .procedure_handle(lifecycle.id())
        .expect("lifecycle handle");
    let fail_handle = graph
        .artifact()
        .procedure_handle(fail.id())
        .expect("fail handle");
    let fail_call = call_containing(lifecycle, EXCEPTIONAL_RETURN_SOURCE, "fail(resource)");
    let exceptional_continuation = lifecycle_handle
        .point_handle(
            fail_call
                .exceptional_continuation
                .target()
                .expect("fail call exceptional continuation"),
        )
        .expect("exceptional continuation handle");
    let fail_exceptional_exit = fail_handle
        .point_handle(fail.exceptional_exit_point())
        .expect("fail exceptional exit");
    let entry = lifecycle_handle
        .point_handle(lifecycle.entry_point())
        .expect("lifecycle entry");
    let subject_object = AbstractObject::new(
        AccessPathRoot::Value(
            lifecycle_handle
                .value_handle(fail_call.arguments[0].value)
                .expect("fail argument"),
        ),
        ObjectCardinality::Singleton,
    )
    .expect("exceptional-return subject");
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &subject_object);

    let mut spec = ProtocolSpec::from_json(RESOURCE_LIFECYCLE).unwrap();
    spec.events
        .iter_mut()
        .find(|event| event.id == "close")
        .expect("close event")
        .observation
        .occurrence = ProtocolEventOccurrence::Endpoint {
        phase: ProtocolObservationPhase::AfterExceptionalReturn,
    };
    let protocol = spec.compile().unwrap();
    let exact = TypestateBindingQuality::proven_unique();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            subject_class,
            subject_object,
            exact.clone(),
        )],
        vec![TypestateInitialSeedSpec::new(
            subject_key.clone(),
            ProtocolStateKey::new("open").unwrap(),
            TypestateObservationSite::program_point(entry, TypestateBindingContext::root()),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("close").unwrap(),
            subject_key.clone(),
            TypestateObservationSite::call_site(
                lifecycle_handle
                    .call_site_handle(fail_call.id)
                    .expect("fail call handle"),
                TypestateBindingContext::root(),
            ),
            0,
            TypestateObjectRole::Argument,
            exact,
        )],
        Vec::new(),
    )
    .unwrap();
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
    .expect("exceptional-return typestate summary solve");
    let closed = protocol
        .state_id(&ProtocolStateKey::new("closed").unwrap())
        .unwrap();
    let reached = summary
        .result()
        .reached_at(&exceptional_continuation)
        .find(|reached| {
            summary
                .result()
                .fact(reached.fact())
                .is_some_and(|fact| fact.protocol_state() == Some(closed))
        })
        .expect("close event must execute at the matched exceptional continuation");
    let quality = reached
        .path_qualities()
        .iter()
        .next()
        .expect("reached exceptional state retains path quality");
    let witness = summary
        .result()
        .witness_for_reached(reached, quality, WitnessReconstructionLimits::default())
        .expect("exceptional-return witness");

    assert!(
        witness.steps().iter().any(|step| {
            step.kind() == SummaryWitnessStepKind::Edge(IcfgEdgeKind::ExceptionalReturn)
                && step.source() == &fail_exceptional_exit
                && step.target() == Some(&exceptional_continuation)
        }),
        "witness must cross the callee exceptional exit back to the exact caller continuation"
    );
    assert!(summary.result().metrics().summary_applications > 0);
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
fn proven_exit_event_transitions_a_partially_discovered_subject() {
    let fixture = fixture(TypestateBindingQuality::proven_unique());
    let protocol = exit_protocol();
    let partial_subject = TypestateBindingQuality::new(
        ProofStatus::Proven,
        EvidenceCompleteness::Partial("selector provenance was truncated".into()),
        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1).unwrap(),
    );
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            fixture.subject_class.clone(),
            fixture.subject_object.clone(),
            partial_subject,
        )],
        Vec::new(),
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("finish").unwrap(),
            fixture.subject_key.clone(),
            TypestateObservationSite::program_point(
                fixture.exit.clone(),
                TypestateBindingContext::root(),
            ),
            0,
            TypestateObjectRole::CurrentObject,
            TypestateBindingQuality::proven_unique(),
        )],
        Vec::new(),
    )
    .unwrap();
    let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
    let proven = ProofStatus::Proven;
    let complete = EvidenceCompleteness::Complete;
    let open = problem
        .state_fact(
            &fixture.subject_key,
            &ProtocolStateKey::new("open").unwrap(),
        )
        .unwrap();

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
        open,
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
        ),
        "subject discovery uncertainty must not suppress a proven authored event"
    );
}

#[test]
fn point_seed_at_exit_observes_the_exit_event_once() {
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
    let protocol = exit_protocol();
    let exact = TypestateBindingQuality::proven_unique();
    let exit_site = TypestateObservationSite::program_point(
        fixture.exit.clone(),
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
            ProtocolStateKey::new("open").unwrap(),
            exit_site.clone(),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![TypestateEventBindingSpec::new(
            ProtocolEventKey::new("finish").unwrap(),
            fixture.subject_key.clone(),
            exit_site,
            0,
            TypestateObjectRole::CurrentObject,
            exact,
        )],
        Vec::new(),
    )
    .unwrap();
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let summary = solve_typestate_with_summaries(
        &fixture.root,
        &[],
        &analyzer.icfg_provider(),
        &protocol,
        &bindings,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap();
    let closed = protocol
        .state_id(&ProtocolStateKey::new("closed").unwrap())
        .unwrap();

    assert!(summary.result().reached_at(&fixture.exit).any(|reached| {
        summary
            .result()
            .fact(reached.fact())
            .is_some_and(|fact| fact.protocol_state() == Some(closed))
    }));
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
        PathQuality::UNPROVEN_PARTIAL
    );
}

#[test]
fn one_protocol_runs_equivalent_pre_resolved_typescript_and_java_lifecycles() {
    let protocol = observable_lifecycle_protocol();
    let expected_hash = protocol.hash();

    // TypeScript still retains conservative unresolved-call coverage alongside
    // these source-resolved helpers; Java proves the same ICFG complete.
    for (language, path, source, expected_complete) in [
        (
            Language::TypeScript,
            "src/main.ts",
            TYPE_SCRIPT_CONFORMANCE_SOURCE,
            false,
        ),
        (
            Language::Java,
            "src/LifecycleFixture.java",
            JAVA_CONFORMANCE_SOURCE,
            true,
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
        let exit_rows = summary.result().reached_at(&exit).collect::<Vec<_>>();
        assert!(
            exit_rows.iter().any(|reached| {
                summary
                    .result()
                    .fact(reached.fact())
                    .is_some_and(|fact| fact.protocol_state() == Some(closed))
            }),
            "{language:?} summary solve did not carry the pre-resolved lifecycle through use to closed: {exit_rows:#?}"
        );
        assert!(
            summary.result().reached().iter().all(|reached| {
                summary
                    .result()
                    .fact(reached.fact())
                    .is_none_or(|fact| fact.violation().is_none())
            }),
            "{language:?} lifecycle reached a protocol violation"
        );
        assert!(summary.result().termination().is_fixed_point());
        assert!(summary.bindings_complete());
        assert_eq!(
            summary.result().is_complete(),
            expected_complete,
            "{language:?} summary coverage changed"
        );
        assert_eq!(
            summary.is_complete(),
            expected_complete,
            "{language:?} typestate completeness changed"
        );

        let mut state_outcomes = exit_rows
            .iter()
            .filter_map(|reached| {
                let fact = summary.result().fact(reached.fact())?;
                let state = fact.protocol_state()?;
                let mut qualities = reached
                    .path_qualities()
                    .iter()
                    .map(|quality| (quality.is_proven(), quality.is_complete()))
                    .collect::<Vec<_>>();
                qualities.sort_unstable();
                Some((state, fact.uncertainty(), fact.abstained(), qualities))
            })
            .collect::<Vec<_>>();
        state_outcomes.sort();
        state_outcomes.dedup();
        assert!(
            state_outcomes
                .iter()
                .all(|(state, _, _, _)| *state == closed),
            "{language:?} retained a non-closed exit state: {state_outcomes:#?}"
        );
        assert!(
            state_outcomes
                .iter()
                .any(|(_, uncertainty, abstained, qualities)| {
                    uncertainty.is_empty() && !abstained && qualities.contains(&(true, true))
                })
        );
        if expected_complete {
            assert_eq!(
                state_outcomes.len(),
                1,
                "{language:?} complete dispatch retained a residual outcome"
            );
        } else {
            assert!(
                state_outcomes
                    .iter()
                    .any(|(_, uncertainty, abstained, qualities)| {
                        uncertainty.contains(TypestateUncertainty::UnknownCall)
                            && !abstained
                            && qualities.contains(&(false, false))
                    })
            );
        }
        assert_eq!(protocol.hash(), expected_hash);
    }
}

#[test]
fn recursive_helper_summary_carries_typestate_back_to_the_caller() {
    let protocol = observable_lifecycle_protocol_with_incomplete_analysis(
        ProtocolUncertaintyBehavior::PreserveUncertainty,
    );
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/RecursiveFixture.java", RECURSIVE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/RecursiveFixture.java");
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
            .unwrap_or_else(|| panic!("recursive fixture missing {name}"))
    };
    let lifecycle = procedure("lifecycle");
    let walk = procedure("walk");
    let lifecycle_handle = graph
        .artifact()
        .procedure_handle(lifecycle.id())
        .expect("lifecycle handle");
    let walk_handle = graph
        .artifact()
        .procedure_handle(walk.id())
        .expect("walk handle");
    let walk_call = call_containing(lifecycle, RECURSIVE_HELPER_SOURCE, "walk(resource, 1)");
    let use_call = call_containing(walk, RECURSIVE_HELPER_SOURCE, "use(resource)");
    let close_call = call_containing(walk, RECURSIVE_HELPER_SOURCE, "close(resource)");
    let subject_object = AbstractObject::new(
        AccessPathRoot::Value(
            lifecycle_handle
                .value_handle(walk_call.arguments[0].value)
                .expect("walk argument"),
        ),
        ObjectCardinality::Singleton,
    )
    .expect("recursive fixture subject");
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &subject_object);
    let entry = lifecycle_handle
        .point_handle(lifecycle.entry_point())
        .expect("lifecycle entry");
    let exit = lifecycle_handle
        .point_handle(lifecycle.normal_exit_point())
        .expect("lifecycle normal exit");
    let use_point = walk_handle
        .point_handle(use_call.point)
        .expect("recursive use point");
    let close_point = walk_handle
        .point_handle(close_call.point)
        .expect("recursive close point");
    let context = TypestateBindingContext::root();
    let exact = TypestateBindingQuality::proven_unique();
    let event = |event: &str, point: brokk_bifrost::analyzer::semantic::ProgramPointHandle| {
        TypestateEventBindingSpec::new(
            ProtocolEventKey::new(event).unwrap(),
            subject_key.clone(),
            TypestateObservationSite::program_point(point, context.clone()),
            0,
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
            event("use", use_point),
            event("close", close_point.clone()),
        ],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
            subject_key,
            TypestateObservationSite::program_point(exit.clone(), context),
            TypestateObjectRole::CurrentObject,
            exact,
        )],
    )
    .expect("recursive lifecycle binding plan");
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
    .expect("recursive typestate summary solve");
    let used = protocol
        .state_id(&ProtocolStateKey::new("used").unwrap())
        .unwrap();
    let closed = protocol
        .state_id(&ProtocolStateKey::new("closed").unwrap())
        .unwrap();

    assert!(summary.result().termination().is_fixed_point());
    assert!(summary.result().metrics().summary_applications > 0);
    assert!(summary.result().metrics().reused_entry_contexts > 0);
    let close_rows = summary
        .result()
        .reached_at(&close_point)
        .collect::<Vec<_>>();
    let close_facts = close_rows
        .iter()
        .filter_map(|reached| summary.result().fact(reached.fact()))
        .map(|fact| {
            (
                fact.protocol_state(),
                fact.uncertainty(),
                fact.abstained(),
                fact.violation(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        close_rows.iter().any(|reached| {
            summary
                .result()
                .fact(reached.fact())
                .is_some_and(|fact| fact.protocol_state() == Some(used))
        }),
        "the base-case use transition must return through the recursive summary to the caller continuation: {close_facts:#?}",
    );
    let exit_rows = summary.result().reached_at(&exit).collect::<Vec<_>>();
    let exit_facts = exit_rows
        .iter()
        .filter_map(|reached| summary.result().fact(reached.fact()))
        .map(|fact| {
            (
                fact.protocol_state(),
                fact.uncertainty(),
                fact.abstained(),
                fact.violation(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        exit_rows.iter().any(|reached| {
            summary
                .result()
                .fact(reached.fact())
                .is_some_and(|fact| fact.protocol_state() == Some(closed))
        }),
        "close must transition the recursively returned used state to closed: {exit_facts:#?}",
    );
    assert!(!summary.is_complete());
}

#[test]
fn branch_dependent_close_reports_both_exit_states_and_a_may_finding() {
    let protocol = protocol();
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/BranchFixture.java", BRANCHING_LIFECYCLE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/BranchFixture.java");
    let lifecycle = graph
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
                == Some("lifecycle")
        })
        .expect("branching lifecycle procedure");
    let lifecycle_handle = graph
        .artifact()
        .procedure_handle(lifecycle.id())
        .expect("branching lifecycle handle");
    let close_call = call_containing(lifecycle, BRANCHING_LIFECYCLE_SOURCE, "close(resource)");
    let close_call_handle = lifecycle_handle
        .call_site_handle(close_call.id)
        .expect("branch close call");
    let subject_object = AbstractObject::new(
        AccessPathRoot::Value(
            lifecycle_handle
                .value_handle(close_call.arguments[0].value)
                .expect("branch close argument"),
        ),
        ObjectCardinality::Singleton,
    )
    .expect("branch fixture subject");
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &subject_object);
    let entry = lifecycle_handle
        .point_handle(lifecycle.entry_point())
        .expect("branch lifecycle entry");
    let exit = lifecycle_handle
        .point_handle(lifecycle.normal_exit_point())
        .expect("branch lifecycle normal exit");
    let context = TypestateBindingContext::root();
    let exact = TypestateBindingQuality::proven_unique();
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
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("close").unwrap(),
                subject_key.clone(),
                TypestateObservationSite::call_site(close_call_handle, context.clone()),
                0,
                TypestateObjectRole::Argument,
                exact.clone(),
            ),
        ],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
            subject_key,
            TypestateObservationSite::program_point(exit.clone(), context),
            TypestateObjectRole::CurrentObject,
            exact,
        )],
    )
    .expect("branch lifecycle binding plan");
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
    .expect("branch typestate summary solve");
    let open = protocol
        .state_id(&ProtocolStateKey::new("open").unwrap())
        .unwrap();
    let closed = protocol
        .state_id(&ProtocolStateKey::new("closed").unwrap())
        .unwrap();
    let mut exit_states = summary
        .result()
        .reached_at(&exit)
        .filter_map(|reached| summary.result().fact(reached.fact())?.protocol_state())
        .collect::<Vec<_>>();
    exit_states.sort_unstable();
    exit_states.dedup();

    assert!(summary.result().termination().is_fixed_point());
    assert_eq!(exit_states, vec![closed, open]);
    let report = collect_summary_findings(&protocol, &bindings, &summary).unwrap();
    let terminal = report
        .findings()
        .iter()
        .find(|finding| {
            matches!(
                finding.kind(),
                TypestateFindingKind::TerminalExpectation { .. }
            )
        })
        .expect("open branch produces a terminal finding");
    assert_eq!(terminal.certainty(), TypestateFindingCertainty::May);
    assert!(!terminal.witnesses().is_empty());
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
