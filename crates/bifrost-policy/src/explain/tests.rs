//! Unit tests for the explanation schema and the two adapters.
//!
//! The fixtures build a real analyzer over real source, load real policies,
//! and evaluate them, so the `why` parity test compares against evidence the
//! production evaluator actually retained rather than against a hand-built
//! stand-in.

use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::structural::CodeQueryExecutionLimits;
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, TestProject, TypescriptAnalyzer};

use crate::budget::PolicyBudget;
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::coordinator::PolicyEvaluationInput;
use crate::definition::PolicyAnalysisType;
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::finding::{
    PolicyFindingEvidence, PolicyIncompleteReason, PolicyObligation, PolicyObligationKind,
    PolicyRun, PolicyRunCompletion, PolicySourceLocation,
};
use crate::finding_identity::PolicyFindingId;
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::resolved::LoadedPolicy;
use crate::source::PolicySourceIdentity;

use super::host::{ExplanationTarget, explain_policy_inputs};
use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, POLICY_EXPLANATION_FORMAT,
    PolicyExplanation, WHY_ADAPTER_ANALYSIS_TYPES, WHY_NOT_ADAPTER_ANALYSIS_TYPES,
};
use super::why::{explain_finding, explain_match_finding};
use super::why_not::{
    ExplanationCandidate, explain_candidate, explain_match_candidate, row_covers_candidate,
};

/// One class with one member plus a free function, so a candidate can sit
/// inside a class but outside every member.
const FIXTURE: &str = "export class Widget {\n  render() {}\n}\nexport function loose() {}\n";

/// A selector with two steps: the class seed, widened to its declaration, then
/// narrowed to that declaration's members.
const MEMBERS_POLICY: &str = r#"(policy
  :id "test.explain.members"
  :name "Members"
  :message "Widget members are reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (members (enclosing-decl (class :name "Widget"))))))"#;

/// A one-stage selector: the seed alone decides everything.
const LOOSE_POLICY: &str = r#"(policy
  :id "test.explain.loose"
  :name "Loose"
  :message "loose is reported"
  :severity warning
  :analysis (analysis :type match :selector (rql (function :name "loose"))))"#;

/// A non-match policy, used to prove the missing-adapter condition is a value
/// and not a panic.
const ASSERTION_POLICY: &str = r#"(policy
  :id "test.explain.assertion"
  :name "Assertion"
  :message "render must be a declaration name"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (identifier :text/regex "^render$" :capture "target"))
    :asserts [
      (assert :id declared :at "target" :role declaration_name :expect declaration
              :cardinality (exactly 1))
    ]))"#;

/// A taint policy, used to prove the missing-adapter condition survives slices
/// 2-3 for the families that still have no adapter.
const TAINT_POLICY: &str = r#"(policy
  :id "test.explain.taint"
  :name "Taint"
  :message (generated-message :relation can-reach)
  :severity warning
  :analysis (analysis
    :type taint
    :mode may
    :sources (endpoint-set :entries [
      (source :id alpha :display-name "user input" :categories [input.user]
        :selector (rql (name "alpha")) :bind return-value :labels [untrusted])])
    :sinks (endpoint-set :entries [
      (sink :id store :display-name "sensitive store" :categories [data.sensitive]
        :selector (rql (name "store")) :dangerous-operand matched-value
        :accepts [untrusted])])))"#;

/// A relational assertion source: one `render` declaration plus one value read
/// of it, so the value-read plan below has exactly one violating group.
const RELATIONAL_FIXTURE: &str =
    "export function render(): number {\n  return 1;\n}\n\nexport const alias = render;\n";

/// The same shape with a second value read, so a one-row pipeline budget
/// truncates the binding and leaves the run inconclusive with a finding.
const RELATIONAL_TWO_READS: &str = "export function render(): number {\n  return 1;\n}\n\nexport const alias = render;\nexport const second = render;\n";

/// A member access, so the two-binding plan's `member_position` binding has a
/// row and its row expansion is reached.
const MEMBER_FIXTURE: &str = "class Service {\n  run(): number {\n    return 1;\n  }\n}\n\nexport function caller(service: Service) {\n  return service.run();\n}\n";

/// Forbid value reads through a relational row plan. One binding, one group,
/// one assertion, so each read violates on its own exact source range.
const FORBID_READS_RELATIONAL: &str = r#"(policy
  :id "test.explain.relational"
  :name "No value reads"
  :message "value reads are forbidden in this fixture"
  :severity warning
  :analysis (analysis
    :type assertion
    (bind :name read :query (rql (occurrences :role [value_reference])))
    (group :name by-read :by (read.ast_id)
      (aggregate :name reads :op count))
    (assert :group by-read :value reads :cardinality (exactly 0))))"#;

/// The same invariant over two bindings, the second of which is a row
/// expansion this slice does not replay.
const TWO_BINDING_RELATIONAL: &str = r#"(policy
  :id "test.explain.relational.two"
  :name "Member sites have receiver outcomes"
  :message "every member occurrence must produce a receiver outcome row"
  :severity error
  :analysis (analysis
    :type assertion
    (bind :name site :query (rql (occurrences :role [member_position])))
    (bind :name receiver :from site :step receiver-outcome)
    (join :left site :right receiver :kind anti :on ((ast_id site_ast_id)))
    (group :name orphaned :by (site.ast_id)
      (aggregate :name sites :op count))
    (assert :group orphaned :value sites :cardinality (exactly 0))))"#;

struct Fixture {
    _temp: tempfile::TempDir,
    analyzer: TypescriptAnalyzer,
}

impl Fixture {
    fn new() -> Self {
        Self::with_source(FIXTURE)
    }

    fn with_source(source: &str) -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "app.ts")
            .write(source)
            .expect("write fixture");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        Self {
            _temp: temp,
            analyzer,
        }
    }

    fn context(&self) -> PolicyEvaluationContext<'_> {
        PolicyEvaluationContext {
            analyzer: &self.analyzer,
            workspace: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
        }
    }

    fn run(&self, source: &str) -> PolicyRun {
        self.run_with_budget(source, PolicyBudget::default())
    }

    fn run_with_budget(&self, source: &str, mut budget: PolicyBudget) -> PolicyRun {
        let registry = registry(source);
        let policy = registry.policies().next().expect("one loaded policy");
        DefaultPolicyEvaluator::new()
            .evaluate(policy, &self.context(), &mut budget)
            .expect("policy evaluation")
    }
}

fn registry(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(PolicySourceIdentity::new("test:explain"), source.as_bytes())
        .expect("valid policy source");
    registry
}

fn with_policy<R>(source: &str, body: impl FnOnce(&LoadedPolicy) -> R) -> R {
    let registry = registry(source);
    let policy = registry.policies().next().expect("one loaded policy");
    body(policy)
}

/// The byte offset of the first occurrence of `needle` in the fixture.
fn offset_of(needle: &str) -> u64 {
    u64::try_from(FIXTURE.find(needle).expect("fixture contains the needle"))
        .expect("fixture offsets fit u64")
}

fn candidate(needle: &str) -> ExplanationCandidate {
    ExplanationCandidate::at_offset("app.ts", offset_of(needle)).expect("workspace-relative path")
}

fn only_finding(run: &PolicyRun) -> PolicyFindingId {
    assert_eq!(run.findings().len(), 1, "fixture expects one finding");
    run.findings()[0].id()
}

fn stage_labels(explanation: &PolicyExplanation) -> Vec<(String, ExplanationOutcome)> {
    explanation
        .root()
        .children()
        .iter()
        .filter(|node| node.kind() == ExplanationNodeKind::SelectorStage)
        .map(|node| (node.label().to_string(), node.outcome()))
        .collect()
}

// --- schema and determinism -------------------------------------------------

#[test]
fn why_explanation_carries_the_versioned_format_and_subject() {
    let fixture = Fixture::new();
    let run = fixture.run(LOOSE_POLICY);
    let id = only_finding(&run);
    let explanation =
        explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");

    assert_eq!(explanation.format(), POLICY_EXPLANATION_FORMAT);
    assert_eq!(explanation.format(), "bifrost_policy_explanation/v1");
    assert_eq!(explanation.question(), ExplanationQuestion::Why);
    assert_eq!(explanation.analysis_type(), PolicyAnalysisType::Match);
    assert_eq!(explanation.outcome(), ExplanationOutcome::Satisfied);
    assert!(matches!(
        explanation.subject(),
        ExplanationSubject::Finding { finding_id, .. } if *finding_id == id
    ));
    assert_eq!(
        explanation.root().kind(),
        ExplanationNodeKind::FindingProjection
    );
    assert_eq!(
        explanation.node_count(),
        u64::try_from(explanation.nodes().len()).unwrap()
    );
    assert!(!explanation.truncation().is_truncated());
}

#[test]
fn why_explanation_serializes_byte_identically_across_runs() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let first = explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("first");
    let second = explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("second");

    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first, second);

    // A second, independently evaluated run of the same policy over the same
    // source must also agree: node identities carry no process-local state.
    let other_fixture = Fixture::new();
    let other_run = other_fixture.run(MEMBERS_POLICY);
    let other_id = only_finding(&other_run);
    let third =
        explain_match_finding(&other_run, &other_id, &ExplanationLimits::default()).expect("third");
    assert_eq!(first.root().id(), third.root().id());
    assert_eq!(first.to_json(), third.to_json());
}

#[test]
fn node_identities_distinguish_position_and_content() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let explanation =
        explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");

    let nodes = explanation.nodes();
    assert!(nodes.len() > 3, "fixture should produce a real tree");
    let mut ids: Vec<String> = nodes.iter().map(|node| node.id().to_string()).collect();
    let total = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), total, "node identities are unique in a tree");
    assert!(
        ids.iter().all(|id| id.len() == 32),
        "identities render as 16 lowercase hex bytes"
    );
}

// --- why: parity with retained evidence -------------------------------------

#[test]
fn why_locations_all_trace_back_to_retained_finding_evidence() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let explanation =
        explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");

    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Match { evidence } = finding.evidence() else {
        panic!("a match run retains match evidence");
    };
    let mut retained: Vec<PolicySourceLocation> = vec![finding.primary().clone()];
    retained.extend(super::why::ref_location(evidence.terminal()));
    let mut retained_operations: Vec<String> = Vec::new();
    for provenance in evidence.provenance() {
        retained.extend(super::why::ref_location(provenance.seed()));
        for step in provenance.steps() {
            retained_operations.push(step.operation().to_string());
            retained.extend(super::why::ref_location(step.result()));
            if let Some(via) = step.via() {
                retained.extend(super::why::ref_location(via));
            }
        }
    }

    for node in explanation.nodes() {
        if let Some(location) = node.location() {
            assert!(
                retained.contains(location),
                "node {} carries a location the finding never retained: {location:?}",
                node.label()
            );
        }
    }

    // Every step node's label is a retained provenance operation, and every
    // retained operation appears.
    let step_labels: Vec<String> = explanation
        .nodes()
        .iter()
        .filter(|node| {
            node.kind() == ExplanationNodeKind::SelectorStage && node.label() != "provenance_branch"
        })
        .map(|node| node.label().to_string())
        .collect();
    assert!(!step_labels.is_empty(), "the fixture selector has steps");
    for label in &step_labels {
        assert!(
            retained_operations.contains(label),
            "step label {label} is not a retained provenance operation"
        );
    }
    for operation in &retained_operations {
        assert!(
            step_labels.contains(operation),
            "retained operation {operation} is missing from the explanation"
        );
    }
}

#[test]
fn why_reports_the_coverage_obligation_of_the_run() {
    let fixture = Fixture::new();
    let run = fixture.run(LOOSE_POLICY);
    let id = only_finding(&run);
    let explanation =
        explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");

    let coverage = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.kind() == ExplanationNodeKind::CoverageObligation)
        .expect("a coverage obligation node");
    assert_eq!(coverage.label(), "run_completion");
    assert_eq!(
        coverage.outcome(),
        if run.completion().is_reliable() {
            ExplanationOutcome::Satisfied
        } else {
            ExplanationOutcome::Unknown
        }
    );
}

// --- why: error conditions --------------------------------------------------

#[test]
fn why_rejects_a_finding_the_run_does_not_retain() {
    let fixture = Fixture::new();
    let run = fixture.run(LOOSE_POLICY);
    let absent = "0".repeat(64).parse::<PolicyFindingId>().expect("parsable");
    assert_eq!(
        explain_match_finding(&run, &absent, &ExplanationLimits::default()),
        Err(ExplainError::FindingNotFound { finding: absent })
    );
}

#[test]
fn the_match_only_why_adapter_still_refuses_a_non_match_run() {
    let fixture = Fixture::new();
    let run = fixture.run(ASSERTION_POLICY);
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    let absent = "0".repeat(64).parse::<PolicyFindingId>().expect("parsable");
    let error = explain_match_finding(&run, &absent, &ExplanationLimits::default())
        .expect_err("the match-only adapter refuses an assertion run");
    assert_eq!(
        error,
        ExplainError::adapter_unavailable(PolicyAnalysisType::Assertion, ExplanationQuestion::Why)
    );
}

/// Issue 2439 slice 2: the missing-adapter condition names what *is*
/// supported, so a caller learns the whole answer from one error.
#[test]
fn a_missing_adapter_names_the_supported_analysis_types() {
    for question in [ExplanationQuestion::Why, ExplanationQuestion::WhyNot] {
        let error = ExplainError::adapter_unavailable(PolicyAnalysisType::Taint, question);
        let ExplainError::ExplanationAdapterUnavailable { supported, .. } = &error else {
            panic!("the constructor builds the adapter-unavailable condition");
        };
        assert_eq!(
            supported,
            &vec![PolicyAnalysisType::Match, PolicyAnalysisType::Assertion]
        );
        let rendered = error.to_string();
        assert!(rendered.contains("not yet implemented"), "{rendered}");
        assert!(
            rendered.contains("supported analysis types: match, assertion"),
            "the error names the supported families: {rendered}"
        );
        assert!(rendered.contains(question.label()), "{rendered}");
    }
    assert_eq!(
        WHY_ADAPTER_ANALYSIS_TYPES,
        [PolicyAnalysisType::Match, PolicyAnalysisType::Assertion]
    );
    assert_eq!(
        WHY_NOT_ADAPTER_ANALYSIS_TYPES,
        [PolicyAnalysisType::Match, PolicyAnalysisType::Assertion]
    );
}

/// Taint, flow and typestate keep the explicit adapter-unavailable condition:
/// slices 2-3 add the relational adapters only.
#[test]
fn why_not_reports_a_missing_adapter_for_a_taint_policy() {
    let fixture = Fixture::new();
    let candidate = candidate("render");
    let error = with_policy(TAINT_POLICY, |policy| {
        explain_candidate(
            policy,
            &fixture.context(),
            &candidate,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .expect_err("taint policies have no why-not adapter yet")
    });
    assert_eq!(
        error,
        ExplainError::adapter_unavailable(PolicyAnalysisType::Taint, ExplanationQuestion::WhyNot)
    );
}

/// An assertion policy whose asserts are the capture-oriented families carries
/// no row plan, which is a different condition from a missing adapter.
#[test]
fn why_not_reports_a_missing_row_plan_for_a_capture_assertion_policy() {
    let fixture = Fixture::new();
    let candidate = candidate("render");
    let error = with_policy(ASSERTION_POLICY, |policy| {
        explain_candidate(
            policy,
            &fixture.context(),
            &candidate,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .expect_err("a capture-oriented assertion policy has no row bindings")
    });
    assert_eq!(error, ExplainError::RelationalPlanUnavailable);
}

// --- bounds -----------------------------------------------------------------

#[test]
fn the_node_limit_truncates_and_reports_a_lower_bound() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let full =
        explain_match_finding(&run, &id, &ExplanationLimits::default()).expect("full explanation");
    let full_nodes = full.node_count();
    assert!(full_nodes > 3);

    let limits = ExplanationLimits::default().with_max_nodes(3);
    let bounded = explain_match_finding(&run, &id, &limits).expect("bounded explanation");
    assert_eq!(bounded.node_count(), 3);
    assert_eq!(u64::try_from(bounded.nodes().len()).unwrap(), 3);
    assert!(bounded.truncation().nodes_truncated());
    assert_eq!(
        bounded.truncation().omitted_nodes_lower_bound(),
        full_nodes - 3
    );
    assert!(
        bounded
            .nodes()
            .iter()
            .any(|node| node.children_truncated() && node.omitted_children_lower_bound() > 0)
    );
}

#[test]
fn the_depth_limit_truncates_and_reports_omitted_levels() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let limits = ExplanationLimits::default().with_max_depth(2);
    let bounded = explain_match_finding(&run, &id, &limits).expect("bounded explanation");

    assert!(bounded.truncation().depth_truncated());
    assert!(bounded.truncation().omitted_depth_levels_lower_bound() >= 1);
    assert!(bounded.truncation().nodes_truncated());
    for child in bounded.root().children() {
        assert!(
            child.children().is_empty(),
            "depth 2 retains no grandchildren"
        );
    }
}

#[test]
fn the_child_limit_truncates_and_reports_a_lower_bound() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let limits = ExplanationLimits::default().with_max_children_per_node(1);
    let bounded = explain_match_finding(&run, &id, &limits).expect("bounded explanation");

    assert_eq!(bounded.root().children().len(), 1);
    assert!(bounded.root().children_truncated());
    assert!(bounded.root().omitted_children_lower_bound() >= 1);
    assert!(bounded.truncation().nodes_truncated());
}

#[test]
fn the_retained_byte_limit_truncates_and_reports_omitted_bytes() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let limits = ExplanationLimits::default()
        .with_max_retained_bytes(size_of::<super::model::ExplanationNode>() + 512);
    let bounded = explain_match_finding(&run, &id, &limits).expect("bounded explanation");

    assert!(bounded.truncation().bytes_truncated());
    assert!(bounded.truncation().omitted_bytes_lower_bound() > 0);
    assert!(bounded.node_count() >= 1);
}

#[test]
fn the_text_limit_truncates_prose_on_a_character_boundary() {
    let fixture = Fixture::new();
    let run = fixture.run(MEMBERS_POLICY);
    let id = only_finding(&run);
    let limits = ExplanationLimits::default().with_max_text_bytes(8);
    let bounded = explain_match_finding(&run, &id, &limits).expect("bounded explanation");

    assert!(bounded.truncation().text_truncated());
    assert!(bounded.truncation().omitted_text_bytes_lower_bound() > 0);
    for node in bounded.nodes() {
        assert!(node.label().len() <= 8);
        assert!(node.expected().is_none_or(|text| text.len() <= 8));
        assert!(node.actual().is_none_or(|text| text.len() <= 8));
    }
}

#[test]
fn impossible_limits_report_budget_exhaustion_instead_of_an_empty_tree() {
    let fixture = Fixture::new();
    let run = fixture.run(LOOSE_POLICY);
    let id = only_finding(&run);

    assert_eq!(
        explain_match_finding(&run, &id, &ExplanationLimits::default().with_max_nodes(0)),
        Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::Nodes
        })
    );
    assert_eq!(
        explain_match_finding(&run, &id, &ExplanationLimits::default().with_max_depth(0)),
        Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::Depth
        })
    );
    assert_eq!(
        explain_match_finding(
            &run,
            &id,
            &ExplanationLimits::default().with_max_retained_bytes(1)
        ),
        Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::RetainedBytes
        })
    );

    let candidate = candidate("Widget");
    let error = with_policy(LOOSE_POLICY, |policy| {
        explain_match_candidate(
            policy,
            &fixture.context(),
            &candidate,
            &PolicyBudget::default(),
            &ExplanationLimits::default().with_max_prefix_executions(0),
        )
        .expect_err("no prefix may be executed")
    });
    assert_eq!(
        error,
        ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::PrefixExecutions
        }
    );
}

// --- candidate containment --------------------------------------------------

#[test]
fn a_point_candidate_is_covered_by_a_half_open_row_span() {
    let point = ExplanationCandidate::at_offset("app.ts", 10).expect("candidate");
    assert!(point.is_point());
    assert!(row_covers_candidate(Some(&(10..11)), &point));
    assert!(row_covers_candidate(Some(&(0..20)), &point));
    assert!(row_covers_candidate(Some(&(10..10 + 1)), &point));
    // The end is exclusive, so a point at the end is outside.
    assert!(!row_covers_candidate(Some(&(0..10)), &point));
    assert!(!row_covers_candidate(Some(&(11..20)), &point));
}

#[test]
fn a_degenerate_empty_row_covers_only_its_own_point() {
    let point = ExplanationCandidate::at_offset("app.ts", 10).expect("candidate");
    assert!(row_covers_candidate(Some(&(10..10)), &point));
    assert!(!row_covers_candidate(Some(&(9..9)), &point));

    let region = ExplanationCandidate::in_range("app.ts", 10, 11).expect("candidate");
    assert!(!row_covers_candidate(Some(&(10..10)), &region));
}

#[test]
fn a_range_candidate_needs_full_containment_not_overlap() {
    let region = ExplanationCandidate::in_range("app.ts", 10, 20).expect("candidate");
    assert!(!region.is_point());
    assert!(row_covers_candidate(Some(&(10..20)), &region));
    assert!(row_covers_candidate(Some(&(0..30)), &region));
    // Overlap is not containment.
    assert!(!row_covers_candidate(Some(&(15..25)), &region));
    assert!(!row_covers_candidate(Some(&(5..15)), &region));
    assert!(!row_covers_candidate(Some(&(11..20)), &region));
}

#[test]
fn a_row_without_a_byte_span_covers_the_whole_file() {
    let point = ExplanationCandidate::at_offset("app.ts", 10).expect("candidate");
    let region = ExplanationCandidate::in_range("app.ts", 10, 20).expect("candidate");
    assert!(row_covers_candidate(None, &point));
    assert!(row_covers_candidate(None, &region));
}

#[test]
fn candidates_reject_paths_outside_the_workspace_and_reversed_ranges() {
    assert!(matches!(
        ExplanationCandidate::at_offset("../outside.ts", 0),
        Err(ExplainError::CandidateOutsideWorkspace { .. })
    ));
    assert!(matches!(
        ExplanationCandidate::at_offset("/etc/passwd", 0),
        Err(ExplainError::CandidateOutsideWorkspace { .. })
    ));
    assert_eq!(
        ExplanationCandidate::in_range("app.ts", 9, 4),
        Err(ExplainError::ReversedCandidateRange { start: 9, end: 4 })
    );
}

// --- why-not ----------------------------------------------------------------

fn why_not(
    fixture: &Fixture,
    source: &str,
    candidate: &ExplanationCandidate,
    budget: &PolicyBudget,
) -> PolicyExplanation {
    with_policy(source, |policy| {
        explain_match_candidate(
            policy,
            &fixture.context(),
            candidate,
            budget,
            &ExplanationLimits::default(),
        )
        .expect("explanation")
    })
}

#[test]
fn why_not_reports_the_seed_stage_that_dropped_the_candidate() {
    let fixture = Fixture::new();
    let explanation = why_not(
        &fixture,
        LOOSE_POLICY,
        &candidate("Widget"),
        &PolicyBudget::default(),
    );

    assert_eq!(explanation.question(), ExplanationQuestion::WhyNot);
    assert_eq!(explanation.outcome(), ExplanationOutcome::Failed);
    let stages = stage_labels(&explanation);
    assert_eq!(
        stages,
        vec![(String::from("seed"), ExplanationOutcome::Failed)]
    );
    assert!(matches!(
        explanation.subject(),
        ExplanationSubject::Candidate { path, .. } if path == "app.ts"
    ));
}

#[test]
fn why_not_reports_the_later_step_that_dropped_the_candidate() {
    let fixture = Fixture::new();
    let explanation = why_not(
        &fixture,
        MEMBERS_POLICY,
        &candidate("Widget"),
        &PolicyBudget::default(),
    );

    let stages = stage_labels(&explanation);
    assert_eq!(
        stages,
        vec![
            (String::from("seed"), ExplanationOutcome::Satisfied),
            (
                String::from("enclosing_decl"),
                ExplanationOutcome::Satisfied
            ),
            (String::from("members"), ExplanationOutcome::Failed),
        ],
        "the candidate survives the seed and widening and dies at `members`"
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Failed);
    assert!(
        explanation
            .root()
            .actual()
            .expect("root prose")
            .contains("members")
    );
}

#[test]
fn why_not_reports_satisfied_when_the_selector_retains_the_candidate() {
    let fixture = Fixture::new();
    let explanation = why_not(
        &fixture,
        MEMBERS_POLICY,
        &candidate("render"),
        &PolicyBudget::default(),
    );

    assert_eq!(explanation.outcome(), ExplanationOutcome::Satisfied);
    assert!(
        stage_labels(&explanation)
            .iter()
            .all(|(_, outcome)| *outcome == ExplanationOutcome::Satisfied)
    );
    assert_eq!(stage_labels(&explanation).len(), 3);
}

#[test]
fn why_not_reports_unknown_rather_than_failed_when_the_prefix_query_is_incomplete() {
    let fixture = Fixture::new();
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_scanned_source_bytes: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let explanation = why_not(&fixture, LOOSE_POLICY, &candidate("Widget"), &budget);

    assert_eq!(
        explanation.outcome(),
        ExplanationOutcome::Unknown,
        "an incomplete query never proves absence"
    );
    let stage = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.kind() == ExplanationNodeKind::SelectorStage)
        .expect("one stage");
    assert_eq!(stage.outcome(), ExplanationOutcome::Unknown);
    assert!(
        !stage.reasons().is_empty(),
        "an unknown stage names why it could not decide"
    );
    let obligation = stage
        .children()
        .iter()
        .find(|node| node.kind() == ExplanationNodeKind::CoverageObligation)
        .expect("a coverage obligation under the undecided stage");
    assert_eq!(obligation.outcome(), ExplanationOutcome::Unknown);
}

#[test]
fn why_not_explanations_serialize_byte_identically_across_runs() {
    let fixture = Fixture::new();
    let first = why_not(
        &fixture,
        MEMBERS_POLICY,
        &candidate("Widget"),
        &PolicyBudget::default(),
    );
    let second = why_not(
        &fixture,
        MEMBERS_POLICY,
        &candidate("Widget"),
        &PolicyBudget::default(),
    );
    assert_eq!(first.to_json(), second.to_json());

    let other_fixture = Fixture::new();
    let third = why_not(
        &other_fixture,
        MEMBERS_POLICY,
        &candidate("Widget"),
        &PolicyBudget::default(),
    );
    assert_eq!(first.to_json(), third.to_json());
}

#[test]
fn why_not_stops_at_the_prefix_limit_and_reports_unknown() {
    let fixture = Fixture::new();
    let candidate = candidate("render");
    let explanation = with_policy(MEMBERS_POLICY, |policy| {
        explain_match_candidate(
            policy,
            &fixture.context(),
            &candidate,
            &PolicyBudget::default(),
            &ExplanationLimits::default().with_max_prefix_executions(2),
        )
        .expect("explanation")
    });

    assert_eq!(stage_labels(&explanation).len(), 2);
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    assert!(explanation.root().children_truncated());
    assert_eq!(explanation.root().omitted_children_lower_bound(), 1);
}

// --- relational assertions: why ---------------------------------------------

/// A fixture over `RELATIONAL_FIXTURE`, so a relational plan has a real
/// violating group to explain.
fn relational_fixture() -> Fixture {
    Fixture::with_source(RELATIONAL_FIXTURE)
}

fn candidate_in(source: &str, needle: &str) -> ExplanationCandidate {
    let offset = u64::try_from(source.find(needle).expect("fixture contains the needle"))
        .expect("fixture offsets fit u64");
    ExplanationCandidate::at_offset("app.ts", offset).expect("workspace-relative path")
}

fn relational_candidate(needle: &str) -> ExplanationCandidate {
    candidate_in(RELATIONAL_FIXTURE, needle)
}

fn child_labels(
    node: &super::model::ExplanationNode,
    kind: ExplanationNodeKind,
) -> Vec<(String, ExplanationOutcome)> {
    node.children()
        .iter()
        .filter(|child| child.kind() == kind)
        .map(|child| (child.label().to_string(), child.outcome()))
        .collect()
}

#[test]
fn why_explains_a_relational_assertion_finding_from_retained_evidence() {
    let fixture = relational_fixture();
    let run = fixture.run(FORBID_READS_RELATIONAL);
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    let id = only_finding(&run);
    let explanation = explain_finding(&run, &id, &ExplanationLimits::default())
        .expect("the relational adapter answers why");

    assert_eq!(explanation.format(), POLICY_EXPLANATION_FORMAT);
    assert_eq!(explanation.question(), ExplanationQuestion::Why);
    assert_eq!(explanation.analysis_type(), PolicyAnalysisType::Assertion);
    // The finding is established, so the projection root is satisfied.
    assert_eq!(explanation.outcome(), ExplanationOutcome::Satisfied);
    assert_eq!(explanation.root().label(), "assertion_finding");

    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("a relational run retains assertion evidence");
    };
    let assertion = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.kind() == ExplanationNodeKind::Assertion)
        .expect("one assertion node");
    // The assertion itself failed; that is exactly why the finding exists.
    assert_eq!(assertion.outcome(), ExplanationOutcome::Failed);
    assert_eq!(assertion.label(), evidence.anchor().assert_id());
    let expected = assertion.expected().expect("an authored expectation");
    assert!(expected.contains(evidence.expectation()), "{expected}");
    assert!(expected.contains(evidence.expected_class()), "{expected}");
    assert!(
        expected.contains(evidence.anchor().subject_ast_id()),
        "the group key is stated: {expected}"
    );
    assert_eq!(
        assertion.actual(),
        evidence.observed(),
        "the observed aggregate is published verbatim"
    );
    assert_eq!(assertion.location(), Some(finding.primary()));
}

#[test]
fn why_carries_every_retained_representative_row_with_its_exact_location() {
    let fixture = relational_fixture();
    let run = fixture.run(FORBID_READS_RELATIONAL);
    let id = only_finding(&run);
    let explanation =
        explain_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");
    let finding = &run.findings()[0];

    let assertion = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.kind() == ExplanationNodeKind::Assertion)
        .expect("one assertion node");
    let rows = assertion
        .children()
        .iter()
        .filter(|node| node.kind() == ExplanationNodeKind::SourceFact)
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        finding.related().len() + 1,
        "the anchor row plus every retained related location"
    );
    assert_eq!(rows[0].label(), "anchor_row");
    assert_eq!(rows[0].location(), Some(finding.primary()));
    for (row, related) in rows[1..].iter().zip(finding.related()) {
        assert_eq!(row.location(), Some(related.location()));
        assert!(
            row.label() == "subject_row" || row.label() == "evidence_row",
            "the relational driver tags rows subject or evidence: {}",
            row.label()
        );
        assert_eq!(row.outcome(), ExplanationOutcome::Satisfied);
    }
    // Every location an explanation publishes was retained by the finding.
    let retained: Vec<PolicySourceLocation> = std::iter::once(finding.primary().clone())
        .chain(finding.related().iter().map(|r| r.location().clone()))
        .collect();
    for node in explanation.nodes() {
        if let Some(location) = node.location() {
            assert!(
                retained.contains(location),
                "node {} carries a location the finding never retained",
                node.label()
            );
        }
    }
}

#[test]
fn why_joins_the_runs_unmet_obligations_for_the_same_assertion() {
    // A truncated binding leaves the run inconclusive while the witnessed
    // positive violation survives (the milestone-1 contract), which is the run
    // shape that can carry both a finding and an unmet obligation.
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let fixture = Fixture::with_source(RELATIONAL_TWO_READS);
    let mut run = fixture.run_with_budget(FORBID_READS_RELATIONAL, budget);
    assert!(
        matches!(run.completion(), PolicyRunCompletion::Inconclusive { .. }),
        "{:?}",
        run.completion()
    );
    let finding = run.findings()[0].clone();
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("a relational run retains assertion evidence");
    };
    let assert_id = evidence.anchor().assert_id().to_string();

    // The canonical obligation list is the join key this adapter reads. A run
    // that carries one for this assertion and one for another must publish
    // exactly the first: an unrelated blocked verdict says nothing about this
    // finding.
    let mine = PolicyObligation::try_new(
        &assert_id,
        PolicyObligationKind::AbsenceRequiresExhaustiveCoverage,
        "by-read",
        Some("app.ts#alias"),
        vec![PolicyIncompleteReason::PipelineRowBudget],
    )
    .expect("a valid obligation");
    let other = PolicyObligation::try_new(
        "some-other-assertion",
        PolicyObligationKind::VerdictRequiresWitnessedRows,
        "by-read",
        None,
        vec![PolicyIncompleteReason::PartialDiscovery],
    )
    .expect("a valid obligation");
    run.set_obligations(&[mine, other], false, 0, &PolicyBudget::default())
        .expect("the run accepts its obligations");

    let explanation =
        explain_finding(&run, &finding.id(), &ExplanationLimits::default()).expect("explanation");
    let obligations = child_labels(explanation.root(), ExplanationNodeKind::CoverageObligation);
    assert_eq!(
        obligations,
        vec![
            (String::from("run_completion"), ExplanationOutcome::Unknown),
            (
                String::from("absence_requires_exhaustive_coverage"),
                ExplanationOutcome::Unknown
            ),
        ],
        "only this assertion's obligation is joined, and an unmet obligation is unknown"
    );
    let obligation = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "absence_requires_exhaustive_coverage")
        .expect("the joined obligation");
    assert_eq!(
        obligation.reasons(),
        [PolicyIncompleteReason::PipelineRowBudget]
    );
    assert!(
        obligation
            .actual()
            .expect("obligation prose")
            .contains("app.ts#alias"),
        "the blocked group key is named"
    );
}

#[test]
fn relational_why_explanations_serialize_byte_identically_across_runs() {
    let fixture = relational_fixture();
    let run = fixture.run(FORBID_READS_RELATIONAL);
    let id = only_finding(&run);
    let first = explain_finding(&run, &id, &ExplanationLimits::default()).expect("first");
    let second = explain_finding(&run, &id, &ExplanationLimits::default()).expect("second");
    assert_eq!(first.to_json(), second.to_json());

    let other_fixture = relational_fixture();
    let other_run = other_fixture.run(FORBID_READS_RELATIONAL);
    let other_id = only_finding(&other_run);
    let third =
        explain_finding(&other_run, &other_id, &ExplanationLimits::default()).expect("third");
    assert_eq!(first.to_json(), third.to_json());
    assert_eq!(first.root().id(), third.root().id());
}

#[test]
fn the_node_limit_bounds_a_relational_why_answer() {
    let fixture = relational_fixture();
    let run = fixture.run(FORBID_READS_RELATIONAL);
    let id = only_finding(&run);
    let full = explain_finding(&run, &id, &ExplanationLimits::default()).expect("full");
    assert!(full.node_count() > 2);
    let bounded = explain_finding(&run, &id, &ExplanationLimits::default().with_max_nodes(2))
        .expect("bounded");
    assert_eq!(bounded.node_count(), 2);
    assert!(bounded.truncation().nodes_truncated());
    assert_eq!(
        bounded.truncation().omitted_nodes_lower_bound(),
        full.node_count() - 2
    );
}

// --- relational assertions: why-not -----------------------------------------

fn relational_why_not(
    fixture: &Fixture,
    source: &str,
    candidate: &ExplanationCandidate,
    limits: &ExplanationLimits,
) -> PolicyExplanation {
    with_policy(source, |policy| {
        explain_candidate(
            policy,
            &fixture.context(),
            candidate,
            &PolicyBudget::default(),
            limits,
        )
        .expect("explanation")
    })
}

fn binding_labels(explanation: &PolicyExplanation) -> Vec<(String, ExplanationOutcome)> {
    child_labels(explanation.root(), ExplanationNodeKind::RelationBinding)
}

#[test]
fn why_not_reports_the_binding_the_candidate_is_absent_from() {
    let fixture = relational_fixture();
    // `return` is a keyword, so no value-reference occurrence covers it.
    let explanation = relational_why_not(
        &fixture,
        FORBID_READS_RELATIONAL,
        &relational_candidate("return 1"),
        &ExplanationLimits::default(),
    );

    assert_eq!(explanation.question(), ExplanationQuestion::WhyNot);
    assert_eq!(explanation.analysis_type(), PolicyAnalysisType::Assertion);
    assert_eq!(explanation.root().label(), "relational_candidate");
    assert_eq!(explanation.outcome(), ExplanationOutcome::Failed);
    assert_eq!(
        binding_labels(&explanation),
        vec![(String::from("read"), ExplanationOutcome::Failed)]
    );
    assert!(
        explanation
            .root()
            .actual()
            .expect("root prose")
            .contains("absent from row binding `read`"),
        "{:?}",
        explanation.root().actual()
    );

    // The binding's own stages say which stage inside it dropped the row.
    let binding = &explanation.root().children()[0];
    let stages = child_labels(binding, ExplanationNodeKind::SelectorStage);
    assert_eq!(
        stages,
        vec![(String::from("occurrences"), ExplanationOutcome::Failed)]
    );
}

#[test]
fn why_not_stops_short_of_claiming_a_finding_when_every_binding_retains_the_row() {
    let fixture = relational_fixture();
    let explanation = relational_why_not(
        &fixture,
        FORBID_READS_RELATIONAL,
        &relational_candidate("render;"),
        &ExplanationLimits::default(),
    );

    assert_eq!(
        binding_labels(&explanation),
        vec![(String::from("read"), ExplanationOutcome::Satisfied)]
    );
    assert_eq!(
        explanation.outcome(),
        ExplanationOutcome::Unknown,
        "membership in every binding is not a finding; the joins are not replayed"
    );
    let gap = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "join_replay_unavailable")
        .expect("the unreplayed join is stated as a node, not only as prose");
    assert_eq!(gap.kind(), ExplanationNodeKind::CoverageObligation);
    assert_eq!(gap.outcome(), ExplanationOutcome::Unknown);
    assert_eq!(
        gap.reasons(),
        [PolicyIncompleteReason::CapabilityIncomplete]
    );
}

#[test]
fn why_not_reports_unknown_for_a_row_expansion_binding_it_cannot_replay() {
    let fixture = Fixture::with_source(MEMBER_FIXTURE);
    let explanation = relational_why_not(
        &fixture,
        TWO_BINDING_RELATIONAL,
        &candidate_in(MEMBER_FIXTURE, "run();"),
        &ExplanationLimits::default(),
    );

    let bindings = binding_labels(&explanation);
    assert_eq!(bindings.len(), 2, "{bindings:?}");
    assert_eq!(bindings[0].0, "site");
    assert_eq!(
        bindings[1],
        (String::from("receiver"), ExplanationOutcome::Unknown)
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    let expansion = &explanation.root().children()[1];
    assert_eq!(
        expansion.reasons(),
        [PolicyIncompleteReason::CapabilityIncomplete]
    );
    assert!(
        expansion
            .actual()
            .expect("expansion prose")
            .contains("not replayed"),
        "{:?}",
        expansion.actual()
    );
    assert!(
        expansion.children().is_empty(),
        "an unreplayed binding executed no prefix"
    );
}

#[test]
fn why_not_shares_one_prefix_budget_across_relational_bindings() {
    let fixture = Fixture::with_source(MEMBER_FIXTURE);
    let limits = ExplanationLimits::default().with_max_prefix_executions(1);
    let explanation = relational_why_not(
        &fixture,
        TWO_BINDING_RELATIONAL,
        &candidate_in(MEMBER_FIXTURE, "run();"),
        &limits,
    );

    assert_eq!(
        binding_labels(&explanation).len(),
        1,
        "one execution funds one binding's single stage"
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    assert!(explanation.root().children_truncated());
    assert_eq!(explanation.root().omitted_children_lower_bound(), 1);
    assert!(
        explanation
            .root()
            .actual()
            .expect("root prose")
            .contains("prefix-execution limit"),
        "{:?}",
        explanation.root().actual()
    );
}

#[test]
fn relational_why_not_explanations_serialize_byte_identically_across_runs() {
    let fixture = relational_fixture();
    let candidate = relational_candidate("return 1");
    let first = relational_why_not(
        &fixture,
        FORBID_READS_RELATIONAL,
        &candidate,
        &ExplanationLimits::default(),
    );
    let second = relational_why_not(
        &fixture,
        FORBID_READS_RELATIONAL,
        &candidate,
        &ExplanationLimits::default(),
    );
    assert_eq!(first.to_json(), second.to_json());

    let other = relational_fixture();
    let third = relational_why_not(
        &other,
        FORBID_READS_RELATIONAL,
        &candidate,
        &ExplanationLimits::default(),
    );
    assert_eq!(first.to_json(), third.to_json());
}

#[test]
fn a_relational_why_not_refuses_an_impossible_prefix_budget() {
    let fixture = relational_fixture();
    let candidate = relational_candidate("render;");
    let error = with_policy(FORBID_READS_RELATIONAL, |policy| {
        explain_candidate(
            policy,
            &fixture.context(),
            &candidate,
            &PolicyBudget::default(),
            &ExplanationLimits::default().with_max_prefix_executions(0),
        )
        .expect_err("no prefix may be executed")
    });
    assert_eq!(
        error,
        ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::PrefixExecutions
        }
    );
}

// --- the host entry point ---------------------------------------------------

/// A workspace on disk holding one source file and one `.rqlp` policy, which
/// is what the CLI and MCP surfaces hand to [`explain_policy_inputs`].
fn host_workspace(source: &str, policy: &str) -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    std::fs::write(root.join("app.ts"), source).expect("write source");
    std::fs::create_dir_all(root.join("policies")).expect("policy directory");
    std::fs::write(root.join("policies").join("explain.rqlp"), policy).expect("write policy");
    temp
}

#[test]
fn the_host_explains_a_relational_finding_from_a_workspace_policy_file() {
    let temp = host_workspace(RELATIONAL_FIXTURE, FORBID_READS_RELATIONAL);
    let root = temp.path().canonicalize().expect("canonical root");
    let inputs = vec![PolicyEvaluationInput::workspace_file(
        "policies/explain.rqlp",
    )];

    // A candidate answer needs no finding identity, so it is the cheapest way
    // to prove the host path loads, resolves and dispatches.
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");
    let explanation = explain_policy_inputs(
        &root,
        &inputs,
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect("the host answers why-not");
    assert_eq!(explanation.question(), ExplanationQuestion::WhyNot);
    assert_eq!(explanation.policy_id().as_str(), "test.explain.relational");

    // The same workspace, asked why about the finding its own run produced.
    let fixture = Fixture::with_source(RELATIONAL_FIXTURE);
    let id = only_finding(&fixture.run(FORBID_READS_RELATIONAL));
    let explanation = explain_policy_inputs(
        &root,
        &inputs,
        &ExplanationTarget::Finding(id),
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect("the host answers why");
    assert_eq!(explanation.question(), ExplanationQuestion::Why);
    assert!(matches!(
        explanation.subject(),
        ExplanationSubject::Finding { finding_id, .. } if *finding_id == id
    ));
}

#[test]
fn the_host_refuses_a_selection_that_is_not_exactly_one_policy() {
    let temp = host_workspace(RELATIONAL_FIXTURE, FORBID_READS_RELATIONAL);
    let root = temp.path().canonicalize().expect("canonical root");
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");

    let empty = explain_policy_inputs(
        &root,
        &[],
        &ExplanationTarget::Candidate(candidate.clone()),
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect_err("an explanation is about one policy");
    assert_eq!(
        empty,
        ExplainError::AmbiguousPolicySelection { selected: 0 }
    );

    let two = explain_policy_inputs(
        &root,
        &[
            PolicyEvaluationInput::workspace_file("policies/explain.rqlp"),
            PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new("test:explain-second"),
                LOOSE_POLICY,
            ),
        ],
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect_err("an explanation is about one policy");
    assert_eq!(two, ExplainError::AmbiguousPolicySelection { selected: 2 });
}

#[test]
fn the_host_reports_an_unloadable_policy_as_a_stated_condition() {
    let temp = host_workspace(RELATIONAL_FIXTURE, FORBID_READS_RELATIONAL);
    let root = temp.path().canonicalize().expect("canonical root");
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");
    let error = explain_policy_inputs(
        &root,
        &[PolicyEvaluationInput::workspace_file(
            "policies/absent.rqlp",
        )],
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect_err("a missing policy file is a stated condition, not a panic");
    assert!(
        matches!(error, ExplainError::PolicyUnavailable { .. }),
        "{error:?}"
    );
}
