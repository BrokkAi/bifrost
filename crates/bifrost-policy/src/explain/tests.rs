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
use crate::definition::PolicyAnalysisType;
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::finding::{PolicyFindingEvidence, PolicyRun, PolicySourceLocation};
use crate::finding_identity::PolicyFindingId;
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::resolved::LoadedPolicy;
use crate::source::PolicySourceIdentity;

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, POLICY_EXPLANATION_FORMAT,
    PolicyExplanation,
};
use super::why::explain_match_finding;
use super::why_not::{ExplanationCandidate, explain_match_candidate, row_covers_candidate};

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

struct Fixture {
    _temp: tempfile::TempDir,
    analyzer: TypescriptAnalyzer,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "app.ts")
            .write(FIXTURE)
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
        let registry = registry(source);
        let policy = registry.policies().next().expect("one loaded policy");
        DefaultPolicyEvaluator::new()
            .evaluate(policy, &self.context(), &mut PolicyBudget::default())
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
fn why_reports_a_missing_adapter_for_a_non_match_run() {
    let fixture = Fixture::new();
    let run = fixture.run(ASSERTION_POLICY);
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    let absent = "0".repeat(64).parse::<PolicyFindingId>().expect("parsable");
    let error = explain_match_finding(&run, &absent, &ExplanationLimits::default())
        .expect_err("assertion runs have no explanation adapter yet");
    assert_eq!(
        error,
        ExplainError::ExplanationAdapterUnavailable {
            analysis_type: PolicyAnalysisType::Assertion
        }
    );
    assert!(
        error.to_string().contains("not yet implemented"),
        "the missing adapter states itself: {error}"
    );
}

#[test]
fn why_not_reports_a_missing_adapter_for_a_non_match_policy() {
    let fixture = Fixture::new();
    let candidate = candidate("render");
    let error = with_policy(ASSERTION_POLICY, |policy| {
        explain_match_candidate(
            policy,
            &fixture.context(),
            &candidate,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .expect_err("assertion policies have no why-not adapter yet")
    });
    assert_eq!(
        error,
        ExplainError::ExplanationAdapterUnavailable {
            analysis_type: PolicyAnalysisType::Assertion
        }
    );
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
