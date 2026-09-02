//! Unit tests for the explanation schema and the two adapters.
//!
//! The fixtures build a real analyzer over real source, load real policies,
//! and evaluate them, so the `why` parity test compares against evidence the
//! production evaluator actually retained rather than against a hand-built
//! stand-in.

use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, Language, Project, ProjectFile, TestProject, TypescriptAnalyzer,
    WorkspaceAnalyzer,
};
use brokk_bifrost_rql::structural::CodeQueryExecutionLimits;

use crate::budget::PolicyBudget;
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::coordinator::{PolicyEvaluationInput, PolicyEvaluationOptions, evaluate_policy_inputs};
use crate::definition::PolicyAnalysisType;
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::finding::{
    PolicyFindingEvidence, PolicyIncompleteReason, PolicyObligation, PolicyObligationKind,
    PolicyRun, PolicyRunCompletion, PolicySourceLocation,
};
use crate::finding_identity::PolicyFindingId;
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::report::PolicyReportDiagnosticCode;
use crate::resolved::LoadedPolicy;
use crate::source::PolicySourceIdentity;

use super::host::{ExplanationTarget, explain_policy_inputs};
use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, NEAR_MISS_ADAPTER_ANALYSIS_TYPES,
    POLICY_EXPLANATION_FORMAT, PolicyExplanation, WHY_ADAPTER_ANALYSIS_TYPES,
    WHY_NOT_ADAPTER_ANALYSIS_TYPES,
};
use super::near_miss::{
    NearMissCandidates, NearMissEnumeration, POLICY_NEAR_MISS_FORMAT, PolicyNearMissRanking,
    rank_near_misses,
};
use super::why::{explain_finding, explain_match_finding};
use super::why_not::{
    ExplanationCandidate, MATCH_SELECTOR_PATH, PrefixExecution, explain_candidate,
    explain_match_candidate, row_covers_candidate, run_prefixes,
};

use crate::inline_project::InlineTestProject;

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

/// A selector whose relation moves from the declaration anchor to a reference
/// anchor elsewhere in the file.
const REFERENCES_POLICY: &str = r#"(policy
  :id "test.explain.references"
  :name "Render references"
  :message "render references are reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (references-of (enclosing-decl (function :name "render"))))))"#;

/// The reference row is an intermediate anchor; the final projection returns
/// to the referenced declaration and no longer covers that source position.
const REFERENCE_TARGET_POLICY: &str = r#"(policy
  :id "test.explain.reference-target"
  :name "Render reference targets"
  :message "render reference targets are reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (occurrence-target
      (occurrences-of (enclosing-decl (function :name "render")))))))"#;

/// A two-prefix selector used to pin execution accounting when presentation
/// stops after the source stage.
const WIDGET_DECLARATION_POLICY: &str = r#"(policy
  :id "test.explain.widget-declaration"
  :name "Widget declaration"
  :message "Widget is reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (enclosing-decl (class :name "Widget")))))"#;

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

/// Two reference sites with the same semantic target. Their detailed semantic
/// key is shared, so exact why-not lineage must also retain source identity.
const TWO_RENDER_REFERENCES: &str = "export function render(): number {\n  return 1;\n}\n\nexport const first = render;\nexport const second = render;\n";

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

/// The same invariant, but the binding admits the declaration name as well as
/// the value reference and an authored `filter` narrows it back to the reads.
/// The declaration name's row therefore exists in the binding's query, and a
/// predicate rather than the query is what removes it.
const FILTERED_READS_RELATIONAL: &str = r#"(policy
  :id "test.explain.relational.filter"
  :name "No value reads"
  :message "value reads are forbidden in this fixture"
  :severity warning
  :analysis (analysis
    :type assertion
    (bind :name read :query (rql (occurrences :role [declaration_name value_reference])))
    (filter :over read :where ((read.role eq value_reference)))
    (group :name by-read :by (read.ast_id)
      (aggregate :name reads :op count))
    (assert :group by-read :value reads :cardinality (exactly 0))))"#;

/// Two bindings that both retain a value reference, with a filter over the
/// second one only. A filter narrows the relation it names and no other, so the
/// first binding's row must reach the unreplayed join untouched.
const SCOPED_FILTER_RELATIONAL: &str = r#"(policy
  :id "test.explain.relational.scoped-filter"
  :name "Scoped filter"
  :message "a filter narrows only the relation it names"
  :severity warning
  :analysis (analysis
    :type assertion
    (bind :name read :query (rql (occurrences :role [value_reference])))
    (bind :name other :query (rql (occurrences :role [declaration_name value_reference])))
    (filter :over other :where ((other.role eq declaration_name)))
    (join :left read :right other :kind inner :on ((ast_id ast_id)))
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
    flow_state: brokk_bifrost_flow::FlowWorkspaceState,
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
            flow_state: brokk_bifrost_flow::FlowWorkspaceState::new(),
        }
    }

    fn context(&self) -> PolicyEvaluationContext<'_> {
        PolicyEvaluationContext {
            analyzer: &self.analyzer,
            workspace: None,
            flow_state: &self.flow_state,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
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
/// supported, so a caller learns the whole answer from one error. The two
/// questions support different families, and the error says which.
#[test]
fn a_missing_adapter_names_the_supported_analysis_types() {
    for (question, expected) in [
        (
            ExplanationQuestion::Why,
            "supported analysis types: match, taint, assertion, flow",
        ),
        (
            ExplanationQuestion::WhyNot,
            "supported analysis types: match, assertion",
        ),
    ] {
        let error = ExplainError::adapter_unavailable(PolicyAnalysisType::Typestate, question);
        let ExplainError::ExplanationAdapterUnavailable { supported, .. } = &error else {
            panic!("the constructor builds the adapter-unavailable condition");
        };
        assert!(!supported.contains(&PolicyAnalysisType::Typestate));
        let rendered = error.to_string();
        assert!(rendered.contains("not yet implemented"), "{rendered}");
        assert!(
            rendered.contains(expected),
            "the error names the supported families: {rendered}"
        );
        assert!(rendered.contains(question.label()), "{rendered}");
    }
    assert_eq!(
        WHY_ADAPTER_ANALYSIS_TYPES,
        [
            PolicyAnalysisType::Match,
            PolicyAnalysisType::Taint,
            PolicyAnalysisType::Assertion,
            PolicyAnalysisType::Flow
        ]
    );
    assert_eq!(
        WHY_NOT_ADAPTER_ANALYSIS_TYPES,
        [PolicyAnalysisType::Match, PolicyAnalysisType::Assertion]
    );
}

/// `why-not` for a taint policy stays refused: answering it needs
/// candidate-specific solver queries, not a projection of retained evidence.
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
fn why_not_tracks_a_candidate_across_an_anchor_changing_relation() {
    let fixture = Fixture::with_source(RELATIONAL_FIXTURE);
    let reference_offset = u64::try_from(
        RELATIONAL_FIXTURE
            .rfind("render")
            .expect("fixture contains the reference"),
    )
    .expect("fixture offsets fit u64");
    let reference = ExplanationCandidate::at_offset("app.ts", reference_offset).expect("candidate");
    let explanation = why_not(
        &fixture,
        REFERENCES_POLICY,
        &reference,
        &PolicyBudget::default(),
    );

    assert_eq!(
        stage_labels(&explanation),
        vec![
            (String::from("seed"), ExplanationOutcome::Satisfied),
            (
                String::from("enclosing_decl"),
                ExplanationOutcome::Satisfied,
            ),
            (String::from("references_of"), ExplanationOutcome::Satisfied),
        ],
        "typed provenance, not terminal source containment, correlates the reference with its seed"
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Satisfied);

    let bounded = with_policy(REFERENCES_POLICY, |policy| {
        explain_match_candidate(
            policy,
            &fixture.context(),
            &reference,
            &PolicyBudget::default(),
            &ExplanationLimits::default().with_max_prefix_executions(2),
        )
        .expect("bounded explanation")
    });
    assert_eq!(
        bounded.outcome(),
        ExplanationOutcome::Unknown,
        "an omitted anchor-changing relation leaves the terminal-site candidate undecided"
    );
    assert_eq!(
        stage_labels(&bounded),
        vec![(String::from("seed"), ExplanationOutcome::Unknown)]
    );
    assert!(bounded.root().children_truncated());
    assert_eq!(bounded.root().omitted_children_lower_bound(), 2);

    let budget = PolicyBudget::default();
    with_policy(REFERENCES_POLICY, |policy| {
        let selector = policy
            .resolved_selectors()
            .iter()
            .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
            .expect("match selector");
        let (_, query) = selector.as_query().expect("query selector");
        let walk = run_prefixes(
            query,
            &fixture.context(),
            &reference,
            &budget,
            2,
            PrefixExecution::AnalyzerOnly,
            budget.max_findings(),
        );
        assert_eq!(walk.executed(), 2);
        assert!(walk.prefixes_truncated());
        assert_eq!(walk.omitted_prefixes(), 2);
        assert_eq!(walk.into_stages().len(), 1);
    });
}

#[test]
fn why_not_lineage_distinguishes_sibling_sites_with_the_same_semantic_key() {
    let fixture = Fixture::with_source(TWO_RENDER_REFERENCES);
    let first = TWO_RENDER_REFERENCES
        .find("render;")
        .expect("fixture contains the first reference");
    let second = TWO_RENDER_REFERENCES
        .rfind("render;")
        .expect("fixture contains the second reference");
    assert_ne!(first, second);
    let reference = ExplanationCandidate::at_offset(
        "app.ts",
        u64::try_from(second).expect("fixture offsets fit u64"),
    )
    .expect("candidate");
    let explanation = why_not(
        &fixture,
        REFERENCES_POLICY,
        &reference,
        &PolicyBudget::default(),
    );

    let reference_stage = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "references_of")
        .expect("reference stage");
    let actual = reference_stage.actual().expect("retained row identity");
    let second_range = format!("bytes [{second}, {})", second + "render".len());
    let first_range = format!("bytes [{first}, {})", first + "render".len());
    assert!(actual.contains(&second_range), "{actual}");
    assert!(!actual.contains(&first_range), "{actual}");

    let repeated = why_not(
        &fixture,
        REFERENCES_POLICY,
        &reference,
        &PolicyBudget::default(),
    );
    assert_eq!(explanation.to_json(), repeated.to_json());
    let other_fixture = Fixture::with_source(TWO_RENDER_REFERENCES);
    let independent = why_not(
        &other_fixture,
        REFERENCES_POLICY,
        &reference,
        &PolicyBudget::default(),
    );
    assert_eq!(explanation.to_json(), independent.to_json());
}

#[test]
fn why_not_does_not_blame_a_complete_seed_when_a_later_anchor_change_is_incomplete() {
    let fixture = Fixture::with_source(TWO_RENDER_REFERENCES);
    let second = TWO_RENDER_REFERENCES
        .rfind("render;")
        .expect("fixture contains the second reference");
    let reference = ExplanationCandidate::at_offset(
        "app.ts",
        u64::try_from(second).expect("fixture offsets fit u64"),
    )
    .expect("candidate");
    let budget = PolicyBudget::builder()
        .with_max_findings(1)
        .expect("one retained finding")
        .build()
        .expect("bounded policy budget");

    let explanation = why_not(&fixture, REFERENCES_POLICY, &reference, &budget);

    assert_eq!(
        stage_labels(&explanation),
        vec![(String::from("seed"), ExplanationOutcome::Unknown)],
        "the complete declaration seed cannot exclude a reference candidate that the bounded relation may have omitted"
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    assert!(
        !explanation.root().children_truncated(),
        "every prefix executed; uncertainty comes from the later query's completion, not the prefix budget"
    );
    let seed = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "seed")
        .expect("seed stage");
    assert!(
        seed.reasons()
            .contains(&PolicyIncompleteReason::QueryResultLimit),
        "the seed carries the exact reason the later anchor-changing prefix could not prove absence: {seed:?}"
    );
}

#[test]
fn prefix_walk_charges_preexecuted_prefixes_that_are_not_presented() {
    let fixture = Fixture::new();
    let budget = PolicyBudget::default();
    with_policy(WIDGET_DECLARATION_POLICY, |policy| {
        let selector = policy
            .resolved_selectors()
            .iter()
            .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
            .expect("match selector");
        let (_, query) = selector.as_query().expect("query selector");
        let walk = run_prefixes(
            query,
            &fixture.context(),
            &candidate("loose"),
            &budget,
            2,
            PrefixExecution::AnalyzerOnly,
            budget.max_findings(),
        );

        assert_eq!(walk.executed(), 2, "the seed and deepest prefix both ran");
        assert_eq!(
            walk.into_stages().len(),
            1,
            "presentation stops when the source proves the candidate absent"
        );
    });
}

#[test]
fn why_not_uses_intermediate_lineage_when_a_later_relation_changes_anchor_again() {
    let fixture = Fixture::with_source(RELATIONAL_FIXTURE);
    let reference_offset = u64::try_from(
        RELATIONAL_FIXTURE
            .rfind("render")
            .expect("fixture contains the reference"),
    )
    .expect("fixture offsets fit u64");
    let reference = ExplanationCandidate::at_offset("app.ts", reference_offset).expect("candidate");
    let explanation = why_not(
        &fixture,
        REFERENCE_TARGET_POLICY,
        &reference,
        &PolicyBudget::default(),
    );

    assert_eq!(
        stage_labels(&explanation),
        vec![
            (String::from("seed"), ExplanationOutcome::Satisfied),
            (
                String::from("enclosing_decl"),
                ExplanationOutcome::Satisfied,
            ),
            (
                String::from("occurrences_of"),
                ExplanationOutcome::Satisfied,
            ),
            (
                String::from("occurrence_target"),
                ExplanationOutcome::Unknown,
            ),
        ],
        "the deepest candidate-bearing prefix supplies lineage before the final anchor change"
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    assert!(
        explanation
            .root()
            .actual()
            .expect("root prose")
            .contains("occurrence_target")
    );
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

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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
    relational_why_not_with_budget(fixture, source, candidate, limits, &PolicyBudget::default())
}

fn relational_why_not_with_budget(
    fixture: &Fixture,
    source: &str,
    candidate: &ExplanationCandidate,
    limits: &ExplanationLimits,
    budget: &PolicyBudget,
) -> PolicyExplanation {
    with_policy(source, |policy| {
        explain_candidate(policy, &fixture.context(), candidate, budget, limits)
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

/// Every node a binding carries for the plan's replayed `filter` records.
fn filter_nodes(
    binding: &super::model::ExplanationNode,
) -> Vec<(String, String, ExplanationOutcome)> {
    binding
        .children()
        .iter()
        .filter(|child| child.kind() == ExplanationNodeKind::FilterPredicate)
        .map(|child| {
            (
                child.expected().expect("predicate").to_string(),
                child.actual().expect("row value").to_string(),
                child.outcome(),
            )
        })
        .collect()
}

fn join_replay_gap(explanation: &PolicyExplanation) -> Option<&super::model::ExplanationNode> {
    explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "join_replay_unavailable")
}

#[test]
fn why_not_names_the_filter_predicate_that_removed_the_candidates_row() {
    let fixture = relational_fixture();
    // The declaration name is an occurrence the binding's query returns, so the
    // query is not what removed it: the authored filter is.
    let explanation = relational_why_not(
        &fixture,
        FILTERED_READS_RELATIONAL,
        &relational_candidate("render("),
        &ExplanationLimits::default(),
    );

    assert_eq!(
        binding_labels(&explanation),
        vec![(String::from("read"), ExplanationOutcome::Failed)]
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Failed);
    assert!(
        join_replay_gap(&explanation).is_none(),
        "a filter decided the candidate, so no join replay is owed: {:?}",
        explanation.root().children()
    );

    let binding = &explanation.root().children()[0];
    assert!(
        binding
            .actual()
            .expect("binding prose")
            .contains("filter (read.role eq value_reference) removed it"),
        "{:?}",
        binding.actual()
    );
    assert_eq!(
        child_labels(binding, ExplanationNodeKind::SelectorStage),
        vec![(String::from("occurrences"), ExplanationOutcome::Satisfied)],
        "the query itself retained the row"
    );
    assert_eq!(
        filter_nodes(binding),
        vec![(
            String::from("(read.role eq value_reference)"),
            String::from("`read.role` is declaration_name"),
            ExplanationOutcome::Failed
        )]
    );
}

#[test]
fn why_not_still_defers_to_the_unreplayed_join_when_a_filter_keeps_the_row() {
    let fixture = relational_fixture();
    let explanation = relational_why_not(
        &fixture,
        FILTERED_READS_RELATIONAL,
        &relational_candidate("render;"),
        &ExplanationLimits::default(),
    );

    assert_eq!(
        binding_labels(&explanation),
        vec![(String::from("read"), ExplanationOutcome::Satisfied)]
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    assert!(
        filter_nodes(&explanation.root().children()[0]).is_empty(),
        "a filter the row passes is not a reason for anything"
    );
    let gap = join_replay_gap(&explanation).expect("the unreplayed join is still stated");
    assert_eq!(gap.outcome(), ExplanationOutcome::Unknown);
    assert_eq!(
        gap.reasons(),
        [PolicyIncompleteReason::CapabilityIncomplete]
    );
}

#[test]
fn why_not_replays_only_the_filters_attached_to_the_bindings_own_relation() {
    let fixture = relational_fixture();
    let explanation = relational_why_not(
        &fixture,
        SCOPED_FILTER_RELATIONAL,
        &relational_candidate("render;"),
        &ExplanationLimits::default(),
    );

    assert_eq!(
        binding_labels(&explanation),
        vec![
            (String::from("read"), ExplanationOutcome::Satisfied),
            (String::from("other"), ExplanationOutcome::Failed),
        ]
    );
    assert!(
        filter_nodes(&explanation.root().children()[0]).is_empty(),
        "binding `read` has no filter of its own, and `other`'s does not apply to it"
    );
    assert_eq!(
        filter_nodes(&explanation.root().children()[1]),
        vec![(
            String::from("(other.role eq declaration_name)"),
            String::from("`other.role` is value_reference"),
            ExplanationOutcome::Failed
        )]
    );
}

#[test]
fn why_not_reports_a_filter_drop_over_a_non_exhaustive_binding_as_unknown() {
    // A one-row pipeline budget truncates the binding's query, so a row it did
    // not return may still cover the candidate and pass the filter.
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let fixture = Fixture::with_source(RELATIONAL_TWO_READS);
    let explanation = relational_why_not_with_budget(
        &fixture,
        FILTERED_READS_RELATIONAL,
        &candidate_in(RELATIONAL_TWO_READS, "render("),
        &ExplanationLimits::default(),
        &budget,
    );

    assert_eq!(
        binding_labels(&explanation),
        vec![(String::from("read"), ExplanationOutcome::Unknown)]
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    let binding = &explanation.root().children()[0];
    assert!(
        binding
            .actual()
            .expect("binding prose")
            .contains("not exhaustive"),
        "{:?}",
        binding.actual()
    );
    let filters = filter_nodes(binding);
    assert_eq!(filters.len(), 1, "{filters:?}");
    assert_eq!(filters[0].2, ExplanationOutcome::Unknown);
    assert!(
        !binding.reasons().is_empty(),
        "an undecided filter drop names why it is undecided"
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
    let owned_builds_before = super::host::owned_workspace_build_count_for_test();

    let empty = explain_policy_inputs(
        &root,
        &[],
        &ExplanationTarget::Candidate(candidate.clone()),
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect_err("an explanation is about one policy");
    assert_eq!(
        empty,
        ExplainError::AmbiguousPolicySelection { selected: 0 }
    );
    assert_eq!(
        super::host::owned_workspace_build_count_for_test(),
        owned_builds_before,
        "zero policy inputs are rejected before constructing an owned analyzer"
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
        None,
        &ExplanationLimits::default(),
    )
    .expect_err("an explanation is about one policy");
    assert_eq!(two, ExplainError::AmbiguousPolicySelection { selected: 2 });
}

#[test]
fn cancellation_after_registration_wins_over_ambiguous_selection() {
    let temp = host_workspace(RELATIONAL_FIXTURE, FORBID_READS_RELATIONAL);
    let root = temp.path().canonicalize().expect("canonical root");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::TypeScript));
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .expect("ephemeral workspace");
    let cancellation = brokk_bifrost_analysis::CancellationToken::cancel_after_checks_for_test(5);
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");

    let error = explain_policy_inputs(
        &root,
        &[
            PolicyEvaluationInput::workspace_file("policies/explain.rqlp"),
            PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new("test:explain-second"),
                LOOSE_POLICY,
            ),
        ],
        &ExplanationTarget::Candidate(candidate),
        Some(&workspace),
        None,
        Some(&cancellation),
        &ExplanationLimits::default(),
    )
    .expect_err("cancellation after the final registration wins before selection");

    assert_eq!(
        error,
        ExplainError::PolicyUnavailable {
            message: "policy explanation cancelled".to_string()
        }
    );
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
        None,
        &ExplanationLimits::default(),
    )
    .expect_err("a missing policy file is a stated condition, not a panic");
    assert!(
        matches!(error, ExplainError::PolicyUnavailable { .. }),
        "{error:?}"
    );
}

#[test]
fn the_host_honors_front_door_cancellation_before_loading_policy_inputs() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", FIXTURE)
        .build();
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");
    let cancellation = brokk_bifrost_analysis::CancellationToken::new();
    cancellation.cancel();

    let error = explain_policy_inputs(
        project.root(),
        &[PolicyEvaluationInput::workspace_file(
            "policies/absent.rqlp",
        )],
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        Some(&cancellation),
        &ExplanationLimits::default(),
    )
    .expect_err("explicit cancellation wins before the absent input is loaded");
    assert_eq!(
        error,
        ExplainError::PolicyUnavailable {
            message: "policy explanation cancelled".to_string()
        }
    );
}

#[test]
fn the_host_resolves_qualified_call_and_receiver_locators_with_its_owned_analyzer() {
    const SOURCE: &str = r#"class Widget {
    int create(int value) { return value; }
}

class Caller {
    int run(Widget widget) { return widget.create(1); }
}
"#;
    const POLICY: &str = r#"(policy
  :id "test.explain.qualified-locators"
  :name "Qualified locators"
  :message "Widget.create is selected"
  :severity warning
  :analysis (analysis :type assertion
    (bind :name calls :query
      (rql (call-bindings (call-shape (call :callee "create")))))
    (call :over calls :resolves-to "Widget.create" :proof exact
          :receiver-type "Widget")))"#;

    let project = InlineTestProject::with_language(Language::Java)
        .file("Example.java", SOURCE)
        .file("policies/qualified.rqlp", POLICY)
        .build();
    let root = project.root();
    let inputs = [PolicyEvaluationInput::workspace_file(
        "policies/qualified.rqlp",
    )];
    let offset = u64::try_from(SOURCE.find("widget.create").expect("call site"))
        .expect("fixture offset fits u64");
    let candidate =
        ExplanationCandidate::at_offset("Example.java", offset).expect("candidate location");

    let explanation = explain_policy_inputs(
        root,
        &inputs,
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect("owned-analyzer registration resolves both qualified locators");
    assert_eq!(explanation.question(), ExplanationQuestion::WhyNot);
    assert_eq!(
        explanation.policy_id().as_str(),
        "test.explain.qualified-locators"
    );
}

#[test]
fn the_host_explains_a_retained_finding_after_a_malformed_packs_document() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", FIXTURE)
        .file("policies/explain.rqlp", LOOSE_POLICY)
        .file(".bifrost/packs.json", "{ not json")
        .build();
    let root = project.root();
    let inputs = [PolicyEvaluationInput::workspace_file(
        "policies/explain.rqlp",
    )];

    let options =
        PolicyEvaluationOptions::new("2026-08-28".parse().expect("fixed explanation parity date"));
    let outcome = evaluate_policy_inputs(root, &inputs, &options)
        .expect("normal evaluation diagnoses packs and continues");
    assert!(
        outcome
            .report()
            .diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.code() == PolicyReportDiagnosticCode::PacksLoadFailed })
    );
    let [run] = outcome.report().runs() else {
        panic!("one normal policy run");
    };
    let finding_id = only_finding(run);

    let explanation = explain_policy_inputs(
        root,
        &inputs,
        &ExplanationTarget::Finding(finding_id),
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect("the retained unreliable finding remains explainable");
    assert_eq!(explanation.question(), ExplanationQuestion::Why);
    assert!(matches!(
        explanation.subject(),
        ExplanationSubject::Finding { finding_id: explained, .. } if *explained == finding_id
    ));
}

// --- flow and taint: why ----------------------------------------------------

/// A flow policy over the same fixture. The solver is faked below, so what the
/// selectors spell only has to load and resolve.
const FLOW_POLICY: &str = r#"(policy
  :id "test.explain.flow"
  :name "Flow"
  :message "the tracked value reached the observation"
  :severity warning
  :analysis (analysis
    :type flow
    :mode may
    :origins (endpoint-set :entries [
      (origin :id reader :display-name "Reader.read"
        :selector (rql (name "alpha")) :bind return-value)])
    :observations (endpoint-set :entries [
      (observation :id writer :display-name "Store.put"
        :selector (rql (name "store")) :observed-operand matched-value)])))"#;

/// How much retained evidence one faked projection carries.
///
/// Every field is a retained fact the adapter must project honestly, so each
/// test names the shape it wants rather than sharing one maximal fixture. The
/// fake is the solver, not the projection: the run below is assembled,
/// validated, and retained by the production evaluator.
#[derive(Debug, Clone, Copy)]
struct FakePath {
    /// Retain one witness with three steps.
    witness: bool,
    /// That witness itself dropped steps.
    witness_steps_truncated: bool,
    /// The finding dropped whole witnesses.
    witnesses_truncated: bool,
    /// The path is reported but not proved.
    unproven: bool,
    /// Retain one related site no origin states.
    extra_related: bool,
}

impl FakePath {
    const fn proved() -> Self {
        Self {
            witness: true,
            witness_steps_truncated: false,
            witnesses_truncated: false,
            unproven: false,
            extra_related: false,
        }
    }
}

struct FakePathAdapter {
    shape: FakePath,
}

impl crate::projection::sealed::TaintAdapter for FakePathAdapter {}

impl crate::evaluator::TaintPolicyEvaluator for FakePathAdapter {
    fn evaluate_taint(
        &self,
        _authority: &crate::projection::TaintProjectionAuthority,
        _policy: &LoadedPolicy,
        spec: &crate::resolved::ResolvedTaintPolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> crate::projection::TaintProjectionPayload {
        crate::projection::TaintProjectionPayload {
            projections: vec![fake_projection(spec, self.shape)],
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: crate::finding::PolicyWorkReport::default(),
            authored_arm_closures: Vec::new(),
        }
    }
}

fn path_location(start: u64, end: u64, line: u64) -> PolicySourceLocation {
    PolicySourceLocation::span(
        brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new("app.ts")
            .expect("workspace-relative path"),
        crate::finding::PolicyByteSpan::new(start, end).expect("a forward span"),
        crate::finding::PolicyDisplayRegion::new(line, 1, line, 2).expect("a display region"),
    )
}

/// The observation site, which is the finding's own anchor.
fn observation_location() -> PolicySourceLocation {
    path_location(40, 41, 4)
}

fn origin_location() -> PolicySourceLocation {
    path_location(0, 1, 1)
}

fn fake_projection(
    spec: &crate::resolved::ResolvedTaintPolicySpec,
    shape: FakePath,
) -> crate::projection::TaintProjectedFinding {
    use crate::definition::TaintLabel;
    use crate::finding::{
        BoundedWitness, CertaintyReason, FindingCertainty, FindingCompleteness,
        FindingIncompleteReason, PolicyLocationRelationship, ProofMetadata, ProofReason,
        ProofState, RelatedPolicyLocation, WitnessStep, WitnessStepKind,
    };
    use crate::finding_identity::{
        AnalysisEventRef, AnalysisFindingId, EvidenceRef, SourceScenarioId, StableSemanticIdentity,
        WitnessId,
    };
    use crate::future_evidence::{
        TaintFindingAnchor, TaintPolicyProjectionFacts, TaintSourceProjectionFact,
    };

    let source = &spec.sources[0];
    let sink = &spec.sinks[0];
    let label = source
        .definition
        .labels
        .first()
        .cloned()
        .unwrap_or_else(|| TaintLabel::new("untrusted").expect("a valid label"));
    let scenario = SourceScenarioId::try_new("test", "root").expect("a scenario id");
    let evidence_ref = EvidenceRef::try_new("test", "origin-alpha").expect("an evidence ref");
    let source_fact = TaintSourceProjectionFact::try_new(
        source.identity.clone(),
        source.semantic_hash,
        source.analysis_projection_hash,
        source.definition.display_name.clone(),
        source.definition.categories.clone(),
        label.clone(),
        source.definition.evidence.clone(),
        vec![scenario.clone()],
        evidence_ref.clone(),
    )
    .expect("a valid source fact");
    let facts = TaintPolicyProjectionFacts::try_new(
        sink.identity.clone(),
        sink.semantic_hash,
        sink.analysis_projection_hash,
        sink.definition.display_name.clone(),
        sink.definition.categories.clone(),
        sink.definition.tags.clone(),
        sink.definition.impacts.clone(),
        vec![label.clone()],
        vec![source_fact],
        &PolicyBudget::default(),
    )
    .expect("valid projection facts");
    let anchor = TaintFindingAnchor::strong(
        StableSemanticIdentity::analyzer_declaration_id(
            "typescript",
            brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new("app.ts")
                .expect("workspace-relative path"),
            "function:store",
        )
        .expect("a stable sink identity"),
        0,
        source.analysis_projection_hash,
        sink.analysis_projection_hash,
        crate::cvss::SourceScenarioSetHash::try_from_scenarios(vec![scenario.clone()])
            .expect("a scenario set hash"),
    )
    .expect("a strong anchor");

    let witnesses = if shape.witness {
        vec![
            BoundedWitness::try_new(
                WitnessId::try_new("test", "path-0").expect("a witness id"),
                vec![
                    WitnessStep::try_new(
                        WitnessStepKind::Source,
                        Some(origin_location()),
                        "value read",
                        vec![evidence_ref.clone()],
                    )
                    .expect("a valid step"),
                    WitnessStep::try_new(
                        WitnessStepKind::Call,
                        Some(path_location(20, 21, 2)),
                        "helper call",
                        Vec::new(),
                    )
                    .expect("a valid step"),
                    WitnessStep::try_new(
                        WitnessStepKind::Propagation,
                        Some(observation_location()),
                        "reaches the observed operand",
                        Vec::new(),
                    )
                    .expect("a valid step"),
                ],
                shape.witness_steps_truncated,
                u64::from(shape.witness_steps_truncated),
            )
            .expect("a valid witness"),
        ]
    } else {
        Vec::new()
    };
    let witness_refs = witnesses
        .iter()
        .map(|witness| witness.id().clone())
        .collect::<Vec<_>>();

    let mut incomplete = Vec::new();
    if shape.unproven {
        incomplete.push(FindingIncompleteReason::ProofPartial);
    }
    if shape.witness_steps_truncated || shape.witnesses_truncated {
        incomplete.push(FindingIncompleteReason::WitnessTruncated);
    }
    incomplete.sort();
    incomplete.dedup();
    let completeness = if incomplete.is_empty() {
        FindingCompleteness::Complete
    } else {
        FindingCompleteness::partial(incomplete).expect("canonical reasons")
    };
    let certainty = if shape.unproven {
        FindingCertainty::possible(vec![
            CertaintyReason::analyzer_ambiguity("flow-unproven-path")
                .expect("a valid ambiguity code"),
        ])
        .expect("canonical reasons")
    } else {
        FindingCertainty::Definite
    };
    let mut related = vec![
        RelatedPolicyLocation::try_new(
            PolicyLocationRelationship::Source,
            origin_location(),
            Vec::new(),
        )
        .expect("a valid related location"),
    ];
    if shape.extra_related {
        related.push(
            RelatedPolicyLocation::try_new(
                PolicyLocationRelationship::Source,
                path_location(60, 61, 6),
                Vec::new(),
            )
            .expect("a valid related location"),
        );
    }

    crate::projection::TaintProjectedFinding {
        facts,
        pairs: vec![crate::projection::TaintPairProjection {
            source_endpoint: source.identity.clone(),
            analysis_finding_id: AnalysisFindingId::try_new("test", "path-finding")
                .expect("an analysis finding id"),
            anchor,
            sink: AnalysisEventRef::try_new("test", "observation-0").expect("an event ref"),
            origins: vec![crate::projection::TaintOriginProjection {
                source_endpoint: source.identity.clone(),
                source_label: label,
                source_evidence: source.definition.evidence.clone(),
                primary: origin_location(),
                scenario_id: scenario,
                evidence_refs: vec![evidence_ref],
            }],
            origins_truncated: false,
            witness_refs,
            // The projection authority requires this to equal the report's own
            // witness truncation flag (`validate_witness_references`).
            witness_refs_truncated: shape.witnesses_truncated,
            report: crate::projection::ProjectedFindingReport {
                primary: observation_location(),
                certainty,
                completeness,
                related,
                related_truncated: false,
                omitted_related_locations_lower_bound: 0,
                evidence_refs_truncated: false,
                omitted_evidence_refs_lower_bound: 0,
                proof: ProofMetadata::try_new(
                    if shape.unproven {
                        ProofState::Unproven
                    } else {
                        ProofState::Proven
                    },
                    vec![ProofReason::DataflowWitness],
                    Vec::new(),
                )
                .expect("valid proof metadata"),
                witnesses,
                witnesses_truncated: shape.witnesses_truncated,
                omitted_witnesses_lower_bound: u64::from(shape.witnesses_truncated),
                display_path: None,
            },
        }],
    }
}

/// One evaluated run of `source` whose solver is the fake above.
fn path_run(fixture: &Fixture, source: &str, shape: FakePath) -> PolicyRun {
    let registry = registry(source);
    let policy = registry.policies().next().expect("one loaded policy");
    let adapter = FakePathAdapter { shape };
    let run = DefaultPolicyEvaluator::new()
        .with_taint(&adapter)
        .evaluate(policy, &fixture.context(), &mut PolicyBudget::default())
        .expect("policy evaluation");
    assert_eq!(
        run.findings().len(),
        1,
        "the fake solver projects one finding; completion={:?} diagnostics={:?}",
        run.completion(),
        run.diagnostics()
    );
    run
}

fn root_child<'a>(
    explanation: &'a PolicyExplanation,
    label: &str,
) -> &'a super::model::ExplanationNode {
    explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == label)
        .unwrap_or_else(|| panic!("a {label} node: {:#?}", explanation.root().children()))
}

#[test]
fn why_explains_a_flow_finding_from_its_retained_witness_path() {
    let fixture = Fixture::new();
    let run = path_run(&fixture, FLOW_POLICY, FakePath::proved());
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Flow);
    let id = only_finding(&run);
    let explanation = explain_finding(&run, &id, &ExplanationLimits::default())
        .expect("the flow adapter answers");

    assert_eq!(explanation.format(), POLICY_EXPLANATION_FORMAT);
    assert_eq!(explanation.question(), ExplanationQuestion::Why);
    assert_eq!(explanation.analysis_type(), PolicyAnalysisType::Flow);
    assert_eq!(explanation.outcome(), ExplanationOutcome::Satisfied);
    assert_eq!(explanation.root().label(), "flow_finding");

    let finding = &run.findings()[0];
    assert_eq!(explanation.root().location(), Some(finding.primary()));
    assert_eq!(explanation.root().actual(), Some(finding.message()));
    let expected = explanation.root().expected().expect("root prose");
    assert!(expected.contains("Reader.read"), "{expected}");
    assert!(expected.contains("Store.put"), "{expected}");

    // The origin is a satisfied source fact at the exact site the run kept.
    assert_eq!(
        child_labels(explanation.root(), ExplanationNodeKind::SourceFact),
        vec![(String::from("origin"), ExplanationOutcome::Satisfied)]
    );
    assert_eq!(
        root_child(&explanation, "origin").location(),
        Some(&origin_location())
    );

    // The witness path is one derivation whose children are its steps in path
    // order, each carrying the step's own kind and exact site.
    let path = root_child(&explanation, "witness_path");
    assert_eq!(path.kind(), ExplanationNodeKind::Derivation);
    let witness = &finding.witnesses()[0];
    assert!(
        path.actual()
            .expect("path prose")
            .contains(witness.id().as_str())
    );
    let steps: Vec<(String, Option<&PolicySourceLocation>)> = path
        .children()
        .iter()
        .map(|node| (node.label().to_string(), node.location()))
        .collect();
    assert_eq!(
        steps,
        witness
            .steps()
            .iter()
            .map(|step| (step.kind().label().to_string(), step.location()))
            .collect::<Vec<_>>(),
        "the path nodes are the retained steps, in the retained order"
    );
    assert!(
        path.children()
            .iter()
            .all(|step| step.outcome() == ExplanationOutcome::Satisfied)
    );

    // A proved, complete, definite finding over a reliable run has no unknown.
    assert!(
        explanation
            .nodes()
            .iter()
            .all(|node| node.outcome() == ExplanationOutcome::Satisfied),
        "{:#?}",
        explanation
            .nodes()
            .iter()
            .filter(|node| node.outcome() != ExplanationOutcome::Satisfied)
            .collect::<Vec<_>>()
    );
}

/// The parity discipline the match adapter established, in both directions:
/// every location an explanation publishes was retained by the finding, and
/// every site the finding retained is published.
#[test]
fn flow_why_locations_all_trace_back_to_retained_finding_evidence() {
    let fixture = Fixture::new();
    let shape = FakePath {
        extra_related: true,
        ..FakePath::proved()
    };
    let run = path_run(&fixture, FLOW_POLICY, shape);
    let id = only_finding(&run);
    let explanation =
        explain_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Flow { evidence } = finding.evidence() else {
        panic!("a flow run retains flow evidence");
    };

    let mut retained: Vec<PolicySourceLocation> = vec![finding.primary().clone()];
    retained.extend(
        evidence
            .origins()
            .iter()
            .map(|origin| origin.primary().clone()),
    );
    retained.extend(
        finding
            .related()
            .iter()
            .map(|related| related.location().clone()),
    );
    for witness in finding.witnesses() {
        retained.extend(
            witness
                .steps()
                .iter()
                .filter_map(|step| step.location().cloned()),
        );
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
    let published: Vec<&PolicySourceLocation> = explanation
        .nodes()
        .iter()
        .filter_map(|node| node.location())
        .collect();
    for location in &retained {
        assert!(
            published.contains(&location),
            "the explanation drops a retained site: {location:?}"
        );
    }

    // The related site no origin states is published exactly once, and the
    // origin's own site is not published twice as a bare row.
    let rows = explanation
        .root()
        .children()
        .iter()
        .filter(|node| node.label() == "source_row")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "{rows:#?}");
    assert_eq!(rows[0].location(), Some(&path_location(60, 61, 6)));
}

/// Truncated and unproven evidence is `unknown`, never `failed`, and each
/// obligation says what is missing.
#[test]
fn flow_why_reports_missing_evidence_as_unknown_obligations() {
    let fixture = Fixture::new();
    let shape = FakePath {
        witness_steps_truncated: true,
        witnesses_truncated: true,
        unproven: true,
        ..FakePath::proved()
    };
    let run = path_run(&fixture, FLOW_POLICY, shape);
    let id = only_finding(&run);
    let explanation =
        explain_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");

    assert!(
        explanation
            .nodes()
            .iter()
            .all(|node| node.outcome() != ExplanationOutcome::Failed),
        "a why answer never reports a retained finding's limits as failure"
    );
    assert_eq!(
        child_labels(explanation.root(), ExplanationNodeKind::CoverageObligation),
        vec![
            (
                String::from("finding_certainty"),
                ExplanationOutcome::Unknown
            ),
            (String::from("path_proof"), ExplanationOutcome::Unknown),
            (
                String::from("retained_witnesses"),
                ExplanationOutcome::Unknown
            ),
            (
                String::from("finding_completeness"),
                ExplanationOutcome::Unknown
            ),
            (
                String::from("run_completion"),
                ExplanationOutcome::Satisfied
            ),
        ]
    );
    let prose = |label: &str| {
        root_child(&explanation, label)
            .actual()
            .expect("obligation prose")
            .to_string()
    };
    assert!(
        prose("finding_certainty").contains("flow-unproven-path"),
        "the may-evidence reason stays visible: {}",
        prose("finding_certainty")
    );
    assert!(prose("path_proof").contains("unproven"));
    assert!(
        prose("retained_witnesses").contains("omitted"),
        "{}",
        prose("retained_witnesses")
    );
    assert!(
        prose("finding_completeness").contains("witness_truncated"),
        "{}",
        prose("finding_completeness")
    );

    // The truncated path states its own dropped steps, and the root states the
    // whole paths the finding dropped.
    let path = root_child(&explanation, "witness_path");
    assert!(path.children_truncated());
    assert_eq!(path.omitted_children_lower_bound(), 1);
    assert!(explanation.root().children_truncated());
    assert!(explanation.root().omitted_children_lower_bound() >= 1);
}

/// A finding with no retained witness explains what is missing instead of
/// pretending the path is walkable.
#[test]
fn flow_why_states_an_absent_witness_rather_than_an_empty_path() {
    let fixture = Fixture::new();
    let shape = FakePath {
        witness: false,
        ..FakePath::proved()
    };
    let run = path_run(&fixture, FLOW_POLICY, shape);
    let id = only_finding(&run);
    let explanation =
        explain_finding(&run, &id, &ExplanationLimits::default()).expect("explanation");

    assert!(
        !explanation
            .nodes()
            .iter()
            .any(|node| node.kind() == ExplanationNodeKind::Derivation),
        "no witness was retained, so no path is invented"
    );
    let node = root_child(&explanation, "retained_witnesses");
    assert_eq!(node.outcome(), ExplanationOutcome::Unknown);
    assert!(
        node.actual()
            .expect("prose")
            .contains("no path is available to walk"),
        "{:?}",
        node.actual()
    );
}

#[test]
fn why_explains_a_taint_finding_in_the_security_vocabulary() {
    let fixture = Fixture::new();
    let run = path_run(&fixture, TAINT_POLICY, FakePath::proved());
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Taint);
    let id = only_finding(&run);
    let explanation = explain_finding(&run, &id, &ExplanationLimits::default())
        .expect("the taint adapter answers");

    assert_eq!(explanation.analysis_type(), PolicyAnalysisType::Taint);
    assert_eq!(explanation.root().label(), "taint_finding");
    let expected = explanation.root().expected().expect("root prose");
    assert!(expected.contains("user input"), "{expected}");
    assert!(expected.contains("sensitive store"), "{expected}");

    let PolicyFindingEvidence::Taint { evidence } = run.findings()[0].evidence() else {
        panic!("a taint run retains taint evidence");
    };
    let origin = root_child(&explanation, "taint_origin");
    assert!(
        origin
            .actual()
            .expect("origin prose")
            .contains(evidence.origins()[0].scenario_id().as_str()),
        "the retained source scenario is named: {:?}",
        origin.actual()
    );
    assert!(
        origin
            .expected()
            .expect("origin prose")
            .contains(evidence.origins()[0].source_label().as_str())
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn flow_why_explanations_serialize_byte_identically_across_runs() {
    let fixture = Fixture::new();
    let run = path_run(&fixture, FLOW_POLICY, FakePath::proved());
    let id = only_finding(&run);
    let first = explain_finding(&run, &id, &ExplanationLimits::default()).expect("first");
    let second = explain_finding(&run, &id, &ExplanationLimits::default()).expect("second");
    assert_eq!(first.to_json(), second.to_json());

    let other_fixture = Fixture::new();
    let other_run = path_run(&other_fixture, FLOW_POLICY, FakePath::proved());
    let other_id = only_finding(&other_run);
    let third =
        explain_finding(&other_run, &other_id, &ExplanationLimits::default()).expect("third");
    assert_eq!(first.to_json(), third.to_json());
    assert_eq!(first.root().id(), third.root().id());
}

#[test]
fn the_node_limit_bounds_a_flow_why_answer() {
    let fixture = Fixture::new();
    let run = path_run(&fixture, FLOW_POLICY, FakePath::proved());
    let id = only_finding(&run);
    let full = explain_finding(&run, &id, &ExplanationLimits::default()).expect("full");
    assert!(full.node_count() > 3);
    let bounded = explain_finding(&run, &id, &ExplanationLimits::default().with_max_nodes(3))
        .expect("bounded");
    assert_eq!(bounded.node_count(), 3);
    assert!(bounded.truncation().nodes_truncated());
    assert_eq!(
        bounded.truncation().omitted_nodes_lower_bound(),
        full.node_count() - 3
    );
}

// --- near-miss ranking (issue 2500) -----------------------------------------

/// Three methods across two classes: the exact target, a near miss that shares
/// the member name on the wrong class, and a member that shares neither. This
/// is the P0 near-miss shape in miniature.
const NEAR_MISS_FIXTURE: &str = "export class Widget {\n  render() {}\n}\nexport class Gadget {\n  render() {}\n  reset() {}\n}\n";

/// A seed with exactly two declared predicates over a bounded kind scope, so
/// the ladder is `scope`, `root.name`, `inside_decl` and the three fixture
/// members land at three distinct distances.
const EXACT_MEMBER_POLICY: &str = r#"(policy
  :id "test.near-miss.exact-member"
  :name "Widget.render"
  :message "Widget.render is reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (inside-decl (class :name "Widget") (method :name "render")))))"#;

/// The same invariant with no kind union on the seed root, which therefore has
/// no bounded search scope at all.
const UNSCOPED_POLICY: &str = r#"(policy
  :id "test.near-miss.unscoped"
  :name "Anything called render"
  :message "render is reported"
  :severity warning
  :analysis (analysis :type match :selector (rql (name "render"))))"#;

fn near_miss_fixture() -> Fixture {
    Fixture::with_source(NEAR_MISS_FIXTURE)
}

fn rank(
    fixture: &Fixture,
    source: &str,
    candidates: &NearMissCandidates,
    limits: &ExplanationLimits,
) -> PolicyNearMissRanking {
    with_policy(source, |policy| {
        rank_near_misses(
            policy,
            &fixture.context(),
            candidates,
            &PolicyBudget::default(),
            limits,
        )
        .expect("the fixture policy ranks")
    })
}

/// The fixture text one ranked subject covers.
fn ranked_source(ranking: &PolicyNearMissRanking, rank: usize) -> &str {
    let ExplanationSubject::Candidate {
        byte_start,
        byte_end,
        ..
    } = ranking.entries()[rank].subject()
    else {
        panic!("a near-miss subject is always a candidate position");
    };
    &NEAR_MISS_FIXTURE[usize::try_from(*byte_start).unwrap()..usize::try_from(*byte_end).unwrap()]
}

#[test]
fn near_miss_ranks_by_declared_predicate_distance_and_names_the_failing_conjunct() {
    let fixture = near_miss_fixture();
    let ranking = rank(
        &fixture,
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default(),
    );

    assert_eq!(ranking.format(), POLICY_NEAR_MISS_FORMAT);
    assert_eq!(ranking.format(), "bifrost_policy_near_miss/v1");
    assert_eq!(ranking.question(), ExplanationQuestion::NearMiss);
    assert_eq!(ranking.analysis_type(), PolicyAnalysisType::Match);
    assert_eq!(
        ranking.conjuncts(),
        ["scope", "root.name", "inside_decl"],
        "the ladder restores the root's own predicate before its context"
    );
    assert_eq!(ranking.executions_used(), 3);
    assert!(!ranking.truncation().is_truncated(), "{ranking:#?}");

    // Enumeration came from the policy's own seed scope, not a workspace walk.
    let NearMissEnumeration::PolicySeed {
        scope,
        rows,
        exhaustive,
    } = ranking.enumeration()
    else {
        panic!("the seed search reports its scope: {ranking:#?}");
    };
    assert!(scope.contains("method"), "{scope}");
    assert!(*exhaustive, "{ranking:#?}");
    assert_eq!(*rows, ranking.candidates_considered());
    assert_eq!(ranking.entries().len(), 3, "{ranking:#?}");

    // Distance 0: the subject the policy actually selects.
    let matched = &ranking.entries()[0];
    assert_eq!(matched.rank(), 1);
    assert_eq!(matched.outcome(), ExplanationOutcome::Satisfied);
    assert_eq!(matched.unsatisfied_conjuncts(), 0);
    assert_eq!(matched.satisfied_conjuncts(), 3);
    assert_eq!(matched.declared_conjuncts(), 3);
    assert_eq!(matched.failing_conjunct(), None);

    // Distance 1: the near miss. It satisfies the member name and fails only
    // the class it sits in, and the failing conjunct says exactly that.
    let near = &ranking.entries()[1];
    assert_eq!(near.rank(), 2);
    assert_eq!(
        near.outcome(),
        ExplanationOutcome::Failed,
        "an exhaustive rung that did not return the subject is failed, not unknown: {near:#?}"
    );
    assert_eq!(near.unsatisfied_conjuncts(), 1);
    assert_eq!(near.failing_conjunct(), Some("inside_decl"));
    assert!(near.reasons().is_empty(), "{near:#?}");

    // Distance 2: unrelated code, which fails the member name too.
    let unrelated = &ranking.entries()[2];
    assert_eq!(unrelated.unsatisfied_conjuncts(), 2);
    assert_eq!(unrelated.failing_conjunct(), Some("root.name"));

    // The near miss really is the same-named member on the wrong class, and it
    // ranks above the member that shares nothing.
    assert!(
        ranked_source(&ranking, 1).starts_with("render"),
        "{ranking:#?}"
    );
    assert!(
        ranked_source(&ranking, 2).starts_with("reset"),
        "{ranking:#?}"
    );
    assert!(
        near.unsatisfied_conjuncts() < unrelated.unsatisfied_conjuncts(),
        "{ranking:#?}"
    );
}

#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn near_miss_rankings_serialize_byte_identically_across_runs() {
    let limits = ExplanationLimits::default();
    let first = rank(
        &near_miss_fixture(),
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &limits,
    );
    let second = rank(
        &near_miss_fixture(),
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &limits,
    );
    assert_eq!(first.to_json(), second.to_json());
    assert!(first.to_json().contains("bifrost_policy_near_miss/v1"));
}

#[test]
fn a_supplied_candidate_outside_the_scope_fails_the_scope_conjunct() {
    let fixture = near_miss_fixture();
    let inside = u64::try_from(NEAR_MISS_FIXTURE.find("reset").expect("fixture")).unwrap();
    let outside = u64::try_from(NEAR_MISS_FIXTURE.find("export").expect("fixture")).unwrap();
    let ranking = rank(
        &fixture,
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::Supplied(vec![
            ExplanationCandidate::at_offset("app.ts", outside).expect("candidate"),
            ExplanationCandidate::at_offset("app.ts", inside).expect("candidate"),
        ]),
        &ExplanationLimits::default(),
    );

    assert_eq!(
        ranking.enumeration(),
        &NearMissEnumeration::Supplied { supplied: 2 },
        "a supplied list is never searched for"
    );
    assert_eq!(ranking.entries().len(), 2);
    assert_eq!(ranking.entries()[0].failing_conjunct(), Some("root.name"));
    assert_eq!(ranking.entries()[0].unsatisfied_conjuncts(), 2);
    let refused = &ranking.entries()[1];
    assert_eq!(
        refused.failing_conjunct(),
        Some("scope"),
        "a subject the policy's own kind pruning excludes fails the scope conjunct: {refused:#?}"
    );
    assert_eq!(refused.unsatisfied_conjuncts(), 3);
}

#[test]
fn the_candidate_limit_bounds_a_ranking_and_reports_the_truncation() {
    let fixture = near_miss_fixture();
    let full = rank(
        &fixture,
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default(),
    );
    let bounded = rank(
        &fixture,
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default().with_max_near_miss_candidates(1),
    );

    assert_eq!(bounded.entries().len(), 1);
    assert_eq!(
        bounded.candidates_considered(),
        full.candidates_considered(),
        "the bound retains fewer subjects; it does not measure fewer"
    );
    assert!(bounded.truncation().candidates_truncated());
    assert_eq!(
        bounded.truncation().omitted_candidates_lower_bound(),
        full.candidates_considered() - 1
    );
    assert_eq!(bounded.entries()[0], full.entries()[0]);
}

#[test]
fn the_retained_byte_limit_bounds_a_ranking_and_reports_the_truncation() {
    let bounded = rank(
        &near_miss_fixture(),
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default().with_max_retained_bytes(1),
    );
    assert!(bounded.entries().is_empty());
    assert!(bounded.truncation().bytes_truncated());
    assert!(bounded.truncation().omitted_bytes_lower_bound() > 0);
    assert!(bounded.truncation().candidates_truncated());
}

#[test]
fn the_text_limit_cuts_ranking_prose_and_reports_the_bytes() {
    let bounded = rank(
        &near_miss_fixture(),
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default().with_max_text_bytes(8),
    );
    assert!(bounded.truncation().text_truncated());
    assert!(bounded.truncation().omitted_text_bytes_lower_bound() > 0);
    for entry in bounded.entries() {
        assert!(entry.actual().len() <= 8, "{entry:#?}");
    }
}

#[test]
fn the_execution_limit_leaves_every_surviving_subject_unknown_rather_than_selected() {
    let bounded = rank(
        &near_miss_fixture(),
        EXACT_MEMBER_POLICY,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default().with_max_near_miss_executions(1),
    );

    assert_eq!(bounded.executions_used(), 1);
    assert!(bounded.truncation().executions_truncated());
    assert_eq!(bounded.truncation().omitted_executions_lower_bound(), 2);
    for entry in bounded.entries() {
        assert_eq!(
            entry.outcome(),
            ExplanationOutcome::Unknown,
            "a ladder the budget cut short can never report selection: {entry:#?}"
        );
        assert_eq!(
            entry.reasons(),
            [PolicyIncompleteReason::ReportRetentionBudget]
        );
        assert_eq!(entry.satisfied_conjuncts(), 1);
        assert_eq!(entry.unsatisfied_conjuncts(), 2);
        assert_eq!(entry.failing_conjunct(), None);
    }
}

#[test]
fn an_undecided_subject_never_outranks_a_decided_one_at_the_same_distance() {
    // A one-row pipeline budget makes every rung non-exhaustive, so an absence
    // inside it is undecided rather than evidence of absence.
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let fixture = near_miss_fixture();
    let ranking = with_policy(EXACT_MEMBER_POLICY, |policy| {
        rank_near_misses(
            policy,
            &fixture.context(),
            &NearMissCandidates::PolicySeedSearch,
            &budget,
            &ExplanationLimits::default(),
        )
        .expect("a truncated ranking is still well formed")
    });

    let NearMissEnumeration::PolicySeed { exhaustive, .. } = ranking.enumeration() else {
        panic!("the seed search reports its scope");
    };
    assert!(
        !exhaustive,
        "a truncated scope query is not an exhaustive candidate set: {ranking:#?}"
    );
    for entry in ranking.entries() {
        if entry.outcome() == ExplanationOutcome::Unknown {
            assert!(
                !entry.reasons().is_empty(),
                "an undecided subject names why: {entry:#?}"
            );
        }
        assert!(
            entry.unsatisfied_conjuncts() <= entry.declared_conjuncts(),
            "incompleteness never inflates distance past the declared conjuncts: {entry:#?}"
        );
    }
    // Ordering: distance first, then decidedness, so incompleteness never
    // reorders two subjects that are equally far away.
    let keys = ranking
        .entries()
        .iter()
        .map(|entry| (entry.unsatisfied_conjuncts(), entry.outcome()))
        .collect::<Vec<_>>();
    let mut sorted = keys.clone();
    sorted.sort_by_key(|(distance, outcome)| {
        (
            *distance,
            match outcome {
                ExplanationOutcome::Satisfied => 0u8,
                ExplanationOutcome::Failed => 1,
                ExplanationOutcome::Unknown => 2,
            },
        )
    });
    assert_eq!(keys, sorted, "{ranking:#?}");
}

#[test]
fn a_policy_with_no_bounded_scope_is_refused_rather_than_scanned() {
    let fixture = near_miss_fixture();
    let error = with_policy(UNSCOPED_POLICY, |policy| {
        rank_near_misses(
            policy,
            &fixture.context(),
            &NearMissCandidates::PolicySeedSearch,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .expect_err("an unscoped seed has nothing bounded to enumerate")
    });
    assert!(
        matches!(error, ExplainError::NearMissScopeUnavailable { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("kind union"), "{error}");
}

#[test]
fn near_miss_refuses_the_families_it_has_no_adapter_for() {
    let fixture = near_miss_fixture();
    let error = with_policy(TAINT_POLICY, |policy| {
        rank_near_misses(
            policy,
            &fixture.context(),
            &NearMissCandidates::PolicySeedSearch,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .expect_err("a taint policy has no selector plan to relax")
    });
    assert!(
        matches!(
            &error,
            ExplainError::ExplanationAdapterUnavailable { question, supported, .. }
                if *question == ExplanationQuestion::NearMiss
                    && supported == NEAR_MISS_ADAPTER_ANALYSIS_TYPES
        ),
        "{error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("supported analysis types: match, assertion"),
        "{error}"
    );
}

#[test]
fn a_ranking_that_cannot_hold_one_execution_or_one_candidate_is_refused() {
    let fixture = near_miss_fixture();
    for (limits, expected) in [
        (
            ExplanationLimits::default().with_max_near_miss_executions(0),
            ExplanationBudgetLimit::NearMissExecutions,
        ),
        (
            ExplanationLimits::default().with_max_near_miss_candidates(0),
            ExplanationBudgetLimit::NearMissCandidates,
        ),
    ] {
        let error = with_policy(EXACT_MEMBER_POLICY, |policy| {
            rank_near_misses(
                policy,
                &fixture.context(),
                &NearMissCandidates::PolicySeedSearch,
                &PolicyBudget::default(),
                &limits,
            )
            .expect_err("a zero bound cannot hold a ranking")
        });
        assert_eq!(error, ExplainError::BudgetExhausted { limit: expected });
    }
}

#[test]
fn a_relational_ranking_measures_binding_membership_without_claiming_a_finding() {
    let fixture = Fixture::with_source(RELATIONAL_FIXTURE);
    let ranking = rank(
        &fixture,
        FORBID_READS_RELATIONAL,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default(),
    );
    assert_eq!(ranking.analysis_type(), PolicyAnalysisType::Assertion);
    assert_eq!(
        ranking.conjuncts()[0],
        "binding:read/scope",
        "a relational ladder is scoped by the first binding's source query: {ranking:#?}"
    );
    assert!(!ranking.entries().is_empty(), "{ranking:#?}");
    for entry in ranking.entries() {
        if entry.unsatisfied_conjuncts() == 0 {
            assert_eq!(
                entry.outcome(),
                ExplanationOutcome::Unknown,
                "row-binding membership is not a finding: {entry:#?}"
            );
            assert_eq!(
                entry.reasons(),
                [PolicyIncompleteReason::CapabilityIncomplete]
            );
            assert!(entry.actual().contains("join"), "{entry:#?}");
        }
    }
}

#[test]
fn a_relational_ranking_reports_an_unreplayed_row_expansion_as_unknown() {
    let fixture = Fixture::with_source(MEMBER_FIXTURE);
    let ranking = rank(
        &fixture,
        TWO_BINDING_RELATIONAL,
        &NearMissCandidates::PolicySeedSearch,
        &ExplanationLimits::default(),
    );
    assert!(
        ranking
            .conjuncts()
            .iter()
            .any(|label| label == "binding:receiver"),
        "each further row binding is one membership conjunct: {ranking:#?}"
    );
    for entry in ranking.entries() {
        if entry.failing_conjunct() == Some("binding:receiver") {
            assert_eq!(entry.outcome(), ExplanationOutcome::Unknown);
            assert_eq!(
                entry.reasons(),
                [PolicyIncompleteReason::CapabilityIncomplete]
            );
            assert!(entry.actual().contains("not replayed"), "{entry:#?}");
        }
    }
}
