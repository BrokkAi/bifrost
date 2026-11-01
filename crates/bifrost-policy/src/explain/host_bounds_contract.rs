use std::mem::size_of;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::{Language, TestProject};
use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;

use crate::budget::PolicyBudget;
use crate::coordinator::PolicyEvaluationInput;
use crate::definition::PolicyAnalysisType;
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::retained::RetainedSize;

use super::host::{
    ExplanationTarget, explain_loaded_policy, explain_policy_inputs, rank_policy_near_misses,
};
use super::model::{
    ExplainError, ExplanationGeneration, ExplanationLimits, ExplanationNode, ExplanationNodeKind,
    ExplanationOutcome, ExplanationPosition, ExplanationQuestion, ExplanationSubject, RawNode,
    WHY_NOT_ADAPTER_ANALYSIS_TYPES, build_explanation,
};
use super::near_miss::{NearMissCandidates, NearMissEnumeration};
use super::why_not::ExplanationCandidate;

const SOURCE: &str = "export class Widget { render() {} }\nexport class Gadget { render() {} }\n";
const POLICY: &str = r#"(policy
  :id "test.explain.widget"
  :name "Widget render"
  :message "Widget render is reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (inside-decl (class :name "Widget") (method :name "render")))))"#;
const SECOND_POLICY: &str = r#"(policy
  :id "test.explain.gadget"
  :name "Gadget render"
  :message "Gadget render is reported"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (inside-decl (class :name "Gadget") (method :name "render")))))"#;

fn disk_workspace() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("canonical root");
    std::fs::write(root.join("app.ts"), SOURCE).expect("source");
    std::fs::create_dir(root.join("policies")).expect("policy directory");
    std::fs::write(root.join("policies/first.rqlp"), POLICY).expect("first policy");
    std::fs::write(root.join("policies/second.rqlp"), SECOND_POLICY).expect("second policy");
    temp
}

fn input(path: &str) -> PolicyEvaluationInput {
    PolicyEvaluationInput::workspace_file(path)
}

#[test]
fn explanation_selection_registers_every_input_and_refuses_ambiguity() {
    let temp = disk_workspace();
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");
    let result = explain_policy_inputs(
        temp.path(),
        &[input("policies/first.rqlp"), input("policies/second.rqlp")],
        &ExplanationTarget::Candidate(candidate.clone()),
        None,
        None,
        None,
        None,
        &ExplanationLimits::default(),
    );
    assert_eq!(
        result.unwrap_err(),
        ExplainError::AmbiguousPolicySelection { selected: 2 }
    );

    // The second input must be registered even when it fails to load.
    let error = explain_policy_inputs(
        temp.path(),
        &[input("policies/first.rqlp"), input("policies/absent.rqlp")],
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ExplainError::PolicyUnavailable { .. }),
        "{error:?}"
    );
}

#[test]
fn loaded_finding_obeys_generation_and_caller_bounds() {
    let temp = disk_workspace();
    let root = temp.path().canonicalize().expect("canonical root");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: &analyzer,
        workspace: None,
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
    };
    let registry = crate::test_support::registry_with_policy("test:host-bounds", POLICY, "policy");
    let policy = registry.policies().next().expect("loaded policy");
    let run = DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut PolicyBudget::default())
        .expect("run");
    let finding = run.findings().first().expect("finding").id();
    let target = ExplanationTarget::Finding(finding);
    let stale = "0"
        .repeat(64)
        .parse::<ExplanationGeneration>()
        .expect("generation");
    let error = explain_loaded_policy(
        policy,
        &context,
        &target,
        Some(stale),
        &mut PolicyBudget::default(),
        &ExplanationLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ExplainError::StaleWorkspaceGeneration { .. }),
        "{error:?}"
    );

    let full = explain_loaded_policy(
        policy,
        &context,
        &target,
        None,
        &mut PolicyBudget::default(),
        &ExplanationLimits::default(),
    )
    .expect("full");
    assert!(full.node_count() > 1, "fixture must have a child");
    let bounded = explain_loaded_policy(
        policy,
        &context,
        &target,
        None,
        &mut PolicyBudget::default(),
        &ExplanationLimits::default().with_max_nodes(1),
    )
    .expect("bounded");
    assert_eq!(bounded.node_count(), 1);
    assert!(bounded.truncation().nodes_truncated());

    let depth = explain_loaded_policy(
        policy,
        &context,
        &target,
        None,
        &mut PolicyBudget::default(),
        &ExplanationLimits::default().with_max_depth(2),
    )
    .expect("depth bound");
    assert!(
        !depth.root().children().is_empty(),
        "depth 2 includes direct children"
    );
    assert!(
        depth
            .root()
            .children()
            .iter()
            .all(|child| child.children().is_empty())
    );
}

#[test]
fn why_not_error_advertises_only_why_not_families() {
    let temp = disk_workspace();
    let typestate = r#"(policy
      :id "test.explain.typestate"
      :name "Typestate"
      :message "resource state"
      :severity error
      :analysis (analysis
        :type typestate
        :mode may
        :subjects (subject-set :entries [
          (subject :id resource :selector (rql (name "alpha"))
            :subject return-value)])
        :uncertainty (uncertainty :escape inconclusive)
        :automaton (automaton
          :states [open closed violated]
          :initial open
          :accepting-states [closed]
          :error-states [violated]
          :events [
            (event :id finish :on (normal-procedure-exit :scope analysis-root))
            (event :id fail :on (exceptional-procedure-exit :scope analysis-root))]
          :transitions [
            (transition :from open :on finish :to closed)
            (transition :from open :on fail :to violated)]
          :terminal-expectations [
            (terminal-expectation :id normal-exit
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed])])))"#;
    std::fs::write(temp.path().join("policies/typestate.rqlp"), typestate).expect("policy");
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");
    let error = explain_policy_inputs(
        temp.path(),
        &[input("policies/typestate.rqlp")],
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        ExplainError::ExplanationAdapterUnavailable {
            analysis_type: PolicyAnalysisType::Typestate,
            question: ExplanationQuestion::WhyNot,
            supported: WHY_NOT_ADAPTER_ANALYSIS_TYPES.to_vec(),
        }
    );
}

#[test]
fn retained_subject_size_counts_both_allocations() {
    let mut candidate_path = String::with_capacity(96);
    candidate_path.push_str("app.ts");
    let candidate = ExplanationSubject::Candidate {
        path: candidate_path,
        byte_start: 0,
        byte_end: 0,
    };
    assert_eq!(
        candidate.retained_size(),
        size_of::<ExplanationSubject>() + 96
    );

    let flow = ExplanationSubject::FlowCandidate {
        source: ExplanationPosition {
            path: String::from("a.ts"),
            byte_start: 0,
            byte_end: 0,
        },
        observation: ExplanationPosition {
            path: "long-observation.ts".to_string(),
            byte_start: 0,
            byte_end: 0,
        },
    };
    assert_eq!(
        flow.retained_size(),
        size_of::<ExplanationSubject>() + 4 + "long-observation.ts".len()
    );
}

#[test]
fn timed_out_host_request_reaches_bounded_explanation() {
    let temp = disk_workspace();
    let candidate = ExplanationCandidate::at_offset("app.ts", 0).expect("candidate");
    let timeout = CancellationToken::timeout_after_checks_for_test(1);
    let result = explain_policy_inputs(
        temp.path(),
        &[input("policies/first.rqlp")],
        &ExplanationTarget::Candidate(candidate),
        None,
        None,
        None,
        Some(&timeout),
        &ExplanationLimits::default(),
    );
    let explanation = result.expect("timeout must remain a structured incomplete result");
    assert_eq!(
        explanation.outcome(),
        super::model::ExplanationOutcome::Unknown
    );
}

#[test]
fn timed_out_ranking_reports_incomplete_work() {
    let temp = disk_workspace();
    let timeout = CancellationToken::timeout_after_checks_for_test(6);
    let result = rank_policy_near_misses(
        temp.path(),
        &[input("policies/first.rqlp")],
        &NearMissCandidates::PolicySeedSearch,
        None,
        None,
        None,
        Some(&timeout),
        &ExplanationLimits::default(),
    );
    let ranking = result.expect("timeout must remain a structured incomplete result");
    assert!(
        matches!(
            ranking.enumeration(),
            NearMissEnumeration::PolicySeed {
                exhaustive: false,
                ..
            }
        ),
        "ranking must disclose incomplete enumeration: {ranking:?}"
    );
}

fn raw_document(
    root: RawNode,
    limits: &ExplanationLimits,
) -> Result<super::model::PolicyExplanation, ExplainError> {
    let registry = crate::test_support::registry_with_policy("test:tree-limits", POLICY, "policy");
    let policy = registry.policies().next().expect("loaded policy");
    build_explanation(
        ExplanationQuestion::WhyNot,
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        PolicyAnalysisType::Match,
        ExplanationSubject::Candidate {
            path: "app.ts".to_owned(),
            byte_start: 0,
            byte_end: 0,
        },
        root,
        limits,
    )
}

fn node(label: &str) -> RawNode {
    RawNode::new(
        ExplanationNodeKind::SelectorStage,
        ExplanationOutcome::Unknown,
        label,
    )
}

#[test]
fn explanation_depth_one_admits_root_and_depth_two_admits_children() {
    let mut root = node("root");
    root.push_child(node("child"));
    let one = raw_document(
        root.clone(),
        &ExplanationLimits::default().with_max_depth(1),
    )
    .expect("root fits depth one");
    assert_eq!(one.node_count(), 1);
    assert!(one.truncation().depth_truncated());
    let two = raw_document(root, &ExplanationLimits::default().with_max_depth(2))
        .expect("child fits depth two");
    assert_eq!(two.node_count(), 2);
    assert!(!two.truncation().depth_truncated());
}

#[test]
fn omitted_depth_reports_deepest_cut_even_after_a_shallower_cut() {
    let mut deep = node("deep");
    let mut fork = node("fork");
    let mut descendant = node("descendant");
    descendant.push_child(node("deepest"));
    fork.push_child(node("shallow descendant"));
    fork.push_child(descendant);
    deep.push_child(fork);
    let mut root = node("root");
    root.push_child(deep);
    let mut later = node("later");
    later.push_child(node("one level past"));
    root.push_child(later);
    let explanation =
        raw_document(root, &ExplanationLimits::default().with_max_depth(2)).expect("bounded tree");
    assert!(explanation.truncation().depth_truncated());
    assert_eq!(
        explanation.truncation().omitted_depth_levels_lower_bound(),
        3
    );
}

#[test]
fn retained_bytes_count_actual_text_and_all_omitted_descendants() {
    let root = node("r")
        .with_expected("x")
        .with_actual("a much longer actual value");
    let root_bytes = size_of::<ExplanationNode>() + 1 + 1 + "a much longer actual value".len();
    let exact = raw_document(
        root.clone(),
        &ExplanationLimits::default().with_max_retained_bytes(root_bytes),
    )
    .expect("exact root allocation fits");
    assert!(!exact.truncation().bytes_truncated());
    let short = raw_document(
        root,
        &ExplanationLimits::default().with_max_retained_bytes(root_bytes - 1),
    );
    assert!(matches!(
        short,
        Err(ExplainError::BudgetExhausted {
            limit: super::model::ExplanationBudgetLimit::RetainedBytes
        })
    ));

    let mut grandchild = node("grandchild");
    grandchild.push_child(node("deepest"));
    let mut child = node("c");
    child.push_child(grandchild);
    let mut root = node("r");
    root.push_child(child);
    let one_node_bytes = size_of::<ExplanationNode>() + 1;
    let cut = raw_document(
        root,
        &ExplanationLimits::default().with_max_retained_bytes(one_node_bytes),
    )
    .expect("root retained");
    assert_eq!(cut.node_count(), 1);
    assert!(cut.truncation().bytes_truncated());
    assert_eq!(
        cut.truncation().omitted_bytes_lower_bound(),
        (size_of::<ExplanationNode>() * 3 + 1 + "grandchild".len() + "deepest".len()) as u64
    );
}

#[test]
fn text_byte_bound_keeps_the_whole_prefix_and_reports_only_removed_bytes() {
    let exact = raw_document(
        node("abcd"),
        &ExplanationLimits::default().with_max_text_bytes(4),
    )
    .expect("exact bound");
    assert_eq!(exact.root().label(), "abcd");
    assert!(!exact.truncation().text_truncated());

    let cut = raw_document(
        node("abcdef"),
        &ExplanationLimits::default().with_max_text_bytes(4),
    )
    .expect("cut");
    assert_eq!(cut.root().label(), "abcd");
    assert_eq!(cut.truncation().omitted_text_bytes_lower_bound(), 2);
    let utf8 = raw_document(
        node("aébc"),
        &ExplanationLimits::default().with_max_text_bytes(3),
    )
    .expect("character boundary");
    assert_eq!(utf8.root().label(), "aé");
    assert_eq!(utf8.truncation().omitted_text_bytes_lower_bound(), 2);
}

#[test]
fn source_cut_remains_visible_after_an_uncut_source_update() {
    let root = node("root")
        .with_source_truncation(true, 2)
        .with_source_truncation(false, 0);
    let explanation = raw_document(root, &ExplanationLimits::default()).expect("explanation");
    assert!(explanation.root().children_truncated());
    assert_eq!(explanation.root().omitted_children_lower_bound(), 2);
}

fn rank_authored(
    source: &str,
    policy: &str,
    candidates: NearMissCandidates,
) -> super::near_miss::PolicyNearMissRanking {
    let temp = tempfile::tempdir().expect("workspace");
    std::fs::write(temp.path().join("app.ts"), source).expect("source");
    std::fs::write(temp.path().join("rule.rqlp"), policy).expect("policy");
    rank_policy_near_misses(
        temp.path(),
        &[input("rule.rqlp")],
        &candidates,
        None,
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect("ranking")
}

#[test]
fn negative_descendant_predicate_is_a_declared_relaxation() {
    let policy = r#"(policy :id "test.negative" :name "No bad descendant" :message "m" :severity warning
      :analysis (analysis :type match :selector
        (rql (function :name "allowed" :not-has (identifier :name "bad")))))"#;
    let source = "export function allowed() { const bad = 1; }\n";
    let candidate = ExplanationCandidate::at_offset("app.ts", 16).expect("candidate");
    let ranking = rank_authored(
        source,
        policy,
        NearMissCandidates::Supplied(vec![candidate]),
    );
    assert_eq!(ranking.conjuncts(), ["scope", "root.name", "root.not_has"]);
    assert_eq!(ranking.entries().len(), 1);
    assert_eq!(
        ranking.entries()[0].failing_conjunct(),
        Some("root.not_has")
    );
}

#[test]
fn restoring_negative_predicate_keeps_its_authored_pattern() {
    let policy = r#"(policy :id "test.positive-negative" :name "Has good without bad" :message "m" :severity warning
      :analysis (analysis :type match :selector
        (rql (function :name "allowed" :has (identifier :name "good") :not-has (identifier :name "bad")))))"#;
    let source = "export function allowed() { const good = 1; }\n";
    let candidate = ExplanationCandidate::at_offset("app.ts", 16).expect("candidate");
    let ranking = rank_authored(
        source,
        policy,
        NearMissCandidates::Supplied(vec![candidate]),
    );
    assert_eq!(
        ranking.conjuncts(),
        ["scope", "root.name", "root.has", "root.not_has"]
    );
    assert_eq!(ranking.entries().len(), 1);
    assert_eq!(
        ranking.entries()[0].outcome(),
        ExplanationOutcome::Satisfied
    );
}

#[test]
fn ranked_seed_search_stays_within_authored_file_scope() {
    let temp = tempfile::tempdir().expect("workspace");
    std::fs::create_dir(temp.path().join("src")).expect("src");
    std::fs::create_dir(temp.path().join("tests")).expect("tests");
    std::fs::write(
        temp.path().join("src/allowed.ts"),
        "export function target() {}\n",
    )
    .expect("allowed");
    std::fs::write(
        temp.path().join("tests/outside.ts"),
        "export function target() {}\n",
    )
    .expect("outside");
    let policy = r#"(policy :id "test.scoped" :name "Scoped" :message "m" :severity warning
      :analysis (analysis :type match :where ["src/**"] :selector (rql (function :name "target"))))"#;
    std::fs::write(temp.path().join("rule.rqlp"), policy).expect("policy");
    let ranking = rank_policy_near_misses(
        temp.path(),
        &[input("rule.rqlp")],
        &NearMissCandidates::PolicySeedSearch,
        None,
        None,
        None,
        None,
        &ExplanationLimits::default(),
    )
    .expect("ranking");
    let NearMissEnumeration::PolicySeed { scope, .. } = ranking.enumeration() else {
        panic!("policy seed search")
    };
    assert!(scope.contains("src/**"), "authored path scope: {scope}");
    assert_eq!(
        ranking.entries().len(),
        1,
        "only src/allowed.ts can be ranked: {ranking:?}"
    );
    assert!(
        matches!(ranking.entries()[0].subject(), ExplanationSubject::Candidate { path, .. } if path == "src/allowed.ts")
    );
}

#[test]
fn relational_ranking_reports_each_binding_relaxation() {
    let policy = r#"(policy
      :id "test.relational.bindings"
      :name "Member sites have receiver outcomes"
      :message "m"
      :severity error
      :analysis (analysis
        :type assertion
        (bind :name site :query (rql (occurrences :role [member_position])))
        (bind :name receiver :query
          (rql (receiver-outcome (occurrences :role [member_position]))))
        (join :left site :right receiver :kind anti :on ((ast_id site_ast_id)))
        (group :name orphaned :by (site.ast_id)
          (aggregate :name sites :op count))
        (assert :group orphaned :value sites :cardinality (exactly 0))))"#;
    let source = "class Service { run() {} }\nexport function caller(s: Service) { s.run(); }\n";
    let candidate = ExplanationCandidate::at_offset(
        "app.ts",
        source.find("run();").expect("member call") as u64,
    )
    .expect("candidate");
    let ranking = rank_authored(
        source,
        policy,
        NearMissCandidates::Supplied(vec![candidate]),
    );
    assert_eq!(
        ranking.conjuncts(),
        ["binding:site/scope", "binding:receiver"]
    );
}
