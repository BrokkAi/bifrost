//! End-to-end coverage for RQLP relational assertion plans (issue #1477).
//!
//! These tests execute named `bind` queries and typed row expansions through
//! the production `run_policy` evaluation path: every binding is a real
//! CodeQuery against a real analyzer snapshot, joins are typed row-field
//! equality, and each violated group becomes one finding anchored at the exact
//! source range of its contributing rows.

use std::sync::Arc;

use brokk_bifrost::analyzer::structural::CodeQueryExecutionLimits;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyAnalysisType, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFindingEvidence, PolicyLocationRelationship,
    PolicyRegistry, PolicyRegistryLimits, PolicyRun, PolicyRunCompletion, PolicySourceIdentity,
    TaintCatalogRegistry,
};
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language, TypescriptAnalyzer};

/// `render` is declared once and never read.
const CORRECT_SOURCE: &str = "export function render(): number {\n  return 1;\n}\n";

/// A second `render` identifier exists that is a plain value read.
const BUGGY_SOURCE: &str =
    "export function render(): number {\n  return 1;\n}\n\nexport const alias = render;\n";

/// Forbid value reads through the relational plan: bind every value-reference
/// occurrence, group by its AST identity, and require an exact zero count. A
/// group only exists where a read exists, so each read violates on its own
/// exact source range.
const FORBID_READS_RELATIONAL: &str = r#"(policy
  :id "test.relational.forbid-reads"
  :name "No value reads"
  :message "value reads are forbidden in this fixture"
  :severity warning
  :analysis (analysis
    :type assertion
    (bind :name read :query (rql (occurrences :role [value_reference])))
    (group :name by-read :by (read.ast_id)
      (aggregate :name reads :op count))
    (assert :group by-read :value reads :cardinality (exactly 0))))"#;

/// Every member-position occurrence must join to at least one mandatory
/// receiver outcome row. The anti-join keeps exactly the sites that have no
/// outcome row, and any surviving group is a violation.
const REQUIRE_RECEIVER_OUTCOME: &str = r#"(policy
  :id "test.relational.receiver-outcome"
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

fn evaluate(source: &str, analyzer: &dyn IAnalyzer, budget: &mut PolicyBudget) -> PolicyRun {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:relational"),
            source.as_bytes(),
        )
        .expect("valid relational assertion policy");
    let policy = registry.policies().next().expect("one policy");
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer,
                workspace: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            budget,
        )
        .expect("relational assertion evaluation")
}

/// Evaluate against a full workspace snapshot, which the semantic row
/// families (the #1477 M4 dispatch expansions) require.
fn evaluate_with_workspace(
    source: &str,
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
    budget: &mut PolicyBudget,
) -> PolicyRun {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:relational"),
            source.as_bytes(),
        )
        .expect("valid relational assertion policy");
    let policy = registry.policies().next().expect("one policy");
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: workspace.analyzer(),
                workspace: Some(workspace),
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            budget,
        )
        .expect("relational assertion evaluation")
}

/// A Java workspace snapshot for the semantic row families.
fn java_workspace(
    source: &str,
) -> (
    crate::common::BuiltInlineTestProject,
    brokk_bifrost::analyzer::WorkspaceAnalyzer,
) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("App.java", source)
        .build();
    let workspace = brokk_bifrost::analyzer::WorkspaceAnalyzer::build(
        project.project_dyn(),
        brokk_bifrost::AnalyzerConfig::default(),
    );
    (project, workspace)
}

fn typescript(source: &str) -> (crate::common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("widget.ts", source)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn java(source: &str) -> (crate::common::BuiltInlineTestProject, JavaAnalyzer) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("App.java", source)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn a_violated_relational_group_is_one_finding_with_exact_source_ranges() {
    let (_project, analyzer) = typescript(BUGGY_SOURCE);
    let run = evaluate(
        FORBID_READS_RELATIONAL,
        &analyzer,
        &mut PolicyBudget::default(),
    );

    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(
        run.findings().len(),
        1,
        "only the single read violates; findings: {:?}",
        run.findings()
    );
    let finding = &run.findings()[0];
    assert_eq!(finding.primary().path(), "widget.ts");
    let region = finding
        .primary()
        .region()
        .expect("a relational violation anchors at the row's exact display range");
    assert_eq!(
        region.start_line(),
        5,
        "the finding points at the read of `render`, not its declaration"
    );
    assert!(
        finding.primary().byte_span().is_some(),
        "the violation retains the exact byte span of the offending row"
    );

    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("relational assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.assert_kind(), "relational");
    assert_eq!(evidence.expectation(), "(exactly 0)");
    assert_eq!(evidence.actual_count(), 1);
    assert_eq!(evidence.anchor().assert_id(), "by-read-reads");
    assert!(
        !evidence.anchor().subject_ast_id().is_empty(),
        "the anchor is keyed on the violated group key"
    );

    let relationships = finding
        .related()
        .iter()
        .map(|related| related.relationship())
        .collect::<Vec<_>>();
    assert!(
        relationships.contains(&PolicyLocationRelationship::Subject),
        "{relationships:?}"
    );
    assert!(!finding.related_truncated());
}

#[test]
fn the_corrected_fixture_is_clean_under_the_relational_plan() {
    let (_project, analyzer) = typescript(CORRECT_SOURCE);
    let run = evaluate(
        FORBID_READS_RELATIONAL,
        &analyzer,
        &mut PolicyBudget::default(),
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(
        run.findings().is_empty(),
        "corrected fixture must be clean: {:?}",
        run.findings()
    );
}

#[test]
fn a_receiver_outcome_expansion_executes_and_covers_every_member_site() {
    let (_project, analyzer) = typescript(
        "class Widget {\n  render(): number {\n    return 1;\n  }\n}\n\nconst w = new Widget();\nexport const n = w.render();\n",
    );
    let run = evaluate(
        REQUIRE_RECEIVER_OUTCOME,
        &analyzer,
        &mut PolicyBudget::default(),
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(
        run.findings().is_empty(),
        "every member occurrence has one mandatory receiver outcome row: {:?}",
        run.findings()
    );
}

/// The #1477 member-selection invariant: every member occurrence selects
/// exactly one member. The plan binds sites, expands them into the mandatory
/// selection summary via the production resolver trace, and asserts on the
/// summary's selected cardinality.
const EXACTLY_ONE_SELECTED_MEMBER: &str = r#"(policy
  :id "test.relational.one-selected-member"
  :name "Every member access selects exactly one member"
  :message "a member access must resolve to exactly one selected member"
  :severity error
  :analysis (analysis
    :type assertion
    (bind :name site :query (rql (occurrences :role [member_position])))
    (bind :name selection :from site :step member-selection)
    (join :left site :right selection :on ((ast_id site_ast_id)))
    (group :name by-site :by (site.ast_id)
      (aggregate :name winners :op min :value selection.selected_count))
    (assert :group by-site :value winners :cardinality (exactly 1))))"#;

/// Clean: a typed receiver selects its owner's member and nothing else.
#[test]
fn member_selection_invariant_is_clean_on_the_resolving_fixture() {
    let (_project, analyzer) = typescript(
        "class Service {\n  run(): number {\n    return 1;\n  }\n}\n\nexport function caller(service: Service) {\n  return service.run();\n}\n",
    );
    let run = evaluate(
        EXACTLY_ONE_SELECTED_MEMBER,
        &analyzer,
        &mut PolicyBudget::default(),
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(run.findings().is_empty(), "{:?}", run.findings());
}

/// Finding: an unresolvable member access has a mandatory summary row with a
/// zero selected count, and the invariant reports it at the exact site.
#[test]
fn member_selection_invariant_reports_the_unresolved_site() {
    let (_project, analyzer) = typescript(
        "class Service {\n  run(): number {\n    return 1;\n  }\n}\n\nexport function caller(service) {\n  return service.run();\n}\n",
    );
    let run = evaluate(
        EXACTLY_ONE_SELECTED_MEMBER,
        &analyzer,
        &mut PolicyBudget::default(),
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
    let finding = &run.findings()[0];
    assert_eq!(finding.primary().path(), "widget.ts");
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("relational assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.expectation(), "(exactly 1)");
    assert_eq!(evidence.actual_count(), 0);
}

/// Unreliable: a truncated site binding makes the invariant inconclusive,
/// never clean.
#[test]
fn member_selection_invariant_is_unreliable_on_a_truncated_binding() {
    let (_project, analyzer) = typescript(
        "class Service {\n  run(): number {\n    return 1;\n  }\n  stop(): number {\n    return 2;\n  }\n}\n\nexport function caller(service: Service) {\n  return service.run() + service.stop();\n}\n",
    );
    let mut budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let run = evaluate(EXACTLY_ONE_SELECTED_MEMBER, &analyzer, &mut budget);
    assert!(
        matches!(run.completion(), PolicyRunCompletion::Inconclusive { .. }),
        "{:?}",
        run.completion()
    );
    assert!(run.findings().is_empty());
}

/// The #1477 hierarchy-route invariant: every traced member candidate's route
/// is exactly as long as the hierarchy distance the resolver walked. The plan
/// binds sites, expands them into hop rows through the production trace, and
/// asserts the per-candidate hop count. This is also the executable proof that
/// `candidate-hierarchy` is a usable relational expansion.
const TWO_HOP_ROUTE: &str = r#"(policy
  :id "test.relational.candidate-route-length"
  :name "The inherited member is reached in exactly two hops"
  :message "the resolver's hierarchy route must be exactly two hops long"
  :severity error
  :analysis (analysis
    :type assertion
    (bind :name site :query (rql (occurrences :role [member_position])))
    (bind :name hop :from site :step candidate-hierarchy)
    (join :left site :right hop :on ((ast_id ast_id)))
    (group :name by-candidate :by (hop.candidate_id)
      (aggregate :name hops :op count))
    (assert :group by-candidate :value hops :cardinality (exactly 2))))"#;

/// Clean: the candidate is found two supertypes up, so its route has exactly
/// two hop rows.
#[test]
fn candidate_hierarchy_expansion_is_clean_on_the_two_hop_route() {
    let (_project, analyzer) = java(
        "class Root { void run() {} }\nclass Base extends Root { }\nclass Service extends Base { }\nclass Caller {\n    void call(Service service) { service.run(); }\n}\n",
    );
    let run = evaluate(TWO_HOP_ROUTE, &analyzer, &mut PolicyBudget::default());
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(run.findings().is_empty(), "{:?}", run.findings());
}

/// Finding: a direct member is reached in zero hops, so the only group that
/// exists is the one-hop route of the *other* site, and the zero-hop candidate
/// contributes no group at all. A one-hop fixture therefore violates.
#[test]
fn candidate_hierarchy_expansion_reports_a_route_of_the_wrong_length() {
    let (_project, analyzer) = java(
        "class Root { void run() {} }\nclass Service extends Root { }\nclass Caller {\n    void call(Service service) { service.run(); }\n}\n",
    );
    let run = evaluate(TWO_HOP_ROUTE, &analyzer, &mut PolicyBudget::default());
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
    let PolicyFindingEvidence::Assertion { evidence } = run.findings()[0].evidence() else {
        panic!("relational assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.expectation(), "(exactly 2)");
    assert_eq!(evidence.actual_count(), 1);
}

/// A truncated binding row set is never a verdict: the relational plan reports
/// the run inconclusive instead of concluding over a proper subset.
#[test]
fn a_truncated_relational_binding_is_inconclusive() {
    // Two reads exist, so a one-row pipeline cap makes the binding a proper
    // subset of the true row set.
    let (_project, analyzer) = typescript(
        "export function render(): number {\n  return 1;\n}\n\nexport const alias = render;\nexport const alias2 = render;\n",
    );
    let mut budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let run = evaluate(FORBID_READS_RELATIONAL, &analyzer, &mut budget);
    assert!(
        matches!(run.completion(), PolicyRunCompletion::Inconclusive { .. }),
        "{:?}",
        run.completion()
    );
    assert!(
        run.findings().is_empty(),
        "an incomplete row set never yields a verdict"
    );
}

/// The #1477 M4 open-world honesty rule as an executable policy: every call
/// site must dispatch to exactly one proven target. A closed monomorphic call
/// satisfies it; an open interface receiver must not, because its arms stay
/// `may_dispatch` inside a non-exhaustive set. This is also the executable
/// proof that `dispatch-outcome` and `dispatch-targets` are usable relational
/// expansions.
const EXACTLY_ONE_PROVEN_DISPATCH: &str = r#"(policy
  :id "test.relational.proven-dispatch"
  :name "Every call has exactly one proven dispatch target"
  :message "a call site must dispatch to exactly one proven target"
  :severity error
  :analysis (analysis
    :type assertion
    (bind :name site :query (rql (occurrences :role [member_position])))
    (bind :name outcome :from site :step dispatch-outcome)
    (bind :name target :from site :step dispatch-targets)
    (join :left site :right outcome :on ((ast_id site_ast_id)))
    (join :left site :right target :on ((ast_id site_ast_id)))
    (group :name by-site :by (outcome.site_id)
      (aggregate :name proven :op count
                 :where ((target.dispatch eq proven_dispatch))))
    (assert :group by-site :value proven :cardinality (exactly 1))))"#;

/// Clean: a closed monomorphic call has one proven target in an exhaustive
/// set, so the exact-set assertion holds.
#[test]
fn dispatch_expansions_are_clean_on_a_closed_monomorphic_call() {
    let (_project, workspace) = java_workspace(
        "public class App {\n  static int helper() { return 1; }\n  static int caller() { return helper(); }\n}\n",
    );
    let run = evaluate_with_workspace(
        EXACTLY_ONE_PROVEN_DISPATCH,
        &workspace,
        &mut PolicyBudget::default(),
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(run.findings().is_empty(), "{:?}", run.findings());
}

/// Open-world dispatch never satisfies an exact-set assertion. The interface
/// receiver's arm stays `may_dispatch`, so the proven count is zero and the
/// site is reported instead of passing.
#[test]
fn open_world_dispatch_never_satisfies_the_exact_set_assertion() {
    let (_project, workspace) = java_workspace(
        "interface Shape { int area(); }\nclass Square implements Shape { public int area() { return 1; } }\nclass Circle implements Shape { public int area() { return 2; } }\npublic class App {\n  static int caller(Shape shape) { return shape.area(); }\n}\n",
    );
    let run = evaluate_with_workspace(
        EXACTLY_ONE_PROVEN_DISPATCH,
        &workspace,
        &mut PolicyBudget::default(),
    );
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
    let PolicyFindingEvidence::Assertion { evidence } = run.findings()[0].evidence() else {
        panic!("relational assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.expectation(), "(exactly 1)");
    assert_eq!(
        evidence.actual_count(),
        0,
        "an open arm must never be counted as a proven dispatch"
    );
}
