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
use brokk_bifrost::{IAnalyzer, Language, TypescriptAnalyzer};

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

fn typescript(source: &str) -> (crate::common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("widget.ts", source)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
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
