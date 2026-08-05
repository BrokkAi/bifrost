//! End-to-end coverage for the RQLP `assertion` analysis kind (issue #1473).
//!
//! The invariant under test is role fidelity: a policy names a captured
//! identifier token and states what the parser must say that token *is*. The
//! join between the subject capture and the occurrence rows is `ast_id`
//! equality and nothing else, so a fixture that moves a token to a different
//! syntactic position changes the verdict without changing any spelling.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use serde_json::Value;

use brokk_bifrost::analyzer::structural::CodeQueryExecutionLimits;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyAnalysisType, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFindingEvidence, PolicyIncompleteReason,
    PolicyLocationRelationship, PolicyRegistry, PolicyRegistryLimits, PolicyRun,
    PolicyRunCompletion, PolicySourceIdentity, TaintCatalogRegistry, format_rqlp_source,
};
use brokk_bifrost::{IAnalyzer, Language, TypescriptAnalyzer};

/// `render` is declared once and never read: the only `render` identifier is a
/// declaration name.
const CORRECT_SOURCE: &str = "export function render(): number {\n  return 1;\n}\n";

/// The seeded role-fidelity bug: a second `render` identifier exists that is a
/// plain value read, not the declaration name.
const BUGGY_SOURCE: &str =
    "export function render(): number {\n  return 1;\n}\n\nexport const alias = render;\n";

/// Every `render` token must be a declaration name, so a value read of the same
/// spelling is a violation carrying the offending occurrence.
const FORBID_READS: &str = r#"(policy
  :id "test.assertion.forbid-reads"
  :name "Render is never read"
  :message "render must only be declared, never read"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (identifier :text/regex "^render$" :capture "target"))
    :asserts [
      (assert :id no-reads :at "target" :role value_reference :expect none)
    ]))"#;

/// The mirror image: every `render` token must carry exactly one declaration
/// name occurrence, so a read violates by *absence*.
const REQUIRE_DECLARATION: &str = r#"(policy
  :id "test.assertion.require-declaration"
  :name "Render is always a declaration"
  :message "render must be a declaration name"
  :severity error
  :analysis (analysis
    :type assertion
    :subject (rql (identifier :text/regex "^render$" :capture "target"))
    :asserts [
      (assert :id declared :at "target" :role declaration_name :expect declaration
              :cardinality (exactly 1))
    ]))"#;

fn registry_with_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:assertion"),
            source.as_bytes(),
        )
        .expect("valid assertion policy");
    registry
}

fn evaluate(source: &str, analyzer: &dyn IAnalyzer, budget: &mut PolicyBudget) -> PolicyRun {
    let registry = registry_with_policy(source);
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
        .expect("assertion evaluation")
}

fn typescript(source: &str) -> (crate::common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("widget.ts", source)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn a_forbidden_occurrence_produces_one_multi_location_finding() {
    let (_project, analyzer) = typescript(BUGGY_SOURCE);
    let run = evaluate(FORBID_READS, &analyzer, &mut PolicyBudget::default());

    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(
        run.findings().len(),
        1,
        "only the read position violates; findings: {:?}",
        run.findings()
    );
    let finding = &run.findings()[0];
    assert_eq!(finding.primary().path(), "widget.ts");

    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.asserted_role(), "value_reference");
    assert_eq!(evidence.expected_class(), "none");
    assert_eq!(evidence.expectation(), "(exactly 0)");
    assert_eq!(evidence.assert_kind(), "occurrence");
    assert_eq!(evidence.actual_count(), 1);
    assert_eq!(evidence.anchor().assert_id(), "no-reads");
    assert!(
        !evidence.anchor().subject_ast_id().is_empty(),
        "the anchor is keyed on the subject node's AST id"
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
    assert!(
        relationships.contains(&PolicyLocationRelationship::ActualOccurrence),
        "a forbidden-occurrence violation lists the offending row: {relationships:?}"
    );
    assert!(!finding.related_truncated());
}

#[test]
fn an_absent_required_occurrence_points_at_the_subject_node() {
    let (_project, analyzer) = typescript(BUGGY_SOURCE);
    let run = evaluate(REQUIRE_DECLARATION, &analyzer, &mut PolicyBudget::default());

    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.actual_count(), 0);
    assert_eq!(evidence.expectation(), "(exactly 1)");

    let relationships = finding
        .related()
        .iter()
        .map(|related| related.relationship())
        .collect::<Vec<_>>();
    assert!(
        relationships.contains(&PolicyLocationRelationship::ExpectedOccurrence),
        "an absence violation names where the occurrence was expected: {relationships:?}"
    );
}

#[test]
fn the_corrected_fixture_is_clean_under_both_assertions() {
    let (_project, analyzer) = typescript(CORRECT_SOURCE);
    for source in [FORBID_READS, REQUIRE_DECLARATION] {
        let run = evaluate(source, &analyzer, &mut PolicyBudget::default());
        assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
        assert!(
            run.findings().is_empty(),
            "corrected fixture must be clean: {:?}",
            run.findings()
        );
    }
}

/// An adapter that declares the asserted role unsupported must make the run
/// unreliable. A forbid over rows the analyzer never classified is not a pass.
#[test]
fn an_unsupported_role_language_is_inconclusive_rather_than_clean() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "widget.go",
            "package main\n\nfunc render() int { return 1 }\n",
        )
        .build();
    let analyzer = brokk_bifrost::GoAnalyzer::from_project(project.project().clone());
    let run = evaluate(FORBID_READS, &analyzer, &mut PolicyBudget::default());

    let PolicyRunCompletion::Inconclusive { reasons } = run.completion() else {
        panic!(
            "an unsupported occurrence role must be inconclusive, got {:?}",
            run.completion()
        );
    };
    assert!(
        reasons.contains(&PolicyIncompleteReason::CapabilityIncomplete),
        "{reasons:?}"
    );
    assert!(
        run.findings().is_empty(),
        "an incomplete row set never yields a verdict"
    );
}

/// A truncated occurrence scan is the same class of unsoundness as an
/// unsupported role: the row set is not the whole row set.
#[test]
fn a_truncated_occurrence_scan_is_inconclusive() {
    let (_project, analyzer) = typescript(BUGGY_SOURCE);
    let mut budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .expect("query limits")
        .build()
        .expect("budget");
    let run = evaluate(FORBID_READS, &analyzer, &mut budget);
    assert!(
        matches!(run.completion(), PolicyRunCompletion::Inconclusive { .. }),
        "{:?}",
        run.completion()
    );
    assert!(run.findings().is_empty());
}

fn decode_error(source: &str) -> String {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let error = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:assertion"),
            source.as_bytes(),
        )
        .expect_err("the policy must be rejected");
    format!("{error}")
}

fn assertion_policy_with(assert_record: &str) -> String {
    format!(
        r#"(policy
  :id "test.assertion.authoring"
  :name "Authoring"
  :message "message"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (identifier :text/regex "^render$" :capture "target"))
    :asserts [{assert_record}]))"#
    )
}

#[test]
fn authoring_errors_are_rejected_at_decode_time() {
    let missing_capture_name =
        assertion_policy_with("(assert :id a :at \"\" :role value_reference :expect reference)");
    assert!(
        decode_error(&missing_capture_name).contains("capture name"),
        "{}",
        decode_error(&missing_capture_name)
    );

    let unknown_role =
        assertion_policy_with("(assert :id a :at \"target\" :role not_a_role :expect reference)");
    assert!(
        decode_error(&unknown_role).contains("occurrence role"),
        "{}",
        decode_error(&unknown_role)
    );

    let zero_without_none = assertion_policy_with(
        "(assert :id a :at \"target\" :role value_reference :expect reference :cardinality (exactly 0))",
    );
    assert!(
        decode_error(&zero_without_none).contains("expect none"),
        "{}",
        decode_error(&zero_without_none)
    );

    let none_with_positive_cardinality = assertion_policy_with(
        "(assert :id a :at \"target\" :role value_reference :expect none :cardinality (at-least 1))",
    );
    assert!(
        decode_error(&none_with_positive_cardinality).contains("exactly 0"),
        "{}",
        decode_error(&none_with_positive_cardinality)
    );

    // A role belongs to exactly one class, so an expectation the role can never
    // satisfy is an authoring error rather than a silently unsatisfiable rule.
    let class_mismatch =
        assertion_policy_with("(assert :id a :at \"target\" :role binder :expect declaration)");
    assert!(
        decode_error(&class_mismatch).contains("can never hold"),
        "{}",
        decode_error(&class_mismatch)
    );
}

#[test]
fn the_formatter_round_trips_assertion_records() {
    let formatted = format_rqlp_source(FORBID_READS).expect("formattable");
    assert!(formatted.contains("(assert"), "{formatted}");
    assert!(formatted.contains(":asserts ["), "{formatted}");
    assert_eq!(
        format_rqlp_source(&formatted).expect("formattable"),
        formatted,
        "the formatter must be idempotent over assertion records"
    );
    registry_with_policy(&formatted);
}

fn bifrost_policy_run(root: &Path, policy_path: &str, format: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    command.arg("--root").arg(root).args([
        "--policy-file",
        policy_path,
        "--evaluation-date",
        "2026-08-04",
        "--format",
        format,
    ]);
    if format == "human" {
        // Related locations and typed evidence are verbose-only detail; the
        // renderer parity claim is about that detail, not about the summary.
        command.arg("--verbose");
    }
    command
        .env("BIFROST_PARALLELISM", "1")
        .output()
        .expect("run bifrost policy")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_policy_cli_reports_finding_clean_and_renders_the_same_locations_everywhere() {
    let buggy = InlineTestProject::with_language(Language::TypeScript)
        .file("src/widget.ts", BUGGY_SOURCE)
        .file("policies/forbid-reads.rqlp", FORBID_READS)
        .build();

    let human = bifrost_policy_run(buggy.root(), "policies/forbid-reads.rqlp", "human");
    assert_eq!(
        human.status.code(),
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        stdout_of(&human),
        String::from_utf8_lossy(&human.stderr)
    );
    let human_text = stdout_of(&human);
    assert!(human_text.contains("subject"), "{human_text}");
    assert!(human_text.contains("actual_occurrence"), "{human_text}");
    assert!(human_text.contains("value_reference"), "{human_text}");

    let json = bifrost_policy_run(buggy.root(), "policies/forbid-reads.rqlp", "json");
    assert_eq!(json.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&json.stdout).expect("JSON report");
    let finding = &report["runs"][0]["findings"][0];
    assert_eq!(finding["evidence"]["type"], "assertion");
    assert_eq!(
        finding["evidence"]["evidence"]["asserted_role"],
        "value_reference"
    );
    assert_eq!(finding["evidence"]["evidence"]["actual_count"], 1);
    let json_relationships = finding["related"]
        .as_array()
        .expect("related locations")
        .iter()
        .map(|related| related["relationship"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(
        json_relationships.contains(&"subject")
            && json_relationships.contains(&"actual_occurrence"),
        "{json_relationships:?}"
    );

    let sarif = bifrost_policy_run(buggy.root(), "policies/forbid-reads.rqlp", "sarif");
    assert_eq!(sarif.status.code(), Some(1));
    let sarif_report: Value = serde_json::from_slice(&sarif.stdout).expect("SARIF report");
    let result = &sarif_report["runs"][0]["results"][0];
    let sarif_relationships = result["relatedLocations"]
        .as_array()
        .expect("SARIF related locations")
        .iter()
        .map(|related| {
            related["message"]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        sarif_relationships
            .iter()
            .any(|text| text.contains("subject"))
            && sarif_relationships
                .iter()
                .any(|text| text.contains("actual occurrence")),
        "{sarif_relationships:?}"
    );
    assert_eq!(
        json_relationships.len(),
        sarif_relationships.len(),
        "human, JSON and SARIF must publish the same related locations"
    );

    let corrected = InlineTestProject::with_language(Language::TypeScript)
        .file("src/widget.ts", CORRECT_SOURCE)
        .file("policies/forbid-reads.rqlp", FORBID_READS)
        .build();
    let clean = bifrost_policy_run(corrected.root(), "policies/forbid-reads.rqlp", "json");
    assert_eq!(
        clean.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        stdout_of(&clean),
        String::from_utf8_lossy(&clean.stderr)
    );
}
