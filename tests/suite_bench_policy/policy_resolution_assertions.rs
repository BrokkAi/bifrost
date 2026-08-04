//! End-to-end coverage for the RQLP resolution asserts (issue #1474, M5).
//!
//! These three assert families state *why* a name means what it means, not
//! merely what the token is. The load-bearing test is
//! `the_loop_invariance_verdict_separates_the_two_fixture_halves`: the 284
//! false positives that motivated this slice reduce to one missing predicate --
//! is the value operated on inside this loop declared inside or outside the
//! loop body? -- and `assert-reaching` answers it as a policy, on both halves
//! of one fixture, with nothing but the binding's declaring scope to go on.
//!
//! Every test asserts the run's completion before reading its findings. The
//! soundness rule returns zero findings whenever an input is incomplete, so a
//! test that only counted findings would pass just as happily on a broken
//! query as on a satisfied invariant.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use serde_json::Value;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyAnalysisType, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFindingEvidence, PolicyIncompleteReason,
    PolicyLocationRelationship, PolicyRegistry, PolicyRegistryLimits, PolicyRun,
    PolicyRunCompletion, PolicySourceIdentity, TaintCatalogRegistry, format_rqlp_source,
};
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language, PythonAnalyzer, RustAnalyzer};

/// A read of `value` shadowed by a nearer `let`. The resolver selects the inner
/// binding at the lexical tier and records the outer one as rejected, so this
/// one fixture exercises the tier verdict and the candidate trace at once.
const RUST_SHADOWING: &str = "fn render() -> usize {\n    let value = 1;\n    {\n        let value = 2;\n        return value;\n    }\n}\n";

/// Both halves sort a `List<String> rows` inside a `while` loop. Only the first
/// is a real finding: its binding is declared outside the loop, so the sort is
/// redundant work per iteration. The second declares `rows` inside the loop
/// body, so each iteration sorts a fresh list. Nothing but the declaration site
/// differs -- the spelling, the call and the loop are identical.
const JAVA_LOOP_HALVES: &str = "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n\nclass Sorter {\n    void invariant(List<String> outerRows) {\n        List<String> rows = new ArrayList<>();\n        int index = 0;\n        while (index < 3) {\n            Collections.sort(rows);\n            index = index + 1;\n        }\n    }\n\n    void perIteration() {\n        int index = 0;\n        while (index < 3) {\n            List<String> rows = new ArrayList<>();\n            Collections.sort(rows);\n            index = index + 1;\n        }\n    }\n}\n";

fn policy(id: &str, subject: &str, asserts: &str) -> String {
    format!(
        r#"(policy
  :id "{id}"
  :name "Resolution assertion"
  :message "the resolution invariant does not hold"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql {subject})
    :asserts [{asserts}]))"#
    )
}

fn registry_with_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:resolution-assertion"),
            source.as_bytes(),
        )
        .expect("valid resolution assertion policy");
    registry
}

fn evaluate(source: &str, analyzer: &dyn IAnalyzer) -> PolicyRun {
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
            &mut PolicyBudget::default(),
        )
        .expect("resolution assertion evaluation")
}

fn rust_shadowing() -> (crate::common::BuiltInlineTestProject, RustAnalyzer) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/shadow.rs", RUST_SHADOWING)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn java_loop() -> (crate::common::BuiltInlineTestProject, JavaAnalyzer) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/Sorter.java", JAVA_LOOP_HALVES)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

const VALUE_SUBJECT: &str = r#"(identifier :text/regex "^value$" :capture "target")"#;

/// The receiver of the sort call, captured together with the loop it sits in,
/// so one match carries both nodes the containment assert compares.
const SORT_IN_LOOP_SUBJECT: &str = r#"(inside (loop :capture "region")
                (call :callee (name "sort") :args [(capture "target")]))"#;

/// The satisfied case: the read resolves to the nearer `let`, which is exactly
/// the lexical tier the invariant demands.
#[test]
fn an_expected_lexical_tier_is_clean_on_the_shadowing_fixture() {
    let (_project, analyzer) = rust_shadowing();
    let run = evaluate(
        &policy(
            "test.resolution.lexical",
            VALUE_SUBJECT,
            r#"(assert-resolution :id lexical :at "target" :role value_reference
                          :expect-tier lexical_binding)"#,
        ),
        &analyzer,
    );
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "the verdict must be read only from a complete run: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "the selected candidate is the lexical binding: {:?}",
        run.findings()
    );
}

/// The seeded near-miss: the same fixture under an invariant that demands a
/// different tier. The finding carries the tier that was actually selected and
/// every candidate the resolver considered, including the one it rejected.
#[test]
fn a_missed_tier_reports_the_selection_and_the_whole_candidate_trace() {
    let (_project, analyzer) = rust_shadowing();
    let run = evaluate(
        &policy(
            "test.resolution.import",
            VALUE_SUBJECT,
            r#"(assert-resolution :id imported :at "target" :role value_reference
                          :expect-tier explicit_import)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.assert_kind(), "resolution");
    assert_eq!(evidence.asserted_role(), "value_reference");
    assert_eq!(
        evidence.expectation(),
        "selected tier exactly explicit_import"
    );
    assert_eq!(
        evidence.observed(),
        Some("1 selected candidate(s) at tier(s) lexical_binding"),
        "the finding states what was selected, not merely that something was"
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
        relationships.contains(&PolicyLocationRelationship::SelectedCandidate),
        "the selection leads the trace: {relationships:?}"
    );
    assert!(
        relationships.contains(&PolicyLocationRelationship::ConsideredCandidate),
        "the rejected outer binding is published beside the winner: {relationships:?}"
    );
    assert!(!finding.related_truncated());
}

/// Tiers are ordered, so "at least this tier" accepts a stronger one. Without
/// the ordering the same document would be a finding, which is what the
/// previous test shows.
#[test]
fn at_least_accepts_a_tier_stronger_than_the_one_named() {
    let (_project, analyzer) = rust_shadowing();
    let run = evaluate(
        &policy(
            "test.resolution.at-least",
            VALUE_SUBJECT,
            r#"(assert-resolution :id at-least :at "target" :role value_reference
                          :expect-tier explicit_import :at-least true)"#,
        ),
        &analyzer,
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert!(
        run.findings().is_empty(),
        "lexical_binding is stronger than explicit_import: {:?}",
        run.findings()
    );
}

/// `:forbid-tier` removes one tier from an otherwise satisfied range, which is
/// how the anti-fallback contract is spelled.
#[test]
fn forbid_tier_fires_on_the_tier_the_resolver_actually_selected() {
    let (_project, analyzer) = rust_shadowing();
    let run = evaluate(
        &policy(
            "test.resolution.forbid",
            VALUE_SUBJECT,
            r#"(assert-resolution :id forbid :at "target" :role value_reference
                          :expect-tier explicit_import :at-least true
                          :forbid-tier lexical_binding)"#,
        ),
        &analyzer,
    );
    assert_eq!(run.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(
        run.findings().len(),
        1,
        "the forbidden tier is the selected one: {:?}",
        run.findings()
    );
}

/// The motivating discriminator as a policy. `:declared outside` must fire on
/// the half whose binding lives outside the loop and stay silent on the half
/// whose binding lives inside it; `:declared inside` must do the exact
/// opposite, on the same file, with the same subject selector.
#[test]
fn the_loop_invariance_verdict_separates_the_two_fixture_halves() {
    let (_project, analyzer) = java_loop();

    // "The sorted list must be declared inside the loop" is the requirement, so
    // the violation is the loop-invariant half -- the list declared once and
    // re-sorted every iteration.
    let inside_required = evaluate(
        &policy(
            "test.reaching.inside",
            SORT_IN_LOOP_SUBJECT,
            r#"(assert-reaching :id invariant :at "target" :role value_reference
                          :declared inside :relative-to "region")"#,
        ),
        &analyzer,
    );
    assert_eq!(
        inside_required.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        inside_required.diagnostics()
    );
    assert_eq!(
        inside_required.findings().len(),
        1,
        "exactly the loop-invariant half violates: {:?}",
        inside_required.findings()
    );
    let finding = &inside_required.findings()[0];
    let line = finding
        .primary()
        .region()
        .expect("the subject is a located node")
        .start_line();
    assert!(
        (9..=11).contains(&line),
        "the finding names the sort inside the first loop, not the second: line {line}"
    );
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.assert_kind(), "reaching");
    assert_eq!(
        evidence.observed(),
        Some("binding `rows` is declared outside capture `region`"),
        "the finding names the binding and where it actually is"
    );
    let relationships = finding
        .related()
        .iter()
        .map(|related| related.relationship())
        .collect::<Vec<_>>();
    assert!(
        relationships.contains(&PolicyLocationRelationship::ReachingBinding),
        "{relationships:?}"
    );
    assert!(
        relationships.contains(&PolicyLocationRelationship::DeclaringScope),
        "the scope that decided the verdict is published: {relationships:?}"
    );

    let outside_required = evaluate(
        &policy(
            "test.reaching.outside",
            SORT_IN_LOOP_SUBJECT,
            r#"(assert-reaching :id per-iteration :at "target" :role value_reference
                          :declared outside :relative-to "region")"#,
        ),
        &analyzer,
    );
    assert_eq!(
        outside_required.completion(),
        &PolicyRunCompletion::Complete
    );
    assert_eq!(
        outside_required.findings().len(),
        1,
        "the mirror invariant fires on the other half: {:?}",
        outside_required.findings()
    );
    let mirrored = outside_required.findings()[0]
        .primary()
        .region()
        .expect("the subject is a located node")
        .start_line();
    assert_ne!(
        mirrored, line,
        "the two halves are separated by the binding, not by the call"
    );
}

/// No resolver in the workspace admits to a name-only fallback today, so the
/// boundary contract is expressible and unviolated. The value of the test is
/// that it is *clean* rather than inconclusive: the trace does state a
/// selection and a boundary, so the assert reaches a verdict.
#[test]
fn a_boundary_contract_is_clean_while_no_resolver_falls_back_by_name() {
    let (_project, analyzer) = java_loop();
    let run = evaluate(
        &policy(
            "test.boundary.no-fallback",
            r#"(identifier :text/regex "^Collections$" :capture "target")"#,
            r#"(assert-boundary :id no-fallback :at "target" :role receiver_position
                          :forbid-fallback-past external_unknown)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "the boundary verdict must come from a complete run: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "nothing selected at name_only_fallback: {:?}",
        run.findings()
    );
}

/// Python's resolver records selections but not rejections, so an assert that
/// needs the whole considered set cannot conclude there. An absent rejection is
/// not evidence that nothing was rejected.
#[test]
fn a_selection_only_language_cannot_conclude_a_rejection_dependent_assert() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/widget.py",
            "def render(rows):\n    total = rows\n    return total\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());

    let unique = evaluate(
        &policy(
            "test.resolution.unique",
            r#"(identifier :text/regex "^rows$" :capture "target")"#,
            r#"(assert-resolution :id unique :at "target" :role value_reference
                          :expect-tier lexical_binding :require-unique true)"#,
        ),
        &analyzer,
    );
    let PolicyRunCompletion::Inconclusive { reasons } = unique.completion() else {
        panic!(
            "a rejection-dependent assert on a selection-only trace must be inconclusive, got {:?}",
            unique.completion()
        );
    };
    assert!(
        reasons.contains(&PolicyIncompleteReason::CapabilityIncomplete),
        "{reasons:?}"
    );
    assert!(
        unique.findings().is_empty(),
        "an incomplete row set never yields a verdict"
    );

    // The same subject without the rejection-dependent option concludes, which
    // is what makes the previous verdict a statement about the option rather
    // than about the language.
    let tier_only = evaluate(
        &policy(
            "test.resolution.tier-only",
            r#"(identifier :text/regex "^rows$" :capture "target")"#,
            r#"(assert-resolution :id tier-only :at "target" :role value_reference
                          :expect-tier lexical_binding)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        tier_only.completion(),
        &PolicyRunCompletion::Complete,
        "the selection axis alone is answerable in Python: {:?}",
        tier_only.diagnostics()
    );
}

fn decode_error(source: &str) -> String {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let error = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:resolution-assertion"),
            source.as_bytes(),
        )
        .expect_err("the policy must be rejected");
    format!("{error}")
}

/// A combination whose verdict is fixed before any row is read is an authoring
/// error, not a rule that always fires.
#[test]
fn unsatisfiable_resolution_asserts_are_rejected_at_decode_time() {
    let same_tier = policy(
        "test.resolution.contradiction",
        VALUE_SUBJECT,
        r#"(assert-resolution :id a :at "target" :role value_reference
                      :expect-tier lexical_binding :forbid-tier lexical_binding)"#,
    );
    assert!(
        decode_error(&same_tier).contains("can never hold"),
        "{}",
        decode_error(&same_tier)
    );

    let self_containment = policy(
        "test.reaching.contradiction",
        VALUE_SUBJECT,
        r#"(assert-reaching :id a :at "target" :role value_reference
                      :declared outside :relative-to "target")"#,
    );
    assert!(
        decode_error(&self_containment).contains("same capture"),
        "{}",
        decode_error(&self_containment)
    );

    // A resolution candidate exists only for a reference, so an assert about
    // one at a binder role can never join anything.
    let binder_role = policy(
        "test.resolution.role",
        VALUE_SUBJECT,
        r#"(assert-resolution :id a :at "target" :role binder
                      :expect-tier lexical_binding)"#,
    );
    assert!(
        decode_error(&binder_role).contains("reference"),
        "{}",
        decode_error(&binder_role)
    );
}

#[test]
fn the_formatter_round_trips_the_three_new_records() {
    let source = policy(
        "test.resolution.format",
        SORT_IN_LOOP_SUBJECT,
        r#"(assert-resolution :id a :at "target" :role value_reference :expect-tier lexical_binding)
       (assert-reaching :id b :at "target" :role value_reference :declared outside :relative-to "region")
       (assert-boundary :id c :at "target" :role value_reference :forbid-fallback-past external_unknown)"#,
    );
    let formatted = format_rqlp_source(&source).expect("formattable");
    for head in ["(assert-resolution", "(assert-reaching", "(assert-boundary"] {
        assert!(formatted.contains(head), "{formatted}");
    }
    assert_eq!(
        format_rqlp_source(&formatted).expect("formattable"),
        formatted,
        "the formatter must be idempotent over the new assert records"
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
        // Related locations and typed evidence are verbose-only detail.
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

/// The checked-in fixture pair: two files that differ only in where `rows` is
/// declared, one policy, and opposite exit codes. This is the shape a
/// conformance fixture reuses.
const LOOP_INVARIANT_POLICY: &str = r#"(policy
  :id "test.reaching.loop-invariant-receiver"
  :name "Sorted receiver is loop-invariant"
  :message "the sorted list is declared outside the loop, so every iteration sorts the same list"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (inside (loop :capture "region")
                          (call :callee (name "sort") :args [(capture "target")])))
    :asserts [
      (assert-reaching :id declared-inside :at "target" :role value_reference
                       :declared inside :relative-to "region")
    ]))"#;

const JAVA_INVARIANT_HALF: &str = "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n\nclass Invariant {\n    void run() {\n        List<String> rows = new ArrayList<>();\n        int index = 0;\n        while (index < 3) {\n            Collections.sort(rows);\n            index = index + 1;\n        }\n    }\n}\n";

const JAVA_PER_ITERATION_HALF: &str = "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n\nclass PerIteration {\n    void run() {\n        int index = 0;\n        while (index < 3) {\n            List<String> rows = new ArrayList<>();\n            Collections.sort(rows);\n            index = index + 1;\n        }\n    }\n}\n";

#[test]
fn the_policy_cli_separates_the_fixture_pair_and_renders_the_same_locations_everywhere() {
    let invariant = InlineTestProject::with_language(Language::Java)
        .file("src/Invariant.java", JAVA_INVARIANT_HALF)
        .file("policies/loop-invariant.rqlp", LOOP_INVARIANT_POLICY)
        .build();

    let human = bifrost_policy_run(invariant.root(), "policies/loop-invariant.rqlp", "human");
    assert_eq!(
        human.status.code(),
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        stdout_of(&human),
        String::from_utf8_lossy(&human.stderr)
    );
    let human_text = stdout_of(&human);
    assert!(human_text.contains("reaching assertion"), "{human_text}");
    assert!(human_text.contains("reaching_binding"), "{human_text}");
    assert!(human_text.contains("declaring_scope"), "{human_text}");

    let json = bifrost_policy_run(invariant.root(), "policies/loop-invariant.rqlp", "json");
    assert_eq!(json.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&json.stdout).expect("JSON report");
    let finding = &report["runs"][0]["findings"][0];
    assert_eq!(finding["evidence"]["type"], "assertion");
    assert_eq!(finding["evidence"]["evidence"]["assert_kind"], "reaching");
    let json_relationships = finding["related"]
        .as_array()
        .expect("related locations")
        .iter()
        .map(|related| related["relationship"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(
        json_relationships.contains(&"reaching_binding")
            && json_relationships.contains(&"declaring_scope"),
        "{json_relationships:?}"
    );

    let sarif = bifrost_policy_run(invariant.root(), "policies/loop-invariant.rqlp", "sarif");
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
            .any(|text| text.contains("reaching binding")),
        "{sarif_relationships:?}"
    );
    assert_eq!(
        json_relationships.len(),
        sarif_relationships.len(),
        "human, JSON and SARIF must publish the same related locations"
    );

    let per_iteration = InlineTestProject::with_language(Language::Java)
        .file("src/PerIteration.java", JAVA_PER_ITERATION_HALF)
        .file("policies/loop-invariant.rqlp", LOOP_INVARIANT_POLICY)
        .build();
    let clean = bifrost_policy_run(per_iteration.root(), "policies/loop-invariant.rqlp", "json");
    assert_eq!(
        clean.status.code(),
        Some(0),
        "a loop-local declaration is not a finding; stdout:\n{}\nstderr:\n{}",
        stdout_of(&clean),
        String::from_utf8_lossy(&clean.stderr)
    );
}
