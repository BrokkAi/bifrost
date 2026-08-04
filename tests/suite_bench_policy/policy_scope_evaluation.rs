use std::fs;
use std::path::{Path, PathBuf};

use crate::common::InlineTestProject;
use brokk_bifrost::Language;
use brokk_bifrost::policy::{
    POLICY_EXIT_CLEAN, POLICY_EXIT_FINDING, POLICY_EXIT_UNRELIABLE, PolicyBatchOutcome,
    PolicyEvaluationOptions, PolicyFailOn, PolicyReportDiagnosticCode, PolicyScopeDocumentState,
    evaluate_policy_files,
};
use serde_json::{Value, json};

const POLICY_PATH: &str = "policies/dynamic-eval.rqlp";
const DYNAMIC_EVAL_POLICY: &str =
    include_str!("../fixtures/policy-cli/project/policies/dynamic-eval.rqlp");
const EVAL_SOURCE: &str = "def run(user_code):\n    return eval(user_code)\n";

fn project_with_eval_files(paths: &[&str]) -> crate::common::BuiltInlineTestProject {
    let mut project = InlineTestProject::with_language(Language::Python);
    for path in paths {
        project = project.file(path, EVAL_SOURCE);
    }
    project.file(POLICY_PATH, DYNAMIC_EVAL_POLICY).build()
}

fn evaluate(root: &Path) -> PolicyBatchOutcome {
    evaluate_policy_files(
        root,
        &[PathBuf::from(POLICY_PATH)],
        &PolicyEvaluationOptions::new("2026-07-27".parse().expect("fixed test date"))
            .with_fail_on(PolicyFailOn::Warning),
    )
    .expect("policy evaluation")
}

fn write_scope(root: &Path, entries: Vec<Value>) {
    let path = root.join(".bifrost/policy-scope.json");
    fs::create_dir_all(path.parent().expect("scope parent")).expect("create scope directory");
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "scopes": entries,
        }))
        .expect("scope JSON"),
    )
    .expect("write scope");
}

fn scoped_paths(outcome: &PolicyBatchOutcome) -> Vec<(String, bool)> {
    outcome.report().runs()[0]
        .findings()
        .iter()
        .map(|finding| {
            (
                finding.primary().path().to_string(),
                finding.scope().is_some(),
            )
        })
        .collect()
}

#[test]
fn directory_scope_accepts_only_component_wise_contained_findings() {
    let project = project_with_eval_files(&["src/app.py", "src_extra/app.py", "vendor/lib.py"]);
    let baseline = evaluate(project.root());
    assert_eq!(baseline.exit_status(), POLICY_EXIT_FINDING);
    assert_eq!(baseline.report().runs()[0].findings().len(), 3);

    write_scope(
        project.root(),
        vec![json!({
            "path": "src",
            "reason": "Directory accepted for the scope evaluation test.",
        })],
    );
    let scoped = evaluate(project.root());
    assert_eq!(
        scoped.report().evaluation().scope_document_state(),
        PolicyScopeDocumentState::Loaded
    );
    // `src` must not cover `src_extra` (component-wise prefix), so the run
    // still fails on the two unscoped findings.
    assert_eq!(scoped.exit_status(), POLICY_EXIT_FINDING);
    let mut paths = scoped_paths(&scoped);
    paths.sort();
    assert_eq!(
        paths,
        vec![
            ("src/app.py".to_string(), true),
            ("src_extra/app.py".to_string(), false),
            ("vendor/lib.py".to_string(), false),
        ]
    );
    assert_eq!(scoped.report().scope().len(), 1);
    let review = &scoped.report().scope()[0];
    assert_eq!(review.entry().path(), "src");
    assert_eq!(review.matched_findings(), 1);
    assert!(review.applied());
    assert!(!review.result_omitted());

    // Scoping every directory turns the run clean while all findings stay
    // visible in the report with their scope decisions attached.
    write_scope(
        project.root(),
        vec![
            json!({"path": "src", "reason": "Directory accepted for the scope evaluation test."}),
            json!({"path": "src_extra", "reason": "Directory accepted for the scope evaluation test."}),
            json!({"path": "vendor", "reason": "Vendored corpus accepted for the scope evaluation test."}),
        ],
    );
    let clean = evaluate(project.root());
    assert_eq!(clean.exit_status(), POLICY_EXIT_CLEAN);
    assert_eq!(clean.report().runs()[0].findings().len(), 3);
    assert!(
        clean.report().runs()[0]
            .findings()
            .iter()
            .all(|finding| finding.scope().is_some())
    );
    let rendered = serde_json::to_value(clean.report()).expect("report JSON");
    assert_eq!(rendered["schema_version"], 3);
    let finding_scope = &rendered["runs"][0]["findings"][0]["scope"];
    assert!(finding_scope["path"].is_string(), "{rendered}");
    assert!(finding_scope["reason"].is_string(), "{rendered}");
}

#[test]
fn policy_selectors_gate_which_policies_an_entry_accepts() {
    let project = project_with_eval_files(&["src/app.py"]);
    let baseline = evaluate(project.root());
    assert_eq!(baseline.exit_status(), POLICY_EXIT_FINDING);
    let policy_id = baseline.report().rules()[0]
        .policy_id()
        .as_str()
        .to_string();

    // A category selector cannot match a repository policy: categories are a
    // built-in pack manifest concept, so the finding stays active.
    write_scope(
        project.root(),
        vec![json!({
            "path": "src",
            "reason": "Category-limited entry that must not match a repository policy.",
            "policy_categories": ["performance"],
        })],
    );
    let unmatched = evaluate(project.root());
    assert_eq!(unmatched.exit_status(), POLICY_EXIT_FINDING);
    assert_eq!(unmatched.report().scope().len(), 1);
    assert!(!unmatched.report().scope()[0].applied());
    assert_eq!(unmatched.report().scope()[0].matched_findings(), 0);

    // An exact policy_ids selector accepts it.
    write_scope(
        project.root(),
        vec![json!({
            "path": "src",
            "reason": "Exact policy id accepted for the scope evaluation test.",
            "policy_ids": [policy_id],
        })],
    );
    let scoped = evaluate(project.root());
    assert_eq!(scoped.exit_status(), POLICY_EXIT_CLEAN);
    assert!(scoped.report().scope()[0].applied());
}

#[test]
fn invalid_scope_documents_surface_a_diagnostic_and_do_not_accept_findings() {
    let project = project_with_eval_files(&["src/app.py"]);
    let path = project.root().join(".bifrost/policy-scope.json");
    fs::create_dir_all(path.parent().expect("scope parent")).expect("create scope directory");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "scopes": [{"path": "/absolute", "reason": "invalid path shape"}],
        }))
        .expect("scope JSON"),
    )
    .expect("write scope");

    let outcome = evaluate(project.root());
    // An invalid scope document must not silently accept anything: the run is
    // unreliable, exactly like an invalid suppression document.
    assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
    assert_eq!(
        outcome.report().evaluation().scope_document_state(),
        PolicyScopeDocumentState::Invalid
    );
    assert!(
        outcome
            .report()
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == PolicyReportDiagnosticCode::ScopeLoadFailed),
        "diagnostics: {:?}",
        outcome.report().diagnostics()
    );
    assert!(outcome.report().scope().is_empty());
}

#[test]
fn suppressed_findings_are_not_double_accepted_by_scope() {
    let project = project_with_eval_files(&["src/app.py"]);
    let baseline = evaluate(project.root());
    let finding = &baseline.report().runs()[0].findings()[0];
    let policy_id = baseline.report().rules()[0]
        .policy_id()
        .as_str()
        .to_string();
    let finding_id = finding.id().to_string();

    let suppression_path = project.root().join(".bifrost/suppressions.json");
    fs::create_dir_all(suppression_path.parent().expect("suppression parent"))
        .expect("create suppression directory");
    fs::write(
        suppression_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "suppressions": [{
                "policy_id": policy_id,
                "finding_id": finding_id,
                "identity_stability": "strong",
                "status": "accepted",
                "reason": "Reviewed for the scope precedence test.",
                "policy_hash_at_acceptance": null,
                "accepted_by": null,
                "accepted_at": "2026-07-01",
                "expires_at": null,
            }],
        }))
        .expect("suppression JSON"),
    )
    .expect("write suppressions");
    write_scope(
        project.root(),
        vec![json!({
            "path": "src",
            "reason": "Scope entry that must not claim the already suppressed finding.",
        })],
    );

    let outcome = evaluate(project.root());
    assert_eq!(outcome.exit_status(), POLICY_EXIT_CLEAN);
    let finding = &outcome.report().runs()[0].findings()[0];
    assert!(finding.suppression().is_some());
    assert!(finding.scope().is_none());
    assert_eq!(outcome.report().scope()[0].matched_findings(), 0);
    assert!(!outcome.report().scope()[0].applied());
}
