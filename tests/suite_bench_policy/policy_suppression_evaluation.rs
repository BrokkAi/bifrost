use std::fs;
use std::path::{Path, PathBuf};

use crate::common::InlineTestProject;
use brokk_bifrost::Language;
use brokk_bifrost::policy::{
    POLICY_EXIT_CLEAN, POLICY_EXIT_FINDING, POLICY_EXIT_UNRELIABLE, PolicyBatchOutcome,
    PolicyEvaluationDate, PolicyEvaluationOptions, PolicyFailOn, PolicyReportDiagnosticCode,
    PolicySuppressionDocumentState, PolicySuppressionMatchState, PolicySuppressionPolicyHashState,
    PolicySuppressionTemporalState, evaluate_policy_files,
};
use serde_json::{Value, json};

const POLICY_PATH: &str = "policies/dynamic-eval.rqlp";
const DYNAMIC_EVAL_POLICY: &str =
    include_str!("../fixtures/policy-cli/project/policies/dynamic-eval.rqlp");
const RESOURCE_POLICY: &str =
    include_str!("../fixtures/policy-cli/project/policies/resource-lifecycle.rqlp");
const RESOURCE_ACQUIRE: &str =
    include_str!("../fixtures/policy-cli/project/policies/endpoints/resource-acquire.rqlp");
const RESOURCE_CLOSE: &str =
    include_str!("../fixtures/policy-cli/project/policies/endpoints/resource-close.rqlp");
const RESOURCE_SOURCE: &str = include_str!("../fixtures/policy-cli/project/src/resource.ts");

fn evaluation_options(date: &str) -> PolicyEvaluationOptions {
    PolicyEvaluationOptions::new(date.parse().expect("fixed test date"))
}

fn project_with_policy(source: &str, policy: &str) -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Python)
        .file("src/app.py", source)
        .file(POLICY_PATH, policy)
        .file("policies/endpoints/resource-acquire.rqlp", RESOURCE_ACQUIRE)
        .file("policies/endpoints/resource-close.rqlp", RESOURCE_CLOSE)
        .build()
}

fn evaluate(
    root: &Path,
    date: &str,
    fail_on: PolicyFailOn,
) -> brokk_bifrost::policy::PolicyBatchOutcome {
    evaluate_policy_files(
        root,
        &[PathBuf::from(POLICY_PATH)],
        &evaluation_options(date).with_fail_on(fail_on),
    )
    .expect("policy evaluation")
}

fn suppression_record(
    policy_id: &str,
    finding_id: &str,
    policy_hash: Option<&str>,
    expires_at: Option<&str>,
) -> Value {
    json!({
        "policy_id": policy_id,
        "finding_id": finding_id,
        "identity_stability": "strong",
        "status": "accepted",
        "reason": "Reviewed compatibility boundary",
        "policy_hash_at_acceptance": policy_hash,
        "accepted_by": "security-review",
        "accepted_at": "2026-07-01",
        "expires_at": expires_at,
    })
}

fn write_suppressions(root: &Path, records: Vec<Value>) {
    let path = root.join(".bifrost/suppressions.json");
    fs::create_dir_all(path.parent().expect("suppression parent"))
        .expect("create suppression directory");
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "suppressions": records,
        }))
        .expect("suppression JSON"),
    )
    .expect("write suppressions");
}

fn first_identity(outcome: &PolicyBatchOutcome) -> (String, String, String) {
    let rule = &outcome.report().rules()[0];
    let finding = &outcome.report().runs()[0].findings()[0];
    (
        rule.policy_id().as_str().to_string(),
        rule.policy_hash().to_string(),
        finding.id().to_string(),
    )
}

fn without_retained_bytes(work: &brokk_bifrost::policy::PolicyWorkReport) -> Value {
    let mut value = serde_json::to_value(work).expect("serialize work");
    value
        .as_object_mut()
        .expect("work object")
        .remove("retained_report_bytes");
    value
}

#[test]
fn exact_strong_suppression_survives_line_and_policy_presentation_changes_but_not_source_edits() {
    let project = project_with_policy(
        "def run(user_code):\n    return eval(user_code)\n",
        DYNAMIC_EVAL_POLICY,
    );
    let baseline = evaluate(project.root(), "2026-07-27", PolicyFailOn::Warning);
    assert_eq!(baseline.exit_status(), POLICY_EXIT_FINDING);
    let (policy_id, policy_hash, finding_id) = first_identity(&baseline);
    let baseline_finding = serde_json::to_value(&baseline.report().runs()[0].findings()[0])
        .expect("baseline finding JSON");
    let baseline_work = without_retained_bytes(baseline.report().runs()[0].work());

    write_suppressions(
        project.root(),
        vec![suppression_record(
            &policy_id,
            &finding_id,
            Some(&policy_hash),
            None,
        )],
    );
    let suppressed = evaluate(project.root(), "2026-07-27", PolicyFailOn::Warning);
    assert_eq!(suppressed.exit_status(), POLICY_EXIT_CLEAN);
    assert_eq!(suppressed.report().schema_version(), 3);
    assert_eq!(
        suppressed.report().evaluation().evaluation_date(),
        PolicyEvaluationDate::from_ymd(2026, 7, 27).unwrap()
    );
    assert_eq!(
        suppressed
            .report()
            .evaluation()
            .suppression_document_state(),
        PolicySuppressionDocumentState::Loaded
    );
    assert_eq!(suppressed.report().suppressions().len(), 1);
    let review = &suppressed.report().suppressions()[0];
    assert!(review.applied());
    assert!(!review.stale());
    assert_eq!(
        review.match_state(),
        PolicySuppressionMatchState::StrongFinding
    );
    assert_eq!(
        review.temporal_state(),
        PolicySuppressionTemporalState::Current
    );
    assert_eq!(
        review.policy_hash_state(),
        PolicySuppressionPolicyHashState::Matching
    );
    let finding = &suppressed.report().runs()[0].findings()[0];
    assert_eq!(finding.id().to_string(), finding_id);
    assert_eq!(
        finding.suppression().unwrap().decision().reason(),
        "Reviewed compatibility boundary"
    );

    let mut expected_finding = baseline_finding;
    let mut actual_finding = serde_json::to_value(finding).expect("suppressed finding JSON");
    assert_eq!(
        expected_finding
            .as_object_mut()
            .expect("finding object")
            .remove("suppression"),
        Some(Value::Null)
    );
    assert!(
        actual_finding
            .as_object_mut()
            .expect("finding object")
            .remove("suppression")
            .unwrap()
            .is_object()
    );
    assert_eq!(actual_finding, expected_finding);
    assert_eq!(
        without_retained_bytes(suppressed.report().runs()[0].work()),
        baseline_work
    );

    fs::write(
        project.root().join("src/app.py"),
        "# unrelated line\ndef run(user_code):\n    return eval(user_code)\n",
    )
    .expect("insert unrelated line");
    let shifted = evaluate(project.root(), "2026-07-27", PolicyFailOn::Warning);
    assert_eq!(shifted.exit_status(), POLICY_EXIT_CLEAN);
    assert_eq!(
        shifted.report().runs()[0].findings()[0].id().to_string(),
        finding_id
    );
    assert!(shifted.report().suppressions()[0].applied());

    let changed_policy = DYNAMIC_EVAL_POLICY
        .replace(
            ":message \"Dynamic evaluation is forbidden\"",
            ":message \"Dynamic evaluation requires review\"",
        )
        .replace(":severity warning", ":severity error");
    fs::write(project.root().join(POLICY_PATH), changed_policy).expect("edit policy presentation");
    let drifted = evaluate(project.root(), "2026-07-27", PolicyFailOn::Error);
    assert_eq!(drifted.exit_status(), POLICY_EXIT_CLEAN);
    assert_eq!(
        drifted.report().runs()[0].findings()[0].id().to_string(),
        finding_id
    );
    assert_eq!(
        drifted.report().suppressions()[0].policy_hash_state(),
        PolicySuppressionPolicyHashState::Drifted
    );
    assert_eq!(
        drifted.report().runs()[0].findings()[0]
            .suppression()
            .unwrap()
            .policy_hash_state(),
        PolicySuppressionPolicyHashState::Drifted
    );

    fs::write(
        project.root().join("src/app.py"),
        "# unrelated line\ndef run(user_code):\n    return eval(user_code.strip())\n",
    )
    .expect("edit selected source");
    let changed = evaluate(project.root(), "2026-07-27", PolicyFailOn::Error);
    assert_eq!(changed.exit_status(), POLICY_EXIT_FINDING);
    assert_ne!(
        changed.report().runs()[0].findings()[0].id().to_string(),
        finding_id
    );
    assert!(
        changed.report().runs()[0].findings()[0]
            .suppression()
            .is_none()
    );
    let review = &changed.report().suppressions()[0];
    assert_eq!(
        review.match_state(),
        PolicySuppressionMatchState::FindingAbsent
    );
    assert!(review.stale());
    assert!(!review.applied());
}

#[test]
fn expired_suppression_is_audited_but_does_not_change_the_failure_threshold() {
    let project = project_with_policy(
        "def run(user_code):\n    return eval(user_code)\n",
        DYNAMIC_EVAL_POLICY,
    );
    let baseline = evaluate(project.root(), "2026-07-27", PolicyFailOn::Warning);
    let (policy_id, policy_hash, finding_id) = first_identity(&baseline);
    write_suppressions(
        project.root(),
        vec![suppression_record(
            &policy_id,
            &finding_id,
            Some(&policy_hash),
            Some("2026-07-26"),
        )],
    );

    let outcome = evaluate(project.root(), "2026-07-27", PolicyFailOn::Warning);
    assert_eq!(outcome.exit_status(), POLICY_EXIT_FINDING);
    assert!(
        outcome.report().runs()[0].findings()[0]
            .suppression()
            .is_none()
    );
    let review = &outcome.report().suppressions()[0];
    assert_eq!(
        review.match_state(),
        PolicySuppressionMatchState::StrongFinding
    );
    assert_eq!(
        review.temporal_state(),
        PolicySuppressionTemporalState::Expired
    );
    assert!(!review.applied());
    assert!(!review.stale());
}

#[test]
fn invalid_suppression_input_is_unreliable_without_skipping_policy_evaluation() {
    let project = project_with_policy(
        "def run(user_code):\n    return eval(user_code)\n",
        DYNAMIC_EVAL_POLICY,
    );
    let path = project.root().join(".bifrost/suppressions.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, r#"{"schema_version":1,"suppressions":{}}"#)
        .expect("invalid suppression shape");

    let outcome = evaluate(project.root(), "2026-07-27", PolicyFailOn::Warning);
    assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    assert!(outcome.report().suppressions().is_empty());
    assert_eq!(
        outcome.report().evaluation().suppression_document_state(),
        PolicySuppressionDocumentState::Invalid
    );
    assert!(outcome.report().diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == PolicyReportDiagnosticCode::SuppressionLoadFailed
    }));
}

#[test]
fn absent_unselected_and_incomplete_policies_are_not_conflated_as_stale() {
    let project = project_with_policy(
        "def run(user_code):\n    return eval(user_code)\n",
        DYNAMIC_EVAL_POLICY,
    );
    write_suppressions(
        project.root(),
        vec![suppression_record(
            "test.not-selected",
            &"1".repeat(64),
            None,
            None,
        )],
    );
    let unselected = evaluate(project.root(), "2026-07-27", PolicyFailOn::Never);
    let review = &unselected.report().suppressions()[0];
    assert_eq!(
        review.match_state(),
        PolicySuppressionMatchState::PolicyNotEvaluated
    );
    assert_eq!(
        review.policy_hash_state(),
        PolicySuppressionPolicyHashState::Unknown
    );
    assert!(!review.stale());

    let project = InlineTestProject::new()
        .file("src/resource.ts", RESOURCE_SOURCE)
        .file(POLICY_PATH, RESOURCE_POLICY)
        .file("policies/endpoints/resource-acquire.rqlp", RESOURCE_ACQUIRE)
        .file("policies/endpoints/resource-close.rqlp", RESOURCE_CLOSE)
        .build();
    write_suppressions(
        project.root(),
        vec![suppression_record(
            "bifrost.test.resource-lifecycle",
            &"2".repeat(64),
            None,
            None,
        )],
    );
    let incomplete = evaluate(project.root(), "2026-07-27", PolicyFailOn::Never);
    assert_eq!(incomplete.exit_status(), POLICY_EXIT_UNRELIABLE);
    let review = &incomplete.report().suppressions()[0];
    assert_eq!(
        review.match_state(),
        PolicySuppressionMatchState::PolicyIncomplete
    );
    assert!(!review.stale());
}
