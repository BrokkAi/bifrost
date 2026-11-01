use super::*;
use crate::baseline::{
    PolicyBaselineEntryReview, PolicyBaselineMatchState, PolicyBaselineReview,
    parse_policy_baseline_document,
};
use crate::retained::RetainedSize;
use crate::suppression::PolicySuppressionPolicyHashState;
use serde_json::json;

fn review(policy_id: &str, with_entry: bool, path: &str) -> PolicyBaselineReview {
    let ids = if with_entry {
        vec!["a".repeat(64)]
    } else {
        Vec::new()
    };
    let document = parse_policy_baseline_document(
        &json!({
            "schema_version": 1,
            "reason": "accepted",
            "accepted_at": "2026-08-08",
            "policies": [{ "policy_id": policy_id, "finding_ids": ids }],
        })
        .to_string(),
    )
    .unwrap();
    let record = &document.policies()[0];
    let entries = record
        .finding_ids()
        .iter()
        .map(|id| {
            PolicyBaselineEntryReview::new(
                record.policy_id().clone(),
                *id,
                PolicyBaselineMatchState::FindingAbsent,
                PolicySuppressionPolicyHashState::Unknown,
            )
        })
        .collect();
    PolicyBaselineReview::new(path, &document, entries)
}

fn report_budget(bytes: usize) -> PolicyBatchBudget {
    let per_policy = crate::budget::PolicyBudget::builder()
        .with_max_retained_report_bytes(bytes)
        .unwrap()
        .build()
        .unwrap();
    PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(bytes)
        .unwrap()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap()
}

fn admitted(review: PolicyBaselineReview, bytes: usize) -> bool {
    let mut builder = PolicyReportBuilder::new(report_budget(bytes), 0).unwrap();
    builder.set_baseline(review).is_ok()
}

fn floor_path(base: PolicyBaselineReview) -> (usize, String) {
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 0).unwrap();
    builder.set_baseline(base).unwrap();
    let current = builder.finish().unwrap().retained_size();
    let floor = match PolicyReportBuilder::new(report_budget(0), 0) {
        Err(PolicyReportBuilderError::SkeletonPreflightExceeded { required_bytes, .. }) => {
            required_bytes
        }
        _ => panic!("expected skeleton preflight"),
    };
    assert!(current <= floor);
    (
        floor,
        format!(".bifrost/baseline.json{}", "x".repeat(floor - current)),
    )
}

#[test]
fn baseline_entry_policy_identifier_is_charged_to_report_budget() {
    let (cap, path) = floor_path(review("test.a", true, ".bifrost/baseline.json"));
    let short = review("test.a", true, &path);
    let long = review(&format!("test.{}", "a".repeat(100)), true, &path);
    assert!(admitted(short, cap));
    assert!(!admitted(long, cap));
}

#[test]
fn baseline_review_entries_are_charged_to_report_budget() {
    let (cap, path) = floor_path(review("test.a", false, ".bifrost/baseline.json"));
    let empty = review("test.a", false, &path);
    let populated = review("test.a", true, &path);
    assert!(admitted(empty, cap));
    assert!(!admitted(populated, cap));
}
