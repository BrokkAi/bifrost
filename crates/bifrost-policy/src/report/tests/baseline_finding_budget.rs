use super::*;
use crate::baseline::{
    PolicyBaselineReview, PolicyFindingBaseline, parse_policy_baseline_document,
};

fn finding_with_accepted_by(loaded: &LoadedPolicy, accepted_by: Option<&str>) -> PolicyFinding {
    let document = parse_policy_baseline_document(
        &json!({
            "schema_version": 1,
            "reason": "approved",
            "accepted_at": "2026-08-08",
            "accepted_by": accepted_by,
            "policies": [],
        })
        .to_string(),
    )
    .unwrap();
    let mut finding = report_finding(loaded);
    finding
        .attach_baseline(PolicyFindingBaseline::new(
            &document,
            PolicySuppressionPolicyHashState::Matching,
        ))
        .unwrap();
    finding
}

fn admitted(loaded: &LoadedPolicy, finding: PolicyFinding, bytes: usize) -> bool {
    let per_policy = crate::budget::PolicyBudget::builder()
        .with_max_retained_report_bytes(bytes)
        .unwrap()
        .build()
        .unwrap();
    let budget = PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(bytes)
        .unwrap()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap();
    let Ok(mut builder) = PolicyReportBuilder::new(budget, 1) else {
        return false;
    };
    let review_document = parse_policy_baseline_document(
        &json!({
            "schema_version": 1,
            "reason": "approved",
            "accepted_at": "2026-08-08",
            "policies": [],
        })
        .to_string(),
    )
    .unwrap();
    if builder
        .set_baseline(PolicyBaselineReview::new(
            &"x".repeat(8_000),
            &review_document,
            Vec::new(),
        ))
        .is_err()
    {
        return false;
    }
    if builder
        .register_policy(
            PolicyRuleDescriptor::from_loaded(loaded),
            report_run(
                loaded,
                PolicyAnalysisType::Match,
                PolicyRunCompletion::Complete,
            ),
        )
        .is_err()
    {
        return false;
    }
    matches!(
        builder.retain_finding(finding),
        Ok(PolicyRetentionOutcome::Retained)
    )
}

#[test]
fn baseline_accepted_by_is_charged_when_admitting_a_finding() {
    let loaded = loaded_match_policy();
    let short = finding_with_accepted_by(&loaded, None);
    let long = finding_with_accepted_by(&loaded, Some(&"a".repeat(256)));
    let mut low = 0usize;
    let mut high = 1_000_000usize;
    assert!(admitted(&loaded, short.clone(), high));
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if admitted(&loaded, short.clone(), middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    assert!(admitted(&loaded, short, high));
    assert!(!admitted(&loaded, long, high));
}
