use super::*;
use crate::budget::PolicyBudget;

fn budget(bytes: usize) -> PolicyBatchBudget {
    let per_policy = PolicyBudget::builder()
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

fn review_with_spare_path_capacity() -> PolicyPackActivationReview {
    let mut path = String::with_capacity(20_000);
    path.push('x');
    PolicyPackActivationReview::new_with_mode(
        path,
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    )
}

#[test]
fn pack_review_retention_charges_allocated_path_capacity() {
    let empty = PolicyReportBuilder::new(PolicyBatchBudget::default(), 0)
        .unwrap()
        .finish()
        .unwrap()
        .retained_size();
    let review = review_with_spare_path_capacity();
    let exact = empty + review.document_path.capacity();
    let mut at_limit = PolicyReportBuilder::new(budget(exact), 0).unwrap();
    at_limit.set_packs(review).unwrap();
    assert!(at_limit.finish().is_ok());

    let mut one_past = PolicyReportBuilder::new(budget(exact - 1), 0).unwrap();
    assert!(matches!(
        one_past.set_packs(review_with_spare_path_capacity()),
        Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. })
            if max_bytes == exact - 1
    ));
}
