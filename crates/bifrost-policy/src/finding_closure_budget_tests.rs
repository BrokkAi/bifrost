use super::*;
use std::mem::size_of;

#[test]
fn authored_closure_storage_obeys_exact_run_byte_budget() {
    let loaded = crate::test_support::load_match_policy(
        r#"(policy :id "test.closure-budget" :name "Closure budget" :message "m"
            :severity warning :analysis (analysis :type match
            :selector (rql (call :callee (name "eval")))))"#,
    );
    let budget = PolicyBudget::default();
    let mut run = PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        PolicyAnalysisType::Match,
        PolicyRunCompletion::ProvenBySummary,
        Vec::new(),
        Vec::new(),
        false,
        PolicyWorkReport::default(),
        &budget,
    )
    .unwrap();
    let without_closures = run.retained_size();
    let closures = (b'a'..=b'd')
        .map(|suffix| {
            AuthoredArmClosureEvidence::try_new(
                format!("model-{}", char::from(suffix)),
                format!("{}{}", "a".repeat(127), char::from(suffix)),
                7,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let expected_closure_bytes = closures
        .iter()
        .map(|closure| {
            size_of::<AuthoredArmClosureEvidence>()
                + closure.model().len()
                + closure.content().len()
        })
        .sum::<usize>();
    run.set_authored_arm_closures(closures);
    assert_eq!(run.authored_arm_closures().len(), 4);
    let exact_bytes = without_closures + expected_closure_bytes;
    assert_eq!(run.retained_size(), exact_bytes);
    assert_eq!(
        run.work().retained_report_bytes(),
        u64::try_from(exact_bytes).unwrap()
    );

    let exact = PolicyBudget::builder()
        .with_max_retained_report_bytes(exact_bytes)
        .unwrap()
        .build()
        .unwrap();
    assert!(run.validate_against_budget(&exact).is_ok());

    let one_short = PolicyBudget::builder()
        .with_max_retained_report_bytes(exact_bytes - 1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        run.validate_against_budget(&one_short),
        Err(PolicyRunError::RetainedReportBytesExceeded {
            max: exact_bytes - 1
        })
    );
}
