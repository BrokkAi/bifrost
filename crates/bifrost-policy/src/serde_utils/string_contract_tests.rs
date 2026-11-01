use crate::PolicyEvaluationDate;

#[test]
fn policy_date_requires_exact_string_input() {
    let date: PolicyEvaluationDate = serde_json::from_str("\"2026-10-30\"").unwrap();
    assert_eq!(serde_json::to_string(&date).unwrap(), "\"2026-10-30\"");

    for input in ["\" 2026-10-30\"", "\"2026-10-30 \"", "42"] {
        let error = serde_json::from_str::<PolicyEvaluationDate>(input).unwrap_err();
        assert_eq!(
            error.classify(),
            serde_json::error::Category::Data,
            "{input}"
        );
    }
}
