use super::*;
use brokk_bifrost_test_macros::hardwon;

fn input(index: usize, reason: String) -> PolicySuppressionAuthoringInput {
    PolicySuppressionAuthoringInput {
        policy_id: PolicyId::new("test.policy").unwrap(),
        finding_id: format!("{index:064x}").parse().unwrap(),
        path: None,
        policy_hash_at_acceptance: None,
        accepted_at: "2026-01-01".parse().unwrap(),
        reason: Some(reason),
        accepted_by: None,
        expires_at: Some("2026-12-31".parse().unwrap()),
    }
}

#[test]
fn calendar_and_portable_path_boundaries_are_inclusive() {
    let date = PolicyEvaluationDate::from_ymd(0, 1, 1).unwrap();
    assert_eq!(serde_json::to_string(&date).unwrap(), "\"0000-01-01\"");
    assert_eq!(date, "0000-01-01".parse().unwrap());
    assert!(PolicyEvaluationDate::from_ymd(-1, 1, 1).is_err());
    assert!(PolicyEvaluationDate::from_ymd(10000, 1, 1).is_err());
    let path = format!("{}file", "abc/".repeat(255));
    assert_eq!(path.len(), 1024);
    assert!(PolicySuppressionSource::explicit_portable(&path).is_ok());
    assert!(PolicySuppressionSource::explicit_portable(format!("{path}x")).is_err());
}

#[test]
fn distinct_findings_preserve_acceptance_provenance() {
    let first = prepare_policy_suppression_document(None, input(1, "reviewed".into())).unwrap();
    let second =
        prepare_policy_suppression_document(Some(&first), input(2, "reviewed".into())).unwrap();
    let value: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_eq!(value["suppressions"].as_array().unwrap().len(), 2);
    for record in value["suppressions"].as_array().unwrap() {
        assert_eq!(record["accepted_at"], "2026-01-01");
        assert_eq!(record["expires_at"], "2026-12-31");
    }
    assert!(
        prepare_policy_suppression_document(Some(&second), input(1, "changed".into())).is_err()
    );
}

#[test]
fn wire_errors_preserve_coordinates_schema_and_reason_contracts() {
    let malformed = "{\n  \"schema_version\": 1,\n  \"suppressions\": ?}";
    let error = parse_policy_suppression_document(malformed).unwrap_err();
    assert!(matches!(
        error,
        PolicySuppressionDocumentError::JsonDecode {
            line: 3,
            column: 19,
            ..
        }
    ));
    assert!(error.to_string().contains("line 3, column 19"), "{error}");
    let encoded = prepare_policy_suppression_document(None, input(1, " reviewed ".into())).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    value["schema_version"] = 0.into();
    assert!(matches!(
        parse_policy_suppression_document(&value.to_string()),
        Err(PolicySuppressionDocumentError::Validation(
            PolicySuppressionValidationError::UnsupportedSchemaVersion { observed: 0 }
        ))
    ));
    value["schema_version"] = 1.into();
    value["suppressions"][0]["reason"] = "   ".into();
    assert!(parse_policy_suppression_document(&value.to_string()).is_err());
    let unknown = format!("{{\"{}\":0}}", "x".repeat(8000));
    let error = parse_policy_suppression_document(&unknown)
        .unwrap_err()
        .to_string();
    assert!(error.len() < 700);
    assert!(error.contains("unknown field"));
}

#[test]
#[hardwon("7b8948e98be3: suppression authoring emitted documents exceeding the loader byte limit")]
fn authored_documents_fit_the_loader_at_the_exact_byte_limit() {
    let limit = MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES as usize;
    // The public loader cap is 256 KiB; each reason is at most 4096 bytes.
    let mut document = None;
    for index in 0..58 {
        document = Some(
            prepare_policy_suppression_document(
                document.as_deref(),
                input(index, "r".repeat(4096)),
            )
            .unwrap(),
        );
    }
    let base =
        prepare_policy_suppression_document(document.as_deref(), input(58, "r".into())).unwrap();
    let padding = limit - base.len();
    assert!(padding < MAX_POLICY_SUPPRESSION_REASON_BYTES);
    let exact = prepare_policy_suppression_document(
        document.as_deref(),
        input(58, "r".repeat(padding + 1)),
    )
    .unwrap();
    assert_eq!(exact.len(), limit);
    assert!(parse_policy_suppression_document(&exact).is_ok());
    assert!(matches!(
        parse_policy_suppression_document(&format!("{exact} ")),
        Err(PolicySuppressionDocumentError::Validation(
            PolicySuppressionValidationError::DocumentTooLarge { .. }
        ))
    ));
    assert!(matches!(
        prepare_policy_suppression_document(
            document.as_deref(),
            input(58, "r".repeat(padding + 2))
        ),
        Err(PolicySuppressionDocumentError::Validation(
            PolicySuppressionValidationError::DocumentTooLarge { .. }
        ))
    ));
}

#[test]
fn unconsulted_sources_keep_all_configured_paths() {
    let options = PolicySuppressionOptions::default();
    assert_eq!(
        options.primary_relative_path(),
        DEFAULT_POLICY_SUPPRESSION_PATH
    );
    let states = options.source_states(PolicySuppressionDocumentState::NotEvaluated);
    let paths: Vec<_> = states.iter().map(|source| source.path()).collect();
    assert_eq!(paths, CONVENTIONAL_POLICY_SUPPRESSION_PATHS);
    assert!(
        states
            .iter()
            .all(|source| source.state() == PolicySuppressionDocumentState::NotEvaluated)
    );
}

#[test]
fn loader_accepts_exact_document_and_merged_record_limits() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".bifrost")).unwrap();
    let options = PolicySuppressionOptions::default();
    let encoded = prepare_policy_suppression_document(None, input(1, "reviewed".into())).unwrap();
    let padded = format!(
        "{encoded}{}",
        " ".repeat(MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES as usize - encoded.len())
    );
    let destination = root.path().join(DEFAULT_POLICY_SUPPRESSION_PATH);
    std::fs::write(&destination, &padded).unwrap();
    let outcome = load_policy_suppressions(root.path(), &options).unwrap();
    assert!(outcome.failures.is_empty(), "{outcome:?}");
    assert_eq!(outcome.document.unwrap().suppressions().len(), 1);
    std::fs::write(&destination, format!("{padded} ")).unwrap();
    assert!(
        !load_policy_suppressions(root.path(), &options)
            .unwrap()
            .failures
            .is_empty()
    );
    let record: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    for count in [512, 513] {
        for (source, range) in [
            (DEFAULT_POLICY_SUPPRESSION_PATH, 0..256),
            (LOCAL_POLICY_SUPPRESSION_PATH, 256..count),
        ] {
            let records: Vec<_> = range
                .map(|index| {
                    let mut value = record["suppressions"][0].clone();
                    value["finding_id"] = format!("{index:064x}").into();
                    value
                })
                .collect();
            std::fs::write(
                root.path().join(source),
                serde_json::json!({"schema_version": 1, "suppressions": records}).to_string(),
            )
            .unwrap();
        }
        let outcome = load_policy_suppressions(root.path(), &options).unwrap();
        if count == 512 {
            assert!(outcome.failures.is_empty(), "{outcome:?}");
            assert_eq!(outcome.document.unwrap().suppressions().len(), 512);
        } else {
            assert!(outcome.failures.iter().any(|failure| matches!(
                failure.error,
                PolicySuppressionSourceFailureKind::TooManyRecords {
                    observed: 513,
                    max: 512
                }
            )));
        }
    }
}

#[test]
#[hardwon("ae156fed62d3: report context omitted suppression source array storage")]
fn report_preflight_counts_each_configured_source_element() {
    use crate::budget::{PolicyBatchBudget, PolicyBudget};
    use crate::report::{PolicyReportBuilder, PolicyReportBuilderError};
    fn floor(sources: Vec<PolicySuppressionSourceState>) -> usize {
        let per_policy = PolicyBudget::builder()
            .with_max_retained_report_bytes(0)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(0)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let context = PolicyReportEvaluationContext::new(
            "2026-01-01".parse().unwrap(),
            sources,
            &PolicyScopeOptions::default(),
            PolicyScopeDocumentState::NotEvaluated,
        );
        match PolicyReportBuilder::new_with_suppression_audit(budget, 0, context, vec![], vec![]) {
            Err(PolicyReportBuilderError::SkeletonPreflightExceeded { required_bytes, .. }) => {
                required_bytes
            }
            _ => panic!("expected preflight refusal"),
        }
    }
    let sources = PolicySuppressionOptions::default()
        .source_states(PolicySuppressionDocumentState::NotEvaluated);
    let payload: usize = CONVENTIONAL_POLICY_SUPPRESSION_PATHS
        .iter()
        .map(|path| path.len() + std::mem::size_of::<PolicySuppressionSourceState>())
        .sum();
    assert_eq!(floor(sources) - floor(vec![]), payload);
}
