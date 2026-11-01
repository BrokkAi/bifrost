use super::*;
use serde_json::json;

fn document(reason: &str, accepted_by: &str) -> String {
    json!({
        "schema_version": 1,
        "reason": reason,
        "accepted_by": accepted_by,
        "accepted_at": "2026-08-08",
        "policies": []
    })
    .to_string()
}

#[test]
fn canonical_baseline_ends_at_a_record_boundary() {
    let parsed = parse_policy_baseline_document(&document("approved", "team")).unwrap();
    let encoded = parsed.to_canonical_json();
    assert!(encoded.ends_with('\n'));
    assert_eq!(parse_policy_baseline_document(&encoded).unwrap(), parsed);
}

#[test]
fn explicit_baseline_path_obeys_its_own_cap() {
    let explicit = PolicyBaselineSource::explicit_portable("config/team.json").unwrap();
    assert_eq!(explicit.relative_path(), "config/team.json");

    let at_cap = "a".repeat(MAX_POLICY_BASELINE_PATH_BYTES);
    assert!(PolicyBaselineSource::explicit_portable(&at_cap).is_ok());
    let too_long = "a".repeat(MAX_POLICY_BASELINE_PATH_BYTES + 1);
    let error = PolicyBaselineSource::explicit_portable(&too_long).unwrap_err();
    assert_eq!(
        error,
        PolicyBaselineSourceError::TooLong {
            max_bytes: MAX_POLICY_BASELINE_PATH_BYTES
        }
    );
}

#[test]
fn baseline_json_errors_have_one_based_coordinates() {
    let error = parse_policy_baseline_document("{\n  nope\n}").unwrap_err();
    let PolicyBaselineDocumentError::JsonDecode { line, column, .. } = error else {
        panic!("expected JSON error")
    };
    assert_eq!((line, column), (2, 3));
    assert!(parse_policy_baseline_document("{").is_err());
    let error = parse_policy_baseline_document("{").unwrap_err();
    let PolicyBaselineDocumentError::JsonDecode { line, .. } = error else {
        panic!("expected JSON error")
    };
    assert_eq!(line, 1);
}

#[test]
fn baseline_text_fields_obey_separate_caps() {
    assert!(
        parse_policy_baseline_document(&document(
            &"r".repeat(MAX_POLICY_BASELINE_REASON_BYTES),
            "team"
        ))
        .is_ok()
    );
    assert!(matches!(
        parse_policy_baseline_document(&document(
            &"r".repeat(MAX_POLICY_BASELINE_REASON_BYTES + 1),
            "team"
        )),
        Err(PolicyBaselineDocumentError::Validation(
            PolicyBaselineValidationError::InvalidReason { .. }
        ))
    ));
    assert!(
        parse_policy_baseline_document(&document(
            "r",
            &"a".repeat(MAX_POLICY_BASELINE_ACCEPTED_BY_BYTES)
        ))
        .is_ok()
    );
    assert!(matches!(
        parse_policy_baseline_document(&document(
            "r",
            &"a".repeat(MAX_POLICY_BASELINE_ACCEPTED_BY_BYTES + 1)
        )),
        Err(PolicyBaselineDocumentError::Validation(
            PolicyBaselineValidationError::InvalidAcceptedBy { .. }
        ))
    ));
    assert!(matches!(
        parse_policy_baseline_document(&document("r", "   ")),
        Err(PolicyBaselineDocumentError::Validation(
            PolicyBaselineValidationError::BlankAcceptedBy
        ))
    ));
}

#[test]
fn explicit_baseline_file_is_loaded() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("config")).unwrap();
    std::fs::write(
        directory.path().join("config/team.json"),
        document("team approval", "team"),
    )
    .unwrap();
    let root = WorkspaceRoot::open(directory.path()).unwrap();
    let source = PolicyBaselineSource::explicit_portable("config/team.json").unwrap();
    let loaded = load_policy_baseline_from_root(&root, &PolicyBaselineOptions::new(source))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.reason(), "team approval");
}

#[test]
fn baseline_document_loads_above_half_of_the_declared_byte_cap() {
    let directory = tempfile::tempdir().unwrap();
    let policies = (0..75_000)
        .map(|index| {
            json!({
                "policy_id": format!("test.policy-{index:05}"),
                "finding_ids": [format!("{index:064x}")],
            })
        })
        .collect::<Vec<_>>();
    let source = json!({
        "schema_version": 1,
        "reason": "onboarding",
        "accepted_at": "2026-08-08",
        "policies": policies,
    })
    .to_string();
    assert!(source.len() as u64 > MAX_POLICY_BASELINE_DOCUMENT_BYTES / 2);
    assert!(source.len() as u64 <= MAX_POLICY_BASELINE_DOCUMENT_BYTES);
    std::fs::create_dir(directory.path().join(".bifrost")).unwrap();
    std::fs::write(directory.path().join(DEFAULT_POLICY_BASELINE_PATH), source).unwrap();
    let root = WorkspaceRoot::open(directory.path()).unwrap();
    let loaded = load_policy_baseline_from_root(&root, &PolicyBaselineOptions::default())
        .unwrap()
        .unwrap();
    assert_eq!(loaded.entry_count(), 75_000);
}

#[test]
fn baseline_review_retains_the_declared_number_of_notable_entries() {
    let ids = (0..=MAX_BASELINE_REVIEW_ENTRIES)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let source = json!({
        "schema_version": 1,
        "reason": "onboarding",
        "accepted_at": "2026-08-08",
        "policies": [{ "policy_id": "test.policy", "finding_ids": ids }],
    })
    .to_string();
    let document = parse_policy_baseline_document(&source).unwrap();
    let policy = &document.policies()[0];
    let entries = policy
        .finding_ids()
        .iter()
        .map(|id| {
            PolicyBaselineEntryReview::new(
                policy.policy_id().clone(),
                *id,
                PolicyBaselineMatchState::FindingAbsent,
                PolicySuppressionPolicyHashState::Unknown,
            )
        })
        .collect();
    let review = PolicyBaselineReview::new(DEFAULT_POLICY_BASELINE_PATH, &document, entries);
    assert!(review.entries_truncated());
    assert_eq!(review.entries().len(), MAX_BASELINE_REVIEW_ENTRIES);
    assert_eq!(
        review.stale_count(),
        (MAX_BASELINE_REVIEW_ENTRIES + 1) as u64
    );
}
