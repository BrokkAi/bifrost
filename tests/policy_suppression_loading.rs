mod common;

use std::fs;
use std::path::Path;

use brokk_bifrost::policy::{
    DEFAULT_POLICY_SUPPRESSION_PATH, MAX_POLICY_SUPPRESSION_ACCEPTED_BY_BYTES,
    MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES, MAX_POLICY_SUPPRESSION_REASON_BYTES,
    MAX_POLICY_SUPPRESSIONS, PolicyDateError, PolicyEvaluationDate, PolicySuppressionDocumentError,
    PolicySuppressionLoadError, PolicySuppressionOptions, PolicySuppressionSource,
    PolicySuppressionValidationError, WorkspaceDocumentError, load_policy_suppressions,
    parse_policy_suppression_document,
};
use common::InlineTestProject;
use serde_json::{Value, json};

fn inline_project() -> common::BuiltInlineTestProject {
    InlineTestProject::new()
        .file("src/lib.rs", "pub fn ready() -> bool { true }\n")
        .build()
}

fn valid_record(policy_id: &str, hex: char) -> Value {
    json!({
        "policy_id": policy_id,
        "finding_id": hex.to_string().repeat(64),
        "identity_stability": "strong",
        "status": "accepted",
        "reason": "Reviewed generated compatibility shim",
        "policy_hash_at_acceptance": "a".repeat(64),
        "accepted_by": "security-review",
        "accepted_at": "2026-07-27",
        "expires_at": "2027-07-27"
    })
}

fn document(records: Vec<Value>) -> String {
    serde_json::to_string(&json!({
        "schema_version": 1,
        "suppressions": records,
    }))
    .unwrap()
}

fn write_conventional(root: &Path, source: impl AsRef<[u8]>) {
    let path = root.join(DEFAULT_POLICY_SUPPRESSION_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn validation_error(source: &str) -> PolicySuppressionValidationError {
    match parse_policy_suppression_document(source).unwrap_err() {
        PolicySuppressionDocumentError::Validation(error) => error,
        other => panic!("expected validation error, got {other:?}"),
    }
}

#[test]
fn missing_conventional_document_is_empty_but_valid_document_is_loaded() {
    let project = inline_project();
    let options = PolicySuppressionOptions::default();

    assert_eq!(
        load_policy_suppressions(project.root(), &options).unwrap(),
        None
    );

    write_conventional(
        project.root(),
        document(vec![valid_record("test.policy", '1')]),
    );
    let loaded = load_policy_suppressions(project.root(), &options)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.schema_version(), 1);
    assert_eq!(loaded.suppressions().len(), 1);
    let record = &loaded.suppressions()[0];
    assert_eq!(record.policy_id().as_str(), "test.policy");
    assert_eq!(record.finding_id().to_string(), "1".repeat(64));
    assert_eq!(record.reason(), "Reviewed generated compatibility shim");
    assert_eq!(record.accepted_by(), Some("security-review"));
    assert_eq!(record.accepted_at().to_string(), "2026-07-27");
    assert_eq!(record.expires_at().unwrap().to_string(), "2027-07-27");
    assert_eq!(
        record.policy_hash_at_acceptance().unwrap().to_string(),
        "a".repeat(64)
    );
}

#[test]
fn reordered_records_normalize_to_identical_canonical_documents() {
    let first = valid_record("test.zeta", '2');
    let second = valid_record("test.alpha", '1');

    let forward =
        parse_policy_suppression_document(&document(vec![first.clone(), second.clone()])).unwrap();
    let reverse = parse_policy_suppression_document(&document(vec![second, first])).unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(forward.suppressions()[0].policy_id().as_str(), "test.alpha");
    assert_eq!(
        serde_json::to_value(&forward).unwrap(),
        serde_json::to_value(&reverse).unwrap()
    );
}

#[test]
fn optional_provenance_normalizes_to_explicit_nulls() {
    let mut record = valid_record("test.policy", '1');
    record.as_object_mut().unwrap().remove("accepted_by");
    record
        .as_object_mut()
        .unwrap()
        .remove("policy_hash_at_acceptance");
    record.as_object_mut().unwrap().remove("expires_at");

    let normalized = parse_policy_suppression_document(&document(vec![record])).unwrap();
    let value = serde_json::to_value(normalized).unwrap();
    let record = &value["suppressions"][0];
    assert_eq!(record["accepted_by"], Value::Null);
    assert_eq!(record["policy_hash_at_acceptance"], Value::Null);
    assert_eq!(record["expires_at"], Value::Null);
}

#[test]
fn json_shape_and_schema_are_closed() {
    let mut unknown = valid_record("test.policy", '1');
    unknown["unexpected"] = json!(true);
    assert!(matches!(
        parse_policy_suppression_document(&document(vec![unknown])),
        Err(PolicySuppressionDocumentError::JsonDecode { .. })
    ));
    assert!(matches!(
        parse_policy_suppression_document(
            &serde_json::to_string(&json!({"schema_version": 2, "suppressions": []})).unwrap()
        ),
        Err(PolicySuppressionDocumentError::Validation(
            PolicySuppressionValidationError::UnsupportedSchemaVersion { observed: 2 }
        ))
    ));
    assert!(matches!(
        parse_policy_suppression_document(
            r#"{"schema_version":1,"schema_version":1,"suppressions":[]}"#
        ),
        Err(PolicySuppressionDocumentError::JsonDecode { .. })
    ));
}

#[test]
fn duplicate_and_conflicting_keys_are_rejected_after_sorting() {
    let record = valid_record("test.policy", '1');
    assert!(matches!(
        validation_error(&document(vec![record.clone(), record.clone()])),
        PolicySuppressionValidationError::DuplicateSuppression { .. }
    ));

    let mut conflict = record.clone();
    conflict["reason"] = json!("Different review decision");
    assert!(matches!(
        validation_error(&document(vec![conflict, record])),
        PolicySuppressionValidationError::ConflictingSuppression { .. }
    ));
}

#[test]
fn hashes_identity_status_and_text_are_strict() {
    let mut uppercase_finding = valid_record("test.policy", '1');
    uppercase_finding["finding_id"] = json!("A".repeat(64));
    assert!(matches!(
        validation_error(&document(vec![uppercase_finding])),
        PolicySuppressionValidationError::InvalidFindingId { .. }
    ));

    let mut malformed_hash = valid_record("test.policy", '1');
    malformed_hash["policy_hash_at_acceptance"] = json!("g".repeat(64));
    assert!(matches!(
        validation_error(&document(vec![malformed_hash])),
        PolicySuppressionValidationError::InvalidAcceptedPolicyHash { .. }
    ));

    let mut weak = valid_record("test.policy", '1');
    weak["identity_stability"] = json!("weak");
    assert!(matches!(
        validation_error(&document(vec![weak])),
        PolicySuppressionValidationError::IdentityMustBeStrong { .. }
    ));

    let mut pending = valid_record("test.policy", '1');
    pending["status"] = json!("pending");
    assert!(matches!(
        validation_error(&document(vec![pending])),
        PolicySuppressionValidationError::StatusMustBeAccepted { .. }
    ));

    let mut unsafe_reason = valid_record("test.policy", '1');
    unsafe_reason["reason"] = json!("unsafe\nreason");
    assert!(matches!(
        validation_error(&document(vec![unsafe_reason])),
        PolicySuppressionValidationError::InvalidReason { .. }
    ));

    let mut blank_reviewer = valid_record("test.policy", '1');
    blank_reviewer["accepted_by"] = json!("   ");
    assert!(matches!(
        validation_error(&document(vec![blank_reviewer])),
        PolicySuppressionValidationError::BlankAcceptedBy { .. }
    ));

    let mut long_reason = valid_record("test.policy", '1');
    long_reason["reason"] = json!("r".repeat(MAX_POLICY_SUPPRESSION_REASON_BYTES + 1));
    assert!(matches!(
        validation_error(&document(vec![long_reason])),
        PolicySuppressionValidationError::InvalidReason { .. }
    ));

    let mut long_reviewer = valid_record("test.policy", '1');
    long_reviewer["accepted_by"] = json!("r".repeat(MAX_POLICY_SUPPRESSION_ACCEPTED_BY_BYTES + 1));
    assert!(matches!(
        validation_error(&document(vec![long_reviewer])),
        PolicySuppressionValidationError::InvalidAcceptedBy { .. }
    ));
}

#[test]
fn dates_use_exact_calendar_syntax_and_expiration_is_ordered() {
    assert_eq!(
        "2026-7-27".parse::<PolicyEvaluationDate>(),
        Err(PolicyDateError::InvalidFormat)
    );
    assert_eq!(
        "2026-02-30".parse::<PolicyEvaluationDate>(),
        Err(PolicyDateError::InvalidDate)
    );
    assert_eq!(
        PolicyEvaluationDate::from_ymd(2024, 2, 29)
            .unwrap()
            .to_string(),
        "2024-02-29"
    );
    assert_eq!(
        PolicyEvaluationDate::from_ymd(-1, 1, 1),
        Err(PolicyDateError::YearOutOfRange)
    );
    assert_eq!(
        PolicyEvaluationDate::from_ymd(10_000, 1, 1),
        Err(PolicyDateError::YearOutOfRange)
    );

    let mut backwards = valid_record("test.policy", '1');
    backwards["expires_at"] = json!("2026-07-26");
    assert!(matches!(
        validation_error(&document(vec![backwards])),
        PolicySuppressionValidationError::ExpirationBeforeAcceptance { .. }
    ));
}

#[test]
fn record_count_and_document_bytes_are_bounded_before_retention() {
    let records = (0..=MAX_POLICY_SUPPRESSIONS)
        .map(|index| valid_record(&format!("test.policy-{index}"), '1'))
        .collect();
    let too_many = document(records);
    assert!(too_many.len() as u64 <= MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES);
    assert!(matches!(
        validation_error(&too_many),
        PolicySuppressionValidationError::TooManySuppressions { .. }
    ));

    let oversized = " ".repeat(MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES as usize + 1);
    assert!(matches!(
        validation_error(&oversized),
        PolicySuppressionValidationError::DocumentTooLarge { .. }
    ));
}

#[test]
fn explicit_json_path_is_confined_and_wrong_extensions_are_rejected() {
    let project = inline_project();
    let source = document(vec![valid_record("test.explicit", '2')]);
    let explicit_path = project.root().join("review/suppressions.json");
    fs::create_dir_all(explicit_path.parent().unwrap()).unwrap();
    fs::write(&explicit_path, source).unwrap();
    let options = PolicySuppressionOptions::new(
        PolicySuppressionSource::explicit(Path::new("review/suppressions.json")).unwrap(),
    );

    let loaded = load_policy_suppressions(project.root(), &options)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.suppressions()[0].policy_id().as_str(),
        "test.explicit"
    );

    assert!(PolicySuppressionSource::explicit_portable("../escape.json").is_err());
    assert!(PolicySuppressionSource::explicit(Path::new("/tmp/escape.json")).is_err());
    assert!(
        PolicySuppressionSource::explicit_portable(format!(
            "{}.json",
            "x".repeat(brokk_bifrost::policy::MAX_POLICY_SUPPRESSION_PATH_BYTES)
        ))
        .is_err()
    );
    let wrong_extension = PolicySuppressionOptions::new(
        PolicySuppressionSource::explicit(Path::new("review/suppressions.txt")).unwrap(),
    );
    assert!(matches!(
        load_policy_suppressions(project.root(), &wrong_extension),
        Err(PolicySuppressionLoadError::Workspace(
            WorkspaceDocumentError::UnsupportedExtension { .. }
        ))
    ));
}

#[test]
fn invalid_utf8_and_directories_are_not_treated_as_missing() {
    let project = inline_project();
    write_conventional(project.root(), [0xff, 0xfe]);
    assert!(matches!(
        load_policy_suppressions(project.root(), &PolicySuppressionOptions::default()),
        Err(PolicySuppressionLoadError::Workspace(
            WorkspaceDocumentError::InvalidUtf8 { .. }
        ))
    ));

    fs::remove_file(project.root().join(DEFAULT_POLICY_SUPPRESSION_PATH)).unwrap();
    fs::create_dir(project.root().join(DEFAULT_POLICY_SUPPRESSION_PATH)).unwrap();
    assert!(matches!(
        load_policy_suppressions(project.root(), &PolicySuppressionOptions::default()),
        Err(PolicySuppressionLoadError::Workspace(
            WorkspaceDocumentError::NotRegularFile { .. }
        ))
    ));
}

#[cfg(unix)]
#[test]
fn fifo_and_symlink_escape_are_rejected_without_blocking_or_following() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let project = inline_project();
    let conventional = project.root().join(DEFAULT_POLICY_SUPPRESSION_PATH);
    fs::create_dir_all(conventional.parent().unwrap()).unwrap();
    let fifo = CString::new(conventional.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        load_policy_suppressions(project.root(), &PolicySuppressionOptions::default()),
        Err(PolicySuppressionLoadError::Workspace(
            WorkspaceDocumentError::NotRegularFile { .. }
        ))
    ));

    fs::remove_file(&conventional).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        outside.path(),
        document(vec![valid_record("test.outside", '3')]),
    )
    .unwrap();
    symlink(outside.path(), &conventional).unwrap();
    assert!(matches!(
        load_policy_suppressions(project.root(), &PolicySuppressionOptions::default()),
        Err(PolicySuppressionLoadError::Workspace(
            WorkspaceDocumentError::PathEscapesWorkspace { .. }
        ))
    ));
}
