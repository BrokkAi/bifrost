use std::time::Duration;

use super::{
    PolicyReportDiagnosticCode, preflight_policy_suppressions,
    suppression_preflight_failure_outcome, workspace_snapshot_deadline_outcome_with_preflight,
};
use crate::suppression::{DEFAULT_POLICY_SUPPRESSION_PATH, PRIVATE_POLICY_SUPPRESSION_PATH};

#[test]
fn suppression_preflight_reports_the_first_failed_source() {
    let project = tempfile::tempdir().expect("workspace");
    std::fs::create_dir(project.path().join(".bifrost")).expect("suppression directory");
    for path in [
        DEFAULT_POLICY_SUPPRESSION_PATH,
        PRIVATE_POLICY_SUPPRESSION_PATH,
    ] {
        std::fs::write(project.path().join(path), "{ invalid json")
            .expect("malformed suppression document");
    }
    let options = crate::test_support::evaluation_options("2026-07-27");
    let preflight =
        preflight_policy_suppressions(project.path(), &options).expect("suppression preflight");
    assert!(!preflight.is_valid());
    let outcome =
        suppression_preflight_failure_outcome(&options, preflight, Duration::ZERO, Duration::ZERO)
            .expect("canonical failure report");
    let diagnostic = outcome
        .report()
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == PolicyReportDiagnosticCode::SuppressionLoadFailed)
        .expect("suppression load diagnostic");
    // `preflight_policy_suppressions` documents conventional load order and
    // the first-failure source selected for the canonical report.
    assert_eq!(
        diagnostic.source().map(|source| source.as_str()),
        Some(DEFAULT_POLICY_SUPPRESSION_PATH)
    );
}

#[test]
fn snapshot_deadline_preserves_discovered_suppression_source() {
    let project = tempfile::tempdir().expect("workspace");
    crate::policy_suppressions::write_policy_suppressions(
        project.path(),
        DEFAULT_POLICY_SUPPRESSION_PATH,
        Vec::new(),
    );
    let options = crate::test_support::evaluation_options("2026-07-27");
    let preflight =
        preflight_policy_suppressions(project.path(), &options).expect("suppression preflight");
    assert!(preflight.is_valid());
    let outcome = workspace_snapshot_deadline_outcome_with_preflight(
        &options,
        Vec::new(),
        Duration::ZERO,
        &preflight,
        Duration::ZERO,
        Duration::ZERO,
    )
    .expect("canonical deadline report");
    assert!(outcome.report().diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == PolicyReportDiagnosticCode::WorkspaceSnapshotDeadlineExceeded
    }));
    assert!(
        outcome
            .report()
            .evaluation()
            .suppression_sources()
            .iter()
            .any(|source| { source.path() == DEFAULT_POLICY_SUPPRESSION_PATH })
    );
}
