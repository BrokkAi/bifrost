use std::time::Duration;

use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};

use super::{
    CancellationToken, PolicyExecutionStage, PolicySourceIdentity, evaluate_policy_source,
};
use crate::inline_project::InlineTestProject;

#[test]
fn deadline_report_sums_distinct_preparation_stages() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "export function target() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default().with_timeout(Duration::ZERO);
    let policy = r#"(policy
  :schema-version 1
  :id "test.preparation-timing"
  :name "Preparation timing"
  :message "Avoid target"
  :severity warning
  :analysis (analysis :type match
    :selector (rql :schema-version 1
      (language typescript (function :name "target")))))"#;
    let mut outcome = evaluate_policy_source(
        project.root(),
        PolicySourceIdentity::new("policies/timing.rqlp"),
        policy,
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &crate::test_support::evaluation_options("2026-07-27"),
        Some(&cancellation),
    )
    .expect("canonical deadline report");
    let before = outcome.report().execution().total_elapsed_ms();
    assert!(outcome.report().execution().termination().is_some());
    assert!(
        outcome
            .report()
            .execution()
            .stage_timings()
            .iter()
            .all(|timing| {
                !matches!(
                    timing.stage(),
                    PolicyExecutionStage::PolicySelection
                        | PolicyExecutionStage::SuppressionPreflight
                        | PolicyExecutionStage::WorkspaceSnapshot
                )
            })
    );
    outcome.record_preparation_timings(
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_millis(30),
    );
    assert_eq!(outcome.report().execution().total_elapsed_ms(), before + 60);
}
