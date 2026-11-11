use std::path::PathBuf;

use super::{IncrementalBaseState, evaluate_policy_files};
use crate::inline_project::InlineTestProject;

#[test]
fn source_only_policy_edit_invalidates_diff_base_reuse() {
    let source = r#"(policy
  :schema-version 1
  :id "test.source-identity"
  :name "Source identity"
  :message "Avoid target"
  :severity warning
  :analysis (analysis :type match
    :selector (rql :schema-version 1
      (language typescript (function :name "target")))))"#;
    let project =
        InlineTestProject::with_language(brokk_bifrost_analysis::analyzer::Language::TypeScript)
            .file("app.ts", "export function target() {}\n")
            .file("policies/target.rqlp", source)
            .with_git()
            .build();
    let path = [PathBuf::from("policies/target.rqlp")];
    let options =
        crate::test_support::evaluation_options("2026-07-27").with_diff_base("HEAD".to_owned());
    let cold = evaluate_policy_files(
        project.root(),
        &path,
        &options,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("cold diff evaluation");
    let warm = evaluate_policy_files(
        project.root(),
        &path,
        &options,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("warm diff evaluation");
    assert_eq!(cold.report().runs()[0].findings().len(), 1);
    assert!(cold.report().runs()[0].completion().is_complete());
    assert_eq!(
        warm.report().incremental().expect("warm review").base(),
        IncrementalBaseState::Reused
    );

    std::fs::write(
        project.root().join("policies/target.rqlp"),
        source.replace(":name \"Source identity\"", ":name  \"Source identity\""),
    )
    .expect("source-only policy edit");
    let changed = evaluate_policy_files(
        project.root(),
        &path,
        &options,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("changed diff evaluation");
    assert_eq!(
        changed.report().runs()[0].policy_hash(),
        cold.report().runs()[0].policy_hash()
    );
    assert_eq!(changed.report().diff(), cold.report().diff());
    assert_eq!(
        changed
            .report()
            .incremental()
            .expect("changed review")
            .base(),
        IncrementalBaseState::Evaluated,
    );
}
