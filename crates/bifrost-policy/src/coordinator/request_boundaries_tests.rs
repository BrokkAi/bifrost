use std::collections::BTreeMap;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
};

use super::{
    PolicyBatchBudget, PolicyCostHints, PolicyEvaluationInput, PolicySourceIdentity,
    evaluate_policy_files_with_analyzer, evaluate_policy_inputs,
};

fn matching_policy(index: usize) -> String {
    format!(
        r#"(policy
  :schema-version 1
  :id "test.capacity-{index}"
  :name "Capacity {index}"
  :message "Avoid target"
  :severity warning
  :analysis (analysis :type match
    :selector (rql :schema-version 1
      (language typescript (function :name "target")))))"#
    )
}

#[test]
fn cost_hints_accept_the_full_policy_batch_capacity() {
    let maximum = PolicyBatchBudget::default().max_policies();
    let hints = (0..maximum)
        .map(|index| (format!("policy-{index}"), 1))
        .collect::<BTreeMap<_, _>>();
    assert!(PolicyCostHints::try_from(hints.clone()).is_ok());

    let mut too_many = hints;
    too_many.insert("one-more-policy".to_owned(), 1);
    assert!(PolicyCostHints::try_from(too_many).is_err());
}

#[test]
fn embedded_policies_accept_the_full_batch_capacity_without_python_models() {
    let project = tempfile::tempdir().expect("workspace");
    for index in 0..5 {
        std::fs::write(
            project.path().join(format!("app-{index}.ts")),
            "export function target() {}\n",
        )
        .expect("source file");
    }
    let maximum = PolicyBatchBudget::default().max_policies();
    let inputs = (0..maximum)
        .map(|index| {
            PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new(format!("policies/{index}.rqlp")),
                matching_policy(index),
            )
        })
        .collect::<Vec<_>>();
    let options = crate::test_support::evaluation_options("2026-07-27");
    let outcome =
        evaluate_policy_inputs(project.path(), &inputs, &options).expect("a full batch is legal");
    assert_eq!(outcome.report().runs().len(), maximum);
    assert!(
        outcome
            .report()
            .runs()
            .iter()
            .all(|run| run.completion().is_complete())
    );
    assert!(
        outcome
            .report()
            .runs()
            .iter()
            .all(|run| run.findings().len() == 5)
    );

    let mut too_many = inputs;
    too_many.push(PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("policies/one-more.rqlp"),
        matching_policy(maximum),
    ));
    assert!(evaluate_policy_inputs(project.path(), &too_many, &options).is_err());
}

#[test]
fn policy_files_accept_the_full_batch_capacity() {
    let project = tempfile::tempdir().expect("workspace");
    std::fs::write(
        project.path().join("app.ts"),
        "export function target() {}\n",
    )
    .expect("source file");
    let maximum = PolicyBatchBudget::default().max_policies();
    let paths = (0..maximum)
        .map(|index| {
            let relative = std::path::PathBuf::from(format!("policy-{index}.rqlp"));
            std::fs::write(project.path().join(&relative), matching_policy(index))
                .expect("policy file");
            relative
        })
        .collect::<Vec<_>>();
    let options = crate::test_support::evaluation_options("2026-07-27");
    let project_handle: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(project.path().to_path_buf()).expect("filesystem project"));
    let workspace =
        WorkspaceAnalyzer::build_ephemeral_footgun(project_handle, AnalyzerConfig::default())
            .expect("workspace analyzer");
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let outcome = evaluate_policy_files_with_analyzer(
        project.path(),
        &paths,
        &workspace,
        &flow,
        &options,
        None,
    )
    .expect("a full file batch is legal");
    assert_eq!(outcome.report().runs().len(), maximum);
    assert!(
        outcome
            .report()
            .runs()
            .iter()
            .all(|run| run.completion().is_complete())
    );

    let mut too_many = paths;
    too_many.push(std::path::PathBuf::from("one-more.rqlp"));
    assert!(
        evaluate_policy_files_with_analyzer(
            project.path(),
            &too_many,
            &workspace,
            &flow,
            &options,
            None
        )
        .is_err()
    );
}
