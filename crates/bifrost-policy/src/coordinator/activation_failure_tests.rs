use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};

use super::{
    POLICY_EXIT_UNRELIABLE, PolicyEvaluationInput, PolicyHostActivationContext,
    PolicyReportDiagnosticCode, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer_and_host_activation,
};
use crate::inline_project::InlineTestProject;

#[test]
fn failed_host_activation_makes_an_otherwise_complete_run_unreliable() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "export function target() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let input = PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("policies/target.rqlp"),
        r#"(policy
  :schema-version 1
  :id "test.host-activation"
  :name "Host activation"
  :message "Avoid target"
  :severity warning
  :analysis (analysis :type match
    :selector (rql :schema-version 1
      (language typescript (function :name "target")))))"#,
    );
    let outcome = evaluate_policy_inputs_with_analyzer_and_host_activation(
        project.root(),
        &[input],
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &crate::test_support::evaluation_options("2026-07-27"),
        PolicyHostActivationContext::new(None, None, &[], Some("activation failed")),
        None,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("failed activation has a canonical report");
    assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
    assert!(outcome.report().runs()[0].completion().is_complete());
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    assert!(outcome.report().diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == PolicyReportDiagnosticCode::PackActivationFailed
    }));
}
