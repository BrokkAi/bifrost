use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::packs_document::WorkspacePacksActivation;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    MatcherIndexes, RegisteredWorkspaceSemanticModel, ResolvedActiveSemanticModels,
    SemanticModelActivationReport, SemanticModelRuntimeOutcome,
};
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, DependencyPackActivationOutcome, Language};

use super::{
    PolicyEvaluationInput, PolicyHostActivationContext, PolicyReportDiagnosticCode,
    PolicySourceIdentity, evaluate_policy_inputs_with_analyzer_and_host_activation,
};
use crate::inline_project::InlineTestProject;

#[test]
fn usable_incomplete_models_report_each_inactive_source_file() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "export function target() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report = SemanticModelActivationReport::default();
    let usable = Arc::new(ResolvedActiveSemanticModels {
        active_model_set_hash: "empty-active-models".to_owned(),
        source_reader: None,
        shards: Vec::new(),
        indexes: MatcherIndexes::default(),
        extraction_gaps: Vec::new(),
        extraction_gaps_by_declaration: Default::default(),
        report: report.clone(),
    });
    let activation = WorkspacePacksActivation {
        ecosystems: Vec::new(),
        workspace_models: vec![
            RegisteredWorkspaceSemanticModel {
                path: ".bifrost/semantic-models/first.json".to_owned(),
                pack_id: "test.inactive-first".to_owned(),
                manifest_digest: "first-digest".to_owned(),
            },
            RegisteredWorkspaceSemanticModel {
                path: ".bifrost/semantic-models/second.json".to_owned(),
                pack_id: "test.inactive-second".to_owned(),
                manifest_digest: "second-digest".to_owned(),
            },
        ],
        outcome: DependencyPackActivationOutcome {
            ecosystems: Vec::new(),
            runtime: Some(SemanticModelRuntimeOutcome::Incomplete {
                usable: Some(usable),
                report,
            }),
            diagnostic_refresh_required: true,
        },
    };
    let input = PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("policies/target.rqlp"),
        r#"(policy
  :schema-version 1
  :id "test.incomplete-models"
  :name "Incomplete models"
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
        PolicyHostActivationContext::new(None, Some(&activation), &[], None),
        None,
    )
    .expect("canonical policy report");
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    let mut sources = outcome
        .report()
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            diagnostic.code() == PolicyReportDiagnosticCode::WorkspaceModelLoadFailed
        })
        .filter_map(|diagnostic| diagnostic.source().map(|source| source.as_str()))
        .collect::<Vec<_>>();
    sources.sort_unstable();
    assert_eq!(
        sources,
        [
            ".bifrost/semantic-models/first.json",
            ".bifrost/semantic-models/second.json",
        ]
    );
}
