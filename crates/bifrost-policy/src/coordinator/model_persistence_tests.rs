use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogOptions, SemanticModelActivationPersistence, SemanticModelActivationRequest,
    SemanticPackCatalog,
};
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};

use super::{
    PolicyEvaluationInput, PolicySemanticModelContext, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer_and_semantic_models,
};
use crate::inline_project::InlineTestProject;

#[test]
fn supplied_model_persistence_publishes_the_active_set_to_its_store() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "export function target() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("semantic model catalog");
    let persistence_store = AnalyzerStore::open_ephemeral().expect("persistence store");
    let request = SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: env!("CARGO_PKG_VERSION").parse().expect("package version"),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: Default::default(),
    };
    let input = PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("policies/target.rqlp"),
        r#"(policy
  :schema-version 1
  :id "test.model-persistence"
  :name "Model persistence"
  :message "Avoid target"
  :severity warning
  :analysis (analysis :type match
    :selector (rql :schema-version 1
      (language typescript (function :name "target")))))"#,
    );
    let options = crate::test_support::evaluation_options("2026-07-27");
    let context = PolicySemanticModelContext {
        catalog: &catalog,
        request: &request,
        persistence: Some(SemanticModelActivationPersistence {
            scope_id: "test-model-persistence",
            store: &persistence_store,
        }),
    };
    assert!(
        persistence_store
            .semantic_pack_active_set()
            .unwrap()
            .is_none()
    );
    let cold = evaluate_policy_inputs_with_analyzer_and_semantic_models(
        project.root(),
        std::slice::from_ref(&input),
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &options,
        context,
        None,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("cold policy evaluation");
    assert_eq!(cold.report().runs()[0].findings().len(), 1);
    assert!(cold.report().runs()[0].completion().is_complete());
    assert!(
        persistence_store
            .semantic_pack_active_set()
            .unwrap()
            .is_some()
    );

    let warm = evaluate_policy_inputs_with_analyzer_and_semantic_models(
        project.root(),
        &[input],
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &options,
        context,
        None,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("warm policy evaluation");
    assert_eq!(warm.report().runs()[0].findings().len(), 1);
    assert!(warm.report().runs()[0].completion().is_complete());
}
