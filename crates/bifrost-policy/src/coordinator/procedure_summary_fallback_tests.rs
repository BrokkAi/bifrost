use std::sync::Arc;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::packs_document::{
    WorkspacePacksActivation, parse_workspace_packs_config,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, DependencyPackActivationOutcome, OverlayProject, WorkspaceAnalyzer,
};

use super::{
    PolicyEvaluationInput, PolicyHostActivationContext, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer_and_host_activation,
};
use crate::inline_project::InlineTestProject;

const SUMMARY_MODEL: &str = r#"{
  "schema_version": 2,
  "pack_id": "test.summary-fallback",
  "version": "1.0.0",
  "producer": { "name": "bifrost-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test:summary-fallback", "revision": "reviewed" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "test.summary-fallback.open",
    "activation": [{}],
    "payload": {
      "kind": "procedure_summaries",
      "summaries": [{
        "id": "summary.open",
        "target": {
          "path": "review.go",
          "symbol": "example.com/review.Open(name string)",
          "has_receiver": false,
          "parameter_count": 1
        },
        "completeness": "complete",
        "transfers": [{
          "input": { "kind": "parameter", "ordinal": 0 },
          "exit_kind": "normal",
          "output": { "kind": "normal_return" }
        }],
        "effects": []
      }]
    }
  }]
}"#;

#[test]
fn incomplete_symbol_index_still_reviews_later_go_summary_declarations() {
    let project = InlineTestProject::new()
        .file("go.mod", "module example.com/review\n")
        .file(
            "review.go",
            "package review\n\nfunc Before() {}\nfunc Open(name string) string { return name }\n",
        )
        .file(
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub fn rust_function() {}\n")
        .build();
    let overlay = Arc::new(OverlayProject::new(project.project_dyn()));
    let workspace =
        WorkspaceAnalyzer::build_ephemeral_footgun(overlay.clone(), AnalyzerConfig::default())
            .expect("mixed-language workspace");
    let catalog =
        SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).expect("semantic catalog");
    let pack = compile_source(
        SourceFormat::Json,
        SUMMARY_MODEL.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("summary model must compile: {diagnostics:#?}"));
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "test:summary-fallback".to_owned(),
            },
        )
        .expect("summary model registration");
    let runtime = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: env!("CARGO_PKG_VERSION").parse().expect("crate version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        },
        &CancellationToken::default(),
    );
    assert!(matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. }));

    // A changed package manifest makes only the Rust delegate's persisted
    // declaration identities stale. Go declarations remain available through
    // the full-declaration fallback.
    assert!(overlay.set(
        project.root().join("Cargo.toml"),
        "[package]\nname = \"changed\"\nversion = \"0.1.0\"\n".to_owned(),
    ));
    let analyzer = workspace.analyzer();
    assert!(!analyzer.has_complete_symbol_lookup_index());
    let declarations = analyzer.all_declarations().collect::<Vec<_>>();
    assert!(declarations.len() >= 2, "{declarations:#?}");
    assert_ne!(declarations[0].terminal_name(), "Open");

    let activation = WorkspacePacksActivation {
        ecosystems: Vec::new(),
        workspace_models: Vec::new(),
        outcome: DependencyPackActivationOutcome {
            ecosystems: Vec::new(),
            runtime: Some(runtime),
            diagnostic_refresh_required: true,
        },
    };
    let config = parse_workspace_packs_config(r#"{"schema_version":1,"ecosystems":["go"]}"#)
        .expect("Go pack configuration");
    let input = PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("policies/go.rqlp"),
        r#"(policy
  :schema-version 1
  :id "test.summary-fallback-policy"
  :name "Go summary review"
  :message "Open call"
  :severity warning
  :analysis (analysis :type match
    :selector (rql :schema-version 1
      (language go (function :name "Open")))))"#,
    );
    let outcome = evaluate_policy_inputs_with_analyzer_and_host_activation(
        project.root(),
        &[input],
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &crate::test_support::evaluation_options("2026-07-27"),
        PolicyHostActivationContext::new(Some(&config), Some(&activation), &[], None),
        None,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("policy evaluation");
    let summaries = outcome
        .report()
        .packs()
        .expect("configured pack review")
        .decisions()
        .iter()
        .flat_map(|decision| decision.summary_matches());
    assert!(
        summaries.into_iter().any(|summary| {
            summary.summary_id() == "summary.open" && summary.match_count() == 1
        }),
        "Go summary must remain reachable after the Rust index becomes incomplete: {:#?}",
        outcome.report(),
    );
}
