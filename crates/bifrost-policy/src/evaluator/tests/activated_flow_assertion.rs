use super::*;
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
    acquire_active_semantic_models, compile_source,
};
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Project, WorkspaceAnalyzer};
use std::sync::Arc;

const GO_NONRETURN_DECLARATIONS: &str = r#"{
  "schema_version": 2,
  "pack_id": "test.flow.go-os-exit-declarations",
  "version": "1.0.0",
  "producer": { "name": "bifrost-flow-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test:flow-os-exit-declarations", "revision": "reviewed" },
  "license": "Apache-2.0",
  "completeness": "partial",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "go.os.exit.declarations",
    "activation": [{}],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "type.flow-test-go-os-module",
        "name": "os",
        "type_kind": "module",
        "visibility": "package",
        "is_abstract": false,
        "is_sealed": false,
        "has_explicit_type_terms": false,
        "type_parameters": [],
        "type_parameter_constraints": [],
        "embedded_types": [],
        "hierarchy": [],
        "aliases": ["os"],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "os/types.go",
          "symbol": "os"
        }
      }],
      "members": [{
        "id": "member.flow-test-go-os-exit",
        "owner": "type.flow-test-go-os-module",
        "name": "Exit",
        "member_kind": "function",
        "visibility": "public",
        "is_static": true,
        "is_abstract": false,
        "is_virtual": false,
        "signature": {
          "type_parameters": [],
          "parameters": [{
            "name": "code",
            "type": {
              "kind": "named",
              "name": "int",
              "arguments": [],
              "nullable": false
            },
            "optional": false,
            "variadic": false
          }]
        },
        "aliases": [],
        "locator": {
          "kind": "artifact",
          "path": "os/proc.go",
          "symbol": "os.Exit"
        }
      }],
      "relations": []
    }
  }]
}"#;

const GO_NONRETURN_MODEL: &str = r#"{
  "schema_version": 2,
  "pack_id": "test.flow.go-nonreturn",
  "version": "1.0.0",
  "producer": { "name": "bifrost-flow-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test:flow-nonreturn", "revision": "reviewed" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "go.os.exit",
    "activation": [{}],
    "payload": {
      "kind": "procedure_summaries",
      "summaries": [{
        "id": "os.exit",
        "target": {
          "path": "src/os/proc.go",
          "symbol": "os.Exit(code int)",
          "has_receiver": false,
          "parameter_count": 1
        },
        "completeness": "complete",
        "normal_continuation_absent": true,
        "transfers": [],
        "effects": []
      }]
    }
  }]
}"#;

#[test]
fn activated_nonreturn_model_changes_flow_assertion_result() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "main.go")
        .write("package sample\nimport \"os\"\ntype item struct { value int }\nfunc inspect(result *item, err error) int {\n  if err != nil { os.Exit(1) } else { result.value = 1 }\n  return result.value\n}\n")
        .unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Go));
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    for (id, source) in [
        ("test:go-declarations", GO_NONRETURN_DECLARATIONS),
        ("test:go-nonreturn", GO_NONRETURN_MODEL),
    ] {
        let pack = compile_source(
            SourceFormat::Json,
            source.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("{diagnostics:#?}"));
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: id.into(),
                },
            )
            .unwrap();
    }
    let request = SemanticModelActivationRequest {
        approximate_standard_libraries: Vec::new(),
        bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "go".into(),
            ecosystem: "go".into(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let activation = acquire_active_semantic_models(
        workspace.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    );
    let SemanticModelRuntimeOutcome::Ready { snapshot, .. } = activation else {
        panic!("model activation failed: {activation:#?}");
    };
    let registry = policy_registry(
        "test:activated-assertion",
        r#"(policy :id "test.activated-assertion" :name "Activated assertion"
            :message "Read requires establishment" :severity warning
            :analysis (analysis :type assertion
              :subject (rql (field_access :field (name "value") :capture "site"))
              :asserts [(assert-flow-establishment :id established :at "site"
                          :role member_position :require dominated)]))"#,
    );
    let policy = registry.policies().next().unwrap();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let context = PolicyEvaluationContext {
        analyzer: workspace.analyzer(),
        workspace: Some(&workspace),
        flow_state: &flow_state,
        root_memo: None,
        cancellation: None,
        cvss_overlays: &[],
        organizational_risk: &[],
        incremental: None,
        identifier_typos: None,
    };
    let cold = DefaultPolicyEvaluator::new()
        .evaluate(policy, &context, &mut PolicyBudget::default())
        .unwrap();
    let close_match = DefaultPolicyEvaluator::new()
        .with_active_semantic_model_snapshot(Some(crate::test_support::close_match_snapshot()))
        .evaluate(policy, &context, &mut PolicyBudget::default())
        .unwrap();
    let active = DefaultPolicyEvaluator::new()
        .with_active_semantic_model_snapshot(Some(snapshot))
        .evaluate(policy, &context, &mut PolicyBudget::default())
        .unwrap();
    assert_eq!(cold.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(active.completion(), &PolicyRunCompletion::Complete);
    assert_eq!(cold.findings().len(), 1, "{cold:#?}");
    assert_eq!(close_match.findings().len(), cold.findings().len());
    assert_eq!(close_match.findings()[0].id(), cold.findings()[0].id());
    assert_eq!(close_match.completion(), cold.completion());
    assert_eq!(
        close_match.findings()[0]
            .model_attribution()
            .unwrap()
            .contributors[0]
            .role,
        ModelAttributionRole::ReadDependency,
    );
    assert!(active.findings().is_empty(), "{active:#?}");
}
