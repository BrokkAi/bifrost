use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogOpenMode, CatalogOptions, CompilerOptions, DurablePackSource, DurablePackSourceKind,
    SemanticPackCatalog, SourceFormat, compile_source,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/semantic-model-packs")
        .join(name)
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bifrost-semantic-pack"))
        .args(arguments)
        .output()
        .unwrap()
}

fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error_value| {
        panic!(
            "invalid JSON output: {error_value}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn validate_lint_compile_and_workspace_check_have_stable_json_and_status() {
    let source = fixture("generator-rules-v1.yaml");
    let source_text = source.to_str().unwrap();
    let validate = run(&["validate", source_text, "--format", "json"]);
    assert!(validate.status.success(), "{validate:#?}");
    assert_eq!(
        json_output(&validate)["format"],
        "bifrost_semantic_model_validate/v1"
    );

    let lint = run(&["lint", source_text, "--format", "json"]);
    assert!(lint.status.success(), "{lint:#?}");
    assert_eq!(
        json_output(&lint)["format"],
        "bifrost_semantic_model_lint/v1"
    );

    let temporary = TempDir::new().unwrap();
    let output = temporary.path().join("compiled");
    let compile = run(&[
        "compile",
        source_text,
        output.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(compile.status.success(), "{compile:#?}");
    assert_eq!(
        json_output(&compile)["format"],
        "bifrost_semantic_model_write/v1"
    );
    let repeated = run(&[
        "compile",
        source_text,
        output.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(repeated.status.success(), "{repeated:#?}");

    let workspace_rules = temporary.path().join(".bifrost/semantic-models");
    fs::create_dir_all(&workspace_rules).unwrap();
    fs::copy(&source, workspace_rules.join("builders.yaml")).unwrap();
    let workspace = run(&[
        "workspace-check",
        temporary.path().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(workspace.status.success(), "{workspace:#?}");
    let workspace = json_output(&workspace);
    assert_eq!(workspace["format"], "bifrost_semantic_model_workspace/v1");
    assert_eq!(workspace["enabled"], true);
    assert_eq!(
        workspace["files"][0]["path"],
        ".bifrost/semantic-models/builders.yaml"
    );
}

#[test]
fn invalid_source_and_arguments_return_versioned_nonzero_results() {
    let temporary = TempDir::new().unwrap();
    let invalid = temporary.path().join("invalid.json");
    fs::write(&invalid, b"{}").unwrap();
    let validate = run(&["validate", invalid.to_str().unwrap(), "--format", "json"]);
    assert_eq!(validate.status.code(), Some(1));
    assert_eq!(
        json_output(&validate)["format"],
        "bifrost_semantic_model_validate/v1"
    );

    let arguments = run(&["validate", "--format", "json"]);
    assert_eq!(arguments.status.code(), Some(2));
    assert_eq!(
        json_output(&arguments)["format"],
        "bifrost_semantic_model_cli_error/v1"
    );
}

#[test]
fn list_reports_installed_and_evidence_backed_active_packs() {
    let temporary = TempDir::new().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let catalog = SemanticPackCatalog::open(
        &catalog_root,
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let source = fs::read(fixture("declarations-v1.json")).unwrap();
    let compiled =
        compile_source(SourceFormat::Json, &source, &CompilerOptions::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::Installed,
                source_id: "cli-test".to_owned(),
            },
        )
        .unwrap();
    drop(catalog);

    let activation = temporary.path().join("activation.json");
    fs::write(
        &activation,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "bifrost_version": "0.8.21",
            "evidence": [{
                "language": "java",
                "ecosystem": "maven",
                "package": {"name": "com.acme:widget", "version": "1.5.0"},
                "toolchain": {"name": "jdk", "version": "17.0.1"},
                "target": "jvm",
                "configuration": "release"
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let output = run(&[
        "list",
        catalog_root.to_str().unwrap(),
        activation.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{output:#?}");
    let report = json_output(&output);
    assert_eq!(report["format"], "bifrost_semantic_model_inventory/v1");
    assert_eq!(report["installed"][0]["pack_id"], "acme.widget");
    assert_eq!(report["active"][0]["pack_id"], "acme.widget");
    assert_eq!(
        report["active"][0]["matched_evidence"]["package"]["name"],
        "com.acme:widget"
    );
}
