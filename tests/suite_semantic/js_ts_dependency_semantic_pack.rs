use brokk_bifrost::analyzer::semantic_model::{
    DependencyArtifactRole, DependencyPackLimits, ExternalArtifactKind,
};
use brokk_bifrost::analyzer::{
    FilesystemProject, JsTsDependencyDiscoveryConfig, resolve_js_ts_semantic_pack_dependencies,
};
use brokk_bifrost::{Language, Project};

use crate::common::InlineTestProject;

#[test]
fn package_lock_selects_exact_types_exports_scopes_and_at_types_without_workspace_files() {
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file(".gitignore", "node_modules/\n")
        .file("src/main.ts", "import { Root } from 'widget';\n")
        .file(
            "package-lock.json",
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/widget": { "version": "2.1.0", "integrity": "sha512-widget" },
                "node_modules/@scope/pkg": { "version": "3.0.0" },
                "node_modules/@types/node": { "version": "22.0.0" }
              }
            }"#,
        )
        .file(
            "node_modules/widget/package.json",
            r#"{
              "name": "widget", "version": "2.1.0", "types": "./dist/index.d.ts",
              "exports": { ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" }, "./extra": { "types": "./dist/extra.d.ts" } }
            }"#,
        )
        .file("node_modules/widget/dist/index.d.ts", "export interface Root {}\n")
        .file("node_modules/widget/dist/extra.d.ts", "export interface Extra {}\n")
        .file(
            "node_modules/@scope/pkg/package.json",
            r#"{ "name": "@scope/pkg", "version": "3.0.0", "typings": "index.d.ts" }"#,
        )
        .file("node_modules/@scope/pkg/index.d.ts", "export class Scoped {}\n")
        .file(
            "node_modules/@types/node/package.json",
            r#"{ "name": "@types/node", "version": "22.0.0" }"#,
        )
        .file("node_modules/@types/node/index.d.ts", "declare namespace NodeJS {}\n")
        .build();
    let project = FilesystemProject::new(fixture.root()).unwrap();
    let files_before = project.all_files().unwrap();

    let outcome = resolve_js_ts_semantic_pack_dependencies(
        &JsTsDependencyDiscoveryConfig::default(),
        &project,
        &DependencyPackLimits::default(),
        None,
    );

    assert!(outcome.complete, "{:#?}", outcome.diagnostics);
    assert_eq!(outcome.dependencies.len(), 4);
    let modules: Vec<_> = outcome
        .dependencies
        .iter()
        .map(|dependency| dependency.evidence.module.as_ref().unwrap().name.as_str())
        .collect();
    assert_eq!(modules, ["@scope/pkg", "node", "widget", "widget/extra"]);
    for dependency in &outcome.dependencies {
        assert_eq!(dependency.artifacts.len(), 2);
        assert_eq!(
            dependency.artifacts[0].role,
            DependencyArtifactRole::Metadata
        );
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::NpmPackageManifest
        );
        assert_eq!(
            dependency.artifacts[1].role,
            DependencyArtifactRole::Declarations
        );
        assert_eq!(
            dependency.artifacts[1].kind,
            ExternalArtifactKind::TypeScriptDeclarationFile
        );
    }
    assert_eq!(project.all_files().unwrap(), files_before);
    assert!(
        files_before
            .iter()
            .all(|file| !file.rel_path().starts_with("node_modules"))
    );
}

#[test]
fn mismatched_missing_and_ambiguous_declarations_are_incomplete_not_targets() {
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file(".gitignore", "node_modules/\n")
        .file("src/main.ts", "export {};\n")
        .file(
            "package-lock.json",
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "node_modules/wrong": { "version": "1.0.0" },
                "node_modules/escaped": { "version": "1.0.0" },
                "node_modules/wild": { "version": "1.0.0" }
              }
            }"#,
        )
        .file(
            "node_modules/wrong/package.json",
            r#"{ "name": "wrong", "version": "2.0.0", "types": "index.d.ts" }"#,
        )
        .file("node_modules/wrong/index.d.ts", "export interface Wrong {}\n")
        .file(
            "node_modules/escaped/package.json",
            r#"{ "name": "escaped", "version": "1.0.0", "types": "../outside.d.ts" }"#,
        )
        .file("node_modules/outside.d.ts", "export interface Outside {}\n")
        .file(
            "node_modules/wild/package.json",
            r#"{ "name": "wild", "version": "1.0.0", "exports": { "./*": { "types": "./types/*.d.ts" } } }"#,
        )
        .file("node_modules/wild/types/a.d.ts", "export interface Wild {}\n")
        .build();

    let outcome = resolve_js_ts_semantic_pack_dependencies(
        &JsTsDependencyDiscoveryConfig::default(),
        fixture.project(),
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!outcome.complete);
    assert!(
        outcome.dependencies.is_empty(),
        "{:#?}",
        outcome.dependencies
    );
    let codes: Vec<_> = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert_eq!(
        codes,
        [
            "npm.declarations.incomplete",
            "npm.declarations.incomplete",
            "npm.package.version_mismatch"
        ]
    );
}
