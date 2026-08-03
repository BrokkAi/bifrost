use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::analyzer::{
    FilesystemProject, JsTsDependencyDiscoveryConfig, JsTsDependencyPackAdapter, WorkspaceAnalyzer,
    resolve_js_ts_semantic_pack_dependencies,
};
use brokk_bifrost::searchtools::{
    ScanUsagesByReferenceParams, ScanUsagesStatus, SearchSymbolsParams, SymbolLookupParams,
    get_symbol_locations, get_symbol_sources, scan_usages_by_reference, search_symbols,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language, Project};
use semver::Version;

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
                "packages/workspace-app": { "name": "workspace-app", "version": "1.0.0" },
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
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let prepared = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &JsTsDependencyPackAdapter,
        outcome,
        &DependencyPackLimits::default(),
        None,
    );
    assert!(!prepared.complete);
    assert!(prepared.packs.is_empty());
    assert!(
        prepared
            .compose_activation_request(empty_activation_request())
            .is_none()
    );
}

#[test]
fn exact_npm_declarations_prepare_activate_navigate_and_reuse_through_shared_overlay() {
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file(".gitignore", "node_modules/\n")
        .file(
            "src/main.ts",
            "import { Widget, create } from 'widget';\nconst value: Widget<string> = create('x');\n",
        )
        .file(
            "package-lock.json",
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/stable": { "version": "1.0.0" },
                "node_modules/widget": { "version": "2.1.0" }
              }
            }"#,
        )
        .file(
            "node_modules/stable/package.json",
            r#"{ "name": "stable", "version": "1.0.0", "types": "index.d.ts" }"#,
        )
        .file(
            "node_modules/stable/index.d.ts",
            "export interface Stable { readonly id: string }\n",
        )
        .file(
            "node_modules/widget/package.json",
            r#"{ "name": "widget", "version": "2.1.0", "types": "index.d.ts" }"#,
        )
        .file(
            "node_modules/widget/index.d.ts",
            r#"export interface Base<T> { value: T }
export interface Widget<T> extends Base<T> { transform(input: T): Promise<T> }
export declare function create<T>(value: T): Widget<T>;
"#,
        )
        .build();
    let project = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let files_before = project.all_files().unwrap();
    assert!(
        files_before
            .iter()
            .all(|file| !file.rel_path().starts_with("node_modules"))
    );
    let analyzer = WorkspaceAnalyzer::build(project.clone(), AnalyzerConfig::default());
    let limits = DependencyPackLimits::default();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

    let discovery = resolve_js_ts_semantic_pack_dependencies(
        &JsTsDependencyDiscoveryConfig::default(),
        project.as_ref(),
        &limits,
        None,
    );
    let prepared = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &JsTsDependencyPackAdapter,
        discovery,
        &limits,
        None,
    );
    assert!(prepared.complete, "{:#?}", prepared.diagnostics);
    assert_eq!(prepared.packs.len(), 2);
    assert!(prepared.packs.iter().all(|pack| {
        pack.status == DependencyPackPreparationStatus::Generated
            && pack.completeness == Completeness::Complete
    }));
    let request = prepared
        .compose_activation_request(empty_activation_request())
        .expect("complete preparation composes exact activation evidence");
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("exact npm packs must activate");
    };
    assert_eq!(active.shards().len(), 2);
    assert_eq!(project.all_files().unwrap(), files_before);

    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("active npm declaration overlay");
    let widget = overlay.symbols_named("widget.Widget");
    assert_eq!(widget.disposition, SemanticModelOverlayDisposition::Unique);
    let widget_locator = match &widget.records[0].location {
        SemanticModelLocation::Authored(location) => location.clone(),
        SemanticModelLocation::Model(location) => {
            panic!("source declaration lost its authored locator {location:?}")
        }
    };
    assert_eq!(widget_locator.path, "widget.d.ts");
    assert!(widget_locator.symbol.starts_with("widget.Widget@"));
    assert!(!widget_locator.path.contains("node_modules"));

    let search = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec!["Widget".to_owned()],
            include_tests: false,
            limit: 10,
        },
    );
    assert!(
        search
            .model_symbols
            .iter()
            .any(|symbol| symbol.qualified_name == "widget.Widget")
    );
    let sources = get_symbol_sources(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["widget.Widget".to_owned()],
        },
    );
    assert!(sources.not_found.is_empty(), "{:#?}", sources.not_found);
    assert_eq!(sources.sources.len(), 1);
    assert!(
        sources.sources[0]
            .text
            .contains("External authored declaration")
    );
    assert!(sources.sources[0].semantic_model.is_some());
    assert!(
        sources.sources[0]
            .text
            .contains("widget.d.ts#widget.Widget@")
    );
    let locations = get_symbol_locations(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["widget.Widget".to_owned()],
        },
    );
    assert!(locations.not_found.is_empty(), "{:#?}", locations.not_found);
    assert_eq!(locations.model_locations.len(), 1);
    let ancestors = overlay.ancestors_of(widget.records[0]);
    assert_eq!(
        ancestors
            .records
            .iter()
            .map(|symbol| symbol.qualified_name.as_str())
            .collect::<Vec<_>>(),
        ["widget.Base"]
    );
    let base_usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["widget.Base".to_owned()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(base_usages.results[0].status, ScanUsagesStatus::Found);
    assert_eq!(base_usages.results[0].model_relations.len(), 1);
    let create = overlay.symbols_named("create");
    assert_eq!(create.disposition, SemanticModelOverlayDisposition::Unique);
    assert_eq!(
        create.records[0].signature.as_deref(),
        Some("create(value: T) -> Widget<T>")
    );

    let mut wrong_version = request.clone();
    for evidence in &mut wrong_version.evidence {
        if evidence
            .package
            .as_ref()
            .is_some_and(|package| package.name == "widget")
        {
            evidence.package.as_mut().unwrap().version = Some(Version::parse("2.2.0").unwrap());
        }
    }
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &wrong_version,
        &CancellationToken::default(),
    ) else {
        panic!("version mismatch produces a ready filtered set");
    };
    assert!(
        active
            .shards()
            .iter()
            .all(|shard| shard.matched_evidence.package.as_ref().unwrap().name != "widget")
    );

    std::fs::write(
        fixture.root().join("node_modules/widget/index.d.ts"),
        "export interface Widget { changed: true }\n",
    )
    .unwrap();
    let changed = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &JsTsDependencyPackAdapter,
        resolve_js_ts_semantic_pack_dependencies(
            &JsTsDependencyDiscoveryConfig::default(),
            project.as_ref(),
            &limits,
            None,
        ),
        &limits,
        None,
    );
    assert!(changed.complete, "{:#?}", changed.diagnostics);
    assert_eq!(
        changed
            .packs
            .iter()
            .map(|pack| (pack.dependency_id.as_str(), pack.status))
            .collect::<Vec<_>>(),
        [
            (
                "npm:stable@1.0.0:stable",
                DependencyPackPreparationStatus::Reused,
            ),
            (
                "npm:widget@2.1.0:widget",
                DependencyPackPreparationStatus::Generated,
            ),
        ]
    );
    assert_eq!(project.all_files().unwrap(), files_before);
}

#[test]
#[ignore = "reproducible npm declaration-pack measurement"]
fn measure_exact_npm_declaration_pack_cold_warm_and_lookup() {
    const TYPE_COUNT: usize = 250;
    let mut declarations = String::new();
    for index in 0..TYPE_COUNT {
        declarations.push_str(&format!(
            "export interface Widget{index}<T> extends Base<T> {{ value: T; transform(input: T): Promise<T>; child: Widget{index}<T>; }}\n"
        ));
    }
    declarations.push_str("export interface Base<T> { value: T }\n");
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file(".gitignore", "node_modules/\n")
        .file("src/main.ts", "import { Widget249 } from 'measured';\n")
        .file(
            "package-lock.json",
            r#"{ "lockfileVersion": 3, "packages": { "node_modules/measured": { "version": "1.0.0" } } }"#,
        )
        .file(
            "node_modules/measured/package.json",
            r#"{ "name": "measured", "version": "1.0.0", "types": "index.d.ts" }"#,
        )
        .file("node_modules/measured/index.d.ts", declarations.clone())
        .build();
    let project = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let analyzer = WorkspaceAnalyzer::build(project.clone(), AnalyzerConfig::default());
    let limits = DependencyPackLimits::default();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

    let cold_started = Instant::now();
    let cold_discovery = resolve_js_ts_semantic_pack_dependencies(
        &JsTsDependencyDiscoveryConfig::default(),
        project.as_ref(),
        &limits,
        None,
    );
    let cold = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &JsTsDependencyPackAdapter,
        cold_discovery,
        &limits,
        None,
    );
    let cold_elapsed = cold_started.elapsed();
    assert!(cold.complete, "{:#?}", cold.diagnostics);
    assert_eq!(cold.profile.generated_packs, 1);

    let warm_started = Instant::now();
    let warm = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &JsTsDependencyPackAdapter,
        resolve_js_ts_semantic_pack_dependencies(
            &JsTsDependencyDiscoveryConfig::default(),
            project.as_ref(),
            &limits,
            None,
        ),
        &limits,
        None,
    );
    let warm_elapsed = warm_started.elapsed();
    assert!(warm.complete, "{:#?}", warm.diagnostics);
    assert_eq!(warm.profile.reused_packs, 1);

    let request = warm
        .compose_activation_request(empty_activation_request())
        .expect("warm complete activation request");
    let activation_started = Instant::now();
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("measured declaration pack must activate");
    };
    let activation_elapsed = activation_started.elapsed();

    let lookup_started = Instant::now();
    let lookup = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec!["Widget249".to_owned()],
            include_tests: false,
            limit: 10,
        },
    );
    let lookup_elapsed = lookup_started.elapsed();
    assert!(
        lookup
            .model_symbols
            .iter()
            .any(|symbol| symbol.qualified_name == "measured.Widget249")
    );
    let accounting = catalog.accounting().unwrap();
    let generated_raw_bytes = active
        .shards()
        .iter()
        .map(|shard| {
            shard
                .manifest
                .shards
                .iter()
                .find(|descriptor| descriptor.shard_id == shard.shard.shard_id())
                .expect("active shard has its compiled descriptor")
                .raw_size
        })
        .sum::<u64>();
    eprintln!(
        "npm declaration measurement: types={TYPE_COUNT}, declaration_bytes={}, artifacts={}, artifact_bytes={}, cold_us={}, warm_us={}, activation_us={}, lookup_us={}, generated_raw_bytes={}, catalog_installed_bytes={}, retained_bytes={}, loaded_records={}",
        declarations.len(),
        cold.profile.artifacts_read,
        cold.profile.artifact_bytes_read,
        cold_elapsed.as_micros(),
        warm_elapsed.as_micros(),
        activation_elapsed.as_micros(),
        lookup_elapsed.as_micros(),
        generated_raw_bytes,
        accounting.installed_stored_bytes,
        active.retained_bytes(),
        active.activation_report().loaded_records,
    );
}

fn empty_activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}
