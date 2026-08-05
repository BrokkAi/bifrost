use std::sync::Arc;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::analyzer::structural::{CodeQuery, execute};
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, ScanUsagesByReferenceParams,
    ScanUsagesIncompleteReason, ScanUsagesStatus, SearchSymbolsParams, SymbolLookupParams,
    get_definitions_by_location, get_symbol_ancestors, get_symbol_locations, get_symbol_sources,
    scan_usages_by_reference, search_symbols,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language, WorkspaceAnalyzer};
use semver::Version;
use serde_json::{Value, json};

use crate::common::{BuiltInlineTestProject, InlineTestProject};

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");
const GENERATOR_RULES_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.json");

fn compiled_declarations() -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        DECLARATIONS_JSON,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

fn compiled_from_value(value: &Value) -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(value).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse("0.8.17").unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_string(),
            ecosystem: "maven".to_string(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_string(),
                version: Some(Version::parse("1.5.0").unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_string(),
                version: Some(Version::parse("17.0.1").unwrap()),
            }),
            target: Some("jvm".to_string()),
            configuration: Some("release".to_string()),
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn generator_activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse("0.8.17").unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_string(),
            ecosystem: "maven".to_string(),
            package: Some(CatalogCoordinate {
                name: "com.acme:builders".to_string(),
                version: Some(Version::parse("1.5.0").unwrap()),
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "acme.builders".to_string(),
                version: None,
                manifest_digest: None,
            },
        }],
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn inline_analyzer() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Main.java", "final class Main {}")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    (project, analyzer)
}

#[test]
fn activated_overlay_flows_through_navigation_and_serialization_without_fake_files() {
    let (_project, analyzer) = inline_analyzer();
    let files_before = analyzer.analyzer().project().all_files().unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_declarations(),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "overlay-fixture".to_string(),
            },
        )
        .unwrap();

    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &activation_request(),
        &CancellationToken::default(),
    ) else {
        panic!("semantic-model acquisition must be ready");
    };
    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("ready activation publishes its overlay");
    assert_eq!(
        overlay.active_model_set_hash(),
        active.active_model_set_hash()
    );
    assert_eq!(
        files_before,
        analyzer.analyzer().project().all_files().unwrap()
    );

    let matched = overlay.symbols_named("com.acme.Widget");
    assert_eq!(matched.disposition, SemanticModelOverlayDisposition::Unique);
    let uri = match &matched.records[0].location {
        SemanticModelLocation::Model(location) => location.uri.clone(),
        SemanticModelLocation::Authored(anchor) => {
            panic!("classfile locator must not invent source at {anchor:?}")
        }
    };
    assert!(uri.starts_with("bifrost-model://v1/"));
    assert!(
        !uri.contains(
            analyzer
                .analyzer()
                .project()
                .root()
                .to_string_lossy()
                .as_ref()
        )
    );

    let search = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec!["Widget".to_string()],
            include_tests: false,
            limit: 10,
        },
    );
    assert_eq!(search.total_model_symbols, 2);
    assert!(
        search
            .model_symbols
            .iter()
            .any(|symbol| symbol.qualified_name == "com.acme.Widget")
    );
    let serialized = serde_json::to_value(&search).unwrap();
    assert_eq!(
        serialized["model_symbols"][0]["provenance"]["pack_id"],
        "acme.widget"
    );

    let locations = get_symbol_locations(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec![uri.clone()],
        },
    );
    assert_eq!(locations.model_locations.len(), 1);
    assert!(locations.not_found.is_empty());

    let sources = get_symbol_sources(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec![uri.clone()],
        },
    );
    assert_eq!(sources.sources.len(), 1);
    assert_eq!(
        sources.sources[0].presentation.as_deref(),
        Some("semantic_model")
    );
    assert!(sources.sources[0].text.contains("not authored source"));
    assert!(sources.sources[0].semantic_model.is_some());

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: uri,
                line: None,
                column: None,
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    let provenance = definitions.results[0].definitions[0]
        .semantic_model
        .as_ref()
        .expect("model definition preserves provenance");
    assert_eq!(provenance.producer, "artifact-scanner");
    assert_eq!(provenance.proof, SemanticModelProof::PackFact);

    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["com.acme.Widget".to_string()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(usages.results[0].status, ScanUsagesStatus::Found);
    assert_eq!(usages.results[0].model_relations.len(), 1);
    assert!(usages.results[0].files.is_empty());

    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "com.acme.Widget" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
    }))
    .unwrap();
    let query_result = serde_json::to_value(execute(analyzer.analyzer(), &query)).unwrap();
    assert_eq!(
        query_result["results"][0]["fq_name"],
        "com.acme.Widget.create"
    );
    assert!(
        query_result["results"][0]["path"]
            .as_str()
            .unwrap()
            .starts_with("bifrost-model://v1/")
    );
    assert_eq!(
        query_result["results"][0]["semantic_model"]["pack_id"],
        "acme.widget"
    );
}

#[test]
fn go_overlay_derives_cross_pack_promotion_and_interface_satisfaction() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("main.go", "package main\n")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = |pack_id: &str, types: Value, members: Value| {
        compiled_from_value(&json!({
            "schema_version": 1,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": { "name": "go-fixture", "version": "1.0.0" },
            "language": "go",
            "ecosystem": "go-module",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "fixture" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "go",
                "activation": [{ "module": { "name": "fixture.invalid" } }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": types,
                    "members": members,
                    "relations": []
                }
            }]
        }))
    };
    let reader_pack = pack(
        "fixture.go.reader",
        json!([{
            "id": "type.go.reader",
            "name": "io.Reader",
            "type_kind": "interface",
            "visibility": "public",
            "locator": { "kind": "artifact", "path": "io/io.go", "symbol": "io.Reader" }
        }]),
        json!([{
            "id": "member.go.reader.read",
            "owner": "type.go.reader",
            "name": "Read",
            "member_kind": "method",
            "visibility": "public",
            "signature": { "parameters": [] },
            "locator": { "kind": "artifact", "path": "io/io.go", "symbol": "io.Reader.Read" }
        }]),
    );
    let consumer_pack = pack(
        "fixture.go.consumer",
        json!([{
            "id": "type.go.embedded",
            "name": "example.com/mod.Embedded",
            "type_kind": "struct",
            "visibility": "public",
            "embedded_types": [{
                "target": { "kind": "named", "name": "io.Reader" },
                "pointer": false
            }],
            "locator": { "kind": "artifact", "path": "mod/api.go", "symbol": "example.com/mod.Embedded" }
        }, {
            "id": "type.go.concrete",
            "name": "example.com/mod.Concrete",
            "type_kind": "struct",
            "visibility": "public",
            "locator": { "kind": "artifact", "path": "mod/api.go", "symbol": "example.com/mod.Concrete" }
        }]),
        json!([{
            "id": "member.go.concrete.read",
            "owner": "type.go.concrete",
            "name": "Read",
            "member_kind": "method",
            "visibility": "public",
            "signature": { "parameters": [] },
            "receiver": { "pointer": false },
            "locator": { "kind": "artifact", "path": "mod/api.go", "symbol": "example.com/mod.Concrete.Read" }
        }]),
    );
    for (compiled, source_id) in [(&reader_pack, "reader"), (&consumer_pack, "consumer")] {
        catalog
            .register_session_pack(
                compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: source_id.to_owned(),
                },
            )
            .unwrap();
    }
    let request = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go-module".to_owned(),
            package: None,
            module: Some(CatalogCoordinate {
                name: "fixture.invalid".to_owned(),
                version: None,
            }),
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: ["fixture.go.reader", "fixture.go.consumer"]
            .into_iter()
            .map(|pack_id| SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: pack_id.to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            })
            .collect(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("cross-pack Go fixture must activate");
    };
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    assert_eq!(
        overlay
            .symbols_named("example.com/mod.Embedded.Read")
            .disposition,
        SemanticModelOverlayDisposition::Unique
    );
    let hierarchy = get_symbol_ancestors(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["example.com/mod.Concrete".to_owned()],
        },
    );
    assert_eq!(hierarchy.ancestors[0].ancestors, ["io.Reader"]);
}

#[test]
fn catalog_source_removal_replaces_the_overlay_on_the_same_snapshot() {
    let (_project, analyzer) = inline_analyzer();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let source = DurablePackSource {
        kind: DurablePackSourceKind::Installed,
        source_id: "installed-fixture".to_string(),
    };
    catalog.install(&compiled_declarations(), &source).unwrap();
    let request = activation_request();

    let SemanticModelRuntimeOutcome::Ready {
        active: installed,
        lifecycle: installed_lifecycle,
    } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    )
    else {
        panic!("installed pack must activate");
    };
    assert_eq!(installed_lifecycle, SemanticModelRuntimeLifecycle::Built);
    assert_eq!(
        analyzer
            .analyzer()
            .semantic_model_overlay()
            .unwrap()
            .symbols_named("com.acme.Widget")
            .disposition,
        SemanticModelOverlayDisposition::Unique
    );

    assert!(catalog.remove_source(&source).unwrap());
    let SemanticModelRuntimeOutcome::Ready {
        active: removed,
        lifecycle: removed_lifecycle,
    } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    )
    else {
        panic!("empty active set after removal is still a complete result");
    };
    assert_eq!(removed_lifecycle, SemanticModelRuntimeLifecycle::Built);
    assert!(!Arc::ptr_eq(&installed, &removed));
    assert_ne!(
        installed.active_model_set_hash(),
        removed.active_model_set_hash()
    );
    assert_eq!(
        analyzer
            .analyzer()
            .semantic_model_overlay()
            .unwrap()
            .symbols_named("com.acme.Widget")
            .disposition,
        SemanticModelOverlayDisposition::Empty
    );
}

#[test]
fn equivalent_pack_source_replacement_refreshes_overlay_provenance() {
    let (_project, analyzer) = inline_analyzer();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let first_source = DurablePackSource {
        kind: DurablePackSourceKind::Installed,
        source_id: "first-source".to_string(),
    };
    let second_source = DurablePackSource {
        kind: DurablePackSourceKind::Installed,
        source_id: "second-source".to_string(),
    };
    let compiled = compiled_declarations();
    catalog.install(&compiled, &first_source).unwrap();
    let SemanticModelRuntimeOutcome::Ready { active: first, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &activation_request(),
        &CancellationToken::default(),
    ) else {
        panic!("first source must activate");
    };
    let first_overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    assert_eq!(
        first_overlay.symbols_with_id("type.widget").records[0]
            .provenance
            .activation
            .source_id,
        "first-source"
    );

    catalog.install(&compiled, &second_source).unwrap();
    assert!(catalog.remove_source(&first_source).unwrap());
    let SemanticModelRuntimeOutcome::Ready { active: second, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &activation_request(),
        &CancellationToken::default(),
    ) else {
        panic!("replacement source must activate");
    };
    let second_overlay = analyzer.analyzer().semantic_model_overlay().unwrap();

    assert_eq!(
        first.active_model_set_hash(),
        second.active_model_set_hash(),
        "equivalent semantic bytes intentionally keep the semantic active-set identity"
    );
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first_overlay, &second_overlay));
    assert_eq!(
        second_overlay.symbols_with_id("type.widget").records[0]
            .provenance
            .activation
            .source_id,
        "second-source"
    );
}

#[test]
fn exact_source_locator_uses_an_authored_anchor_and_keeps_model_provenance() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/com/acme/Widget.java",
            "package com.acme;\npublic class Widget {}\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut source: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    source["shards"][0]["payload"]["types"][0]["locator"] = json!({
        "kind": "source",
        "path": "src/com/acme/Widget.java",
        "symbol": "com.acme.Widget"
    });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::EphemeralWorkspace,
                source_id: "authored-anchor".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let matched = overlay.symbols_with_id("type.widget");
    assert_eq!(matched.disposition, SemanticModelOverlayDisposition::Unique);
    let SemanticModelLocation::Authored(anchor) = &matched.records[0].location else {
        panic!("exact source locator must resolve to authored source");
    };
    assert_eq!(anchor.path, "src/com/acme/Widget.java");
    assert_eq!(anchor.symbol, "com.acme.Widget");
    assert_eq!(
        matched.records[0].provenance.proof,
        SemanticModelProof::PackFact
    );
    assert_eq!(
        matched.records[0].provenance.origin,
        SemanticModelOriginKind::DeclarativeModel
    );
    assert_eq!(
        matched.records[0]
            .provenance
            .activation
            .matched_evidence
            .package
            .as_ref()
            .unwrap()
            .name,
        "com.acme:widget"
    );

    let search = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec!["Widget".to_string()],
            include_tests: false,
            limit: 10,
        },
    );
    assert!(
        search
            .model_symbols
            .iter()
            .all(|symbol| symbol.qualified_name != "com.acme.Widget")
    );
    let source_hit = search
        .files
        .iter()
        .flat_map(|file| &file.classes)
        .find(|hit| hit.semantic_model.is_some())
        .expect("authored declaration must win search precedence");
    assert_eq!(
        source_hit.semantic_model.as_ref().unwrap().proof,
        SemanticModelProof::PackFact
    );
}

#[test]
fn source_locator_outside_the_workspace_preserves_the_authored_anchor() {
    let (_project, analyzer) = inline_analyzer();
    let mut source: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    source["shards"][0]["payload"]["types"][0]["locator"] = json!({
        "kind": "source",
        "path": "dependency/com/acme/Widget.java",
        "symbol": "com.acme.Widget"
    });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "external-source-locator".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let matched = overlay.symbols_with_id("type.widget");
    let SemanticModelLocation::Authored(anchor) = &matched.records[0].location else {
        panic!("an external source locator must remain an authored anchor");
    };
    assert_eq!(anchor.path, "dependency/com/acme/Widget.java");
    assert_eq!(anchor.symbol, "com.acme.Widget");
    assert_eq!(anchor.range.start_line, 0);
    assert_eq!(anchor.range.end_line, 0);
}

#[test]
fn scala_explicit_import_selects_the_qualified_model_declaration() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/Main.scala",
            "import scala.collection.immutable.List\nobject Main { val values: List[Int] = List(1) }",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut source: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    source["pack_id"] = json!("scala-library");
    source["language"] = json!("scala");
    source["shards"][0]["payload"]["types"][0]["name"] = json!("scala.collection.immutable.List");
    source["shards"][0]["payload"]["types"][0]["locator"]["symbol"] =
        json!("scala.collection.immutable.List");
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "scala-explicit-import".to_string(),
            },
        )
        .unwrap();
    let mut request = activation_request();
    request.evidence[0].language = "scala".to_string();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &request,
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: "src/Main.scala".to_string(),
                line: Some(2),
                column: Some(27),
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    assert_eq!(definitions.results[0].definitions.len(), 1);
    assert_eq!(
        definitions.results[0].definitions[0].fqn.as_deref(),
        Some("scala.collection.immutable.List")
    );
    let hierarchy = get_symbol_ancestors(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["scala.collection.immutable.List".to_string()],
        },
    );
    assert!(hierarchy.not_found.is_empty());
    assert_eq!(
        hierarchy.ancestors[0].symbol,
        "scala.collection.immutable.List"
    );
}

#[test]
fn java_explicit_import_selects_the_qualified_model_declaration() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Main.java",
            "import com.acme.Widget;\nfinal class Main { Widget value; }",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_declarations(),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "java-explicit-import".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: "src/Main.java".to_string(),
                line: Some(2),
                column: Some(20),
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    assert_eq!(definitions.results[0].definitions.len(), 1);
    assert_eq!(
        definitions.results[0].definitions[0].fqn.as_deref(),
        Some("com.acme.Widget")
    );
}

#[test]
fn external_import_navigation_requires_compatible_active_model_evidence() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Main.java",
            "import com.acme.Widget;\nfinal class Main { Widget value; }",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let lookup = || {
        get_definitions_by_location(
            analyzer.analyzer(),
            GetDefinitionParams {
                references: vec![DefinitionReferenceQuery {
                    path: "src/Main.java".to_string(),
                    line: Some(2),
                    column: Some(20),
                }],
            },
        )
    };
    assert!(lookup().results[0].definitions.is_empty());

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_declarations(),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "incompatible-evidence".to_string(),
            },
        )
        .unwrap();
    let mut request = activation_request();
    request.evidence[0].package.as_mut().unwrap().version = Some(Version::parse("9.9.0").unwrap());
    request.evidence[0].artifact_sha256 = Some("0".repeat(64));
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("incompatible evidence must produce a safe ready-but-empty activation");
    };
    assert!(active.shards().is_empty());
    assert!(lookup().results[0].definitions.is_empty());
}

#[test]
fn equal_rank_model_conflicts_are_visible_but_never_selected() {
    let (_project, analyzer) = inline_analyzer();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let first = compiled_declarations();
    let mut alternate: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    alternate["pack_id"] = Value::String("acme.widget.alternate".to_string());
    alternate["shards"][0]["payload"]["types"][0]["name"] =
        Value::String("com.acme.AlternateWidget".to_string());
    for (pack, source_id) in [
        (first, "first"),
        (compiled_from_value(&alternate), "alternate"),
    ] {
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: source_id.to_string(),
                },
            )
            .unwrap();
    }
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let matched = overlay.symbols_with_id("type.widget");
    assert_eq!(
        matched.disposition,
        SemanticModelOverlayDisposition::Conflict
    );
    assert_eq!(matched.records.len(), 2);
    assert!(
        matched
            .records
            .iter()
            .all(|symbol| symbol.provenance.ambiguous)
    );
    let uri = matched.records[0].location.identity().to_string();
    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: uri,
                line: None,
                column: None,
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "ambiguous");
    assert!(definitions.results[0].definitions.is_empty());
    assert_eq!(
        definitions.results[0].diagnostics[0].kind,
        "semantic_model_conflict"
    );
}

#[test]
fn conflicting_model_relations_make_usage_ambiguous() {
    let (_project, analyzer) = inline_analyzer();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let first = compiled_declarations();
    let mut alternate: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    alternate["pack_id"] = Value::String("acme.widget.alternate".to_string());
    alternate["shards"][0]["payload"]["relations"][0]["relation_kind"] =
        Value::String("references".to_string());
    for (pack, source_id) in [
        (first, "navigation-relation"),
        (compiled_from_value(&alternate), "reference-relation"),
    ] {
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: source_id.to_string(),
                },
            )
            .unwrap();
    }
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    assert_eq!(
        overlay.symbols_with_id("type.widget").disposition,
        SemanticModelOverlayDisposition::Unique
    );
    assert_eq!(
        overlay.relations_to("type.widget").disposition,
        SemanticModelOverlayDisposition::Conflict
    );
    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["com.acme.Widget".to_string()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(usages.results[0].status, ScanUsagesStatus::Ambiguous);
    assert!(usages.results[0].model_relations.is_empty());
}

#[test]
fn modeled_usage_relations_fit_the_public_response_budget() {
    let (_project, analyzer) = inline_analyzer();
    let mut source: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    source["shards"][0]["payload"]["relations"] = Value::Array(
        (0..200)
            .map(|index| {
                json!({
                    "id": format!("relation.widget.reference.{index:03}"),
                    "relation_kind": "references",
                    "from": "member.widget.create",
                    "to": "type.widget"
                })
            })
            .collect(),
    );
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "large-relation-set".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["com.acme.Widget".to_string()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    let entry = &usages.results[0];
    assert!(entry.model_relations_omitted > 0);
    assert!(!entry.complete);
    assert_eq!(
        entry.incomplete_reason,
        Some(ScanUsagesIncompleteReason::ResponseBudget)
    );
    assert!(serde_json::to_vec(&usages).unwrap().len() <= 8 * 1024);
}

#[test]
fn code_query_model_hierarchy_honors_depth_transitive_and_cycles() {
    let (_project, analyzer) = inline_analyzer();
    let mut source: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    let template = source["shards"][0]["payload"]["types"][0].clone();
    let modeled_type = |id: &str, name: &str, parent: Option<&str>| {
        let mut value = template.clone();
        value["id"] = Value::String(id.to_string());
        value["name"] = Value::String(name.to_string());
        value["aliases"] = json!([]);
        value["extension_surfaces"] = json!([]);
        value["hierarchy"] = parent.map_or_else(
            || json!([]),
            |parent| {
                json!([{
                    "hierarchy_kind": "extends",
                    "target": { "kind": "named", "name": parent }
                }])
            },
        );
        value
    };
    source["shards"][0]["payload"]["types"] = Value::Array(vec![
        modeled_type("type.base", "com.acme.Base", Some("com.acme.Leaf")),
        modeled_type("type.mid", "com.acme.Mid", Some("com.acme.Base")),
        modeled_type("type.leaf", "com.acme.Leaf", Some("com.acme.Mid")),
    ]);
    source["shards"][0]["payload"]["members"] = json!([]);
    source["shards"][0]["payload"]["relations"] = json!([]);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "hierarchy-cycle".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let names_for = |hierarchy_step: Value| {
        let query = CodeQuery::from_json(&json!({
            "match": { "kind": "class", "name": "com.acme.Leaf" },
            "steps": [{ "op": "enclosing_decl" }, hierarchy_step]
        }))
        .unwrap();
        let value = serde_json::to_value(execute(analyzer.analyzer(), &query)).unwrap();
        let mut names = value["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|result| result["fq_name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    assert_eq!(
        names_for(json!({ "op": "supertypes" })),
        vec!["com.acme.Mid"]
    );
    assert_eq!(
        names_for(json!({ "op": "supertypes", "depth": 2 })),
        vec!["com.acme.Base", "com.acme.Mid"]
    );
    assert_eq!(
        names_for(json!({ "op": "supertypes", "transitive": true })),
        vec!["com.acme.Base", "com.acme.Mid"],
        "the cycle back to Leaf must terminate without repeating the root"
    );
}

#[test]
fn durable_mutation_from_another_catalog_connection_invalidates_the_overlay() {
    let (_project, analyzer) = inline_analyzer();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let request = activation_request();
    let SemanticModelRuntimeOutcome::Ready {
        active: empty,
        lifecycle: empty_lifecycle,
    } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    )
    else {
        panic!("empty catalog is a complete active set");
    };
    assert_eq!(empty_lifecycle, SemanticModelRuntimeLifecycle::Built);

    let second = SemanticPackCatalog::open(
        catalog.root(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    second
        .install(
            &compiled_declarations(),
            &DurablePackSource {
                kind: DurablePackSourceKind::Installed,
                source_id: "other-connection".to_string(),
            },
        )
        .unwrap();

    let SemanticModelRuntimeOutcome::Ready {
        active: installed,
        lifecycle: installed_lifecycle,
    } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    )
    else {
        panic!("the first catalog connection must observe the installed pack");
    };
    assert_eq!(installed_lifecycle, SemanticModelRuntimeLifecycle::Built);
    assert!(!Arc::ptr_eq(&empty, &installed));
    assert_eq!(
        analyzer
            .analyzer()
            .semantic_model_overlay()
            .unwrap()
            .symbols_with_id("type.widget")
            .disposition,
        SemanticModelOverlayDisposition::Unique
    );
}

#[test]
fn active_generator_rule_emits_a_typed_model_declaration_with_rule_provenance() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Order.java",
            "package app;\n@interface GenerateBuilder {}\n@GenerateBuilder class LocalOnly {}\n@com.acme.GenerateBuilder\nclass Order {}\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut source: Value = serde_json::from_slice(GENERATOR_RULES_JSON).unwrap();
    source["shards"][0]["payload"]["rules"][0]["emissions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "kind": "relation",
            "id": {
                "op": "concat",
                "values": [
                    { "op": "capture", "name": "owner_id" },
                    { "op": "literal", "value": ".builder.navigation" }
                ]
            },
            "relation_kind": "navigates_to",
            "from": {
                "op": "concat",
                "values": [
                    { "op": "capture", "name": "owner_id" },
                    { "op": "literal", "value": ".builder" }
                ]
            },
            "to": { "op": "capture", "name": "owner_id" }
        }));
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "generator-fixture".to_string(),
            },
        )
        .unwrap();

    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &generator_activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let generated = overlay.symbols_with_id("app.Order.builder");
    assert_eq!(
        generated.disposition,
        SemanticModelOverlayDisposition::Unique
    );
    assert_eq!(generated.records[0].qualified_name, "app.Order.Order");
    assert_eq!(
        generated.records[0].provenance.rule_id.as_deref(),
        Some("rule.builder")
    );
    assert!(matches!(
        generated.records[0].location,
        SemanticModelLocation::Model(_)
    ));
    assert_eq!(
        overlay.symbols_with_id("app.LocalOnly.builder").disposition,
        SemanticModelOverlayDisposition::Empty,
        "a fully qualified annotation trigger must reject an unqualified lookalike"
    );

    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: generated.records[0].location.identity().to_string(),
                line: None,
                column: None,
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    assert_eq!(
        definitions.results[0].definitions[0].fqn.as_deref(),
        Some("app.Order")
    );
    assert_eq!(
        definitions.results[0].definitions[0].path,
        "src/app/Order.java"
    );
    assert_eq!(
        definitions.results[0].definitions[0]
            .semantic_model
            .as_ref()
            .and_then(|provenance| provenance.rule_id.as_deref()),
        Some("rule.builder")
    );
}

#[test]
fn repeated_argument_captures_emit_ordered_declarations_with_authored_anchors() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/app/Order.java",
            "package app; class Order { void make() { build(first, second); } }",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut source: Value = serde_json::from_slice(GENERATOR_RULES_JSON).unwrap();
    let rule = &mut source["shards"][0]["payload"]["rules"][0];
    rule["trigger"] = json!({ "kind": "language_construct", "construct": "call" });
    rule["captures"] = json!([
      {
        "name": "owner_id",
        "binding": {
          "source": { "kind": "enclosing_declaration" },
          "projection": "stable_id"
        },
        "value_kind": "stable_id",
        "cardinality": "one"
      },
      {
        "name": "argument",
        "binding": {
          "source": { "kind": "arguments", "from": 0 },
          "projection": "stable_id"
        },
        "value_kind": "stable_id",
        "cardinality": "many"
      }
    ]);
    rule["emissions"] = json!([{
      "kind": "declaration",
      "id": { "op": "capture", "name": "argument" },
      "name": { "op": "literal", "value": "generated" },
      "anchor": { "op": "capture", "name": "argument" },
      "declaration": {
        "kind": "member",
        "owner": { "op": "capture", "name": "owner_id" },
        "member_kind": "method",
        "visibility": "public"
      }
    }]);

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "repeated-generator-fixture".to_owned(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &generator_activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));

    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let first = overlay.symbols_with_id("app.Order.make.first");
    let second = overlay.symbols_with_id("app.Order.make.second");
    assert_eq!(first.disposition, SemanticModelOverlayDisposition::Unique);
    assert_eq!(second.disposition, SemanticModelOverlayDisposition::Unique);
    let SemanticModelLocation::Authored(first_anchor) = &first.records[0].location else {
        panic!("the first repeated declaration needs an authored anchor");
    };
    let SemanticModelLocation::Authored(second_anchor) = &second.records[0].location else {
        panic!("the second repeated declaration needs an authored anchor");
    };
    assert_eq!(first_anchor.path, "src/app/Order.java");
    assert_eq!(first_anchor.symbol, "app.Order.make.first");
    assert!(first_anchor.range.start_byte < second_anchor.range.start_byte);
    assert_eq!(
        first.records[0].provenance.rule_id.as_deref(),
        Some("rule.builder")
    );
    assert_eq!(
        second.records[0].provenance.rule_id.as_deref(),
        Some("rule.builder")
    );
}

#[test]
fn unqualified_model_name_is_indexed_once() {
    let (_project, analyzer) = inline_analyzer();
    let mut source: Value = serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    source["shards"][0]["payload"]["types"][0]["name"] = Value::String("Widget".to_string());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_from_value(&source),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "unqualified-name".to_string(),
            },
        )
        .unwrap();
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer.analyzer(),
            &catalog,
            None,
            &activation_request(),
            &CancellationToken::default(),
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));
    let overlay = analyzer.analyzer().semantic_model_overlay().unwrap();
    let matched = overlay.symbols_named("Widget");
    assert_eq!(matched.disposition, SemanticModelOverlayDisposition::Unique);
    assert_eq!(matched.records.len(), 1);
}
