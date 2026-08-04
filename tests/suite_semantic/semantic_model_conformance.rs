use std::collections::BTreeMap;

use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use brokk_bifrost_analysis::analyzer::semantic_model::*;
use serde_json::{Value, json};

use crate::common::InlineTestProject;

const GENERATOR_RULES: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.json");
const DECLARATIONS: &[u8] = include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");
const CONFORMANCE: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-authoring-conformance-v1.json");
const DECLARATION_CONFORMANCE: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declaration-authoring-conformance-v1.json");

fn compiled_generator_pack() -> CompiledSemanticModelPack {
    let mut source: Value = serde_json::from_slice(GENERATOR_RULES).unwrap();
    let emissions = source["shards"][0]["payload"]["rules"][0]["emissions"]
        .as_array_mut()
        .unwrap();
    for (suffix, relation_kind) in [("navigation", "navigates_to"), ("reference", "references")] {
        emissions.push(json!({
            "kind": "relation",
            "id": {
                "op": "concat",
                "values": [
                    { "op": "capture", "name": "owner_id" },
                    { "op": "literal", "value": format!(".builder.{suffix}") }
                ]
            },
            "relation_kind": relation_kind,
            "from": {
                "op": "concat",
                "values": [
                    { "op": "capture", "name": "owner_id" },
                    { "op": "literal", "value": ".builder" }
                ]
            },
            "to": { "op": "capture", "name": "owner_id" }
        }));
    }
    compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap()
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:builders".to_owned(),
                version: Some("1.5.0".parse().unwrap()),
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
                pack_id: "acme.builders".to_owned(),
                version: None,
                manifest_digest: None,
            },
        }],
        limits: Default::default(),
    }
}

fn declaration_activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: "0.8.17".parse().unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some("1.5.0".parse().unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some("17.0.1".parse().unwrap()),
            }),
            target: Some("jvm".to_owned()),
            configuration: Some("release".to_owned()),
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: Default::default(),
    }
}

#[test]
fn explain_preview_scan_and_golden_conformance_share_the_production_matcher() {
    let project = InlineTestProject::new()
        .file(
            "src/app/Order.java",
            "package app;\n@interface GenerateBuilder {}\n@GenerateBuilder class LocalOnly {}\n@com.acme.GenerateBuilder\nclass Order {}\n@MissingGenerator class Unmapped {}\nclass UsesMacro { void run() { makeWidget(); } }\n",
        )
        .build();
    assert!(project.languages().contains(&Language::Java));
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_generator_pack(),
            &SessionPackSource {
                kind: SessionPackSourceKind::EphemeralWorkspace,
                source_id: "conformance-workspace".to_owned(),
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
        panic!("generator activation must be ready");
    };

    let positive = explain_semantic_model_site(
        analyzer.analyzer(),
        &active,
        SemanticModelSite {
            path: "src/app/Order.java".to_owned(),
            line: 4,
        },
        Some("rule.builder"),
        &CancellationToken::default(),
        16,
    );
    assert!(positive.complete);
    let matched = positive
        .explanations
        .iter()
        .find(|explanation| explanation.matched)
        .expect("qualified annotation must match");
    assert_eq!(matched.pack_id, "acme.builders");
    assert_eq!(matched.shadowing, "unique");
    assert_eq!(matched.captures["owner_id"], "app.Order");
    assert_eq!(matched.emitted_symbols[0].id, "app.Order.builder");
    assert_eq!(matched.emitted_relations.len(), 2);
    assert!(matched.first_failed_predicate.is_none());

    let negative = explain_semantic_model_site(
        analyzer.analyzer(),
        &active,
        SemanticModelSite {
            path: "src/app/Order.java".to_owned(),
            line: 3,
        },
        Some("rule.builder"),
        &CancellationToken::default(),
        16,
    );
    assert!(!negative.explanations[0].matched);
    assert_eq!(
        negative.explanations[0]
            .first_failed_predicate
            .as_ref()
            .unwrap()
            .code,
        "trigger.mismatch"
    );

    let captures = matched.captures.clone();
    let preview = preview_semantic_model_emissions(&active, "rule.builder", &captures);
    assert!(preview.complete);
    assert_eq!(preview.emitted_symbols, matched.emitted_symbols);
    assert_eq!(preview.emitted_relations, matched.emitted_relations);

    let scan = scan_unmapped_semantic_model_sites(
        analyzer.analyzer(),
        &active,
        &[
            SemanticModelGeneratorSelector {
                language: "java".to_owned(),
                trigger: RuleTrigger::Annotation {
                    name: "MissingGenerator".to_owned(),
                },
                site_kind: SemanticModelGeneratorSiteKind::ModelEligibleGenerator,
            },
            SemanticModelGeneratorSelector {
                language: "java".to_owned(),
                trigger: RuleTrigger::MacroInvocation {
                    name: "makeWidget".to_owned(),
                },
                site_kind: SemanticModelGeneratorSiteKind::InspectableSourceMacro,
            },
        ],
        SemanticModelUnmappedScanLimits::default(),
        &CancellationToken::default(),
    );
    assert!(scan.complete, "{:#?}", scan.diagnostics);
    assert!(scan.sites.iter().any(|site| {
        site.site_kind == SemanticModelGeneratorSiteKind::ModelEligibleGenerator
            && site.path == "src/app/Order.java"
    }));
    assert!(
        scan.sites.iter().any(|site| {
            site.site_kind == SemanticModelGeneratorSiteKind::InspectableSourceMacro
                && site.path == "src/app/Order.java"
        }),
        "{scan:#?}"
    );
    let bounded = scan_unmapped_semantic_model_sites(
        analyzer.analyzer(),
        &active,
        &[SemanticModelGeneratorSelector {
            language: "java".to_owned(),
            trigger: RuleTrigger::Annotation {
                name: "MissingGenerator".to_owned(),
            },
            site_kind: SemanticModelGeneratorSiteKind::ModelEligibleGenerator,
        }],
        SemanticModelUnmappedScanLimits {
            max_files: 1,
            max_nodes: 1,
            max_sites: 1,
        },
        &CancellationToken::default(),
    );
    assert!(!bounded.complete);

    let fixture: SemanticModelConformanceFixture = serde_json::from_slice(CONFORMANCE).unwrap();
    let conformance = run_semantic_model_conformance(
        analyzer.analyzer(),
        &active,
        &fixture,
        &CancellationToken::default(),
        128,
    );
    assert!(conformance.passed, "{:#?}", conformance.failures);
    assert_eq!(conformance.checked_assertions, 7);

    let mut missing = fixture;
    missing.symbols[0].id = "missing.symbol".to_owned();
    let mismatch = run_semantic_model_conformance(
        analyzer.analyzer(),
        &active,
        &missing,
        &CancellationToken::default(),
        128,
    );
    assert!(mismatch.complete);
    assert!(!mismatch.passed);
    assert_eq!(
        mismatch.failures,
        ["missing expected symbol `missing.symbol`"]
    );
}

#[test]
fn emission_preview_rejects_missing_rules_without_guessing() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled_generator_pack(),
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "preview-fixture".to_owned(),
            },
        )
        .unwrap();
    let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
        &catalog,
        &activation_request(),
        &CancellationToken::default(),
    ) else {
        panic!("generator activation must be ready");
    };
    let preview = preview_semantic_model_emissions(&active, "missing.rule", &BTreeMap::new());
    assert!(!preview.complete);
    assert_eq!(preview.shadowing, "absent");
    assert!(preview.emitted_symbols.is_empty());

    let preview = preview_semantic_model_emissions(&active, "rule.builder", &BTreeMap::new());
    assert!(!preview.complete);
    assert_eq!(
        preview.diagnostics,
        ["required captures are missing: [\"owner_id\", \"entity\", \"entity_type\"]"]
    );
    assert!(preview.emitted_symbols.is_empty());
}

#[test]
fn declaration_golden_covers_owners_signatures_hierarchy_and_authored_anchors() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/com/acme/Widget.java",
            "package com.acme;\npublic class Widget {}\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut source: Value = serde_json::from_slice(DECLARATIONS).unwrap();
    source["shards"][0]["payload"]["types"][0]["locator"] = json!({
        "kind": "source",
        "path": "src/com/acme/Widget.java",
        "symbol": "com.acme.Widget"
    });
    let compiled = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_session_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::EphemeralWorkspace,
                source_id: "declaration-conformance-workspace".to_owned(),
            },
        )
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &declaration_activation_request(),
        &CancellationToken::default(),
    ) else {
        panic!("declaration activation must be ready");
    };

    let fixture: SemanticModelConformanceFixture =
        serde_json::from_slice(DECLARATION_CONFORMANCE).unwrap();
    let report = run_semantic_model_conformance(
        analyzer.analyzer(),
        &active,
        &fixture,
        &CancellationToken::default(),
        64,
    );
    assert!(report.passed, "{:#?}", report.failures);
    assert_eq!(report.checked_assertions, 5);
}
