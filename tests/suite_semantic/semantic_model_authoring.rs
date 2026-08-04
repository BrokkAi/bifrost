use std::fs;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    AuthoredPayload, AuthoredSemanticModelPack, CaptureSource, CatalogCoordinate, CatalogOptions,
    CompilerOptions, DurablePackSource, DurablePackSourceKind, RuleEmission,
    SEMANTIC_MODEL_INVENTORY_FORMAT, SEMANTIC_MODEL_LINT_FORMAT, SEMANTIC_MODEL_VALIDATE_FORMAT,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelResolutionOutcome, SemanticPackCatalog, SourceFormat,
    TemplateExpression, WORKSPACE_SEMANTIC_MODEL_DIRECTORY, WorkspaceSemanticModelOptions,
    compile_source, discover_workspace_semantic_models, lint_semantic_model_pack,
    lint_semantic_model_source, resolve_active_semantic_models, semantic_model_inventory,
    validate_semantic_model_source, write_compiled_semantic_model_pack,
};

const GENERATOR_RULES: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/generator-rules-v1.json");

#[test]
fn validation_and_compile_use_the_canonical_source_pipeline() {
    let options = CompilerOptions::default();
    let report = validate_semantic_model_source(SourceFormat::Json, GENERATOR_RULES, &options);
    assert_eq!(report.format, SEMANTIC_MODEL_VALIDATE_FORMAT);
    assert!(report.valid, "{:#?}", report.diagnostics);
    assert_eq!(report.pack_id.as_deref(), Some("acme.builders"));

    let first = compile_source(SourceFormat::Json, GENERATOR_RULES, &options).unwrap();
    let second = compile_source(SourceFormat::Json, GENERATOR_RULES, &options).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        report.manifest_content_sha256.as_deref(),
        Some(first.manifest.content_sha256.as_str())
    );
}

#[test]
fn lint_reports_broad_ambiguous_unbound_unreachable_and_conflicting_rules() {
    let mut pack: AuthoredSemanticModelPack = serde_json::from_slice(GENERATOR_RULES).unwrap();
    pack.shards[0].activation[0].package = None;
    let AuthoredPayload::GeneratorRules { rules } = &mut pack.shards[0].payload else {
        panic!("fixture must contain generator rules");
    };
    let RuleEmission::Declaration { id, .. } = &mut rules[0].emissions[0] else {
        panic!("fixture rule must emit a declaration");
    };
    *id = TemplateExpression::Literal {
        value: "generated.member".to_owned(),
    };
    let mut duplicate = rules[0].clone();
    duplicate.id = rules[0].id.clone();
    duplicate.captures[0].name = "unused".to_owned();
    duplicate.captures[0].binding.source = CaptureSource::ResolvedOwner;
    let RuleEmission::Declaration { name, .. } = &mut duplicate.emissions[0] else {
        panic!("fixture rule must emit a declaration");
    };
    *name = TemplateExpression::Literal {
        value: "Different".to_owned(),
    };
    rules.push(duplicate);

    let diagnostics = lint_semantic_model_pack(&pack);
    let codes = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert!(
        codes.contains(&"selector.unsafe_wildcard_breadth"),
        "{codes:?}"
    );
    assert!(codes.contains(&"selector.ambiguous"), "{codes:?}");
    assert!(codes.contains(&"capture.unbound"), "{codes:?}");
    assert!(codes.contains(&"rule.unreachable"), "{codes:?}");
    assert!(codes.contains(&"emission.conflict"), "{codes:?}");

    let invalid_source = serde_json::to_vec(&pack).unwrap();
    let invalid_report = lint_semantic_model_source(
        SourceFormat::Json,
        &invalid_source,
        &CompilerOptions::default(),
    );
    assert!(!invalid_report.valid);
    assert!(
        invalid_report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "identifier.duplicate")
    );

    let report = lint_semantic_model_source(
        SourceFormat::Json,
        GENERATOR_RULES,
        &CompilerOptions::default(),
    );
    assert_eq!(report.format, SEMANTIC_MODEL_LINT_FORMAT);
    assert!(report.valid, "{:#?}", report.diagnostics);
}

#[test]
fn compiled_output_is_idempotent_and_rejects_changed_existing_content() {
    let compiled = compile_source(
        SourceFormat::Json,
        GENERATOR_RULES,
        &CompilerOptions::default(),
    )
    .unwrap();
    let output = tempfile::tempdir().unwrap();
    let first = write_compiled_semantic_model_pack(output.path(), &compiled).unwrap();
    let second = write_compiled_semantic_model_pack(output.path(), &compiled).unwrap();
    assert_eq!(first, second);

    fs::write(output.path().join("manifest.json"), b"changed").unwrap();
    let error = write_compiled_semantic_model_pack(output.path(), &compiled).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn workspace_rules_are_explicit_hashed_and_confined() {
    let workspace = tempfile::tempdir().unwrap();
    let rules = workspace.path().join(WORKSPACE_SEMANTIC_MODEL_DIRECTORY);
    fs::create_dir_all(&rules).unwrap();
    fs::write(rules.join("generators.json"), GENERATOR_RULES).unwrap();
    fs::write(rules.join("notes.txt"), "not a pack").unwrap();

    let report = discover_workspace_semantic_models(
        workspace.path(),
        WorkspaceSemanticModelOptions::default(),
    );
    assert!(report.enabled);
    assert!(report.complete, "{:#?}", report.diagnostics);
    assert_eq!(report.files.len(), 1);
    assert_eq!(
        report.files[0].path,
        ".bifrost/semantic-models/generators.json"
    );
    assert!(report.files[0].valid, "{:#?}", report.files[0].diagnostics);

    fs::write(rules.join("generators.json"), b"{}").unwrap();
    let changed = discover_workspace_semantic_models(
        workspace.path(),
        WorkspaceSemanticModelOptions::default(),
    );
    assert_ne!(
        report.files[0].source_sha256,
        changed.files[0].source_sha256
    );
    assert!(!changed.complete);
}

#[cfg(unix)]
#[test]
fn workspace_rules_reject_symbolic_links() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let rules = workspace.path().join(WORKSPACE_SEMANTIC_MODEL_DIRECTORY);
    fs::create_dir_all(&rules).unwrap();
    symlink(outside.path(), rules.join("escape.json")).unwrap();

    let report = discover_workspace_semantic_models(
        workspace.path(),
        WorkspaceSemanticModelOptions::default(),
    );
    assert!(!report.complete);
    assert_eq!(report.diagnostics[0].code, "workspace.invalid_file");
}

#[test]
fn inventory_separates_installation_from_evidence_backed_activation() {
    let compiled = compile_source(
        SourceFormat::Json,
        GENERATOR_RULES,
        &CompilerOptions::default(),
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::Installed,
                source_id: "test:acme-builders".to_owned(),
            },
        )
        .unwrap();

    let installed = semantic_model_inventory(&catalog, None, 8).unwrap();
    assert_eq!(installed.format, SEMANTIC_MODEL_INVENTORY_FORMAT);
    assert!(installed.complete);
    assert_eq!(installed.installed.len(), 1);
    assert!(installed.active.is_empty());
    assert_eq!(installed.installed[0].sources[0].source_kind, "installed");
    assert_eq!(
        installed.installed[0].provenance.source,
        "https://docs.example/acme-builders"
    );
    let bounded = semantic_model_inventory(&catalog, None, 0).unwrap();
    assert!(!bounded.complete);
    assert!(bounded.installed.is_empty());

    let request = SemanticModelActivationRequest {
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
    };
    let outcome = resolve_active_semantic_models(&catalog, &request, &CancellationToken::new());
    let SemanticModelResolutionOutcome::Ready(active) = outcome else {
        panic!("activation must be ready: {outcome:#?}");
    };
    let inventory = semantic_model_inventory(&catalog, Some(&active), 8).unwrap();
    assert_eq!(inventory.active.len(), 1);
    assert_eq!(inventory.active[0].activation_status, "active");
    assert_eq!(
        inventory.active[0]
            .matched_evidence
            .package
            .as_ref()
            .unwrap()
            .version
            .as_deref(),
        Some("1.5.0")
    );
    assert!(
        inventory
            .activation_explanations
            .iter()
            .any(|explanation| explanation.status == "active")
    );
}
