use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost::CancellationToken;
use brokk_bifrost::analyzer::semantic_model::{
    AuthoredSemanticModelPack, CatalogCoordinate, CatalogOpenMode, CatalogOptions, Completeness,
    DependencyArtifactRole, DependencyPackAdapter, DependencyPackLimits,
    DependencyPackPreparationStatus, DependencyPackProduction, DependencyProvenance,
    DurablePackSource, DurablePackSourceKind, ExactDependencyArtifact, ExternalArtifactKind,
    Producer, ResolvedActiveSemanticModels, ResolvedDependency, ResolvedDependencyArtifact,
    SemanticModelActivationEvidence, SemanticModelActivationRequest,
    SemanticModelResolutionOutcome, SemanticModelRuntimeLimits, SemanticPackCatalog, SourceFormat,
    compile_pack, compile_source, prepare_dependency_semantic_packs,
    resolve_active_semantic_models,
};
use semver::Version;

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");

#[derive(Default)]
struct FixtureAdapter {
    productions: AtomicUsize,
}

impl DependencyPackAdapter for FixtureAdapter {
    fn adapter_name(&self) -> &str {
        "fixture-maven"
    }

    fn adapter_version(&self) -> &str {
        "1"
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "artifact-scanner".to_owned(),
            version: "2.0.0".to_owned(),
        }
    }

    fn produce(
        &self,
        _dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        _limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
        _cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        self.productions.fetch_add(1, Ordering::Relaxed);
        assert_eq!(artifacts.len(), 1);
        assert!(!artifacts[0].bytes().is_empty());
        DependencyPackProduction {
            pack: Some(serde_json::from_slice(DECLARATIONS_JSON).unwrap()),
            diagnostics: Vec::new(),
            suppressed_diagnostics: 0,
        }
    }
}

fn dependency(path: std::path::PathBuf) -> ResolvedDependency {
    ResolvedDependency {
        id: "com.acme:widget:1.5.0".to_owned(),
        evidence: SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:widget".to_owned(),
                version: Some(Version::parse("1.5.0").unwrap()),
            }),
            module: None,
            toolchain: None,
            target: Some("jvm".to_owned()),
            configuration: Some("release".to_owned()),
            artifact_sha256: None,
        },
        provenance: Vec::new(),
        artifacts: vec![ResolvedDependencyArtifact {
            role: DependencyArtifactRole::Binary,
            kind: ExternalArtifactKind::JavaClassJar,
            path,
        }],
    }
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse("0.8.17").unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn ready(outcome: SemanticModelResolutionOutcome) -> ResolvedActiveSemanticModels {
    match outcome {
        SemanticModelResolutionOutcome::Ready(active) => active,
        other => panic!("expected ready semantic models, got {other:#?}"),
    }
}

#[test]
fn identical_bytes_reuse_one_generated_production_across_paths() {
    let root = tempfile::tempdir().unwrap();
    let first_path = root.path().join("workspace-a/widget.jar");
    let second_path = root.path().join("workspace-b/widget.jar");
    std::fs::create_dir_all(first_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    std::fs::write(&first_path, b"same exact artifact bytes").unwrap();
    std::fs::write(&second_path, b"same exact artifact bytes").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();

    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(first_path)],
        &DependencyPackLimits::default(),
        None,
    );
    let accounting = catalog.accounting().unwrap();
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(second_path)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(first.complete, "{:#?}", first.diagnostics);
    assert!(second.complete, "{:#?}", second.diagnostics);
    assert_eq!(
        first.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Reused
    );
    assert_eq!(first.packs[0].production, second.packs[0].production);
    assert_eq!(first.evidence, second.evidence);
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 1);
    assert_eq!(catalog.accounting().unwrap(), accounting);
    assert_eq!(
        second
            .compose_activation_request(activation_request())
            .unwrap()
            .evidence,
        second.evidence
    );
}

#[test]
fn evidence_only_dependency_uses_compatible_installed_pack() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let compiled =
        compile_source(SourceFormat::Json, DECLARATIONS_JSON, &Default::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "github-release:test".to_owned(),
            },
        )
        .unwrap();
    let mut dependency = dependency(std::path::PathBuf::new());
    dependency.artifacts.clear();
    let adapter = FixtureAdapter::default();

    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(prepared.complete, "{:#?}", prepared.diagnostics);
    assert!(prepared.packs.is_empty());
    assert_eq!(prepared.installed_packs.len(), 1);
    assert_eq!(prepared.profile.installed_packs, 1);
    assert_eq!(prepared.evidence.len(), 1);
    assert!(prepared.evidence[0].artifact_sha256.is_none());
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
    assert!(
        prepared
            .compose_activation_request(activation_request())
            .is_some()
    );
}

#[test]
fn evidence_only_dependency_never_selects_a_pack_without_exact_version() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let compiled =
        compile_source(SourceFormat::Json, DECLARATIONS_JSON, &Default::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "github-release:test".to_owned(),
            },
        )
        .unwrap();
    let mut dependency = dependency(std::path::PathBuf::new());
    dependency.artifacts.clear();
    dependency.evidence.package.as_mut().unwrap().version = None;
    let adapter = FixtureAdapter::default();

    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!prepared.complete);
    assert!(prepared.installed_packs.is_empty());
    assert!(prepared.evidence.is_empty());
    assert_eq!(prepared.diagnostics[0].code, "dependency.pack_unavailable");
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
}

#[test]
fn partial_installed_pack_composes_evidence_without_claiming_complete_coverage() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let mut authored: AuthoredSemanticModelPack =
        serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    authored.completeness = Completeness::Partial;
    let compiled = compile_pack(&authored, &Default::default()).unwrap();
    catalog
        .install(
            &compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: "github-release:partial-test".to_owned(),
            },
        )
        .unwrap();
    let mut dependency = dependency(std::path::PathBuf::new());
    dependency.artifacts.clear();

    let prepared = prepare_dependency_semantic_packs(
        &catalog,
        &FixtureAdapter::default(),
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!prepared.complete);
    assert_eq!(prepared.installed_packs.len(), 1);
    assert_eq!(
        prepared.installed_packs[0].completeness,
        Completeness::Partial
    );
    assert!(
        prepared
            .compose_activation_request(activation_request())
            .is_some()
    );
}

#[test]
fn changed_artifact_bytes_invalidate_only_the_exact_production() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("widget.jar");
    std::fs::write(&path, b"first artifact revision").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();
    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(path.clone())],
        &DependencyPackLimits::default(),
        None,
    );

    std::fs::write(&path, b"second artifact revision").unwrap();
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(path)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(first.complete && second.complete);
    assert_ne!(
        first.packs[0].production.key.input_digest(),
        second.packs[0].production.key.input_digest()
    );
    assert_ne!(
        first.packs[0].production.manifest_digest,
        second.packs[0].production.manifest_digest
    );
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 2);
    assert_eq!(catalog.accounting().unwrap().source_count, 2);
}

#[test]
fn output_affecting_generation_limits_have_distinct_production_keys() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("widget.jar");
    std::fs::write(&artifact, b"same artifact").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();
    let default_limits = DependencyPackLimits::default();
    let mut constrained_limits = default_limits;
    constrained_limits.producer.max_records -= 1;

    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact.clone())],
        &default_limits,
        None,
    );
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact)],
        &constrained_limits,
        None,
    );

    assert!(first.complete && second.complete);
    assert_ne!(
        first.packs[0].production.key,
        second.packs[0].production.key
    );
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 2);
}

#[test]
fn cancellation_before_artifact_read_publishes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("widget.jar");
    std::fs::write(&artifact, b"artifact").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let outcome = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact)],
        &DependencyPackLimits::default(),
        Some(&cancellation),
    );

    assert!(outcome.cancelled);
    assert!(!outcome.complete);
    assert!(outcome.packs.is_empty());
    assert!(outcome.evidence.is_empty());
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
    assert_eq!(catalog.accounting().unwrap().object_count, 0);
    assert!(
        outcome
            .compose_activation_request(activation_request())
            .is_none()
    );
}

#[test]
fn missing_artifact_is_partial_and_never_claims_empty_success() {
    let root = tempfile::tempdir().unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = FixtureAdapter::default();

    let outcome = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(root.path().join("missing.jar"))],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!outcome.complete);
    assert!(!outcome.cancelled);
    assert!(outcome.packs.is_empty());
    assert!(outcome.evidence.is_empty());
    assert_eq!(outcome.diagnostics[0].code, "artifact.metadata");
    assert_eq!(adapter.productions.load(Ordering::Relaxed), 0);
    assert!(
        outcome
            .compose_activation_request(activation_request())
            .is_none()
    );
}

#[test]
fn partial_generated_pack_is_reproduced_with_actionable_diagnostic() {
    struct PartialAdapter(FixtureAdapter);

    impl DependencyPackAdapter for PartialAdapter {
        fn adapter_name(&self) -> &str {
            self.0.adapter_name()
        }

        fn adapter_version(&self) -> &str {
            self.0.adapter_version()
        }

        fn producer(&self) -> Producer {
            self.0.producer()
        }

        fn produce(
            &self,
            dependency: &ResolvedDependency,
            artifacts: &[ExactDependencyArtifact],
            limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
            cancellation: Option<&CancellationToken>,
        ) -> DependencyPackProduction {
            let mut production = self.0.produce(dependency, artifacts, limits, cancellation);
            production.pack.as_mut().unwrap().completeness = Completeness::Partial;
            production
        }
    }

    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("widget.jar");
    std::fs::write(&artifact, b"artifact").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let adapter = PartialAdapter(FixtureAdapter::default());
    let first = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact.clone())],
        &DependencyPackLimits::default(),
        None,
    );
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &adapter,
        &[dependency(artifact)],
        &DependencyPackLimits::default(),
        None,
    );

    assert!(!first.complete && !second.complete);
    assert_eq!(first.packs[0].completeness, Completeness::Partial);
    assert_eq!(second.packs[0].completeness, Completeness::Partial);
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(second.diagnostics[0].code, "production.partial");
    assert_eq!(adapter.0.productions.load(Ordering::Relaxed), 2);
}

#[test]
fn changing_one_dependency_preserves_unrelated_production_and_overlay() {
    struct DistinctAdapter;

    impl DependencyPackAdapter for DistinctAdapter {
        fn adapter_name(&self) -> &str {
            "distinct-fixture"
        }

        fn adapter_version(&self) -> &str {
            "1"
        }

        fn producer(&self) -> Producer {
            Producer {
                name: "artifact-scanner".to_owned(),
                version: "2.0.0".to_owned(),
            }
        }

        fn produce(
            &self,
            dependency: &ResolvedDependency,
            artifacts: &[ExactDependencyArtifact],
            _limits: &brokk_bifrost::analyzer::semantic_model::ArtifactProducerLimits,
            _cancellation: Option<&CancellationToken>,
        ) -> DependencyPackProduction {
            let revision = artifacts[0].bytes()[0] as char;
            let mut pack: brokk_bifrost::analyzer::semantic_model::AuthoredSemanticModelPack =
                serde_json::from_slice(DECLARATIONS_JSON).unwrap();
            pack.pack_id = format!("fixture.{}", dependency.id);
            pack.compatibility.toolchains.clear();
            pack.shards[0].id = format!("declarations.{}", dependency.id);
            pack.shards[0].activation = vec![
                brokk_bifrost::analyzer::semantic_model::ActivationSelector {
                    package: None,
                    module: Some(brokk_bifrost::analyzer::semantic_model::NameSelector {
                        name: dependency.id.clone(),
                        version: None,
                    }),
                    toolchain: None,
                    targets: Vec::new(),
                    configurations: Vec::new(),
                    artifact_sha256: None,
                },
            ];
            let brokk_bifrost::analyzer::semantic_model::AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
            } = &mut pack.shards[0].payload
            else {
                unreachable!()
            };
            types.truncate(1);
            types[0].id = format!("type.{}", dependency.id);
            types[0].name = format!("com.acme.{}{revision}", dependency.id);
            members.clear();
            relations.clear();
            DependencyPackProduction {
                pack: Some(pack),
                diagnostics: Vec::new(),
                suppressed_diagnostics: 0,
            }
        }
    }

    fn distinct_dependency(id: &str, path: std::path::PathBuf) -> ResolvedDependency {
        ResolvedDependency {
            id: id.to_owned(),
            evidence: SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: None,
                module: Some(CatalogCoordinate {
                    name: id.to_owned(),
                    version: None,
                }),
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            provenance: vec![DependencyProvenance {
                key: "fixture".to_owned(),
                value: id.to_owned(),
            }],
            artifacts: vec![ResolvedDependencyArtifact {
                role: DependencyArtifactRole::Binary,
                kind: ExternalArtifactKind::JavaClassJar,
                path,
            }],
        }
    }

    let root = tempfile::tempdir().unwrap();
    let alpha = root.path().join("alpha.jar");
    let beta = root.path().join("beta.jar");
    std::fs::write(&alpha, b"1-alpha").unwrap();
    std::fs::write(&beta, b"1-beta").unwrap();
    let catalog = SemanticPackCatalog::open(
        &root.path().join("catalog"),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let first = prepare_dependency_semantic_packs(
        &catalog,
        &DistinctAdapter,
        &[
            distinct_dependency("alpha", alpha.clone()),
            distinct_dependency("beta", beta.clone()),
        ],
        &DependencyPackLimits::default(),
        None,
    );
    assert!(first.complete, "{:#?}", first.diagnostics);
    let first_active = ready(resolve_active_semantic_models(
        &catalog,
        &first
            .compose_activation_request(activation_request())
            .unwrap(),
        &CancellationToken::default(),
    ));

    std::fs::write(&alpha, b"2-alpha").unwrap();
    let second = prepare_dependency_semantic_packs(
        &catalog,
        &DistinctAdapter,
        &[
            distinct_dependency("alpha", alpha),
            distinct_dependency("beta", beta),
        ],
        &DependencyPackLimits::default(),
        None,
    );
    let second_active = ready(resolve_active_semantic_models(
        &catalog,
        &second
            .compose_activation_request(activation_request())
            .unwrap(),
        &CancellationToken::default(),
    ));

    assert!(first.complete && second.complete);
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Generated
    );
    assert_eq!(
        second.packs[1].status,
        DependencyPackPreparationStatus::Reused
    );
    assert_ne!(first.packs[0].production, second.packs[0].production);
    assert_eq!(first.packs[1].production, second.packs[1].production);
    assert_eq!(
        first_active.shards().len(),
        2,
        "{:#?}",
        first_active.activation_report()
    );
    assert_eq!(
        second_active.shards().len(),
        2,
        "{:#?}",
        second_active.activation_report()
    );
    assert_ne!(
        first_active.active_model_set_hash(),
        second_active.active_model_set_hash()
    );
    assert_eq!(first_active.types_named("com.acme.alpha1").records.len(), 1);
    assert!(
        second_active
            .types_named("com.acme.alpha1")
            .records
            .is_empty()
    );
    assert_eq!(
        second_active.types_named("com.acme.alpha2").records.len(),
        1
    );
    assert_eq!(first_active.types_named("com.acme.beta1").records.len(), 1);
    assert_eq!(second_active.types_named("com.acme.beta1").records.len(), 1);
}
