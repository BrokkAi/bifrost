use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost::CancellationToken;
use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOpenMode, CatalogOptions, Completeness, DependencyArtifactRole,
    DependencyPackAdapter, DependencyPackLimits, DependencyPackPreparationStatus,
    DependencyPackProduction, ExactDependencyArtifact, ExternalArtifactKind, Producer,
    ResolvedDependency, ResolvedDependencyArtifact, SemanticModelActivationEvidence,
    SemanticPackCatalog, prepare_dependency_semantic_packs,
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
}

#[test]
fn partial_generated_pack_remains_partial_when_reused() {
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
        DependencyPackPreparationStatus::Reused
    );
    assert_eq!(adapter.0.productions.load(Ordering::Relaxed), 1);
}
