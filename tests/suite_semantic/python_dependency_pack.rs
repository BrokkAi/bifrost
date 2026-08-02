use brokk_bifrost::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProductionRequest, AuthoredPayload,
    CatalogOptions, Compatibility, DependencyPackLimits, ExternalArtifactKind,
    ExternalArtifactPackProducer, Provenance, Safety, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticPackCatalog,
};
use brokk_bifrost::analyzer::{
    AnalyzerConfig, PythonAnalyzerConfig, PythonArtifactPackProducer, PythonEnvironmentConfig,
    PythonEnvironmentLimits, PythonSemanticModelWorkspaceContext,
    resolve_python_semantic_pack_dependencies,
};
use brokk_bifrost::{CancellationToken, Language, Project};
use semver::Version;

use crate::common::InlineTestProject;

fn environment(
    standard_library_root: std::path::PathBuf,
    distribution_root: std::path::PathBuf,
) -> PythonAnalyzerConfig {
    PythonAnalyzerConfig {
        environment: Some(PythonEnvironmentConfig {
            implementation: "cpython".to_owned(),
            version: "3.12.3".to_owned(),
            platform: "macos-arm64".to_owned(),
            standard_library_root,
            bundled_stub_roots: Vec::new(),
            distribution_roots: vec![distribution_root],
            limits: PythonEnvironmentLimits::default(),
        }),
    }
}

fn write_distribution(
    root: &std::path::Path,
    metadata_name: &str,
    version: &str,
    top_level: &str,
    source: &str,
    typed: bool,
) {
    let package = root.join(top_level);
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("__init__.py"), source).unwrap();
    if typed {
        std::fs::write(package.join("py.typed"), "").unwrap();
    }
    let metadata = root.join(format!("{metadata_name}-{version}.dist-info"));
    std::fs::create_dir_all(&metadata).unwrap();
    std::fs::write(
        metadata.join("METADATA"),
        format!("Name: {metadata_name}\nVersion: {version}\n"),
    )
    .unwrap();
    std::fs::write(metadata.join("top_level.txt"), format!("{top_level}\n")).unwrap();
}

fn artifact_request(
    path: std::path::PathBuf,
    kind: ExternalArtifactKind,
) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path,
        artifact_kind: kind,
        pack_id: "test.python".to_owned(),
        pack_version: "1.0.0".to_owned(),
        ecosystem: "python".to_owned(),
        compatibility: Compatibility {
            bifrost: "*".to_owned(),
            toolchains: Vec::new(),
        },
        activation: vec![ActivationSelector {
            package: None,
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "test".to_owned(),
            revision: None,
        },
        license: "NOASSERTION".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

#[test]
fn explicitly_configured_environment_discovers_static_artifacts_without_expanding_workspace() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("app.py", "import alpha\n")
        .build();
    let files_before = workspace.project().all_files().unwrap();
    let environment_root = tempfile::tempdir().unwrap();
    let standard_library = environment_root.path().join("stdlib");
    let distributions = environment_root.path().join("site-packages");
    std::fs::create_dir_all(&standard_library).unwrap();
    std::fs::create_dir_all(&distributions).unwrap();
    std::fs::write(
        standard_library.join("re.pyi"),
        "def compile(pattern: str) -> Pattern: ...\n",
    )
    .unwrap();
    write_distribution(
        &distributions,
        "alpha",
        "1.2.3",
        "alpha",
        "def connect(host: str) -> None: ...\n",
        true,
    );
    write_distribution(
        &distributions,
        "beta-stubs",
        "2.0.0",
        "beta",
        "def parse(value: str) -> int: ...\n",
        false,
    );

    let outcome = resolve_python_semantic_pack_dependencies(
        &environment(standard_library, distributions),
        workspace.project(),
        &DependencyPackLimits::default(),
        None,
    );

    assert!(outcome.complete, "{:#?}", outcome.diagnostics);
    assert_eq!(outcome.dependencies.len(), 3);
    assert_eq!(
        outcome
            .dependencies
            .iter()
            .map(|dependency| dependency.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "python:distribution:alpha:1.2.3",
            "python:distribution:beta-stubs:2.0.0",
            "python:stdlib:cpython:3.12.3",
        ]
    );
    assert!(outcome.dependencies.iter().all(|dependency| {
        dependency.evidence.language == "python"
            && dependency.evidence.ecosystem == "python"
            && dependency.evidence.artifact_sha256.is_none()
            && !dependency.artifacts.is_empty()
    }));
    assert_eq!(workspace.project().all_files().unwrap(), files_before);
}

#[test]
fn disabled_environment_has_no_implicit_interpreter_or_cache_discovery() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("app.py", "import re\n")
        .build();

    let outcome = resolve_python_semantic_pack_dependencies(
        &PythonAnalyzerConfig::default(),
        workspace.project(),
        &DependencyPackLimits::default(),
        None,
    );

    assert!(outcome.complete);
    assert!(outcome.dependencies.is_empty());
    assert!(outcome.diagnostics.is_empty());
}

#[test]
fn discovery_preserves_qualified_module_names_and_applies_global_stub_precedence() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("app.py", "import nested.widget\n")
        .build();
    let environment_root = tempfile::tempdir().unwrap();
    let standard_library = environment_root.path().join("stdlib");
    let bundled_stubs = environment_root.path().join("bundled-stubs");
    let distributions = environment_root.path().join("site-packages");
    std::fs::create_dir_all(standard_library.join("nested")).unwrap();
    std::fs::create_dir_all(bundled_stubs.join("nested")).unwrap();
    std::fs::create_dir_all(&distributions).unwrap();
    std::fs::write(
        standard_library.join("nested").join("widget.py"),
        "def standard() -> None: ...\n",
    )
    .unwrap();
    std::fs::write(
        bundled_stubs.join("nested").join("widget.pyi"),
        "def stub() -> None: ...\n",
    )
    .unwrap();
    write_distribution(
        &distributions,
        "nested-widget",
        "1.0.0",
        "nested",
        "def distribution() -> None: ...\n",
        true,
    );

    let mut config = environment(standard_library, distributions);
    config
        .environment
        .as_mut()
        .unwrap()
        .bundled_stub_roots
        .push(bundled_stubs.clone());
    let outcome = resolve_python_semantic_pack_dependencies(
        &config,
        workspace.project(),
        &DependencyPackLimits::default(),
        None,
    );

    assert!(outcome.complete, "{:#?}", outcome.diagnostics);
    let artifacts = outcome
        .dependencies
        .iter()
        .flat_map(|dependency| dependency.artifacts.iter())
        .filter(|artifact| artifact.module.as_deref() == Some("nested.widget"))
        .collect::<Vec<_>>();
    assert_eq!(artifacts.len(), 1, "{outcome:#?}");
    assert_eq!(artifacts[0].kind, ExternalArtifactKind::PythonStub);
    assert_eq!(
        artifacts[0].path,
        bundled_stubs.join("nested").join("widget.pyi")
    );
}

#[test]
fn cancelled_discovery_returns_no_dependencies() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("app.py", "import re\n")
        .build();
    let environment_root = tempfile::tempdir().unwrap();
    let standard_library = environment_root.path().join("stdlib");
    let distributions = environment_root.path().join("site-packages");
    std::fs::create_dir_all(&standard_library).unwrap();
    std::fs::create_dir_all(&distributions).unwrap();
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let outcome = resolve_python_semantic_pack_dependencies(
        &environment(standard_library, distributions),
        workspace.project(),
        &DependencyPackLimits::default(),
        Some(&cancellation),
    );

    assert!(outcome.cancelled);
    assert!(!outcome.complete);
    assert!(outcome.dependencies.is_empty());
    assert_eq!(outcome.diagnostics[0].code, "discovery.cancelled");
}

#[test]
fn static_stub_producer_preserves_classes_signatures_properties_and_aliases() {
    let environment = tempfile::tempdir().unwrap();
    let artifact = environment.path().join("widgets.pyi");
    std::fs::write(
        &artifact,
        r#"
from typing import Protocol, TypeAlias, overload

Alias: TypeAlias = str

class Reader(Protocol):
    value: int

    @property
    def name(self) -> str: ...

    @overload
    def read(self, count: int) -> bytes: ...
    @overload
    def read(self, count: None = ...) -> str: ...
"#,
    )
    .unwrap();

    let production = PythonArtifactPackProducer.produce_exact_artifact(
        &artifact_request(artifact, ExternalArtifactKind::PythonStub),
        &ArtifactProducerLimits::default(),
    );

    assert_eq!(
        production.completeness,
        brokk_bifrost::analyzer::semantic_model::Completeness::Complete
    );
    let pack = production.pack.unwrap();
    let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload else {
        panic!("expected declaration facts");
    };
    assert!(types.iter().any(|fact| fact.name == "widgets.Reader"));
    assert!(types.iter().any(|fact| fact.name == "widgets.Alias"));
    assert_eq!(members.iter().filter(|fact| fact.name == "read").count(), 2);
    assert!(members.iter().any(|fact| fact.name == "name"
        && fact.member_kind == brokk_bifrost::analyzer::semantic_model::MemberKind::Property));
    assert!(
        members
            .iter()
            .filter(|fact| fact.name == "read")
            .all(|fact| fact
                .signature
                .as_ref()
                .is_some_and(|signature| signature.returns.is_some()))
    );
}

#[test]
fn explicit_activation_publishes_python_facts_without_expanding_workspace_files() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("app.py", "import re\nre.compile('a')\n")
        .build();
    let environment_root = tempfile::tempdir().unwrap();
    let standard_library = environment_root.path().join("stdlib");
    let distributions = environment_root.path().join("site-packages");
    std::fs::create_dir_all(&standard_library).unwrap();
    std::fs::create_dir_all(&distributions).unwrap();
    std::fs::write(
        standard_library.join("re.pyi"),
        "def compile(pattern: str) -> Pattern: ...\n",
    )
    .unwrap();
    let mut config = AnalyzerConfig::default();
    config.python = environment(standard_library, distributions);
    let analyzer = workspace.workspace_analyzer(config.clone());
    let files_before = analyzer.analyzer().project().all_files().unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let cancellation = CancellationToken::default();
    let activation = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };

    let outcome = analyzer.activate_python_environment_packs(
        &config,
        PythonSemanticModelWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );

    let preparation = outcome.preparation.as_ref().unwrap();
    assert!(preparation.complete, "{preparation:#?}");
    assert!(outcome.runtime.is_some());
    assert!(analyzer.analyzer().semantic_model_overlay().is_some());
    assert_eq!(
        analyzer.analyzer().project().all_files().unwrap(),
        files_before
    );
}
