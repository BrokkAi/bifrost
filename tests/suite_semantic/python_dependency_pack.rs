use brokk_bifrost::analyzer::{
    DependencyPackLimits, PythonAnalyzerConfig, PythonEnvironmentConfig, PythonEnvironmentLimits,
    resolve_python_semantic_pack_dependencies,
};
use brokk_bifrost::{CancellationToken, Language, Project};

use crate::common::inline_project::InlineTestProject;

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
