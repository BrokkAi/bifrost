//! Python semantic diagnostics against an activated, offline Python
//! environment.
//!
//! Every fixture here writes its own standard library and site-packages tree
//! into a temporary directory and activates packs from it. Nothing downloads,
//! imports, or executes a package: activation reads the exact local files, and
//! a diagnostic request afterwards reads only what activation published.

use std::path::{Path, PathBuf};

use brokk_bifrost::analyzer::semantic_model::{
    CatalogOptions, DependencyPackLimits, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticPackCatalog,
};
use brokk_bifrost::analyzer::{
    AnalyzerConfig, DependencyPackEcosystem, PythonAnalyzerConfig, PythonEnvironmentConfig,
    PythonEnvironmentLimits, PythonSemanticModelWorkspaceContext,
};
use brokk_bifrost::{CancellationToken, Language, WorkspaceAnalyzer};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport,
};
use semver::Version;

use crate::common::{BuiltInlineTestProject, InlineTestProject};

const APP: &str = "app.py";

/// A temporary Python environment: one standard-library root and one
/// site-packages root, both written by the test.
struct Environment {
    _temp: tempfile::TempDir,
    standard_library: PathBuf,
    bundled_stubs: PathBuf,
    distributions: PathBuf,
}

impl Environment {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let standard_library = temp.path().join("stdlib");
        let bundled_stubs = temp.path().join("bundled-stubs");
        let distributions = temp.path().join("site-packages");
        std::fs::create_dir_all(&standard_library).unwrap();
        std::fs::create_dir_all(&bundled_stubs).unwrap();
        std::fs::create_dir_all(&distributions).unwrap();
        Self {
            _temp: temp,
            standard_library,
            bundled_stubs,
            distributions,
        }
    }

    /// Write one standard-library module, e.g. `("re.pyi", "...")` or
    /// `("ns/pkg.pyi", "...")`.
    fn standard_library_module(self, rel_path: &str, source: &str) -> Self {
        write_file(&self.standard_library.join(rel_path), source);
        self
    }

    /// Write one bundled stub, which outranks the standard-library file it
    /// shadows.
    fn bundled_stub(self, rel_path: &str, source: &str) -> Self {
        write_file(&self.bundled_stubs.join(rel_path), source);
        self
    }

    /// Write one installed distribution: its dist-info metadata plus the files
    /// of its top-level package, each relative to that package directory.
    fn distribution(
        self,
        name: &str,
        top_level: &str,
        typed: bool,
        files: &[(&str, &str)],
    ) -> Self {
        let package = self.distributions.join(top_level);
        for (rel_path, source) in files {
            write_file(&package.join(rel_path), source);
        }
        if typed {
            write_file(&package.join("py.typed"), "");
        }
        let metadata = self.distributions.join(format!("{name}-1.0.0.dist-info"));
        write_file(
            &metadata.join("METADATA"),
            &format!("Name: {name}\nVersion: 1.0.0\n"),
        );
        write_file(&metadata.join("top_level.txt"), &format!("{top_level}\n"));
        self
    }

    fn config(&self) -> AnalyzerConfig {
        AnalyzerConfig {
            python: PythonAnalyzerConfig {
                environment: Some(PythonEnvironmentConfig {
                    implementation: "cpython".to_owned(),
                    version: "3.12.3".to_owned(),
                    platform: "macos-arm64".to_owned(),
                    standard_library_root: self.standard_library.clone(),
                    bundled_stub_roots: vec![self.bundled_stubs.clone()],
                    distribution_roots: vec![self.distributions.clone()],
                    limits: PythonEnvironmentLimits::default(),
                }),
            },
            ..Default::default()
        }
    }
}

fn write_file(path: &Path, source: &str) {
    std::fs::create_dir_all(path.parent().expect("file has a parent")).unwrap();
    std::fs::write(path, source).unwrap();
}

/// A workspace whose analyzer has the environment's packs activated.
struct Fixture {
    _environment: Environment,
    workspace: BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
    // The published overlay is retained by the analyzer, but the catalog owns
    // the registered packs it was built from.
    _catalog: SemanticPackCatalog,
    source: String,
}

impl Fixture {
    fn report(&self) -> SemanticDiagnosticReport {
        let file = self.workspace.file(APP);
        self.analyzer
            .analyzer()
            .semantic_diagnostics(&file, &self.source)
    }

    fn invalidate(&self) {
        assert!(
            self.analyzer
                .invalidate_dependency_pack_state(&[DependencyPackEcosystem::Python])
        );
    }
}

fn activate(environment: Environment, source: &str) -> Fixture {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file(APP, source)
        .build();
    let config = environment.config();
    let analyzer = workspace.workspace_analyzer(config.clone());
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
    assert!(outcome.runtime.is_some(), "{outcome:#?}");
    assert!(
        analyzer.analyzer().semantic_model_overlay().is_some(),
        "activation must publish an overlay: {outcome:#?}"
    );
    Fixture {
        _environment: environment,
        workspace,
        analyzer,
        _catalog: catalog,
        source: source.to_owned(),
    }
}

fn resolved_at(report: &SemanticDiagnosticReport, boundary: BoundaryStatus) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(outcome, SemanticDiagnosticOutcome::Resolved { boundary: found, .. }
            if *found == boundary)
    })
}

fn incomplete_reasons(
    report: &SemanticDiagnosticReport,
) -> Vec<&SemanticDiagnosticIncompleteReason> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
            _ => None,
        })
        .flatten()
        .collect()
}

fn absence_domains(report: &SemanticDiagnosticReport) -> Vec<&SemanticDiagnosticDomain> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Absent(proof) => Some(&proof.domain),
            _ => None,
        })
        .collect()
}

#[test]
fn indexed_standard_library_symbols_never_error() {
    let environment = Environment::new().standard_library_module(
        "re.pyi",
        "def compile(pattern: str) -> str: ...\nclass Pattern: ...\n",
    );
    let fixture = activate(
        environment,
        "import re\n\n\ndef run():\n    return re.compile('a')\n",
    );

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "the import and the module attribute both resolve into the pack: {report:#?}"
    );
}

#[test]
fn installed_distribution_symbols_never_error() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .distribution(
            "alpha",
            "alpha",
            true,
            &[("__init__.py", "def connect(host: str) -> None: ...\n")],
        );
    let fixture = activate(
        environment,
        "from alpha import connect\n\n\ndef run():\n    return connect('h')\n",
    );

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{report:#?}"
    );
}

#[test]
fn complete_stub_proves_a_missing_exported_name() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n");
    let fixture = activate(environment, "from re import no_such_name\n");

    let report = fixture.report();
    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(
        report.diagnostics()[0].message.contains("no_such_name"),
        "{report:#?}"
    );
    assert!(
        absence_domains(&report).iter().any(|domain| matches!(
            domain,
            SemanticDiagnosticDomain::Module { name } if name == "re"
        )),
        "the checked domain is the module surface: {report:#?}"
    );
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.boundary == BoundaryStatus::ExternalIndexed
        )),
        "{report:#?}"
    );
}

#[test]
fn complete_stub_proves_a_missing_module_attribute() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n");
    let fixture = activate(
        environment,
        "import re\n\n\ndef run():\n    return re.nope\n",
    );

    let report = fixture.report();
    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(
        absence_domains(&report).iter().any(|domain| matches!(
            domain,
            SemanticDiagnosticDomain::MemberSurface { owner, member }
                if owner == "re" && member == "nope"
        )),
        "{report:#?}"
    );
}

#[test]
fn an_unenumerated_re_export_can_never_prove_absence() {
    // A wildcard import binds names the pack producer cannot enumerate, so
    // what the surface lists is not all of it.
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .distribution(
            "delta",
            "delta",
            true,
            &[(
                "__init__.py",
                "from ._impl import *\n\ndef go() -> None: ...\n",
            )],
        );
    let fixture = activate(environment, "from delta import no_such_name\n");

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::DynamicBehavior { detail }
                if detail.contains("enumerate")
        )),
        "{report:#?}"
    );
}

#[test]
fn a_dynamic_only_stub_can_never_prove_absence() {
    // PEP 562: a module `__getattr__` answers any name at run time.
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .distribution(
            "epsilon",
            "epsilon",
            true,
            &[("__init__.py", "def __getattr__(name: str) -> int: ...\n")],
        );
    let fixture = activate(environment, "from epsilon import no_such_name\n");

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::DynamicBehavior { detail }
                if detail.contains("__getattr__")
        )),
        "{report:#?}"
    );
}

#[test]
fn a_declared_but_unindexed_module_suppresses_with_a_typed_reason() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .distribution(
            "alpha",
            "alpha",
            true,
            &[("__init__.py", "def connect(host: str) -> None: ...\n")],
        );
    let fixture = activate(environment, "import alpha.missing_submodule\n");

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalDeclaredUnindexed,
            }
        )),
        "the build declares `alpha`, so its unindexed submodule is not unknown: {report:#?}"
    );
}

#[test]
fn an_undeclared_module_suppresses_as_an_unknown_boundary() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n");
    let fixture = activate(environment, "import nothing_declares_this\n");

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalUnknown,
            }
        )),
        "{report:#?}"
    );
}

#[test]
fn a_re_exported_name_resolves_and_a_missing_one_is_proven_absent() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .distribution(
            "requestslike",
            "requestslike",
            true,
            &[
                ("__init__.pyi", "from .sessions import Session as Session\n"),
                ("sessions.pyi", "class Session: ...\n"),
            ],
        );
    let fixture = activate(
        environment,
        "from requestslike import Session\nfrom requestslike import NoSuchName\n",
    );

    let report = fixture.report();
    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(
        report.diagnostics()[0].message.contains("NoSuchName"),
        "the re-exported name must not be reported: {report:#?}"
    );
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "{report:#?}"
    );
}

#[test]
fn overloaded_declarations_resolve_without_conflict() {
    let environment = Environment::new().standard_library_module(
        "overloaded.pyi",
        "from typing import overload\n\n@overload\ndef fn(value: int) -> int: ...\n@overload\ndef fn(value: str) -> str: ...\n",
    );
    let fixture = activate(
        environment,
        "from overloaded import fn\nfrom overloaded import missing_name\n",
    );

    let report = fixture.report();
    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(
        report.diagnostics()[0].message.contains("missing_name"),
        "{report:#?}"
    );
}

#[test]
fn a_namespace_package_module_is_indexed_under_its_qualified_name() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .standard_library_module("ns/pkg.pyi", "def widget() -> None: ...\n");
    let fixture = activate(environment, "import ns.pkg\n");

    let report = fixture.report();
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_at(&report, BoundaryStatus::ExternalIndexed),
        "a namespace package's module carries its whole dotted identity: {report:#?}"
    );
}

#[test]
fn a_stub_takes_precedence_over_the_source_it_shadows() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n")
        .standard_library_module("widget.py", "def from_source() -> None:\n    pass\n")
        .bundled_stub("widget.pyi", "def from_stub() -> None: ...\n");
    let fixture = activate(
        environment,
        "from widget import from_stub\nfrom widget import from_source\n",
    );

    let report = fixture.report();
    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(
        report.diagnostics()[0].message.contains("from_source"),
        "the stub is the module's whole surface: {report:#?}"
    );
}

#[test]
fn invalidating_the_environment_withdraws_a_prior_absence_proof() {
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n");
    let fixture = activate(environment, "from re import no_such_name\n");

    let proven = fixture.report();
    assert_eq!(1, proven.diagnostics().len(), "{proven:#?}");

    fixture.invalidate();

    let withdrawn = fixture.report();
    assert!(
        withdrawn.diagnostics().is_empty(),
        "an invalidated environment proves nothing absent: {withdrawn:#?}"
    );
    assert!(
        incomplete_reasons(&withdrawn).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
        )),
        "{withdrawn:#?}"
    );
}

#[test]
fn a_diagnostic_request_never_acquires_the_environment_itself() {
    // The workspace is configured with a full environment, and no host has
    // activated it. The request must read retained state only.
    let environment = Environment::new()
        .standard_library_module("re.pyi", "def compile(pattern: str) -> str: ...\n");
    let source = "import re\n\n\ndef run():\n    return re.compile('a')\n";
    let workspace = InlineTestProject::with_language(Language::Python)
        .file(APP, source)
        .build();
    let analyzer = workspace.workspace_analyzer(environment.config());
    let files_before = analyzer.analyzer().project().all_files().unwrap();

    let report = analyzer
        .analyzer()
        .semantic_diagnostics(&workspace.file(APP), source);

    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalUnknown,
            }
        )),
        "{report:#?}"
    );
    assert!(analyzer.analyzer().semantic_model_overlay().is_none());
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_none()
    );
    assert_eq!(
        analyzer.analyzer().project().all_files().unwrap(),
        files_before
    );
}
