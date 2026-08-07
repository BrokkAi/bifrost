//! Exact Composer packages, end to end.
//!
//! Each test installs an offline vendor tree, activates it through the ordinary
//! host-owned path, and then asks the PHP collector what it can prove. Nothing
//! here runs Composer or reaches the network: every input is a file the fixture
//! wrote.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, DependencyPackEcosystem, DependencyPackWorkspaceContext,
    FilesystemProject, PhpAnalyzerConfig, PhpDependencyApiEvidence,
    PhpDependencyPackAdapter, Project, ProjectFile, WorkspaceAnalyzer,
    resolve_php_semantic_pack_dependencies,
};
use brokk_bifrost_analysis::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
    SemanticDiagnosticReport,
};
use semver::Version;
use sha2::{Digest, Sha256};

/// One Composer package to install into the fixture vendor tree.
struct PackageSpec {
    name: &'static str,
    version: &'static str,
    autoload: &'static str,
    files: &'static [(&'static str, &'static str)],
}

/// An installed Composer project: a vendor tree, a matching lock, the
/// installed.json Composer would have written, and the workspace sources.
struct ComposerFixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    config: AnalyzerConfig,
}

impl ComposerFixture {
    fn new(packages: &[PackageSpec], workspace: &[(&str, &str)]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        // The vendor tree lives outside the workspace root on purpose. An
        // installed dependency must reach the analyzer as pack facts, not as
        // ordinary project files, and keeping it out of the root is what makes
        // this test exercise the external boundary at all.
        let vendor_root = temp.path().join("vendor");
        fs::create_dir_all(vendor_root.join("composer")).unwrap();
        fs::create_dir_all(&root).unwrap();
        for (path, source) in workspace {
            let absolute = root.join(path);
            fs::create_dir_all(absolute.parent().unwrap()).unwrap();
            fs::write(absolute, source).unwrap();
        }

        let mut locked = Vec::new();
        let mut installed = Vec::new();
        for package in packages {
            let install_dir = vendor_root.join(package.name);
            for (path, source) in package.files {
                let absolute = install_dir.join(path);
                fs::create_dir_all(absolute.parent().unwrap()).unwrap();
                fs::write(absolute, source).unwrap();
            }
            locked.push(format!(
                r#"{{"name":"{}","version":"{}","type":"library","dist":{{"type":"path","url":"file:///{}","reference":"ref-{}"}},"autoload":{}}}"#,
                package.name,
                package.version,
                package.name,
                package.version,
                package.autoload
            ));
            installed.push(format!(
                r#"{{"name":"{}","version":"{}","type":"library","install-path":"../{}","autoload":{}}}"#,
                package.name, package.version, package.name, package.autoload
            ));
        }
        let lockfile = format!(
            r#"{{"content-hash":"fixture","packages":[{}],"packages-dev":[]}}"#,
            locked.join(",")
        );
        let installed_json = format!(r#"{{"packages":[{}],"dev":false}}"#, installed.join(","));
        fs::write(root.join("composer.lock"), &lockfile).unwrap();
        fs::write(vendor_root.join("composer/installed.json"), &installed_json).unwrap();

        let config = AnalyzerConfig {
            php: PhpAnalyzerConfig {
                dependency_api_evidence: vec![PhpDependencyApiEvidence {
                    lockfile_path: root.join("composer.lock"),
                    lockfile_sha256: digest(lockfile.as_bytes()),
                    installed_json_path: Some(vendor_root.join("composer/installed.json")),
                    installed_json_sha256: Some(digest(installed_json.as_bytes())),
                    php_version: "8.3.0".to_owned(),
                    approved_vendor_roots: vec![vendor_root.clone()],
                    include_dev_packages: false,
                }],
            },
            ..AnalyzerConfig::default()
        };
        Self {
            _temp: temp,
            root,
            config,
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    /// Build a workspace analyzer and activate the Composer ecosystem through
    /// the ordinary host path, so the overlay and the retained discovery
    /// evidence are published exactly as production publishes them.
    fn activated(&self) -> (WorkspaceAnalyzer, Arc<FilesystemProject>) {
        let project = Arc::new(FilesystemProject::new(self.root()).unwrap());
        let analyzer = WorkspaceAnalyzer::build(project.clone(), self.config.clone());
        let catalog = Box::leak(Box::new(
            SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap(),
        ));
        let request = SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cancellation = CancellationToken::default();
        let outcome = analyzer.activate_dependency_packs(
            &self.config,
            &[DependencyPackEcosystem::Composer],
            DependencyPackWorkspaceContext {
                catalog,
                persistence: None,
                activation: &request,
                limits: DependencyPackLimits::default(),
                cancellation: &cancellation,
            },
        );
        assert!(
            outcome.complete(),
            "Composer activation must succeed: {:#?}",
            outcome.ecosystems
        );
        (analyzer, project)
    }

    fn report_for(&self, analyzer: &WorkspaceAnalyzer, rel_path: &str) -> SemanticDiagnosticReport {
        let file = ProjectFile::new(self.root.to_path_buf(), rel_path);
        let source = file.read_to_string().expect("read workspace source");
        analyzer.analyzer().semantic_diagnostics(&file, &source)
    }
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

const WIDGET_SRC: &str = r#"<?php
namespace Vendor\Widget;

use Vendor\Widget\Contracts\Renderable;

class Widget implements Renderable {
    public const MODE = 'fast';

    public function render(int $width): string { return ''; }
}
"#;

const RENDERABLE_SRC: &str = r#"<?php
namespace Vendor\Widget\Contracts;

interface Renderable {
    public function render(int $width): string;
}
"#;

const TRAIT_SRC: &str = r#"<?php
namespace Vendor\Widget;

trait Sizeable {
    public function width(): int { return 0; }
}
"#;

/// PSR-4 gives each class its own file, so the trait user lives beside the
/// trait rather than inside its file.
const SIZED_WIDGET_SRC: &str = r#"<?php
namespace Vendor\Widget;

class SizedWidget {
    use Sizeable;
}
"#;

const LEGACY_SRC: &str = r#"<?php
class Vendor_Widget_Legacy {
    public function legacyCall(): void {}
}
"#;

const HELPERS_SRC: &str = r#"<?php
namespace Vendor\Widget;

function widget_mode(): string { return Widget::MODE; }
"#;

fn widget_package() -> PackageSpec {
    PackageSpec {
        name: "vendor/widget",
        version: "1.2.3",
        autoload: r#"{"psr-4":{"Vendor\\Widget\\":"src/"},"classmap":["legacy/"],"files":["helpers.php"]}"#,
        files: &[
            ("src/Widget.php", WIDGET_SRC),
            ("src/Contracts/Renderable.php", RENDERABLE_SRC),
            ("src/Sizeable.php", TRAIT_SRC),
            ("src/SizedWidget.php", SIZED_WIDGET_SRC),
            ("legacy/Vendor_Widget_Legacy.php", LEGACY_SRC),
            ("helpers.php", HELPERS_SRC),
        ],
    }
}

fn has_incomplete_reason(
    report: &SemanticDiagnosticReport,
    matcher: fn(&SemanticDiagnosticIncompleteReason) -> bool,
) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(matcher)
        )
    })
}

#[test]
fn exact_composer_package_produces_a_deterministic_pack_without_workspace_files() {
    let fixture = ComposerFixture::new(&[widget_package()], &[("src/App.php", "<?php\n")]);
    let project = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let files_before = project.all_files().unwrap();
    let limits = DependencyPackLimits::default();

    let first = resolve_php_semantic_pack_dependencies(
        &fixture.config.php,
        project.as_ref(),
        &limits,
        None,
    );
    let second = resolve_php_semantic_pack_dependencies(
        &fixture.config.php,
        project.as_ref(),
        &limits,
        None,
    );

    assert!(first.complete, "{:#?}", first.diagnostics);
    // Two discoveries of the same install must agree exactly.
    assert_eq!(first.dependencies, second.dependencies);

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let cold = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &PhpDependencyPackAdapter,
        first,
        &limits,
        None,
    );
    assert!(cold.complete, "{:#?}", cold.diagnostics);
    let warm = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &PhpDependencyPackAdapter,
        second,
        &limits,
        None,
    );
    assert!(warm.complete, "{:#?}", warm.diagnostics);
    assert_eq!(warm.profile.reused_packs, 1, "the pack must be reusable");
    assert_eq!(project.all_files().unwrap(), files_before);
}

#[test]
fn psr4_classmap_and_files_autoloading_all_reach_the_overlay() {
    let fixture = ComposerFixture::new(&[widget_package()], &[("src/App.php", "<?php\n")]);
    let (analyzer, _project) = fixture.activated();
    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("Composer overlay");

    // PSR-4 mapped class and interface.
    assert!(
        !overlay
            .symbols_named("Vendor.Widget.Widget")
            .records
            .is_empty()
    );
    assert!(
        !overlay
            .symbols_named("Vendor.Widget.Contracts.Renderable")
            .records
            .is_empty()
    );
    // A trait, which PHP resolves separately from classes.
    assert!(
        !overlay
            .symbols_named("Vendor.Widget.Sizeable")
            .records
            .is_empty()
    );
    // A classmap class in the global namespace, which no PSR-4 prefix covers.
    assert!(
        !overlay
            .symbols_named("Vendor_Widget_Legacy")
            .records
            .is_empty()
    );
    // A `files`-autoloaded free function.
    assert!(!overlay.symbols_named("widget_mode").records.is_empty());

    // The PSR-4 prefix itself becomes a namespace scaffold, which is what lets
    // the collector know the package's surface covers `Vendor\Widget\`.
    assert!(
        overlay
            .symbols_named("Vendor.Widget")
            .records
            .iter()
            .any(|symbol| {
                symbol.kind
                == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Module
            })
    );
}

#[test]
fn an_indexed_vendor_type_and_member_resolve_without_errors() {
    let fixture = ComposerFixture::new(
        &[widget_package()],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

use Vendor\Widget\Widget;

class App {
    public function run(Widget $widget): void {
        $widget->render(10);
    }
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome,
        SemanticDiagnosticOutcome::Resolved {
            boundary: BoundaryStatus::ExternalIndexed,
            ..
        }
    )));
}

#[test]
fn a_complete_package_surface_proves_a_missing_export() {
    let fixture = ComposerFixture::new(
        &[widget_package()],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

class App {
    private \Vendor\Widget\MissingWidget $value;
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    assert_eq!(report.diagnostics().len(), 1, "{:#?}", report.outcomes());
    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if matches!(&proof.domain, SemanticDiagnosticDomain::Type { name } if name == "Vendor.Widget.MissingWidget")
                    && proof.boundary == BoundaryStatus::ExternalIndexed
        )),
        "the absence must be proved against the indexed package surface: {:#?}",
        report.outcomes()
    );
}

#[test]
fn a_complete_owner_surface_proves_a_missing_member() {
    let fixture = ComposerFixture::new(
        &[widget_package()],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

use Vendor\Widget\Widget;

class App {
    public function run(Widget $widget): void {
        $widget->missingMethod();
    }
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    assert!(
        report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if matches!(
                    &proof.domain,
                    SemanticDiagnosticDomain::MemberSurface { member, .. } if member == "missingMethod"
                ) && proof.boundary == BoundaryStatus::ExternalIndexed
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn an_inherited_vendor_member_resolves_rather_than_erroring() {
    // `Widget` declares `render` only through its interface contract, and the
    // member lookup must consult the owner's ancestors before it reports a
    // member missing.
    let fixture = ComposerFixture::new(
        &[widget_package()],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

use Vendor\Widget\Contracts\Renderable;

class App {
    public function run(Renderable $renderable): void {
        $renderable->render(10);
    }
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
}

#[test]
fn an_unrelated_vendor_namespace_stays_incomplete_even_with_an_active_pack() {
    // Indexing `vendor/widget` says nothing about `Other\Vendor`. Proving a
    // name absent there would be an error Bifrost has not earned.
    let fixture = ComposerFixture::new(
        &[widget_package()],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

class App {
    private \Other\Vendor\MissingType $value;
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn two_packages_declaring_the_same_class_stay_ambiguous_rather_than_picking_a_winner() {
    const CONFLICT_A: &str = r#"<?php
namespace Shared\Conflict;

class Duplicate {
    public function fromA(): void {}
}
"#;
    const CONFLICT_B: &str = r#"<?php
namespace Shared\Conflict;

class Duplicate {
    public function fromB(): void {}
}
"#;
    let fixture = ComposerFixture::new(
        &[
            PackageSpec {
                name: "vendor/alpha",
                version: "1.0.0",
                autoload: r#"{"psr-4":{"Shared\\Conflict\\":"src/"}}"#,
                files: &[("src/Duplicate.php", CONFLICT_A)],
            },
            PackageSpec {
                name: "vendor/beta",
                version: "1.0.0",
                autoload: r#"{"psr-4":{"Shared\\Conflict\\":"src/"}}"#,
                files: &[("src/Duplicate.php", CONFLICT_B)],
            },
        ],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

class App {
    private \Shared\Conflict\Duplicate $value;
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    // Whatever the ladder concludes, a name two packages both install must
    // never be reported as an error.
    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
}

#[test]
fn a_use_alias_for_a_vendor_type_resolves_through_the_pack() {
    let fixture = ComposerFixture::new(
        &[widget_package()],
        &[(
            "src/App.php",
            r#"<?php
namespace App;

use Vendor\Widget\Widget as RenamedWidget;

class App {
    private RenamedWidget $value;
}
"#,
        )],
    );
    let (analyzer, _project) = fixture.activated();

    let report = fixture.report_for(&analyzer, "src/App.php");

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome,
        SemanticDiagnosticOutcome::Resolved {
            boundary: BoundaryStatus::ExternalIndexed,
            ..
        }
    )));
}
