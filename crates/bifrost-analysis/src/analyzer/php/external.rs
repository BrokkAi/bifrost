//! The Composer dependency pack adapter.
//!
//! Discovery hands this adapter one exact source set per autoload rule. The
//! adapter parses each PHP file and merges the declarations into one pack for
//! the package.

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, AuthoredPayload, AuthoredSemanticModelPack,
    AuthoredShard, BoundedProducerDiagnostics, Compatibility, Completeness, DependencyArtifactRole,
    DependencyPackAdapter, DependencyPackProduction, ExactDependencyArtifact, ExternalArtifactKind,
    MemberFact, NameSelector, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance,
    ResolvedDependency, SEMANTIC_MODEL_SCHEMA_VERSION, Safety, TypeFact,
};
use crate::hash::HashMap;

use super::source_artifact::{
    COMPOSER_ECOSYSTEM, PhpAutoloadRule, is_php_entry, project_php_source,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct PhpDependencyPackAdapter;

impl DependencyPackAdapter for PhpDependencyPackAdapter {
    fn adapter_name(&self) -> &str {
        "bifrost-php-dependency"
    }

    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-composer-package".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn can_produce(&self, dependency: &ResolvedDependency) -> bool {
        dependency.evidence.language == "php"
            && dependency.evidence.ecosystem == COMPOSER_ECOSYSTEM
            && dependency
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ExternalArtifactKind::ComposerPackageSourceSet)
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        if artifacts.is_empty() {
            return failed(
                "composer.artifact_count",
                "Composer production requires at least one package source set",
            );
        }
        if artifacts
            .iter()
            .any(|artifact| artifact.kind() != ExternalArtifactKind::ComposerPackageSourceSet)
        {
            return failed(
                "composer.artifact_kind",
                "Composer production requires Composer package source sets",
            );
        }

        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut types: HashMap<String, TypeFact> = HashMap::default();
        let mut members: HashMap<String, MemberFact> = HashMap::default();
        let mut complete = true;

        for artifact in artifacts {
            // The autoload rule survives as the artifact's own shape: a module
            // identity is the PSR-4 prefix, a runtime role is `files`
            // autoloading, and anything else is a classmap rule.
            let rule = match (artifact.module(), artifact.role()) {
                (Some(prefix), _) => PhpAutoloadRule::Psr4 {
                    namespace_prefix: prefix,
                },
                (None, DependencyArtifactRole::Runtime) => PhpAutoloadRule::Files,
                (None, _) => PhpAutoloadRule::Classmap,
            };
            for entry in artifact.source_entries() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    diagnostics.error(
                        "composer.projection.cancelled",
                        None,
                        "Composer declaration projection was cancelled",
                    );
                    complete = false;
                    break;
                }
                if !is_php_entry(entry.relative_path()) {
                    continue;
                }
                let Ok(source) = std::str::from_utf8(entry.bytes()) else {
                    diagnostics.error(
                        "composer.source.encoding",
                        Some(entry.relative_path().to_owned()),
                        "PHP source entry is not valid UTF-8",
                    );
                    complete = false;
                    continue;
                };
                let projection = project_php_source(
                    artifact.sha256(),
                    entry.relative_path(),
                    source,
                    rule,
                    limits,
                    cancellation,
                );
                complete &= projection.complete && projection.suppressed_diagnostics == 0;
                append_diagnostics(&mut diagnostics, projection.diagnostics);
                for fact in projection.types {
                    merge_type(&mut types, fact, &mut diagnostics, &mut complete);
                }
                for fact in projection.members {
                    members.entry(fact.id.clone()).or_insert(fact);
                }
                if types.len().saturating_add(members.len()) >= limits.max_records {
                    diagnostics.error(
                        "limit.records",
                        Some(entry.relative_path().to_owned()),
                        format!(
                            "Composer declarations exceed the {} record limit",
                            limits.max_records
                        ),
                    );
                    complete = false;
                    break;
                }
            }
        }

        if types.is_empty() && members.is_empty() {
            diagnostics.error(
                "composer.package.no_declarations",
                None,
                "Composer package autoloads no projectable PHP declarations",
            );
            complete = false;
        }
        let completeness = if complete && diagnostics.is_empty() {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let mut types = types.into_values().collect::<Vec<_>>();
        let mut members = members.into_values().collect::<Vec<_>>();
        types.sort_by(|left, right| left.id.cmp(&right.id));
        members.sort_by(|left, right| left.id.cmp(&right.id));

        let activation = vec![ActivationSelector {
            package: dependency
                .evidence
                .package
                .as_ref()
                .map(|coordinate| NameSelector {
                    name: coordinate.name.clone(),
                    version: coordinate
                        .version
                        .as_ref()
                        .map(|version| format!("={version}")),
                }),
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: dependency
                .evidence
                .configuration
                .clone()
                .into_iter()
                .collect(),
            artifact_sha256: None,
        }];
        let source = dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "composer.dist_url" || entry.key == "composer.source_url")
            .map(|entry| entry.value.clone())
            .unwrap_or_else(|| "exact Composer package".to_owned());
        let revision = dependency
            .provenance
            .iter()
            .find(|entry| {
                entry.key == "composer.dist_reference" || entry.key == "composer.source_reference"
            })
            .map(|entry| entry.value.clone());

        DependencyPackProduction {
            pack: (!types.is_empty() || !members.is_empty()).then(|| AuthoredSemanticModelPack {
                schema_version: SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: "bifrost.external.php".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                producer: self.producer(),
                language: "php".to_owned(),
                ecosystem: COMPOSER_ECOSYSTEM.to_owned(),
                compatibility: Compatibility {
                    bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                    toolchains: Vec::new(),
                },
                provenance: Provenance { source, revision },
                license: "NOASSERTION".to_owned(),
                completeness,
                safety: Safety {
                    generated_code_only: false,
                    review_required: false,
                },
                shards: vec![AuthoredShard {
                    id: "declarations.php.external".to_owned(),
                    activation,
                    payload: AuthoredPayload::DeclarationFacts {
                        types,
                        members,
                        relations: Vec::new(),
                    },
                }],
            }),
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

/// Merge one projected type into the package surface.
///
/// A namespace scaffold repeats across every file that declares into it, so it
/// merges silently. Two different declarations of the same class name are a
/// real Composer conflict and must not collapse into one silent winner.
fn merge_type(
    types: &mut HashMap<String, TypeFact>,
    incoming: TypeFact,
    diagnostics: &mut BoundedProducerDiagnostics,
    complete: &mut bool,
) {
    use crate::analyzer::semantic_model::TypeKind;
    match types.get(&incoming.id) {
        None => {
            types.insert(incoming.id.clone(), incoming);
        }
        Some(existing) if existing.type_kind == TypeKind::Module => {}
        Some(existing) => {
            if existing.locator != incoming.locator {
                diagnostics.warning(
                    "composer.declaration.conflict",
                    Some(locator_path(&incoming.locator)),
                    format!(
                        "Composer package declares {} more than once; the first declaration came from {}",
                        incoming.name,
                        locator_path(&existing.locator)
                    ),
                );
                *complete = false;
            }
        }
    }
}

fn locator_path(locator: &crate::analyzer::semantic_model::Locator) -> String {
    match locator {
        crate::analyzer::semantic_model::Locator::Source { path, .. }
        | crate::analyzer::semantic_model::Locator::Artifact { path, .. } => path.clone(),
    }
}

fn append_diagnostics(
    bounded: &mut BoundedProducerDiagnostics,
    diagnostics: Vec<ProducerDiagnostic>,
) {
    for diagnostic in diagnostics {
        match diagnostic.severity {
            ProducerDiagnosticSeverity::Warning => {
                bounded.warning(diagnostic.code, diagnostic.location, diagnostic.message)
            }
            ProducerDiagnosticSeverity::Error => {
                bounded.error(diagnostic.code, diagnostic.location, diagnostic.message)
            }
        }
    }
}

fn failed(code: &str, message: &str) -> DependencyPackProduction {
    DependencyPackProduction {
        pack: None,
        diagnostics: vec![ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: code.to_owned(),
            location: None,
            message: message.to_owned(),
        }],
        suppressed_diagnostics: 0,
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use std::fs;
    use std::path::PathBuf;

    use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
    use crate::analyzer::{Language, PhpAnalyzerConfig, PhpDependencyApiEvidence, TestProject};

    /// One Composer package to install into a fixture vendor tree.
    pub(crate) struct PackageSpec<'a> {
        pub name: &'a str,
        pub version: &'a str,
        pub reference: &'a str,
        pub autoload: &'a str,
        pub files: &'a [(&'a str, &'a str)],
    }

    /// An installed Composer vendor tree with a matching lock and installed.json.
    pub(crate) struct VendorFixture {
        pub _temp: tempfile::TempDir,
        pub root: PathBuf,
        pub project: TestProject,
        pub config: PhpAnalyzerConfig,
    }

    impl VendorFixture {
        pub(crate) fn new(packages: &[PackageSpec<'_>]) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("project");
            fs::create_dir_all(root.join("vendor/composer")).unwrap();
            let mut locked = Vec::new();
            let mut installed = Vec::new();
            for package in packages {
                let install_dir = root.join("vendor").join(package.name);
                for (path, source) in package.files {
                    let absolute = install_dir.join(path);
                    fs::create_dir_all(absolute.parent().unwrap()).unwrap();
                    fs::write(absolute, source).unwrap();
                }
                locked.push(format!(
                    r#"{{"name":"{}","version":"{}","type":"library","dist":{{"type":"path","url":"file:///{}","reference":"{}"}},"autoload":{}}}"#,
                    package.name,
                    package.version,
                    package.name,
                    package.reference,
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
            fs::write(root.join("vendor/composer/installed.json"), &installed_json).unwrap();
            fs::write(root.join("main.php"), "<?php\n").unwrap();

            let project = TestProject::new(&root, Language::Php);
            let config = PhpAnalyzerConfig {
                dependency_api_evidence: vec![PhpDependencyApiEvidence {
                    lockfile_path: PathBuf::from("composer.lock"),
                    lockfile_sha256: digest(lockfile.as_bytes()),
                    installed_json_path: Some(PathBuf::from("vendor/composer/installed.json")),
                    installed_json_sha256: Some(digest(installed_json.as_bytes())),
                    php_version: "8.3.0".to_owned(),
                    approved_vendor_roots: vec![PathBuf::from("vendor")],
                    include_dev_packages: false,
                }],
            };
            Self {
                _temp: temp,
                root,
                project,
                config,
            }
        }
    }

    pub(crate) fn digest(bytes: &[u8]) -> String {
        lower_hex_string(&sha256_bytes(bytes))
    }

    pub(crate) const WIDGET_PSR4: &str = r#"<?php
namespace Vendor\Widget;

use Vendor\Widget\Contracts\Renderable;

abstract class Widget implements Renderable {
    public const MODE = 'fast';
    protected string $label;
    public function __construct(string $label) { $this->label = $label; }
    public function render(int $width): string { return $this->label; }
    private function hidden(): void {}
    public static function create(string $label): static { return new static($label); }
}
"#;

    pub(crate) const RENDERABLE_PSR4: &str = r#"<?php
namespace Vendor\Widget\Contracts;

interface Renderable {
    public function render(int $width): string;
}
"#;

    pub(crate) const LEGACY_CLASSMAP: &str = r#"<?php
class Vendor_Widget_Legacy {
    public function legacyCall(): void {}
}
"#;

    pub(crate) const HELPERS_FILES: &str = r#"<?php
namespace Vendor\Widget;

function widget_render(Widget $widget): string { return $widget->render(10); }
"#;

    pub(crate) fn widget_package() -> PackageSpec<'static> {
        PackageSpec {
            name: "vendor/widget",
            version: "1.2.3",
            reference: "ref-widget",
            autoload: r#"{"psr-4":{"Vendor\\Widget\\":"src/"},"classmap":["legacy/"],"files":["helpers.php"]}"#,
            files: &[
                ("src/Widget.php", WIDGET_PSR4),
                ("src/Contracts/Renderable.php", RENDERABLE_PSR4),
                ("helpers.php", HELPERS_FILES),
                ("legacy/Vendor_Widget_Legacy.php", LEGACY_CLASSMAP),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{PackageSpec, VendorFixture, widget_package};
    use super::*;
    use crate::analyzer::Project;
    use crate::analyzer::php::resolve_php_semantic_pack_dependencies;
    use crate::analyzer::semantic_model::{
        CatalogOptions, DependencyPackLimits, SemanticPackCatalog,
        prepare_discovered_dependency_semantic_packs,
    };

    #[test]
    fn composer_discovery_binds_lockfile_vendor_roots_and_autoload_rules() {
        let fixture = VendorFixture::new(&[widget_package()]);
        let limits = DependencyPackLimits::default();

        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );

        assert!(discovery.complete, "{:#?}", discovery.diagnostics);
        assert_eq!(discovery.dependencies.len(), 1);
        let dependency = &discovery.dependencies[0];
        assert_eq!(dependency.evidence.language, "php");
        assert_eq!(dependency.evidence.ecosystem, "composer");
        assert_eq!(
            dependency.evidence.package.as_ref().unwrap().name,
            "vendor/widget"
        );
        assert_eq!(dependency.evidence.configuration.as_deref(), Some("8.3.0"));
        // One artifact per autoload rule: PSR-4, then classmap, then files.
        assert_eq!(dependency.artifacts.len(), 3, "{:#?}", dependency.artifacts);
        assert_eq!(
            dependency.artifacts[0].module.as_deref(),
            Some("Vendor.Widget")
        );
        assert_eq!(
            dependency.artifacts[0].role,
            DependencyArtifactRole::Declarations
        );
        assert_eq!(
            dependency.artifacts[2].role,
            DependencyArtifactRole::Runtime
        );
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| entry.key == "composer.dist_reference" && entry.value == "ref-widget"),
            "{:#?}",
            dependency.provenance
        );
    }

    #[test]
    fn dependency_files_are_read_through_the_pack_pipeline_not_the_workspace() {
        // The acceptance criterion is that indexing a dependency never grows the
        // ordinary workspace file set: vendor sources reach the analyzer as pack
        // facts, not as ProjectFiles.
        let fixture = VendorFixture::new(&[widget_package()]);
        let limits = DependencyPackLimits::default();
        let files_before = fixture.project.all_files().unwrap();
        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &PhpDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(fixture.project.all_files().unwrap(), files_before);
    }

    #[test]
    fn exact_composer_package_produces_a_complete_reusable_pack() {
        let fixture = VendorFixture::new(&[widget_package()]);
        let limits = DependencyPackLimits::default();
        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &PhpDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.packs.len(), 1);
        assert_eq!(prepared.packs[0].completeness, Completeness::Complete);
    }

    #[test]
    fn a_psr4_path_mismatch_keeps_the_package_surface_partial() {
        // `Vendor\Widget\Widget` must autoload from `src/Widget.php`. Declaring
        // it in `src/Wrong.php` is a real Composer autoload failure, so the
        // package surface must not claim to be complete.
        let package = PackageSpec {
            name: "vendor/widget",
            version: "1.2.3",
            reference: "ref-widget",
            autoload: r#"{"psr-4":{"Vendor\\Widget\\":"src/"}}"#,
            files: &[("src/Wrong.php", super::fixture::WIDGET_PSR4)],
        };
        let fixture = VendorFixture::new(&[package]);
        let limits = DependencyPackLimits::default();
        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let prepared = prepare_discovered_dependency_semantic_packs(
            &catalog,
            &PhpDependencyPackAdapter,
            discovery,
            &limits,
            None,
        );

        assert!(
            prepared
                .packs
                .iter()
                .all(|pack| pack.completeness == Completeness::Partial)
                || !prepared.complete,
            "{:#?}",
            prepared.diagnostics
        );
    }

    #[test]
    fn a_package_installed_outside_every_approved_root_is_rejected() {
        let mut fixture = VendorFixture::new(&[widget_package()]);
        fixture.config.dependency_api_evidence[0].approved_vendor_roots =
            vec![fixture.root.join("vendor/composer")];
        let limits = DependencyPackLimits::default();

        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );

        assert!(!discovery.complete);
        assert!(
            discovery
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "composer.package.outside_roots"),
            "{:#?}",
            discovery.diagnostics
        );
    }

    #[test]
    fn a_changed_lockfile_digest_rejects_the_evidence() {
        let mut fixture = VendorFixture::new(&[widget_package()]);
        fixture.config.dependency_api_evidence[0].lockfile_sha256 = "0".repeat(64);
        let limits = DependencyPackLimits::default();

        let discovery = resolve_php_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &limits,
            None,
        );

        assert!(!discovery.complete);
        assert_eq!(
            discovery.diagnostics[0].code,
            "composer.evidence.lockfile_digest_mismatch"
        );
    }
}
