//! Exact Composer dependency discovery.
//!
//! This module reads two declared metadata files -- `composer.lock` and the
//! `vendor/composer/installed.json` Composer wrote next to the install -- and
//! the installed package trees beneath explicitly approved vendor roots. It
//! never runs Composer, a Composer script, a Composer plugin, or any dependency
//! code, and it never opens a network connection.
//!
//! Discovery is host-owned activation work. A diagnostic request must never
//! reach this module; it reads only what activation already published.

use std::path::{Path, PathBuf};

use semver::Version;
use serde::Deserialize;

use crate::CancellationToken;
use crate::analyzer::canonical_hash::is_lower_sha256;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedDependencyDiagnostics, CatalogCoordinate,
    DependencyArtifactRole, DependencyDiscoveryOutcome, DependencyDiscoveryProfile,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyProvenance, ExternalArtifactKind, ProducerDiagnostic, ProducerDiagnosticSeverity,
    ResolvedDependency, ResolvedDependencyArtifact, SemanticModelActivationEvidence,
    read_exact_artifact_while,
};
use crate::analyzer::{PhpAnalyzerConfig, PhpDependencyApiEvidence, Project};
use crate::hash::{HashMap, HashSet};

use crate::analyzer::topology::DependencyScope;
use brokk_bifrost_php::aliases::php_namespace_to_fq;

/// The most autoload rules one Composer package may contribute. Each rule
/// becomes its own artifact so a PSR-4 prefix stays attached to the files it
/// admits, so this also bounds the artifact count per dependency.
pub const PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE: usize = 64;

/// The most directories one package tree walk may visit.
const MAX_PACKAGE_DIRECTORIES: usize = 8_192;

pub fn resolve_php_semantic_pack_dependencies(
    config: &PhpAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let mut dependencies = Vec::new();
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let mut metadata_inputs_considered = 0_usize;
    let mut evidence_bytes_read = 0_u64;
    let mut cancelled = false;

    // The runtime dependency is *declared*, not installed, so it is resolved
    // whether or not a host configured Composer evidence. A workspace that
    // declares no PHP version resolves nothing here and stays complete.
    match resolve_declared_php_runtime_dependency(project.root(), &mut metadata_inputs_considered) {
        Ok(Some(runtime)) => dependencies.push(runtime),
        Ok(None) => {}
        Err(error) => diagnostics.push(error),
    }

    for configured in &config.dependency_api_evidence {
        if is_cancelled(cancellation) {
            cancelled = true;
            diagnostics.push(cancelled_diagnostic(None));
            break;
        }
        let evidence = evidence_paths_from_root(project.root(), configured);
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(1);
        match resolve_evidence(&evidence, limits, &mut evidence_bytes_read, cancellation) {
            Ok(mut resolved) => {
                metadata_inputs_considered =
                    metadata_inputs_considered.saturating_add(resolved.len());
                if dependencies.len().saturating_add(resolved.len()) > limits.max_dependencies {
                    diagnostics.push(diagnostic(
                        "limit.dependencies",
                        None,
                        format!(
                            "Composer dependency discovery exceeds the {} dependency limit",
                            limits.max_dependencies
                        ),
                    ));
                    break;
                }
                dependencies.append(&mut resolved);
            }
            Err(error) => {
                cancelled |= error.code == "artifact.cancelled"
                    || error.code == "composer.evidence.cancelled";
                diagnostics.push(error);
            }
        }
    }

    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    let before_dedup = dependencies.len();
    dependencies.dedup_by(|left, right| left.id == right.id);
    if dependencies.len() != before_dedup {
        diagnostics.push(diagnostic(
            "composer.evidence.duplicate_package",
            None,
            "Composer dependency evidence contains duplicate package identities",
        ));
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
        },
        complete: diagnostics.is_empty() && suppressed_diagnostics.total() == 0 && !cancelled,
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled,
    }
}

fn resolve_evidence(
    evidence: &PhpDependencyApiEvidence,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<ResolvedDependency>, DependencyPackDiagnostic> {
    require_non_empty("php_version", &evidence.php_version)?;
    if !is_lower_sha256(&evidence.lockfile_sha256) {
        return Err(diagnostic(
            "composer.evidence.invalid_lockfile_digest",
            Some(&evidence.lockfile_path),
            "Composer dependency evidence lockfile digest must be lowercase SHA-256",
        ));
    }
    if evidence.approved_vendor_roots.is_empty() {
        return Err(diagnostic(
            "composer.evidence.missing_vendor_roots",
            None,
            "Composer dependency evidence must declare at least one approved vendor root",
        ));
    }

    let lockfile = read_evidence_file_with_budget(
        &evidence.lockfile_path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    if lockfile.sha256() != evidence.lockfile_sha256 {
        return Err(diagnostic(
            "composer.evidence.lockfile_digest_mismatch",
            Some(&evidence.lockfile_path),
            format!(
                "composer.lock digest {} does not match configured digest {}",
                lockfile.sha256(),
                evidence.lockfile_sha256
            ),
        ));
    }
    let locked: ComposerLockfile = serde_json::from_slice(lockfile.bytes()).map_err(|error| {
        diagnostic(
            "composer.evidence.lockfile_decode",
            Some(&evidence.lockfile_path),
            format!("could not decode composer.lock: {error}"),
        )
    })?;

    let installed_manifest =
        read_installed_manifest(evidence, limits, evidence_bytes_read, cancellation)?;
    let installed = installed_manifest
        .iter()
        .flat_map(|manifest| manifest.packages.iter())
        .map(|entry| (entry.package.name.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let approved_roots = canonical_approved_roots(evidence)?;

    let mut locked_packages = Vec::with_capacity(locked.packages.len());
    locked_packages.extend(locked.packages.iter());
    if evidence.include_dev_packages {
        locked_packages.extend(locked.packages_dev.iter());
    }

    let mut identities = HashSet::default();
    let mut resolved = Vec::with_capacity(locked_packages.len());
    for package in locked_packages {
        if is_cancelled(cancellation) {
            return Err(cancelled_diagnostic(None));
        }
        require_non_empty("package.name", &package.name)?;
        require_non_empty("package.version", &package.version)?;
        if !identities.insert(package.name.as_str()) {
            return Err(diagnostic(
                "composer.evidence.duplicate_package",
                Some(&evidence.lockfile_path),
                format!("composer.lock repeats package {}", package.name),
            ));
        }

        let installed_entry = installed.get(package.name.as_str());
        let install_dir = resolve_install_directory(
            package,
            installed_entry.copied(),
            evidence,
            &approved_roots,
        )?;
        // Composer writes the autoload block it actually installed into
        // installed.json. Prefer it, and fall back to the locked block when a
        // host approved no installed.json.
        let autoload = installed_entry
            .map(|entry| &entry.package.autoload)
            .unwrap_or(&package.autoload);
        let artifacts = collect_autoload_artifacts(autoload, &install_dir, limits)?;
        if artifacts.is_empty() {
            // A package that autoloads nothing (a metapackage, or one whose
            // whole surface is `exclude-from-classmap`) contributes no API.
            // Skipping it is not a failure of discovery.
            continue;
        }

        resolved.push(ResolvedDependency {
            id: format!(
                "composer:{}@{}:{}:{}:{}",
                package.name,
                package.version,
                evidence.php_version,
                evidence.lockfile_sha256,
                package.reference().unwrap_or("none")
            ),
            evidence: SemanticModelActivationEvidence {
                language: "php".to_owned(),
                ecosystem: "composer".to_owned(),
                package: Some(CatalogCoordinate {
                    name: package.name.clone(),
                    version: Version::parse(package.version.trim_start_matches('v')).ok(),
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: Some(evidence.php_version.clone()),
                artifact_sha256: None,
            },
            provenance: package_provenance(package, evidence, &install_dir),
            artifacts,
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
    }
    Ok(resolved)
}

fn package_provenance(
    package: &ComposerPackage,
    evidence: &PhpDependencyApiEvidence,
    install_dir: &Path,
) -> Vec<DependencyProvenance> {
    let mut provenance = Vec::with_capacity(8);
    provenance.extend([
        provenance_entry("composer.install_path", install_dir.to_string_lossy()),
        provenance_entry("composer.lockfile_sha256", &evidence.lockfile_sha256),
        provenance_entry("composer.package_name", &package.name),
        provenance_entry("composer.package_version", &package.version),
        provenance_entry("php.version", &evidence.php_version),
    ]);
    if let Some(package_type) = &package.package_type {
        provenance.push(provenance_entry("composer.package_type", package_type));
    }
    if let Some(dist) = &package.dist {
        if let Some(reference) = &dist.reference {
            provenance.push(provenance_entry("composer.dist_reference", reference));
        }
        if let Some(shasum) = dist.shasum.as_ref().filter(|shasum| !shasum.is_empty()) {
            provenance.push(provenance_entry("composer.dist_shasum", shasum));
        }
        if let Some(url) = &dist.url {
            provenance.push(provenance_entry("composer.dist_url", url));
        }
    }
    if let Some(source) = &package.source {
        if let Some(reference) = &source.reference {
            provenance.push(provenance_entry("composer.source_reference", reference));
        }
        if let Some(url) = &source.url {
            provenance.push(provenance_entry("composer.source_url", url));
        }
    }
    provenance.sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));
    provenance
}

/// Build one artifact per autoload rule.
///
/// The rule shape survives into production through the artifact itself rather
/// than an encoded string: a PSR-4 prefix becomes the artifact's module
/// identity, a classmap rule is a module-less declaration artifact, and `files`
/// autoloading is a module-less runtime artifact because Composer includes
/// those files unconditionally.
fn collect_autoload_artifacts(
    autoload: &ComposerAutoload,
    install_dir: &Path,
    limits: &DependencyPackLimits,
) -> Result<Vec<ResolvedDependencyArtifact>, DependencyPackDiagnostic> {
    let mut artifacts = Vec::new();
    let mut psr4_prefixes = autoload.psr4.iter().collect::<Vec<_>>();
    psr4_prefixes.sort_by(|left, right| left.0.cmp(right.0));
    for (prefix, target) in psr4_prefixes {
        let mut files = Vec::new();
        for relative in target.paths() {
            collect_php_files(install_dir, relative, limits, &mut files)?;
        }
        if files.is_empty() {
            continue;
        }
        sort_and_dedup(&mut files);
        artifacts.push(ResolvedDependencyArtifact::module_source_set(
            DependencyArtifactRole::Declarations,
            ExternalArtifactKind::ComposerPackageSourceSet,
            php_namespace_to_fq(prefix),
            install_dir.to_path_buf(),
            files,
        ));
    }

    let mut classmap_files = Vec::new();
    for relative in &autoload.classmap {
        collect_php_files(install_dir, relative, limits, &mut classmap_files)?;
    }
    if !classmap_files.is_empty() {
        sort_and_dedup(&mut classmap_files);
        artifacts.push(ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Declarations,
            ExternalArtifactKind::ComposerPackageSourceSet,
            install_dir.to_path_buf(),
            classmap_files,
        ));
    }

    let mut included_files = Vec::new();
    for relative in &autoload.files {
        collect_php_files(install_dir, relative, limits, &mut included_files)?;
    }
    if !included_files.is_empty() {
        sort_and_dedup(&mut included_files);
        artifacts.push(ResolvedDependencyArtifact::source_set(
            DependencyArtifactRole::Runtime,
            ExternalArtifactKind::ComposerPackageSourceSet,
            install_dir.to_path_buf(),
            included_files,
        ));
    }

    if !autoload.psr0.is_empty() {
        // PSR-0 maps underscores in a class name onto directory separators, so
        // its file set is not the PSR-4 set. Report it instead of projecting a
        // surface under the wrong rule; an unprojected rule must not become a
        // silent absence proof.
        return Err(diagnostic(
            "composer.autoload.psr0_unsupported",
            Some(install_dir),
            format!(
                "Composer PSR-0 autoloading is not projected: {:?}",
                autoload.psr0.keys().collect::<Vec<_>>()
            ),
        ));
    }
    if artifacts.len() > PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE {
        return Err(diagnostic(
            "limit.autoload_rules",
            Some(install_dir),
            format!(
                "Composer package declares more than the {PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE} supported autoload rules"
            ),
        ));
    }
    Ok(artifacts)
}

/// Collect the `.php` files a single autoload target admits.
///
/// `relative` is either a file or a directory. The walk is an explicit stack:
/// a vendor tree is arbitrarily deep and must not consume the Rust stack.
fn collect_php_files(
    install_dir: &Path,
    relative: &Path,
    limits: &DependencyPackLimits,
    files: &mut Vec<PathBuf>,
) -> Result<(), DependencyPackDiagnostic> {
    let Some(relative) = normalize_relative(relative) else {
        return Err(diagnostic(
            "composer.autoload.path_escape",
            Some(install_dir),
            format!(
                "Composer autoload target {} escapes its package",
                relative.display()
            ),
        ));
    };
    let absolute = install_dir.join(&relative);
    let Ok(metadata) = std::fs::symlink_metadata(&absolute) else {
        // Composer records autoload rules from the package manifest, and a
        // package can ship a rule whose target it does not install. A missing
        // target contributes no files and is not an error.
        return Ok(());
    };
    if metadata.is_symlink() {
        return Err(diagnostic(
            "composer.autoload.symlink",
            Some(&absolute),
            "Composer autoload target must not be a symbolic link",
        ));
    }
    if metadata.is_file() {
        if is_php_file(&absolute) {
            files.push(relative);
        }
        return Ok(());
    }

    let mut directories = vec![relative];
    let mut visited = 0_usize;
    while let Some(directory) = directories.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_PACKAGE_DIRECTORIES {
            return Err(diagnostic(
                "limit.package_directories",
                Some(install_dir),
                format!(
                    "Composer package tree exceeds the {MAX_PACKAGE_DIRECTORIES} directory limit"
                ),
            ));
        }
        let Ok(entries) = std::fs::read_dir(install_dir.join(&directory)) else {
            continue;
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                diagnostic(
                    "composer.package.read_dir",
                    Some(install_dir),
                    format!("could not read Composer package directory: {error}"),
                )
            })?;
            let child = directory.join(entry.file_name());
            if child.components().count() > limits.max_source_path_depth {
                return Err(diagnostic(
                    "limit.source_path_depth",
                    Some(install_dir),
                    format!(
                        "Composer package path exceeds the {} depth limit",
                        limits.max_source_path_depth
                    ),
                ));
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            // `read_exact_source_set_while` rejects a symlink again when it
            // reads the set. Skipping here keeps the walk itself from
            // following one out of the package.
            if metadata.is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                directories.push(child);
            } else if metadata.is_file() && is_php_file(&child) {
                if files.len() >= limits.max_source_files_per_artifact {
                    return Err(diagnostic(
                        "limit.source_files",
                        Some(install_dir),
                        format!(
                            "Composer package exceeds the {} file limit",
                            limits.max_source_files_per_artifact
                        ),
                    ));
                }
                files.push(child);
            }
        }
    }
    Ok(())
}

fn resolve_install_directory(
    package: &ComposerPackage,
    installed: Option<&InstalledPackage>,
    evidence: &PhpDependencyApiEvidence,
    approved_roots: &[PathBuf],
) -> Result<PathBuf, DependencyPackDiagnostic> {
    // Composer records `install-path` relative to `vendor/composer/`. When a
    // host approved no installed.json, fall back to the conventional layout.
    let candidate = match (
        installed.and_then(|entry| entry.install_path.as_ref()),
        &evidence.installed_json_path,
    ) {
        (Some(install_path), Some(installed_json)) => installed_json
            .parent()
            .unwrap_or(Path::new("."))
            .join(install_path),
        _ => {
            let mut found = None;
            for root in approved_roots {
                let candidate = root.join(&package.name);
                if candidate.is_dir() {
                    found = Some(candidate);
                    break;
                }
            }
            let Some(found) = found else {
                return Err(diagnostic(
                    "composer.package.not_installed",
                    None,
                    format!(
                        "Composer package {} is locked but installed under no approved vendor root",
                        package.name
                    ),
                ));
            };
            found
        }
    };

    let canonical = candidate.canonicalize().map_err(|error| {
        diagnostic(
            "composer.package.install_path",
            Some(&candidate),
            format!(
                "could not canonicalize the install path for {}: {error}",
                package.name
            ),
        )
    })?;
    if !canonical.is_dir() {
        return Err(diagnostic(
            "composer.package.install_path_not_directory",
            Some(&canonical),
            format!(
                "Composer install path for {} is not a directory",
                package.name
            ),
        ));
    }
    if !approved_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        return Err(diagnostic(
            "composer.package.outside_roots",
            Some(&canonical),
            format!(
                "Composer package {} is installed outside every approved vendor root",
                package.name
            ),
        ));
    }
    Ok(canonical)
}

/// Decode the approved `installed.json`, when the host declared one.
fn read_installed_manifest(
    evidence: &PhpDependencyApiEvidence,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<InstalledManifest>, DependencyPackDiagnostic> {
    let Some(path) = &evidence.installed_json_path else {
        return Ok(None);
    };
    let Some(expected_digest) = &evidence.installed_json_sha256 else {
        return Err(diagnostic(
            "composer.evidence.missing_installed_digest",
            Some(path),
            "Composer installed.json evidence must declare its digest",
        ));
    };
    if !is_lower_sha256(expected_digest) {
        return Err(diagnostic(
            "composer.evidence.invalid_installed_digest",
            Some(path),
            "Composer installed.json digest must be lowercase SHA-256",
        ));
    }
    let artifact = read_evidence_file_with_budget(path, limits, evidence_bytes_read, cancellation)?;
    if artifact.sha256() != expected_digest {
        return Err(diagnostic(
            "composer.evidence.installed_digest_mismatch",
            Some(path),
            format!(
                "installed.json digest {} does not match configured digest {expected_digest}",
                artifact.sha256()
            ),
        ));
    }
    serde_json::from_slice(artifact.bytes())
        .map(Some)
        .map_err(|error| {
            diagnostic(
                "composer.evidence.installed_decode",
                Some(path),
                format!("could not decode installed.json: {error}"),
            )
        })
}

fn canonical_approved_roots(
    evidence: &PhpDependencyApiEvidence,
) -> Result<Vec<PathBuf>, DependencyPackDiagnostic> {
    let roots = evidence
        .approved_vendor_roots
        .iter()
        .map(|root| {
            root.canonicalize().map_err(|error| {
                diagnostic(
                    "composer.evidence.vendor_root",
                    Some(root),
                    format!("could not canonicalize approved Composer vendor root: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if roots.iter().any(|root| !root.is_dir()) {
        return Err(diagnostic(
            "composer.evidence.vendor_root_not_directory",
            None,
            "approved Composer vendor roots must be directories",
        ));
    }
    Ok(roots)
}

fn evidence_paths_from_root(
    root: &Path,
    evidence: &PhpDependencyApiEvidence,
) -> PhpDependencyApiEvidence {
    let mut resolved = evidence.clone();
    resolved.lockfile_path = resolve_path(root, &resolved.lockfile_path);
    resolved.installed_json_path = resolved
        .installed_json_path
        .map(|path| resolve_path(root, &path));
    for vendor_root in &mut resolved.approved_vendor_roots {
        *vendor_root = resolve_path(root, vendor_root);
    }
    resolved
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn normalize_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::ParentDir => return None,
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

fn is_php_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("php"))
}

fn sort_and_dedup(files: &mut Vec<PathBuf>) {
    files.sort();
    files.dedup();
}

fn read_evidence_file_with_budget(
    path: &Path,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<crate::analyzer::semantic_model::ExactArtifact, DependencyPackDiagnostic> {
    let remaining = limits
        .max_total_artifact_bytes
        .saturating_sub(*evidence_bytes_read);
    if remaining == 0 {
        return Err(diagnostic(
            "limit.total_artifact_bytes",
            Some(path),
            format!(
                "Composer dependency evidence exceeds the {} byte aggregate limit",
                limits.max_total_artifact_bytes
            ),
        ));
    }
    let producer_limits = ArtifactProducerLimits {
        max_artifact_bytes: limits.producer.max_artifact_bytes.min(remaining),
        ..limits.producer
    };
    let artifact = read_exact_artifact_while(path, &producer_limits, || is_cancelled(cancellation))
        .map_err(|producer| producer_diagnostic(path, producer))?;
    *evidence_bytes_read = evidence_bytes_read.saturating_add(artifact.bytes().len() as u64);
    Ok(artifact)
}

#[derive(Debug, Deserialize)]
struct ComposerLockfile {
    #[serde(default)]
    packages: Vec<ComposerPackage>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<ComposerPackage>,
}

#[derive(Debug, Deserialize)]
struct ComposerPackage {
    name: String,
    version: String,
    #[serde(default, rename = "type")]
    package_type: Option<String>,
    #[serde(default)]
    dist: Option<ComposerReference>,
    #[serde(default)]
    source: Option<ComposerReference>,
    #[serde(default)]
    autoload: ComposerAutoload,
}

impl ComposerPackage {
    fn reference(&self) -> Option<&str> {
        self.dist
            .as_ref()
            .and_then(|dist| dist.reference.as_deref())
            .or_else(|| {
                self.source
                    .as_ref()
                    .and_then(|source| source.reference.as_deref())
            })
    }
}

#[derive(Debug, Deserialize)]
struct ComposerReference {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    shasum: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ComposerAutoload {
    #[serde(default, rename = "psr-4")]
    psr4: HashMap<String, ComposerAutoloadTarget>,
    #[serde(default, rename = "psr-0")]
    psr0: HashMap<String, ComposerAutoloadTarget>,
    #[serde(default)]
    classmap: Vec<PathBuf>,
    #[serde(default)]
    files: Vec<PathBuf>,
}

/// A PSR-4 prefix maps to one path or to several.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ComposerAutoloadTarget {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl ComposerAutoloadTarget {
    fn paths(&self) -> &[PathBuf] {
        match self {
            Self::One(path) => std::slice::from_ref(path),
            Self::Many(paths) => paths,
        }
    }
}

#[derive(Debug, Deserialize)]
struct InstalledManifest {
    #[serde(default)]
    packages: Vec<InstalledPackage>,
}

#[derive(Debug, Deserialize)]
struct InstalledPackage {
    #[serde(flatten)]
    package: ComposerPackage,
    #[serde(default, rename = "install-path")]
    install_path: Option<PathBuf>,
}

/// The workspace file that pins an exact PHP interpreter line, by the
/// phpenv/asdf convention.
const PHP_VERSION_FILE_NAME: &str = ".php-version";

/// Composer's own manifest, which states the platform the project targets in
/// `config.platform.php` and the versions it supports in `require.php`.
const COMPOSER_MANIFEST_FILE_NAME: &str = "composer.json";

/// The toolchain name a PHP runtime pack's activation selector matches.
const PHP_TOOLCHAIN_NAME: &str = "php";

/// The ecosystem term a PHP *runtime* dependency publishes. The runtime is not
/// a Composer package, so it never carries the `composer` ecosystem.
const PHP_RUNTIME_ECOSYSTEM: &str = "php";

const MAX_PHP_TOOLCHAIN_DECLARATION_BYTES: u64 = 256 * 1024;

/// Resolve the PHP runtime dependency a workspace *declares* rather than
/// installs: an exact interpreter pin read from `.php-version`, from
/// `composer.json`'s `config.platform.php`, or from the provable inclusive
/// lower bound of `composer.json`'s `require.php` constraint.
///
/// The dependency carries no artifacts on purpose. Preparation serves an
/// artifact-less dependency from a compatible installed pack, which is what
/// selects a released PHP builtin declaration pack, exactly as a declared
/// `.python-version` selects the released typeshed pack. No interpreter is
/// discovered, executed, or consulted; the declaration files are ordinary
/// workspace files that Composer dependency invalidation already watches.
///
/// A declaration this cannot read exactly is an attributable refusal rather
/// than a guessed pin: guessing would let a pack prove a name absent for an
/// interpreter the workspace actually supports.
fn resolve_declared_php_runtime_dependency(
    project_root: &Path,
    inputs_considered: &mut usize,
) -> Result<Option<ResolvedDependency>, DependencyPackDiagnostic> {
    let version_file = project_root.join(PHP_VERSION_FILE_NAME);
    if let Some(source) = read_bounded_declaration_file(&version_file).map_err(|message| {
        declaration_diagnostic("php.toolchain.version_file", &version_file, message)
    })? {
        *inputs_considered += 1;
        let declared = source
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .ok_or_else(|| {
                declaration_diagnostic(
                    "php.toolchain.version_file",
                    &version_file,
                    "`.php-version` declares no version line".to_owned(),
                )
            })?;
        let version = parse_exact_php_version(declared).ok_or_else(|| {
            declaration_diagnostic(
                "php.toolchain.version_file",
                &version_file,
                format!(
                    "`.php-version` declaration {declared:?} is not an exact PHP version \
                     (expected MAJOR.MINOR or MAJOR.MINOR.PATCH)"
                ),
            )
        })?;
        return Ok(Some(declared_php_runtime_dependency(
            version,
            PHP_VERSION_FILE_NAME,
            declared,
        )));
    }

    let manifest_path = project_root.join(COMPOSER_MANIFEST_FILE_NAME);
    let Some(source) = read_bounded_declaration_file(&manifest_path).map_err(|message| {
        declaration_diagnostic("php.toolchain.composer_manifest", &manifest_path, message)
    })?
    else {
        return Ok(None);
    };
    *inputs_considered += 1;
    let manifest: ComposerManifest = serde_json::from_str(&source).map_err(|error| {
        declaration_diagnostic(
            "php.toolchain.composer_manifest",
            &manifest_path,
            format!("could not decode composer.json: {error}"),
        )
    })?;
    // `config.platform.php` is Composer's own exact statement of the platform
    // it resolved against, so it outranks the range the project merely
    // supports.
    if let Some(platform) = manifest
        .config
        .as_ref()
        .and_then(|config| config.platform.as_ref())
        .and_then(|platform| platform.php.as_ref())
    {
        let version = parse_exact_php_version(platform).ok_or_else(|| {
            declaration_diagnostic(
                "php.toolchain.platform",
                &manifest_path,
                format!(
                    "composer.json config.platform.php {platform:?} is not an exact PHP version"
                ),
            )
        })?;
        return Ok(Some(declared_php_runtime_dependency(
            version,
            "composer.json config.platform.php",
            platform,
        )));
    }
    let Some(requirement) = manifest
        .require
        .as_ref()
        .and_then(|require| require.get(PHP_TOOLCHAIN_NAME))
    else {
        return Ok(None);
    };
    let version = php_constraint_lower_bound(requirement).map_err(|message| {
        declaration_diagnostic("php.toolchain.require", &manifest_path, message)
    })?;
    Ok(Some(declared_php_runtime_dependency(
        version,
        "composer.json require.php",
        requirement,
    )))
}

#[derive(Debug, Deserialize)]
struct ComposerManifest {
    #[serde(default)]
    require: Option<HashMap<String, String>>,
    #[serde(default)]
    config: Option<ComposerManifestConfig>,
}

#[derive(Debug, Deserialize)]
struct ComposerManifestConfig {
    #[serde(default)]
    platform: Option<ComposerManifestPlatform>,
}

#[derive(Debug, Deserialize)]
struct ComposerManifestPlatform {
    #[serde(default)]
    php: Option<String>,
}

/// Read one workspace declaration file. Absent means "the workspace declares
/// nothing here" and is not a diagnostic.
fn read_bounded_declaration_file(path: &Path) -> Result<Option<String>, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect declaration file: {error}")),
    };
    if !metadata.is_file() || metadata.len() > MAX_PHP_TOOLCHAIN_DECLARATION_BYTES {
        return Err(format!(
            "declaration file is not a regular file within \
             {MAX_PHP_TOOLCHAIN_DECLARATION_BYTES} bytes"
        ));
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|error| format!("could not read declaration file: {error}"))
}

/// Parse a plain dotted numeric PHP version with one to three components. A
/// missing component means `.0`: declaring `8.2` pins the line's floor, which
/// is the only version the declaration proves.
fn parse_exact_php_version(text: &str) -> Option<Version> {
    let text = text.trim();
    let mut components = text.split('.').map(|component| {
        (!component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| component.parse::<u64>().ok())
            .flatten()
    });
    let major = components.next().flatten()?;
    let minor = components.next().unwrap_or(Some(0))?;
    let patch = components.next().unwrap_or(Some(0))?;
    components
        .next()
        .is_none()
        .then(|| Version::new(major, minor, patch))
}

/// Pin the provable inclusive lower bound of one Composer version constraint.
///
/// Composer separates alternatives with `||` and conjuncts with a comma or a
/// space. Within one alternative, the greatest inclusive lower bound decides;
/// across alternatives, the least does, because the workspace supports all of
/// them. `^`, `~`, `>=`, `=` and a bare or wildcard version state a bound
/// directly; `<`, `<=` and `!=` never lower one and pass through
/// uninterpreted. Any clause this cannot read exactly refuses the whole
/// declaration.
fn php_constraint_lower_bound(requirement: &str) -> Result<Version, String> {
    let mut overall: Option<Version> = None;
    for alternative in requirement.split("||") {
        let mut lower: Option<Version> = None;
        let mut clauses = 0_usize;
        for clause in alternative.split([',', ' ']) {
            let clause = clause.trim();
            if clause.is_empty() {
                continue;
            }
            clauses += 1;
            let bound = if let Some(rest) = clause
                .strip_prefix("^")
                .or_else(|| clause.strip_prefix("~"))
                .or_else(|| clause.strip_prefix(">="))
                .or_else(|| clause.strip_prefix("=="))
                .or_else(|| clause.strip_prefix('='))
            {
                Some(parse_php_constraint_version(rest).ok_or_else(|| {
                    format!("php constraint clause {clause:?} does not state an exact lower bound")
                })?)
            } else if clause.starts_with("<=")
                || clause.starts_with('<')
                || clause.starts_with("!=")
            {
                None
            } else {
                Some(parse_php_constraint_version(clause).ok_or_else(|| {
                    format!("php constraint clause {clause:?} is not an interpretable version")
                })?)
            };
            if let Some(bound) = bound
                && lower.as_ref().is_none_or(|current| bound > *current)
            {
                lower = Some(bound);
            }
        }
        if clauses == 0 {
            continue;
        }
        let Some(lower) = lower else {
            return Err(format!(
                "php constraint {requirement:?} declares no provable inclusive lower bound"
            ));
        };
        if overall.as_ref().is_none_or(|current| lower < *current) {
            overall = Some(lower);
        }
    }
    overall.ok_or_else(|| {
        format!("php constraint {requirement:?} declares no provable inclusive lower bound")
    })
}

/// One constraint version, which may end in a `*` wildcard component. `8.2.*`
/// and `8.*` both floor at the version their fixed components name.
fn parse_php_constraint_version(text: &str) -> Option<Version> {
    let text = text.trim();
    let text = text
        .strip_suffix(".*")
        .or_else(|| text.strip_suffix(".x"))
        .unwrap_or(text);
    parse_exact_php_version(text)
}

fn declared_php_runtime_dependency(
    version: Version,
    source_file: &str,
    declared: &str,
) -> ResolvedDependency {
    ResolvedDependency {
        id: format!("php:runtime:declared:php:{version}"),
        evidence: SemanticModelActivationEvidence {
            language: "php".to_owned(),
            ecosystem: PHP_RUNTIME_ECOSYSTEM.to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: PHP_TOOLCHAIN_NAME.to_owned(),
                version: Some(version.clone()),
            }),
            // The workspace declares a version, not a platform or a build
            // configuration, so both stay unpinned.
            target: None,
            configuration: None,
            artifact_sha256: None,
        },
        provenance: vec![
            provenance_entry("php.toolchain_declaration", source_file),
            provenance_entry("php.declared_requirement", declared),
            provenance_entry("php.pinned_version", &version),
        ],
        artifacts: Vec::new(),
        scope: DependencyScope::Unknown,
        declared_by: None,
    }
}

fn declaration_diagnostic(
    code: &str,
    location: &Path,
    message: String,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Warning,
        code: code.to_owned(),
        dependency_id: None,
        location: Some(location.display().to_string()),
        message,
    }
}

fn provenance_entry(key: &str, value: impl ToString) -> DependencyProvenance {
    DependencyProvenance {
        key: key.to_owned(),
        value: value.to_string(),
    }
}

fn producer_diagnostic(path: &Path, producer: ProducerDiagnostic) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: match producer.severity {
            ProducerDiagnosticSeverity::Warning => DependencyPackDiagnosticSeverity::Warning,
            ProducerDiagnosticSeverity::Error => DependencyPackDiagnosticSeverity::Error,
        },
        code: producer.code,
        dependency_id: None,
        location: Some(path.to_string_lossy().into_owned()),
        message: producer.message,
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), DependencyPackDiagnostic> {
    if value.trim().is_empty() {
        return Err(diagnostic(
            "composer.evidence.empty_field",
            None,
            format!("Composer dependency evidence field {field} must not be empty"),
        ));
    }
    Ok(())
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn cancelled_diagnostic(path: Option<&Path>) -> DependencyPackDiagnostic {
    diagnostic(
        "composer.evidence.cancelled",
        path,
        "Composer dependency evidence decoding was cancelled",
    )
}

fn diagnostic(
    code: &str,
    path: Option<&Path>,
    message: impl Into<String>,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Error,
        code: code.to_owned(),
        dependency_id: None,
        location: path.map(|value| value.to_string_lossy().into_owned()),
        message: message.into(),
    }
}

/// Milestone 2 of issue #2374: the PHP runtime dependency a workspace declares.
///
/// Every case here is a file the workspace already contains. Nothing in this
/// module runs Composer or a PHP interpreter, so these tests only write files
/// and read the resolved evidence back.
#[cfg(test)]
mod declared_runtime_tests {
    use super::*;
    use crate::analyzer::{Language, TestProject};

    struct Workspace {
        _temp: tempfile::TempDir,
        project: TestProject,
    }

    fn workspace(files: &[(&str, &str)]) -> Workspace {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        for (path, source) in files {
            let absolute = root.join(path);
            std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
            std::fs::write(absolute, source).unwrap();
        }
        let project = TestProject::new(root, Language::Php);
        Workspace {
            _temp: temp,
            project,
        }
    }

    fn discover(files: &[(&str, &str)]) -> DependencyDiscoveryOutcome {
        let workspace = workspace(files);
        resolve_php_semantic_pack_dependencies(
            &PhpAnalyzerConfig::default(),
            &workspace.project,
            &DependencyPackLimits::default(),
            None,
        )
    }

    fn pinned_version(files: &[(&str, &str)]) -> String {
        let outcome = discover(files);
        assert!(outcome.complete, "{:#?}", outcome.diagnostics);
        assert_eq!(outcome.dependencies.len(), 1, "{:#?}", outcome.dependencies);
        let dependency = &outcome.dependencies[0];
        assert_eq!(dependency.evidence.language, "php");
        assert_eq!(dependency.evidence.ecosystem, "php");
        assert!(
            dependency.artifacts.is_empty(),
            "a declared runtime dependency names no artifact: {:#?}",
            dependency.artifacts
        );
        let toolchain = dependency
            .evidence
            .toolchain
            .as_ref()
            .expect("a declared runtime dependency pins a toolchain");
        assert_eq!(toolchain.name, "php");
        toolchain.version.as_ref().unwrap().to_string()
    }

    /// An exact interpreter pin outranks the range the project merely
    /// supports, and an exact platform pin outranks that range too.
    #[test]
    fn an_exact_declaration_outranks_the_supported_range() {
        assert_eq!(
            pinned_version(&[
                (".php-version", "8.3.7\n"),
                (
                    "composer.json",
                    r#"{"require":{"php":"^8.1"},"config":{"platform":{"php":"8.2.0"}}}"#
                ),
            ]),
            "8.3.7"
        );
        assert_eq!(
            pinned_version(&[(
                "composer.json",
                r#"{"require":{"php":"^8.1"},"config":{"platform":{"php":"8.2.0"}}}"#
            )]),
            "8.2.0"
        );
    }

    /// Every Composer constraint spelling this reads states one inclusive
    /// lower bound, and a missing component floors at zero.
    #[test]
    fn composer_constraints_pin_their_provable_inclusive_lower_bound() {
        for (constraint, expected) in [
            ("^8.2", "8.2.0"),
            ("~8.1.3", "8.1.3"),
            (">=8.1.3", "8.1.3"),
            ("8.2.*", "8.2.0"),
            ("8.3.1", "8.3.1"),
            (">=8.1 <9.0", "8.1.0"),
            // Two supported alternatives are both supported, so the lower one
            // is the only version the declaration proves.
            ("^7.4 || ^8.0", "7.4.0"),
        ] {
            let manifest = format!(r#"{{"require":{{"php":"{constraint}"}}}}"#);
            assert_eq!(
                pinned_version(&[("composer.json", manifest.as_str())]),
                expected,
                "constraint {constraint}"
            );
        }
    }

    /// A constraint with no readable inclusive lower bound refuses the whole
    /// declaration and says which file it refused, rather than guessing a pin
    /// a pack could later use to prove a name absent.
    #[test]
    fn an_unreadable_declaration_is_an_attributable_refusal() {
        let outcome = discover(&[("composer.json", r#"{"require":{"php":"<9.0"}}"#)]);

        assert!(!outcome.complete);
        assert!(outcome.dependencies.is_empty(), "{:#?}", outcome);
        assert_eq!(
            outcome
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            vec!["php.toolchain.require"],
            "{:#?}",
            outcome.diagnostics
        );

        let version_file = discover(&[(".php-version", "nightly\n")]);
        assert_eq!(
            version_file
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            vec!["php.toolchain.version_file"],
            "{:#?}",
            version_file.diagnostics
        );
    }

    /// A workspace that declares nothing declares nothing: no dependency, no
    /// diagnostic, and discovery stays complete.
    #[test]
    fn a_workspace_that_declares_no_php_version_resolves_nothing() {
        let outcome = discover(&[("src/App.php", "<?php\nclass App {}\n")]);

        assert!(outcome.complete, "{:#?}", outcome.diagnostics);
        assert!(outcome.dependencies.is_empty(), "{:#?}", outcome);
        assert!(outcome.diagnostics.is_empty(), "{:#?}", outcome.diagnostics);

        let no_php_key = discover(&[("composer.json", r#"{"require":{"ext-json":"*"}}"#)]);
        assert!(no_php_key.complete, "{:#?}", no_php_key.diagnostics);
        assert!(no_php_key.dependencies.is_empty(), "{:#?}", no_php_key);
    }
}
