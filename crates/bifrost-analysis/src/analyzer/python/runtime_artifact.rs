//! Bounded, passive verification of Python wheel contents against an
//! explicitly selected installed tree.

pub use super::runtime_environment::{
    PythonDeclaredEnvironmentError, SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION,
    SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION,
};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::python::external::{
    metadata_header, normalize_distribution_name, python_module_components_from_relative,
};
use crate::analyzer::semantic_model::csmi::{
    CsmiArtifactDigest, CsmiArtifactSelector, CsmiDigestAlgorithm,
};
use crate::analyzer::semantic_model::{
    DependencyPackLimits, ExactArtifact, read_exact_artifact_while,
};
pub use brokk_bifrost_core::analyzer::config::PYTHON_DECLARED_PROJECT_CONFIG_CANONICALIZATION_URI;
use brokk_bifrost_core::analyzer::config::{
    PythonRuntimeArtifactConfig, PythonRuntimeEnvironmentConfig,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonRuntimeArtifactStatus {
    ArchiveVerified,
    Incomplete,
    Unresolved,
    Conflicting,
    Cancelled,
}

/// One exact, checked PyPI coordinate and the SHA-256 of its original wheel
/// bytes. Fields stay private so profile and provider evidence share the same
/// validated identity value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PythonRuntimeArtifactIdentity {
    purl: String,
    archive_sha256: String,
}

impl PythonRuntimeArtifactIdentity {
    fn checked(purl: &str, archive_sha256: &str) -> Option<Self> {
        if !purl.starts_with("pkg:pypi/") {
            return None;
        }
        let selector = CsmiArtifactSelector {
            purl: purl.to_owned(),
            version_range: None,
            digests: vec![CsmiArtifactDigest {
                algorithm: CsmiDigestAlgorithm::Sha256,
                coverage: "artifact".to_owned(),
                canonicalization: None,
                value: archive_sha256.to_owned(),
            }],
        };
        crate::analyzer::semantic_model::csmi::python::validate_python_artifact(&selector).ok()?;
        Some(Self {
            purl: purl.to_owned(),
            archive_sha256: archive_sha256.to_owned(),
        })
    }

    /// Rebuild identity only from the exact PyPI selector and digest already
    /// validated by the profile-acquisition path.
    pub(crate) fn from_validated_profile_selector(
        purl: &str,
        archive_sha256: &str,
    ) -> Option<Self> {
        Self::checked(purl, archive_sha256)
    }

    pub(crate) fn purl(&self) -> &str {
        &self.purl
    }

    pub(crate) fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonRuntimeModuleStatus {
    BytesMatched,
    StubOnly,
    MissingInstalled,
    ContentMismatch,
    Unsupported,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonRuntimeImportStatus {
    Unresolved,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonRuntimeScanKind {
    SourceRoot,
    StandardLibraryRoot,
    InstalledRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonRuntimeFrontierKind {
    ExtraInstalledCandidate,
    SourceShadowCandidate,
    CompetingRuntimeProvider,
    NamespaceContributor,
    PackageInitializerEffects,
    CandidatePathCollision,
    CandidateIdentityUnknown,
    MissingInstalledCandidate,
    SymlinkSkipped,
    PathUnreadable,
    ScanLimit,
    ScanDepthLimit,
    ImportPathOrderUnknown,
    ImportHookSemanticsUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntimeScanSummary {
    pub environment_index: usize,
    pub artifact_index: Option<usize>,
    pub kind: PythonRuntimeScanKind,
    pub root: PathBuf,
    pub entries_visited: usize,
    pub candidates_found: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntimeFrontier {
    pub kind: PythonRuntimeFrontierKind,
    pub environment_index: usize,
    pub artifact_index: Option<usize>,
    pub root: PathBuf,
    pub path: Option<PathBuf>,
    pub import_name: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPythonRuntimeModule {
    pub import_name: Option<String>,
    pub archive_member_path: PathBuf,
    pub module_components: Vec<String>,
    pub installed_path: Option<PathBuf>,
    pub member_sha256: Option<String>,
    pub installed_sha256: Option<String>,
    pub installed_bytes_match: Option<bool>,
    pub runtime: bool,
    pub stub: bool,
    pub status: PythonRuntimeModuleStatus,
    pub import_status: PythonRuntimeImportStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPythonRuntimeArtifact {
    pub environment_index: usize,
    pub artifact_index: usize,
    pub source_root: Option<PathBuf>,
    pub archive_path: PathBuf,
    pub archive_sha256: Option<String>,
    pub(crate) identity: Option<PythonRuntimeArtifactIdentity>,
    pub installed_root: PathBuf,
    pub normalized_name: Option<String>,
    pub raw_version: Option<String>,
    pub coordinate: Option<String>,
    pub status: PythonRuntimeArtifactStatus,
    pub modules: Vec<VerifiedPythonRuntimeModule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntimeArtifactDiagnostic {
    pub code: String,
    pub environment_index: Option<usize>,
    pub artifact_index: Option<usize>,
    pub location: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonRuntimeArtifactWork {
    pub environments_considered: usize,
    pub artifacts_considered: usize,
    pub artifacts_skipped: usize,
    pub archives_read: usize,
    pub archive_bytes_read: u64,
    pub entries_considered: usize,
    pub declared_uncompressed_bytes: u64,
    pub installed_files_read: usize,
    pub installed_bytes_read: u64,
    pub declared_input_files_read: usize,
    pub declared_input_bytes_read: u64,
    pub modules_verified: usize,
    pub scan_entries_visited: usize,
    pub scan_candidates_found: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonRuntimeArtifactReport {
    pub artifacts: Vec<VerifiedPythonRuntimeArtifact>,
    pub(crate) declared_environments:
        Vec<Option<super::runtime_environment::CheckedPythonDeclaredEnvironment>>,
    pub diagnostics: Vec<PythonRuntimeArtifactDiagnostic>,
    pub suppressed_diagnostics: usize,
    pub frontiers: Vec<PythonRuntimeFrontier>,
    pub suppressed_frontiers: usize,
    pub scans: Vec<PythonRuntimeScanSummary>,
    pub work: PythonRuntimeArtifactWork,
    /// True only when every configured source and installed root was scanned
    /// within the configured bounds.
    pub scope_complete: bool,
    /// Ambient interpreter path order and hooks are outside the explicit
    /// source/installed universe, even when that configured universe is fully
    /// scanned.
    pub ambient_import_semantics_known: bool,
    /// True when the bounded configured-input acquisition completed. This
    /// does not mean any module's import binding was resolved.
    pub complete: bool,
    pub cancelled: bool,
}

#[derive(Debug)]
struct RuntimeWheelEntry {
    index: usize,
    path: PathBuf,
    import_name: Option<String>,
    components: Vec<String>,
    runtime: bool,
    stub: bool,
    duplicate: bool,
    path_supported: bool,
    unsupported: bool,
}

#[derive(Debug)]
struct RuntimeTreeCandidate {
    path: PathBuf,
    import_name: Option<String>,
    module_components: Vec<String>,
    runtime: bool,
    unsupported: bool,
}

#[derive(Debug, Default)]
struct RuntimeTreeScan {
    candidates: Vec<RuntimeTreeCandidate>,
    complete: bool,
}

fn scan_runtime_tree(
    root: &Path,
    environment_index: usize,
    artifact_index: Option<usize>,
    kind: PythonRuntimeScanKind,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    report: &mut PythonRuntimeArtifactReport,
) -> RuntimeTreeScan {
    let mut scan = RuntimeTreeScan::default();
    let mut pending = vec![(PathBuf::new(), 0_usize)];
    let mut summary = PythonRuntimeScanSummary {
        environment_index,
        artifact_index,
        kind,
        root: root.to_path_buf(),
        entries_visited: 0,
        candidates_found: 0,
        complete: true,
    };
    let mut stopped = false;
    let mut folded_candidate_paths = HashSet::new();
    while let Some((relative_directory, depth)) = pending.pop() {
        if is_cancelled(cancellation) {
            summary.complete = false;
            report.cancelled = true;
            report.scope_complete = false;
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::PathUnreadable,
                    environment_index,
                    artifact_index,
                    root: root.to_path_buf(),
                    path: Some(root.join(&relative_directory)),
                    import_name: None,
                    message: "runtime-tree scan was cancelled before this directory was read"
                        .to_owned(),
                },
            );
            break;
        }
        let directory = root.join(&relative_directory);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                summary.complete = false;
                report.scope_complete = false;
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::PathUnreadable,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(directory.clone()),
                        import_name: None,
                        message: format!("could not read runtime-tree directory: {error}"),
                    },
                );
                continue;
            }
        };
        for entry in entries {
            if is_cancelled(cancellation) {
                summary.complete = false;
                report.cancelled = true;
                report.scope_complete = false;
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::PathUnreadable,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(directory.clone()),
                        import_name: None,
                        message:
                            "runtime-tree scan was cancelled before all directory entries were read"
                                .to_owned(),
                    },
                );
                stopped = true;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    summary.complete = false;
                    report.scope_complete = false;
                    push_frontier(
                        report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::PathUnreadable,
                            environment_index,
                            artifact_index,
                            root: root.to_path_buf(),
                            path: Some(directory.clone()),
                            import_name: None,
                            message: format!("could not enumerate runtime-tree entry: {error}"),
                        },
                    );
                    continue;
                }
            };
            summary.entries_visited += 1;
            report.work.scan_entries_visited += 1;
            if summary.entries_visited > limits.max_source_files_per_artifact {
                summary.complete = false;
                report.scope_complete = false;
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::ScanLimit,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(entry.path()),
                        import_name: None,
                        message: format!(
                            "runtime-tree scan reached entry limit {}",
                            limits.max_source_files_per_artifact
                        ),
                    },
                );
                stopped = true;
                break;
            }
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    summary.complete = false;
                    report.scope_complete = false;
                    push_frontier(
                        report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::PathUnreadable,
                            environment_index,
                            artifact_index,
                            root: root.to_path_buf(),
                            path: Some(path),
                            import_name: None,
                            message: format!("could not inspect runtime-tree entry: {error}"),
                        },
                    );
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                summary.complete = false;
                report.scope_complete = false;
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::SymlinkSkipped,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(path),
                        import_name: None,
                        message: "runtime-tree symlink was not followed".to_owned(),
                    },
                );
                continue;
            }
            let relative = match path.strip_prefix(root) {
                Ok(relative) => relative.to_path_buf(),
                Err(_) => {
                    summary.complete = false;
                    report.scope_complete = false;
                    push_frontier(
                        report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::PathUnreadable,
                            environment_index,
                            artifact_index,
                            root: root.to_path_buf(),
                            path: Some(path),
                            import_name: None,
                            message: "runtime-tree entry escaped its canonical scan root"
                                .to_owned(),
                        },
                    );
                    continue;
                }
            };
            if metadata.is_dir() {
                let next_depth = depth + 1;
                if next_depth > limits.max_source_path_depth {
                    summary.complete = false;
                    report.scope_complete = false;
                    push_frontier(
                        report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::ScanDepthLimit,
                            environment_index,
                            artifact_index,
                            root: root.to_path_buf(),
                            path: Some(path),
                            import_name: None,
                            message: format!(
                                "runtime-tree scan reached path depth limit {}",
                                limits.max_source_path_depth
                            ),
                        },
                    );
                } else {
                    pending.push((relative, next_depth));
                }
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let source_kind = python_source_kind(&relative);
            let unsupported = is_unsupported_runtime_member(&relative);
            let Some((runtime, _stub)) = source_kind.or(unsupported.then_some((true, false)))
            else {
                continue;
            };
            let components = python_module_components_from_relative(&relative);
            let module_components = components.unwrap_or_default();
            let import_name = (!module_components.is_empty()).then(|| module_components.join("."));
            if let Some(path_key) = relative.to_str().map(str::to_ascii_lowercase)
                && !folded_candidate_paths.insert(path_key)
            {
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::CandidatePathCollision,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(path.clone()),
                        import_name: import_name.clone(),
                        message: "runtime candidate paths collide on a case-insensitive filesystem"
                            .to_owned(),
                    },
                );
            }
            if import_name.is_none() {
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::CandidateIdentityUnknown,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(path),
                        import_name: None,
                        message:
                            "runtime candidate path cannot be mapped to a structured Python module"
                                .to_owned(),
                    },
                );
            }
            summary.candidates_found += 1;
            report.work.scan_candidates_found += 1;
            scan.candidates.push(RuntimeTreeCandidate {
                path: relative,
                import_name,
                module_components,
                runtime,
                unsupported,
            });
        }
        if stopped {
            break;
        }
    }
    if !summary.complete {
        report.scope_complete = false;
    }
    scan.complete = summary.complete;
    report.scans.push(summary);
    record_package_frontiers(
        &scan,
        root,
        environment_index,
        artifact_index,
        kind,
        limits,
        report,
    );
    scan
}

fn record_package_frontiers(
    scan: &RuntimeTreeScan,
    root: &Path,
    environment_index: usize,
    artifact_index: Option<usize>,
    kind: PythonRuntimeScanKind,
    limits: &DependencyPackLimits,
    report: &mut PythonRuntimeArtifactReport,
) {
    let initializers = scan
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.runtime
                && candidate
                    .path
                    .file_name()
                    .is_some_and(|name| name == "__init__.py")
        })
        .filter_map(|candidate| candidate.path.parent().map(Path::to_path_buf))
        .collect::<HashSet<_>>();
    let mut reported = HashSet::new();
    for candidate in scan.candidates.iter().filter(|candidate| candidate.runtime) {
        let mut parent = candidate.path.parent();
        while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
            if initializers.contains(directory) {
                if reported.insert((0_u8, directory.to_path_buf(), candidate.import_name.clone())) {
                    push_frontier(
                        report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::PackageInitializerEffects,
                            environment_index,
                            artifact_index,
                            root: root.to_path_buf(),
                            path: Some(root.join(directory).join("__init__.py")),
                            import_name: candidate.import_name.clone(),
                            message:
                                "package initializer body and decorator effects are not inspected"
                                    .to_owned(),
                        },
                    );
                }
            } else if reported.insert((
                1_u8,
                directory.to_path_buf(),
                candidate.import_name.clone(),
            )) {
                push_frontier(
                    report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::NamespaceContributor,
                        environment_index,
                        artifact_index,
                        root: root.to_path_buf(),
                        path: Some(root.join(directory)),
                        import_name: candidate.import_name.clone(),
                        message: format!(
                            "{} tree has a Python descendant under a directory without __init__.py",
                            match kind {
                                PythonRuntimeScanKind::SourceRoot => "source",
                                PythonRuntimeScanKind::StandardLibraryRoot => "standard-library",
                                PythonRuntimeScanKind::InstalledRoot => "installed",
                            }
                        ),
                    },
                );
            }
            parent = directory.parent();
        }
    }
}

fn compare_runtime_universe(
    artifact: &mut VerifiedPythonRuntimeArtifact,
    source_root: Option<&Path>,
    source_candidates: &[RuntimeTreeCandidate],
    installed_candidates: &[RuntimeTreeCandidate],
    limits: &DependencyPackLimits,
    report: &mut PythonRuntimeArtifactReport,
) {
    let environment_index = artifact.environment_index;
    let artifact_index = artifact.artifact_index;
    let installed_root = &artifact.installed_root;
    let modules = &mut artifact.modules;
    let archive_runtime_paths = modules
        .iter()
        .filter(|module| module.runtime)
        .map(|module| module.archive_member_path.clone())
        .collect::<HashSet<_>>();
    for candidate in installed_candidates {
        if !candidate.runtime || archive_runtime_paths.contains(&candidate.path) {
            continue;
        }
        push_frontier(
            report,
            limits,
            PythonRuntimeFrontier {
                kind: PythonRuntimeFrontierKind::ExtraInstalledCandidate,
                environment_index,
                artifact_index: Some(artifact_index),
                root: installed_root.to_path_buf(),
                path: Some(installed_root.join(&candidate.path)),
                import_name: candidate.import_name.clone(),
                message: if candidate.unsupported {
                    "installed tree has an additional native or bytecode runtime candidate outside the wheel's pure-source members".to_owned()
                } else {
                    "installed runtime tree contains an additional path outside this wheel's runtime members".to_owned()
                },
            },
        );
        let affected_imports = modules
            .iter()
            .filter(|module| {
                module.runtime
                    && module_components_prefix(
                        &candidate.module_components,
                        &module.module_components,
                    )
            })
            .filter_map(|module| module.import_name.clone())
            .collect::<HashSet<_>>();
        for import_name in affected_imports {
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::ExtraInstalledCandidate,
                    environment_index,
                    artifact_index: Some(artifact_index),
                    root: installed_root.to_path_buf(),
                    path: Some(installed_root.join(&candidate.path)),
                    import_name: Some(import_name.clone()),
                    message: "additional installed candidate can shadow this wheel module within the configured universe".to_owned(),
                },
            );
            for module in modules.iter_mut().filter(|module| {
                module.runtime && module.import_name.as_deref() == Some(import_name.as_str())
            }) {
                module.import_status = PythonRuntimeImportStatus::Conflict;
            }
        }
    }
    for candidate in source_candidates {
        if !candidate.runtime {
            continue;
        }
        let affected_imports = modules
            .iter()
            .filter(|module| {
                module.runtime
                    && module_components_prefix(
                        &candidate.module_components,
                        &module.module_components,
                    )
            })
            .filter_map(|module| module.import_name.clone())
            .collect::<HashSet<_>>();
        for import_name in affected_imports {
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::SourceShadowCandidate,
                    environment_index,
                    artifact_index: Some(artifact_index),
                    root: source_root.unwrap_or(installed_root).to_path_buf(),
                    path: Some(source_root.unwrap_or(installed_root).join(&candidate.path)),
                    import_name: Some(import_name.clone()),
                    message: "source-root Python candidate may precede or shadow this wheel module"
                        .to_owned(),
                },
            );
            for module in modules.iter_mut().filter(|module| {
                module.runtime && module.import_name.as_deref() == Some(import_name.as_str())
            }) {
                module.import_status = PythonRuntimeImportStatus::Conflict;
            }
        }
    }
    let installed_runtime_paths = installed_candidates
        .iter()
        .filter(|candidate| candidate.runtime)
        .map(|candidate| candidate.path.as_path())
        .collect::<HashSet<_>>();
    for module in modules.iter().filter(|module| module.runtime) {
        if !installed_runtime_paths.contains(module.archive_member_path.as_path()) {
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::MissingInstalledCandidate,
                    environment_index,
                    artifact_index: Some(artifact_index),
                    root: installed_root.to_path_buf(),
                    path: Some(installed_root.join(&module.archive_member_path)),
                    import_name: module.import_name.clone(),
                    message:
                        "wheel runtime path was not observed in the bounded installed-root scan"
                            .to_owned(),
                },
            );
        }
    }
    let mut by_import = HashMap::<String, Vec<usize>>::new();
    for (index, module) in modules.iter().enumerate() {
        if module.runtime
            && let Some(import_name) = module.import_name.as_deref()
        {
            by_import
                .entry(import_name.to_owned())
                .or_default()
                .push(index);
        }
    }
    for (import_name, indices) in by_import {
        if indices.len() < 2 {
            continue;
        }
        for index in indices {
            modules[index].import_status = PythonRuntimeImportStatus::Conflict;
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::CandidatePathCollision,
                    environment_index,
                    artifact_index: Some(artifact_index),
                    root: installed_root.to_path_buf(),
                    path: Some(modules[index].archive_member_path.clone()),
                    import_name: Some(import_name.to_owned()),
                    message: "multiple archive paths map to the same import name".to_owned(),
                },
            );
        }
    }
}

fn module_components_prefix(prefix: &[String], module: &[String]) -> bool {
    !prefix.is_empty() && module.starts_with(prefix)
}

/// Produce the portable projectConfig condition for the supported declared
/// launch inputs and their current root contents. This checks the descriptor
/// and exact input bytes without executing an interpreter or dependency code.
pub fn python_declared_environment_project_config(
    workspace: &Path,
    environment: &PythonRuntimeEnvironmentConfig,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<crate::analyzer::semantic_model::csmi::CsmiArtifactDigest, PythonDeclaredEnvironmentError>
{
    Ok(
        acquire_python_declared_environment(workspace, environment, limits, cancellation)?
            .0
            .project_config()
            .clone(),
    )
}

/// Acquire the content inventory before the declared-environment producer can
/// mint projectConfig evidence. No caller-supplied digest closes a root scan.
pub(crate) fn acquire_python_declared_environment(
    workspace: &Path,
    environment: &PythonRuntimeEnvironmentConfig,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<
    (
        super::runtime_environment::CheckedPythonDeclaredEnvironment,
        usize,
        u64,
    ),
    super::runtime_environment::PythonDeclaredEnvironmentError,
> {
    use super::runtime_environment::{
        PythonDeclaredEnvironmentError as Error, PythonDeclaredRootInventory,
    };
    let workspace = workspace.canonicalize().map_err(|source| Error::Io {
        path: workspace.to_path_buf(),
        source,
    })?;
    let declared = environment
        .declared_environment
        .as_ref()
        .ok_or(Error::MissingDeclaredEnvironment)?;
    if declared.root_slots.len() > limits.max_source_files_per_artifact {
        return Err(Error::LimitExceeded {
            resource: "declared root slots",
            limit: limits.max_source_files_per_artifact as u64,
        });
    }
    let mut inventories = Vec::new();
    let mut bytes_read = 0_u64;
    let mut entries = 0_usize;
    let mut files_read = 0_usize;
    for slot in &declared.root_slots {
        let root =
            resolve_workspace_path(&workspace, &slot.path, true, limits.max_source_path_depth)
                .map_err(Error::Incomplete)?;
        let mut pending = vec![(PathBuf::new(), 0_usize)];
        let mut content = Vec::<(String, String, Option<String>)>::new();
        while let Some((relative, depth)) = pending.pop() {
            if is_cancelled(cancellation) {
                return Err(Error::Cancelled);
            }
            if depth > limits.max_source_path_depth {
                return Err(Error::LimitExceeded {
                    resource: "root depth",
                    limit: limits.max_source_path_depth as u64,
                });
            }
            let path = root.join(&relative);
            let metadata = fs::symlink_metadata(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() {
                return Err(Error::Symlink(path));
            }
            let relative_name = relative
                .to_str()
                .ok_or_else(|| Error::Incomplete("root inventory path is not Unicode".into()))?
                .replace('\\', "/");
            entries += 1;
            if entries > limits.max_source_files_per_artifact {
                return Err(Error::LimitExceeded {
                    resource: "root entries",
                    limit: limits.max_source_files_per_artifact as u64,
                });
            }
            if metadata.is_dir() {
                content.push(("directory".into(), relative_name, None));
                for entry in fs::read_dir(&path).map_err(|source| Error::Io {
                    path: path.clone(),
                    source,
                })? {
                    let entry = entry.map_err(|source| Error::Io {
                        path: path.clone(),
                        source,
                    })?;
                    if entries.saturating_add(pending.len()) >= limits.max_source_files_per_artifact
                    {
                        return Err(Error::LimitExceeded {
                            resource: "root entries",
                            limit: limits.max_source_files_per_artifact as u64,
                        });
                    }
                    pending.push((relative.join(entry.file_name()), depth + 1));
                }
            } else if metadata.is_file() {
                let mut producer = limits.producer;
                producer.max_artifact_bytes = producer
                    .max_artifact_bytes
                    .min(limits.max_total_artifact_bytes.saturating_sub(bytes_read));
                if metadata.len() > producer.max_artifact_bytes {
                    return Err(Error::LimitExceeded {
                        resource: "root bytes",
                        limit: producer.max_artifact_bytes,
                    });
                }
                let exact =
                    read_exact_artifact_while(&path, &producer, || is_cancelled(cancellation))
                        .map_err(|diagnostic| {
                            if is_cancelled(cancellation) {
                                Error::Cancelled
                            } else {
                                Error::Incomplete(format!(
                                    "root content acquisition failed: {diagnostic:?}"
                                ))
                            }
                        })?;
                bytes_read += exact.bytes().len() as u64;
                files_read += 1;
                content.push((
                    "file".into(),
                    relative_name,
                    Some(lower_hex_string(&sha256_bytes(exact.bytes()))),
                ));
            } else {
                return Err(Error::UnsupportedPathKind {
                    path,
                    expected: "regular file or directory",
                });
            }
        }
        content.sort_unstable();
        let bytes = crate::analyzer::semantic_model::csmi::canonical_json(&content)
            .map_err(|error| Error::Canonicalization(error.to_string()))?;
        inventories.push(PythonDeclaredRootInventory {
            ordinal: slot.ordinal,
            slot_id: slot.slot_id.clone(),
            role: slot.role,
            inventory_sha256: lower_hex_string(&sha256_bytes(&bytes)),
        });
    }
    let mut remaining_limits = *limits;
    remaining_limits.max_total_artifact_bytes =
        limits.max_total_artifact_bytes.saturating_sub(bytes_read);
    let proof = super::runtime_environment::produce_python_declared_environment(
        &workspace,
        environment,
        &inventories,
        &remaining_limits,
        cancellation,
    )?;
    Ok((proof, files_read, bytes_read))
}

/// Verify each configured wheel against its explicit installed root. This
/// reads exact bytes and metadata only; it never imports or executes a wheel.
pub fn verify_python_runtime_artifacts(
    workspace_root: &Path,
    environments: &[PythonRuntimeEnvironmentConfig],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> PythonRuntimeArtifactReport {
    let mut report = PythonRuntimeArtifactReport {
        complete: true,
        scope_complete: true,
        // This provider never executes or interrogates an interpreter. A fully
        // scanned explicit universe is useful evidence, but ambient semantics
        // remain unknown in every configuration.
        ambient_import_semantics_known: false,
        declared_environments: vec![None; environments.len().min(limits.max_dependencies)],
        ..PythonRuntimeArtifactReport::default()
    };
    let workspace = match workspace_root.canonicalize() {
        Ok(workspace) if workspace.is_dir() => workspace,
        Ok(_) => {
            push_diagnostic(
                &mut report,
                limits,
                "python.runtime.workspace",
                None,
                None,
                Some(workspace_root.to_path_buf()),
                "workspace root is not a directory".to_owned(),
            );
            return report;
        }
        Err(error) => {
            push_diagnostic(
                &mut report,
                limits,
                "python.runtime.workspace",
                None,
                None,
                Some(workspace_root.to_path_buf()),
                format!("could not canonicalize workspace root: {error}"),
            );
            return report;
        }
    };

    let environment_limit = environments.len().min(limits.max_dependencies);
    if environment_limit < environments.len() {
        report.complete = false;
        report.scope_complete = false;
        report.work.artifacts_skipped = environments[environment_limit..]
            .iter()
            .fold(0_usize, |total, environment| {
                total.saturating_add(environment.artifacts.len())
            });
        push_diagnostic(
            &mut report,
            limits,
            "limit.python_runtime_environments",
            None,
            None,
            None,
            format!(
                "Python runtime environment count exceeds limit {}",
                limits.max_dependencies
            ),
        );
    }

    let mut configured_artifacts = HashSet::new();
    for (environment_index, environment) in environments.iter().take(environment_limit).enumerate()
    {
        report.work.environments_considered += 1;
        if is_cancelled(cancellation) {
            report.cancelled = true;
            report.complete = false;
            report.scope_complete = false;
            break;
        }

        let source_root = match resolve_workspace_path(
            &workspace,
            &environment.source_root,
            true,
            limits.max_source_path_depth,
        ) {
            Ok(path) => Some(path),
            Err(error) => {
                report.scope_complete = false;
                push_diagnostic(
                    &mut report,
                    limits,
                    "python.runtime.source_root",
                    Some(environment_index),
                    None,
                    Some(environment.source_root.clone()),
                    error,
                );
                push_frontier(
                    &mut report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::PathUnreadable,
                        environment_index,
                        artifact_index: None,
                        root: workspace.to_path_buf(),
                        path: Some(workspace.join(&environment.source_root)),
                        import_name: None,
                        message:
                            "configured source root could not be included in the scanned universe"
                                .to_owned(),
                    },
                );
                None
            }
        };
        let source_scan = source_root.as_ref().map(|root| {
            scan_runtime_tree(
                root,
                environment_index,
                None,
                PythonRuntimeScanKind::SourceRoot,
                limits,
                cancellation,
                &mut report,
            )
        });
        let mut standard_library_scans = Vec::new();
        if let Some(declared) = &environment.declared_environment {
            for slot in declared.root_slots.iter().filter(|slot| slot.role == brokk_bifrost_core::analyzer::config::PythonDeclaredRootRole::StandardLibrary) {
                match resolve_workspace_path(&workspace, &slot.path, true, limits.max_source_path_depth) {
                    Ok(root) => {
                        let scan = scan_runtime_tree(&root, environment_index, None, PythonRuntimeScanKind::StandardLibraryRoot, limits, cancellation, &mut report);
                        standard_library_scans.push((root, scan));
                    }
                    Err(error) => {
                        report.scope_complete = false;
                        push_frontier(
                            &mut report,
                            limits,
                            PythonRuntimeFrontier {
                                kind: PythonRuntimeFrontierKind::PathUnreadable,
                                environment_index,
                                artifact_index: None,
                                root: workspace.to_path_buf(),
                                path: Some(workspace.join(&slot.path)),
                                import_name: None,
                                message: error,
                            },
                        );
                    }
                }
            }
        }
        if source_root.is_none() {
            report.scans.push(PythonRuntimeScanSummary {
                environment_index,
                artifact_index: None,
                kind: PythonRuntimeScanKind::SourceRoot,
                root: workspace.join(&environment.source_root),
                entries_visited: 0,
                candidates_found: 0,
                complete: false,
            });
        }
        let frontier_root = source_root.as_deref().unwrap_or(&workspace);
        let mut declared_limits = *limits;
        declared_limits.max_total_artifact_bytes = limits.max_total_artifact_bytes.saturating_sub(
            report
                .work
                .archive_bytes_read
                .saturating_add(report.work.installed_bytes_read)
                .saturating_add(report.work.declared_input_bytes_read),
        );
        match acquire_python_declared_environment(
            &workspace,
            environment,
            &declared_limits,
            cancellation,
        ) {
            Ok((proof, root_files, root_bytes)) => {
                report.work.declared_input_files_read += root_files + proof.input_files_read();
                report.work.declared_input_bytes_read += root_bytes + proof.input_bytes_read();
                report.declared_environments[environment_index] = Some(proof);
            }
            Err(error) => {
                use super::runtime_environment::PythonDeclaredEnvironmentError as Error;
                let code = match &error {
                    Error::MissingDeclaredEnvironment => None,
                    Error::Cancelled => {
                        report.cancelled = true;
                        report.complete = false;
                        Some("python.runtime.declared_environment.cancelled")
                    }
                    Error::LimitExceeded { .. } => {
                        report.scope_complete = false;
                        report.complete = false;
                        Some("limit.python_runtime_declared_environment")
                    }
                    Error::UnsupportedLaunchSemantics { .. }
                    | Error::UnsupportedProducerVersion(_)
                    | Error::UnsupportedResolverVersion(_)
                    | Error::UnsupportedPathKind { .. } => {
                        Some("python.runtime.declared_environment.unsupported")
                    }
                    _ => Some("python.runtime.declared_environment.incomplete"),
                };
                if let Some(code) = code {
                    push_diagnostic(
                        &mut report,
                        limits,
                        code,
                        Some(environment_index),
                        None,
                        Some(frontier_root.to_path_buf()),
                        error.to_string(),
                    );
                }
                push_frontier(
                    &mut report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::ImportPathOrderUnknown,
                        environment_index,
                        artifact_index: None,
                        root: frontier_root.to_path_buf(),
                        path: None,
                        import_name: None,
                        message: "configuration does not enumerate the complete ordered interpreter import path"
                                    .to_owned(),
                    },
                );
                push_frontier(
                    &mut report,
                    limits,
                    PythonRuntimeFrontier {
                        kind: PythonRuntimeFrontierKind::ImportHookSemanticsUnknown,
                        environment_index,
                        artifact_index: None,
                        root: frontier_root.to_path_buf(),
                        path: None,
                        import_name: None,
                        message: "custom finders, decorators, and dynamic import effects are outside byte verification"
                                    .to_owned(),
                    },
                );
                if environment.declared_environment.is_some() {
                    // Failed acquisition may have consumed part of the byte budget.
                    // Do not begin another acquisition without exact accounting.
                    report.complete = false;
                    report.scope_complete = false;
                    break;
                }
            }
        }

        let artifact_limit = environment
            .artifacts
            .len()
            .min(limits.max_artifacts_per_dependency);
        if artifact_limit < environment.artifacts.len() {
            report.complete = false;
            report.scope_complete = false;
            report.work.artifacts_skipped = report
                .work
                .artifacts_skipped
                .saturating_add(environment.artifacts.len() - artifact_limit);
            push_diagnostic(
                &mut report,
                limits,
                "limit.python_runtime_artifacts",
                Some(environment_index),
                None,
                Some(environment.source_root.clone()),
                format!(
                    "Python runtime artifact count exceeds per-environment limit {}",
                    limits.max_artifacts_per_dependency
                ),
            );
        }

        for (artifact_index, config) in environment
            .artifacts
            .iter()
            .take(artifact_limit)
            .enumerate()
        {
            if is_cancelled(cancellation) {
                report.cancelled = true;
                report.complete = false;
                report.scope_complete = false;
                break;
            }
            report.work.artifacts_considered += 1;
            let mut artifact = unresolved_artifact(
                environment_index,
                artifact_index,
                source_root.clone(),
                config,
            );
            let before = report.diagnostics.len();
            let mut artifact_incomplete = source_root.is_none();

            let archive_path = match resolve_workspace_path(
                &workspace,
                &config.archive_path,
                false,
                limits.max_source_path_depth,
            ) {
                Ok(path) => {
                    artifact.archive_path = path.clone();
                    Some(path)
                }
                Err(error) => {
                    report.scope_complete = false;
                    diagnostic_for_artifact(
                        &mut report,
                        limits,
                        &artifact,
                        "python.runtime.archive_path",
                        Some(config.archive_path.clone()),
                        error,
                    );
                    push_frontier(
                        &mut report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::PathUnreadable,
                            environment_index,
                            artifact_index: Some(artifact_index),
                            root: workspace.to_path_buf(),
                            path: Some(workspace.join(&config.archive_path)),
                            import_name: None,
                            message: "configured original wheel could not be read into the candidate universe"
                                            .to_owned(),
                        },
                    );
                    artifact_incomplete = true;
                    None
                }
            };
            let installed_root = match resolve_workspace_path(
                &workspace,
                &config.installed_root,
                true,
                limits.max_source_path_depth,
            ) {
                Ok(path) => {
                    artifact.installed_root = path.clone();
                    Some(path)
                }
                Err(error) => {
                    report.scope_complete = false;
                    diagnostic_for_artifact(
                        &mut report,
                        limits,
                        &artifact,
                        "python.runtime.installed_root",
                        Some(config.installed_root.clone()),
                        error,
                    );
                    report.scans.push(PythonRuntimeScanSummary {
                        environment_index,
                        artifact_index: Some(artifact_index),
                        kind: PythonRuntimeScanKind::InstalledRoot,
                        root: workspace.join(&config.installed_root),
                        entries_visited: 0,
                        candidates_found: 0,
                        complete: false,
                    });
                    push_frontier(
                        &mut report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::PathUnreadable,
                            environment_index,
                            artifact_index: Some(artifact_index),
                            root: workspace.to_path_buf(),
                            path: Some(workspace.join(&config.installed_root)),
                            import_name: None,
                            message: "configured installed root could not be included in the scanned universe"
                                            .to_owned(),
                        },
                    );
                    artifact_incomplete = true;
                    None
                }
            };
            let installed_scan = installed_root.as_ref().map(|root| {
                scan_runtime_tree(
                    root,
                    environment_index,
                    Some(artifact_index),
                    PythonRuntimeScanKind::InstalledRoot,
                    limits,
                    cancellation,
                    &mut report,
                )
            });

            let archive_available = archive_path.is_some();
            if let (Some(archive_path), Some(installed_root)) = (archive_path, installed_root) {
                let duplicate_key = (archive_path.clone(), installed_root.clone());
                if !configured_artifacts.insert(duplicate_key) {
                    diagnostic_for_artifact(
                        &mut report,
                        limits,
                        &artifact,
                        "python.runtime.duplicate_artifact",
                        Some(archive_path.clone()),
                        "the same archive and installed root were configured more than once"
                            .to_owned(),
                    );
                    artifact_incomplete = true;
                }
                let artifact_byte_budget = limits.max_total_artifact_bytes.saturating_sub(
                    report
                        .work
                        .archive_bytes_read
                        .saturating_add(report.work.installed_bytes_read)
                        .saturating_add(report.work.declared_input_bytes_read),
                );
                let mut producer_limits = limits.producer;
                producer_limits.max_artifact_bytes =
                    producer_limits.max_artifact_bytes.min(artifact_byte_budget);
                match read_exact_artifact_while(&archive_path, &producer_limits, || {
                    is_cancelled(cancellation)
                }) {
                    Ok(exact) => {
                        report.work.archives_read += 1;
                        report.work.archive_bytes_read = report
                            .work
                            .archive_bytes_read
                            .saturating_add(exact.bytes().len() as u64);
                        artifact.archive_sha256 = Some(sha256(exact.bytes()));
                        let mut verified = verify_wheel(
                            &exact,
                            &installed_root,
                            &artifact,
                            limits,
                            cancellation,
                            &mut report,
                        );
                        artifact.normalized_name = verified.0.take();
                        artifact.raw_version = verified.1.take();
                        artifact.coordinate = verified.2.take();
                        artifact.identity = artifact
                            .coordinate
                            .as_deref()
                            .zip(artifact.archive_sha256.as_deref())
                            .and_then(|(purl, digest)| {
                                PythonRuntimeArtifactIdentity::checked(purl, digest)
                            });
                        if artifact.coordinate.is_some() && artifact.identity.is_none() {
                            diagnostic_for_artifact(
                                &mut report,
                                limits,
                                &artifact,
                                "python.runtime.identity",
                                Some(archive_path.clone()),
                                "verified wheel metadata did not produce a valid exact PyPI identity"
                                    .to_owned(),
                            );
                            artifact_incomplete = true;
                        }
                        artifact.modules = verified.3;
                        artifact_incomplete |= !verified.4;
                        artifact_incomplete |=
                            source_scan.as_ref().is_none_or(|scan| !scan.complete);
                        artifact_incomplete |=
                            installed_scan.as_ref().is_none_or(|scan| !scan.complete);
                        let source_candidates = source_scan
                            .as_ref()
                            .map_or(&[][..], |scan| scan.candidates.as_slice());
                        compare_runtime_universe(
                            &mut artifact,
                            source_root.as_deref(),
                            source_candidates,
                            &installed_scan
                                .as_ref()
                                .expect("installed scan exists after resolving its root")
                                .candidates,
                            limits,
                            &mut report,
                        );
                        for (root, scan) in &standard_library_scans {
                            artifact_incomplete |= !scan.complete;
                            compare_runtime_universe(
                                &mut artifact,
                                Some(root),
                                &scan.candidates,
                                &installed_scan
                                    .as_ref()
                                    .expect("resolved installed root")
                                    .candidates,
                                limits,
                                &mut report,
                            );
                        }
                        if report.cancelled {
                            artifact.status = PythonRuntimeArtifactStatus::Cancelled;
                        }
                    }
                    Err(diagnostic) => {
                        if diagnostic.code.starts_with("limit.") {
                            push_frontier(
                                &mut report,
                                limits,
                                PythonRuntimeFrontier {
                                    kind: PythonRuntimeFrontierKind::ScanLimit,
                                    environment_index,
                                    artifact_index: Some(artifact_index),
                                    root: workspace.to_path_buf(),
                                    path: Some(config.archive_path.clone()),
                                    import_name: None,
                                    message: "original wheel could not be read within the configured byte limit"
                                                            .to_owned(),
                                },
                            );
                        }
                        diagnostic_for_artifact(
                            &mut report,
                            limits,
                            &artifact,
                            &diagnostic.code,
                            Some(archive_path),
                            diagnostic.message,
                        );
                        artifact_incomplete = true;
                        if is_cancelled(cancellation) {
                            report.cancelled = true;
                        }
                    }
                }
            } else if !archive_available && let Some(installed_scan) = &installed_scan {
                for candidate in &installed_scan.candidates {
                    push_frontier(
                        &mut report,
                        limits,
                        PythonRuntimeFrontier {
                            kind: PythonRuntimeFrontierKind::CandidateIdentityUnknown,
                            environment_index,
                            artifact_index: Some(artifact_index),
                            root: artifact.installed_root.to_path_buf(),
                            path: Some(artifact.installed_root.join(&candidate.path)),
                            import_name: candidate.import_name.clone(),
                            message: "installed candidate could not be compared because the configured wheel is unavailable"
                                            .to_owned(),
                        },
                    );
                }
            }

            if artifact.status != PythonRuntimeArtifactStatus::Cancelled {
                artifact.status = if artifact.coordinate.is_none() {
                    PythonRuntimeArtifactStatus::Unresolved
                } else if artifact_incomplete || report.diagnostics.len() > before {
                    PythonRuntimeArtifactStatus::Incomplete
                } else {
                    PythonRuntimeArtifactStatus::ArchiveVerified
                };
            }
            report.artifacts.push(artifact);
            if report.cancelled {
                break;
            }
        }
        if report.cancelled {
            break;
        }
    }

    mark_conflicting_runtime_providers(&mut report, limits);
    report.complete &= report.scope_complete;
    report
}

fn verify_wheel(
    exact: &ExactArtifact,
    installed_root: &Path,
    artifact: &VerifiedPythonRuntimeArtifact,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    report: &mut PythonRuntimeArtifactReport,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<VerifiedPythonRuntimeModule>,
    bool,
) {
    let mut complete = true;
    let mut archive = match ZipArchive::new(Cursor::new(exact.bytes())) {
        Ok(archive) => archive,
        Err(error) => {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.invalid_wheel",
                Some(exact.path().to_path_buf()),
                format!("wheel ZIP is invalid: {error}"),
            );
            return (None, None, None, Vec::new(), false);
        }
    };
    let mut seen_paths = HashSet::new();
    let mut folded_paths = HashSet::new();
    let mut collision_paths = HashSet::new();
    let mut metadata_indices = Vec::new();
    let mut runtime_entries = Vec::new();
    let mut entries_in_archive = 0_usize;
    for index in 0..archive.len() {
        if is_cancelled(cancellation) {
            report.cancelled = true;
            report.complete = false;
            complete = false;
            break;
        }
        report.work.entries_considered += 1;
        entries_in_archive += 1;
        if entries_in_archive > limits.max_source_files_per_artifact {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "limit.python_runtime_entries",
                Some(exact.path().to_path_buf()),
                format!(
                    "wheel entry count exceeds limit {}",
                    limits.max_source_files_per_artifact
                ),
            );
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::ScanLimit,
                    environment_index: artifact.environment_index,
                    artifact_index: Some(artifact.artifact_index),
                    root: exact.path().to_path_buf(),
                    path: Some(exact.path().to_path_buf()),
                    import_name: None,
                    message: format!(
                        "wheel entry scan stopped at limit {}",
                        limits.max_source_files_per_artifact
                    ),
                },
            );
            complete = false;
            break;
        }
        let entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                diagnostic_for_artifact(
                    report,
                    limits,
                    artifact,
                    "python.runtime.zip_entry",
                    Some(exact.path().to_path_buf()),
                    format!("could not inspect wheel entry {index}: {error}"),
                );
                complete = false;
                continue;
            }
        };
        let is_dir = entry.is_dir();
        let name = entry.name().to_owned();
        let Some(path) = canonical_member_path(&name, is_dir, limits.max_source_path_depth) else {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.unsafe_member_path",
                Some(PathBuf::from(&name)),
                "wheel member path is not canonical and relative".to_owned(),
            );
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::CandidateIdentityUnknown,
                    environment_index: artifact.environment_index,
                    artifact_index: Some(artifact.artifact_index),
                    root: exact.path().to_path_buf(),
                    path: Some(PathBuf::from(&name)),
                    import_name: None,
                    message: "wheel member has an unsafe or non-canonical path".to_owned(),
                },
            );
            complete = false;
            continue;
        };
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.member_symlink",
                Some(path.clone()),
                "wheel symlink entries are unsupported".to_owned(),
            );
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::SymlinkSkipped,
                    environment_index: artifact.environment_index,
                    artifact_index: Some(artifact.artifact_index),
                    root: exact.path().to_path_buf(),
                    path: Some(path.clone()),
                    import_name: python_module_components_from_relative(&path)
                        .map(|components| components.join(".")),
                    message: "wheel symlink member was not treated as a runtime file".to_owned(),
                },
            );
            if is_python_runtime_member(&path) {
                let source_kind = python_source_kind(&path);
                let (runtime, stub) = source_kind.unwrap_or((true, false));
                let components = source_kind
                    .and_then(|_| python_module_components_from_relative(&path))
                    .unwrap_or_default();
                let import_name = (!components.is_empty()).then(|| components.join("."));
                runtime_entries.push(RuntimeWheelEntry {
                    index,
                    path,
                    import_name,
                    components,
                    runtime,
                    stub,
                    duplicate: false,
                    path_supported: false,
                    unsupported: false,
                });
            }
            complete = false;
            continue;
        }
        let canonical_name = path_to_slash_string(&path);
        let duplicate = !seen_paths.insert(canonical_name.clone());
        let folded_name = canonical_name.to_ascii_lowercase();
        let case_collision = !folded_paths.insert(folded_name.clone());
        if (duplicate || case_collision) && is_python_runtime_member(&path) {
            collision_paths.insert(folded_name);
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::CandidatePathCollision,
                    environment_index: artifact.environment_index,
                    artifact_index: Some(artifact.artifact_index),
                    root: exact.path().to_path_buf(),
                    path: Some(path.clone()),
                    import_name: python_module_components_from_relative(&path)
                        .map(|components| components.join(".")),
                    message: "wheel contains duplicate or case-colliding runtime member paths"
                        .to_owned(),
                },
            );
        }
        if duplicate {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.duplicate_member",
                Some(path.clone()),
                "wheel contains duplicate canonical member paths".to_owned(),
            );
            complete = false;
        }
        if case_collision && !duplicate {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.member_case_collision",
                Some(path.clone()),
                "wheel member paths collide on a case-insensitive filesystem".to_owned(),
            );
            complete = false;
        }

        let size = entry.size();
        let total_uncompressed_bytes = report.work.declared_uncompressed_bytes.saturating_add(size);
        if total_uncompressed_bytes > limits.max_total_artifact_bytes {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "limit.python_runtime_uncompressed_bytes",
                Some(exact.path().to_path_buf()),
                format!(
                    "wheel uncompressed size exceeds limit {}",
                    limits.max_total_artifact_bytes
                ),
            );
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::ScanLimit,
                    environment_index: artifact.environment_index,
                    artifact_index: Some(artifact.artifact_index),
                    root: exact.path().to_path_buf(),
                    path: Some(exact.path().to_path_buf()),
                    import_name: None,
                    message: format!(
                        "wheel uncompressed-entry budget reached {} bytes",
                        limits.max_total_artifact_bytes
                    ),
                },
            );
            complete = false;
            break;
        }
        report.work.declared_uncompressed_bytes = total_uncompressed_bytes;
        if is_dir {
            continue;
        }
        if path.file_name().is_some_and(|name| name == "METADATA")
            && path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".dist-info"))
        {
            metadata_indices.push(index);
            continue;
        }

        if path
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .any(|component| component.ends_with(".data"))
        {
            if is_python_runtime_member(&path) {
                diagnostic_for_artifact(
                    report,
                    limits,
                    artifact,
                    "python.runtime.data_relocation_unsupported",
                    Some(path.clone()),
                    "wheel .data relocation requires installation semantics and is unsupported"
                        .to_owned(),
                );
                complete = false;
                let (runtime, stub) = python_source_kind(&path).unwrap_or((true, false));
                runtime_entries.push(RuntimeWheelEntry {
                    index,
                    path,
                    import_name: None,
                    components: Vec::new(),
                    runtime,
                    stub,
                    duplicate,
                    path_supported: false,
                    unsupported: true,
                });
            }
            continue;
        }
        if is_unsupported_runtime_member(&path) {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.dynamic_artifact_unsupported",
                Some(path.clone()),
                "native and bytecode runtime artifacts are unsupported".to_owned(),
            );
            complete = false;
            runtime_entries.push(RuntimeWheelEntry {
                index,
                path,
                import_name: None,
                components: Vec::new(),
                runtime: true,
                stub: false,
                duplicate,
                path_supported: false,
                unsupported: true,
            });
            continue;
        }
        let (runtime, stub) = match python_source_kind(&path) {
            Some(kind) => kind,
            None => continue,
        };
        let components = python_module_components_from_relative(&path);
        if components.is_none() {
            diagnostic_for_artifact(
                report,
                limits,
                artifact,
                "python.runtime.module_path_unsupported",
                Some(path.clone()),
                "Python source path cannot be represented as an import module".to_owned(),
            );
            complete = false;
        }
        let import_name = components.as_ref().map(|components| components.join("."));
        let path_supported = components.is_some();
        runtime_entries.push(RuntimeWheelEntry {
            index,
            path,
            import_name,
            components: components.unwrap_or_default(),
            runtime,
            stub,
            duplicate,
            path_supported,
            unsupported: false,
        });
    }

    let metadata = if metadata_indices.len() == 1 {
        match read_zip_member(
            &mut archive,
            metadata_indices[0],
            limits.producer.max_artifact_bytes,
            cancellation,
        ) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(metadata) => Some(metadata),
                Err(_) => {
                    diagnostic_for_artifact(
                        report,
                        limits,
                        artifact,
                        "python.runtime.metadata_encoding",
                        Some(exact.path().to_path_buf()),
                        "wheel METADATA is not UTF-8".to_owned(),
                    );
                    complete = false;
                    None
                }
            },
            Err(ZipMemberReadError::Invalid(error)) => {
                diagnostic_for_artifact(
                    report,
                    limits,
                    artifact,
                    "python.runtime.metadata_read",
                    Some(exact.path().to_path_buf()),
                    error,
                );
                complete = false;
                None
            }
            Err(ZipMemberReadError::Cancelled) => {
                report.cancelled = true;
                report.complete = false;
                complete = false;
                None
            }
        }
    } else {
        diagnostic_for_artifact(
            report,
            limits,
            artifact,
            "python.runtime.metadata_count",
            Some(exact.path().to_path_buf()),
            format!(
                "wheel must contain exactly one dist-info METADATA file; found {}",
                metadata_indices.len()
            ),
        );
        complete = false;
        None
    };
    let (normalized_name, raw_version) = match metadata.as_deref() {
        Some(metadata) => match (
            metadata_header(metadata, "Name"),
            metadata_header(metadata, "Version"),
        ) {
            (Some(name), Some(version)) => {
                (Some(normalize_distribution_name(&name)), Some(version))
            }
            _ => {
                diagnostic_for_artifact(
                    report,
                    limits,
                    artifact,
                    "python.runtime.metadata_identity",
                    Some(exact.path().to_path_buf()),
                    "wheel METADATA must contain non-empty Name and Version fields".to_owned(),
                );
                complete = false;
                (None, None)
            }
        },
        None => (None, None),
    };
    let coordinate = normalized_name
        .as_ref()
        .zip(raw_version.as_ref())
        .map(|(name, version)| format!("pkg:pypi/{name}@{version}"));

    let mut modules = Vec::with_capacity(runtime_entries.len());
    for candidate in runtime_entries {
        if is_cancelled(cancellation) {
            report.cancelled = true;
            report.complete = false;
            complete = false;
            break;
        }
        let member_bytes = match read_zip_member(
            &mut archive,
            candidate.index,
            limits.max_total_artifact_bytes,
            cancellation,
        ) {
            Ok(bytes) => bytes,
            Err(ZipMemberReadError::Invalid(error)) => {
                diagnostic_for_artifact(
                    report,
                    limits,
                    artifact,
                    "python.runtime.member_read",
                    Some(candidate.path.clone()),
                    error,
                );
                complete = false;
                modules.push(unresolved_module(candidate));
                continue;
            }
            Err(ZipMemberReadError::Cancelled) => {
                report.cancelled = true;
                report.complete = false;
                complete = false;
                modules.push(unresolved_module(candidate));
                break;
            }
        };
        let member_sha256 = sha256(&member_bytes);
        if candidate.unsupported || !candidate.path_supported || candidate.stub {
            let status = if coordinate.is_none() || candidate.duplicate || !candidate.path_supported
            {
                PythonRuntimeModuleStatus::Unresolved
            } else if candidate.unsupported {
                PythonRuntimeModuleStatus::Unsupported
            } else {
                PythonRuntimeModuleStatus::StubOnly
            };
            modules.push(VerifiedPythonRuntimeModule {
                import_name: candidate.import_name,
                archive_member_path: candidate.path,
                module_components: candidate.components,
                installed_path: None,
                member_sha256: Some(member_sha256),
                installed_sha256: None,
                installed_bytes_match: None,
                runtime: candidate.runtime,
                stub: candidate.stub,
                status,
                import_status: PythonRuntimeImportStatus::Unresolved,
            });
            continue;
        }
        let (installed_path, installed_sha256, installed_bytes_match, status) =
            match read_installed_candidate(
                installed_root,
                &candidate.path,
                limits,
                report,
                cancellation,
            ) {
                Ok((path, bytes)) => {
                    let installed_sha256 = sha256(&bytes);
                    let matches = bytes == member_bytes;
                    if matches {
                        report.work.modules_verified += 1;
                        (
                            Some(path),
                            Some(installed_sha256),
                            Some(true),
                            PythonRuntimeModuleStatus::BytesMatched,
                        )
                    } else {
                        diagnostic_for_artifact(
                            report,
                            limits,
                            artifact,
                            "python.runtime.installed_mismatch",
                            Some(path.clone()),
                            "installed file bytes differ from the exact wheel member".to_owned(),
                        );
                        complete = false;
                        (
                            Some(path),
                            Some(installed_sha256),
                            Some(false),
                            PythonRuntimeModuleStatus::ContentMismatch,
                        )
                    }
                }
                Err(InstalledCandidateError::Missing(path)) => {
                    diagnostic_for_artifact(
                        report,
                        limits,
                        artifact,
                        "python.runtime.installed_missing",
                        Some(path),
                        "wheel member is missing from the configured installed root".to_owned(),
                    );
                    complete = false;
                    (
                        None,
                        None,
                        Some(false),
                        PythonRuntimeModuleStatus::MissingInstalled,
                    )
                }
                Err(InstalledCandidateError::Invalid(path, error)) => {
                    diagnostic_for_artifact(
                        report,
                        limits,
                        artifact,
                        "python.runtime.installed_path",
                        Some(path),
                        error,
                    );
                    complete = false;
                    (None, None, None, PythonRuntimeModuleStatus::Unresolved)
                }
                Err(InstalledCandidateError::Cancelled) => {
                    report.cancelled = true;
                    report.complete = false;
                    complete = false;
                    (None, None, None, PythonRuntimeModuleStatus::Unresolved)
                }
            };
        modules.push(VerifiedPythonRuntimeModule {
            import_name: candidate.import_name,
            archive_member_path: candidate.path,
            module_components: candidate.components,
            installed_path,
            member_sha256: Some(member_sha256),
            installed_sha256,
            installed_bytes_match,
            runtime: candidate.runtime,
            stub: candidate.stub,
            status: if coordinate.is_none() || candidate.duplicate {
                PythonRuntimeModuleStatus::Unresolved
            } else {
                status
            },
            import_status: PythonRuntimeImportStatus::Unresolved,
        });
        if report.cancelled {
            break;
        }
    }

    for module in &mut modules {
        let folded_path = path_to_slash_string(&module.archive_member_path).to_ascii_lowercase();
        if collision_paths.contains(&folded_path) {
            module.status = PythonRuntimeModuleStatus::Unresolved;
            if module.runtime {
                module.import_status = PythonRuntimeImportStatus::Conflict;
            }
        }
    }

    (normalized_name, raw_version, coordinate, modules, complete)
}

enum InstalledCandidateError {
    Missing(PathBuf),
    Invalid(PathBuf, String),
    Cancelled,
}

fn read_installed_candidate(
    installed_root: &Path,
    relative: &Path,
    limits: &DependencyPackLimits,
    report: &mut PythonRuntimeArtifactReport,
    cancellation: Option<&CancellationToken>,
) -> Result<(PathBuf, Vec<u8>), InstalledCandidateError> {
    let path = installed_root.join(relative);
    let mut current = installed_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(InstalledCandidateError::Invalid(
                path,
                "installed candidate path contains a non-normal component".to_owned(),
            ));
        };
        current.push(segment);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(InstalledCandidateError::Missing(path));
            }
            Err(error) => {
                return Err(InstalledCandidateError::Invalid(
                    current,
                    format!("could not inspect installed path component: {error}"),
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(InstalledCandidateError::Invalid(
                current,
                "installed candidate contains a symlink path component".to_owned(),
            ));
        }
    }
    let canonical = path.canonicalize().map_err(|error| {
        InstalledCandidateError::Invalid(
            path.clone(),
            format!("could not canonicalize installed candidate: {error}"),
        )
    })?;
    if !canonical.starts_with(installed_root) {
        return Err(InstalledCandidateError::Invalid(
            canonical,
            "installed candidate escapes its configured root".to_owned(),
        ));
    }
    if !canonical.is_file() {
        return Err(InstalledCandidateError::Invalid(
            canonical,
            "installed candidate is not a regular file".to_owned(),
        ));
    }
    if is_cancelled(cancellation) {
        return Err(InstalledCandidateError::Cancelled);
    }
    let remaining = limits.max_total_artifact_bytes.saturating_sub(
        report
            .work
            .archive_bytes_read
            .saturating_add(report.work.installed_bytes_read)
            .saturating_add(report.work.declared_input_bytes_read),
    );
    let mut producer_limits = limits.producer;
    producer_limits.max_artifact_bytes = producer_limits.max_artifact_bytes.min(remaining);
    let exact =
        read_exact_artifact_while(&canonical, &producer_limits, || is_cancelled(cancellation))
            .map_err(|diagnostic| {
                if diagnostic.code == "artifact.cancelled" || is_cancelled(cancellation) {
                    InstalledCandidateError::Cancelled
                } else {
                    InstalledCandidateError::Invalid(canonical.clone(), diagnostic.message)
                }
            })?;
    report.work.installed_files_read += 1;
    report.work.installed_bytes_read = report
        .work
        .installed_bytes_read
        .saturating_add(exact.bytes().len() as u64);
    Ok((canonical, exact.into_bytes()))
}

enum ZipMemberReadError {
    Invalid(String),
    Cancelled,
}

fn read_zip_member(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
    max_bytes: u64,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<u8>, ZipMemberReadError> {
    let mut entry = archive.by_index(index).map_err(|error| {
        ZipMemberReadError::Invalid(format!("could not open wheel entry {index}: {error}"))
    })?;
    let expected = entry.size();
    if expected > max_bytes {
        return Err(ZipMemberReadError::Invalid(format!(
            "wheel entry exceeds byte limit {max_bytes}"
        )));
    }
    let capacity = usize::try_from(expected).map_err(|_| {
        ZipMemberReadError::Invalid("wheel entry size does not fit in memory".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if is_cancelled(cancellation) {
            return Err(ZipMemberReadError::Cancelled);
        }
        let read = entry.read(&mut buffer).map_err(|error| {
            ZipMemberReadError::Invalid(format!("could not decompress wheel entry: {error}"))
        })?;
        if read == 0 {
            break;
        }
        if (bytes.len() as u64).saturating_add(read as u64) > expected {
            return Err(ZipMemberReadError::Invalid(
                "wheel entry decompressed beyond its declared size".to_owned(),
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() as u64 != expected {
        return Err(ZipMemberReadError::Invalid(format!(
            "wheel entry decompressed to {} bytes; expected {expected}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn canonical_member_path(name: &str, is_dir: bool, max_depth: usize) -> Option<PathBuf> {
    let name = if is_dir {
        name.strip_suffix('/')?
    } else {
        name
    };
    if name.is_empty() || name.contains('\\') {
        return None;
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0;
    for component in path.components() {
        let Component::Normal(segment) = component else {
            return None;
        };
        if segment.is_empty() || segment.to_str().is_none() {
            return None;
        }
        depth += 1;
        if depth > max_depth {
            return None;
        }
        normalized.push(segment);
    }
    (depth > 0 && path_to_slash_string(&normalized) == name).then_some(normalized)
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(segment) => segment.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn python_source_kind(path: &Path) -> Option<(bool, bool)> {
    match path.extension()?.to_str()? {
        "py" => Some((true, false)),
        "pyi" => Some((false, true)),
        _ => None,
    }
}

fn is_python_runtime_member(path: &Path) -> bool {
    python_source_kind(path).is_some() || is_unsupported_runtime_member(path)
}

fn is_unsupported_runtime_member(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "pyc" | "so" | "pyd" | "dll" | "dylib"
            )
        })
}

fn unresolved_artifact(
    environment_index: usize,
    artifact_index: usize,
    source_root: Option<PathBuf>,
    config: &PythonRuntimeArtifactConfig,
) -> VerifiedPythonRuntimeArtifact {
    VerifiedPythonRuntimeArtifact {
        environment_index,
        artifact_index,
        source_root,
        archive_path: config.archive_path.clone(),
        archive_sha256: None,
        identity: None,
        installed_root: config.installed_root.clone(),
        normalized_name: None,
        raw_version: None,
        coordinate: None,
        status: PythonRuntimeArtifactStatus::Unresolved,
        modules: Vec::new(),
    }
}

fn unresolved_module(candidate: RuntimeWheelEntry) -> VerifiedPythonRuntimeModule {
    VerifiedPythonRuntimeModule {
        import_name: candidate.import_name,
        archive_member_path: candidate.path,
        module_components: candidate.components,
        installed_path: None,
        member_sha256: None,
        installed_sha256: None,
        installed_bytes_match: None,
        runtime: candidate.runtime,
        stub: candidate.stub,
        status: PythonRuntimeModuleStatus::Unresolved,
        import_status: PythonRuntimeImportStatus::Unresolved,
    }
}

fn resolve_workspace_path(
    workspace: &Path,
    configured: &Path,
    directory: bool,
    max_depth: usize,
) -> Result<PathBuf, String> {
    if configured.is_absolute() {
        return Err("configured runtime paths must be workspace-relative".to_owned());
    }
    let mut relative = PathBuf::new();
    let mut depth = 0;
    for component in configured.components() {
        let Component::Normal(segment) = component else {
            return Err(
                "configured runtime path must contain only normal relative components".to_owned(),
            );
        };
        if segment.is_empty() {
            return Err("configured runtime path contains an empty component".to_owned());
        }
        depth += 1;
        if depth > max_depth {
            return Err(format!(
                "configured runtime path exceeds depth limit {max_depth}"
            ));
        }
        relative.push(segment);
    }
    if depth == 0 {
        return Err("configured runtime path must not be empty".to_owned());
    }
    let mut current = workspace.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            unreachable!("validated workspace path has normal components")
        };
        current.push(segment);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("could not inspect configured path component: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("configured runtime path contains a symlink component".to_owned());
        }
    }
    let canonical = current
        .canonicalize()
        .map_err(|error| format!("could not canonicalize configured runtime path: {error}"))?;
    if !canonical.starts_with(workspace) {
        return Err("configured runtime path escapes the workspace".to_owned());
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("could not inspect configured runtime path: {error}"))?;
    if directory && !metadata.is_dir() {
        return Err("configured runtime root is not a directory".to_owned());
    }
    if !directory && !metadata.is_file() {
        return Err("configured archive path is not a regular file".to_owned());
    }
    Ok(canonical)
}

fn mark_conflicting_runtime_providers(
    report: &mut PythonRuntimeArtifactReport,
    limits: &DependencyPackLimits,
) {
    if report.cancelled {
        return;
    }
    let mut providers: HashMap<(usize, String), Vec<(usize, usize)>> = HashMap::new();
    for (artifact_index, artifact) in report.artifacts.iter().enumerate() {
        for (module_index, module) in artifact.modules.iter().enumerate() {
            if module.runtime
                && let Some(import_name) = &module.import_name
            {
                providers
                    .entry((artifact.environment_index, import_name.clone()))
                    .or_default()
                    .push((artifact_index, module_index));
            }
        }
    }
    for ((environment_index, import_name), candidates) in providers {
        let configured_artifacts = candidates
            .iter()
            .map(|(report_index, _)| report.artifacts[*report_index].artifact_index)
            .collect::<HashSet<_>>();
        if configured_artifacts.len() < 2 {
            continue;
        }
        for (artifact_index, module_index) in &candidates {
            report.artifacts[*artifact_index].modules[*module_index].import_status =
                PythonRuntimeImportStatus::Conflict;
            report.artifacts[*artifact_index].status = PythonRuntimeArtifactStatus::Conflicting;
            let (artifact_index, installed_root, path) = {
                let artifact = &report.artifacts[*artifact_index];
                (
                    artifact.artifact_index,
                    artifact.installed_root.clone(),
                    artifact.modules[*module_index].archive_member_path.clone(),
                )
            };
            push_frontier(
                report,
                limits,
                PythonRuntimeFrontier {
                    kind: PythonRuntimeFrontierKind::CompetingRuntimeProvider,
                    environment_index,
                    artifact_index: Some(artifact_index),
                    root: installed_root.to_path_buf(),
                    path: Some(path),
                    import_name: Some(import_name.clone()),
                    message: "multiple configured artifacts provide this runtime import".to_owned(),
                },
            );
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    lower_hex_string(&sha256_bytes(bytes))
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn diagnostic_for_artifact(
    report: &mut PythonRuntimeArtifactReport,
    limits: &DependencyPackLimits,
    artifact: &VerifiedPythonRuntimeArtifact,
    code: &str,
    location: Option<PathBuf>,
    message: String,
) {
    push_diagnostic(
        report,
        limits,
        code,
        Some(artifact.environment_index),
        Some(artifact.artifact_index),
        location,
        message,
    );
}

fn push_diagnostic(
    report: &mut PythonRuntimeArtifactReport,
    limits: &DependencyPackLimits,
    code: &str,
    environment_index: Option<usize>,
    artifact_index: Option<usize>,
    location: Option<PathBuf>,
    mut message: String,
) {
    report.complete = false;
    if report.diagnostics.len() >= limits.max_diagnostics {
        report.suppressed_diagnostics = report.suppressed_diagnostics.saturating_add(1);
        return;
    }
    let limit = limits.max_diagnostic_message_bytes;
    if message.len() > limit {
        let mut end = limit;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    report.diagnostics.push(PythonRuntimeArtifactDiagnostic {
        code: code.to_owned(),
        environment_index,
        artifact_index,
        location,
        message,
    });
}

fn push_frontier(
    report: &mut PythonRuntimeArtifactReport,
    limits: &DependencyPackLimits,
    mut frontier: PythonRuntimeFrontier,
) {
    if report.frontiers.len() >= limits.max_diagnostics {
        report.suppressed_frontiers = report.suppressed_frontiers.saturating_add(1);
        report.complete = false;
        return;
    }
    let limit = limits.max_diagnostic_message_bytes;
    if frontier.message.len() > limit {
        let mut end = limit;
        while !frontier.message.is_char_boundary(end) {
            end -= 1;
        }
        frontier.message.truncate(end);
    }
    report.frontiers.push(frontier);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    fn write_wheel(path: &Path, runtime_path: &str, runtime_bytes: &[u8]) {
        let mut archive = zip::ZipWriter::new(fs::File::create(path).expect("create wheel"));
        archive
            .start_file("demo-1.0.dist-info/METADATA", SimpleFileOptions::default())
            .expect("start metadata member");
        archive
            .write_all(b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n")
            .expect("write metadata");
        archive
            .start_file(runtime_path, SimpleFileOptions::default())
            .expect("start runtime member");
        archive
            .write_all(runtime_bytes)
            .expect("write runtime member");
        archive.finish().expect("finish wheel");
    }

    #[test]
    fn package_frontiers_retain_every_affected_import() {
        let root = Path::new("/declared-root");
        let candidates = ["pkg/__init__.py", "pkg/first.py", "pkg/second.py"]
            .into_iter()
            .map(|path| {
                let path = PathBuf::from(path);
                let module_components =
                    python_module_components_from_relative(&path).expect("runtime module path");
                RuntimeTreeCandidate {
                    import_name: Some(module_components.join(".")),
                    path,
                    module_components,
                    runtime: true,
                    unsupported: false,
                }
            })
            .collect();
        let scan = RuntimeTreeScan {
            candidates,
            complete: true,
        };
        let mut report = PythonRuntimeArtifactReport::default();
        record_package_frontiers(
            &scan,
            root,
            0,
            Some(0),
            PythonRuntimeScanKind::InstalledRoot,
            &DependencyPackLimits::default(),
            &mut report,
        );
        let affected = report
            .frontiers
            .iter()
            .filter(|frontier| {
                frontier.kind == PythonRuntimeFrontierKind::PackageInitializerEffects
            })
            .map(|frontier| (frontier.import_name.as_deref(), frontier.path.as_deref()))
            .collect::<HashSet<_>>();
        let initializer = root.join("pkg/__init__.py");
        assert_eq!(
            affected,
            HashSet::from([
                (Some("pkg"), Some(initializer.as_path())),
                (Some("pkg.first"), Some(initializer.as_path())),
                (Some("pkg.second"), Some(initializer.as_path())),
            ])
        );
    }

    fn runtime_environment(
        source_root: &str,
        archive: &str,
        installed_root: &str,
    ) -> Vec<PythonRuntimeEnvironmentConfig> {
        vec![PythonRuntimeEnvironmentConfig {
            declared_environment: None,
            source_root: source_root.into(),
            artifacts: vec![PythonRuntimeArtifactConfig {
                archive_path: archive.into(),
                installed_root: installed_root.into(),
            }],
        }]
    }

    fn verify(
        root: &Path,
        environments: &[PythonRuntimeEnvironmentConfig],
    ) -> PythonRuntimeArtifactReport {
        verify_python_runtime_artifacts(root, environments, &DependencyPackLimits::default(), None)
    }

    #[test]
    fn matches_installed_member_bytes_and_rehashes_mutated_archive() {
        let workspace = tempdir().expect("workspace tempdir");
        let source = workspace.path().join("src");
        let installed = workspace.path().join("site");
        fs::create_dir_all(&source).expect("source root");
        fs::create_dir_all(&installed).expect("installed root");
        fs::write(installed.join("api.py"), b"VALUE = 1\n").expect("installed module");
        let archive = workspace.path().join("demo.whl");
        write_wheel(&archive, "api.py", b"VALUE = 1\n");
        let environments = runtime_environment("src", "demo.whl", "site");

        let matching = verify(workspace.path(), &environments);
        assert!(matching.complete);
        assert!(matching.scope_complete);
        assert!(!matching.ambient_import_semantics_known);
        let matched_artifact = &matching.artifacts[0];
        let original_digest = matched_artifact
            .archive_sha256
            .clone()
            .expect("wheel digest");
        assert_eq!(
            matched_artifact.status,
            PythonRuntimeArtifactStatus::ArchiveVerified
        );
        assert_eq!(
            matched_artifact.modules[0].status,
            PythonRuntimeModuleStatus::BytesMatched
        );
        assert_eq!(
            matched_artifact.modules[0].installed_bytes_match,
            Some(true)
        );

        write_wheel(&archive, "api.py", b"VALUE = 2\n");
        let mutated = verify(workspace.path(), &environments);
        let mutated_artifact = &mutated.artifacts[0];
        assert_ne!(
            mutated_artifact.archive_sha256.as_deref(),
            Some(original_digest.as_str())
        );
        assert_eq!(
            mutated_artifact.modules[0].status,
            PythonRuntimeModuleStatus::ContentMismatch
        );
        assert_eq!(
            mutated_artifact.modules[0].installed_bytes_match,
            Some(false)
        );
        assert!(!mutated.complete);
    }

    #[test]
    fn preserves_extra_source_and_namespace_frontiers_alongside_byte_match() {
        let workspace = tempdir().expect("workspace tempdir");
        let workspace_root = workspace
            .path()
            .canonicalize()
            .expect("canonical workspace tempdir");
        let source = workspace_root.join("src");
        let installed = workspace_root.join("site");
        fs::create_dir_all(installed.join("pkg")).expect("installed package path");
        fs::create_dir_all(&source).expect("source root");
        fs::write(source.join("pkg.py"), b"VALUE = 1\n").expect("source module shadow");
        fs::write(installed.join("pkg/mod.py"), b"VALUE = 1\n").expect("installed module");
        fs::write(installed.join("extra.py"), b"OTHER = True\n").expect("extra module");
        let archive = workspace_root.join("demo.whl");
        write_wheel(&archive, "pkg/mod.py", b"VALUE = 1\n");

        let report = verify(
            &workspace_root,
            &runtime_environment("src", "demo.whl", "site"),
        );
        let module = &report.artifacts[0].modules[0];
        assert_eq!(module.status, PythonRuntimeModuleStatus::BytesMatched);
        assert_eq!(module.import_status, PythonRuntimeImportStatus::Conflict);
        assert!(report.scope_complete);
        assert!(report.frontiers.iter().any(|frontier| {
            frontier.kind == PythonRuntimeFrontierKind::ExtraInstalledCandidate
                && frontier.path.as_deref() == Some(installed.join("extra.py").as_path())
        }));
        assert!(report.frontiers.iter().any(|frontier| {
            frontier.kind == PythonRuntimeFrontierKind::SourceShadowCandidate
                && frontier.import_name.as_deref() == Some("pkg.mod")
        }));
        assert!(report.frontiers.iter().any(|frontier| {
            frontier.kind == PythonRuntimeFrontierKind::NamespaceContributor
                && frontier.import_name.as_deref() == Some("pkg.mod")
        }));
    }
}
