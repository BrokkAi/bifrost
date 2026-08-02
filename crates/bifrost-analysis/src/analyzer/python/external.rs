//! Static discovery of explicitly selected Python API-pack inputs.
//!
//! This module never invokes Python or imports a dependency. It only reads
//! configured directories and distribution metadata, returning exact local
//! files for the shared semantic-pack coordinator to hash and consume later.

use std::fs;
use std::path::{Path, PathBuf};

use semver::Version;

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    CatalogCoordinate, DependencyArtifactRole, DependencyDiscoveryOutcome,
    DependencyDiscoveryProfile, DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    DependencyPackLimits, DependencyProvenance, ExternalArtifactKind, ResolvedDependency,
    ResolvedDependencyArtifact, SemanticModelActivationEvidence,
};
use crate::analyzer::{Project, PythonAnalyzerConfig, PythonEnvironmentConfig};

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonDependencyPackAdapter;

/// Resolve configured Python standard-library, bundled-stub, and installed
/// distribution files without using the interpreter, `sys.path`, `.pth`, or a
/// package manager. A disabled Python environment intentionally resolves no
/// dependencies.
pub fn resolve_python_semantic_pack_dependencies(
    config: &PythonAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let Some(environment) = &config.environment else {
        return DependencyDiscoveryOutcome::complete(Vec::new());
    };
    let mut state = DiscoveryState::new(environment, limits);
    if state.cancelled(cancellation) {
        return state.cancelled_outcome();
    }

    let standard_library_root =
        match state.resolve_root(project.root(), &environment.standard_library_root, "stdlib") {
            Some(root) => root,
            None => return state.outcome(Vec::new()),
        };
    let standard_library = state.collect_dependency(
        "python:stdlib",
        None,
        "stdlib",
        &standard_library_root,
        cancellation,
    );

    let mut dependencies = standard_library.into_iter().collect::<Vec<_>>();
    for root in &environment.bundled_stub_roots {
        if state.cancelled(cancellation) {
            return state.cancelled_outcome();
        }
        let Some(root) = state.resolve_root(project.root(), root, "bundled_stub") else {
            continue;
        };
        if let Some(dependency) = state.collect_dependency(
            "python:bundled-stubs",
            None,
            "bundled_stub",
            &root,
            cancellation,
        ) {
            dependencies.push(dependency);
        }
    }
    for root in &environment.distribution_roots {
        if state.cancelled(cancellation) {
            return state.cancelled_outcome();
        }
        let Some(root) = state.resolve_root(project.root(), root, "distribution") else {
            continue;
        };
        dependencies.extend(state.collect_distributions(&root, cancellation));
    }
    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    dependencies.dedup_by(|left, right| left.id == right.id && left.artifacts == right.artifacts);
    if dependencies.len() > limits.max_dependencies {
        state.error(
            "limit.dependencies",
            None,
            None,
            format!(
                "Python environment discovery exceeded dependency limit {}",
                limits.max_dependencies
            ),
        );
        dependencies.truncate(limits.max_dependencies);
    }
    state.outcome(dependencies)
}

struct DiscoveryState<'a> {
    environment: &'a PythonEnvironmentConfig,
    limits: &'a DependencyPackLimits,
    diagnostics: Vec<DependencyPackDiagnostic>,
    suppressed_diagnostics: usize,
    metadata_inputs_considered: usize,
    directories_considered: usize,
    candidate_bytes: u64,
    incomplete: bool,
}

impl<'a> DiscoveryState<'a> {
    fn new(environment: &'a PythonEnvironmentConfig, limits: &'a DependencyPackLimits) -> Self {
        Self {
            environment,
            limits,
            diagnostics: Vec::new(),
            suppressed_diagnostics: 0,
            metadata_inputs_considered: 0,
            directories_considered: 0,
            candidate_bytes: 0,
            incomplete: false,
        }
    }

    fn cancelled(&self, cancellation: Option<&CancellationToken>) -> bool {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    }

    fn cancelled_outcome(mut self) -> DependencyDiscoveryOutcome {
        self.error(
            "discovery.cancelled",
            None,
            None,
            "Python environment discovery was cancelled".to_owned(),
        );
        DependencyDiscoveryOutcome {
            dependencies: Vec::new(),
            diagnostics: self.diagnostics,
            suppressed_diagnostics: self.suppressed_diagnostics,
            complete: false,
            cancelled: true,
            profile: DependencyDiscoveryProfile {
                metadata_inputs_considered: self.metadata_inputs_considered,
                dependencies_resolved: 0,
            },
        }
    }

    fn outcome(self, dependencies: Vec<ResolvedDependency>) -> DependencyDiscoveryOutcome {
        DependencyDiscoveryOutcome {
            profile: DependencyDiscoveryProfile {
                metadata_inputs_considered: self.metadata_inputs_considered,
                dependencies_resolved: dependencies.len(),
            },
            complete: !self.incomplete && self.suppressed_diagnostics == 0,
            dependencies,
            diagnostics: self.diagnostics,
            suppressed_diagnostics: self.suppressed_diagnostics,
            cancelled: false,
        }
    }

    fn resolve_root(
        &mut self,
        project_root: &Path,
        configured: &Path,
        role: &str,
    ) -> Option<PathBuf> {
        let path = if configured.is_absolute() {
            configured.to_path_buf()
        } else {
            project_root.join(configured)
        };
        let root = match path.canonicalize() {
            Ok(root) if root.is_dir() => root,
            Ok(_) => {
                self.error(
                    "python.environment_root",
                    None,
                    Some(&path),
                    format!("configured {role} root is not a directory"),
                );
                return None;
            }
            Err(error) => {
                self.error(
                    "python.environment_root",
                    None,
                    Some(&path),
                    format!("could not inspect configured {role} root: {error}"),
                );
                return None;
            }
        };
        Some(root)
    }

    fn collect_distributions(
        &mut self,
        root: &Path,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<ResolvedDependency> {
        let entries = match sorted_directory_entries(root) {
            Ok(entries) => entries,
            Err(error) => {
                self.error(
                    "python.distribution_root",
                    None,
                    Some(root),
                    format!("could not list configured distribution root: {error}"),
                );
                return Vec::new();
            }
        };
        let mut dependencies = Vec::new();
        for metadata in entries
            .into_iter()
            .filter(|path| is_distribution_metadata(path))
        {
            if self.cancelled(cancellation) {
                break;
            }
            if dependencies.len() >= self.environment.limits.max_distributions {
                self.error(
                    "limit.distributions",
                    None,
                    Some(root),
                    format!(
                        "Python environment exceeds distribution limit {}",
                        self.environment.limits.max_distributions
                    ),
                );
                break;
            }
            self.metadata_inputs_considered += 1;
            let Some((name, version)) = self.distribution_identity(&metadata) else {
                continue;
            };
            let package_roots = self.distribution_package_roots(root, &metadata, &name);
            if package_roots.is_empty() {
                self.error(
                    "python.distribution_artifacts",
                    Some(&name),
                    Some(&metadata),
                    "distribution metadata did not identify an importable package or module"
                        .to_owned(),
                );
                continue;
            }
            let mut artifacts = Vec::new();
            let typed = package_roots
                .iter()
                .any(|path| path.join("py.typed").is_file());
            for package_root in package_roots {
                artifacts.extend(self.collect_artifacts(&package_root, cancellation));
            }
            if artifacts.is_empty() {
                self.error(
                    "python.distribution_artifacts",
                    Some(&name),
                    Some(&metadata),
                    "distribution contains no supported .pyi or .py artifacts".to_owned(),
                );
                continue;
            }
            artifacts.sort_by(|left, right| {
                (artifact_kind_rank(left.kind), &left.path)
                    .cmp(&(artifact_kind_rank(right.kind), &right.path))
            });
            artifacts.dedup();
            dependencies.push(self.dependency(
                format!("python:distribution:{name}:{version}"),
                Some((name, version)),
                if typed {
                    "inline_py_typed"
                } else {
                    "implementation_source"
                },
                artifacts,
            ));
        }
        dependencies
    }

    fn distribution_identity(&mut self, metadata: &Path) -> Option<(String, String)> {
        let metadata_file = metadata.join("METADATA");
        let source = match read_bounded(&metadata_file, self.environment.limits.max_metadata_bytes)
        {
            Ok(source) => source,
            Err(error) => {
                self.error(
                    "python.distribution_metadata",
                    None,
                    Some(&metadata_file),
                    error,
                );
                return None;
            }
        };
        let Some(name) = metadata_header(&source, "Name") else {
            self.error(
                "python.distribution_metadata",
                None,
                Some(&metadata_file),
                "METADATA is missing Name".to_owned(),
            );
            return None;
        };
        let Some(version) = metadata_header(&source, "Version") else {
            self.error(
                "python.distribution_metadata",
                Some(&name),
                Some(&metadata_file),
                "METADATA is missing Version".to_owned(),
            );
            return None;
        };
        Some((normalize_distribution_name(&name), version))
    }

    fn distribution_package_roots(
        &mut self,
        root: &Path,
        metadata: &Path,
        name: &str,
    ) -> Vec<PathBuf> {
        let top_level = metadata.join("top_level.txt");
        let names = read_bounded(&top_level, self.environment.limits.max_metadata_bytes)
            .ok()
            .map(|contents| {
                contents
                    .lines()
                    .map(str::trim)
                    .filter(|value| {
                        !value.is_empty()
                            && value
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                    })
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|names| !names.is_empty())
            .unwrap_or_else(|| vec![name.replace('-', "_")]);
        let mut roots = Vec::new();
        for name in names {
            let package = root.join(&name);
            let module = root.join(format!("{name}.pyi"));
            let source_module = root.join(format!("{name}.py"));
            if package.is_dir() {
                roots.push(package);
            } else if module.is_file() {
                roots.push(module);
            } else if source_module.is_file() {
                roots.push(source_module);
            }
        }
        roots.sort();
        roots.dedup();
        roots
    }

    fn collect_dependency(
        &mut self,
        id_prefix: &str,
        package: Option<(String, String)>,
        source_kind: &str,
        root: &Path,
        cancellation: Option<&CancellationToken>,
    ) -> Option<ResolvedDependency> {
        let artifacts = self.collect_artifacts(root, cancellation);
        (!artifacts.is_empty()).then(|| {
            let id = match &package {
                Some((name, version)) => format!("{id_prefix}:{name}:{version}"),
                None => format!(
                    "{id_prefix}:{}:{}",
                    self.environment.implementation, self.environment.version
                ),
            };
            self.dependency(id, package, source_kind, artifacts)
        })
    }

    fn collect_artifacts(
        &mut self,
        root: &Path,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<ResolvedDependencyArtifact> {
        let root = match root.canonicalize() {
            Ok(root) => root,
            Err(error) => {
                self.error(
                    "python.artifact_root",
                    None,
                    Some(root),
                    format!("could not canonicalize artifact root: {error}"),
                );
                return Vec::new();
            }
        };
        if root.is_file() {
            let Some(kind) = python_artifact_kind(&root) else {
                return Vec::new();
            };
            let metadata = match root.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.error(
                        "python.artifact_metadata",
                        None,
                        Some(&root),
                        format!("could not inspect artifact candidate: {error}"),
                    );
                    return Vec::new();
                }
            };
            self.candidate_bytes = self.candidate_bytes.saturating_add(metadata.len());
            if self.candidate_bytes > self.environment.limits.max_total_candidate_bytes {
                self.error(
                    "limit.candidate_bytes",
                    None,
                    Some(&root),
                    format!(
                        "Python environment candidates exceed byte limit {}",
                        self.environment.limits.max_total_candidate_bytes
                    ),
                );
                return Vec::new();
            }
            return vec![ResolvedDependencyArtifact {
                role: artifact_role(kind),
                kind,
                path: root,
            }];
        }
        let mut pending = vec![root.clone()];
        let mut artifacts = Vec::new();
        while let Some(directory) = pending.pop() {
            if self.cancelled(cancellation) {
                break;
            }
            self.directories_considered += 1;
            if self.directories_considered > self.environment.limits.max_directories {
                self.error(
                    "limit.directories",
                    None,
                    Some(&root),
                    format!(
                        "Python environment exceeds directory limit {}",
                        self.environment.limits.max_directories
                    ),
                );
                break;
            }
            let entries = match sorted_directory_entries(&directory) {
                Ok(entries) => entries,
                Err(error) => {
                    self.error(
                        "python.artifact_directory",
                        None,
                        Some(&directory),
                        format!("could not list artifact directory: {error}"),
                    );
                    continue;
                }
            };
            for entry in entries {
                if self.cancelled(cancellation) {
                    break;
                }
                let metadata = match fs::symlink_metadata(&entry) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        self.error(
                            "python.artifact_metadata",
                            None,
                            Some(&entry),
                            format!("could not inspect artifact candidate: {error}"),
                        );
                        continue;
                    }
                };
                if metadata.file_type().is_symlink() {
                    let Ok(target) = entry.canonicalize() else {
                        self.error(
                            "python.artifact_symlink",
                            None,
                            Some(&entry),
                            "could not resolve artifact symlink".to_owned(),
                        );
                        continue;
                    };
                    if !target.starts_with(&root) {
                        self.error(
                            "python.artifact_symlink",
                            None,
                            Some(&entry),
                            "artifact symlink escapes its configured root".to_owned(),
                        );
                    }
                    continue;
                }
                if metadata.is_dir() {
                    pending.push(entry);
                    continue;
                }
                if !metadata.is_file()
                    || artifacts.len() >= self.environment.limits.max_files_per_distribution
                {
                    continue;
                }
                let Some(kind) = python_artifact_kind(&entry) else {
                    continue;
                };
                self.candidate_bytes = self.candidate_bytes.saturating_add(metadata.len());
                if self.candidate_bytes > self.environment.limits.max_total_candidate_bytes {
                    self.error(
                        "limit.candidate_bytes",
                        None,
                        Some(&entry),
                        format!(
                            "Python environment candidates exceed byte limit {}",
                            self.environment.limits.max_total_candidate_bytes
                        ),
                    );
                    return artifacts;
                }
                artifacts.push(ResolvedDependencyArtifact {
                    role: artifact_role(kind),
                    kind,
                    path: entry,
                });
            }
        }
        artifacts.sort_by(|left, right| {
            (artifact_kind_rank(left.kind), &left.path)
                .cmp(&(artifact_kind_rank(right.kind), &right.path))
        });
        artifacts
    }

    fn dependency(
        &self,
        id: String,
        package: Option<(String, String)>,
        source_kind: &str,
        artifacts: Vec<ResolvedDependencyArtifact>,
    ) -> ResolvedDependency {
        let package = package.map(|(name, version)| CatalogCoordinate {
            name,
            version: Version::parse(&version).ok(),
        });
        ResolvedDependency {
            id,
            evidence: SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
                package,
                module: None,
                toolchain: Some(CatalogCoordinate {
                    name: self.environment.implementation.clone(),
                    version: Version::parse(&self.environment.version).ok(),
                }),
                target: Some(self.environment.platform.clone()),
                configuration: None,
                artifact_sha256: None,
            },
            provenance: vec![
                DependencyProvenance {
                    key: "python_implementation".to_owned(),
                    value: self.environment.implementation.clone(),
                },
                DependencyProvenance {
                    key: "python_version".to_owned(),
                    value: self.environment.version.clone(),
                },
                DependencyProvenance {
                    key: "platform".to_owned(),
                    value: self.environment.platform.clone(),
                },
                DependencyProvenance {
                    key: "source_kind".to_owned(),
                    value: source_kind.to_owned(),
                },
            ],
            artifacts,
        }
    }

    fn error(
        &mut self,
        code: &str,
        dependency_id: Option<&str>,
        location: Option<&Path>,
        message: String,
    ) {
        self.incomplete = true;
        if self.diagnostics.len()
            >= self
                .environment
                .limits
                .max_diagnostics
                .min(self.limits.max_diagnostics)
        {
            self.suppressed_diagnostics = self.suppressed_diagnostics.saturating_add(1);
            return;
        }
        self.diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: code.to_owned(),
            dependency_id: dependency_id.map(str::to_owned),
            location: location.map(|path| path.display().to_string()),
            message: bounded_message(
                message,
                self.environment
                    .limits
                    .max_diagnostic_message_bytes
                    .min(self.limits.max_diagnostic_message_bytes),
            ),
        });
    }
}

fn sorted_directory_entries(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

fn is_distribution_metadata(path: &Path) -> bool {
    path.is_dir()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".dist-info") || name.ends_with(".egg-info"))
}

fn python_artifact_kind(path: &Path) -> Option<ExternalArtifactKind> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("pyi") => Some(ExternalArtifactKind::PythonStub),
        Some("py") => Some(ExternalArtifactKind::PythonSource),
        _ => None,
    }
}

fn artifact_kind_rank(kind: ExternalArtifactKind) -> u8 {
    match kind {
        ExternalArtifactKind::PythonStub => 0,
        ExternalArtifactKind::PythonSource => 1,
        _ => unreachable!("Python discovery only returns Python artifact kinds"),
    }
}

fn artifact_role(kind: ExternalArtifactKind) -> DependencyArtifactRole {
    match kind {
        ExternalArtifactKind::PythonStub => DependencyArtifactRole::Reference,
        ExternalArtifactKind::PythonSource => DependencyArtifactRole::Sources,
        _ => unreachable!("Python discovery only returns Python artifact kinds"),
    }
}

fn metadata_header(metadata: &str, name: &str) -> Option<String> {
    metadata.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.eq_ignore_ascii_case(name) && !value.trim().is_empty())
            .then(|| value.trim().to_owned())
    })
}

fn normalize_distribution_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("could not inspect metadata: {error}"))?;
    if metadata.len() > max_bytes {
        return Err(format!("metadata exceeds byte limit {max_bytes}"));
    }
    fs::read_to_string(path).map_err(|error| format!("could not read metadata: {error}"))
}

fn bounded_message(mut message: String, limit: usize) -> String {
    if message.len() > limit {
        message.truncate(limit);
    }
    message
}
