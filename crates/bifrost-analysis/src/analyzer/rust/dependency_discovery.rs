use std::collections::VecDeque;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedDependencyDiagnostics, CatalogCoordinate,
    DependencyArtifactRole, DependencyDiscoveryOutcome, DependencyDiscoveryProfile,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyProvenance, ExternalArtifactKind, ProducerDiagnostic, ProducerDiagnosticSeverity,
    ResolvedDependency, ResolvedDependencyArtifact, SemanticModelActivationEvidence,
    read_exact_artifact_while,
};
use crate::analyzer::topology::DependencyScope;
use crate::analyzer::{Project, RustAnalyzerConfig, RustDependencyApiEvidence};
use crate::hash::{HashMap, HashSet};

const CARGO_METADATA_FORMAT_VERSION: u32 = 1;
const MINIMUM_LOCKFILE_VERSION: u32 = 3;
const MAXIMUM_LOCKFILE_VERSION: u32 = 4;

pub const RUST_STDLIB_TOOLCHAIN_CHANNEL: &str = "nightly-2026-08-24";
pub const RUST_STDLIB_TOOLCHAIN_NAME: &str = "rust";
pub const RUST_STDLIB_TOOLCHAIN_VERSION: &str = "1.100.0-nightly";
pub const RUST_STDLIB_RUSTC_COMMIT: &str = "fb6531d55";

#[derive(Debug, Deserialize)]
struct RustToolchainFile {
    toolchain: RustToolchainSection,
}

#[derive(Debug, Deserialize)]
struct RustToolchainSection {
    channel: String,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    version: u32,
    #[serde(default)]
    packages: Vec<CargoMetadataPackage>,
    resolve: Option<CargoMetadataResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    #[serde(default)]
    targets: Vec<CargoMetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataTarget {
    name: String,
    #[serde(default)]
    kind: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataResolve {
    #[serde(default)]
    nodes: Vec<CargoMetadataNode>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataNode {
    id: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    deps: Vec<CargoMetadataNodeDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataNodeDependency {
    name: String,
    pkg: String,
}

#[derive(Debug, Deserialize)]
struct CargoLockfile {
    version: u32,
    #[serde(default, rename = "package")]
    packages: Vec<CargoLockPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RustdocVersionEnvelope {
    format_version: u32,
    #[serde(default)]
    crate_version: Option<String>,
    #[serde(default)]
    target: Option<RustdocTargetEnvelope>,
}

#[derive(Debug, Deserialize)]
struct RustdocTargetEnvelope {
    triple: String,
}

#[derive(Debug)]
struct DecodedRustdocArtifact {
    package_id: String,
    crate_name: String,
    enabled_features: Vec<String>,
    toolchain: String,
    path: PathBuf,
    format_version: u32,
    crate_version: Option<String>,
    target: String,
}

#[derive(Debug)]
struct DecodedRustDependencyEvidence {
    metadata: CargoMetadata,
    lockfile: CargoLockfile,
    artifacts: Vec<DecodedRustdocArtifact>,
}

pub fn resolve_rust_semantic_pack_dependencies(
    config: &RustAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let mut dependencies = Vec::new();
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let mut metadata_inputs_considered = 0_usize;
    let mut dependencies_considered = 0_usize;
    let mut evidence_bytes_read = 0_u64;
    let mut cancelled = false;

    for configured in &config.dependency_api_evidence {
        if is_cancelled(cancellation) {
            cancelled = true;
            diagnostics.push(cancelled_diagnostic(None));
            break;
        }
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(2);
        let evidence = evidence_paths_from_root(project.root(), configured);
        if dependencies_considered.saturating_add(evidence.packages.len()) > limits.max_dependencies
        {
            diagnostics.push(diagnostic(
                "limit.dependencies",
                None,
                format!(
                    "Rust dependency discovery exceeds the {} dependency limit",
                    limits.max_dependencies
                ),
            ));
            break;
        }
        dependencies_considered = dependencies_considered.saturating_add(evidence.packages.len());
        match decode_rust_dependency_evidence(
            &evidence,
            limits,
            &mut evidence_bytes_read,
            cancellation,
        ) {
            Ok(decoded) => match resolve_rust_dependency_evidence(&evidence, decoded) {
                Ok(mut resolved) => dependencies.append(&mut resolved),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            Err(diagnostic) => {
                cancelled |= diagnostic.code == "artifact.cancelled"
                    || diagnostic.code == "rust.evidence.cancelled";
                diagnostics.push(diagnostic);
            }
        }
    }

    if !cancelled {
        match resolve_rust_stdlib_dependency(
            project,
            limits,
            &mut evidence_bytes_read,
            cancellation,
        ) {
            Ok(Some(stdlib)) => dependencies.push(stdlib),
            Ok(None) => {}
            Err(diagnostic) => {
                cancelled |= diagnostic.code == "rust.evidence.cancelled";
                diagnostics.push(diagnostic);
            }
        }
    }

    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    dependencies.dedup();
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
        },
        complete: diagnostics.is_empty() && !cancelled,
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled,
    }
}

fn resolve_rust_stdlib_dependency(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<ResolvedDependency>, DependencyPackDiagnostic> {
    let path = project.root().join("rust-toolchain.toml");
    match std::fs::metadata(&path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(diagnostic(
                "rust.toolchain.not_file",
                Some(&path),
                "rust-toolchain.toml is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(diagnostic(
                "rust.toolchain.metadata",
                Some(&path),
                format!("could not inspect rust-toolchain.toml: {error}"),
            ));
        }
    }
    let artifact =
        read_evidence_file_with_budget(&path, limits, evidence_bytes_read, cancellation)?;
    let source = std::str::from_utf8(artifact.bytes()).map_err(|error| {
        diagnostic(
            "rust.toolchain.invalid_utf8",
            Some(&path),
            format!("rust-toolchain.toml is not UTF-8: {error}"),
        )
    })?;
    let file: RustToolchainFile = toml::from_str(source).map_err(|error| {
        diagnostic(
            "rust.toolchain.invalid_toml",
            Some(&path),
            format!("could not decode rust-toolchain.toml: {error}"),
        )
    })?;
    if file.toolchain.channel != RUST_STDLIB_TOOLCHAIN_CHANNEL {
        return Err(diagnostic(
            "rust.toolchain.stdlib_channel_mismatch",
            Some(&path),
            format!(
                "Rust standard-library pack requires exact channel {}; configured channel {} does not select it",
                RUST_STDLIB_TOOLCHAIN_CHANNEL, file.toolchain.channel
            ),
        ));
    }
    let version = semver::Version::parse(RUST_STDLIB_TOOLCHAIN_VERSION)
        .expect("pinned Rust toolchain version is valid semver");
    Ok(Some(ResolvedDependency {
        id: format!("rust:stdlib:{RUST_STDLIB_TOOLCHAIN_CHANNEL}"),
        evidence: SemanticModelActivationEvidence {
            language: "rust".to_owned(),
            ecosystem: "cargo".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: RUST_STDLIB_TOOLCHAIN_NAME.to_owned(),
                version: Some(version),
            }),
            target: None,
            configuration: None,
            artifact_sha256: None,
        },
        provenance: vec![
            DependencyProvenance {
                key: "rust.toolchain_channel".to_owned(),
                value: RUST_STDLIB_TOOLCHAIN_CHANNEL.to_owned(),
            },
            DependencyProvenance {
                key: "rustc.version".to_owned(),
                value: RUST_STDLIB_TOOLCHAIN_VERSION.to_owned(),
            },
            DependencyProvenance {
                key: "rustc.commit".to_owned(),
                value: RUST_STDLIB_RUSTC_COMMIT.to_owned(),
            },
            DependencyProvenance {
                key: "rustdoc.format_version".to_owned(),
                value: rustdoc_types::FORMAT_VERSION.to_string(),
            },
            DependencyProvenance {
                key: "rust.stdlib.crates".to_owned(),
                value: "core,alloc,std".to_owned(),
            },
        ],
        artifacts: Vec::new(),
        scope: DependencyScope::Unknown,
        declared_by: None,
    }))
}

fn resolve_rust_dependency_evidence(
    evidence: &RustDependencyApiEvidence,
    decoded: DecodedRustDependencyEvidence,
) -> Result<Vec<ResolvedDependency>, DependencyPackDiagnostic> {
    let packages_by_id: HashMap<_, _> = decoded
        .metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    if packages_by_id.len() != decoded.metadata.packages.len() {
        return Err(diagnostic(
            "rust.metadata.duplicate_package_id",
            Some(&evidence.metadata_path),
            "Cargo metadata contains duplicate package IDs",
        ));
    }

    let nodes_by_id: HashMap<_, _> = decoded
        .metadata
        .resolve
        .as_ref()
        .ok_or_else(|| {
            diagnostic(
                "rust.metadata.missing_resolve",
                Some(&evidence.metadata_path),
                "Cargo metadata does not contain a resolved dependency graph",
            )
        })?
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    if nodes_by_id.len() != decoded.metadata.resolve.as_ref().unwrap().nodes.len() {
        return Err(diagnostic(
            "rust.metadata.duplicate_node_id",
            Some(&evidence.metadata_path),
            "Cargo metadata resolve graph contains duplicate node IDs",
        ));
    }

    validate_selected_targets(evidence, &packages_by_id)?;
    let reachable = reachable_package_ids(evidence, &nodes_by_id)?;
    let mut resolved = Vec::with_capacity(decoded.artifacts.len());
    for artifact in decoded.artifacts {
        let package = packages_by_id
            .get(artifact.package_id.as_str())
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_package",
                    Some(&evidence.metadata_path),
                    format!(
                        "Cargo metadata does not contain package {}",
                        artifact.package_id
                    ),
                )
            })?;
        if !reachable.contains(artifact.package_id.as_str()) {
            return Err(diagnostic(
                "rust.metadata.unreachable_package",
                Some(&evidence.metadata_path),
                format!(
                    "package {} is not reachable from the selected Cargo targets",
                    artifact.package_id
                ),
            ));
        }
        let node = nodes_by_id
            .get(artifact.package_id.as_str())
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_node",
                    Some(&evidence.metadata_path),
                    format!(
                        "Cargo metadata resolve graph does not contain package {}",
                        artifact.package_id
                    ),
                )
            })?;
        let lock_package = exact_lock_package(package, &decoded.lockfile, &evidence.lockfile_path)?;
        if artifact.crate_version.as_deref() != Some(package.version.as_str()) {
            return Err(diagnostic(
                "rust.rustdoc.version_mismatch",
                Some(&artifact.path),
                format!(
                    "rustdoc crate version {:?} does not match Cargo package version {}",
                    artifact.crate_version, package.version
                ),
            ));
        }
        if !package.targets.iter().any(|target| {
            target.name.replace('-', "_") == artifact.crate_name.replace('-', "_")
                && target
                    .kind
                    .iter()
                    .any(|kind| kind == "lib" || kind == "proc-macro")
        }) {
            return Err(diagnostic(
                "rust.rustdoc.crate_name_mismatch",
                Some(&artifact.path),
                format!(
                    "configured crate name {} is not a library target of Cargo package {}",
                    artifact.crate_name, package.name
                ),
            ));
        }
        let version = semver::Version::parse(&package.version).map_err(|error| {
            diagnostic(
                "rust.metadata.invalid_semver",
                Some(&evidence.metadata_path),
                format!(
                    "Cargo package {} has invalid semantic version: {error}",
                    package.id
                ),
            )
        })?;

        let selected_roots = evidence
            .selected_targets
            .iter()
            .map(|target| target.package_id.as_str())
            .collect::<HashSet<_>>();
        let aliases =
            incoming_dependency_names(&artifact.package_id, &selected_roots, &nodes_by_id);
        let mut provenance = Vec::new();
        push_provenance(
            &mut provenance,
            "cargo.metadata_format",
            decoded.metadata.version,
        );
        push_provenance(
            &mut provenance,
            "cargo.lockfile_version",
            decoded.lockfile.version,
        );
        push_provenance(
            &mut provenance,
            "cargo.source_kind",
            source_kind(package.source.as_deref()),
        );
        if let Some(source) = &package.source {
            push_provenance(&mut provenance, "cargo.source", source);
        }
        if let Some(checksum) = &lock_package.checksum {
            push_provenance(&mut provenance, "cargo.checksum", checksum);
        }
        push_provenance(&mut provenance, "cargo.crate_name", &artifact.crate_name);
        push_provenance(&mut provenance, "cargo.target", &evidence.target);
        push_provenance(
            &mut provenance,
            "cargo.configuration",
            &evidence.configuration,
        );
        for selected in &evidence.selected_targets {
            push_provenance(
                &mut provenance,
                "cargo.selected_target",
                format!(
                    "{}:{}:{}",
                    stable_package_label(&selected.package_id, &packages_by_id),
                    selected.target_name,
                    selected.target_kind
                ),
            );
        }
        for feature in &artifact.enabled_features {
            push_provenance(&mut provenance, "cargo.feature", feature);
        }
        for feature in &node.features {
            push_provenance(&mut provenance, "cargo.metadata_feature", feature);
        }
        for alias in aliases {
            push_provenance(&mut provenance, "cargo.dependency_name", alias);
        }
        push_provenance(&mut provenance, "rustdoc.toolchain", &artifact.toolchain);
        push_provenance(
            &mut provenance,
            "rustdoc.format_version",
            artifact.format_version,
        );
        push_provenance(&mut provenance, "rustdoc.target", &artifact.target);
        provenance.sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));
        provenance.dedup();

        let feature_identity = if artifact.enabled_features.is_empty() {
            "none".to_owned()
        } else {
            artifact.enabled_features.join(",")
        };
        resolved.push(ResolvedDependency {
            id: format!(
                "rust:{}@{}:{}:{}:{}",
                package.name,
                package.version,
                artifact.crate_name,
                evidence.target,
                feature_identity
            ),
            evidence: SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
                package: Some(CatalogCoordinate {
                    name: package.name.clone(),
                    version: Some(version.clone()),
                }),
                module: Some(CatalogCoordinate {
                    name: artifact.crate_name,
                    version: Some(version),
                }),
                toolchain: None,
                target: Some(evidence.target.clone()),
                configuration: Some(evidence.configuration.clone()),
                artifact_sha256: None,
            },
            provenance,
            artifacts: vec![ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Reference,
                ExternalArtifactKind::RustdocJson,
                artifact.path,
            )],
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
    }
    Ok(resolved)
}

fn decode_rust_dependency_evidence(
    evidence: &RustDependencyApiEvidence,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<DecodedRustDependencyEvidence, DependencyPackDiagnostic> {
    require_non_empty("target", &evidence.target)?;
    require_non_empty("configuration", &evidence.configuration)?;
    if evidence.selected_targets.is_empty() {
        return Err(diagnostic(
            "rust.evidence.selected_targets",
            None,
            "Rust dependency evidence must select at least one Cargo target",
        ));
    }
    if evidence.packages.is_empty() {
        return Err(diagnostic(
            "rust.evidence.artifacts",
            None,
            "Rust dependency evidence must bind at least one rustdoc JSON artifact",
        ));
    }

    let metadata_artifact = read_evidence_file_with_budget(
        &evidence.metadata_path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    let metadata: CargoMetadata =
        serde_json::from_slice(metadata_artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.metadata.invalid_json",
                Some(&evidence.metadata_path),
                format!("could not decode Cargo metadata JSON: {error}"),
            )
        })?;
    if metadata.version != CARGO_METADATA_FORMAT_VERSION {
        return Err(diagnostic(
            "rust.metadata.unsupported_version",
            Some(&evidence.metadata_path),
            format!(
                "Cargo metadata format {} is unsupported; expected {}",
                metadata.version, CARGO_METADATA_FORMAT_VERSION
            ),
        ));
    }

    let lockfile_artifact = read_evidence_file_with_budget(
        &evidence.lockfile_path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    let lockfile: CargoLockfile = toml::from_str(
        std::str::from_utf8(lockfile_artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.lockfile.invalid_utf8",
                Some(&evidence.lockfile_path),
                format!("Cargo.lock is not UTF-8: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        diagnostic(
            "rust.lockfile.invalid_toml",
            Some(&evidence.lockfile_path),
            format!("could not decode Cargo.lock: {error}"),
        )
    })?;
    if !(MINIMUM_LOCKFILE_VERSION..=MAXIMUM_LOCKFILE_VERSION).contains(&lockfile.version) {
        return Err(diagnostic(
            "rust.lockfile.unsupported_version",
            Some(&evidence.lockfile_path),
            format!(
                "Cargo.lock version {} is unsupported; expected {} through {}",
                lockfile.version, MINIMUM_LOCKFILE_VERSION, MAXIMUM_LOCKFILE_VERSION
            ),
        ));
    }

    let mut artifacts = Vec::with_capacity(evidence.packages.len());
    for binding in &evidence.packages {
        if is_cancelled(cancellation) {
            return Err(cancelled_diagnostic(Some(&binding.rustdoc_json_path)));
        }
        require_non_empty("package_id", &binding.package_id)?;
        require_non_empty("crate_name", &binding.crate_name)?;
        require_non_empty("rustdoc_toolchain", &binding.rustdoc_toolchain)?;
        if binding.rustdoc_format_version != rustdoc_types::FORMAT_VERSION {
            return Err(diagnostic(
                "rust.rustdoc.unsupported_expected_version",
                Some(&binding.rustdoc_json_path),
                format!(
                    "configured rustdoc format {} is unsupported; this producer accepts {}",
                    binding.rustdoc_format_version,
                    rustdoc_types::FORMAT_VERSION
                ),
            ));
        }

        let artifact = read_evidence_file_with_budget(
            &binding.rustdoc_json_path,
            limits,
            evidence_bytes_read,
            cancellation,
        )?;
        let envelope: RustdocVersionEnvelope =
            serde_json::from_slice(artifact.bytes()).map_err(|error| {
                diagnostic(
                    "rust.rustdoc.invalid_json",
                    Some(&binding.rustdoc_json_path),
                    format!("could not read rustdoc JSON version: {error}"),
                )
            })?;
        if envelope.format_version != rustdoc_types::FORMAT_VERSION {
            return Err(diagnostic(
                "rust.rustdoc.unsupported_version",
                Some(&binding.rustdoc_json_path),
                format!(
                    "rustdoc JSON format {} is unsupported; this producer accepts {}",
                    envelope.format_version,
                    rustdoc_types::FORMAT_VERSION
                ),
            ));
        }
        let artifact_target = envelope.target.ok_or_else(|| {
            diagnostic(
                "rust.rustdoc.missing_target",
                Some(&binding.rustdoc_json_path),
                "rustdoc JSON does not declare its compilation target",
            )
        })?;
        if artifact_target.triple != evidence.target {
            return Err(diagnostic(
                "rust.rustdoc.target_mismatch",
                Some(&binding.rustdoc_json_path),
                format!(
                    "rustdoc target {} does not match selected target {}",
                    artifact_target.triple, evidence.target
                ),
            ));
        }

        let mut enabled_features = binding.enabled_features.clone();
        enabled_features.sort();
        enabled_features.dedup();
        artifacts.push(DecodedRustdocArtifact {
            package_id: binding.package_id.clone(),
            crate_name: binding.crate_name.clone(),
            enabled_features,
            toolchain: binding.rustdoc_toolchain.clone(),
            path: binding.rustdoc_json_path.clone(),
            format_version: envelope.format_version,
            crate_version: envelope.crate_version,
            target: artifact_target.triple,
        });
    }

    Ok(DecodedRustDependencyEvidence {
        metadata,
        lockfile,
        artifacts,
    })
}

fn evidence_paths_from_root(
    root: &Path,
    evidence: &RustDependencyApiEvidence,
) -> RustDependencyApiEvidence {
    let mut resolved = evidence.clone();
    resolved.metadata_path = resolve_path(root, &resolved.metadata_path);
    resolved.lockfile_path = resolve_path(root, &resolved.lockfile_path);
    for artifact in &mut resolved.packages {
        artifact.rustdoc_json_path = resolve_path(root, &artifact.rustdoc_json_path);
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

fn validate_selected_targets<'a>(
    evidence: &RustDependencyApiEvidence,
    packages_by_id: &HashMap<&'a str, &'a CargoMetadataPackage>,
) -> Result<(), DependencyPackDiagnostic> {
    let mut selected = HashSet::default();
    for target in &evidence.selected_targets {
        let package = packages_by_id
            .get(target.package_id.as_str())
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_selected_package",
                    Some(&evidence.metadata_path),
                    format!(
                        "selected Cargo target package {} is absent from metadata",
                        target.package_id
                    ),
                )
            })?;
        if !selected.insert((
            target.package_id.as_str(),
            target.target_name.as_str(),
            target.target_kind.as_str(),
        )) {
            return Err(diagnostic(
                "rust.evidence.duplicate_selected_target",
                None,
                format!(
                    "Cargo target {}:{}:{} is selected more than once",
                    target.package_id, target.target_name, target.target_kind
                ),
            ));
        }
        if !package.targets.iter().any(|candidate| {
            candidate.name == target.target_name && candidate.kind.contains(&target.target_kind)
        }) {
            return Err(diagnostic(
                "rust.metadata.missing_selected_target",
                Some(&evidence.metadata_path),
                format!(
                    "package {} has no Cargo target named {} of kind {}",
                    target.package_id, target.target_name, target.target_kind
                ),
            ));
        }
    }
    Ok(())
}

fn reachable_package_ids<'a>(
    evidence: &RustDependencyApiEvidence,
    nodes_by_id: &HashMap<&'a str, &'a CargoMetadataNode>,
) -> Result<HashSet<&'a str>, DependencyPackDiagnostic> {
    let mut reachable = HashSet::default();
    let mut pending = VecDeque::new();
    for target in &evidence.selected_targets {
        let id = nodes_by_id
            .get_key_value(target.package_id.as_str())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_selected_node",
                    Some(&evidence.metadata_path),
                    format!(
                        "selected Cargo target package {} is absent from the resolve graph",
                        target.package_id
                    ),
                )
            })?;
        pending.push_back(id);
    }
    while let Some(id) = pending.pop_front() {
        if !reachable.insert(id) {
            continue;
        }
        let node = nodes_by_id[id];
        for dependency in &node.deps {
            let Some((dependency_id, _)) = nodes_by_id.get_key_value(dependency.pkg.as_str())
            else {
                return Err(diagnostic(
                    "rust.metadata.missing_dependency_node",
                    Some(&evidence.metadata_path),
                    format!(
                        "Cargo resolve edge {} -> {} has no destination node",
                        id, dependency.pkg
                    ),
                ));
            };
            pending.push_back(*dependency_id);
        }
    }
    Ok(reachable)
}

fn exact_lock_package<'a>(
    package: &CargoMetadataPackage,
    lockfile: &'a CargoLockfile,
    path: &Path,
) -> Result<&'a CargoLockPackage, DependencyPackDiagnostic> {
    let mut matches = lockfile.packages.iter().filter(|candidate| {
        candidate.name == package.name
            && candidate.version == package.version
            && candidate.source == package.source
    });
    let Some(found) = matches.next() else {
        return Err(diagnostic(
            "rust.lockfile.missing_package",
            Some(path),
            format!(
                "Cargo.lock has no exact entry for {} {} from {:?}",
                package.name, package.version, package.source
            ),
        ));
    };
    if matches.next().is_some() {
        return Err(diagnostic(
            "rust.lockfile.ambiguous_package",
            Some(path),
            format!(
                "Cargo.lock has multiple entries for {} {} from {:?}",
                package.name, package.version, package.source
            ),
        ));
    }
    Ok(found)
}

fn incoming_dependency_names(
    package_id: &str,
    selected_roots: &HashSet<&str>,
    nodes_by_id: &HashMap<&str, &CargoMetadataNode>,
) -> Vec<String> {
    let mut names = selected_roots
        .iter()
        .filter_map(|root| nodes_by_id.get(root))
        .flat_map(|node| &node.deps)
        .filter(|dependency| dependency.pkg == package_id)
        .map(|dependency| dependency.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn stable_package_label(
    package_id: &str,
    packages_by_id: &HashMap<&str, &CargoMetadataPackage>,
) -> String {
    packages_by_id
        .get(package_id)
        .map(|package| format!("{}@{}", package.name, package.version))
        .unwrap_or_else(|| package_id.to_owned())
}

fn source_kind(source: Option<&str>) -> &'static str {
    match source {
        Some(value) if value.starts_with("registry+") => "registry",
        Some(value) if value.starts_with("git+") => "git",
        Some(_) => "other",
        None => "path",
    }
}

fn push_provenance(provenance: &mut Vec<DependencyProvenance>, key: &str, value: impl ToString) {
    provenance.push(DependencyProvenance {
        key: key.to_owned(),
        value: value.to_string(),
    });
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
                "Rust dependency evidence exceeds the {} byte aggregate limit",
                limits.max_total_artifact_bytes
            ),
        ));
    }
    let producer_limits = ArtifactProducerLimits {
        max_artifact_bytes: limits.producer.max_artifact_bytes.min(remaining),
        ..limits.producer
    };
    let artifact = read_exact_artifact_while(path, &producer_limits, || is_cancelled(cancellation))
        .map_err(|producer| {
            let mut diagnostic = producer_diagnostic(path, producer);
            if diagnostic.code == "limit.artifact_bytes"
                && remaining < limits.producer.max_artifact_bytes
            {
                diagnostic.code = "limit.total_artifact_bytes".to_owned();
                diagnostic.message = format!(
                    "Rust dependency evidence exceeds the {} byte aggregate limit",
                    limits.max_total_artifact_bytes
                );
            }
            diagnostic
        })?;
    *evidence_bytes_read = evidence_bytes_read.saturating_add(artifact.bytes().len() as u64);
    Ok(artifact)
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
            "rust.evidence.empty_field",
            None,
            format!("Rust dependency evidence field {field} must not be empty"),
        ));
    }
    Ok(())
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn cancelled_diagnostic(path: Option<&Path>) -> DependencyPackDiagnostic {
    diagnostic(
        "rust.evidence.cancelled",
        path,
        "Rust dependency evidence decoding was cancelled",
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use rustdoc_types::{Crate as RustdocCrate, Id, Target};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::analyzer::{
        Language, RustAnalyzerConfig, RustPackageApiArtifact, RustSelectedTarget, TestProject,
    };

    const PACKAGE_ID: &str = "registry+https://github.com/rust-lang/crates.io-index#widget@1.2.3";
    const TARGET: &str = "x86_64-unknown-linux-gnu";

    #[test]
    fn exact_evidence_decodes_supported_metadata_lockfile_and_rustdoc() {
        let fixture = EvidenceFixture::new();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        assert_eq!(decoded.metadata.version, CARGO_METADATA_FORMAT_VERSION);
        assert_eq!(decoded.metadata.packages.len(), 2);
        assert_eq!(decoded.metadata.packages[1].id, PACKAGE_ID);
        assert_eq!(decoded.metadata.packages[1].name, "widget");
        assert_eq!(decoded.metadata.packages[1].version, "1.2.3");
        assert_eq!(
            decoded.metadata.packages[1].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(decoded.metadata.resolve.as_ref().unwrap().nodes.len(), 2);
        assert_eq!(
            decoded.metadata.resolve.as_ref().unwrap().nodes[1].features,
            ["derive"]
        );
        assert_eq!(decoded.lockfile.version, MAXIMUM_LOCKFILE_VERSION);
        assert_eq!(decoded.lockfile.packages.len(), 1);
        assert_eq!(decoded.lockfile.packages[0].name, "widget");
        assert_eq!(decoded.lockfile.packages[0].version, "1.2.3");
        assert_eq!(
            decoded.lockfile.packages[0].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(
            decoded.lockfile.packages[0].checksum.as_deref(),
            Some("abc123")
        );
        assert_eq!(decoded.artifacts.len(), 1);
        assert_eq!(decoded.artifacts[0].package_id, PACKAGE_ID);
        assert_eq!(decoded.artifacts[0].crate_name, "widget");
        assert_eq!(decoded.artifacts[0].enabled_features, ["derive"]);
        assert_eq!(decoded.artifacts[0].toolchain, "nightly-2026-07-14");
        assert_eq!(decoded.artifacts[0].target, TARGET);
    }

    #[test]
    fn exact_evidence_resolves_reachable_package_with_normalized_provenance() {
        let fixture = EvidenceFixture::new();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let resolved = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap();

        assert_eq!(resolved.len(), 1);
        let dependency = &resolved[0];
        assert_eq!(dependency.evidence.language, "rust");
        assert_eq!(dependency.evidence.ecosystem, "cargo");
        assert_eq!(dependency.evidence.package.as_ref().unwrap().name, "widget");
        assert_eq!(dependency.evidence.module.as_ref().unwrap().name, "widget");
        assert_eq!(dependency.evidence.target.as_deref(), Some(TARGET));
        assert_eq!(
            dependency.evidence.configuration.as_deref(),
            Some("library")
        );
        assert_eq!(dependency.artifacts.len(), 1);
        assert_eq!(
            dependency.artifacts[0].role,
            DependencyArtifactRole::Reference
        );
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::RustdocJson
        );
        assert!(dependency.provenance.iter().any(|entry| {
            entry.key == "cargo.dependency_name" && entry.value == "renamed_widget"
        }));
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| { entry.key == "cargo.checksum" && entry.value == "abc123" })
        );
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| { entry.key == "cargo.feature" && entry.value == "derive" })
        );
    }

    #[test]
    fn exact_package_missing_from_lockfile_is_incomplete() {
        let fixture = EvidenceFixture::new();
        fs::write(&fixture.evidence.lockfile_path, "version = 4\n").unwrap();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let diagnostic = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap_err();

        assert_eq!(diagnostic.code, "rust.lockfile.missing_package");
    }

    #[test]
    fn artifact_package_must_be_reachable_from_selected_target() {
        let fixture = EvidenceFixture::new();
        fixture.write_metadata(false);
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let diagnostic = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap_err();

        assert_eq!(diagnostic.code, "rust.metadata.unreachable_package");
    }

    #[test]
    fn configured_crate_name_must_be_a_cargo_library_target() {
        let mut fixture = EvidenceFixture::new();
        fixture.evidence.packages[0].crate_name = "different_crate".to_owned();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let diagnostic = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.crate_name_mismatch");
    }

    #[test]
    fn dependency_names_are_scoped_to_selected_workspace_roots() {
        let root = CargoMetadataNode {
            id: "root".to_owned(),
            features: Vec::new(),
            deps: vec![
                CargoMetadataNodeDependency {
                    name: "renamed_widget".to_owned(),
                    pkg: "widget".to_owned(),
                },
                CargoMetadataNodeDependency {
                    name: "foo".to_owned(),
                    pkg: "foo".to_owned(),
                },
            ],
        };
        let transitive = CargoMetadataNode {
            id: "foo".to_owned(),
            features: Vec::new(),
            deps: vec![CargoMetadataNodeDependency {
                name: "internal_widget".to_owned(),
                pkg: "widget".to_owned(),
            }],
        };
        let nodes = crate::hash::HashMap::from_iter([("root", &root), ("foo", &transitive)]);
        let selected_roots = crate::hash::HashSet::from_iter(["root"]);

        assert_eq!(
            incoming_dependency_names("widget", &selected_roots, &nodes),
            ["renamed_widget"]
        );
    }

    #[test]
    fn public_discovery_reports_complete_exact_dependency() {
        let fixture = EvidenceFixture::new();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        };

        let outcome = resolve_rust_semantic_pack_dependencies(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(outcome.complete, "diagnostics: {:?}", outcome.diagnostics);
        assert!(!outcome.cancelled);
        assert_eq!(outcome.profile.metadata_inputs_considered, 2);
        assert_eq!(outcome.profile.dependencies_resolved, 1);
        assert_eq!(outcome.dependencies.len(), 1);
    }

    #[test]
    fn exact_rust_toolchain_toml_emits_stdlib_dependency() {
        let fixture = EvidenceFixture::new();
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            format!(
                "[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}\"\ncomponents = [\"rust-src\"]\n"
            ),
        )
        .unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(outcome.complete, "diagnostics: {:?}", outcome.diagnostics);
        let dependency = outcome
            .dependencies
            .iter()
            .find(|dependency| dependency.id == "rust:stdlib:nightly-2026-08-24")
            .expect("exact pinned Rust nightly should emit stdlib evidence");
        assert_eq!(dependency.evidence.ecosystem, "cargo");
        assert_eq!(dependency.evidence.package, None);
        assert_eq!(dependency.evidence.module, None);
        assert_eq!(
            dependency.evidence.toolchain.as_ref().unwrap().name,
            RUST_STDLIB_TOOLCHAIN_NAME
        );
        assert_eq!(
            dependency
                .evidence
                .toolchain
                .as_ref()
                .unwrap()
                .version
                .as_ref()
                .unwrap()
                .to_string(),
            RUST_STDLIB_TOOLCHAIN_VERSION
        );
        assert!(dependency.artifacts.is_empty());
        assert!(dependency.provenance.iter().any(|entry| {
            entry.key == "rustc.commit" && entry.value == RUST_STDLIB_RUSTC_COMMIT
        }));
    }

    #[test]
    fn non_exact_rust_toolchain_is_attributable_and_does_not_emit_stdlib_dependency() {
        let fixture = EvidenceFixture::new();
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"nightly\"\n",
        )
        .unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!outcome.complete);
        assert!(outcome.dependencies.is_empty());
        assert_eq!(
            outcome.diagnostics[0].code,
            "rust.toolchain.stdlib_channel_mismatch"
        );
        assert!(
            outcome.diagnostics[0]
                .message
                .contains(RUST_STDLIB_TOOLCHAIN_CHANNEL)
        );
        assert!(
            outcome.diagnostics[0]
                .message
                .contains("configured channel nightly")
        );
    }

    #[test]
    fn public_discovery_enforces_dependency_and_aggregate_byte_limits() {
        let fixture = EvidenceFixture::new();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        };
        let dependency_limits = DependencyPackLimits {
            max_dependencies: 0,
            ..DependencyPackLimits::default()
        };
        let dependency_outcome =
            resolve_rust_semantic_pack_dependencies(&config, &project, &dependency_limits, None);
        assert_eq!(dependency_outcome.diagnostics[0].code, "limit.dependencies");

        let byte_limits = DependencyPackLimits {
            max_total_artifact_bytes: 1,
            ..DependencyPackLimits::default()
        };
        let byte_outcome =
            resolve_rust_semantic_pack_dependencies(&config, &project, &byte_limits, None);
        assert_eq!(
            byte_outcome.diagnostics[0].code,
            "limit.total_artifact_bytes"
        );
    }

    #[test]
    fn invalid_bundles_still_consume_discovery_budgets() {
        let fixture = EvidenceFixture::new();
        fs::write(&fixture.evidence.metadata_path, b"not json").unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone(), fixture.evidence.clone()],
        };
        let limits = DependencyPackLimits {
            max_dependencies: 1,
            ..DependencyPackLimits::default()
        };

        let outcome = resolve_rust_semantic_pack_dependencies(&config, &project, &limits, None);

        assert_eq!(
            outcome
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            ["rust.metadata.invalid_json", "limit.dependencies"]
        );

        let mut bytes_read = 0;
        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut bytes_read,
            None,
        )
        .unwrap_err();
        assert_eq!(diagnostic.code, "rust.metadata.invalid_json");
        assert_eq!(bytes_read, b"not json".len() as u64);
    }

    #[test]
    fn unsupported_rustdoc_version_fails_before_full_decode() {
        let fixture = EvidenceFixture::new();
        fs::write(
            &fixture.rustdoc_path,
            serde_json::to_vec(&json!({ "format_version": rustdoc_types::FORMAT_VERSION + 1 }))
                .unwrap(),
        )
        .unwrap();

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.unsupported_version");
    }

    #[test]
    fn rustdoc_target_must_match_selected_target() {
        let fixture = EvidenceFixture::new();
        fixture.write_rustdoc("aarch64-apple-darwin");

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.target_mismatch");
    }

    #[test]
    fn cancellation_stops_before_decoding_evidence() {
        let fixture = EvidenceFixture::new();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            Some(&cancellation),
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "artifact.cancelled");
    }

    struct EvidenceFixture {
        _root: TempDir,
        rustdoc_path: std::path::PathBuf,
        evidence: RustDependencyApiEvidence,
    }

    impl EvidenceFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let metadata_path = root.path().join("metadata.json");
            let lockfile_path = root.path().join("Cargo.lock");
            let rustdoc_path = root.path().join("widget.json");
            fs::write(
                &lockfile_path,
                "version = 4\n\n[[package]]\nname = \"widget\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc123\"\n",
            )
            .unwrap();
            let evidence = RustDependencyApiEvidence {
                metadata_path,
                lockfile_path,
                target: TARGET.to_owned(),
                configuration: "library".to_owned(),
                selected_targets: vec![RustSelectedTarget {
                    package_id: "path+file:///workspace#consumer@0.1.0".to_owned(),
                    target_name: "consumer".to_owned(),
                    target_kind: "lib".to_owned(),
                }],
                packages: vec![RustPackageApiArtifact {
                    package_id: PACKAGE_ID.to_owned(),
                    crate_name: "widget".to_owned(),
                    enabled_features: vec!["derive".to_owned()],
                    rustdoc_json_path: rustdoc_path.clone(),
                    rustdoc_toolchain: "nightly-2026-07-14".to_owned(),
                    rustdoc_format_version: rustdoc_types::FORMAT_VERSION,
                }],
            };
            let fixture = Self {
                _root: root,
                rustdoc_path,
                evidence,
            };
            fixture.write_metadata(true);
            fixture.write_rustdoc(TARGET);
            fixture
        }

        fn write_metadata(&self, reachable: bool) {
            let dependencies = if reachable {
                vec![json!({
                    "name": "renamed_widget",
                    "pkg": PACKAGE_ID,
                    "dep_kinds": [{ "kind": null, "target": null }]
                })]
            } else {
                Vec::new()
            };
            fs::write(
                &self.evidence.metadata_path,
                serde_json::to_vec(&json!({
                    "version": CARGO_METADATA_FORMAT_VERSION,
                    "packages": [
                        {
                            "id": "path+file:///workspace#consumer@0.1.0",
                            "name": "consumer",
                            "version": "0.1.0",
                            "source": null,
                            "targets": [{ "name": "consumer", "kind": ["lib"] }]
                        },
                        {
                            "id": PACKAGE_ID,
                            "name": "widget",
                            "version": "1.2.3",
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "targets": [{ "name": "widget", "kind": ["lib"] }]
                        }
                    ],
                    "resolve": {
                        "nodes": [
                            {
                                "id": "path+file:///workspace#consumer@0.1.0",
                                "features": [],
                                "deps": dependencies
                            },
                            {
                                "id": PACKAGE_ID,
                                "features": ["derive"],
                                "deps": []
                            }
                        ]
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        }

        fn write_rustdoc(&self, target: &str) {
            let document = RustdocCrate {
                root: Id(0),
                crate_version: Some("1.2.3".to_owned()),
                includes_private: false,
                index: HashMap::new(),
                paths: HashMap::new(),
                external_crates: HashMap::new(),
                target: Target {
                    triple: target.to_owned(),
                    target_features: Vec::new(),
                },
                format_version: rustdoc_types::FORMAT_VERSION,
            };
            fs::write(&self.rustdoc_path, serde_json::to_vec(&document).unwrap()).unwrap();
        }
    }
}
