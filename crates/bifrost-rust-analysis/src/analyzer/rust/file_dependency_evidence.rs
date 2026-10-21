//! Bounded, files-only Cargo evidence using the #2442 discovery envelope.
//!
//! This producer is deliberately separate from artifact-backed pack activation.
//! Its rows have no artifacts or selected target/configuration. Consumers must
//! preserve `evidence.kind` and association uncertainty when projecting them into
//! the shared durable dependency/query contract. Nothing is retained on an
//! analyzer, and queries must consume persisted rows rather than call acquisition.

use std::path::{Path, PathBuf};

use brokk_bifrost_rust::cargo_config::RustCargoConfiguration;
use brokk_bifrost_rust::cargo_manifest::RustCargoManifestDocument;
use brokk_bifrost_rust::cargo_routes::{
    RustCargoDependencyKind, cargo_dependency_directory_with, cargo_dependency_tables_with_kind,
    cargo_dependency_value, cargo_package_string, cargo_workspace_manifest_directory,
};
use semver::{Version, VersionReq};
use toml_edit::ImDocument;

use crate::analyzer::rust::dependency_discovery::CargoLockPackage;

use crate::analyzer::rust::dependency_discovery::CargoLockfile;

use crate::analyzer::rust::dependency_discovery::cargo_lock_reference;

use crate::analyzer::rust::dependency_discovery::decode_cargo_lockfile;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use crate::analyzer::semantic_model::{
    BoundedDependencyDiagnostics, CatalogCoordinate, DependencyCondition,
    DependencyDiscoveryOutcome, DependencyEvidence, DependencyEvidenceGap,
    DependencyEvidenceGapKind, DependencyEvidenceKind, DependencyFileEvidence,
    DependencyFileEvidenceLimits, DependencyPackLimits, DependencyProvenance, ResolvedDependency,
    SemanticModelActivationEvidence,
};
use brokk_bifrost_analysis::analyzer::dependency_support::dependency_diagnostic as diagnostic;

use crate::analyzer::topology::DependencyScope;

use brokk_bifrost_analysis::analyzer::topology::TopologyCompleteness;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntity;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntityKind;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenance;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenanceKind;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::path_normalization::NormalizePath;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Acquire selected disk/overlay snapshots without invoking any Cargo tool.
/// All maps are bounded by the supplied limits and live only for this request.
/// The result is static evidence, not a semantic-pack activation request.
fn acquire_cargo_discovery_rows(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> (DependencyDiscoveryOutcome, usize) {
    let mut selected = Vec::new();
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let mut bytes = 0_u64;
    let mut cancelled = false;
    let files = match project.all_files_shared() {
        Ok(files) => files,
        Err(error) => {
            diagnostics.push(diagnostic("rust.files.list", None, error.to_string()));
            let mut outcome = DependencyDiscoveryOutcome::complete(Vec::new());
            (outcome.diagnostics, outcome.suppressed_diagnostics) = diagnostics.finish();
            outcome.complete = false;
            return (outcome, 0);
        }
    };
    for file in files.iter().filter(|file| cargo_input(file.rel_path())) {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            diagnostics.push(diagnostic(
                "rust.evidence.cancelled",
                None,
                "Cargo file acquisition cancelled",
            ));
            break;
        }
        if selected.len() >= limits.max_source_files_per_artifact {
            diagnostics.push(diagnostic(
                "limit.cargo_files",
                None,
                "Cargo file count exceeds the dependency evidence limit",
            ));
            break;
        }
        let remaining = limits.max_total_artifact_bytes.saturating_sub(bytes);
        let cap = remaining
            .min(limits.producer.max_artifact_bytes)
            .min(usize::MAX as u64) as usize;
        if cap == 0 {
            diagnostics.push(diagnostic(
                "limit.total_artifact_bytes",
                Some(file.rel_path()),
                "Cargo evidence byte budget exhausted",
            ));
            break;
        }
        match project.read_source_snapshot_limited(file, cap) {
            Ok(Some(snapshot)) => {
                bytes += snapshot.source().len() as u64;
                selected.push((file.clone(), snapshot));
            }
            Ok(None) => diagnostics.push(diagnostic(
                "limit.artifact_bytes",
                Some(file.rel_path()),
                "selected Cargo snapshot exceeds its byte limit",
            )),
            Err(error) => diagnostics.push(diagnostic(
                "rust.files.read",
                Some(file.rel_path()),
                error.to_string(),
            )),
        }
    }
    let mut outcome = cargo_file_discovery_rows(project.root(), &selected, limits, cancellation);
    for entry in outcome.diagnostics.drain(..) {
        diagnostics.push(entry);
    }
    let (entries, suppressed) = diagnostics.finish();
    // Preserve both independently bounded diagnostic sets' omission counts.
    outcome.suppressed_diagnostics += suppressed;
    outcome.diagnostics = entries;
    outcome.cancelled |= cancelled;
    outcome.complete &= outcome.diagnostics.is_empty()
        && outcome.suppressed_diagnostics.errors == 0
        && !outcome.cancelled;
    (outcome, bytes as usize)
}
fn cargo_input(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("Cargo.toml" | "Cargo.lock")
    ) || (path
        .parent()
        .is_some_and(|parent| parent.ends_with(".cargo"))
        && matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("config" | "config.toml")
        ))
}

/// Project a bounded set of immutable Cargo snapshots. The caller selects the
/// input files; this function never reads disk, environment, or build artifacts.
/// Duplicate paths and lossy-decoded snapshots are rejected explicitly.
fn cargo_file_discovery_rows(
    root: &Path,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    if !selected.iter().any(|(file, _)| {
        matches!(
            file.rel_path().file_name().and_then(|n| n.to_str()),
            Some("Cargo.toml" | "Cargo.lock")
        )
    }) {
        diagnostics.push(diagnostic(
            "rust.cargo.missing_inputs",
            None,
            "no Cargo manifest or lockfile is selected; dependency evidence is missing",
        ));
    }
    let mut manifests = HashMap::default();
    let mut sources = HashMap::default();
    let mut documents = HashMap::default();
    let mut locks = HashMap::default();
    let mut configs = Vec::new();
    let mut rows = Vec::new();
    let mut retained_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut cancelled = false;
    let mut inputs = 0;
    for (file, snapshot) in selected
        .iter()
        .filter(|(file, _)| cargo_input(file.rel_path()))
    {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            break;
        }
        if inputs >= limits.max_source_files_per_artifact {
            diagnostics.push(diagnostic(
                "limit.cargo_files",
                None,
                "Cargo file count exceeds the dependency evidence limit",
            ));
            break;
        }
        inputs += 1;
        total_bytes = total_bytes.saturating_add(snapshot.source().len() as u64);
        if snapshot.source().len() as u64 > limits.producer.max_artifact_bytes
            || total_bytes > limits.max_total_artifact_bytes
        {
            diagnostics.push(diagnostic(
                "limit.artifact_bytes",
                Some(file.rel_path()),
                "selected Cargo snapshots exceed the byte budget",
            ));
            break;
        }
        if file.root() != root
            || !file.rel_path().is_relative()
            || file
                .rel_path()
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            diagnostics.push(diagnostic(
                "rust.files.outside_workspace",
                Some(file.rel_path()),
                "Cargo input must belong to the selected workspace",
            ));
            continue;
        }
        if sources.contains_key(file.rel_path()) {
            diagnostics.push(diagnostic(
                "rust.files.duplicate_snapshot",
                Some(file.rel_path()),
                "multiple selected snapshots for one Cargo file",
            ));
            continue;
        }
        // Disk source decoding can be lossy; never relabel decoded bytes as the
        // exact original evidence. This also catches a custom mismatched OID.
        let actual = git2::Oid::hash_object(git2::ObjectType::Blob, snapshot.source().as_bytes())
            .expect("hashing selected Cargo bytes");
        if actual != snapshot.oid() {
            diagnostics.push(diagnostic(
                "rust.files.inexact_source",
                Some(file.rel_path()),
                "Cargo snapshot is not exact UTF-8 evidence",
            ));
            continue;
        }
        sources.insert(file.rel_path().to_path_buf(), snapshot);
        match ImDocument::parse(snapshot.source()) {
            Ok(document) => {
                documents.insert(file.rel_path().to_path_buf(), document);
            }
            Err(error) => {
                diagnostics.push(diagnostic(
                    "rust.files.invalid_toml",
                    Some(file.rel_path()),
                    error.to_string(),
                ));
                continue;
            }
        }
        let directory = file
            .rel_path()
            .parent()
            .expect("Cargo file has a parent")
            .to_path_buf();
        match file.rel_path().file_name().and_then(|name| name.to_str()) {
            Some("Cargo.toml") => match RustCargoManifestDocument::from_source(snapshot.source()) {
                Ok(manifest) => match validate_manifest(&manifest) {
                    Ok(()) => {
                        manifests.insert(directory, manifest);
                    }
                    Err(error) => diagnostics.push(diagnostic(
                        "rust.manifest.invalid_shape",
                        Some(file.rel_path()),
                        error,
                    )),
                },
                Err(error) => diagnostics.push(diagnostic(
                    "rust.manifest.invalid_toml",
                    Some(file.rel_path()),
                    error,
                )),
            },
            Some("Cargo.lock") => match decode_cargo_lockfile(snapshot.source(), file.rel_path()) {
                Ok(lock) => {
                    locks.insert(directory, lock);
                }
                Err(entry) => diagnostics.push(entry),
            },
            _ => configs.push(file.rel_path().to_path_buf()),
        }
    }
    if manifests.is_empty() {
        diagnostics.push(diagnostic(
            "rust.manifest.missing",
            None,
            "no readable selected Cargo manifest; absence of dependencies is unverified",
        ));
    }
    let mut directories = manifests.keys().collect::<Vec<_>>();
    directories.sort();
    for directory in directories {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            break;
        }
        let manifest = &manifests[directory];
        let path = directory.join("Cargo.toml");
        let snapshot = sources[&path];
        let spans = &documents[&path];
        validate_members(directory, manifest, &manifests, &mut diagnostics);
        // A virtual workspace's dependency table is inheritance data, not a
        // declaration by every member or a dependency of the workspace itself.
        if manifest.package_name().is_none() {
            continue;
        }
        let workspace = cargo_workspace_manifest_directory(root, directory, manifest, &manifests);
        let membership = workspace.as_deref().is_some_and(|workspace| {
            workspace == directory || explicit_member(root, workspace, directory, &manifests)
        });
        let owner = member_entity(directory);
        let mut declaration_count = 0;
        for (kind, target, table) in cargo_dependency_tables_with_kind(manifest) {
            for (alias, raw) in table {
                if rows.len() >= limits.max_dependencies {
                    diagnostics.push(diagnostic(
                        "limit.dependencies",
                        Some(&path),
                        "Cargo evidence row limit exceeded",
                    ));
                    break;
                }
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    cancelled = true;
                    break;
                }
                let inherited = raw.get("workspace").and_then(toml::Value::as_bool) == Some(true);
                let effective = if inherited && !membership {
                    None
                } else {
                    cargo_dependency_value(root, directory, manifest, alias, raw, &manifests)
                };
                let mut provenance = vec![
                    entry("evidence.kind", "declared"),
                    entry("cargo.alias", alias),
                    entry("cargo.dependency_kind", kind_label(kind)),
                    entry("cargo.activation", "unresolved"),
                ];
                source_provenance(
                    &mut provenance,
                    &path,
                    snapshot,
                    declaration_span(spans, kind, target, alias),
                );
                provenance.push(entry(
                    "cargo.member_package",
                    manifest.package_name().expect("member package"),
                ));
                if membership {
                    if let Some(workspace) = &workspace {
                        provenance.push(entry(
                            "cargo.workspace_manifest",
                            display(&workspace.join("Cargo.toml")),
                        ));
                    }
                } else {
                    provenance.push(entry("cargo.workspace_membership", "unresolved"));
                }
                if let Some(workspace) = workspace
                    .as_ref()
                    .and_then(|workspace| manifests.get(workspace))
                {
                    for key in ["patch", "replace"] {
                        if let Some(declaration) = workspace.get(key) {
                            provenance
                                .push(entry(&format!("cargo.{key}_declaration"), declaration));
                        }
                    }
                }
                if let Some(target) = target {
                    provenance.push(entry("cargo.target_condition", target));
                }
                for (feature, values) in manifest
                    .get("features")
                    .and_then(toml::Value::as_table)
                    .into_iter()
                    .flatten()
                {
                    provenance.push(entry(
                        &format!("cargo.feature_declaration.{feature}"),
                        values.to_string(),
                    ));
                }
                let (value, base) = effective
                    .as_ref()
                    .map_or((raw, directory.as_path()), |(value, base)| {
                        (*value, base.as_path())
                    });
                if inherited {
                    provenance.push(entry("cargo.inherited", "true"));
                    if effective.is_some() {
                        let inherited_path = base.join("Cargo.toml");
                        provenance.push(entry("cargo.inherited_from", display(&inherited_path)));
                        if let Some(source) = sources.get(&inherited_path) {
                            provenance.push(entry("cargo.inherited_snapshot_oid", source.oid()));
                            let inherited_spans = &documents[&inherited_path];
                            if let Some(span) = inherited_spans
                                .get("workspace")
                                .and_then(|item| item.get("dependencies"))
                                .and_then(|item| item.get(alias))
                                .and_then(toml_edit::Item::span)
                            {
                                provenance.push(entry("cargo.inherited_start_byte", span.start));
                                provenance.push(entry("cargo.inherited_end_byte", span.end));
                            }
                        }
                    } else {
                        diagnostics.push(diagnostic(
                            "rust.manifest.unresolved_inheritance",
                            Some(&path),
                            format!(
                                "workspace dependency {alias} is not established for this member"
                            ),
                        ));
                    }
                }
                provenance.push(entry("cargo.source_base", display(base)));
                let package = value
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(alias);
                let requirement = value
                    .as_str()
                    .or_else(|| value.get("version").and_then(toml::Value::as_str));
                if let Some(requirement) = requirement {
                    provenance.push(entry("cargo.version_requirement", requirement));
                }
                let version_requirement = requirement.map(VersionReq::parse).transpose();
                if let Err(error) = &version_requirement {
                    diagnostics.push(diagnostic(
                        "rust.manifest.invalid_version_requirement",
                        Some(&path),
                        format!("{alias}: {error}"),
                    ));
                }
                for key in [
                    "path",
                    "git",
                    "registry",
                    "registry-index",
                    "branch",
                    "tag",
                    "rev",
                ] {
                    if let Some(value) = value.get(key) {
                        provenance.push(entry(
                            &format!("cargo.{key}"),
                            value.as_str().expect("validated source setting"),
                        ));
                    }
                }
                let optional = raw
                    .get("optional")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false);
                provenance.push(entry("cargo.optional", optional));
                let default_features = value
                    .get("default-features")
                    .or_else(|| value.get("default_features"))
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(true);
                // In inherited declarations member false cannot disable an
                // inherited true. Retain both authored settings as evidence.
                provenance.push(entry("cargo.default_features", default_features));
                if let Some(setting) = raw
                    .get("default-features")
                    .or_else(|| raw.get("default_features"))
                {
                    provenance.push(entry("cargo.member_default_features", setting));
                }
                for features in [
                    value.get("features"),
                    inherited.then(|| raw.get("features")).flatten(),
                ]
                .into_iter()
                .flatten()
                {
                    for feature in features.as_array().expect("validated dependency features") {
                        provenance.push(entry(
                            "cargo.requested_feature",
                            feature.as_str().expect("validated feature"),
                        ));
                    }
                }
                let mut row = ResolvedDependency {
                    id: identity(
                        "declared",
                        &[
                            &display(&path),
                            kind_label(kind),
                            target.unwrap_or(""),
                            alias,
                        ],
                    ),
                    evidence: activation(package, None),
                    provenance,
                    artifacts: Vec::new(),
                    scope: match kind {
                        RustCargoDependencyKind::Normal => DependencyScope::Compile,
                        RustCargoDependencyKind::Development => DependencyScope::Test,
                        RustCargoDependencyKind::Build => DependencyScope::Unknown,
                    },
                    declared_by: Some(owner.id()),
                };
                if inherited && effective.is_none() {
                    // The alias is known, but the inherited package identity
                    // is not. Do not turn the alias into a package identity.
                    row.evidence.package = None;
                }
                let association = associate(
                    root,
                    directory,
                    manifest,
                    alias,
                    raw,
                    value,
                    base,
                    package,
                    version_requirement
                        .as_ref()
                        .ok()
                        .and_then(|value| value.as_ref()),
                    effective.is_some() && version_requirement.is_ok(),
                    workspace.as_deref().filter(|_| membership),
                    &manifests,
                    &locks,
                    &configs,
                    &mut row.provenance,
                );
                if association != "exact" {
                    diagnostics.push(diagnostic("rust.lockfile.unresolved_association", Some(&path), format!("{alias}: declaration-to-lock association is {association}; activation remains unresolved")));
                }
                row.provenance
                    .push(entry("cargo.lock_association", association));
                if !push_row(
                    &mut rows,
                    &mut retained_bytes,
                    row,
                    limits,
                    &path,
                    &mut diagnostics,
                ) {
                    break;
                }
                declaration_count += 1;
            }
        }
        if declaration_count == 0
            && workspace
                .as_ref()
                .is_some_and(|workspace| !locks.contains_key(workspace))
        {
            diagnostics.push(diagnostic(
                "rust.lockfile.missing",
                Some(&path),
                "member has no selected lockfile",
            ));
        }
    }
    let mut lock_directories = locks.keys().collect::<Vec<_>>();
    lock_directories.sort();
    for directory in lock_directories {
        let lock = &locks[directory];
        let path = directory.join("Cargo.lock");
        let snapshot = sources[&path];
        let spans = &documents[&path];
        let mut seen = HashSet::default();
        for (index, package) in lock.packages.iter().enumerate() {
            if rows.len() >= limits.max_dependencies {
                diagnostics.push(diagnostic(
                    "limit.dependencies",
                    Some(&path),
                    "Cargo evidence row limit exceeded",
                ));
                break;
            }
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                cancelled = true;
                break;
            }
            let id = lock_identity(&path, package);
            let mut provenance = vec![
                entry("evidence.kind", "locked"),
                entry("cargo.lockfile_version", lock.version),
                entry("cargo.activation", "unresolved"),
            ];
            source_provenance(
                &mut provenance,
                &path,
                snapshot,
                spans
                    .get("package")
                    .and_then(toml_edit::Item::as_array_of_tables)
                    .and_then(|tables| tables.get(index))
                    .and_then(toml_edit::Table::span),
            );
            if let Some(source) = &package.source {
                provenance.push(entry("cargo.source", source));
                if let Some((_, revision)) = source
                    .strip_prefix("git+")
                    .and_then(|value| value.rsplit_once('#'))
                {
                    provenance.push(entry("cargo.git_revision", revision));
                }
            } else {
                provenance.push(entry("cargo.source_kind", "path_unspecified"));
            }
            if let Some(checksum) = &package.checksum {
                provenance.push(entry("cargo.checksum", checksum));
            }
            for dependency in &package.dependencies {
                provenance.push(entry("cargo.lock_dependency", dependency));
            }
            if !seen.insert(id.clone()) {
                diagnostics.push(diagnostic(
                    "rust.lockfile.duplicate_identity",
                    Some(&path),
                    format!(
                        "duplicate exact lock instance {} {} {:?}",
                        package.name, package.version, package.source
                    ),
                ));
            }
            let row = ResolvedDependency {
                id,
                evidence: activation(
                    &package.name,
                    Some(Version::parse(&package.version).expect("validated locked version")),
                ),
                provenance,
                artifacts: Vec::new(),
                scope: DependencyScope::Unknown,
                declared_by: None,
            };
            if !push_row(
                &mut rows,
                &mut retained_bytes,
                row,
                limits,
                &path,
                &mut diagnostics,
            ) {
                break;
            }
        }
    }
    for path in configs {
        diagnostics.push(diagnostic("rust.configuration.unresolved", Some(&path), "Cargo configuration overrides are owned by #3768; no effective target, rustflags, or patch selection is inferred"));
    }
    if cancelled {
        diagnostics.push(diagnostic(
            "rust.evidence.cancelled",
            None,
            "Cargo file projection cancelled",
        ));
    }
    for row in &mut rows {
        row.provenance
            .sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));
        row.provenance.dedup();
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let (entries, suppressed) = diagnostics.finish();
    let mut outcome = DependencyDiscoveryOutcome::complete(rows);
    outcome.profile.metadata_inputs_considered = inputs;
    outcome.complete = entries.is_empty() && suppressed.errors == 0 && !cancelled;
    outcome.cancelled = cancelled;
    outcome.diagnostics = entries;
    outcome.suppressed_diagnostics = suppressed;
    outcome
}

fn entry(key: &str, value: impl ToString) -> DependencyProvenance {
    DependencyProvenance {
        key: key.to_owned(),
        value: value.to_string(),
    }
}
fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
fn identity(kind: &str, values: &[&str]) -> String {
    let mut hash = CanonicalHasher::new(b"bifrost.cargo.file_evidence.v1");
    hash.field("kind", kind.as_bytes());
    for value in values {
        hash.value(value.as_bytes());
    }
    lower_hex_string(&hash.finish())
}
fn lock_identity(path: &Path, package: &CargoLockPackage) -> String {
    identity(
        "locked",
        &[
            &display(path),
            &package.name,
            &package.version,
            package.source.as_deref().unwrap_or(""),
        ],
    )
}
fn activation(package: &str, version: Option<Version>) -> SemanticModelActivationEvidence {
    SemanticModelActivationEvidence {
        language: "rust".to_owned(),
        ecosystem: "cargo".to_owned(),
        package: Some(CatalogCoordinate {
            name: package.to_owned(),
            version,
        }),
        module: None,
        toolchain: None,
        target: None,
        configuration: None,
        artifact_sha256: None,
    }
}
fn kind_label(kind: RustCargoDependencyKind) -> &'static str {
    match kind {
        RustCargoDependencyKind::Normal => "normal",
        RustCargoDependencyKind::Development => "dev",
        RustCargoDependencyKind::Build => "build",
    }
}
fn kind_table(kind: RustCargoDependencyKind) -> &'static str {
    match kind {
        RustCargoDependencyKind::Normal => "dependencies",
        RustCargoDependencyKind::Development => "dev-dependencies",
        RustCargoDependencyKind::Build => "build-dependencies",
    }
}
pub(crate) fn member_entity(directory: &Path) -> TopologyEntity {
    TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        name: format!("cargo:{}", display(&directory.join("Cargo.toml"))),
        owner: None,
        root: Some(directory.to_path_buf()),
        provenance: vec![TopologyProvenance::new(
            directory.join("Cargo.toml"),
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    }
}
fn source_provenance(
    provenance: &mut Vec<DependencyProvenance>,
    path: &Path,
    snapshot: &ProjectSourceSnapshot,
    span: Option<std::ops::Range<usize>>,
) {
    provenance.push(entry("evidence.file", display(path)));
    provenance.push(entry("evidence.snapshot_oid", snapshot.oid()));
    provenance.push(entry("evidence.configuration_selection", "unresolved"));
    if let Some(span) = span {
        provenance.push(entry("evidence.start_byte", span.start));
        provenance.push(entry("evidence.end_byte", span.end));
    }
}
fn declaration_span(
    document: &ImDocument<&str>,
    kind: RustCargoDependencyKind,
    target: Option<&str>,
    alias: &str,
) -> Option<std::ops::Range<usize>> {
    let table = match target {
        Some(target) => document.get("target")?.get(target)?,
        None => document.as_item(),
    };
    let dependencies = table.get(kind_table(kind))?;
    let value = dependencies.get(alias)?;
    let key = dependencies.as_table_like()?.key(alias)?.span()?;
    Some(key.start..value.span().map_or(key.end, |range| range.end))
}
fn push_row(
    rows: &mut Vec<ResolvedDependency>,
    retained_bytes: &mut u64,
    row: ResolvedDependency,
    limits: &DependencyPackLimits,
    path: &Path,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> bool {
    let retained = retained_bytes
        .saturating_add(row.id.len() as u64)
        .saturating_add(row.provenance.iter().fold(0_u64, |total, entry| {
            total
                .saturating_add(entry.key.len() as u64)
                .saturating_add(entry.value.len() as u64)
        }));
    if retained > limits.max_total_artifact_bytes {
        diagnostics.push(diagnostic(
            "limit.retained_evidence_bytes",
            Some(path),
            "Cargo evidence output exceeds its retained byte budget",
        ));
        return false;
    }
    if rows.len() >= limits.max_dependencies {
        diagnostics.push(diagnostic(
            "limit.dependencies",
            Some(path),
            "Cargo evidence row limit exceeded",
        ));
        false
    } else {
        *retained_bytes = retained;
        rows.push(row);
        true
    }
}

fn validate_dependency(value: &toml::Value, inherited: bool) -> Result<(), String> {
    if value.as_str().is_some() {
        return Ok(());
    }
    let table = value
        .as_table()
        .ok_or("dependency must be a version string or table")?;
    for key in [
        "package",
        "version",
        "path",
        "git",
        "registry",
        "registry-index",
        "branch",
        "tag",
        "rev",
    ] {
        if table.get(key).is_some_and(|value| value.as_str().is_none()) {
            return Err(format!("dependency {key} must be a string"));
        }
        if inherited && table.contains_key(key) {
            return Err(format!(
                "workspace-inherited dependency cannot override {key}"
            ));
        }
    }
    for key in [
        "workspace",
        "optional",
        "default-features",
        "default_features",
    ] {
        if table
            .get(key)
            .is_some_and(|value| value.as_bool().is_none())
        {
            return Err(format!("dependency {key} must be a boolean"));
        }
    }
    if let Some(features) = table.get("features") {
        string_array(features)?;
    }
    if !inherited
        && !["version", "path", "git"]
            .iter()
            .any(|key| table.contains_key(*key))
    {
        return Err("dependency has no version, path, git, or workspace requirement".to_owned());
    }
    if (table.contains_key("git")
        && ["path", "registry", "registry-index"]
            .iter()
            .any(|key| table.contains_key(*key)))
        || (table.contains_key("registry") && table.contains_key("registry-index"))
    {
        return Err("dependency has conflicting source selectors".to_owned());
    }
    if ["branch", "tag", "rev"]
        .iter()
        .filter(|key| table.contains_key(**key))
        .count()
        > 1
    {
        return Err("git dependency has conflicting revision selectors".to_owned());
    }
    if ["branch", "tag", "rev"]
        .iter()
        .any(|key| table.contains_key(*key))
        && !table.contains_key("git")
    {
        return Err("revision selector requires a git source".to_owned());
    }
    if table.get("workspace").and_then(toml::Value::as_bool) == Some(false) {
        return Err("dependency workspace inheritance must be true".to_owned());
    }
    Ok(())
}
fn string_array(value: &toml::Value) -> Result<(), String> {
    if value
        .as_array()
        .is_some_and(|values| values.iter().all(|value| value.as_str().is_some()))
    {
        Ok(())
    } else {
        Err("expected an array of strings".to_owned())
    }
}
fn validate_manifest(manifest: &RustCargoManifestDocument) -> Result<(), String> {
    for key in [
        "package",
        "workspace",
        "features",
        "target",
        "patch",
        "replace",
    ] {
        if manifest
            .get(key)
            .is_some_and(|value| value.as_table().is_none())
        {
            return Err(format!("{key} must be a table"));
        }
    }
    if manifest.get("package").is_some() && manifest.package_name().is_none_or(str::is_empty) {
        return Err("package.name must be a nonempty string".to_owned());
    }
    if let Some(package) = manifest.get("package") {
        if let Some(version) = package.get("version") {
            if let Some(version) = version.as_str() {
                Version::parse(version)
                    .map_err(|error| format!("invalid package version: {error}"))?;
            } else if version.get("workspace").and_then(toml::Value::as_bool) != Some(true) {
                return Err(
                    "package.version must be a version string or workspace inheritance".to_owned(),
                );
            }
        }
        if package
            .get("workspace")
            .is_some_and(|workspace| workspace.as_str().is_none())
        {
            return Err("package.workspace must be a string".to_owned());
        }
    }
    if let Some(workspace) = manifest.get("workspace") {
        if let Some(dependencies) = workspace
            .get("dependencies")
            .and_then(toml::Value::as_table)
        {
            for (alias, dependency) in dependencies {
                if dependency.get("optional").and_then(toml::Value::as_bool) == Some(true)
                    || dependency.get("workspace").is_some()
                {
                    return Err(format!(
                        "workspace dependency {alias} cannot be optional or inherit workspace"
                    ));
                }
            }
        }
        if let Some(version) = workspace
            .get("package")
            .and_then(|package| package.get("version"))
        {
            Version::parse(
                version
                    .as_str()
                    .ok_or("workspace.package.version must be a string")?,
            )
            .map_err(|error| format!("invalid workspace package version: {error}"))?;
        }
    }
    let mut containers = Vec::new();
    for (target, container) in manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
    {
        if container.as_table().is_none() {
            return Err(format!("target {target} must be a table"));
        }
        containers.push(Some(container));
    }
    containers.push(manifest.get("workspace"));
    for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let all = std::iter::once(manifest.get(table)).chain(
            containers
                .iter()
                .map(|container| container.and_then(|container| container.get(table))),
        );
        for value in all.flatten() {
            let entries = value
                .as_table()
                .ok_or_else(|| format!("{table} must be a table"))?;
            for (alias, dependency) in entries {
                let inherited =
                    dependency.get("workspace").and_then(toml::Value::as_bool) == Some(true);
                validate_dependency(dependency, inherited)
                    .map_err(|error| format!("{table}.{alias}: {error}"))?;
            }
        }
    }
    for key in ["members", "exclude", "default-members"] {
        if let Some(value) = manifest
            .get("workspace")
            .and_then(|workspace| workspace.get(key))
        {
            string_array(value)?;
        }
    }
    for (_, features) in manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
    {
        string_array(features)?;
    }
    Ok(())
}

/// Match the structured workspace list against selected manifest directories.
/// No disk glob expansion or path-prefix ownership fallback is used.
fn explicit_member(
    root: &Path,
    workspace: &Path,
    directory: &Path,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
) -> bool {
    let Some(workspace_manifest) = manifests.get(workspace) else {
        return false;
    };
    let Some(table) = workspace_manifest.get("workspace") else {
        return false;
    };
    let matches = |key: &str, candidate: &Path| {
        candidate.strip_prefix(workspace).is_ok_and(|relative| {
            table
                .get(key)
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .any(|pattern| {
                    glob::Pattern::new(pattern).is_ok_and(|pattern| pattern.matches_path(relative))
                })
        })
    };
    if matches("exclude", directory) {
        return false;
    }
    let mut known = HashSet::default();
    let mut pending = Vec::new();
    for (candidate, manifest) in manifests {
        let explicit_workspace = manifest
            .get("package")
            .and_then(|package| package.get("workspace"))
            .and_then(toml::Value::as_str)
            .is_some_and(|path| {
                root.join(candidate).join(path).normalize() == root.join(workspace).normalize()
            });
        if !matches("exclude", candidate)
            && (candidate == workspace || matches("members", candidate) || explicit_workspace)
        {
            known.insert(candidate.clone());
            pending.push(candidate.clone());
        }
    }
    // Cargo automatically includes in-workspace path dependencies of members.
    // Follow only those structured declarations, never a directory prefix.
    while let Some(member) = pending.pop() {
        let Some(manifest) = manifests.get(&member) else {
            continue;
        };
        for (_, _, dependencies) in cargo_dependency_tables_with_kind(manifest) {
            for (alias, value) in dependencies {
                let Some((value, base)) =
                    cargo_dependency_value(root, &member, manifest, alias, value, manifests)
                else {
                    continue;
                };
                let Some(path) = value.get("path").and_then(toml::Value::as_str) else {
                    continue;
                };
                let absolute = root.join(base).join(path).normalize();
                let Ok(candidate) = absolute.strip_prefix(root.to_path_buf().normalize()) else {
                    continue;
                };
                if candidate.starts_with(workspace)
                    && manifests.contains_key(candidate)
                    && !matches("exclude", candidate)
                    && known.insert(candidate.to_path_buf())
                {
                    pending.push(candidate.to_path_buf());
                }
            }
        }
    }
    known.contains(directory)
}

fn validate_members(
    directory: &Path,
    manifest: &RustCargoManifestDocument,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
    diagnostics: &mut BoundedDependencyDiagnostics,
) {
    for member in manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
    {
        match glob::Pattern::new(member) {
            Ok(pattern)
                if manifests.keys().any(|candidate| {
                    candidate
                        .strip_prefix(directory)
                        .is_ok_and(|relative| pattern.matches_path(relative))
                }) => {}
            Ok(_) => diagnostics.push(diagnostic(
                "rust.workspace.missing_member",
                Some(&directory.join("Cargo.toml")),
                format!("workspace member {member} has no selected readable manifest"),
            )),
            Err(error) => diagnostics.push(diagnostic(
                "rust.workspace.invalid_member_pattern",
                Some(&directory.join("Cargo.toml")),
                error.to_string(),
            )),
        }
    }
}

/// Cargo lock reference grammar: name [version] [(source)]. This parses a
/// Cargo wire identity, never a Rust source path or rendered analyzer identity.
fn lock_reference_matches(
    reference: &str,
    package: &CargoLockPackage,
) -> Result<bool, &'static str> {
    let (name, version, source) = cargo_lock_reference(reference)?;
    Ok(name == package.name
        && version.is_none_or(|version| version == package.version)
        && source.is_none_or(|source| Some(source) == package.source.as_deref()))
}

#[allow(clippy::too_many_arguments)]
fn associate(
    root: &Path,
    directory: &Path,
    manifest: &RustCargoManifestDocument,
    alias: &str,
    raw: &toml::Value,
    value: &toml::Value,
    base: &Path,
    package: &str,
    requirement: Option<&VersionReq>,
    declaration_known: bool,
    workspace: Option<&Path>,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
    locks: &HashMap<PathBuf, CargoLockfile>,
    configs: &[PathBuf],
    provenance: &mut Vec<DependencyProvenance>,
) -> &'static str {
    let Some(workspace) = workspace else {
        provenance.push(entry("cargo.lock_reason", "unresolved_member_ownership"));
        return "unresolved";
    };
    let lock_path = workspace.join("Cargo.lock");
    let Some(lock) = locks.get(workspace) else {
        provenance.push(entry("cargo.lock_reason", "missing_lockfile"));
        return "unresolved";
    };
    let member_version = cargo_package_string(root, directory, manifest, manifests, "version");
    let owners = lock
        .packages
        .iter()
        .filter(|locked| {
            Some(locked.name.as_str()) == manifest.package_name()
                && Some(locked.version.as_str()) == member_version.as_deref()
                && locked.source.is_none()
        })
        .collect::<Vec<_>>();
    let member_identity_unique = manifests
        .iter()
        .filter(|(candidate_directory, candidate)| {
            candidate.package_name() == manifest.package_name()
                && cargo_package_string(root, candidate_directory, candidate, manifests, "version")
                    == member_version
        })
        .count()
        == 1;
    let owner = match owners.as_slice() {
        [owner] if member_identity_unique => *owner,
        _ => {
            provenance.push(entry(
                "cargo.lock_reason",
                "missing_or_ambiguous_member_lock_identity",
            ));
            return "unresolved";
        }
    };
    // Evidence leaves Cargo configuration unresolved (`configs` below), so the
    // path candidate is the manifests' route without configuration patches.
    let selected_path = cargo_dependency_directory_with(
        root,
        directory,
        manifest,
        alias,
        raw,
        manifests,
        &RustCargoConfiguration::default(),
        &mut |base, path| {
            let absolute = root.join(base).join(path).normalize();
            absolute
                .strip_prefix(root.to_path_buf().normalize())
                .ok()
                .map(Path::to_path_buf)
        },
    );
    let local_version = selected_path.as_ref().and_then(|directory| {
        manifests
            .get(directory)
            .filter(|manifest| manifest.package_name() == Some(package))
            .and_then(|manifest| {
                cargo_package_string(root, directory, manifest, manifests, "version")
            })
    });
    if let Some(selected_path) = &selected_path {
        provenance.push(entry(
            "cargo.path_candidate",
            display(&selected_path.join("Cargo.toml")),
        ));
    }
    let local_identity_unique = local_version.as_ref().is_none_or(|version| {
        manifests
            .iter()
            .filter(|(directory, manifest)| {
                manifest.package_name() == Some(package)
                    && cargo_package_string(root, directory, manifest, manifests, "version")
                        .as_ref()
                        == Some(version)
            })
            .count()
            == 1
    });
    let patches = manifests
        .get(workspace)
        .and_then(|manifest| manifest.get("patch"))
        .and_then(toml::Value::as_table);
    // The route helper proves only supported local patches. A git patch,
    // alternate registry, replacement, or conflicting patch remains explicit.
    let patch_present = patches.is_some_and(|sources| {
        sources
            .values()
            .filter_map(toml::Value::as_table)
            .any(|table| {
                table.iter().any(|(name, patch)| {
                    name == package
                        || patch.get("package").and_then(toml::Value::as_str) == Some(package)
                })
            })
    });
    let replacement_present = manifests
        .get(workspace)
        .is_some_and(|manifest| manifest.get("replace").is_some());
    let mut source_known =
        declaration_known && local_identity_unique && !replacement_present && configs.is_empty();
    if patch_present && local_version.is_none() {
        source_known = false;
        provenance.push(entry("cargo.lock_reason", "unsupported_or_ambiguous_patch"));
    }
    if replacement_present {
        provenance.push(entry("cargo.lock_reason", "unsupported_replacement"));
    }
    if !configs.is_empty() {
        provenance.push(entry("cargo.lock_reason", "unresolved_cargo_configuration"));
    }
    if value.get("path").is_some() && local_version.is_none() {
        source_known = false;
        provenance.push(entry("cargo.lock_reason", "missing_path_manifest"));
    }
    if let Some(registry) = value.get("registry").and_then(toml::Value::as_str)
        && registry != "crates-io"
    {
        source_known = false;
        provenance.push(entry("cargo.lock_reason", "unresolved_registry_name"));
    }
    if value.get("registry-index").is_some() {
        source_known = false;
        provenance.push(entry("cargo.lock_reason", "unsupported_registry_index"));
    }
    let git = value.get("git").and_then(toml::Value::as_str);
    let source_matches = |locked: &CargoLockPackage| {
        if let Some(version) = &local_version {
            return locked.source.is_none() && &locked.version == version;
        }
        if let Some(git) = git {
            let Some(source) = locked
                .source
                .as_deref()
                .and_then(|source| source.strip_prefix("git+"))
            else {
                return false;
            };
            let Some((source, revision)) = source.rsplit_once('#') else {
                return false;
            };
            if revision.is_empty() {
                return false;
            }
            let (repository, selector) = source
                .split_once('?')
                .map_or((source, None), |(repository, selector)| {
                    (repository, Some(selector))
                });
            if repository != git {
                return false;
            }
            let wanted = ["branch", "tag", "rev"].iter().find_map(|key| {
                value
                    .get(*key)
                    .and_then(toml::Value::as_str)
                    .map(|setting| format!("{key}={setting}"))
            });
            return selector == wanted.as_deref();
        }
        locked.source.as_deref() == Some(CRATES_IO)
    };
    let mut candidates = Vec::new();
    let mut malformed_reference = false;
    for locked in &lock.packages {
        if locked.name != package
            || requirement.is_some_and(|requirement| {
                !requirement
                    .matches(&Version::parse(&locked.version).expect("validated lock version"))
            })
        {
            continue;
        }
        let referenced = owner.dependencies.iter().any(|reference| {
            match lock_reference_matches(reference, locked) {
                Ok(matches) => matches,
                Err(_) => {
                    malformed_reference = true;
                    false
                }
            }
        });
        if referenced && (!source_known || source_matches(locked)) {
            candidates.push(locked);
        }
    }
    if malformed_reference {
        source_known = false;
        provenance.push(entry(
            "cargo.lock_reason",
            "malformed_lock_dependency_reference",
        ));
    }
    for locked in &candidates {
        provenance.push(entry(
            "cargo.lock_candidate",
            lock_identity(&lock_path, locked),
        ));
    }
    // The inherited source's base is retained even if no exact path can be
    // selected. This is provenance, not an ownership heuristic.
    provenance.push(entry("cargo.source_base", display(base)));
    if !source_known {
        return if candidates.len() > 1 {
            "ambiguous"
        } else {
            "unresolved"
        };
    }
    match candidates.as_slice() {
        [_] => "exact",
        [] => "unresolved",
        _ => "ambiguous",
    }
}

/// Acquire bounded Cargo file facts through the shared #2442 contract. No
/// subprocess, artifact preparation, or query-time discovery is performed.
pub fn acquire_rust_file_dependency_evidence(
    project: &dyn Project,
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyFileEvidence {
    let (outcome, bytes) =
        acquire_cargo_discovery_rows(project, &discovery_limits(limits), cancellation);
    shared_file_evidence(outcome, bytes, limits)
}

/// Interpret explicitly selected snapshots, including immutable revision or
/// overlay inputs. Nothing outside these snapshots participates in selection.
pub fn rust_file_dependency_evidence(
    root: &Path,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyFileEvidence {
    let outcome =
        cargo_file_discovery_rows(root, selected, &discovery_limits(limits), cancellation);
    let bytes = selected
        .iter()
        .filter(|(file, _)| cargo_input(file.rel_path()))
        .take(limits.max_files)
        .fold(0_usize, |total, (_, snapshot)| {
            total.saturating_add(snapshot.source().len())
        });
    shared_file_evidence(outcome, bytes, limits)
}

fn discovery_limits(limits: &DependencyFileEvidenceLimits) -> DependencyPackLimits {
    let mut discovery = DependencyPackLimits {
        max_dependencies: limits.max_rows,
        max_source_files_per_artifact: limits.max_files,
        max_total_artifact_bytes: limits.max_total_bytes as u64,
        ..DependencyPackLimits::default()
    };
    discovery.producer.max_artifact_bytes = limits.max_file_bytes as u64;
    discovery
}

fn shared_file_evidence(
    outcome: DependencyDiscoveryOutcome,
    bytes: usize,
    limits: &DependencyFileEvidenceLimits,
) -> DependencyFileEvidence {
    let mut result = DependencyFileEvidence {
        files_read: outcome.profile.metadata_inputs_considered,
        bytes_read: bytes,
        ..DependencyFileEvidence::default()
    };
    let mut locks = HashMap::default();
    let mut associations = Vec::new();
    for row in &outcome.dependencies {
        let get = |key: &str| {
            row.provenance
                .iter()
                .find(|entry| entry.key == key)
                .map(|entry| entry.value.as_str())
        };
        let Some(package) = &row.evidence.package else {
            continue;
        };
        let kind = match get("evidence.kind") {
            Some("declared") => DependencyEvidenceKind::Declared,
            Some("locked") => DependencyEvidenceKind::Locked,
            _ => unreachable!("Cargo file producer emits declarations and locks"),
        };
        let start = get("evidence.start_byte").and_then(|value| value.parse().ok());
        let end = get("evidence.end_byte").and_then(|value| value.parse().ok());
        let path = PathBuf::from(get("evidence.file").expect("Cargo evidence source path"));
        let (Some(start), Some(end)) = (start, end) else {
            result.gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Unresolved,
                build_file: path,
                byte_range: 0..0,
                message: "Cargo evidence has no exact parser range".to_owned(),
            });
            continue;
        };
        let source = if kind == DependencyEvidenceKind::Locked {
            get("cargo.source").map(str::to_owned)
        } else if let Some(git) = get("cargo.git") {
            Some(format!("git+{git}"))
        } else if let Some(path) = get("cargo.path") {
            Some(format!(
                "path:{}",
                display(
                    &Path::new(get("cargo.source_base").unwrap_or(""))
                        .join(path)
                        .normalize()
                )
            ))
        } else if let Some(registry) =
            get("cargo.registry").filter(|registry| *registry != "crates-io")
        {
            Some(format!("registry-name:{registry}"))
        } else {
            Some(CRATES_IO.to_owned())
        };
        let conditions = row
            .provenance
            .iter()
            .filter(|entry| {
                !matches!(
                    entry.key.as_str(),
                    "evidence.kind"
                        | "evidence.file"
                        | "evidence.snapshot_oid"
                        | "evidence.start_byte"
                        | "evidence.end_byte"
                        | "cargo.source"
                        | "cargo.version_requirement"
                )
            })
            .map(|entry| DependencyCondition {
                kind: entry.key.clone(),
                value: entry.value.clone(),
            })
            .collect::<Vec<_>>();
        let fact = DependencyEvidence {
            ecosystem: "cargo".to_owned(),
            package: package.name.clone(),
            kind,
            version_requirement: get("cargo.version_requirement").map(str::to_owned),
            exact_version: package.version.as_ref().map(ToString::to_string),
            source,
            locator: Some(row.id.clone()),
            declared_by: row.declared_by.clone(),
            scope: row.scope,
            conditions,
            build_file: path,
            source_digest: get("evidence.snapshot_oid")
                .expect("Cargo snapshot identity")
                .to_owned(),
            byte_range: start..end,
            complete: true,
        };
        if kind == DependencyEvidenceKind::Locked {
            locks.insert(row.id.as_str(), fact.clone());
        }
        if kind == DependencyEvidenceKind::Declared
            && get("cargo.lock_association") == Some("exact")
        {
            associations.push((
                get("cargo.lock_candidate").expect("exact association has a candidate"),
                fact.clone(),
            ));
        }
        result.rows.push(fact);
    }
    for (candidate, declaration) in associations {
        if result.rows.len() >= limits.max_rows {
            result.gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Limit,
                build_file: declaration.build_file,
                byte_range: declaration.byte_range,
                message: "Cargo associated lock row limit exceeded".to_owned(),
            });
            break;
        }
        let Some(locked) = locks.get(candidate) else {
            result.gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Unresolved,
                build_file: declaration.build_file,
                byte_range: declaration.byte_range,
                message: "associated lock evidence was omitted by an acquisition limit".to_owned(),
            });
            continue;
        };
        let mut associated = locked.clone();
        associated.declared_by = declaration.declared_by;
        associated.scope = declaration.scope;
        associated.conditions.extend(declaration.conditions);
        associated.conditions.push(DependencyCondition {
            kind: "cargo.declaration_file".to_owned(),
            value: display(&declaration.build_file),
        });
        associated.conditions.push(DependencyCondition {
            kind: "cargo.declaration_snapshot".to_owned(),
            value: declaration.source_digest,
        });
        associated.conditions.push(DependencyCondition {
            kind: "cargo.declaration_start_byte".to_owned(),
            value: declaration.byte_range.start.to_string(),
        });
        associated.conditions.push(DependencyCondition {
            kind: "cargo.declaration_end_byte".to_owned(),
            value: declaration.byte_range.end.to_string(),
        });
        associated
            .conditions
            .sort_by(|left, right| (&left.kind, &left.value).cmp(&(&right.kind, &right.value)));
        associated.conditions.dedup();
        result.rows.push(associated);
    }
    for entry in outcome.diagnostics {
        let kind = if entry.code == "rust.evidence.cancelled" {
            DependencyEvidenceGapKind::Cancelled
        } else if entry.code.starts_with("limit.") {
            DependencyEvidenceGapKind::Limit
        } else if entry.code.contains("duplicate") {
            DependencyEvidenceGapKind::Conflict
        } else if entry.code.contains("missing") {
            DependencyEvidenceGapKind::Missing
        } else if entry.code.contains("invalid") || entry.code.contains("inexact") {
            DependencyEvidenceGapKind::Malformed
        } else if entry.code.contains("unsupported") || entry.code.contains("configuration") {
            DependencyEvidenceGapKind::Unsupported
        } else {
            DependencyEvidenceGapKind::Unresolved
        };
        result.gaps.push(DependencyEvidenceGap {
            kind,
            build_file: entry.location.map(PathBuf::from).unwrap_or_default(),
            byte_range: 0..0,
            message: entry.message,
        });
    }
    if outcome.cancelled
        && !result
            .gaps
            .iter()
            .any(|gap| gap.kind == DependencyEvidenceGapKind::Cancelled)
    {
        result.gaps.push(DependencyEvidenceGap {
            kind: DependencyEvidenceGapKind::Cancelled,
            build_file: PathBuf::new(),
            byte_range: 0..0,
            message: "Cargo evidence acquisition cancelled".to_owned(),
        });
    }
    if outcome.suppressed_diagnostics.errors > 0 {
        result.gaps.push(DependencyEvidenceGap {
            kind: DependencyEvidenceGapKind::Limit,
            build_file: PathBuf::new(),
            byte_range: 0..0,
            message: format!(
                "Cargo diagnostic limit omitted {} errors",
                outcome.suppressed_diagnostics.errors
            ),
        });
    }
    let mut retained_bytes = 0_usize;
    let mut exceeded = false;
    result.rows.retain(|row| {
        let bytes = row
            .package
            .len()
            .saturating_add(row.source_digest.len())
            .saturating_add(row.conditions.iter().fold(0_usize, |total, condition| {
                total
                    .saturating_add(condition.kind.len())
                    .saturating_add(condition.value.len())
            }));
        retained_bytes = retained_bytes.saturating_add(bytes);
        let retain = retained_bytes <= limits.max_total_bytes;
        exceeded |= !retain;
        retain
    });
    if exceeded {
        result.gaps.push(DependencyEvidenceGap {
            kind: DependencyEvidenceGapKind::Limit,
            build_file: PathBuf::new(),
            byte_range: 0..0,
            message: "Cargo associated evidence exceeds retained byte limit".to_owned(),
        });
    }
    result.rows.sort_by_key(DependencyEvidence::id);
    result
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::file_dependency_evidence::*;

    fn root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\cargo-evidence")
        } else {
            PathBuf::from("/cargo-evidence")
        }
    }
    fn inputs(files: &[(&str, &str)]) -> Vec<(ProjectFile, ProjectSourceSnapshot)> {
        files
            .iter()
            .map(|(path, source)| {
                (
                    ProjectFile::new(root(), PathBuf::from(path)),
                    ProjectSourceSnapshot::disk(*source),
                )
            })
            .collect()
    }
    fn evidence(files: &[(&str, &str)]) -> DependencyDiscoveryOutcome {
        cargo_file_discovery_rows(
            &root(),
            &inputs(files),
            &DependencyPackLimits::default(),
            None,
        )
    }
    fn values<'a>(row: &'a ResolvedDependency, key: &'a str) -> impl Iterator<Item = &'a str> {
        row.provenance
            .iter()
            .filter(move |entry| entry.key == key)
            .map(|entry| entry.value.as_str())
    }
    fn declared<'a>(
        outcome: &'a DependencyDiscoveryOutcome,
        file: &str,
        alias: &str,
        kind: &str,
    ) -> &'a ResolvedDependency {
        outcome
            .dependencies
            .iter()
            .find(|row| {
                values(row, "evidence.kind").any(|value| value == "declared")
                    && values(row, "evidence.file").any(|value| value == file)
                    && values(row, "cargo.alias").any(|value| value == alias)
                    && values(row, "cargo.dependency_kind").any(|value| value == kind)
            })
            .unwrap_or_else(|| panic!("missing declaration {file} {alias} {kind}: {outcome:?}"))
    }
    const WORKSPACE: &str = r#"
[workspace]
members = ["alpha", "beta"]
[workspace.package]
version = "0.1.0"
[workspace.dependencies]
renamed = { package = "widget", version = "1", default-features = false, features = ["serde"] }
single = "1"
[patch.crates-io]
patched = { path = "patched" }
"#;
    const ALPHA: &str = r#"
[package]
name = "alpha"
version.workspace = true
[dependencies]
renamed = { workspace = true, optional = true, features = ["fast"] }
single.workspace = true
patched = "3"
[dev-dependencies]
widget = "2"
[build-dependencies]
helper = "1"
[target.'cfg(windows)'.dependencies]
conditional = { package = "widget", version = "1", optional = true }
[features]
default = ["dep:renamed"]
fast = ["renamed?/fast"]
"#;
    const BETA: &str = "[package]\nname='beta'\nversion='0.1.0'\n[dependencies]\nwidget='2'\n";
    const PATCHED: &str = "[package]\nname='patched'\nversion='3.2.1'\n";
    const LOCK: &str = r#"
version = 4
[[package]]
name = "alpha"
version = "0.1.0"
dependencies = ["widget 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)", "widget 2.3.4 (registry+https://github.com/rust-lang/crates.io-index)", "single", "helper", "patched"]
[[package]]
name = "beta"
version = "0.1.0"
dependencies = ["widget 2.3.4 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "widget"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[package]]
name = "widget"
version = "2.3.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "widget"
version = "1.2.3"
source = "registry+https://other.example/index"
[[package]]
name = "single"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "helper"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "patched"
version = "3.2.1"
[[package]]
name = "lock-only"
version = "9.9.9"
source = "git+https://git.example/unused#abcdef"
"#;
    fn fixture() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Cargo.toml", WORKSPACE),
            ("alpha/Cargo.toml", ALPHA),
            ("beta/Cargo.toml", BETA),
            ("patched/Cargo.toml", PATCHED),
            ("Cargo.lock", LOCK),
        ]
    }

    #[test]
    fn renamed_inherited_conditional_scopes_and_exact_sources_remain_distinct() {
        let outcome = evidence(&fixture());
        assert!(outcome.complete, "{outcome:?}");
        let alias = declared(&outcome, "alpha/Cargo.toml", "renamed", "normal");
        assert_eq!(alias.evidence.package.as_ref().unwrap().name, "widget");
        assert_eq!(alias.evidence.package.as_ref().unwrap().version, None);
        assert_eq!(
            values(alias, "cargo.version_requirement").collect::<Vec<_>>(),
            ["1"]
        );
        assert_eq!(
            values(alias, "cargo.requested_feature").collect::<Vec<_>>(),
            ["fast", "serde"]
        );
        assert_eq!(
            values(alias, "cargo.optional").collect::<Vec<_>>(),
            ["true"]
        );
        assert_eq!(
            values(alias, "cargo.default_features").collect::<Vec<_>>(),
            ["false"]
        );
        assert_eq!(
            values(alias, "cargo.lock_association").collect::<Vec<_>>(),
            ["exact"]
        );
        assert_eq!(alias.scope, DependencyScope::Compile);
        assert_eq!(
            values(alias, "cargo.inherited_from").collect::<Vec<_>>(),
            ["Cargo.toml"]
        );
        assert!(values(alias, "evidence.start_byte").next().is_some());
        assert!(values(alias, "cargo.inherited_start_byte").next().is_some());
        assert!(
            values(alias, "cargo.feature_declaration.default")
                .next()
                .is_some()
        );
        let dev = declared(&outcome, "alpha/Cargo.toml", "widget", "dev");
        let beta = declared(&outcome, "beta/Cargo.toml", "widget", "normal");
        assert_eq!(dev.scope, DependencyScope::Test);
        assert_ne!(alias.declared_by, beta.declared_by);
        assert_ne!(
            values(alias, "cargo.lock_candidate").next(),
            values(beta, "cargo.lock_candidate").next()
        );
        assert_eq!(
            values(dev, "cargo.lock_candidate").next(),
            values(beta, "cargo.lock_candidate").next()
        );
        assert_eq!(
            values(
                declared(&outcome, "alpha/Cargo.toml", "helper", "build"),
                "cargo.dependency_kind"
            )
            .next(),
            Some("build")
        );
        let conditional = declared(&outcome, "alpha/Cargo.toml", "conditional", "normal");
        assert_eq!(
            values(conditional, "cargo.target_condition").next(),
            Some("cfg(windows)")
        );
        assert_eq!(
            values(conditional, "cargo.activation").next(),
            Some("unresolved")
        );
        assert!(
            outcome
                .dependencies
                .iter()
                .all(|row| row.artifacts.is_empty()
                    && row.evidence.target.is_none()
                    && row.evidence.configuration.is_none())
        );
        let locks = outcome
            .dependencies
            .iter()
            .filter(|row| values(row, "evidence.kind").any(|value| value == "locked"))
            .collect::<Vec<_>>();
        let widgets = locks
            .iter()
            .filter(|row| row.evidence.package.as_ref().unwrap().name == "widget")
            .collect::<Vec<_>>();
        assert_eq!(widgets.len(), 3);
        assert_eq!(
            widgets
                .iter()
                .map(|row| &row.id)
                .collect::<HashSet<_>>()
                .len(),
            3
        );
        assert!(
            locks
                .iter()
                .all(|row| row.declared_by.is_none() && row.scope == DependencyScope::Unknown)
        );
        assert!(
            locks
                .iter()
                .any(|row| values(row, "cargo.git_revision").next() == Some("abcdef"))
        );
    }

    #[test]
    fn string_inheritance_and_supported_path_patch_reuse_cargo_routes() {
        let outcome = evidence(&fixture());
        let single = declared(&outcome, "alpha/Cargo.toml", "single", "normal");
        assert_eq!(
            values(single, "cargo.version_requirement").next(),
            Some("1")
        );
        assert_eq!(
            values(single, "cargo.lock_association").next(),
            Some("exact")
        );
        let patched = declared(&outcome, "alpha/Cargo.toml", "patched", "normal");
        assert_eq!(
            values(patched, "cargo.path_candidate").next(),
            Some("patched/Cargo.toml")
        );
        assert_eq!(
            values(patched, "cargo.lock_association").next(),
            Some("exact")
        );
    }

    #[test]
    fn owner_references_do_not_pick_one_of_two_compatible_versions() {
        let alpha = ALPHA.replace("version = \"1\", optional", "version = \"*\", optional");
        let mut files = fixture();
        files[1].1 = &alpha;
        let outcome = evidence(&files);
        let row = declared(&outcome, "alpha/Cargo.toml", "conditional", "normal");
        assert_eq!(
            values(row, "cargo.lock_association").next(),
            Some("ambiguous")
        );
        assert_eq!(values(row, "cargo.lock_candidate").count(), 2);
        assert!(!outcome.complete);
    }

    #[test]
    fn unsupported_registry_patch_config_and_missing_lock_stay_unresolved() {
        for replacement in [
            "registry = 'company'",
            "git = 'https://git.example/widget'",
            "path = '../missing'",
        ] {
            let alpha = format!(
                "[package]\nname='alpha'\nversion='0.1.0'\n[dependencies]\nwidget={{ version='1', {replacement} }}\n"
            );
            let outcome = evidence(&[
                ("Cargo.toml", WORKSPACE),
                ("alpha/Cargo.toml", &alpha),
                ("beta/Cargo.toml", BETA),
                ("Cargo.lock", LOCK),
            ]);
            assert!(!outcome.complete);
            assert_ne!(
                values(
                    declared(&outcome, "alpha/Cargo.toml", "widget", "normal"),
                    "cargo.lock_association"
                )
                .next(),
                Some("exact")
            );
        }
        let mut files = fixture();
        files.push((
            ".cargo/config.toml",
            "[patch.crates-io]\nwidget={git='https://git.example/replacement'}\n",
        ));
        let configured = evidence(&files);
        assert!(
            configured
                .diagnostics
                .iter()
                .any(|entry| entry.code == "rust.configuration.unresolved")
        );
        assert!(
            configured
                .dependencies
                .iter()
                .filter(|row| row.declared_by.is_some())
                .all(|row| values(row, "cargo.lock_association").next() != Some("exact"))
        );
        files.retain(|(path, _)| *path != "Cargo.lock");
        let missing = evidence(&files);
        assert!(!missing.complete);
        assert!(
            missing.dependencies.iter().all(|row| row
                .evidence
                .package
                .as_ref()
                .unwrap()
                .version
                .is_none())
        );
    }

    #[test]
    fn git_revision_and_unsupported_patch_replacement_are_explicit() {
        let manifest = "[package]\nname='alpha'\nversion='0.1.0'\n[dependencies]\nrenamed={package='widget',git='https://git.example/widget',rev='abcdef',version='1'}";
        let lock = "version=4\n[[package]]\nname='alpha'\nversion='0.1.0'\ndependencies=['widget 1.2.3 (git+https://git.example/widget?rev=abcdef#abcdef0123456789)']\n[[package]]\nname='widget'\nversion='1.2.3'\nsource='git+https://git.example/widget?rev=abcdef#abcdef0123456789'";
        let result = evidence(&[("Cargo.toml", manifest), ("Cargo.lock", lock)]);
        assert!(result.complete, "{result:?}");
        let declaration = declared(&result, "Cargo.toml", "renamed", "normal");
        assert_eq!(
            values(declaration, "cargo.lock_association").next(),
            Some("exact")
        );
        assert!(
            result
                .dependencies
                .iter()
                .any(|row| values(row, "cargo.git_revision").next() == Some("abcdef0123456789"))
        );
        for workspace in [
            WORKSPACE.replace(
                "path = \"patched\"",
                "git = \"https://git.example/patched\"",
            ),
            format!("{WORKSPACE}\n[replace]\n'patched:3.2.1'={{path='patched'}}\n"),
        ] {
            let mut files = fixture();
            files[0].1 = &workspace;
            let result = evidence(&files);
            assert!(!result.complete);
            let patched = declared(&result, "alpha/Cargo.toml", "patched", "normal");
            assert_ne!(
                values(patched, "cargo.lock_association").next(),
                Some("exact")
            );
        }
    }

    #[test]
    fn malformed_shapes_and_versions_never_become_complete_empty_evidence() {
        for source in [
            "[",
            "dependencies = false",
            "[dependencies]\nbroken=7",
            "[dependencies]\nbroken={version='1',features=[true]}",
            "[features]\nfoo=false",
            "[package]\nname=17",
        ] {
            let outcome = evidence(&[("Cargo.toml", source)]);
            assert!(!outcome.complete, "{source}: {outcome:?}");
            assert!(!outcome.diagnostics.is_empty());
        }
        for source in [
            "version=1",
            "version=4\n[[package]]\nname='widget'\nversion='garbage'",
            "version=4\n[[package]]\nname='widget'\nversion='1.0.0'\ndependencies=[false]",
        ] {
            let outcome = evidence(&[
                ("Cargo.toml", "[package]\nname='empty'\nversion='0.1.0'"),
                ("Cargo.lock", source),
            ]);
            assert!(!outcome.complete, "{outcome:?}");
        }
    }
    #[test]
    fn snapshot_replacement_and_fresh_projection_are_equivalent() {
        let mut selected = inputs(&fixture());
        let original =
            cargo_file_discovery_rows(&root(), &selected, &DependencyPackLimits::default(), None);
        selected.push((
            ProjectFile::new(root(), PathBuf::from("alpha/src/lib.rs")),
            ProjectSourceSnapshot::disk("pub fn unrelated() {}"),
        ));
        assert_eq!(
            original,
            cargo_file_discovery_rows(&root(), &selected, &DependencyPackLimits::default(), None)
        );
        let changed = LOCK.replace("1.2.3", "1.4.0");
        selected[4].1 = ProjectSourceSnapshot::disk(changed.as_str());
        let incremental =
            cargo_file_discovery_rows(&root(), &selected, &DependencyPackLimits::default(), None);
        let mut fresh = fixture();
        fresh[4].1 = &changed;
        assert_eq!(incremental, evidence(&fresh));
        assert_ne!(incremental, original);
        let previous = original
            .dependencies
            .iter()
            .find(|row| row.declared_by.is_some())
            .unwrap();
        assert!(
            incremental
                .dependencies
                .iter()
                .any(|row| row.id == previous.id)
        );
    }

    #[test]
    fn shared_contract_associates_only_proven_lock_instances_with_members() {
        let selected = inputs(&fixture());
        let result = rust_file_dependency_evidence(
            &root(),
            &selected,
            &DependencyFileEvidenceLimits::default(),
            None,
        );
        assert!(result.complete(), "{result:?}");
        let alpha_owner = member_entity(Path::new("alpha")).id();
        let beta_owner = member_entity(Path::new("beta")).id();
        // This is the data predicate a synthetic affected-version policy
        // consumes; it makes no runtime/advisory-exploitability claim.
        let affected = result
            .rows
            .iter()
            .filter(|row| {
                row.kind == DependencyEvidenceKind::Locked
                    && row.package == "widget"
                    && row.exact_version.as_deref() == Some("1.2.3")
                    && row.source.as_deref() == Some(CRATES_IO)
                    && row.declared_by.as_deref() == Some(alpha_owner.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            affected.len(),
            2,
            "normal and conditional declarations remain separate"
        );
        assert!(
            result
                .rows
                .iter()
                .any(|row| row.kind == DependencyEvidenceKind::Locked
                    && row.package == "widget"
                    && row.exact_version.as_deref() == Some("1.2.3")
                    && row.source.as_deref() == Some("registry+https://other.example/index")
                    && row.declared_by.is_none())
        );
        assert!(
            !result
                .rows
                .iter()
                .any(|row| row.kind == DependencyEvidenceKind::Locked
                    && row.package == "widget"
                    && row.exact_version.as_deref() == Some("1.2.3")
                    && row.declared_by.as_deref() == Some(beta_owner.as_str()))
        );
        assert!(
            result
                .rows
                .iter()
                .filter(
                    |row| row.kind == DependencyEvidenceKind::Locked && row.package == "lock-only"
                )
                .all(|row| row.declared_by.is_none())
        );
        assert!(
            result
                .rows
                .iter()
                .all(|row| row.byte_range.end > row.byte_range.start
                    && row.source_digest.len() == 40)
        );
    }

    #[test]
    fn duplicate_snapshots_and_missing_members_are_explicit() {
        let mut selected = inputs(&fixture());
        selected.push(selected[0].clone());
        let duplicate =
            cargo_file_discovery_rows(&root(), &selected, &DependencyPackLimits::default(), None);
        assert!(!duplicate.complete);
        assert!(
            duplicate
                .diagnostics
                .iter()
                .any(|entry| entry.code == "rust.files.duplicate_snapshot")
        );
        let mut files = fixture();
        files.retain(|(path, _)| *path != "beta/Cargo.toml");
        let missing = evidence(&files);
        assert!(!missing.complete);
        assert!(
            missing
                .diagnostics
                .iter()
                .any(|entry| entry.code == "rust.workspace.missing_member")
        );
    }

    #[test]
    fn limits_cancellation_and_suppressed_errors_preserve_incompleteness() {
        let selected = inputs(&fixture());
        let limits = DependencyPackLimits {
            max_dependencies: 2,
            max_diagnostics: 0,
            ..DependencyPackLimits::default()
        };
        let outcome = cargo_file_discovery_rows(&root(), &selected, &limits, None);
        assert!(!outcome.complete);
        assert!(outcome.dependencies.len() <= 2);
        assert!(outcome.suppressed_diagnostics.errors > 0);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = cargo_file_discovery_rows(
            &root(),
            &selected,
            &DependencyPackLimits::default(),
            Some(&cancellation),
        );
        assert!(cancelled.cancelled && !cancelled.complete);
        let limits = DependencyPackLimits {
            max_total_artifact_bytes: 8,
            ..DependencyPackLimits::default()
        };
        assert!(!cargo_file_discovery_rows(&root(), &selected, &limits, None).complete);
    }
}
