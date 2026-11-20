use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{RustSelectedManifestMount, normalize_selected_path};
use crate::cargo_routes::{cargo_dependency_tables_with_kind, cargo_workspace_exclude_covers};

pub(super) fn cargo_manifest_documents(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
) -> super::CargoHashMap<PathBuf, crate::cargo_manifest::RustCargoManifestDocument> {
    manifests
        .values()
        .map(|m| {
            (
                m.relative_path
                    .parent()
                    .expect("manifest directory")
                    .to_path_buf(),
                m.document.clone(),
            )
        })
        .collect()
}

/// Check every root and workspace entry against the exact selected listing.
/// Cargo workspace membership and target rules:
/// https://doc.rust-lang.org/cargo/reference/workspaces.html
/// https://doc.rust-lang.org/cargo/reference/cargo-targets.html
pub(super) fn target_discovery_reasons(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    sources: &BTreeSet<&Path>,
    configuration: &crate::cargo_config::RustCargoConfiguration,
    cargo_manifests: &super::CargoHashMap<
        PathBuf,
        crate::cargo_manifest::RustCargoManifestDocument,
    >,
) -> BTreeMap<PathBuf, BTreeSet<String>> {
    let mut reasons = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    for manifest in manifests.values() {
        let path = &manifest.relative_path;
        let directory = path.parent().unwrap_or(Path::new(""));
        if !super::broad_discovery::manifest_schema_and_edition_supported(
            manifest,
            manifests,
            cargo_manifests,
        ) {
            reasons.entry(path.clone()).or_default().insert(format!(
                "{}: unsupported Cargo target settings or unresolved workspace edition",
                path.display()
            ));
        }
        if let Some(workspace) = manifest.document.get("workspace") {
            for key in ["members", "exclude", "default-members"] {
                if let Some(value) = workspace.get(key) {
                    if let Some(entries) = value.as_array() {
                        for (index, entry) in entries.iter().enumerate() {
                            let invalid = match entry.as_str() {
                                None => true,
                                Some(pattern) if key != "exclude" => {
                                    glob::Pattern::new(pattern).is_err()
                                }
                                Some(_) => false,
                            };
                            if invalid {
                                reasons.entry(path.clone()).or_default().insert(format!(
                                    "{}: workspace.{key}[{index}] is invalid: {entry}",
                                    path.display()
                                ));
                            }
                        }
                    } else {
                        reasons.entry(path.clone()).or_default().insert(format!(
                            "{}: workspace.{key} is not an array",
                            path.display()
                        ));
                    }
                }
            }
            // Cargo requires every members entry to resolve to a manifest,
            // including globs with zero matches (Cargo metadata rejects them).
            for member in &manifest.facts.workspace_members {
                let Some(_) = normalize_selected_path(directory, member) else {
                    reasons.entry(path.clone()).or_default().insert(format!(
                        "{}: workspace.members {} escapes workspace",
                        path.display(),
                        member.display()
                    ));
                    continue;
                };
                if !manifests.keys().any(|candidate| {
                    candidate.parent().is_some_and(|parent| {
                        super::crate_inventory::workspace_member_pattern_matches(
                            directory, member, parent,
                        )
                    })
                }) {
                    reasons.entry(path.clone()).or_default().insert(format!(
                        "{}: workspace.members {} is absent from selected manifests",
                        path.display(),
                        member.display()
                    ));
                }
            }
        }
        let Some(package) = &manifest.facts.package else {
            continue;
        };
        for gap in &package.target_configuration_gaps {
            reasons
                .entry(path.clone())
                .or_default()
                .insert(format!("{}: {gap}", path.display()));
        }
        if manifest
            .document
            .get("package")
            .and_then(|table| table.get("workspace"))
            .is_some_and(|value| value.as_str().is_none())
        {
            reasons
                .entry(path.clone())
                .or_default()
                .insert(format!("{}: package.workspace is invalid", path.display()));
        }
        if let Some(pointer) = package.workspace_path.as_deref() {
            let workspace = normalize_selected_path(directory, pointer)
                .and_then(|root| manifests.get(&root.join("Cargo.toml")));
            if workspace.is_none_or(|root| !root.facts.is_workspace) {
                reasons.entry(path.clone()).or_default().insert(format!(
                    "{}: package.workspace {} has no selected workspace manifest",
                    path.display(),
                    pointer.display()
                ));
            }
        }
        let mut check = |candidate: &Path, required: bool| {
            let target = normalize_selected_path(directory, candidate);
            let reason = if target
                .as_ref()
                .is_none_or(|target| !target.starts_with(directory))
            {
                // Discovery returns a typed unavailable target for this case.
                // It is not a failure of the package's other healthy targets.
                None
            } else if required
                && target
                    .as_ref()
                    .is_some_and(|target| !sources.contains(target.as_path()))
            {
                Some(format!(
                    "{}: target path {} is absent from selected sources",
                    path.display(),
                    candidate.display()
                ))
            } else {
                None
            };
            if let Some(reason) = reason {
                reasons
                    .entry(path.clone())
                    .or_default()
                    .insert(reason.clone());
                // The target's owning package retains this discovery reason.
                // Other packages consume intentional target availability only
                // when the question ranges over workspace members (#13410).
            }
        };
        if super::cargo_library_target_enabled(package) {
            check(
                &package.library_path,
                package.automatic_targets.library_explicit,
            );
        }
        for target in &package.explicit_targets {
            let present = target.candidate_paths.iter().any(|candidate| {
                normalize_selected_path(directory, candidate)
                    .is_some_and(|path| sources.contains(path.as_path()))
            });
            for (index, candidate) in target.candidate_paths.iter().enumerate() {
                check(candidate, !present && index == 0);
            }
        }
        if let Some(build) = package.build_script.as_deref() {
            check(
                build,
                manifest
                    .document
                    .get("package")
                    .and_then(|p| p.get("build"))
                    .is_some(),
            );
        }
    }
    // Only real members can introduce implicit members. An unrelated fixture
    // below a workspace is not itself a workspace-discovery input.
    let members = super::crate_inventory::workspace_member_manifests(
        manifests,
        cargo_manifests,
        configuration,
    );
    for member in manifests.values().filter(|m| m.facts.package.is_some()) {
        let member_dir = member.relative_path.parent().expect("manifest directory");
        for (_, _, table) in cargo_dependency_tables_with_kind(&member.document) {
            for (name, value) in table {
                let Some(target) = crate::cargo_routes::cargo_dependency_directory_with(
                    Path::new(""),
                    member_dir,
                    &member.document,
                    name,
                    value,
                    cargo_manifests,
                    configuration,
                    &mut normalize_selected_path,
                ) else {
                    continue;
                };
                if manifests.contains_key(&target.join("Cargo.toml")) {
                    continue;
                }
                let reason = format!(
                    "{}: path dependency {name} at {} is absent from selected manifests",
                    member.relative_path.display(),
                    target.display()
                );
                // A dependency gap always concerns its declaring package. Only
                // actual membership can make it a workspace-discovery gap too.
                reasons
                    .entry(member.relative_path.clone())
                    .or_default()
                    .insert(reason.clone());
                for (root_dir, member_paths) in &members {
                    if !member_paths.contains(&member.relative_path) {
                        continue;
                    }
                    let root = &manifests[&root_dir.join("Cargo.toml")];
                    let Ok(relative) = target.strip_prefix(root_dir) else {
                        continue;
                    };
                    if root
                        .facts
                        .workspace_excludes
                        .iter()
                        .any(|exclude| cargo_workspace_exclude_covers(exclude, relative))
                    {
                        continue;
                    }
                    reasons
                        .entry(root.relative_path.clone())
                        .or_default()
                        .insert(reason.clone());
                }
            }
        }
    }
    reasons
}
