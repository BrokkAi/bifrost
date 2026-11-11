use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{RustSelectedManifestMount, normalize_selected_path};
use crate::cargo_routes::{cargo_dependency_tables_with_kind, cargo_workspace_exclude_covers};

/// Check every root and workspace entry against the exact selected listing.
/// Cargo workspace membership and target rules:
/// https://doc.rust-lang.org/cargo/reference/workspaces.html
/// https://doc.rust-lang.org/cargo/reference/cargo-targets.html
pub(super) fn target_discovery_reasons(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    sources: &BTreeSet<&Path>,
) -> BTreeSet<String> {
    let mut reasons = BTreeSet::new();
    for manifest in manifests.values() {
        let path = &manifest.relative_path;
        let directory = path.parent().unwrap_or(Path::new(""));
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
                                reasons.insert(format!(
                                    "{}: workspace.{key}[{index}] is invalid: {entry}",
                                    path.display()
                                ));
                            }
                        }
                    } else {
                        reasons.insert(format!(
                            "{}: workspace.{key} is not an array",
                            path.display()
                        ));
                    }
                }
            }
            // Cargo requires every members entry to resolve to a manifest,
            // including globs with zero matches (Cargo metadata rejects them).
            for member in &manifest.facts.workspace_members {
                let Some(pattern_path) = normalize_selected_path(directory, member) else {
                    reasons.insert(format!(
                        "{}: workspace.members {} escapes workspace",
                        path.display(),
                        member.display()
                    ));
                    continue;
                };
                let Ok(pattern) = glob::Pattern::new(&pattern_path.to_string_lossy()) else {
                    continue;
                };
                if !manifests.keys().any(|candidate| {
                    candidate.parent().is_some_and(|parent| {
                        pattern.matches_path_with(
                            parent,
                            glob::MatchOptions {
                                require_literal_separator: true,
                                ..Default::default()
                            },
                        )
                    })
                }) {
                    reasons.insert(format!(
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
        if manifest
            .document
            .get("package")
            .and_then(|table| table.get("workspace"))
            .is_some_and(|value| value.as_str().is_none())
        {
            reasons.insert(format!("{}: package.workspace is invalid", path.display()));
        }
        if let Some(pointer) = package.workspace_path.as_deref() {
            let workspace = normalize_selected_path(directory, pointer)
                .and_then(|root| manifests.get(&root.join("Cargo.toml")));
            if workspace.is_none_or(|root| !root.facts.is_workspace) {
                reasons.insert(format!(
                    "{}: package.workspace {} has no selected workspace manifest",
                    path.display(),
                    pointer.display()
                ));
            }
        }
        let mut check = |candidate: &Path, required: bool| {
            let target = normalize_selected_path(directory, candidate);
            if target
                .as_ref()
                .is_none_or(|target| !target.starts_with(directory))
            {
                reasons.insert(format!(
                    "{}: target path {} escapes package",
                    path.display(),
                    candidate.display()
                ));
            } else if required
                && target
                    .as_ref()
                    .is_some_and(|target| !sources.contains(target.as_path()))
            {
                reasons.insert(format!(
                    "{}: target path {} is absent from selected sources",
                    path.display(),
                    candidate.display()
                ));
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
    // Cargo includes path dependencies under a workspace root, including target,
    // dev and build dependencies. Excluded paths remain outside that workspace.
    for root in manifests.values().filter(|m| m.facts.is_workspace) {
        let root_dir = root.relative_path.parent().unwrap_or(Path::new(""));
        for member in manifests.values().filter(|m| m.facts.package.is_some()) {
            let member_dir = member.relative_path.parent().unwrap_or(Path::new(""));
            if !member_dir.starts_with(root_dir) {
                continue;
            }
            for (_, _, table) in cargo_dependency_tables_with_kind(&member.document) {
                for (name, value) in table {
                    let Some(path) = value
                        .as_table()
                        .and_then(|v| v.get("path"))
                        .and_then(toml::Value::as_str)
                    else {
                        continue;
                    };
                    let Some(target) = normalize_selected_path(member_dir, Path::new(path)) else {
                        continue;
                    };
                    if !target.starts_with(root_dir) {
                        continue;
                    }
                    let relative = target.strip_prefix(root_dir).expect("prefix checked");
                    if root
                        .facts
                        .workspace_excludes
                        .iter()
                        .any(|exclude| cargo_workspace_exclude_covers(exclude, relative))
                    {
                        continue;
                    }
                    if !manifests.contains_key(&target.join("Cargo.toml")) {
                        reasons.insert(format!("{}: path dependency {name} at {path} is absent from selected manifests", member.relative_path.display()));
                    }
                }
            }
        }
    }
    reasons
}
