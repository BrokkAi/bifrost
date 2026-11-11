//! Positive, broad-only Cargo target discovery from selected manifest and source listings.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::target_discovery::target_discovery_reasons;
use super::{RustCargoPackageEdition, RustSelectedManifestMount, normalize_selected_path};

// Closed keys from https://doc.rust-lang.org/cargo/reference/manifest.html,
// https://doc.rust-lang.org/cargo/reference/cargo-targets.html, and
// https://doc.rust-lang.org/cargo/reference/workspaces.html. Unknown keys fail closed.
const TARGET_KEYS: &[&str] = &[
    "name",
    "path",
    "crate-type",
    "required-features",
    "harness",
    "test",
    "doctest",
    "bench",
    "doc",
    "proc-macro",
    "plugin",
    "edition",
];
const PACKAGE_KEYS: &[&str] = &[
    "name",
    "version",
    "authors",
    "edition",
    "rust-version",
    "description",
    "documentation",
    "readme",
    "homepage",
    "repository",
    "license",
    "license-file",
    "keywords",
    "categories",
    "workspace",
    "build",
    "links",
    "exclude",
    "include",
    "publish",
    "metadata",
    "default-run",
    "autolib",
    "autobins",
    "autoexamples",
    "autotests",
    "autobenches",
    "resolver",
    "im-a-teapot",
];
const WORKSPACE_KEYS: &[&str] = &[
    "resolver",
    "members",
    "exclude",
    "default-members",
    "package",
    "dependencies",
    "lints",
    "metadata",
];

fn known_keys(value: &toml::Value, keys: &[&str]) -> bool {
    value
        .as_table()
        .is_some_and(|table| table.keys().all(|key| keys.contains(&key.as_str())))
}

/// Whether all manifest-defined roots and workspace members for one package have
/// positive witnesses in the selected listing. The caller separately certifies
/// that the selected listing itself is complete before using this broad bit.
/// This never changes selected profiles or their completeness.
pub fn rust_broad_target_discovery_complete(
    manifest: &RustSelectedManifestMount,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    sources: &BTreeSet<PathBuf>,
) -> bool {
    let document = &manifest.document;
    if document.get("cargo-features").is_some() {
        return false;
    }
    for key in ["package", "workspace", "lib"] {
        if let Some(value) = document.get(key) {
            let keys = match key {
                "package" => PACKAGE_KEYS,
                "workspace" => WORKSPACE_KEYS,
                _ => TARGET_KEYS,
            };
            if !known_keys(value, keys) {
                return false;
            }
        }
    }
    for key in ["bin", "example", "test", "bench"] {
        if let Some(value) = document.get(key) {
            let Some(targets) = value.as_array() else {
                return false;
            };
            if !targets.iter().all(|target| known_keys(target, TARGET_KEYS)) {
                return false;
            }
        }
    }
    let source_paths = sources.iter().map(PathBuf::as_path).collect();
    if !target_discovery_reasons(manifests, &source_paths).is_empty() {
        return false;
    }
    let Some(package) = manifest.facts.package.as_ref() else {
        return true;
    };
    let directory = manifest.relative_path.parent().unwrap_or(Path::new(""));
    let workspace = if let Some(pointer) = package.workspace_path.as_deref() {
        normalize_selected_path(directory, pointer)
            .and_then(|root| manifests.get(&root.join("Cargo.toml")))
    } else {
        manifests
            .values()
            .filter(|other| {
                other.facts.is_workspace
                    && directory.starts_with(other.relative_path.parent().unwrap_or(Path::new("")))
            })
            .max_by_key(|other| other.relative_path.components().count())
    };
    if package.workspace_path.is_some() && workspace.is_none() {
        return false;
    }
    if let Some(root) = workspace
        && (root.document.get("cargo-features").is_some()
            || root
                .document
                .get("workspace")
                .is_none_or(|value| !known_keys(value, WORKSPACE_KEYS)))
    {
        return false;
    }
    if package.edition == RustCargoPackageEdition::Workspace
        && workspace
            .and_then(|root| root.facts.workspace_package_edition)
            .is_none()
    {
        return false;
    }
    // Auto roots and optional defaults arise only from the separately
    // certified complete source listing. In edition 2015 Cargo suppresses
    // auto-discovery when an explicit target is present; that changes which
    // listed files become roots, but cannot create an unlisted required root.
    true
}

/// Whether an omitted directory can hide Cargo inputs for this package or a
/// workspace member. Module and include routes are checked by the topology walk.
/// The prefix is a workspace-relative directory from the listing certificate.
pub fn rust_directory_omission_affects_cargo(
    manifest: &RustSelectedManifestMount,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    prefix: &Path,
) -> bool {
    use crate::cargo_routes::rust_omission_path_key;
    let directory = manifest.relative_path.parent().unwrap_or(Path::new(""));
    let prefix = PathBuf::from(rust_omission_path_key(&prefix.to_string_lossy()));
    // Default target locations are checked whatever the auto-discovery
    // switches and the edition-2015 explicit-target rule say: the implicit
    // library root src/lib.rs is discovered independently of autobins, and a
    // [[bin]], [[example]], [[test]] or [[bench]] without a path defaults into
    // these same locations. An omission that could hold a default root keeps
    // the topology incomplete.
    for root in ["src/lib.rs", "src/main.rs"] {
        let root = PathBuf::from(rust_omission_path_key(
            &directory.join(root).to_string_lossy(),
        ));
        if root.starts_with(&prefix) {
            return true;
        }
    }
    for candidate in ["src/bin", "examples", "tests", "benches"] {
        let candidate = PathBuf::from(rust_omission_path_key(
            &directory.join(candidate).to_string_lossy(),
        ));
        // Only the directory itself or a direct child can hide a target root
        // accepted by auto_cargo_target_kind (including */name/main.rs).
        if candidate.starts_with(&prefix)
            || prefix
                .strip_prefix(&candidate)
                .is_ok_and(|relative| relative.components().count() <= 1)
        {
            return true;
        }
    }
    for key in ["lib", "bin", "example", "test", "bench"] {
        let Some(value) = manifest.document.get(key) else {
            continue;
        };
        let targets = value
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(std::slice::from_ref(value));
        for target in targets {
            if let Some(path) = target.get("path").and_then(toml::Value::as_str) {
                let Some(candidate) = normalize_selected_path(directory, Path::new(path)) else {
                    return true;
                };
                if Path::new(&rust_omission_path_key(&candidate.to_string_lossy()))
                    .starts_with(&prefix)
                {
                    return true;
                }
            }
        }
    }
    for workspace in manifests.values().filter(|mount| mount.facts.is_workspace) {
        let directory = workspace.relative_path.parent().unwrap_or(Path::new(""));
        for member in &workspace.facts.workspace_members {
            let Some(member) = normalize_selected_path(directory, member) else {
                return true;
            };
            let member = PathBuf::from(rust_omission_path_key(&member.to_string_lossy()));
            // A member pattern can continue below the omitted directory. Match
            // its ancestor patterns against the prefix, rather than requiring
            // the full member directory to have been enumerated already.
            for ancestor in member.ancestors() {
                if glob::Pattern::new(&ancestor.to_string_lossy()).is_ok_and(|pattern| {
                    pattern.matches_path_with(
                        &prefix,
                        glob::MatchOptions {
                            require_literal_separator: true,
                            ..Default::default()
                        },
                    )
                }) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_discovery_manifest_and_listing_controls() {
        let cases: &[(&str, &[&str], bool)] = &[
            (
                "[package]\nname = 'plain'\nversion = '0.1.0'",
                &["src/lib.rs"],
                true,
            ),
            (
                "[package]\nname = 'plain'\nversion = '0.1.0'\n[[bin]]\nname = 'gone'\npath = 'src/gone.rs'",
                &["src/lib.rs"],
                false,
            ),
            (
                "[package]\nname = 'plain'\nversion = '0.1.0'\n[[bin]]\nname = 'ok'\npath = 'src/main.rs'\nmystery = true",
                &["src/main.rs"],
                false,
            ),
            (
                "[package]\nname = 'plain'\nversion = '0.1.0'\n[[bin]]\nname = 'ok'\npath = 'src/main.rs'\nharness = false",
                &["src/main.rs"],
                true,
            ),
            (
                "cargo-features = ['test']\n[package]\nname = 'plain'\nversion = '0.1.0'",
                &["src/lib.rs"],
                false,
            ),
            (
                "[package]\nname = 'plain'\nversion = '0.1.0'\nedition = '2015'\n[[bin]]\nname = 'ok'\npath = 'src/main.rs'",
                &["src/main.rs", "src/bin/x.rs"],
                true,
            ),
            ("[workspace]\nmembers = [42]", &[], false),
            ("[workspace]\nmembers = ['[bad']", &[], false),
        ];
        for (source, paths, expected) in cases {
            let manifest = RustSelectedManifestMount::from_source("Cargo.toml", source).unwrap();
            let manifests = BTreeMap::from([(PathBuf::from("Cargo.toml"), manifest.clone())]);
            let sources = paths.iter().map(PathBuf::from).collect();
            assert_eq!(
                rust_broad_target_discovery_complete(&manifest, &manifests, &sources),
                *expected,
                "{source}"
            );
        }
    }

    #[test]
    fn path_dependency_is_an_implicit_workspace_member() {
        let root =
            RustSelectedManifestMount::from_source("Cargo.toml", "[workspace]\nmembers = ['app']")
                .unwrap();
        let app = RustSelectedManifestMount::from_source("app/Cargo.toml", "[package]\nname = 'app'\nversion = '0.1.0'\n[dependencies]\nhelper = { path = '../helper' }").unwrap();
        let helper = RustSelectedManifestMount::from_source(
            "helper/Cargo.toml",
            "[package]\nname = 'helper'\nversion = '0.1.0'",
        )
        .unwrap();
        let manifests = BTreeMap::from([
            (root.relative_path.clone(), root),
            (app.relative_path.clone(), app.clone()),
            (helper.relative_path.clone(), helper),
        ]);
        assert!(rust_broad_target_discovery_complete(
            &app,
            &manifests,
            &BTreeSet::new()
        ));
        let mut missing = manifests.clone();
        missing.remove(Path::new("helper/Cargo.toml"));
        assert!(!rust_broad_target_discovery_complete(
            &app,
            &missing,
            &BTreeSet::new()
        ));
        let malformed_root =
            RustSelectedManifestMount::from_source("Cargo.toml", "[workspace]\nmembers = [42]")
                .unwrap();
        let mut malformed = manifests;
        malformed.insert(PathBuf::from("Cargo.toml"), malformed_root);
        assert!(!rust_broad_target_discovery_complete(
            &app,
            &malformed,
            &BTreeSet::new()
        ));
    }
}
