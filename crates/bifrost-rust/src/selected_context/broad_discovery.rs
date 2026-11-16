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

// Keep every settings gap on its own manifest before a context selects inputs.
pub(super) fn manifest_schema_and_edition_supported(
    manifest: &RustSelectedManifestMount,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &super::CargoHashMap<
        PathBuf,
        crate::cargo_manifest::RustCargoManifestDocument,
    >,
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
    if let Some(package) = manifest.facts.package.as_ref()
        && package.edition == RustCargoPackageEdition::Workspace
    {
        let workspace = crate::cargo_routes::cargo_workspace_manifest_directory(
            Path::new(""),
            manifest.relative_path.parent().expect("manifest directory"),
            &manifest.document,
            cargo_manifests,
        )
        .and_then(|root| manifests.get(&root.join("Cargo.toml")));
        if workspace
            .and_then(|root| root.facts.workspace_package_edition)
            .is_none()
        {
            return false;
        }
    }
    true
}

/// Whether manifest-defined roots and workspace discovery for a context have
/// positive witnesses in the selected listing. Selected and broad context
/// publications share this fold. The broad publisher separately requires a
/// complete source-listing certificate.
/// Evaluate the listing-wide reasons and Cargo directory index once, then
/// select each context's manifest closure and retained failures from those shared inputs.
pub fn rust_broad_target_discovery_completeness(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    sources: &BTreeSet<PathBuf>,
    configuration: &crate::cargo_config::RustCargoConfiguration,
    failed: &BTreeSet<PathBuf>,
) -> BTreeMap<PathBuf, bool> {
    let cargo_manifests = super::target_discovery::cargo_manifest_documents(manifests);
    let mut completeness =
        manifest_discovery_completeness(manifests, sources, configuration, &cargo_manifests);
    for (path, complete) in &mut completeness {
        *complete = *complete
            && !manifest_errors_affect_context(
                path,
                manifests,
                configuration,
                &cargo_manifests,
                failed,
            );
    }
    completeness
}

/// Attribute retained manifest failures through the same context closure as
/// target discovery, including identities whose bytes could not be parsed.
fn manifest_errors_affect_context(
    path: &Path,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    configuration: &crate::cargo_config::RustCargoConfiguration,
    cargo_manifests: &super::CargoHashMap<
        PathBuf,
        crate::cargo_manifest::RustCargoManifestDocument,
    >,
    failed: &BTreeSet<PathBuf>,
) -> bool {
    if failed.is_empty() {
        return false;
    }
    let closure =
        broad_manifest_closure(&manifests[path], manifests, configuration, cargo_manifests);
    if closure.iter().any(|path| failed.contains(path)) {
        return true;
    }
    closure
        .iter()
        .filter_map(|path| manifests.get(path))
        .any(|manifest| {
            let directory = manifest.relative_path.parent().expect("manifest directory");
            if crate::cargo_routes::cargo_dependency_tables_with_kind(&manifest.document)
                .iter()
                .any(|(_, _, table)| {
                    table.iter().any(|(name, value)| {
                        crate::cargo_routes::cargo_expected_dependency_patch_manifests(
                            directory,
                            &manifest.document,
                            name,
                            value,
                            cargo_manifests,
                            configuration,
                        )
                        .iter()
                        .any(|path| failed.contains(path))
                    })
                })
            {
                return true;
            }
            manifest.facts.is_workspace
                && failed.iter().any(|path| {
                    let candidate = path.parent().expect("manifest directory");
                    super::cargo_workspace_claims_package(directory, &manifest.facts, candidate)
                        && manifest.facts.workspace_members.iter().any(|member| {
                            super::crate_inventory::workspace_member_pattern_matches(
                                directory, member, candidate,
                            )
                        })
                })
        })
}

pub(super) fn manifest_discovery_completeness(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    sources: &BTreeSet<PathBuf>,
    configuration: &crate::cargo_config::RustCargoConfiguration,
    cargo_manifests: &super::CargoHashMap<
        PathBuf,
        crate::cargo_manifest::RustCargoManifestDocument,
    >,
) -> BTreeMap<PathBuf, bool> {
    let source_paths = sources.iter().map(PathBuf::as_path).collect();
    let reasons =
        target_discovery_reasons(manifests, &source_paths, configuration, cargo_manifests);
    manifests
        .iter()
        .map(|(path, manifest)| {
            let closure =
                broad_manifest_closure(manifest, manifests, configuration, cargo_manifests);
            (
                path.clone(),
                reasons.keys().all(|path| !closure.contains(path)),
            )
        })
        .collect()
}

// One context reads its own manifest, its workspace root and recursively its
// dependencies' manifests. Workspace siblings are discovery witnesses, not
// target inputs. Keep roots in the closure so missing members fail closed.
fn broad_manifest_closure(
    manifest: &RustSelectedManifestMount,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    configuration: &crate::cargo_config::RustCargoConfiguration,
    cargo_manifests: &super::CargoHashMap<
        PathBuf,
        crate::cargo_manifest::RustCargoManifestDocument,
    >,
) -> BTreeSet<PathBuf> {
    use crate::cargo_routes::{
        cargo_dependency_tables_with_kind, cargo_workspace_manifest_directory,
    };
    let mut closure = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = vec![manifest.relative_path.clone()];
    while let Some(path) = pending.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        closure.insert(path.clone());
        let Some(current) = manifests.get(&path) else {
            continue;
        };
        if let Some(root) = cargo_workspace_manifest_directory(
            Path::new(""),
            path.parent().expect("manifest directory"),
            &current.document,
            cargo_manifests,
        ) {
            let root = root.join("Cargo.toml");
            // Retain required roots even when their bytes failed to parse.
            closure.insert(root);
        }
        for (_, _, table) in cargo_dependency_tables_with_kind(&current.document) {
            for (name, value) in table {
                if let Some(directory) = crate::cargo_routes::cargo_dependency_directory_with(
                    Path::new(""),
                    path.parent().expect("manifest directory"),
                    &current.document,
                    name,
                    value,
                    cargo_manifests,
                    configuration,
                    &mut normalize_selected_path,
                ) {
                    pending.push(directory.join("Cargo.toml"));
                }
            }
        }
    }
    closure
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
    #[brokk_bifrost_test_macros::hardwon(
        "#11799: dependency schema and inherited-edition gaps escaped context completeness"
    )]
    fn dependency_manifest_settings_stay_in_the_manifest_closure() {
        for helper_source in [
            "cargo-features=['future-targets']\n[package]\nname='helper'\nversion='0.1.0'",
            "[package]\nname='helper'\nversion='0.1.0'\nedition={workspace=true}",
        ] {
            let mounts = [
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=['app','helper','other']",
                ),
                (
                    "app/Cargo.toml",
                    "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\nhelper={path='../helper'}",
                ),
                ("helper/Cargo.toml", helper_source),
                (
                    "other/Cargo.toml",
                    "[package]\nname='other'\nversion='0.1.0'",
                ),
            ];
            let manifests: BTreeMap<_, _> = mounts
                .into_iter()
                .map(|(path, source)| {
                    let manifest = RustSelectedManifestMount::from_source(path, source).unwrap();
                    (manifest.relative_path.clone(), manifest)
                })
                .collect();
            let sources = ["app/src/lib.rs", "helper/src/lib.rs", "other/src/lib.rs"]
                .into_iter()
                .map(PathBuf::from)
                .collect();
            assert!(
                !rust_broad_target_discovery_completeness(
                    &manifests,
                    &sources,
                    &Default::default(),
                    &BTreeSet::new(),
                )[&manifests[Path::new("app/Cargo.toml")].relative_path],
                "{helper_source}"
            );
            assert!(
                rust_broad_target_discovery_completeness(
                    &manifests,
                    &sources,
                    &Default::default(),
                    &BTreeSet::new()
                )[&manifests[Path::new("other/Cargo.toml")].relative_path],
                "{helper_source}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11799: member filtering dropped a non-member package's own missing dependency"
    )]
    fn non_member_dependency_gap_stays_on_its_own_context() {
        let mounts = [
            ("Cargo.toml", "[workspace]\nmembers=['app']"),
            ("app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'"),
            (
                "fixture/Cargo.toml",
                "[package]\nname='fixture'\nversion='0.1.0'\n[dependencies]\nmissing={path='missing'}",
            ),
        ];
        let manifests: BTreeMap<_, _> = mounts
            .into_iter()
            .map(|(path, source)| {
                let manifest = RustSelectedManifestMount::from_source(path, source).unwrap();
                (manifest.relative_path.clone(), manifest)
            })
            .collect();
        assert!(
            rust_broad_target_discovery_completeness(
                &manifests,
                &BTreeSet::new(),
                &Default::default(),
                &BTreeSet::new(),
            )[&manifests[Path::new("app/Cargo.toml")].relative_path]
        );
        assert!(
            !rust_broad_target_discovery_completeness(
                &manifests,
                &BTreeSet::new(),
                &Default::default(),
                &BTreeSet::new(),
            )[&manifests[Path::new("fixture/Cargo.toml")].relative_path]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11799: configured patches omitted local dependency discovery failures"
    )]
    fn configured_patch_dependency_keeps_context_incomplete() {
        let app = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\nhelper='0.1'",
        )
        .unwrap();
        let helper = RustSelectedManifestMount::from_source(
            "helper/Cargo.toml",
            "[package]\nname='helper'\nversion='0.1.0'\nbuild='build.rs'",
        )
        .unwrap();
        let manifests = [app.clone(), helper]
            .into_iter()
            .map(|m| (m.relative_path.clone(), m))
            .collect();
        let configuration = crate::cargo_config::RustCargoConfiguration::from_files([(
            PathBuf::from(".cargo/config.toml"),
            crate::cargo_config::RustCargoConfigDocument::from_source_bytes(
                b"[patch.crates-io]\nhelper={path='helper'}",
            )
            .unwrap(),
        )]);
        assert!(
            !super::rust_broad_target_discovery_completeness(
                &manifests,
                &BTreeSet::new(),
                &configuration,
                &BTreeSet::new(),
            )[&app.relative_path]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11799: a missing implicit member was not attributed to workspace discovery"
    )]
    fn missing_implicit_member_taints_sibling_context() {
        let mounts = [
            ("Cargo.toml", "[workspace]\nmembers=['app','other']"),
            ("app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'"),
            (
                "other/Cargo.toml",
                "[package]\nname='other'\nversion='0.1.0'\n[dependencies]\nhelper={path='../helper'}",
            ),
        ];
        let manifests: BTreeMap<_, _> = mounts
            .into_iter()
            .map(|(p, s)| {
                let m = RustSelectedManifestMount::from_source(p, s).unwrap();
                (m.relative_path.clone(), m)
            })
            .collect();
        assert!(
            !rust_broad_target_discovery_completeness(
                &manifests,
                &BTreeSet::new(),
                &Default::default(),
                &BTreeSet::new(),
            )[&manifests[Path::new("app/Cargo.toml")].relative_path]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11799: an unrelated fixture manifest made every Rust context broad-incomplete"
    )]
    fn broad_completeness_manifest_closure() {
        let root = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[workspace]\nmembers=['app','other']",
        )
        .unwrap();
        let app = RustSelectedManifestMount::from_source(
            "app/Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'",
        )
        .unwrap();
        let broken = |path| {
            RustSelectedManifestMount::from_source(
                path,
                "[package]\nname='broken'\nversion='0.1.0'\nbuild='build.rs'",
            )
            .unwrap()
        };
        let mut manifests: BTreeMap<_, _> = [
            root,
            app.clone(),
            broken("other/Cargo.toml"),
            broken("tests/fixture/Cargo.toml"),
        ]
        .into_iter()
        .map(|m| (m.relative_path.clone(), m))
        .collect();
        let sources = [
            PathBuf::from("app/src/lib.rs"),
            PathBuf::from("other/src/lib.rs"),
        ]
        .into_iter()
        .collect();
        assert!(
            rust_broad_target_discovery_completeness(
                &manifests,
                &sources,
                &Default::default(),
                &BTreeSet::new()
            )[&app.relative_path],
            "unrelated member and non-member targets must not taint app"
        );
        assert!(
            !rust_broad_target_discovery_completeness(
                &manifests,
                &sources,
                &Default::default(),
                &BTreeSet::new()
            )[&manifests[Path::new("other/Cargo.toml")].relative_path],
            "own absent target"
        );
        let dependent = RustSelectedManifestMount::from_source(
            "app/Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\nbroken={path='../other'}",
        )
        .unwrap();
        manifests.insert(dependent.relative_path.clone(), dependent.clone());
        assert!(
            !rust_broad_target_discovery_completeness(
                &manifests,
                &sources,
                &Default::default(),
                &BTreeSet::new()
            )[&dependent.relative_path],
            "path dependency absent target"
        );
        manifests.insert(app.relative_path.clone(), app.clone());
        manifests.remove(Path::new("other/Cargo.toml"));
        assert!(
            !rust_broad_target_discovery_completeness(
                &manifests,
                &sources,
                &Default::default(),
                &BTreeSet::new()
            )[&app.relative_path],
            "workspace member discovery gap"
        );
    }

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
                rust_broad_target_discovery_completeness(
                    &manifests,
                    &sources,
                    &Default::default(),
                    &BTreeSet::new()
                )[&manifest.relative_path],
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
        assert!(
            rust_broad_target_discovery_completeness(
                &manifests,
                &BTreeSet::new(),
                &Default::default(),
                &BTreeSet::new(),
            )[&app.relative_path]
        );
        let mut missing = manifests.clone();
        missing.remove(Path::new("helper/Cargo.toml"));
        assert!(
            !rust_broad_target_discovery_completeness(
                &missing,
                &BTreeSet::new(),
                &Default::default(),
                &BTreeSet::new(),
            )[&app.relative_path]
        );
        let malformed_root =
            RustSelectedManifestMount::from_source("Cargo.toml", "[workspace]\nmembers = [42]")
                .unwrap();
        let mut malformed = manifests;
        malformed.insert(PathBuf::from("Cargo.toml"), malformed_root);
        assert!(
            !rust_broad_target_discovery_completeness(
                &malformed,
                &BTreeSet::new(),
                &Default::default(),
                &BTreeSet::new(),
            )[&app.relative_path]
        );
    }
}
