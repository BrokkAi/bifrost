//! Files-only Rust toolchain and build-target evidence (#9049).
//!
//! Each Cargo package gets the toolchain facts that apply to its builds as
//! `rust-toolchain` dependency rows, owned by the same package entity as its
//! Cargo dependency rows:
//! - the channel of the `rust-toolchain.toml` or legacy `rust-toolchain` file
//!   rustup finds from the workspace root upward, with its `targets`; a
//!   pinned release (`1.77.0`) is `locked` with an exact version, any other
//!   channel (`stable`, `1.77`, a nightly) or a custom `path` toolchain is a
//!   `constraint` with no version;
//! - `no_toolchain_file` when there is none, so the toolchain that builds is a
//!   typed unknown rather than an absent row;
//! - the package's `rust-version`, a declared minimum, never the toolchain
//!   that builds;
//! - each `build.target` of the Cargo configuration a workspace build reads.
//!
//! Overrides outside the workspace (`RUSTUP_TOOLCHAIN`, `rustup override`,
//! `cargo +toolchain`, `CARGO_BUILD_TARGET`) belong to one build's process
//! and are not read; `rust.toolchain_override=unobserved` says so on every
//! toolchain-file row.

use std::ops::Range;
use std::path::{Path, PathBuf};

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_rust::cargo_config::{
    RustCargoConfigDocument, RustCargoConfiguration, is_cargo_configuration_path,
};
use brokk_bifrost_rust::cargo_manifest::RustCargoManifestDocument;
use brokk_bifrost_rust::cargo_routes::{cargo_package_string, cargo_workspace_manifest_directory};
use toml_edit::ImDocument;

use crate::analyzer::rust::file_dependency_evidence::member_entity;
use crate::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
};
use crate::analyzer::topology::DependencyScope;

/// Toolchain and build-target rows; the package is always `rust`.
pub const RUST_TOOLCHAIN_ECOSYSTEM: &str = "rust-toolchain";

/// Whether `path` is a rustup toolchain file.
pub(super) fn rust_toolchain_input(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("rust-toolchain" | "rust-toolchain.toml")
    )
}

struct Input<'a> {
    snapshot: &'a ProjectSourceSnapshot,
    document: Option<ImDocument<&'a str>>,
}

/// Append the toolchain rows of every Cargo package in `selected`.
pub(super) fn push_rust_toolchain_evidence(
    root: &Path,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
    result: &mut DependencyFileEvidence,
) {
    let mut inputs = HashMap::<PathBuf, Input<'_>>::default();
    let mut manifests = HashMap::default();
    let mut configs = Vec::new();
    for (file, snapshot) in selected {
        let path = file.rel_path();
        let toolchain = rust_toolchain_input(path);
        let manifest = path.file_name().is_some_and(|name| name == "Cargo.toml");
        let config = is_cargo_configuration_path(path);
        if !(toolchain || manifest || config) {
            continue;
        }
        // The Cargo producer reports duplicate, inexact and malformed Cargo
        // files; this pass reads only the ones it can interpret.
        let exact = git2::Oid::hash_object(git2::ObjectType::Blob, snapshot.source().as_bytes())
            .expect("hashing selected Rust toolchain bytes")
            == snapshot.oid();
        if inputs.contains_key(path) || !exact {
            if toolchain {
                gap(
                    result,
                    path,
                    0..0,
                    DependencyEvidenceGapKind::Malformed,
                    "rustup toolchain file is duplicated or not exact UTF-8 evidence",
                );
            }
            continue;
        }
        if toolchain {
            result.files_read += 1;
            result.bytes_read += snapshot.source().len();
        }
        if manifest && let Ok(document) = RustCargoManifestDocument::from_source(snapshot.source())
        {
            manifests.insert(parent(path), document);
        }
        if config
            && let Ok(document) =
                RustCargoConfigDocument::from_source_bytes(snapshot.source().as_bytes())
        {
            configs.push((path.to_path_buf(), document));
        }
        inputs.insert(
            path.to_path_buf(),
            Input {
                snapshot,
                document: ImDocument::parse(snapshot.source()).ok(),
            },
        );
    }
    let configuration = RustCargoConfiguration::from_files(configs);
    let mut members = manifests
        .iter()
        .filter(|(_, manifest)| manifest.package_name().is_some())
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.0.cmp(right.0));
    let mut rows = Vec::new();
    for (directory, manifest) in members {
        let package = manifest.package_name().expect("member package");
        let manifest_path = directory.join("Cargo.toml");
        let manifest_input = &inputs[&manifest_path];
        // Cargo and rustup run where a workspace build starts: its root.
        let workspace = cargo_workspace_manifest_directory(root, directory, manifest, &manifests)
            .unwrap_or_else(|| directory.clone());
        let owner = Owner {
            id: member_entity(directory).id(),
            conditions: vec![
                condition("cargo.member_manifest", &display(&manifest_path)),
                condition("cargo.member_package", package),
            ],
        };
        rows.push(toolchain_row(
            &owner,
            toolchain_file(&workspace, &inputs),
            &manifest_path,
            manifest_input,
            result,
        ));
        if let Some(minimum) =
            cargo_package_string(root, directory, manifest, &manifests, "rust-version")
        {
            rows.push(owner.row(
                DependencyEvidenceKind::Constraint,
                Some(minimum),
                None,
                vec![condition(
                    "rust.toolchain_evidence",
                    "minimum_supported_rust_version",
                )],
                &manifest_path,
                manifest_input,
                &["package", "rust-version"],
            ));
        }
        let (targets, defining) = configuration.configured_build_targets(&workspace);
        if let Some(level) = defining.last() {
            let path = ["config", "config.toml"]
                .into_iter()
                .map(|name| level.join(".cargo").join(name))
                .find(|path| inputs.contains_key(path))
                .expect("a defining configuration level has a selected file");
            for target in targets {
                let mut conditions = vec![
                    condition("rust.toolchain_evidence", "cargo_build_target"),
                    condition("rust.build_target", &target),
                ];
                conditions.extend(defining.iter().map(|level| {
                    let level = display(level);
                    condition(
                        "cargo.config_level",
                        if level.is_empty() { "." } else { &level },
                    )
                }));
                rows.push(owner.row(
                    DependencyEvidenceKind::Declared,
                    None,
                    None,
                    conditions,
                    &path,
                    &inputs[&path],
                    &["build", "target"],
                ));
            }
        }
    }
    for row in rows {
        if result.rows.len() >= limits.max_rows {
            gap(
                result,
                &row.build_file,
                row.byte_range,
                DependencyEvidenceGapKind::Limit,
                "Rust toolchain evidence row limit",
            );
            break;
        }
        result.rows.push(row);
    }
    result.rows.sort_by_key(DependencyEvidence::id);
}

/// The toolchain file rustup reads for a build started in `directory`: the
/// nearest level that has one, the legacy file winning where a level has
/// both.
fn toolchain_file<'a>(
    directory: &Path,
    inputs: &'a HashMap<PathBuf, Input<'a>>,
) -> Option<(PathBuf, &'a Input<'a>)> {
    directory.ancestors().find_map(|level| {
        ["rust-toolchain", "rust-toolchain.toml"]
            .into_iter()
            .map(|name| level.join(name))
            .find_map(|path| inputs.get(&path).map(|input| (path, input)))
    })
}

fn toolchain_row(
    owner: &Owner,
    file: Option<(PathBuf, &Input<'_>)>,
    manifest_path: &Path,
    manifest_input: &Input<'_>,
    result: &mut DependencyFileEvidence,
) -> DependencyEvidence {
    let Some((path, input)) = file else {
        return owner.row(
            DependencyEvidenceKind::Constraint,
            None,
            None,
            vec![condition("rust.toolchain_evidence", "no_toolchain_file")],
            manifest_path,
            manifest_input,
            &["package"],
        );
    };
    let mut conditions = vec![
        condition("rust.toolchain_evidence", "toolchain_file"),
        condition("rust.toolchain_override", "unobserved"),
    ];
    let toolchain = input
        .document
        .as_ref()
        .and_then(|document| document.get("toolchain"));
    // A legacy file may hold just a toolchain name instead of TOML.
    let legacy_name = (toolchain.is_none() && path.ends_with("rust-toolchain"))
        .then(|| input.snapshot.source().trim())
        .filter(|name| !name.is_empty() && !name.contains(char::is_whitespace));
    let channel = toolchain
        .and_then(|toolchain| toolchain.get("channel"))
        .and_then(toml_edit::Item::as_str)
        .or(legacy_name);
    for target in toolchain
        .and_then(|toolchain| toolchain.get("targets"))
        .and_then(toml_edit::Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml_edit::Value::as_str)
    {
        conditions.push(condition("rust.toolchain_target", target));
    }
    if let Some(custom) = toolchain
        .and_then(|toolchain| toolchain.get("path"))
        .and_then(toml_edit::Item::as_str)
    {
        conditions.push(condition("rust.toolchain_path", custom));
    }
    let interpreted = channel.is_some()
        || conditions
            .iter()
            .any(|condition| condition.kind == "rust.toolchain_path");
    if !interpreted {
        gap(
            result,
            &path,
            0..input.snapshot.source().len(),
            DependencyEvidenceGapKind::Malformed,
            "rustup toolchain file names no channel or path",
        );
    }
    let exact = channel.filter(|channel| {
        semver::Version::parse(channel)
            .is_ok_and(|version| version.pre.is_empty() && version.build.is_empty())
    });
    if let Some(channel) = channel {
        conditions.push(condition("rust.toolchain_channel", channel));
    }
    let mut row = owner.row(
        if exact.is_some() {
            DependencyEvidenceKind::Locked
        } else {
            DependencyEvidenceKind::Constraint
        },
        None,
        exact.map(str::to_owned),
        conditions,
        &path,
        input,
        if legacy_name.is_some() {
            &[]
        } else {
            &["toolchain", "channel"]
        },
    );
    row.complete = interpreted;
    row
}

struct Owner {
    id: String,
    conditions: Vec<DependencyCondition>,
}

impl Owner {
    #[allow(clippy::too_many_arguments)]
    fn row(
        &self,
        kind: DependencyEvidenceKind,
        version_requirement: Option<String>,
        exact_version: Option<String>,
        mut conditions: Vec<DependencyCondition>,
        build_file: &Path,
        input: &Input<'_>,
        keys: &[&str],
    ) -> DependencyEvidence {
        conditions.extend(self.conditions.iter().cloned());
        conditions
            .sort_by(|left, right| (&left.kind, &left.value).cmp(&(&right.kind, &right.value)));
        conditions.dedup();
        DependencyEvidence {
            ecosystem: RUST_TOOLCHAIN_ECOSYSTEM.to_owned(),
            package: "rust".to_owned(),
            kind,
            version_requirement,
            exact_version,
            source: None,
            locator: None,
            declared_by: Some(self.id.clone()),
            scope: DependencyScope::Unknown,
            conditions,
            build_file: build_file.to_path_buf(),
            source_digest: input.snapshot.oid().to_string(),
            byte_range: span(input, keys),
            complete: true,
        }
    }
}

/// The byte range of the item at `keys`, or of the nearest enclosing item
/// that has one (an inherited dotted key has none), or else the whole file.
fn span(input: &Input<'_>, keys: &[&str]) -> Range<usize> {
    let mut range = 0..input.snapshot.source().len();
    let Some(document) = &input.document else {
        return range;
    };
    let mut item = document.as_item();
    for key in keys {
        let Some(next) = item.get(key) else {
            break;
        };
        if let Some(span) = next.span() {
            range = span;
        }
        item = next;
    }
    range
}

fn condition(kind: &str, value: &str) -> DependencyCondition {
    DependencyCondition {
        kind: kind.to_owned(),
        value: value.to_owned(),
    }
}

fn gap(
    result: &mut DependencyFileEvidence,
    path: &Path,
    byte_range: Range<usize>,
    kind: DependencyEvidenceGapKind,
    message: &str,
) {
    result.gaps.push(DependencyEvidenceGap {
        kind,
        build_file: path.to_path_buf(),
        byte_range,
        message: message.to_owned(),
    });
}

fn parent(path: &Path) -> PathBuf {
    path.parent().expect("a file has a directory").to_path_buf()
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
