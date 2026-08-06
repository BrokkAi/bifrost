//! Crate-aware Rust package naming.
//!
//! Rust packages are currently fabricated from repo directory paths
//! (`crates.webidl.src.generator`), which is wrong under directory renames and
//! under the same blob being mounted in two crates. This module derives the
//! naming from the nearest Cargo manifest instead: a file's package and the
//! `crate::` root it resolves against are both anchored on the crate name.
//!
//! Deliberately **not** built on [`super::cargo_routes::RustCargoRouteIndex`]:
//! naming is reached from inside the rayon build, and the route index lives
//! behind a `PoolSafeMemo` (see the comment on `RustAnalyzer::cargo_routes`),
//! so consulting it here would risk re-entering the pool. Everything below is a
//! filesystem ancestor walk plus pure manifest interpretation, mirroring the Go
//! precedent in `go/packages.rs`.
//!
//! `rust_package_components` (`declarations.rs`) and `rust_crate_root_package`
//! (`imports.rs`) are the two consumers; both fall back to the legacy
//! path-derived scheme when this module answers `None`.

use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use crate::analyzer::ProjectFile;
use crate::hash::HashMap;

use super::cargo_routes::{
    cargo_manifest_library_name, cargo_manifest_package_name, normalize_crate_name,
};

/// Directory names that Cargo gives their own target tree, relative to the
/// manifest directory. A file directly in one of them is a target root and is
/// its own `crate::` root (`benches/b.rs` sees its own consts under
/// `crate::`); the shared modules beside it (`tests/common/mod.rs`) keep the
/// kind-level root so cross-target references still name one file.
const TARGET_DIRECTORIES: [&str; 3] = ["tests", "examples", "benches"];

/// The crate-aware names of one file.
///
/// `crate_root` is always a prefix of `package`; consumers (`ModuleKey`,
/// `Domain::Crate`) depend on that, and it is asserted over the whole mapping
/// table in this module's tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CratePaths {
    /// Package components of the file itself, e.g. `[wasm_bindgen, describe]`.
    pub(super) package: Vec<String>,
    /// Components that `crate::` resolves to from this file, e.g.
    /// `[wasm_bindgen]`.
    pub(super) crate_root: Vec<String>,
}

/// Crate-aware package and `crate::` root for `file`, or `None` when no
/// `Cargo.toml` governs it.
///
/// `None` means "not a Cargo-managed file"; callers fall back to the legacy
/// path-derived scheme, which this module deliberately does not reimplement.
pub(super) fn rust_crate_paths(file: &ProjectFile) -> Option<CratePaths> {
    let (manifest_directory, crate_name) = nearest_crate(file)?;
    let relative = file.rel_path().strip_prefix(&manifest_directory).ok()?;
    Some(classify(
        &file.root().join(&manifest_directory),
        relative,
        crate_name,
    ))
}

/// Name of the crate `file` belongs to, i.e. the identifier its own code may
/// spell in place of `crate` (`wasm_bindgen::foo` from inside `wasm-bindgen`).
/// `None` when no manifest governs the file.
pub(super) fn rust_file_crate_name(file: &ProjectFile) -> Option<String> {
    nearest_crate(file).map(|(_, crate_name)| crate_name)
}

/// Kind-level root (`C.tests`, `C.benches`, `C.examples`) of the multi-target
/// directory holding `file`, when that is not already the file's own
/// `crate::` root.
///
/// A target root file owns its `crate::` root so sibling targets stay isolated,
/// but the modules they share (`tests/common/mod.rs`) have a single identity
/// under the kind root. This is therefore the second candidate for anything
/// that resolves a name out of a target root file: own root first, kind root on
/// a miss. `None` for files that already sit at the kind root, for `src/`
/// files, and for manifest-less trees.
pub(super) fn rust_target_kind_root(file: &ProjectFile) -> Option<Vec<String>> {
    let (manifest_directory, crate_name) = nearest_crate(file)?;
    let relative = file.rel_path().strip_prefix(&manifest_directory).ok()?;
    let head = relative
        .components()
        .find_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .filter(|head| TARGET_DIRECTORIES.contains(&head.as_str()))?;
    let kind_root = vec![crate_name, head];
    (rust_crate_paths(file)?.crate_root != kind_root).then_some(kind_root)
}

/// Nearest ancestor directory holding a `Cargo.toml` that names a crate, paired
/// with that crate's name. A `[workspace]`-only manifest names no crate, so the
/// walk continues upward past it.
fn nearest_crate(file: &ProjectFile) -> Option<(PathBuf, String)> {
    let mut directory = file.rel_path().parent();
    loop {
        let relative = directory.unwrap_or_else(|| Path::new(""));
        let manifest = file.root().join(relative).join("Cargo.toml");
        if manifest.is_file()
            && let Some(name) = cached_manifest_crate_name(&manifest)
        {
            return Some((relative.to_path_buf(), name));
        }
        directory = relative.parent();
        directory?;
    }
}

/// Split `relative` (a path below the manifest directory) into the crate-aware
/// package and `crate::` root. `manifest_root` is the absolute manifest
/// directory, used only for layout probes.
fn classify(manifest_root: &Path, relative: &Path, crate_name: String) -> CratePaths {
    let mut components: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .filter(|component| !component.is_empty())
        .collect();
    let Some(file_name) = components.pop() else {
        return CratePaths {
            package: vec![crate_name.clone()],
            crate_root: vec![crate_name],
        };
    };
    let directories = components;
    let stem = Path::new(&file_name)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    // A `lib`/`main`/`mod` stem names its directory, not a module below it.
    let stem_segment = (!matches!(stem.as_str(), "lib" | "main" | "mod") && !stem.is_empty())
        .then(|| stem.clone());

    let package_of = |tail: &[String]| {
        std::iter::once(crate_name.clone())
            .chain(tail.iter().cloned())
            .chain(stem_segment.clone())
            .collect::<Vec<_>>()
    };

    match directories.split_first() {
        // `src/main.rs` keeps its `main` segment: dropping the stem would
        // collide the binary root with `src/lib.rs`'s package.
        Some((head, [])) if head == "src" && stem == "main" => CratePaths {
            package: vec![crate_name.clone(), "main".to_string()],
            crate_root: vec![crate_name],
        },
        // `src/bin/<target>`: each target directory is its own crate root.
        Some((head, rest)) if head == "src" && rest.first().is_some_and(|dir| dir == "bin") => {
            let below_bin = &rest[1..];
            let mut tail = vec!["bin".to_string()];
            tail.extend_from_slice(below_bin);
            CratePaths {
                package: package_of(&tail),
                crate_root: target_root(
                    &crate_name,
                    &manifest_root.join("src").join("bin"),
                    "bin",
                    below_bin,
                ),
            }
        }
        Some((head, rest)) if head == "src" => CratePaths {
            package: package_of(rest),
            crate_root: vec![crate_name],
        },
        // `tests/`, `examples/`, `benches/`.
        Some((head, rest)) if TARGET_DIRECTORIES.contains(&head.as_str()) => {
            let mut tail = vec![head.clone()];
            tail.extend_from_slice(rest);
            let package = package_of(&tail);
            // A file directly in the kind directory is a target root: it is
            // compiled as its own crate, so `crate::` names its own items and
            // sibling targets stay isolated from each other.
            let crate_root = if rest.is_empty() {
                package.clone()
            } else {
                target_root(&crate_name, &manifest_root.join(head), head, rest)
            };
            CratePaths {
                package,
                crate_root,
            }
        }
        // `build.rs` is compiled as its own crate, so it is its own root.
        None if stem == "build" => CratePaths {
            package: vec![crate_name.clone(), "build".to_string()],
            crate_root: vec![crate_name, "build".to_string()],
        },
        _ => CratePaths {
            package: package_of(&directories),
            crate_root: vec![crate_name],
        },
    }
}

/// `crate::` root for a file under a multi-target directory (`src/bin`,
/// `tests`, ...). A subdirectory holding a `main.rs` is a target of its own, so
/// it extends the root; a plain shared-module directory (`tests/common`) does
/// not.
fn target_root(
    crate_name: &str,
    kind_directory: &Path,
    kind: &str,
    below_kind: &[String],
) -> Vec<String> {
    let mut root = vec![crate_name.to_string(), kind.to_string()];
    if let Some(target) = below_kind.first()
        && kind_directory.join(target).join("main.rs").is_file()
    {
        root.push(target.clone());
    }
    root
}

/// Crate name declared by a parsed manifest: the normalized `[lib]` name when
/// one is declared, else the normalized `[package]` name. An implicit lib
/// (`src/lib.rs` autodiscovery) is unnamed and therefore takes the package
/// name too, so no layout probe is needed here. `None` for a manifest that
/// declares no package, i.e. a `[workspace]`-only manifest.
fn manifest_crate_name(manifest: &toml::Value) -> Option<String> {
    let package_name = cargo_manifest_package_name(manifest)?;
    Some(
        cargo_manifest_library_name(manifest)
            .unwrap_or_else(|| normalize_crate_name(&package_name)),
    )
}

/// Manifest absolute path plus its mtime, so an edited manifest re-parses
/// instead of answering from the cache.
type ManifestKey = (PathBuf, Option<SystemTime>);

/// Process-global manifest cache. Naming is asked for every Rust file, and the
/// same handful of manifests answer all of them.
static MANIFEST_CRATE_NAMES: LazyLock<Mutex<HashMap<ManifestKey, Option<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::default()));

fn cached_manifest_crate_name(manifest: &Path) -> Option<String> {
    let modified = std::fs::metadata(manifest)
        .and_then(|metadata| metadata.modified())
        .ok();
    let key = (manifest.to_path_buf(), modified);
    if let Some(cached) = MANIFEST_CRATE_NAMES
        .lock()
        .ok()
        .and_then(|names| names.get(&key).cloned())
    {
        return cached;
    }
    let name = std::fs::read_to_string(manifest)
        .ok()
        .and_then(|source| toml::from_str::<toml::Value>(&source).ok())
        .as_ref()
        .and_then(manifest_crate_name);
    if let Ok(mut names) = MANIFEST_CRATE_NAMES.lock() {
        names.insert(key, name.clone());
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        /// Materializes `files` (relative path, contents) under a fresh root.
        fn new(files: &[(&str, &str)]) -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let root = temp.path().to_path_buf();
            for (path, contents) in files {
                let path = root.join(path);
                std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
                std::fs::write(&path, contents).expect("write fixture");
            }
            Self { _root: temp, root }
        }

        fn paths(&self, relative: &str) -> Option<CratePaths> {
            rust_crate_paths(&ProjectFile::new(self.root.clone(), relative))
        }

        /// Package/root for a file that must be Cargo-managed.
        fn resolved(&self, relative: &str) -> (Vec<String>, Vec<String>) {
            let paths = self
                .paths(relative)
                .unwrap_or_else(|| panic!("{relative} has no crate paths"));
            assert!(
                paths.package.starts_with(&paths.crate_root),
                "crate root {:?} must prefix package {:?} for {relative}",
                paths.crate_root,
                paths.package,
            );
            (paths.package, paths.crate_root)
        }
    }

    fn components(joined: &str) -> Vec<String> {
        if joined.is_empty() {
            return Vec::new();
        }
        joined.split('.').map(str::to_string).collect()
    }

    const MANIFEST: &str = "[package]\nname = \"wasm-bindgen\"\n";

    /// Every row of the naming table, checked together with the
    /// crate-root-prefixes-package invariant the resolver depends on.
    #[test]
    fn crate_layout_maps_to_crate_anchored_names() {
        let files = [
            "src/lib.rs",
            "src/describe.rs",
            "src/convert/mod.rs",
            "src/foo/bar.rs",
            "src/main.rs",
            "src/bin/tool.rs",
            "src/bin/tool/main.rs",
            "build.rs",
            "tests/it.rs",
            "tests/common/mod.rs",
            "examples/demo.rs",
            "benches/b.rs",
            "weird/x.rs",
        ];
        let mut fixture_files = vec![("Cargo.toml", MANIFEST)];
        fixture_files.extend(files.iter().map(|path| (*path, "")));
        let fixture = Fixture::new(&fixture_files);

        let expected = [
            ("src/lib.rs", "wasm_bindgen", "wasm_bindgen"),
            ("src/describe.rs", "wasm_bindgen.describe", "wasm_bindgen"),
            ("src/convert/mod.rs", "wasm_bindgen.convert", "wasm_bindgen"),
            ("src/foo/bar.rs", "wasm_bindgen.foo.bar", "wasm_bindgen"),
            ("src/main.rs", "wasm_bindgen.main", "wasm_bindgen"),
            (
                "src/bin/tool.rs",
                "wasm_bindgen.bin.tool",
                "wasm_bindgen.bin",
            ),
            (
                "src/bin/tool/main.rs",
                "wasm_bindgen.bin.tool",
                "wasm_bindgen.bin.tool",
            ),
            ("build.rs", "wasm_bindgen.build", "wasm_bindgen.build"),
            (
                "tests/it.rs",
                "wasm_bindgen.tests.it",
                "wasm_bindgen.tests.it",
            ),
            (
                "tests/common/mod.rs",
                "wasm_bindgen.tests.common",
                "wasm_bindgen.tests",
            ),
            (
                "examples/demo.rs",
                "wasm_bindgen.examples.demo",
                "wasm_bindgen.examples.demo",
            ),
            (
                "benches/b.rs",
                "wasm_bindgen.benches.b",
                "wasm_bindgen.benches.b",
            ),
            ("weird/x.rs", "wasm_bindgen.weird.x", "wasm_bindgen"),
        ];
        for (relative, package, crate_root) in expected {
            assert_eq!(
                fixture.resolved(relative),
                (components(package), components(crate_root)),
                "naming for {relative}",
            );
        }
    }

    /// The crate name a `use` path spells is the lib target's, not the
    /// package's, when they differ.
    #[test]
    fn explicit_lib_name_wins_over_package_name() {
        let fixture = Fixture::new(&[
            (
                "Cargo.toml",
                "[package]\nname = \"outer-package\"\n\n[lib]\nname = \"renamed\"\n",
            ),
            ("src/lib.rs", ""),
            ("src/inner.rs", ""),
        ]);
        assert_eq!(fixture.resolved("src/lib.rs").0, components("renamed"));
        assert_eq!(
            fixture.resolved("src/inner.rs").0,
            components("renamed.inner"),
        );
    }

    /// Dashes are not legal in Rust paths; Cargo maps them to underscores and
    /// so must the naming.
    #[test]
    fn dashed_package_names_are_normalized() {
        let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "")]);
        assert_eq!(fixture.resolved("src/lib.rs").0, components("wasm_bindgen"));
    }

    /// A virtual-manifest directory names no crate, so a file below it belongs
    /// to the nearest enclosing package instead.
    #[test]
    fn workspace_only_manifest_is_skipped() {
        let fixture = Fixture::new(&[
            ("Cargo.toml", "[package]\nname = \"outer\"\n"),
            ("crates/Cargo.toml", "[workspace]\nmembers = [\"a\"]\n"),
            ("crates/src/lib.rs", ""),
        ]);
        assert_eq!(
            fixture.resolved("crates/src/lib.rs"),
            (components("outer.crates.src"), components("outer")),
        );
    }

    /// A nested member manifest wins over the workspace root above it.
    #[test]
    fn nearest_member_manifest_wins() {
        let fixture = Fixture::new(&[
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/a\"]\n"),
            ("crates/a/Cargo.toml", "[package]\nname = \"member-a\"\n"),
            ("crates/a/src/lib.rs", ""),
            ("crates/a/src/deep/mod.rs", ""),
        ]);
        assert_eq!(
            fixture.resolved("crates/a/src/deep/mod.rs"),
            (components("member_a.deep"), components("member_a")),
        );
    }

    /// Manifest-less trees are the caller's problem: this module reports
    /// nothing rather than reimplementing the legacy path-derived scheme.
    #[test]
    fn files_without_a_manifest_have_no_crate_paths() {
        let fixture = Fixture::new(&[("src/lib.rs", "")]);
        assert!(fixture.paths("src/lib.rs").is_none());
    }

    /// The cache is keyed by mtime, so editing a manifest changes the answer.
    #[test]
    fn editing_a_manifest_renames_the_crate() {
        let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "")]);
        assert_eq!(fixture.resolved("src/lib.rs").0, components("wasm_bindgen"));
        let manifest = fixture.root.join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname = \"other\"\n").expect("rewrite manifest");
        filetime::set_file_mtime(
            &manifest,
            filetime::FileTime::from_unix_time(1_700_000_000, 0),
        )
        .expect("set mtime");
        assert_eq!(fixture.resolved("src/lib.rs").0, components("other"));
    }
}
