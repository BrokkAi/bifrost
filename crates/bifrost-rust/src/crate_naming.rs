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
//! `with_rust_package_components` (`declarations.rs`) and
//! `rust_crate_root_package` (`imports.rs`) are the two consumers; both fall
//! back to the legacy path-derived scheme when this module answers `None`.
//!
//! Live naming results use bounded caches invalidated per analyzer generation. The resolvers ask for a
//! file's naming once per resolved type node and once per import segment, and a
//! `scan_usages` profile of this repository (#2632) put a quarter of all CPU in
//! the ancestor walk below: one `is_file` syscall per directory level, one
//! `stat` on the manifest it lands on, and the manifest mutex, repeated for
//! every question about every file. Nothing a memo holds can change within a
//! generation, so [`invalidate`] at the generation boundary is what makes the
//! per-call filesystem work unnecessary rather than merely cheap.

use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::RwLock;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::{PackageAnchor, ProjectFile};
#[cfg(test)]
use brokk_bifrost_core::hash::HashMap;
use moka::sync::Cache;

use crate::cargo_manifest::{RustCargoManifestDocument, normalize_crate_name};
use crate::selected_context::RustSelectedManifestMount;

/// Directory names that Cargo gives their own target tree, relative to the
/// manifest directory. A file directly in one of them is a target root and is
/// its own `crate::` root (`benches/b.rs` sees its own consts under
/// `crate::`); the shared modules beside it (`tests/common/mod.rs`) keep the
/// kind-level root so cross-target references still name one file.
const TARGET_DIRECTORIES: [&str; 3] = ["tests", "examples", "benches"];

/// Cargo naming reconstructed from one selected operation's exact inputs.
///
/// This authority is deliberately separate from [`rust_crate_paths`]. The
/// latter is the generation-scoped live-filesystem cache used while indexing;
/// selected resolution must name a persisted row from the selected manifest
/// bytes and selected source paths instead. In particular, changing a dirty
/// manifest changes this value for one operation without invalidating or
/// mutating the live naming cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedCargoNaming {
    crates: Box<[RustSelectedCrateNaming]>,
    source_paths: std::collections::BTreeSet<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustSelectedCrateNaming {
    manifest_path: PathBuf,
    directory: PathBuf,
    crate_name: String,
    library_path: PathBuf,
}

impl RustSelectedCargoNaming {
    /// Build naming from the exact selected source inventory and parsed Cargo
    /// documents. No manifest or source path is read from the filesystem.
    pub fn from_selected_inputs(
        source_paths: impl IntoIterator<Item = PathBuf>,
        manifest_mounts: &[RustSelectedManifestMount],
    ) -> Result<Self, String> {
        let source_paths = source_paths
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let mut crates = Vec::new();
        for manifest in manifest_mounts {
            let Some(package) = manifest.facts.package.as_ref() else {
                continue;
            };
            let directory = manifest
                .relative_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            crates.push(RustSelectedCrateNaming {
                manifest_path: manifest.relative_path.clone(),
                directory,
                crate_name: package.library_name.clone(),
                library_path: package.library_path.clone(),
            });
        }
        crates.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
        for pair in crates.windows(2) {
            if pair[0].manifest_path == pair[1].manifest_path {
                return Err(format!(
                    "selected Rust naming has duplicate Cargo manifest path {:?}",
                    pair[0].manifest_path
                ));
            }
        }
        Ok(Self {
            crates: crates.into_boxed_slice(),
            source_paths,
        })
    }

    /// Resolve the package prefix for a selected persisted unit.
    ///
    /// `None` is a structured selected-input gap: the file is absent from the
    /// selected source inventory, or two equally deep selected package
    /// manifests would govern it. Manifest-less files intentionally use the
    /// existing path-derived identity rather than consulting the live naming
    /// cache.
    pub fn resolve_package_anchor(
        &self,
        anchor: PackageAnchor,
        _content_qualifier: &str,
        relative_path: &Path,
    ) -> Option<FqName> {
        if !self.source_paths.contains(relative_path) {
            return None;
        }
        let paths = match self.crate_for(relative_path) {
            Some(selected_crate) => {
                let relative = relative_path.strip_prefix(&selected_crate.directory).ok()?;
                classify_selected(
                    relative,
                    selected_crate.crate_name.as_str(),
                    &selected_crate.directory,
                    &selected_crate.library_path,
                    &self.source_paths,
                )
            }
            None if self.has_package_manifest_for(relative_path) => return None,
            None => path_derived_paths(relative_path),
        };
        let components = match anchor {
            PackageAnchor::OwnModule { pop } => {
                let keep = paths.package.len().saturating_sub(usize::from(pop));
                &paths.package[..keep]
            }
            PackageAnchor::CrateRoot => &paths.crate_root,
        };
        Some(fq_from_package_components(components))
    }

    fn crate_for(&self, relative_path: &Path) -> Option<&RustSelectedCrateNaming> {
        let mut selected = None;
        let mut selected_depth = 0;
        for candidate in &self.crates {
            if !relative_path.starts_with(&candidate.directory) {
                continue;
            }
            let depth = candidate.directory.components().count();
            if depth < selected_depth {
                continue;
            }
            if depth == selected_depth && selected.is_some() {
                // Two package manifests at one depth make the selected
                // authority ambiguous. Keep that distinction from becoming
                // an accidental filesystem-order choice.
                return None;
            }
            selected = Some(candidate);
            selected_depth = depth;
        }
        selected
    }

    fn has_package_manifest_for(&self, relative_path: &Path) -> bool {
        self.crates
            .iter()
            .any(|candidate| relative_path.starts_with(&candidate.directory))
    }
}

fn fq_from_package_components(components: &[String]) -> FqName {
    let interner = segment_interner();
    let mut fq = FqName::new();
    for component in components {
        fq.push(interner.intern(component, SegmentKind::Package));
    }
    fq
}

fn path_derived_paths(relative_path: &Path) -> CratePaths {
    CratePaths {
        package: path_derived_package_components(relative_path),
        crate_root: path_derived_crate_root_components(relative_path),
    }
}

pub(crate) fn path_derived_package_components(relative_path: &Path) -> Vec<String> {
    let mut components = relative_path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    let source_root = components.iter().rposition(|component| component == "src");
    if source_root == Some(0) {
        components.remove(0);
    }
    if components.is_empty() {
        return Vec::new();
    }
    let file_name = components.pop().unwrap_or_default();
    let stem = Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if matches!(stem, "lib" | "main" | "mod") {
        components
    } else if source_root.is_some() {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect()
    } else {
        components
    }
}

pub(crate) fn path_derived_crate_root_components(relative_path: &Path) -> Vec<String> {
    let components = relative_path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    let Some(src_index) = components.iter().rposition(|component| component == "src") else {
        return path_derived_package_components(relative_path);
    };
    if src_index == 0 {
        return Vec::new();
    }
    components[..=src_index].to_vec()
}

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
///
/// Shared behind an `Arc` because the same file is named thousands of times per
/// scan and the components below are the only allocation in the answer.
pub(super) fn rust_crate_paths(file: &ProjectFile) -> Option<Arc<CratePaths>> {
    if let Some(memoized) = CRATE_PATHS_BY_FILE.get(file) {
        return memoized;
    }
    let paths = derive_crate_paths(file).map(Arc::new);
    CRATE_PATHS_BY_FILE.insert(file.clone(), paths.clone());
    paths
}

fn derive_crate_paths(file: &ProjectFile) -> Option<CratePaths> {
    let nearest = nearest_crate(file)?;
    let relative = file.rel_path().strip_prefix(&nearest.directory).ok()?;
    Some(classify(
        &file.root().join(&nearest.directory),
        relative,
        nearest.crate_name.clone(),
        &nearest.library_path,
    ))
}

/// Name of the crate `file` belongs to, i.e. the identifier its own code may
/// spell in place of `crate` (`wasm_bindgen::foo` from inside `wasm-bindgen`).
/// `None` when no manifest governs the file.
pub(super) fn rust_file_crate_name(file: &ProjectFile) -> Option<String> {
    nearest_crate(file).map(|nearest| nearest.crate_name.clone())
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
    let nearest = nearest_crate(file)?;
    let relative = file.rel_path().strip_prefix(&nearest.directory).ok()?;
    let head = relative
        .components()
        .find_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .filter(|head| TARGET_DIRECTORIES.contains(&head.as_str()))?;
    let kind_root = vec![nearest.crate_name.clone(), head];
    (rust_crate_paths(file)?.crate_root != kind_root).then_some(kind_root)
}

/// The manifest that governs some directory: where it sits, relative to the
/// workspace root, and the crate name it declares.
#[derive(Debug, PartialEq, Eq)]
struct NearestCrate {
    directory: PathBuf,
    crate_name: String,
    library_path: PathBuf,
}

/// Nearest ancestor directory holding a `Cargo.toml` that names a crate, paired
/// with that crate's name. A `[workspace]`-only manifest names no crate, so the
/// walk continues upward past it.
///
/// Every directory the walk passes through shares the manifest it lands on, so
/// one walk fills bounded cache entries for that chain. Later lookups reuse
/// them until invalidation or eviction. Without that, the walk ran once per question
/// about every file and paid one `is_file` syscall per level each time.
fn nearest_crate(file: &ProjectFile) -> Option<Arc<NearestCrate>> {
    let root = file.root();
    let start = file.rel_path().parent().unwrap_or_else(|| Path::new(""));
    if let Some(memoized) = memoized_nearest_crate(root, start) {
        return memoized;
    }
    let mut walked: Vec<PathBuf> = Vec::new();
    let mut directory = Some(start);
    let nearest = loop {
        let Some(relative) = directory else {
            break None;
        };
        // `start` is already known to miss; anything above it may not be.
        if !walked.is_empty()
            && let Some(memoized) = memoized_nearest_crate(root, relative)
        {
            break memoized;
        }
        walked.push(relative.to_path_buf());
        #[cfg(test)]
        record_manifest_probe(root);
        let manifest = root.join(relative).join("Cargo.toml");
        if manifest.is_file()
            && let Some(naming) = cached_manifest_naming(&manifest)
        {
            break Some(Arc::new(NearestCrate {
                directory: relative.to_path_buf(),
                crate_name: naming.crate_name.clone(),
                library_path: naming.library_path.clone(),
            }));
        }
        directory = relative.parent();
    };
    for directory in walked {
        NEAREST_CRATE_BY_DIRECTORY.insert((root.to_path_buf(), directory), nearest.clone());
    }
    nearest
}

/// `None` when the memo has never been asked about `directory`, `Some(answer)`
/// otherwise -- including `Some(None)` for a directory with no manifest above
/// it, which is as expensive to rediscover as any other answer.
fn memoized_nearest_crate(root: &Path, directory: &Path) -> Option<Option<Arc<NearestCrate>>> {
    NEAREST_CRATE_BY_DIRECTORY.get(&(root.to_path_buf(), directory.to_path_buf()))
}

/// Split `relative` (a path below the manifest directory) into the crate-aware
/// package and `crate::` root. `manifest_root` is the absolute manifest
/// directory, used only for layout probes.
fn classify(
    manifest_root: &Path,
    relative: &Path,
    crate_name: String,
    library_path: &Path,
) -> CratePaths {
    classify_with_target_probe(
        relative,
        crate_name,
        library_path,
        |kind_directory, target| {
            manifest_root
                .join(kind_directory)
                .join(target)
                .join("main.rs")
                .is_file()
        },
    )
}

/// The selected equivalent of [`classify`]. The source inventory is the only
/// target-layout authority; this closure never probes the live filesystem.
fn classify_selected(
    relative: &Path,
    crate_name: &str,
    manifest_directory: &Path,
    library_path: &Path,
    source_paths: &std::collections::BTreeSet<PathBuf>,
) -> CratePaths {
    classify_with_target_probe(
        relative,
        crate_name.to_string(),
        library_path,
        |kind_directory, target| {
            source_paths.contains(
                &manifest_directory
                    .join(kind_directory)
                    .join(target)
                    .join("main.rs"),
            )
        },
    )
}

fn classify_with_target_probe(
    relative: &Path,
    crate_name: String,
    library_path: &Path,
    has_target_main: impl Fn(&Path, &str) -> bool,
) -> CratePaths {
    if relative == library_path {
        return CratePaths {
            package: vec![crate_name.clone()],
            crate_root: vec![crate_name.clone()],
        };
    }
    let relative = if library_path != Path::new("src/lib.rs") {
        let library_directory = library_path.parent().unwrap_or_else(|| Path::new(""));
        if library_directory != Path::new("src") && relative.starts_with(library_directory) {
            relative.strip_prefix(library_directory).unwrap_or(relative)
        } else {
            relative
        }
    } else {
        relative
    };
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
                    Path::new("src/bin"),
                    "bin",
                    below_bin,
                    &has_target_main,
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
                target_root(&crate_name, Path::new(head), head, rest, &has_target_main)
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
    has_target_main: &impl Fn(&Path, &str) -> bool,
) -> Vec<String> {
    let mut root = vec![crate_name.to_string(), kind.to_string()];
    if let Some(target) = below_kind.first()
        && has_target_main(kind_directory, target)
    {
        root.push(target.clone());
    }
    root
}

/// Derive the crate identifier from one already parsed Cargo document.
/// The normalized `[lib]` name wins when one is declared; otherwise the
/// normalized `[package]` name is returned. An implicit lib (`src/lib.rs`
/// autodiscovery) inherits the package name. `None` means the document is a
/// `[workspace]`-only manifest.
///
/// Selected operations can pass their exact retained manifest here instead of
/// consulting the generation-scoped filesystem cache below.
pub fn rust_manifest_crate_name(manifest: &RustCargoManifestDocument) -> Option<String> {
    let package_name = manifest.package_name()?;
    Some(
        manifest
            .library_name()
            .map(normalize_crate_name)
            .unwrap_or_else(|| normalize_crate_name(package_name)),
    )
}

/// Lookup results are bounded independently of workspace size. Eviction only
/// repeats one naming query; selected resolution still reads its SQLite rows.
const NAMING_CACHE_ENTRIES: u64 = 4096;

#[derive(Clone, Debug)]
struct ManifestNaming {
    crate_name: String,
    library_path: PathBuf,
}

type ManifestKey = (PathBuf, Option<SystemTime>);
static MANIFEST_NAMING: LazyLock<Cache<ManifestKey, Option<Arc<ManifestNaming>>>> =
    LazyLock::new(|| Cache::new(NAMING_CACHE_ENTRIES));
type DirectoryKey = (PathBuf, PathBuf);
static NEAREST_CRATE_BY_DIRECTORY: LazyLock<Cache<DirectoryKey, Option<Arc<NearestCrate>>>> =
    LazyLock::new(|| Cache::new(NAMING_CACHE_ENTRIES));
static CRATE_PATHS_BY_FILE: LazyLock<Cache<ProjectFile, Option<Arc<CratePaths>>>> =
    LazyLock::new(|| Cache::new(NAMING_CACHE_ENTRIES));

/// Forget live-filesystem naming results at the analyzer generation boundary.
pub fn invalidate() {
    MANIFEST_NAMING.invalidate_all();
    NEAREST_CRATE_BY_DIRECTORY.invalidate_all();
    CRATE_PATHS_BY_FILE.invalidate_all();
}

fn cached_manifest_naming(manifest: &Path) -> Option<Arc<ManifestNaming>> {
    let modified = std::fs::metadata(manifest)
        .and_then(|metadata| metadata.modified())
        .ok();
    let key = (manifest.to_path_buf(), modified);
    if let Some(cached) = MANIFEST_NAMING.get(&key) {
        return cached;
    }
    let naming = std::fs::read(manifest)
        .ok()
        .and_then(|source_bytes| {
            RustCargoManifestDocument::from_source_bytes(source_bytes.into_boxed_slice()).ok()
        })
        .and_then(|document| {
            Some(Arc::new(ManifestNaming {
                crate_name: rust_manifest_crate_name(&document)?,
                library_path: document.library_path().ok()?.to_path_buf(),
            }))
        });
    MANIFEST_NAMING.insert(key, naming.clone());
    naming
}

#[cfg(test)]
const POISONED: &str = "crate-naming test probe lock is poisoned";

/// Ancestor-walk manifest probes per workspace root, so a test can prove the
/// walk runs once per directory rather than once per file. Per root, because
/// unit tests in this binary run concurrently and each owns its own fixture
/// root.
#[cfg(test)]
static MANIFEST_PROBES: LazyLock<RwLock<HashMap<PathBuf, usize>>> =
    LazyLock::new(|| RwLock::new(HashMap::default()));

#[cfg(test)]
fn record_manifest_probe(root: &Path) {
    *MANIFEST_PROBES
        .write()
        .expect(POISONED)
        .entry(root.to_path_buf())
        .or_default() += 1;
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

        fn paths(&self, relative: &str) -> Option<Arc<CratePaths>> {
            rust_crate_paths(&ProjectFile::new(self.root.clone(), relative))
        }

        /// Ancestor-walk manifest probes charged to this fixture's root so far.
        fn manifest_probes(&self) -> usize {
            MANIFEST_PROBES
                .read()
                .expect(POISONED)
                .get(&self.root)
                .copied()
                .unwrap_or_default()
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
            (paths.package.clone(), paths.crate_root.clone())
        }
    }

    /// Serializes the tests that call [`invalidate`] against the tests that
    /// count probes: the memos are process-global, so one test's generation
    /// boundary would otherwise force another's ancestor walks to run again.
    fn exclusive_memo() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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

    #[test]
    fn selected_manifest_name_uses_exact_document_without_filesystem_reads() {
        let manifest = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname = \"outer-package\"\n\n[lib]\nname = \"renamed-lib\"\n",
        )
        .expect("selected manifest");
        let naming = RustSelectedCargoNaming::from_selected_inputs(
            [
                PathBuf::from("src/lib.rs"),
                PathBuf::from("src/inner.rs"),
                PathBuf::from("tests/common/mod.rs"),
            ],
            &[manifest],
        )
        .expect("selected naming");

        let lib_root = naming
            .resolve_package_anchor(PackageAnchor::CrateRoot, "", Path::new("src/lib.rs"))
            .expect("selected library root");
        assert_eq!(
            lib_root.display(segment_interner()),
            "renamed_lib",
            "the explicit lib target controls the crate root",
        );
        let inner = naming
            .resolve_package_anchor(
                PackageAnchor::OwnModule { pop: 0 },
                "",
                Path::new("src/inner.rs"),
            )
            .expect("selected module package");
        assert_eq!(inner.display(segment_interner()), "renamed_lib.inner");
    }

    #[test]
    fn selected_target_roots_use_only_selected_source_paths() {
        let manifest =
            RustSelectedManifestMount::from_source("Cargo.toml", "[package]\nname = \"package\"\n")
                .expect("selected manifest");
        let naming = RustSelectedCargoNaming::from_selected_inputs(
            [
                PathBuf::from("src/lib.rs"),
                PathBuf::from("tests/common/mod.rs"),
                PathBuf::from("src/bin/tool/main.rs"),
            ],
            &[manifest],
        )
        .expect("selected naming");

        let shared_test_root = naming
            .resolve_package_anchor(
                PackageAnchor::CrateRoot,
                "",
                Path::new("tests/common/mod.rs"),
            )
            .expect("selected shared test root");
        assert_eq!(
            shared_test_root.display(segment_interner()),
            "package.tests"
        );
        let binary_root = naming
            .resolve_package_anchor(
                PackageAnchor::CrateRoot,
                "",
                Path::new("src/bin/tool/main.rs"),
            )
            .expect("selected binary root");
        assert_eq!(binary_root.display(segment_interner()), "package.bin.tool");
        let popped = naming
            .resolve_package_anchor(
                PackageAnchor::OwnModule { pop: 1 },
                "",
                Path::new("src/bin/tool/main.rs"),
            )
            .expect("selected popped package");
        assert_eq!(popped.display(segment_interner()), "package.bin");
    }

    #[test]
    fn selected_nested_package_uses_workspace_relative_target_paths() {
        let manifest = RustSelectedManifestMount::from_source(
            "crates/member/Cargo.toml",
            "[package]\nname = \"member-package\"\n",
        )
        .expect("selected manifest");
        let naming = RustSelectedCargoNaming::from_selected_inputs(
            [
                PathBuf::from("crates/member/src/lib.rs"),
                PathBuf::from("crates/member/src/bin/tool/main.rs"),
            ],
            &[manifest],
        )
        .expect("selected naming");
        let root = naming
            .resolve_package_anchor(
                PackageAnchor::CrateRoot,
                "",
                Path::new("crates/member/src/bin/tool/main.rs"),
            )
            .expect("selected nested binary root");
        assert_eq!(root.display(segment_interner()), "member_package.bin.tool");
    }

    #[test]
    fn selected_custom_library_path_controls_module_package_root() {
        let manifest = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname = \"package\"\n[lib]\npath = \"src/custom/lib.rs\"\n",
        )
        .expect("selected manifest");
        let naming = RustSelectedCargoNaming::from_selected_inputs(
            [
                PathBuf::from("src/custom/lib.rs"),
                PathBuf::from("src/custom/inner.rs"),
                PathBuf::from("src/main.rs"),
            ],
            &[manifest],
        )
        .expect("selected naming");
        let library_root = naming
            .resolve_package_anchor(PackageAnchor::CrateRoot, "", Path::new("src/custom/lib.rs"))
            .expect("selected custom library root");
        assert_eq!(library_root.display(segment_interner()), "package");
        let inner = naming
            .resolve_package_anchor(
                PackageAnchor::OwnModule { pop: 0 },
                "",
                Path::new("src/custom/inner.rs"),
            )
            .expect("selected custom library module");
        assert_eq!(inner.display(segment_interner()), "package.inner");
    }

    #[test]
    fn live_and_selected_custom_library_roots_have_the_same_identity() {
        for (library, inner) in [
            ("app.rs", "inner.rs"),
            ("src/custom/lib.rs", "src/custom/inner.rs"),
            ("alt/entry.rs", "alt/inner.rs"),
        ] {
            let manifest_source =
                format!("[package]\nname = \"package\"\n[lib]\npath = {library:?}\n");
            let fixture = Fixture::new(&[
                ("Cargo.toml", &manifest_source),
                (library, "pub mod inner;"),
                (inner, "pub fn take() {}"),
            ]);
            let manifest = RustSelectedManifestMount::from_source("Cargo.toml", &manifest_source)
                .expect("selected manifest");
            let selected = RustSelectedCargoNaming::from_selected_inputs(
                [PathBuf::from(library), PathBuf::from(inner)],
                &[manifest],
            )
            .expect("selected naming");
            for (file, expected) in [(library, "package"), (inner, "package.inner")] {
                let live = fixture.paths(file).expect("live naming");
                assert_eq!(live.package.join("."), expected, "{file}");
                assert_eq!(live.crate_root, ["package"], "{file}");
                let package = selected
                    .resolve_package_anchor(
                        PackageAnchor::OwnModule { pop: 0 },
                        "",
                        Path::new(file),
                    )
                    .expect("selected package");
                assert_eq!(
                    package.display(segment_interner()).to_string(),
                    expected,
                    "{file}"
                );
            }
        }
    }

    #[test]
    fn selected_manifestless_files_keep_path_derived_identity() {
        let naming = RustSelectedCargoNaming::from_selected_inputs(
            [PathBuf::from("src/lib.rs"), PathBuf::from("src/inner.rs")],
            &[],
        )
        .expect("selected naming");
        let root = naming
            .resolve_package_anchor(PackageAnchor::CrateRoot, "", Path::new("src/lib.rs"))
            .expect("manifestless crate root");
        assert!(root.is_empty());
        let inner = naming
            .resolve_package_anchor(
                PackageAnchor::OwnModule { pop: 0 },
                "",
                Path::new("src/inner.rs"),
            )
            .expect("manifestless module package");
        assert_eq!(inner.display(segment_interner()), "inner");
    }

    #[test]
    fn selected_naming_reports_files_outside_the_selected_inventory() {
        let manifest =
            RustSelectedManifestMount::from_source("Cargo.toml", "[package]\nname = \"package\"\n")
                .expect("selected manifest");
        let naming = RustSelectedCargoNaming::from_selected_inputs(
            [PathBuf::from("src/lib.rs")],
            &[manifest],
        )
        .expect("selected naming");
        assert!(
            naming
                .resolve_package_anchor(PackageAnchor::CrateRoot, "", Path::new("src/missing.rs"))
                .is_none()
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

    /// The memos answer from the last generation until the generation
    /// boundary drops them, which is the whole point of not stat-ing a
    /// manifest per call. `RustAnalyzer` construction and update call
    /// `invalidate`, so an edit between two builds is picked up.
    #[test]
    fn editing_a_manifest_renames_the_crate_after_invalidation() {
        let _exclusive = exclusive_memo();
        let fixture = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "")]);
        assert_eq!(fixture.resolved("src/lib.rs").0, components("wasm_bindgen"));

        let manifest = fixture.root.join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname = \"other\"\n").expect("rewrite manifest");
        filetime::set_file_mtime(
            &manifest,
            filetime::FileTime::from_unix_time(1_700_000_000, 0),
        )
        .expect("set mtime");
        assert_eq!(
            fixture.resolved("src/lib.rs").0,
            components("wasm_bindgen"),
            "the memo answers for the whole generation",
        );

        invalidate();
        assert_eq!(fixture.resolved("src/lib.rs").0, components("other"));
    }

    /// The cost this module exists to remove: the ancestor walk used to run
    /// once per question about every file, one `is_file` syscall per level.
    /// Every directory it passes shares the manifest it lands on, so a whole
    /// crate's files cost one walk per distinct directory and nothing after.
    #[test]
    fn one_ancestor_walk_serves_every_file_under_a_directory() {
        let _exclusive = exclusive_memo();
        let fixture = Fixture::new(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n",
            ),
            ("crates/a/Cargo.toml", "[package]\nname = \"member-a\"\n"),
            ("crates/b/Cargo.toml", "[package]\nname = \"member-b\"\n"),
        ]);
        invalidate();
        assert_eq!(fixture.manifest_probes(), 0, "a fresh fixture root");

        // Two crates, two directories each, 50 files per directory.
        let directories = [
            "crates/a/src",
            "crates/a/src/deep",
            "crates/b/src",
            "crates/b/src/deep",
        ];
        let files: Vec<String> = directories
            .iter()
            .flat_map(|directory| (0..50).map(move |index| format!("{directory}/f{index}.rs")))
            .collect();
        assert_eq!(files.len(), 200);

        for file in &files {
            let package = fixture.resolved(file).0;
            let expected = if file.starts_with("crates/a/") {
                "member_a"
            } else {
                "member_b"
            };
            assert_eq!(
                package.first().map(String::as_str),
                Some(expected),
                "{file}"
            );
        }

        // `crates/<x>/src` walks itself and finds `crates/<x>`: two probes.
        // `crates/<x>/src/deep` probes itself and then stops on the memoized
        // `crates/<x>/src`: one probe. Nothing else on disk is touched, and no
        // walk is charged to the 49 further files in each directory.
        assert_eq!(
            fixture.manifest_probes(),
            directories.len() + 2,
            "one ancestor walk per distinct directory, none per file",
        );

        for file in &files {
            fixture.resolved(file);
        }
        assert_eq!(
            fixture.manifest_probes(),
            directories.len() + 2,
            "a second pass over the same files opens no new walk",
        );
    }
}
