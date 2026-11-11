//! Crate-aware Rust package naming.
//!
//! Rust packages are currently fabricated from repo directory paths
//! (`crates.webidl.src.generator`), which is wrong under directory renames and
//! under the same blob being mounted in two crates. This module derives the
//! naming from the nearest Cargo manifest instead: a file's package and the
//! `crate::` root it resolves against are both anchored on the crate name.
//!
//! Naming walks captured configuration during indexing and the same published
//! configuration in SQL afterwards, so a store-backed generation never reads
//! the live filesystem. Caches with no generation authority read files directly.
//! Each adapter binding owns fresh bounded naming caches, so misses and evictions
//! cannot observe another generation's manifests. Both answers and their walk
//! receipts use the owner's existing retention budget.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::LazyLock;
#[cfg(test)]
use std::sync::RwLock;

use brokk_bifrost_core::analyzer::fq_name::FqName;
#[cfg(test)]
use brokk_bifrost_core::analyzer::fq_name::segment_interner;
use brokk_bifrost_core::analyzer::project::IdentityWalkInput;
use brokk_bifrost_core::analyzer::{PackageAnchor, ProjectFile};
#[cfg(test)]
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::retention_budget::{Accounted, RetentionBudget};

use crate::cargo_manifest::{RustCargoManifestDocument, normalize_crate_name};
use crate::selected_context::RustSelectedManifestMount;
use crate::usage_walks::WalkCache;

/// Directory names that Cargo gives their own target tree, relative to the
/// manifest directory. A file directly in one of them is a target root and is
/// its own `crate::` root (`benches/b.rs` sees its own consts under
/// `crate::`); the shared modules beside it (`tests/common/mod.rs`) keep the
/// kind-level root so cross-target references still name one file.
const TARGET_DIRECTORIES: [&str; 3] = [
    brokk_bifrost_core::analyzer::project::RUST_TARGET_LAYOUT_DIRECTORIES[0],
    brokk_bifrost_core::analyzer::project::RUST_TARGET_LAYOUT_DIRECTORIES[1],
    brokk_bifrost_core::analyzer::project::RUST_TARGET_LAYOUT_DIRECTORIES[2],
];

/// Cargo naming reconstructed from one selected operation's exact inputs.
///
/// This authority is deliberately separate from [`rust_crate_paths`]. The
/// latter is the generation-scoped captured configuration cache used while indexing;
/// selected resolution must name a persisted row from the selected manifest
/// bytes and selected source paths instead. In particular, changing a dirty
/// manifest changes this value for one operation without invalidating or
/// mutating the generation naming cache.
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

    /// Build from the package naming records of selected manifests.
    pub fn from_naming_records(
        source_paths: impl IntoIterator<Item = PathBuf>,
        records: &[(PathBuf, String, PathBuf)],
    ) -> Self {
        Self {
            source_paths: source_paths.into_iter().collect(),
            crates: records
                .iter()
                .map(|(path, name, library)| RustSelectedCrateNaming {
                    manifest_path: path.clone(),
                    directory: path.parent().unwrap_or_else(|| Path::new("")).to_path_buf(),
                    crate_name: name.clone(),
                    library_path: library.clone(),
                })
                .collect(),
        }
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
        let paths = self.crate_paths(relative_path)?;
        let components = match anchor {
            PackageAnchor::OwnModule { pop } => {
                let keep = paths.package.len().saturating_sub(usize::from(pop));
                &paths.package[..keep]
            }
            PackageAnchor::CrateRoot => &paths.crate_root,
        };
        Some(FqName::from_package_components(components))
    }

    /// The dotted package name of a selected file: the selected equivalent of
    /// `rust_package_name_with`. `None` has the meaning given for
    /// [`Self::resolve_package_anchor`].
    pub fn package_name(&self, relative_path: &Path) -> Option<String> {
        Some(self.crate_paths(relative_path)?.package.join("."))
    }

    /// Paths whose selected presence determines this member's target naming.
    pub fn path_probes(&self, relative_path: &Path) -> Vec<PathBuf> {
        let probes = std::cell::RefCell::new(Vec::new());
        let _paths = self.crate_paths_with_probe(relative_path, |path| {
            probes.borrow_mut().push(path.to_owned())
        });
        probes.into_inner()
    }

    fn crate_paths(&self, relative_path: &Path) -> Option<CratePaths> {
        self.crate_paths_with_probe(relative_path, |_| {})
    }

    fn crate_paths_with_probe(
        &self,
        relative_path: &Path,
        probe: impl Fn(&Path),
    ) -> Option<CratePaths> {
        if !self.source_paths.contains(relative_path) {
            return None;
        }
        match self.crate_for(relative_path) {
            Some(selected_crate) => {
                let relative = relative_path.strip_prefix(&selected_crate.directory).ok()?;
                Some(classify_selected(
                    relative,
                    selected_crate.crate_name.as_str(),
                    &selected_crate.directory,
                    &selected_crate.library_path,
                    &self.source_paths,
                    probe,
                ))
            }
            None if self.has_package_manifest_for(relative_path) => None,
            None => Some(path_derived_paths(relative_path)),
        }
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

/// Classify using the selected inventory, recording each target-layout probe.
fn classify_selected(
    relative: &Path,
    crate_name: &str,
    manifest_directory: &Path,
    library_path: &Path,
    source_paths: &std::collections::BTreeSet<PathBuf>,
    probe: impl Fn(&Path),
) -> CratePaths {
    classify_with_target_probe(
        relative,
        crate_name.to_string(),
        library_path,
        |kind_directory, target| {
            let path = manifest_directory
                .join(kind_directory)
                .join(target)
                .join("main.rs");
            probe(&path);
            source_paths.contains(&path)
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
                    Path::new(
                        brokk_bifrost_core::analyzer::project::RUST_TARGET_LAYOUT_DIRECTORIES[3],
                    ),
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
    let mut root = rust_target_kind_root_components(crate_name, kind);
    if let Some(target) = below_kind.first()
        && has_target_main(kind_directory, target)
    {
        root.push(target.clone());
    }
    root
}

fn rust_target_kind_root_components(crate_name: &str, kind: &str) -> Vec<String> {
    vec![crate_name.to_string(), kind.to_string()]
}

/// Derive the crate identifier from one already parsed Cargo document.
/// The normalized `[lib]` name wins when one is declared; otherwise the
/// normalized `[package]` name is returned. An implicit lib (`src/lib.rs`
/// autodiscovery) inherits the package name. `None` means the document is a
/// `[workspace]`-only manifest.
///
/// Selected operations can pass their exact retained manifest here instead of
/// consulting the generation-scoped configuration cache below.
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

type DirectoryKey = (PathBuf, PathBuf);
#[derive(Clone, Debug, PartialEq, Eq)]
struct NearestCrate {
    directory: PathBuf,
    crate_name: String,
    library_path: PathBuf,
}
/// The answer and receipt are produced together, including cached misses.
/// Each directory shares the full receipt allocation and selects its suffix.
#[derive(Clone)]
struct NearestCrateEntry {
    nearest: Option<NearestCrate>,
    inputs: Arc<[IdentityWalkInput]>,
    offset: usize,
}

fn naming_weight(bytes: usize) -> u32 {
    bytes.min(u32::MAX as usize) as u32
}

/// Immutable manifest authority for one naming generation. Missing paths are
/// absent even when a later disk edit creates them.
pub trait RustManifestSource: Send + Sync {
    fn retained_bytes(&self) -> usize {
        0
    }
    fn lists_path(&self, file: &ProjectFile) -> bool {
        file.root().join(file.rel_path()).is_file()
    }
    fn bytes(&self, file: &ProjectFile) -> std::io::Result<Option<Vec<u8>>>;
}

impl<F> RustManifestSource for F
where
    F: Fn(&ProjectFile) -> std::io::Result<Option<Vec<u8>>> + Send + Sync,
{
    fn bytes(&self, file: &ProjectFile) -> std::io::Result<Option<Vec<u8>>> {
        self(file)
    }
}

pub struct RustCrateNamingCaches {
    budget: RetentionBudget,
    source: Arc<dyn RustManifestSource>,
    _source_charge: brokk_bifrost_core::retention_budget::AllocationCharge,
    nearest_crate: WalkCache<DirectoryKey, NearestCrateEntry>,
    crate_paths: WalkCache<ProjectFile, CratePaths>,
}

impl RustCrateNamingCaches {
    /// Caches with no generation authority: an ownerless adapter, or one not
    /// yet bound to a project. They read manifests from the file system, as a
    /// project that is not store-backed would. An analyzer generation binds
    /// its own source through `for_source` and never uses this reader.
    pub fn new(budget: &RetentionBudget) -> Self {
        Self::with_source(
            budget,
            Arc::new(
                |file: &ProjectFile| match std::fs::read(file.root().join(file.rel_path())) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) => Err(error),
                },
            ),
        )
    }

    pub fn for_source(&self, source: Arc<dyn RustManifestSource>) -> Self {
        Self::with_source(&self.budget, source)
    }

    pub fn with_source(budget: &RetentionBudget, source: Arc<dyn RustManifestSource>) -> Self {
        Self {
            budget: budget.clone(),
            _source_charge:
                brokk_bifrost_core::retention_budget::AllocationCharge::acquire_required(
                    budget,
                    source.retained_bytes(),
                ),
            source,
            nearest_crate: WalkCache::new_capped(
                budget,
                "rust.crate_naming.nearest_crate",
                Some(NAMING_CACHE_ENTRIES as usize),
                |_, value| {
                    naming_weight(
                        size_of::<NearestCrateEntry>()
                            + value.nearest.as_ref().map_or(0, |nearest| {
                                nearest.directory.capacity()
                                    + nearest.crate_name.capacity()
                                    + nearest.library_path.capacity()
                            })
                            // Charge the full shared allocation for each entry.
                            + std::mem::size_of_val(value.inputs.as_ref())
                            + value.inputs.iter().map(|input| match input {
                                IdentityWalkInput::File { rel_path, .. }
                                | IdentityWalkInput::PathAbsent { rel_path } => rel_path.capacity(),
                                IdentityWalkInput::Unavailable => 0,
                            }).sum::<usize>(),
                    )
                },
            ),
            crate_paths: WalkCache::new_capped(
                budget,
                "rust.crate_naming.crate_paths",
                Some(NAMING_CACHE_ENTRIES as usize),
                |_, value| {
                    // The vectors' buffers and each string's full capacity.
                    let strings = |parts: &Vec<String>| {
                        brokk_bifrost_core::hash::vec_slot_bytes(parts)
                            + parts.iter().map(String::capacity).sum::<usize>()
                    };
                    naming_weight(
                        size_of::<CratePaths>()
                            + strings(&value.package)
                            + strings(&value.crate_root),
                    )
                },
            ),
        }
    }

    /// Each naming cache's name and its count of reads answered from a kept
    /// entry, for the hit-path read parity test.
    pub fn hit_counts(&self) -> [(&'static str, u64); 2] {
        [self.nearest_crate.hit_count(), self.crate_paths.hit_count()]
    }

    /// Evict naming answers without changing their immutable manifest authority.
    /// Updates bind fresh caches rather than mutating older generations.
    pub fn invalidate_all(&self) {
        self.nearest_crate.invalidate_all();
        self.crate_paths.invalidate_all();
    }
}

pub(super) fn rust_crate_paths_with(
    caches: &RustCrateNamingCaches,
    file: &ProjectFile,
) -> Option<Arc<Accounted<CratePaths>>> {
    if let Some(cached) = caches.crate_paths.get_optional(file) {
        return cached;
    }
    let paths = derive_crate_paths_with(caches, file);
    caches.crate_paths.keep_optional(file.clone(), paths)
}

fn derive_crate_paths_with(
    caches: &RustCrateNamingCaches,
    file: &ProjectFile,
) -> Option<CratePaths> {
    let nearest = nearest_crate_with(caches, file)?;
    let relative = file.rel_path().strip_prefix(&nearest.directory).ok()?;
    Some(classify_with_target_probe(
        relative,
        nearest.crate_name.clone(),
        &nearest.library_path,
        |kind, target| {
            caches.source.lists_path(&ProjectFile::new(
                file.root(),
                nearest.directory.join(kind).join(target).join("main.rs"),
            ))
        },
    ))
}

#[allow(dead_code)] // Used when the remaining Rust query callers move onto the handle.
pub(super) fn rust_file_crate_name_with(
    caches: &RustCrateNamingCaches,
    file: &ProjectFile,
) -> Option<String> {
    nearest_crate_with(caches, file).map(|nearest| nearest.crate_name.clone())
}

#[allow(dead_code)] // Used when the remaining Rust query callers move onto the handle.
pub(super) fn rust_target_kind_root_with(
    caches: &RustCrateNamingCaches,
    file: &ProjectFile,
) -> Option<Vec<String>> {
    let nearest = nearest_crate_with(caches, file)?;
    let relative = file.rel_path().strip_prefix(&nearest.directory).ok()?;
    let head = relative
        .components()
        .find_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .filter(|head| TARGET_DIRECTORIES.contains(&head.as_str()))?;
    let kind_root = rust_target_kind_root_components(&nearest.crate_name, &head);
    (rust_crate_paths_with(caches, file)?.crate_root != kind_root).then_some(kind_root)
}

/// Replay all ancestor probes behind a file's generation-scoped identity.
/// Eviction re-probes the same captured or stored configuration, keeping the
/// answer and receipt together; the analyzer checks reads against its snapshot.
pub fn rust_file_identity_inputs_with(
    caches: &RustCrateNamingCaches,
    file: &ProjectFile,
) -> Vec<IdentityWalkInput> {
    let entry = nearest_crate_entry_with(caches, file);
    entry.inputs[entry.offset..].to_vec()
}

fn nearest_crate_with(caches: &RustCrateNamingCaches, file: &ProjectFile) -> Option<NearestCrate> {
    nearest_crate_entry_with(caches, file).nearest.clone()
}

fn nearest_crate_entry_with(
    caches: &RustCrateNamingCaches,
    file: &ProjectFile,
) -> Arc<Accounted<NearestCrateEntry>> {
    let root = file.root();
    let start = file.rel_path().parent().unwrap_or_else(|| Path::new(""));
    let key = |directory: &Path| (root.to_path_buf(), directory.to_path_buf());
    if let Some(entry) = caches.nearest_crate.get(&key(start)) {
        return entry;
    }
    let mut walked = Vec::new();
    let mut inputs = Vec::new();
    let mut directory = Some(start);
    let nearest = loop {
        let Some(relative) = directory else {
            break None;
        };
        if !walked.is_empty()
            && let Some(entry) = caches.nearest_crate.get(&key(relative))
        {
            inputs.extend_from_slice(&entry.inputs[entry.offset..]);
            break entry.nearest.clone();
        }
        walked.push((relative.to_path_buf(), inputs.len()));
        #[cfg(test)]
        record_manifest_probe(root);
        let path = relative.join("Cargo.toml");
        let rel_path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(&path);
        match caches.source.bytes(&ProjectFile::new(root, &path)) {
            Ok(Some(source)) => {
                let blob = git2::Oid::hash_object(git2::ObjectType::Blob, &source)
                    .expect("hashing captured manifest");
                inputs.push(IdentityWalkInput::File {
                    rel_path,
                    blob: blob.as_bytes().try_into().expect("blob width"),
                    content_digest: brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                        &source,
                    ),
                });
                if let Ok(document) =
                    RustCargoManifestDocument::from_source_bytes(source.into_boxed_slice())
                    && let Some(crate_name) = rust_manifest_crate_name(&document)
                    && let Ok(library_path) = document.library_path()
                {
                    break Some(NearestCrate {
                        directory: relative.to_path_buf(),
                        crate_name,
                        library_path: library_path.to_path_buf(),
                    });
                }
            }
            Ok(None) => {
                inputs.push(IdentityWalkInput::PathAbsent { rel_path });
            }
            Err(_) => {
                // Preserve naming's ancestor search, but refuse attribution
                // when a probe cannot supply its bytes.
                inputs.push(IdentityWalkInput::Unavailable);
            }
        }
        directory = relative.parent();
    };
    let inputs: Arc<[IdentityWalkInput]> = inputs.into();
    let mut result = None;
    for (directory, offset) in walked.into_iter().rev() {
        result = Some(caches.nearest_crate.keep(
            key(&directory),
            NearestCrateEntry {
                nearest: nearest.clone(),
                inputs: inputs.clone(),
                offset,
            },
        ));
    }
    result.expect("the starting directory was probed")
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
    use brokk_bifrost_test_macros::hardwon;

    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
        caches: RustCrateNamingCaches,
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
            Self {
                _root: temp,
                root,
                caches: RustCrateNamingCaches::with_source(&RetentionBudget::for_tests(), {
                    let inputs = files
                        .iter()
                        .map(|(path, source)| (PathBuf::from(path), source.as_bytes().to_vec()))
                        .collect::<std::collections::HashMap<_, _>>();
                    Arc::new(move |file: &ProjectFile| Ok(inputs.get(file.rel_path()).cloned()))
                }),
            }
        }

        fn paths(&self, relative: &str) -> Option<Arc<Accounted<CratePaths>>> {
            rust_crate_paths_with(&self.caches, &ProjectFile::new(self.root.clone(), relative))
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

    /// Eviction must keep naming tied to its captured inputs after disk edits.
    #[test]
    #[hardwon("#10596: crate naming read new Cargo.toml bytes for an older generation")]
    fn eviction_keeps_the_captured_manifest_after_disk_edits() {
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

        fixture.caches.invalidate_all();
        assert_eq!(fixture.resolved("src/lib.rs").0, components("wasm_bindgen"));
    }

    /// The cost this module exists to remove: the ancestor walk used to run
    /// once per question about every file, one `is_file` syscall per level.
    /// Every directory it passes shares the manifest it lands on, so a whole
    /// crate's files cost one walk per distinct directory and nothing after.
    #[test]
    #[hardwon("78436c5a27bb: repeated file lookups reran the same Cargo manifest ancestor walk")]
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
        fixture.caches.invalidate_all();
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
            let file = ProjectFile::new(fixture.root.clone(), file);
            let first = rust_file_identity_inputs_with(&fixture.caches, &file);
            let second = rust_file_identity_inputs_with(&fixture.caches, &file);
            assert!(!first.is_empty(), "the walk records its manifest probes");
            assert_eq!(
                first.len(),
                second.len(),
                "warm identity reads retain the receipt"
            );
        }
        assert_eq!(
            fixture.manifest_probes(),
            directories.len() + 2,
            "a second pass over the same files opens no new walk",
        );
    }

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
}

#[cfg(test)]
mod qs3_path_contract {
    use super::*;

    #[test]
    fn qs3_manifest_free_mount_identity() {
        // Authored nearest-src contract, shared by live and selected inputs.
        for (path, package, root) in [
            (
                "src/vendor/src/unit.rs",
                vec!["src", "vendor", "src", "unit"],
                vec!["src", "vendor", "src"],
            ),
            (
                "vendor/src/inner/src/lib.rs",
                vec!["vendor", "src", "inner", "src"],
                vec!["vendor", "src", "inner", "src"],
            ),
            ("src/unit.rs", vec!["unit"], vec![]),
        ] {
            let fixture = tempfile::tempdir().unwrap();
            let file = ProjectFile::new(fixture.path(), path);
            assert_eq!(
                path_derived_package_components(Path::new(path)),
                package,
                "{path}"
            );
            assert_eq!(
                path_derived_crate_root_components(Path::new(path)),
                root,
                "{path}"
            );
            let selected =
                RustSelectedCargoNaming::from_selected_inputs([PathBuf::from(path)], &[]).unwrap();
            let name = selected
                .resolve_package_anchor(PackageAnchor::OwnModule { pop: 0 }, "", Path::new(path))
                .unwrap();
            assert_eq!(
                name.resolved_segments()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
                package
            );
            assert_eq!(
                crate::declarations::rust_file_package_fq(&file)
                    .resolved_segments()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
                package
            );
        }
    }
}
