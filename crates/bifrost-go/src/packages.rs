//! Canonical Go package identity.
//!
//! A Go symbol's machine identity must be its *import path*, not the bare
//! `package` clause. Three directories that all declare `package list` are
//! distinct packages (`.../discussion/list`, `.../issue/list`,
//! `.../pr/list`); collapsing them to `list` makes `list.TestListRun`
//! ambiguous before any lookup happens. This module derives the import path
//! from the nearest `go.mod` (falling back to directory layout when no module
//! is present) so that `CodeUnit::fq_name()` is unique per declaration.

use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use crate::declarations::go_package_fq;

/// Synthetic scope segment owning a Go package's module-level `var`, `const`
/// and type-alias declarations, which have no enclosing type of their own.
pub const GO_MODULE_SCOPE_SEGMENT: &str = "_module_";

/// Whether this field's package-less short name starts with the synthetic
/// module-scope segment used for top-level Go values.
pub fn is_go_module_field(unit: &CodeUnit) -> bool {
    unit.is_field()
        && unit
            .short_name()
            .split('.')
            .next()
            .is_some_and(|segment| segment == GO_MODULE_SCOPE_SEGMENT)
}

pub struct GoModuleRoot {
    pub import_path: String,
    /// Workspace-relative directory; empty for the module at the project root.
    pub workspace_dir: PathBuf,
}

pub struct GoWorkspacePathIndex {
    module_roots: Vec<GoModuleRoot>,
    unnamed_module_roots: Vec<PathBuf>,
    representative_by_directory: HashMap<PathBuf, ProjectFile>,
    exact_import_paths: HashSet<String>,
    complete: bool,
}

impl GoWorkspacePathIndex {
    /// Complete path authority, excluding source positions and host mounts.
    pub fn read_answer(&self) -> [u8; 32] {
        use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
        use brokk_bifrost_core::path_utils::{rel_path_string, workspace_relative_slash_path};
        let mut hash = CanonicalHasher::new(b"go-workspace-paths-v1");
        hash.value(&[u8::from(self.complete)]);
        for root in &self.module_roots {
            hash.value(root.import_path.as_bytes());
            hash.value(workspace_relative_slash_path(&root.workspace_dir).as_bytes());
        }
        hash.sequence("unnamed", &self.unnamed_module_roots, |hash, root| {
            hash.value(workspace_relative_slash_path(root).as_bytes())
        });
        let mut paths = self.exact_import_paths.iter().collect::<Vec<_>>();
        paths.sort();
        hash.sequence("packages", &paths, |hash, path| hash.value(path.as_bytes()));
        let mut representatives = self
            .representative_by_directory
            .iter()
            .map(|(dir, file)| (workspace_relative_slash_path(dir), rel_path_string(file)))
            .collect::<Vec<_>>();
        representatives.sort();
        hash.sequence("representatives", &representatives, |hash, (dir, file)| {
            hash.value(dir.as_bytes());
            hash.value(file.as_bytes());
        });
        hash.finish()
    }

    /// `refused_sources` are the sources that source admission refused at the
    /// selected revision. They supply no `package` clause and no facts, but
    /// they are explained exclusions rather than missing inventory.
    pub fn build(
        project: &dyn Project,
        mut declared_package: impl FnMut(&ProjectFile) -> Option<String>,
        refused_sources: &HashSet<ProjectFile>,
    ) -> Self {
        let (files, complete) = match project.all_files() {
            Ok(files) => (files, true),
            Err(_) => (Default::default(), false),
        };
        let (module_roots, unnamed_module_roots, module_roots_complete) =
            go_module_roots_from_files(project, &files);
        let mut go_files = files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .is_some_and(|extension| extension == "go")
            })
            .filter(|file| !is_under_unnamed_module(file, &unnamed_module_roots, &module_roots))
            .collect::<Vec<_>>();
        go_files.sort();
        let mut representative_by_directory: HashMap<PathBuf, ProjectFile> = HashMap::default();
        for file in go_files
            .iter()
            .filter(|file| !refused_sources.contains(*file))
        {
            representative_by_directory
                .entry(file.parent())
                .and_modify(|representative| {
                    if is_go_test_file(representative) && !is_go_test_file(file) {
                        *representative = file.clone();
                    }
                })
                .or_insert_with(|| file.clone());
        }
        let mut index = Self {
            module_roots,
            unnamed_module_roots,
            representative_by_directory,
            exact_import_paths: HashSet::default(),
            complete: complete && module_roots_complete,
        };
        let mut exact_import_paths = HashSet::default();
        for file in &go_files {
            let Some(declared_package) =
                declared_package(file).filter(|declared_package| !declared_package.is_empty())
            else {
                // A refused non-test source in a named module still proves
                // its directory's importable package; a refused test file
                // adds no importable package. Elsewhere the identity needs
                // the clause, so absence stays unproven.
                match refused_sources
                    .contains(file)
                    .then(|| index.module_import_path(file))
                    .flatten()
                {
                    Some(package) => {
                        if !is_go_test_file(file) {
                            exact_import_paths.insert(package);
                        }
                    }
                    None => index.complete = false,
                }
                continue;
            };
            let canonical = index.canonical_package_name(file, &declared_package);
            let canonical_fq = go_package_fq(&canonical);
            if let Some(alias) = go_vendor_package_alias(file, &canonical_fq) {
                exact_import_paths.insert(alias.display(segment_interner()));
            }
            exact_import_paths.insert(canonical);
        }
        index.exact_import_paths = exact_import_paths;
        index
    }

    /// Whether every input needed to enumerate exact workspace import paths
    /// was available: the whole-workspace file listing succeeded, every listed
    /// `go.mod` was readable and lexically valid, each named module's decoded
    /// path satisfies Go's module-path element restrictions, and every Go file
    /// inside a named module supplied a nonempty parsed `package` clause or
    /// was refused by source admission.
    /// A valid manifest without a module directive is an unnamed module
    /// boundary, so its files are excluded from the package inventory. Other
    /// go.mod directives are not semantically validated. When this is false,
    /// positive lookup evidence remains usable, but a missing package is not
    /// proof that the package is absent.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn import_files(&self, source_file: &ProjectFile, import_path: &str) -> Vec<ProjectFile> {
        if self.is_outside_selected_modules(source_file) {
            return Vec::new();
        }
        let import_path = import_path.trim().trim_matches('/');
        if import_path.is_empty() {
            return Vec::new();
        }
        if let Some(relative) = import_path.strip_prefix("./") {
            return self
                .representative_by_directory
                .get(&source_file.parent().join(relative))
                .cloned()
                .into_iter()
                .collect();
        }

        // The nearest vendor package shadows both ancestor vendor copies and
        // workspace modules with the same import path.
        let mut cursor = Some(source_file.parent());
        while let Some(directory) = cursor {
            let vendored = directory.join("vendor").join(import_path);
            if let Some(file) = self.representative_by_directory.get(&vendored) {
                return vec![file.clone()];
            }
            cursor = directory.parent().map(Path::to_path_buf);
        }

        let mut module_files = self
            .module_roots
            .iter()
            .filter_map(|module| {
                let relative = module_relative_import(&module.import_path, import_path)?;
                self.representative_by_directory
                    .get(&module.workspace_dir.join(relative))
                    .cloned()
            })
            .collect::<Vec<_>>();
        module_files.sort();
        module_files.dedup();
        if !module_files.is_empty() {
            return module_files;
        }

        self.module_roots
            .is_empty()
            .then(|| {
                self.representative_by_directory
                    .get(Path::new(import_path))
                    .cloned()
            })
            .flatten()
            .into_iter()
            .collect()
    }

    pub fn exact_package_exists(&self, import_path: &str) -> bool {
        self.exact_import_paths
            .contains(import_path.trim_matches('/'))
    }

    /// Canonical package identity using the module roots already indexed for
    /// this workspace. Unlike [`canonical_go_package_name`], this performs no
    /// ancestor filesystem walk and no repeated `go.mod` reads.
    pub fn canonical_package_name(&self, file: &ProjectFile, declared_package: &str) -> String {
        if self.is_outside_selected_modules(file) {
            return no_module_base(file, declared_package);
        }
        let (declared_base, is_external_test) = declared_package_parts(file, declared_package);
        let base = self
            .module_import_path(file)
            .unwrap_or_else(|| no_module_base(file, declared_base));
        external_test_package_name(base, is_external_test)
    }

    /// The import path of the file's directory under its nearest named
    /// module, which needs no `package` clause.
    fn module_import_path(&self, file: &ProjectFile) -> Option<String> {
        if self.is_outside_selected_modules(file) {
            return None;
        }
        let file_dir = file.parent();
        self.module_roots
            .iter()
            .filter(|module| file_dir.starts_with(&module.workspace_dir))
            .max_by_key(|module| module.workspace_dir.components().count())
            .and_then(|module| {
                let relative = file_dir.strip_prefix(&module.workspace_dir).ok()?;
                Some(join_import_path(
                    &module.import_path,
                    &relative.to_string_lossy().replace('\\', "/"),
                ))
            })
    }

    /// Whether two source files belong to the same nearest Go module. When
    /// neither file is under an indexed module, the workspace root is the
    /// module-local boundary; a file inside a module never joins that fallback.
    pub fn same_module(&self, left: &ProjectFile, right: &ProjectFile) -> bool {
        let nearest_module = |file: &ProjectFile| {
            let named = self
                .module_roots
                .iter()
                .filter(|module| file.parent().starts_with(&module.workspace_dir))
                .max_by_key(|module| module.workspace_dir.components().count());
            let unnamed = self
                .unnamed_module_roots
                .iter()
                .filter(|directory| file.parent().starts_with(directory.as_path()))
                .max_by_key(|directory| directory.components().count());
            match (named, unnamed) {
                (Some(named), Some(unnamed))
                    if unnamed.components().count() >= named.workspace_dir.components().count() =>
                {
                    Some((false, unnamed.as_path()))
                }
                (Some(named), _) => Some((true, named.workspace_dir.as_path())),
                (None, Some(unnamed)) => Some((false, unnamed.as_path())),
                (None, None) => None,
            }
        };
        match (nearest_module(left), nearest_module(right)) {
            (Some(left), Some(right)) => left == right,
            (None, None) => left.root() == right.root(),
            _ => false,
        }
    }

    /// Whether a Go file falls under a nearer unnamed module boundary and is
    /// therefore outside every import-path-bearing module in this workspace.
    pub fn is_outside_selected_modules(&self, file: &ProjectFile) -> bool {
        self.unnamed_module_root(file).is_some()
    }

    /// The nearest unnamed module boundary containing this file, if any.
    pub fn unnamed_module_root(&self, file: &ProjectFile) -> Option<&Path> {
        nearest_unnamed_module_root(file, &self.unnamed_module_roots, &self.module_roots)
    }
}

fn is_under_unnamed_module(
    file: &ProjectFile,
    unnamed_roots: &[PathBuf],
    named_roots: &[GoModuleRoot],
) -> bool {
    nearest_unnamed_module_root(file, unnamed_roots, named_roots).is_some()
}

fn nearest_unnamed_module_root<'a>(
    file: &ProjectFile,
    unnamed_roots: &'a [PathBuf],
    named_roots: &[GoModuleRoot],
) -> Option<&'a Path> {
    let file_dir = file.parent();
    let nearest_unnamed = unnamed_roots
        .iter()
        .filter(|directory| file_dir.starts_with(directory.as_path()))
        .max_by_key(|directory| directory.components().count());
    let nearest_named = named_roots
        .iter()
        .filter(|module| file_dir.starts_with(&module.workspace_dir))
        .max_by_key(|module| module.workspace_dir.components().count());
    nearest_unnamed
        .filter(|unnamed| {
            nearest_named.is_none_or(|named| {
                unnamed.components().count() >= named.workspace_dir.components().count()
            })
        })
        .map(PathBuf::as_path)
}

/// Source-inventory role from the selected path and declared package clause.
/// This does not claim tool-selected build or synthetic test-variant admission.
pub fn source_inventory_role(file: &ProjectFile, declared_package: &str) -> &'static str {
    if declared_package_parts(file, declared_package).1 {
        "xtest"
    } else if is_go_test_file(file) {
        "test"
    } else {
        "go"
    }
}

/// Whether a source filename or parsed leading comment excludes package
/// inventory from Go-tool-independent completion.
pub fn source_file_has_build_constraints(file: &ProjectFile, has_build_directive: bool) -> bool {
    source_path_has_build_constraints(file.rel_path(), has_build_directive)
}

/// Build constraints carried by a source-relative path or extracted directive.
pub fn source_path_has_build_constraints(path: &Path, has_build_directive: bool) -> bool {
    let (goos, goarch) = source_filename_target(path);
    has_build_directive || goos.is_some() || goarch.is_some()
}

/// Filename-only build selection. Directive evaluation requires Go-tool evidence.
pub fn source_filename_matches_target(file: &ProjectFile, goos: &str, goarch: &str) -> bool {
    let (file_os, file_arch) = source_filename_target(file.rel_path());
    file_os.is_none_or(|os| {
        os == goos
            || matches!(
                (goos, os),
                ("android", "linux") | ("illumos", "solaris") | ("ios", "darwin")
            )
    }) && file_arch.is_none_or(|arch| arch == goarch)
}

fn source_filename_target(path: &Path) -> (Option<&str>, Option<&str>) {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return (None, None);
    };
    let stem = stem.strip_suffix("_test").unwrap_or(stem);
    const GOOS: &[&str] = &[
        "aix",
        "android",
        "darwin",
        "dragonfly",
        "freebsd",
        "illumos",
        "ios",
        "js",
        "linux",
        "netbsd",
        "openbsd",
        "plan9",
        "solaris",
        "wasip1",
        "windows",
        "zos",
    ];
    const GOARCH: &[&str] = &[
        "386",
        "amd64",
        "amd64p32",
        "arm",
        "armbe",
        "arm64",
        "arm64be",
        "loong64",
        "mips",
        "mipsle",
        "mips64",
        "mips64le",
        "mips64p32",
        "mips64p32le",
        "ppc",
        "ppc64",
        "ppc64le",
        "riscv",
        "riscv64",
        "s390",
        "s390x",
        "sparc",
        "sparc64",
        "wasm",
    ];
    let Some((prefix, suffix)) = stem.rsplit_once('_') else {
        return (None, None);
    };
    if GOARCH.contains(&suffix) {
        let os = prefix
            .rsplit_once('_')
            .map(|(_, os)| os)
            .filter(|os| GOOS.contains(os));
        (os, Some(suffix))
    } else {
        (GOOS.contains(&suffix).then_some(suffix), None)
    }
}

fn is_go_test_file(file: &ProjectFile) -> bool {
    file.rel_path()
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"))
}

fn module_relative_import<'a>(module: &str, import_path: &'a str) -> Option<&'a str> {
    if import_path == module {
        Some("")
    } else {
        import_path
            .strip_prefix(module)
            .and_then(|suffix| suffix.strip_prefix('/'))
    }
}

pub fn go_module_roots(project: &dyn Project) -> Vec<GoModuleRoot> {
    let files = project.all_files().unwrap_or_default();
    go_module_roots_from_files(project, &files).0
}

fn go_module_roots_from_files<'a>(
    project: &dyn Project,
    files: impl IntoIterator<Item = &'a ProjectFile>,
) -> (Vec<GoModuleRoot>, Vec<PathBuf>, bool) {
    let mut complete = true;
    let mut module_roots = Vec::new();
    let mut unnamed_module_roots = Vec::new();
    for manifest in files.into_iter().filter(|file| {
        file.rel_path()
            .file_name()
            .is_some_and(|name| name == "go.mod")
    }) {
        let Ok(contents) = project.read_source(manifest) else {
            complete = false;
            continue;
        };
        match parse_go_module_manifest(&contents) {
            Some(Some(import_path)) => module_roots.push(GoModuleRoot {
                import_path,
                workspace_dir: manifest.parent(),
            }),
            Some(None) => unnamed_module_roots.push(manifest.parent()),
            None => complete = false,
        }
    }
    module_roots.sort_by(|left, right| {
        right
            .import_path
            .len()
            .cmp(&left.import_path.len())
            .then_with(|| left.workspace_dir.cmp(&right.workspace_dir))
    });
    unnamed_module_roots.sort();
    (module_roots, unnamed_module_roots, complete)
}

/// Canonical Go package identity (import path) for `file`, given the
/// `declared_package` from its `package` clause.
///
/// External test packages (`package foo_test` in a `*_test.go` file) live in
/// the same directory as the package under test but form their own import path,
/// so the canonical name keeps the `_test` suffix on top of the directory's
/// import path. A non-test file is part of the directory package even when its
/// declaration happens to end in `_test`.
pub fn canonical_go_package_name(file: &ProjectFile, declared_package: &str) -> String {
    let (declared_base, is_external_test) = declared_package_parts(file, declared_package);

    let base = match nearest_go_module(file) {
        Some((module_path, rel_dir)) => join_import_path(&module_path, &rel_dir),
        None => no_module_base(file, declared_base),
    };

    external_test_package_name(base, is_external_test)
}

/// Canonical package identity for publication into the workspace package
/// inventory.
///
/// Unlike [`canonical_go_package_name`], this refuses to publish an identity
/// when a nearest `go.mod` exists but cannot be read or its lexical scan does
/// not produce exactly one top-level module directive with a valid decoded
/// module path. Treating that case as a module-less workspace would make an
/// exact miss under the real import path look authoritative.
pub fn canonical_go_workspace_package_name(
    file: &ProjectFile,
    declared_package: &str,
) -> Option<String> {
    let (declared_base, is_external_test) = declared_package_parts(file, declared_package);
    let base = match nearest_go_module_lookup(file)? {
        GoModuleLookup::Found((module_path, rel_dir)) => join_import_path(&module_path, &rel_dir),
        GoModuleLookup::Missing => no_module_base(file, declared_base),
        GoModuleLookup::Invalid => return None,
    };
    Some(external_test_package_name(base, is_external_test))
}

fn external_test_package_name(base: String, is_external_test: bool) -> String {
    if is_external_test {
        format!("{base}_test")
    } else {
        base
    }
}

fn declared_package_parts<'a>(file: &ProjectFile, declared_package: &'a str) -> (&'a str, bool) {
    match declared_package
        .strip_suffix("_test")
        .filter(|_| is_go_test_file(file))
    {
        Some(stripped) if !stripped.is_empty() => (stripped, true),
        _ => (declared_package, false),
    }
}

/// Import-path alias contributed by a package below the last real `vendor`
/// directory in `file`'s workspace-relative path.
///
/// The canonical identity keeps the workspace/module prefix and `vendor`
/// segment so declarations remain globally unique. Go source imports only the
/// suffix after `vendor`, however. Count that suffix from structured path
/// components and project the same number of structured canonical segments;
/// never recover it by splitting a rendered qualified name.
pub fn go_vendor_package_alias(file: &ProjectFile, canonical: &FqName) -> Option<FqName> {
    let directory_components = file
        .rel_path()
        .parent()?
        .components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => None,
        })
        .collect::<Vec<_>>();
    let vendor = directory_components
        .iter()
        .rposition(|component| *component == "vendor")?;
    let suffix_len = directory_components.len().saturating_sub(vendor + 1);
    if suffix_len == 0 || canonical.len() < suffix_len {
        return None;
    }
    let alias = canonical.suffix_from(canonical.len() - suffix_len);
    let interner = segment_interner();
    alias
        .segments()
        .iter()
        .all(|segment| interner.resolve(*segment).1 == SegmentKind::Path)
        .then_some(alias)
}

pub fn go_internal_import_allowed(importer: &str, imported: &str) -> bool {
    let imported_segments = imported.split('/').collect::<Vec<_>>();
    let internal_indices = imported_segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| (*segment == "internal").then_some(index));
    for internal_index in internal_indices {
        if internal_index == 0 {
            return false;
        }
        let parent = imported_segments[..internal_index].join("/");
        if importer != parent
            && !importer
                .strip_prefix(&parent)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return false;
        }
    }
    true
}

/// Walk from `file`'s directory up to the project root, returning the module
/// path and the file directory's path relative to the nearest `go.mod`.
fn nearest_go_module(file: &ProjectFile) -> Option<(String, String)> {
    match nearest_go_module_lookup(file)? {
        GoModuleLookup::Found(module) => Some(module),
        GoModuleLookup::Missing | GoModuleLookup::Invalid => None,
    }
}

fn nearest_go_module_lookup(file: &ProjectFile) -> Option<GoModuleLookup<(String, String)>> {
    let root = file.root();
    let abs = file.abs_path();
    let file_dir = abs.parent()?;
    Some(match nearest_go_module_anchor(file_dir, root) {
        GoModuleLookup::Found((anchor, module_path)) => {
            let rel_dir = file_dir
                .strip_prefix(&anchor)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            GoModuleLookup::Found((module_path, rel_dir))
        }
        GoModuleLookup::Missing => GoModuleLookup::Missing,
        GoModuleLookup::Invalid => GoModuleLookup::Invalid,
    })
}

type GoModuleAnchor = (PathBuf, String);
type GoModuleCacheKey = (PathBuf, PathBuf);
type GoModuleCacheEntry = (GoModuleLookup<GoModuleAnchor>, GoModuleInputs);

/// Shared original probes with the starting point for one directory's answer.
#[derive(Clone)]
pub struct GoModuleInputs {
    inputs: std::sync::Arc<[GoModuleInput]>,
    offset: usize,
}

impl std::ops::Deref for GoModuleInputs {
    type Target = [GoModuleInput];

    fn deref(&self) -> &Self::Target {
        &self.inputs[self.offset..]
    }
}

/// The exact non-source probes behind a cached nearest-module answer.
#[derive(Clone, Debug)]
pub enum GoModuleInput {
    File {
        rel_path: String,
        blob: [u8; 20],
        content_digest: [u8; 32],
    },
    PathAbsent {
        rel_path: String,
    },
    Unavailable,
}

/// Replays the receipt, including negative probes, while the entry is resident.
/// An evicted entry is re-probed from disk and its newly computed receipt is
/// checked against the generation's file hashes in the same way. The analyzer
/// records it on every file-identity read, including warm hydration.
pub fn nearest_go_module_inputs(file: &ProjectFile) -> GoModuleInputs {
    let Some(dir) = file.abs_path().parent().map(Path::to_path_buf) else {
        return GoModuleInputs {
            inputs: std::sync::Arc::from([GoModuleInput::Unavailable]),
            offset: 0,
        };
    };
    nearest_go_module_entry(&dir, file.root()).1
}

#[derive(Clone)]
enum GoModuleLookup<T> {
    Found(T),
    Missing,
    Invalid,
}

// A byte budget, so that retained directory chains cannot grow with the
// workspace. Eviction is cheap: re-walking one chain costs a few go.mod probes,
// and the new receipt is recomputed with its answer. 8 MiB is within the range
// of the workspace's other weighed caches.
const NEAREST_GO_MODULE_CACHE_BYTES: u64 = 8 * 1024 * 1024;

fn nearest_go_module_cache() -> &'static Cache<GoModuleCacheKey, GoModuleCacheEntry> {
    static CACHE: LazyLock<Cache<GoModuleCacheKey, GoModuleCacheEntry>> = LazyLock::new(|| {
        build_weighted_cache(
            NEAREST_GO_MODULE_CACHE_BYTES,
            |key: &GoModuleCacheKey, entry: &GoModuleCacheEntry| {
                let mut bytes = 256usize
                    .saturating_add(key.0.to_string_lossy().len())
                    .saturating_add(key.1.to_string_lossy().len());
                if let GoModuleLookup::Found((anchor, module_path)) = &entry.0 {
                    bytes = bytes
                        .saturating_add(anchor.to_string_lossy().len())
                        .saturating_add(module_path.len());
                }
                // Charge the full shared allocation for every entry, even
                // when this directory's receipt starts at a later offset.
                bytes = entry.1.inputs.iter().fold(bytes, |bytes, input| {
                    bytes.saturating_add(match input {
                        GoModuleInput::File { rel_path, .. }
                        | GoModuleInput::PathAbsent { rel_path } => {
                            64usize.saturating_add(rel_path.len())
                        }
                        GoModuleInput::Unavailable => 64,
                    })
                });
                bytes.min(u32::MAX as usize) as u32
            },
        )
    });
    &CACHE
}

/// Clear cached nearest-module answers after the workspace file set changes.
pub fn invalidate_nearest_go_module_cache() {
    nearest_go_module_cache().invalidate_all();
}

#[cfg(test)]
fn go_mod_probe_attempts() -> &'static Mutex<HashMap<PathBuf, usize>> {
    static ATTEMPTS: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    ATTEMPTS.get_or_init(|| Mutex::new(HashMap::default()))
}

fn nearest_go_module_anchor(dir: &Path, root: &Path) -> GoModuleLookup<GoModuleAnchor> {
    nearest_go_module_entry(dir, root).0
}

fn nearest_go_module_entry(dir: &Path, root: &Path) -> GoModuleCacheEntry {
    let cache = nearest_go_module_cache();
    let mut visited = Vec::new();
    let mut inputs = Vec::new();
    let mut cursor = dir;
    let result = loop {
        let key = (root.to_path_buf(), cursor.to_path_buf());
        if let Some(cached) = cache.get(&key) {
            if visited.is_empty() {
                return cached;
            }
            inputs.extend(cached.1.iter().cloned());
            break cached.0;
        }
        visited.push((key, inputs.len()));
        #[cfg(test)]
        {
            *go_mod_probe_attempts()
                .lock()
                .expect("go module probe count mutex")
                .entry(root.to_path_buf())
                .or_default() += 1;
        }
        let path = cursor.join("go.mod");
        let rel_path = match path.strip_prefix(root) {
            Ok(path) => brokk_bifrost_core::path_utils::workspace_relative_slash_path(path),
            Err(_) => {
                inputs.push(GoModuleInput::Unavailable);
                break GoModuleLookup::Invalid;
            }
        };
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let snapshot = brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot::disk(
                    contents.as_str(),
                );
                inputs.push(GoModuleInput::File {
                    content_digest: brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                        contents.as_bytes(),
                    ),
                    rel_path,
                    blob: snapshot.oid().as_bytes().try_into().expect("blob width"),
                });
                break match go_module_path_from_source(&contents) {
                    Some(module_path) => GoModuleLookup::Found((cursor.to_path_buf(), module_path)),
                    None => GoModuleLookup::Invalid,
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                inputs.push(GoModuleInput::PathAbsent { rel_path })
            }
            Err(_) => {
                inputs.push(GoModuleInput::Unavailable);
                break GoModuleLookup::Invalid;
            }
        }
        if cursor == root {
            break GoModuleLookup::Missing;
        }
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break GoModuleLookup::Missing,
        }
    };
    let inputs: std::sync::Arc<[GoModuleInput]> = inputs.into();
    if !visited.is_empty() {
        for (key, offset) in visited {
            cache.insert(
                key,
                (
                    result.clone(),
                    GoModuleInputs {
                        inputs: Arc::clone(&inputs),
                        offset,
                    },
                ),
            );
        }
    }
    (result, GoModuleInputs { inputs, offset: 0 })
}

/// Import path with no `go.mod`: the project-relative parent directory, or the
/// declared package name for files sitting at the project root. This preserves
/// the historical `package.Symbol` shape for flat, module-less fixtures.
fn no_module_base(file: &ProjectFile, declared_base: &str) -> String {
    let parent = file.parent().to_string_lossy().replace('\\', "/");
    let parent = parent.trim_matches('/');
    if parent.is_empty() {
        declared_base.to_string()
    } else {
        parent.to_string()
    }
}

fn join_import_path(module_path: &str, rel_dir: &str) -> String {
    let module_path = module_path.trim_matches('/');
    let rel_dir = rel_dir.trim_matches('/');
    if rel_dir.is_empty() {
        module_path.to_string()
    } else {
        format!("{module_path}/{rel_dir}")
    }
}

/// Read the `module` path from the `go.mod` in `dir`, if present.
///
/// Invariant: the returned path (like [`go_module_path_from_source`]'s) is a
/// single clean token -- no embedded whitespace, no `//` comment text, no
/// surrounding quotes. Callers may join it with `/`-separated path segments
/// without re-normalizing.
pub fn read_go_module_path(dir: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(dir.join("go.mod")).ok()?;
    go_module_path_from_source(&contents)
}

/// Extract the `module` directive's path from `go.mod` source.
///
/// This is deliberately a conservative recognizer, not a claim that the whole
/// `go.mod` is valid. It accepts exactly one top-level `module` directive in
/// either the direct or parenthesized grammar form. Identifiers and interpreted
/// strings are decoded according to the go.mod lexical rules; raw backtick
/// strings are rejected. Decoded paths are checked against the module-path
/// element restrictions. Other directives may surround the module directive,
/// including blocks. Malformed lexical
/// input, duplicate directives, extra module arguments, or invalid module paths
/// return `None`, making workspace authority incomplete rather than publishing
/// a guessed identity.
pub fn go_module_path_from_source(contents: &str) -> Option<String> {
    parse_go_module_manifest(contents).flatten()
}

/// `Some(None)` is a lexically valid go.mod with no module directive. Go
/// still treats that file as a module boundary, but it has no import path.
pub(crate) fn parse_go_module_manifest(contents: &str) -> Option<Option<String>> {
    let tokens = go_mod_tokens(contents)?;
    let mut module_path = None;
    let mut cursor = 0;
    let mut other_block_depth = 0;
    while cursor < tokens.len() {
        let line = next_go_mod_line(&tokens, &mut cursor);
        if line.is_empty() {
            continue;
        }
        if other_block_depth > 0 {
            update_go_mod_block_depth(line, &mut other_block_depth);
            continue;
        }
        if !matches!(line.first(), Some(GoModToken::Identifier(keyword)) if keyword == "module") {
            update_go_mod_block_depth(line, &mut other_block_depth);
            continue;
        }
        if module_path.is_some() || line.len() != 2 {
            return None;
        }
        if matches!(line.get(1), Some(GoModToken::LeftParen)) {
            let path_line = next_go_mod_line(&tokens, &mut cursor);
            let close_line = next_go_mod_line(&tokens, &mut cursor);
            if path_line.len() != 1 || close_line != [GoModToken::RightParen] {
                return None;
            }
            module_path = Some(go_module_path_token(&path_line[0])?.to_owned());
        } else {
            module_path = Some(go_module_path_token(&line[1])?.to_owned());
        }
    }
    match module_path {
        Some(path) if valid_go_module_path(&path) => Some(Some(path)),
        Some(_) => None,
        None => Some(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoModToken {
    Identifier(String),
    String(String),
    LeftParen,
    RightParen,
    Newline,
}

fn go_mod_tokens(contents: &str) -> Option<Vec<GoModToken>> {
    let limits = crate::build_files::BuildFileLimits {
        max_bytes: usize::MAX,
        max_tokens: usize::MAX,
        max_entries: usize::MAX,
    };
    crate::build_files::lex(contents, &limits, &|| false)
        .ok()
        .map(|tokens| tokens.into_iter().map(|token| token.kind).collect())
}

fn next_go_mod_line<'a>(tokens: &'a [GoModToken], cursor: &mut usize) -> &'a [GoModToken] {
    let start = *cursor;
    while *cursor < tokens.len() && !matches!(tokens[*cursor], GoModToken::Newline) {
        *cursor += 1;
    }
    let line = &tokens[start..*cursor];
    if *cursor < tokens.len() {
        *cursor += 1;
    }
    line
}

fn update_go_mod_block_depth(line: &[GoModToken], block_depth: &mut usize) {
    for token in line {
        match token {
            GoModToken::LeftParen => *block_depth += 1,
            GoModToken::RightParen => *block_depth = (*block_depth).saturating_sub(1),
            GoModToken::Identifier(_) | GoModToken::String(_) | GoModToken::Newline => {}
        }
    }
}

fn go_module_path_token(token: &GoModToken) -> Option<&str> {
    match token {
        GoModToken::Identifier(value) | GoModToken::String(value) => Some(value),
        GoModToken::LeftParen | GoModToken::RightParen | GoModToken::Newline => None,
    }
}

pub(crate) fn valid_go_module_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return false;
    }
    let mut segment_start = 0;
    for (offset, character) in path.char_indices() {
        if character == '/' {
            let segment = &path[segment_start..offset];
            if !valid_go_module_path_element(segment) {
                return false;
            }
            segment_start = offset + character.len_utf8();
        } else if !(character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~'))
        {
            return false;
        }
    }
    valid_go_module_path_element(&path[segment_start..])
}

fn valid_go_module_path_element(element: &str) -> bool {
    if element.is_empty() || element.starts_with('.') || element.ends_with('.') {
        return false;
    }
    let prefix = element
        .char_indices()
        .find_map(|(offset, character)| (character == '.').then_some(&element[..offset]))
        .unwrap_or(element);
    if is_windows_reserved_name(prefix) {
        return false;
    }
    let bytes = prefix.as_bytes();
    let mut digit_start = bytes.len();
    while digit_start > 0 && bytes[digit_start - 1].is_ascii_digit() {
        digit_start -= 1;
    }
    digit_start == bytes.len() || digit_start == 0 || bytes[digit_start - 1] != b'~'
}

fn is_windows_reserved_name(prefix: &str) -> bool {
    if ["con", "prn", "aux", "nul"]
        .iter()
        .any(|reserved| prefix.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let bytes = prefix.as_bytes();
    bytes.len() == 4
        && (prefix[..3].eq_ignore_ascii_case("com") || prefix[..3].eq_ignore_ascii_case("lpt"))
        && matches!(bytes[3], b'1'..=b'9')
}

#[cfg(test)]
mod tests {
    use super::{
        GoWorkspacePathIndex, canonical_go_package_name, canonical_go_workspace_package_name,
        go_mod_probe_attempts, go_module_path_from_source, go_vendor_package_alias,
        invalidate_nearest_go_module_cache, source_file_has_build_constraints,
    };
    use crate::declarations::go_package_fq;
    use brokk_bifrost_core::analyzer::fq_name::segment_interner;
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use brokk_bifrost_core::analyzer::{Language, ProjectFile};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::Mutex;

    static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn source_inventory_build_constraints_cover_goos_and_goarch_suffixes() {
        let root = std::env::current_dir().expect("test working directory must be available");
        for path in [
            "pkg/files_linux.go",
            "pkg/files_arm64.go",
            "pkg/files_linux_arm64.go",
            "pkg/files_linux_test.go",
        ] {
            assert!(source_file_has_build_constraints(
                &ProjectFile::new(root.clone(), path),
                false
            ));
        }
        for path in [
            "pkg/files_test.go",
            "pkg/linux.go",
            "pkg/files_unsupported.go",
        ] {
            assert!(!source_file_has_build_constraints(
                &ProjectFile::new(root.clone(), path),
                false
            ));
        }
        assert!(source_file_has_build_constraints(
            &ProjectFile::new(root, "pkg/files.go"),
            true
        ));
    }

    #[test]
    fn workspace_package_identity_rejects_invalid_go_mod_without_changing_legacy_fallback() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(repo.path().to_path_buf(), "pkg/file.go");

        reset_cache_probe_count(repo.path());
        assert_eq!(
            canonical_go_workspace_package_name(&file, "pkg"),
            Some("pkg".to_owned())
        );

        write_file(repo.path(), "go.mod", "go 1.26\n");
        invalidate_nearest_go_module_cache();
        assert_eq!(canonical_go_workspace_package_name(&file, "pkg"), None);
        assert_eq!(canonical_go_package_name(&file, "pkg"), "pkg");

        write_file(repo.path(), "go.mod", "module example.com/repo\n");
        invalidate_nearest_go_module_cache();
        assert_eq!(
            canonical_go_workspace_package_name(&file, "pkg"),
            Some("example.com/repo/pkg".to_owned())
        );
    }

    struct UnlistableProject {
        delegate: TestProject,
    }

    struct UnreadableManifestProject {
        delegate: TestProject,
    }

    impl Project for UnlistableProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected workspace listing failure",
            ))
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }
    }

    impl Project for UnreadableManifestProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            if file
                .rel_path()
                .file_name()
                .is_some_and(|name| name == "go.mod")
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected go.mod read failure",
                ))
            } else {
                self.delegate.read_source(file)
            }
        }
    }

    #[test]
    fn workspace_path_index_retains_file_listing_completeness() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        write_file(&root, "go.mod", "module example.com/repo\n");
        write_file(&root, "pkg/foo.go", "package pkg\n");
        let project = TestProject::new(root.clone(), Language::Go);

        let complete = GoWorkspacePathIndex::build(
            &project,
            |_| Some("pkg".to_owned()),
            &brokk_bifrost_core::hash::HashSet::default(),
        );
        assert!(complete.is_complete());
        assert!(complete.exact_package_exists("example.com/repo/pkg"));

        let incomplete = GoWorkspacePathIndex::build(
            &UnlistableProject { delegate: project },
            |_| Some("pkg".to_owned()),
            &brokk_bifrost_core::hash::HashSet::default(),
        );
        assert!(!incomplete.is_complete());
        assert!(!incomplete.exact_package_exists("example.com/repo/pkg"));
        assert!(
            incomplete
                .import_files(&ProjectFile::new(root, "main.go"), "example.com/repo/pkg")
                .is_empty()
        );
    }

    #[test]
    fn workspace_path_index_retains_manifest_read_completeness() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        write_file(&root, "go.mod", "module example.com/repo\n");
        write_file(&root, "pkg/foo.go", "package pkg\n");
        let project = TestProject::new(root, Language::Go);

        let incomplete = GoWorkspacePathIndex::build(
            &UnreadableManifestProject { delegate: project },
            |_| Some("pkg".to_owned()),
            &brokk_bifrost_core::hash::HashSet::default(),
        );
        assert!(!incomplete.is_complete());
        assert!(!incomplete.exact_package_exists("example.com/repo/pkg"));
    }

    #[test]
    fn workspace_path_index_uses_exact_canonical_and_vendor_import_paths() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        for (path, source) in [
            ("go.mod", "module example.com/repo\n"),
            ("pkg/pkg.go", "package pkg\n"),
            ("vendor/example.com/dep/pkg/pkg.go", "package pkg\n"),
            (
                "vendor/outer/vendor/nested.example/dep/pkg/pkg.go",
                "package pkg\n",
            ),
            ("myvendor/example.com/fake/pkg/pkg.go", "package pkg\n"),
            ("mixed/a_external_test.go", "package mixed_test\n"),
            ("mixed/z_internal_test.go", "package mixed\n"),
        ] {
            write_file(&root, path, source);
        }
        let project = TestProject::new(root, Language::Go);
        let index = GoWorkspacePathIndex::build(
            &project,
            |file| {
                Some(
                    match file.rel_path().file_name().and_then(|name| name.to_str()) {
                        Some("a_external_test.go") => "mixed_test",
                        Some("z_internal_test.go") => "mixed",
                        _ => "pkg",
                    }
                    .to_owned(),
                )
            },
            &brokk_bifrost_core::hash::HashSet::default(),
        );

        assert!(index.is_complete());
        for import_path in [
            "example.com/repo/pkg",
            "example.com/repo/vendor/example.com/dep/pkg",
            "example.com/dep/pkg",
            "nested.example/dep/pkg",
            "example.com/repo/myvendor/example.com/fake/pkg",
            "example.com/repo/mixed",
            "example.com/repo/mixed_test",
        ] {
            assert!(index.exact_package_exists(import_path), "{import_path}");
        }
        for import_path in [
            "example.com/repo",
            "example.com/dep",
            "nested.example/dep",
            "example.com/fake/pkg",
            "os",
        ] {
            assert!(!index.exact_package_exists(import_path), "{import_path}");
        }
    }

    #[test]
    fn only_actual_test_files_form_external_test_package_identities() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        for (path, source) in [
            ("go.mod", "module example.com/repo\n"),
            ("ordinary/ordinary.go", "package ordinary_test\n"),
            ("external/external.go", "package external\n"),
            ("external/external_test.go", "package external_test\n"),
        ] {
            write_file(&root, path, source);
        }
        let ordinary = ProjectFile::new(root.clone(), "ordinary/ordinary.go");
        let actual_test = ProjectFile::new(root.clone(), "external/external_test.go");

        assert_eq!(
            canonical_go_package_name(&ordinary, "ordinary_test"),
            "example.com/repo/ordinary"
        );
        assert_eq!(
            canonical_go_package_name(&actual_test, "external_test"),
            "example.com/repo/external_test"
        );
        assert_eq!(
            canonical_go_workspace_package_name(&ordinary, "ordinary_test"),
            Some("example.com/repo/ordinary".to_owned())
        );
        assert_eq!(
            canonical_go_workspace_package_name(&actual_test, "external_test"),
            Some("example.com/repo/external_test".to_owned())
        );

        let project = TestProject::new(root, Language::Go);
        let index = GoWorkspacePathIndex::build(
            &project,
            |file| {
                Some(
                    match file.rel_path().file_name().and_then(|name| name.to_str()) {
                        Some("ordinary.go") => "ordinary_test",
                        Some("external_test.go") => "external_test",
                        _ => "external",
                    }
                    .to_owned(),
                )
            },
            &brokk_bifrost_core::hash::HashSet::default(),
        );
        assert_eq!(
            index.canonical_package_name(&ordinary, "ordinary_test"),
            "example.com/repo/ordinary"
        );
        assert_eq!(
            index.canonical_package_name(&actual_test, "external_test"),
            "example.com/repo/external_test"
        );
        assert!(index.exact_package_exists("example.com/repo/ordinary"));
        assert!(index.exact_package_exists("example.com/repo/external"));
        assert!(index.exact_package_exists("example.com/repo/external_test"));
    }

    #[test]
    #[hardwon("#2445: nearest-module receipts copied every probe suffix in a directory walk")]
    fn nearest_module_probe_receipts_share_the_walk_allocation() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap();
        let repo = tempfile::tempdir().unwrap();
        reset_cache_probe_count(repo.path());
        write_file(repo.path(), "go.mod", "module example.com/repo\n");
        write_file(repo.path(), "a/b/file.go", "package b\n");
        let file = ProjectFile::new(repo.path().to_path_buf(), "a/b/file.go");
        let receipt = super::nearest_go_module_inputs(&file);
        assert_eq!(receipt.len(), 3);
        {
            let cache = super::nearest_go_module_cache();
            for (dir, offset) in [("a/b", 0), ("a", 1), ("", 2)] {
                let entry = cache
                    .get(&(repo.path().to_path_buf(), repo.path().join(dir)))
                    .unwrap();
                assert!(std::sync::Arc::ptr_eq(&receipt.inputs, &entry.1.inputs));
                assert_eq!(entry.1.offset, offset);
                assert_eq!(entry.1.len(), 3 - offset);
            }
        }
        let warm = super::nearest_go_module_inputs(&ProjectFile::new(
            repo.path().to_path_buf(),
            "a/file.go",
        ));
        assert!(std::sync::Arc::ptr_eq(&receipt.inputs, &warm.inputs));
        assert!(
            matches!(&warm[0], super::GoModuleInput::PathAbsent { rel_path } if rel_path == "a/go.mod")
        );
        assert!(
            matches!(&warm[1], super::GoModuleInput::File { rel_path, .. } if rel_path == "go.mod")
        );

        // A new sibling walk appends only the ancestor's visible suffix.
        write_file(repo.path(), "a/c/file.go", "package c\n");
        let sibling = super::nearest_go_module_inputs(&ProjectFile::new(
            repo.path().to_path_buf(),
            "a/c/file.go",
        ));
        assert_eq!(sibling.len(), 3);
        assert!(
            matches!(&sibling[0], super::GoModuleInput::PathAbsent { rel_path } if rel_path == "a/c/go.mod")
        );
        assert!(
            matches!(&sibling[1], super::GoModuleInput::PathAbsent { rel_path } if rel_path == "a/go.mod")
        );
        assert!(
            matches!(&sibling[2], super::GoModuleInput::File { rel_path, .. } if rel_path == "go.mod")
        );
        assert_eq!(go_mod_probe_attempts().lock().unwrap()[repo.path()], 4);
    }

    #[test]
    #[hardwon("3a8f1703f7ac: sibling lookups repeated the same filesystem walk")]
    fn sibling_files_reuse_the_cached_go_mod_walk() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap();
        let repo = tempfile::tempdir().unwrap();
        reset_cache_probe_count(repo.path());
        write_file(repo.path(), "go.mod", "module example.com/repo\n");

        for name in ["a.go", "b.go", "c.go"] {
            let file = ProjectFile::new(
                repo.path().to_path_buf(),
                format!("vendor/k8s.io/utils/strings/{name}"),
            );
            assert_eq!(
                canonical_go_package_name(&file, "strings"),
                "example.com/repo/vendor/k8s.io/utils/strings"
            );
        }

        assert_eq!(
            go_mod_probe_attempts()
                .lock()
                .expect("go module probe count mutex")[repo.path()],
            5
        );
    }

    #[test]
    #[hardwon("3a8f1703f7ac: edited go.mod data remained stale in the module cache")]
    fn invalidation_refreshes_an_edited_module_path() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap();
        let repo = tempfile::tempdir().unwrap();
        reset_cache_probe_count(repo.path());
        write_file(repo.path(), "go.mod", "module example.com/old\n");
        let file = ProjectFile::new(repo.path().to_path_buf(), "pkg/foo.go");

        assert_eq!(
            canonical_go_package_name(&file, "foo"),
            "example.com/old/pkg"
        );
        write_file(repo.path(), "go.mod", "module example.com/new\n");
        assert_eq!(
            canonical_go_package_name(&file, "foo"),
            "example.com/old/pkg"
        );
        invalidate_nearest_go_module_cache();
        assert_eq!(
            canonical_go_package_name(&file, "foo"),
            "example.com/new/pkg"
        );
    }

    #[test]
    #[hardwon("3a8f1703f7ac: cached module anchors crossed project roots")]
    fn cache_keeps_project_root_boundaries_distinct() {
        let _guard = CACHE_TEST_LOCK.lock().unwrap();
        let repo = tempfile::tempdir().unwrap();
        reset_cache_probe_count(repo.path());
        write_file(repo.path(), "go.mod", "module example.com/outer\n");
        let nested_root = repo.path().join("nested");
        std::fs::create_dir_all(nested_root.join("pkg")).unwrap();
        let outer_file = ProjectFile::new(repo.path().to_path_buf(), "nested/pkg/foo.go");
        let nested_file = ProjectFile::new(nested_root, "pkg/foo.go");

        assert_eq!(
            canonical_go_package_name(&outer_file, "foo"),
            "example.com/outer/nested/pkg"
        );
        assert_eq!(canonical_go_package_name(&nested_file, "foo"), "pkg");
    }

    #[test]
    #[hardwon("#2341: trailing go.mod comments, including slash text, leaked into module identity")]
    fn trailing_line_comment_is_excluded() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module example.com/repo // comment\n")
        );
        // The go2hx/go4hx go.mod line verbatim: the comment's own text
        // contains `/` characters, which must not be mistaken for part of
        // the module path.
        assert_eq!(
            Some("github.com/go2hx/go4hx".to_string()),
            go_module_path_from_source(
                "module github.com/go2hx/go4hx //not a real repo, used to set the name to go4hx\n"
            )
        );
    }

    #[test]
    fn comment_directly_abutting_the_path_with_no_space_is_excluded() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module example.com/repo//comment\n")
        );
    }

    #[test]
    fn interpreted_string_escapes_do_not_manufacture_a_module_path() {
        assert_eq!(
            None,
            go_module_path_from_source("module \"example.com/\\repo\"\n")
        );
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module \"example.com/\\x72epo\"\n")
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "a23aa6f37f80: quicksilver round 11 on brokk-bifrost-go: raw go.mod strings are invalid"
    )]
    fn raw_quoted_module_path() {
        assert_eq!(
            None,
            go_module_path_from_source("module `example.com/repo`\n")
        );
    }

    #[test]
    fn parenthesized_module_path_is_supported_at_top_level() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module ( // comment\n\texample.com/repo // comment\n)\n")
        );
    }

    #[test]
    fn module_named_dependency_inside_another_directive_block_is_not_a_directive() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("require (\n\tmodule v1.0.0\n)\nmodule example.com/repo\n")
        );
    }

    #[test]
    fn duplicate_or_extra_module_tokens_are_rejected() {
        for source in [
            "module example.com/one\nmodule example.com/two\n",
            "module example.com/repo extra\n",
            "module example.com/repo extra\nmodule example.com/other\n",
            "module \"example.com/repo\"extra\n",
        ] {
            assert_eq!(None, go_module_path_from_source(source), "{source:?}");
        }
    }

    #[test]
    fn malformed_or_invalid_module_paths_are_rejected() {
        for source in [
            "module \"example.com/repo\n",
            "module `example.com/repo\n",
            "module example.com/repo@v1\n",
            "module example.com\\repo\n",
            "module /example.com/repo\n",
            "module example.com/repo/\n",
            "module example.com/.repo\n",
            "module example.com/repo.\n",
            "module example.com/.../repo\n",
            "module example.com/../repo\n",
            "module example.com/CON.txt\n",
            "module example.com/EXAMPL~1.COM\n",
        ] {
            assert_eq!(None, go_module_path_from_source(source), "{source:?}");
        }
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn plain_module_path() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module example.com/repo\n")
        );
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn quoted_module_path() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module \"example.com/repo\"\n")
        );
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn quoted_module_path_with_trailing_comment() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module \"example.com/repo\" // comment\n")
        );
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn tab_after_module_keyword() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source("module\texample.com/repo\n")
        );
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn module_line_that_is_only_a_comment_has_no_path() {
        assert_eq!(
            None,
            go_module_path_from_source("module // just a comment, no path\n")
        );
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn empty_go_mod_has_no_path() {
        assert_eq!(None, go_module_path_from_source(""));
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn identifier_that_merely_starts_with_module_is_not_the_keyword() {
        assert_eq!(
            None,
            go_module_path_from_source("modules example.com/repo\n")
        );
    }

    #[test]
    #[hardwon(
        "93d79e79cc84: go.mod module parsing took the rest of the line instead of the module directive token"
    )]
    fn module_path_is_found_among_other_directives() {
        assert_eq!(
            Some("example.com/repo".to_string()),
            go_module_path_from_source(
                "go 1.22\n\nmodule example.com/repo\n\nrequire foo v1.0.0\n"
            )
        );
    }

    #[test]
    #[hardwon(
        "5c5d4e214494: Go vendor alias resolution selected a false nested vendor directory or suffix"
    )]
    fn vendor_alias_uses_the_last_real_vendor_directory_and_structured_suffix() {
        let root = std::env::current_dir().expect("test working directory must be available");
        for (path, canonical, expected) in [
            (
                "vendor/k8s.io/utils/strings/strings.go",
                "example.com/repo/vendor/k8s.io/utils/strings",
                Some("k8s.io/utils/strings"),
            ),
            (
                "vendor/outer/vendor/example.com/dep/pkg/pkg.go",
                "example.com/repo/vendor/outer/vendor/example.com/dep/pkg",
                Some("example.com/dep/pkg"),
            ),
            (
                "vendor/example.com/dep/pkg/pkg_test.go",
                "example.com/repo/vendor/example.com/dep/pkg_test",
                Some("example.com/dep/pkg_test"),
            ),
            ("pkg/pkg.go", "vendor/pkg", None),
        ] {
            let alias = go_vendor_package_alias(
                &ProjectFile::new(root.clone(), path),
                &go_package_fq(canonical),
            );
            assert_eq!(
                alias.map(|alias| alias.display(segment_interner())),
                expected.map(str::to_string),
                "{path}"
            );
        }
    }

    fn write_file(root: &std::path::Path, rel_path: &str, contents: &str) {
        let path = root.join(rel_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn reset_cache_probe_count(root: &Path) {
        invalidate_nearest_go_module_cache();
        go_mod_probe_attempts()
            .lock()
            .expect("go module probe count mutex")
            .remove(root);
    }

    #[test]
    #[hardwon(
        "5c5d4e214494: moduleless workspace root package identity was lost in the path index"
    )]
    fn workspace_path_index_preserves_moduleless_root_package_identity() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().canonicalize().unwrap();
        write_file(&root, "root.go", "package rootpkg\n");
        write_file(&root, "child/child.go", "package child\n");
        let project = TestProject::new(root, Language::Go);
        let index = GoWorkspacePathIndex::build(
            &project,
            |file| {
                if file.parent().as_os_str().is_empty() {
                    Some("rootpkg".to_owned())
                } else {
                    Some("child".to_owned())
                }
            },
            &brokk_bifrost_core::hash::HashSet::default(),
        );

        assert!(index.is_complete());
        assert!(index.exact_package_exists("rootpkg"));
        assert!(index.exact_package_exists("child"));
        assert!(!index.exact_package_exists("root"));
    }
}
