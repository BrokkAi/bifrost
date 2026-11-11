use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_normalization::NormalizePath;
use semver::{Version, VersionReq};
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;
use unicode_normalization::UnicodeNormalization;

/// The path facts the module-edge construction reads: whether a module
/// candidate exists, where a `#[path]` attribute leads, and a file's package
/// name. The whole index answers them from the live filesystem. A retained
/// per-unit derivation must answer them from its selection instead, because
/// nothing it read from the filesystem is recorded in its identity.
pub trait RustRoutePathFacts {
    fn file_exists(&self, file: &ProjectFile) -> bool;
    fn workspace_relative(&self, root: &Path, base: &Path, path: &Path) -> Option<PathBuf>;
    fn package_name(&self, file: &ProjectFile) -> String;
    /// Called for a module candidate that `file_exists` denied. A fact source
    /// that cannot prove the absence records it. The live filesystem proves it.
    fn deny_candidate(&self, _candidate: &ProjectFile) {}
}

/// Rust source-listing derivation rules. Bump when listing or admission rules
/// change; readers treat older rows as absent. Changing
/// [`is_rust_listing_path`] changes what the certificate covers, so it
/// requires a bump here.
///
/// 2: a symbolic link to a directory, or to a target that cannot be read, fails
/// the certificate (#10321). A version 1 certificate may have certified a
/// listing that hid `.rs` files behind such a link.
///
/// 3: names compare ignoring ASCII case (#10469). On a case-insensitive volume
/// rustc opens src/foo.RS for `mod foo;`, so an omitted `.RS` file must fail
/// the certificate as an omitted `.rs` file does.
pub const RUST_SOURCE_LISTING_DERIVATION_VERSION: i64 = 3;

/// Whether a file listing that was certified complete for Rust proves a path
/// absent. The listing certificate covers `.rs` names and `Cargo.toml`,
/// ignoring ASCII case as a case-insensitive volume and the language of a
/// selected file do: an omitted file with another name is not recorded as
/// relevant, although a `#[path]` attribute may name any file and rustc
/// compiles it as Rust.
///
/// The certificate's coverage, its omission rule, the per-unit route kinds
/// and the crate-row producer share this predicate. A change to it requires a
/// bump of [`RUST_SOURCE_LISTING_DERIVATION_VERSION`].
pub fn is_rust_listing_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        || path
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("Cargo.toml"))
}

/// The key under which a module candidate and a selected file match on a
/// case-insensitive volume. A missing candidate whose key equals a selected
/// file's is unproven, never resolved to that file: on a case-sensitive volume
/// they are different files, and the selection does not record the volume's
/// case policy. APFS and NTFS fold letters beyond ASCII, so the key maps each
/// character to upper case and then to lower case, one character at a time,
/// and repeats until nothing changes. One pass unifies the final and medial
/// sigma and the Kelvin sign with `k`, which `str::to_lowercase` with its
/// context rule for a word-final sigma does not; the repeat unifies a letter
/// whose lower case expands on the next pass, as U+1E9E (capital sharp s)
/// becomes U+00DF and then `ss`. The key is an approximation of the volume's
/// folding that errs toward folding more: that only marks more candidates
/// unproven. Composed and decomposed forms of one letter are not unified.
///
/// The per-unit route kinds and the crate-row producer share this key.
pub fn rust_case_fold_key(path: &str) -> String {
    let mut key = case_fold_pass(path);
    // Each pass only expands letters into lower-case ones, which reach their
    // fixed point within a few passes.
    for _ in 0..CASE_FOLD_EXTRA_PASSES {
        let next = case_fold_pass(&key);
        if next == key {
            return key;
        }
        key = next;
    }
    panic!("case folding of {path:?} did not reach a fixed point");
}

/// A directory omission comparison must also cover volumes that normalize
/// Unicode names. Keep this separate from the persisted case-folded path probes:
/// their key format does not change when omission coverage gains NFD matching.
pub fn rust_omission_path_key(path: &str) -> String {
    rust_case_fold_key(&path.nfd().collect::<String>())
        .nfd()
        .collect()
}

const CASE_FOLD_EXTRA_PASSES: usize = 4;

fn case_fold_pass(text: &str) -> String {
    text.chars()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Path facts of one selection. A candidate exists when it is a selected file.
/// Containment is lexical, because the file listing records symbolic links as
/// omissions, so the selection holds no path that reaches through one. Package
/// names come from the selection's manifests, as the persisted package rows
/// do.
///
/// A denied candidate whose name the listing certificate does not cover (see
/// [`is_rust_listing_path`]) is recorded, because the selection proves no
/// absence for it: a symbolic link or a file such as `gen.inc` named by a
/// `#[path]` attribute is not a selected file, and may still be Rust.
///
/// A denied candidate whose [`rust_case_fold_key`] equals a selected file's is
/// recorded whatever its name.
pub struct SelectedRustRoutePathFacts<'a> {
    pub files: &'a HashSet<ProjectFile>,
    pub naming: &'a crate::crate_naming::RustSelectedCargoNaming,
    folded_files: HashSet<String>,
    unproven: std::sync::Mutex<std::collections::BTreeSet<ProjectFile>>,
}
impl<'a> SelectedRustRoutePathFacts<'a> {
    pub fn new(
        files: &'a HashSet<ProjectFile>,
        naming: &'a crate::crate_naming::RustSelectedCargoNaming,
    ) -> Self {
        Self {
            files,
            naming,
            folded_files: files
                .iter()
                .map(|file| rust_case_fold_key(&file.rel_path().to_string_lossy()))
                .collect(),
            unproven: Default::default(),
        }
    }
    /// The module candidates the route build found missing and the listing
    /// certificate cannot prove absent, sorted. Read it after the build.
    pub fn unproven_candidates(&self) -> Vec<ProjectFile> {
        let unproven = self.unproven.lock().expect("unproven candidates lock");
        unproven.iter().cloned().collect()
    }
}
impl RustRoutePathFacts for SelectedRustRoutePathFacts<'_> {
    fn deny_candidate(&self, candidate: &ProjectFile) {
        if !is_rust_listing_path(candidate.rel_path())
            || self
                .folded_files
                .contains(&rust_case_fold_key(&candidate.rel_path().to_string_lossy()))
        {
            self.unproven
                .lock()
                .expect("unproven candidates lock")
                .insert(candidate.clone());
        }
    }
    fn file_exists(&self, file: &ProjectFile) -> bool {
        self.files.contains(file)
    }
    fn workspace_relative(&self, root: &Path, base: &Path, path: &Path) -> Option<PathBuf> {
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(base).join(path)
        };
        let relative = joined.strip_prefix(root).ok()?;
        let mut normalized = PathBuf::new();
        for component in relative.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop() {
                        return None;
                    }
                }
                Component::Normal(part) => normalized.push(part),
                Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        Some(normalized)
    }
    fn package_name(&self, file: &ProjectFile) -> String {
        self.naming
            .package_name(file.rel_path())
            .unwrap_or_else(|| panic!("selected route file {file:?} has no selected package name"))
    }
}

use brokk_bifrost_core::analyzer::rust_facts::{
    RustCfgCondition, RustModuleRouteFact, RustModuleRouteFacts, RustVisibility,
};

use crate::cargo_config::RustCargoConfiguration;
use crate::cargo_manifest::RustCargoManifestDocument;
use crate::graph_support::RustRoutedAnswer;
use crate::imports::{rust_external_module_route, rust_external_module_segments};

// How many times one Cargo-route build has iterated the complete analyzed
// file set (issue #1817).
//
// Before #1817 the build ran one such sweep per crate -- twice, once in each
// membership pass -- and one per Cargo target, on top of the passes
// themselves, so its cost grew as workspace size times workspace topology and
// reached 9-19 s on the rustc tree. Every loop whose length is the analyzed
// file set reports here, and
// `a_cargo_route_build_sweeps_the_workspace_a_bounded_number_of_times` pins
// the total against a workspace whose crate and target count grows while its
// file count does not.
//
// Loops over the module-declaration list (`build_test_only_files_while`) are
// deliberately not counted: that list is not the file set, and it was one
// bounded pass before this change and after it.
//
// Thread-local rather than a process-global counter or a field, because the
// build is one sequential call stack and the pin then does not depend on
// nextest's process-per-test isolation to stay meaningful.
#[cfg(test)]
thread_local! {
    static WORKSPACE_FILE_SWEEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_workspace_file_sweep() {
    WORKSPACE_FILE_SWEEPS.with(|sweeps| sweeps.set(sweeps.get().saturating_add(1)));
}

#[cfg(not(test))]
fn note_workspace_file_sweep() {}

#[cfg(test)]
fn workspace_file_sweeps_of(build: impl FnOnce()) -> usize {
    WORKSPACE_FILE_SWEEPS.with(|sweeps| sweeps.set(0));
    build();
    WORKSPACE_FILE_SWEEPS.with(std::cell::Cell::get)
}

#[derive(Debug, Clone, Default)]
pub struct RustCargoRouteIndex {
    routes_by_manifest_and_name: HashMap<(PathBuf, String), Vec<RustCargoRoute>>,
    declared_dependencies_by_manifest_and_name:
        HashMap<(PathBuf, String), Vec<RustCargoDependencyKind>>,
    declared_dependencies_by_unit_and_name:
        HashMap<([u8; 32], String), Vec<RustCargoDependencyKind>>,
    target_roots_by_file: HashMap<ProjectFile, HashSet<ProjectFile>>,
    targets_by_root: HashMap<ProjectFile, HashSet<RustCargoTarget>>,
    files_by_reachable_root: HashMap<ProjectFile, Vec<ProjectFile>>,
    external_module_declarations: Vec<RustCargoModuleDeclaration>,
    test_only_files: HashSet<ProjectFile>,
}

#[derive(Debug, Clone)]
pub struct RustFileRoutes {
    units: Vec<Arc<RustCargoRouteIndex>>,
    complete: bool,
}

impl RustFileRoutes {
    pub fn new(units: Vec<Arc<RustCargoRouteIndex>>) -> Self {
        Self {
            units,
            complete: true,
        }
    }
    pub fn with_completeness(units: Vec<Arc<RustCargoRouteIndex>>, complete: bool) -> Self {
        Self { units, complete }
    }
    pub fn from_index(index: Arc<RustCargoRouteIndex>) -> Self {
        Self::new(vec![index])
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }
    /// Return an extern-root identity only when all contributing units agree.
    pub fn type_root_identity(&self, file: &ProjectFile, name: &str) -> Option<([u8; 32], String)> {
        let mut answers = self
            .units
            .iter()
            .map(|unit| unit.type_root_identity(file, name));
        let first = answers.next()??;
        answers
            .all(|answer| answer.as_ref() == Some(&first))
            .then_some(first)
    }
    pub fn target_roots(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let mut roots = self
            .units
            .iter()
            .flat_map(|unit| unit.target_roots_for_file(file))
            .collect::<Vec<_>>();
        roots.sort_unstable();
        roots.dedup();
        roots
    }
    pub fn uses_rust_2015_edition(&self, file: &ProjectFile) -> bool {
        let mut found = false;
        for unit in &self.units {
            if !unit.target_roots_for_file(file).is_empty() {
                found = true;
                if !unit.file_uses_rust_2015_edition(file) {
                    return false;
                }
            }
        }
        found
    }
    pub fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.complete
            && !self.units.is_empty()
            && self.units.iter().all(|unit| unit.file_is_test_only(file))
    }
    pub fn target_relation(
        &self,
        file: &ProjectFile,
        other: &Self,
        other_file: &ProjectFile,
    ) -> RustCargoTargetRelation {
        let roots = self.target_roots(file);
        let other_roots = other.target_roots(other_file);
        if roots.is_empty() || other_roots.is_empty() {
            RustCargoTargetRelation::Unknown
        } else if roots.iter().any(|root| other_roots.contains(root)) {
            RustCargoTargetRelation::Shared
        } else if !self.complete || !other.complete {
            RustCargoTargetRelation::Unknown
        } else {
            RustCargoTargetRelation::Disjoint
        }
    }
    pub fn files_share_target(
        &self,
        file: &ProjectFile,
        other: &Self,
        other_file: &ProjectFile,
    ) -> Option<bool> {
        match self.target_relation(file, other, other_file) {
            RustCargoTargetRelation::Shared => Some(true),
            RustCargoTargetRelation::Disjoint => Some(false),
            RustCargoTargetRelation::Unknown => None,
        }
    }
    /// Forward module-package resolution for a file that may sit in several
    /// units. Candidate lists are merged across the file's units before the
    /// whole index's uniqueness check: merging each unit's own `Option` would
    /// hide a second candidate that makes the answer ambiguous.
    ///
    /// A partial answer returns no target, because an omitted unit can add
    /// the candidate that makes an observed unique target wrong. A file that
    /// no unit's target holds has no routes here. The whole index's
    /// workspace-wide unscoped-library fallback needs the crate-name question,
    /// which only the `_or_unscoped` forms ask.
    pub fn resolve_module_package(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        self.resolve_module_package_or_unscoped(importing_file, module_specifier, &|_| {
            RustRoutedAnswer::incomplete(Vec::new())
        })
    }
    pub fn resolve_module_package_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(String, RustCargoRouteKind)> {
        self.resolve_module_package_segments_with_kind_or_unscoped(
            importing_file,
            segments,
            &|_| RustRoutedAnswer::incomplete(Vec::new()),
        )
    }
    pub fn resolve_crate_root_file(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<ProjectFile> {
        self.resolve_crate_root_file_or_unscoped(importing_file, module_specifier, &|_| {
            RustRoutedAnswer::incomplete(Vec::new())
        })
    }
    pub fn resolve_crate_root_file_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(ProjectFile, RustCargoRouteKind)> {
        self.resolve_crate_root_file_segments_with_kind_or_unscoped(
            importing_file,
            segments,
            &|_| RustRoutedAnswer::incomplete(Vec::new()),
        )
    }
    /// [`Self::resolve_module_package`] for a file that no unit's target holds:
    /// `unscoped` answers the crate-name question for a normalized name, and a
    /// complete answer with exactly one library root is a dependency route, as
    /// in the whole index. A partial answer returns no target.
    pub fn resolve_module_package_or_unscoped(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
        unscoped: &dyn Fn(&str) -> RustUnscopedLibraries,
    ) -> Option<String> {
        resolve_module_package_with(module_specifier, |name| {
            self.resolve_available_route(importing_file, name, unscoped)
        })
    }
    pub fn resolve_module_package_segments_with_kind_or_unscoped(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
        unscoped: &dyn Fn(&str) -> RustUnscopedLibraries,
    ) -> Option<(String, RustCargoRouteKind)> {
        resolve_module_package_segments_with(segments, |name| {
            self.resolve_available_route(importing_file, name, unscoped)
        })
    }
    pub fn resolve_crate_root_file_or_unscoped(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
        unscoped: &dyn Fn(&str) -> RustUnscopedLibraries,
    ) -> Option<ProjectFile> {
        resolve_crate_root_file_with(module_specifier, |name| {
            self.resolve_available_route(importing_file, name, unscoped)
        })
    }
    pub fn resolve_crate_root_file_segments_with_kind_or_unscoped(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
        unscoped: &dyn Fn(&str) -> RustUnscopedLibraries,
    ) -> Option<(ProjectFile, RustCargoRouteKind)> {
        resolve_crate_root_file_segments_with(segments, |name| {
            self.resolve_available_route(importing_file, name, unscoped)
        })
    }
    /// Whether some unit of this answer has `file` in one of its targets. A
    /// file in no target is the whole index's unscoped case.
    pub fn is_in_target(&self, file: &ProjectFile) -> bool {
        self.units
            .iter()
            .any(|unit| !unit.target_roots_for_file(file).is_empty())
    }
    fn resolve_available_route(
        &self,
        file: &ProjectFile,
        route_name: &str,
        unscoped: &dyn Fn(&str) -> RustUnscopedLibraries,
    ) -> Option<RustCargoRoute> {
        if !self.complete {
            return None;
        }
        let normalized = normalize_crate_name(route_name);
        if !self.is_in_target(file) {
            return unique_library_route(&unscoped(&normalized));
        }
        let scoped = self
            .units
            .iter()
            .filter_map(|unit| unit.scoped_route_candidates(file, &normalized))
            .collect::<Vec<_>>();
        unique_scoped_route(scoped.into_iter().flatten().collect())
    }
    /// Whether one of the file's units declares a dependency under this name
    /// that its targets can use. `None` is unknown: a negative needs a
    /// complete answer.
    pub fn has_available_declared_dependency(
        &self,
        file: &ProjectFile,
        route_name: &str,
    ) -> Option<bool> {
        if self
            .units
            .iter()
            .any(|unit| unit.has_available_declared_dependency(file, route_name))
        {
            Some(true)
        } else {
            self.complete.then_some(false)
        }
    }
    /// Module declarations written in `file`, over all of its units.
    pub fn module_declarations_declared_in(&self, file: &ProjectFile) -> RustFileDeclarations {
        self.declarations(|declaration| &declaration.declaring_file == file)
    }
    /// Module declarations that name `file` as their target, over all of its
    /// units.
    pub fn module_declarations_targeting(&self, file: &ProjectFile) -> RustFileDeclarations {
        self.declarations(|declaration| &declaration.target_file == file)
    }
    fn declarations(
        &self,
        wanted: impl Fn(&RustCargoModuleDeclaration) -> bool,
    ) -> RustFileDeclarations {
        let mut declarations = self
            .units
            .iter()
            .flat_map(|unit| unit.external_module_declarations())
            .filter(|declaration| wanted(declaration))
            .cloned()
            .collect();
        sort_and_dedup_external_module_declarations(&mut declarations);
        RustFileDeclarations {
            declarations,
            complete: self.complete,
        }
    }
    /// Whether `file` can name something in `target_file`'s target roots: it
    /// shares a root with it, or one of its roots' targets has a Cargo route
    /// to one. `self` holds the routes of `file`'s units and `target` those of
    /// `target_file`'s. `None` is unknown: a negative needs both complete.
    pub fn file_can_reference_target_of(
        &self,
        file: &ProjectFile,
        target: &Self,
        target_file: &ProjectFile,
    ) -> Option<bool> {
        let target_roots = target.target_roots(target_file);
        if target_roots.iter().any(|root| {
            self.units
                .iter()
                .any(|unit| unit.file_reaches_root(file, root))
        }) {
            Some(true)
        } else {
            (self.complete && target.complete).then_some(false)
        }
    }
    pub fn candidates_in_same_target_root(
        &self,
        file: &ProjectFile,
        candidates: Vec<CodeUnit>,
        candidate_routes: &HashMap<ProjectFile, RustFileRoutes>,
    ) -> Option<Vec<CodeUnit>> {
        let roots = self.target_roots(file);
        if roots.is_empty()
            || !self.complete
            || candidates.iter().any(|candidate| {
                candidate_routes
                    .get(candidate.source())
                    .is_none_or(|routes| !routes.complete)
            })
        {
            return None;
        }
        Some(
            candidates
                .into_iter()
                .filter(|candidate| {
                    candidate_routes
                        .get(candidate.source())
                        .is_some_and(|routes| {
                            routes
                                .target_roots(candidate.source())
                                .iter()
                                .any(|root| roots.contains(root))
                        })
                })
                .collect(),
        )
    }
}

/// Module declarations selected from a file's units. When `complete` is
/// false, declarations may be missing: a caller must not close a scope on it.
#[derive(Debug, Clone)]
pub struct RustFileDeclarations {
    pub declarations: Vec<RustCargoModuleDeclaration>,
    pub complete: bool,
}

/// The library roots that the crate-name question names under one normalized
/// crate name. A file that no unit's target holds reaches a workspace library
/// by name: a unique root is a dependency route, as in the whole index, and a
/// second root makes the name ambiguous. When the answer is incomplete a root
/// may be missing, so no route is drawn from it.
pub type RustUnscopedLibraries = RustRoutedAnswer<Vec<RustLibraryRoot>>;

/// One library root file and the package it roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustLibraryRoot {
    pub root_file: ProjectFile,
    pub package: String,
}

/// The dependency route that a complete crate-name answer with exactly one
/// library root gives, as in the whole index.
fn unique_library_route(libraries: &RustUnscopedLibraries) -> Option<RustCargoRoute> {
    if !libraries.complete {
        return None;
    }
    let mut roots = libraries.value.clone();
    roots.sort_by(|left, right| left.root_file.cmp(&right.root_file));
    roots.dedup_by(|duplicate, retained| duplicate.root_file == retained.root_file);
    match roots.as_slice() {
        [root] => Some(RustCargoRoute {
            package: root.package.clone(),
            root_file: root.root_file.clone(),
            kind: RustCargoRouteKind::Dependency,
            dependency_kind: None,
            target_predicate: None,
            target_unit_key: None,
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustCargoModuleDeclaration {
    pub declaring_file: ProjectFile,
    pub declaring_module: String,
    pub target_file: ProjectFile,
    pub visibility: RustVisibility,
    /// Byte offset of the `mod` declaration, including an item-macro argument
    /// when the route was recovered from a passthrough expansion.
    pub declaration_start_byte: usize,
    /// Byte offset at which a `#[macro_use]` module becomes visible to its
    /// parent scope. `usize::MAX` means the module does not import macros.
    pub visibility_start_byte: usize,
    /// Whether this module route imports its child's module-scope macros.
    pub imports_macros: bool,
    /// Whether the `mod x;` item carries a bare `#[cfg(test)]`, so the declared
    /// file is compiled into test builds only. The canonical route facts carry
    /// this structured verdict; only the bare predicate counts.
    pub test_gated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCargoRouteKind {
    CurrentLibrary,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCargoTargetRelation {
    Shared,
    Disjoint,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustCargoTargetKind {
    Library,
    Binary,
    Example,
    Test,
    Bench,
    Build,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RustCargoTarget {
    manifest: PathBuf,
    summary_unit_key: Option<[u8; 32]>,
    kind: RustCargoTargetKind,
    development_capable: bool,
    edition: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustCargoDependencyKind {
    Normal,
    Development,
    Build,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustCargoRoute {
    package: String,
    root_file: ProjectFile,
    kind: RustCargoRouteKind,
    dependency_kind: Option<RustCargoDependencyKind>,
    target_predicate: Option<String>,
    target_unit_key: Option<[u8; 32]>,
}

/// One row from the live Rust summary route query. Dependency columns are
/// NULL when the unit has no dependencies; a workspace dependency carries its
/// live library root when that unit is published.
#[derive(Debug, Clone)]
pub struct RustCargoRouteSummaryRow {
    pub unit_key: [u8; 32],
    pub manifest_directory: Option<PathBuf>,
    pub target_kind: String,
    pub crate_name: String,
    pub edition: String,
    pub development_capable: bool,
    pub root_file: Option<ProjectFile>,
    pub root_package: Option<String>,
    pub dependency_extern_name: Option<String>,
    pub dependency_kind: Option<RustCargoDependencyKind>,
    pub dependency_boundary: Option<String>,
    pub dependency_unit_key: Option<[u8; 32]>,
    pub dependency_target_kind: Option<String>,
    pub dependency_root_file: Option<ProjectFile>,
    pub dependency_root_package: Option<String>,
    pub dependency_manifest_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustVisibleItemMacroDefinition {
    visible_after: usize,
    scope_start: usize,
    scope_end: usize,
    /// The activation the definition's rules add to each item they replay,
    /// when the definition decides its invocations: a passthrough whose rules
    /// add only `cfg` (and documentation) attributes. `None` when it does not,
    /// as `source_rust_item_macros.decoration_cfg` is NULL, so a `mod` route
    /// through its invocation is not admitted, exactly as the crate's module
    /// walk leaves it undecided.
    decoration: Option<RustCfgCondition>,
}

impl RustCargoRouteIndex {
    pub fn retained_bytes(&self) -> usize {
        use std::mem::size_of;
        let mut bytes = size_of::<Self>();
        bytes += self.routes_by_manifest_and_name.capacity()
            * (size_of::<(PathBuf, String)>()
                + size_of::<Vec<RustCargoRoute>>()
                + 2 * size_of::<usize>());
        for ((path, name), routes) in &self.routes_by_manifest_and_name {
            bytes +=
                path.capacity() + name.capacity() + routes.capacity() * size_of::<RustCargoRoute>();
            for route in routes {
                bytes += route.package.capacity()
                    + route.root_file.retained_heap_bytes()
                    + route.target_predicate.as_ref().map_or(0, String::capacity);
            }
        }
        bytes += self.declared_dependencies_by_manifest_and_name.capacity()
            * (size_of::<(PathBuf, String)>()
                + size_of::<Vec<RustCargoDependencyKind>>()
                + 2 * size_of::<usize>());
        for ((path, name), kinds) in &self.declared_dependencies_by_manifest_and_name {
            bytes += path.capacity()
                + name.capacity()
                + kinds.capacity() * size_of::<RustCargoDependencyKind>();
        }
        bytes += self.declared_dependencies_by_unit_and_name.capacity()
            * (size_of::<([u8; 32], String)>()
                + size_of::<Vec<RustCargoDependencyKind>>()
                + 2 * size_of::<usize>());
        for ((_, name), kinds) in &self.declared_dependencies_by_unit_and_name {
            bytes += name.capacity() + kinds.capacity() * size_of::<RustCargoDependencyKind>();
        }
        bytes += self.target_roots_by_file.capacity()
            * (size_of::<ProjectFile>()
                + size_of::<HashSet<ProjectFile>>()
                + 2 * size_of::<usize>());
        for (file, roots) in &self.target_roots_by_file {
            bytes += file.retained_heap_bytes()
                + roots.capacity() * (size_of::<ProjectFile>() + 2 * size_of::<usize>());
            for root in roots {
                bytes += root.retained_heap_bytes();
            }
        }
        bytes += self.targets_by_root.capacity()
            * (size_of::<ProjectFile>()
                + size_of::<HashSet<RustCargoTarget>>()
                + 2 * size_of::<usize>());
        for (root, targets) in &self.targets_by_root {
            bytes += root.retained_heap_bytes()
                + targets.capacity() * (size_of::<RustCargoTarget>() + 2 * size_of::<usize>());
            for target in targets {
                bytes += target.manifest.capacity() + target.edition.capacity();
            }
        }
        bytes += self.files_by_reachable_root.capacity()
            * (size_of::<ProjectFile>() + size_of::<Vec<ProjectFile>>() + 2 * size_of::<usize>());
        for (root, files) in &self.files_by_reachable_root {
            bytes += root.retained_heap_bytes() + files.capacity() * size_of::<ProjectFile>();
            for file in files {
                bytes += file.retained_heap_bytes();
            }
        }
        bytes +=
            self.external_module_declarations.capacity() * size_of::<RustCargoModuleDeclaration>();
        for decl in &self.external_module_declarations {
            bytes += decl.declaring_file.retained_heap_bytes()
                + decl.target_file.retained_heap_bytes()
                + decl.declaring_module.capacity();
        }
        bytes +=
            self.test_only_files.capacity() * (size_of::<ProjectFile>() + 2 * size_of::<usize>());
        for file in &self.test_only_files {
            bytes += file.retained_heap_bytes();
        }
        bytes
    }

    /// Compose routes from authored summary rows and explicit path facts.
    pub fn build_from_summary_rows_with_path_facts(
        files: &[ProjectFile],
        module_route_facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
        rows: &[RustCargoRouteSummaryRow],
        paths: &dyn RustRoutePathFacts,
        keep_going_fn: &dyn Fn() -> bool,
    ) -> Option<Self> {
        let keep_going = || keep_going_fn();
        keep_going().then_some(())?;
        let analyzed = files.iter().cloned().collect::<HashSet<_>>();
        let mut topology = CargoManifestTopology {
            routes_by_manifest_and_name: HashMap::default(),
            declared_dependencies_by_manifest_and_name: HashMap::default(),
            declared_dependencies_by_unit_and_name: HashMap::default(),
            targets_by_root: HashMap::default(),
            target_roots: Vec::new(),
            analyzed,
        };
        let mut indexed_units = HashSet::default();
        for row in rows {
            keep_going().then_some(())?;
            let manifest = row.manifest_directory.as_ref();
            let target_kind = summary_target_kind(&row.target_kind);
            if target_kind.is_none() {
                assert!(
                    manifest.is_none(),
                    "detached Rust summary has no Cargo manifest: {row:?}"
                );
            }
            if target_kind.is_some()
                && let (Some(manifest), Some(root_file)) = (manifest, row.root_file.as_ref())
            {
                let kind = target_kind.expect("checked summary target kind");
                topology
                    .targets_by_root
                    .entry(root_file.clone())
                    .or_default()
                    .insert(RustCargoTarget {
                        manifest: manifest.clone(),
                        summary_unit_key: Some(row.unit_key),
                        kind,
                        development_capable: row.development_capable,
                        edition: row.edition.clone(),
                    });
                // Every Cargo target root comes from its live summary member.
            } else if target_kind.is_some() && manifest.is_some() {
                assert!(
                    row.root_file.is_some(),
                    "Cargo summary has a root member: {row:?}"
                );
            }

            if row.target_kind == "lib" && manifest.is_some() {
                assert!(
                    row.root_file.is_some(),
                    "library summary has a root member: {row:?}"
                );
                assert!(
                    row.root_package.is_some(),
                    "library summary has root naming: {row:?}"
                );
            }
            if indexed_units.insert(row.unit_key)
                && row.target_kind == "lib"
                && let (Some(manifest), Some(root_file), Some(package)) =
                    (manifest, row.root_file.as_ref(), row.root_package.as_ref())
            {
                topology
                    .routes_by_manifest_and_name
                    .entry((manifest.clone(), normalize_crate_name(&row.crate_name)))
                    .or_default()
                    .push(RustCargoRoute {
                        package: package.clone(),
                        root_file: root_file.clone(),
                        kind: RustCargoRouteKind::CurrentLibrary,
                        dependency_kind: None,
                        target_predicate: None,
                        target_unit_key: None,
                    });
            }

            let Some(extern_name) = row.dependency_extern_name.as_ref() else {
                assert!(row.dependency_kind.is_none());
                assert!(row.dependency_boundary.is_none());
                continue;
            };
            let dependency_kind = row
                .dependency_kind
                .expect("named Rust summary dependency has a kind");
            if row.dependency_boundary.as_deref() == Some("workspace") {
                assert!(row.dependency_unit_key.is_some());
            }
            let (Some(manifest), Some(_target_root)) = (manifest, row.root_file.as_ref()) else {
                continue;
            };
            let normalized_name = normalize_crate_name(extern_name);
            topology
                .declared_dependencies_by_unit_and_name
                .entry((row.unit_key, normalized_name.clone()))
                .or_default()
                .push(dependency_kind);
            if row.dependency_boundary.as_deref() != Some("workspace")
                || row.dependency_target_kind.as_deref() != Some("lib")
            {
                continue;
            }
            let (Some(root_file), Some(package), Some(dependency_manifest)) = (
                row.dependency_root_file.as_ref(),
                row.dependency_root_package.as_ref(),
                row.dependency_manifest_directory.as_ref(),
            ) else {
                continue;
            };
            let route = RustCargoRoute {
                package: package.clone(),
                root_file: root_file.clone(),
                kind: if dependency_manifest == manifest {
                    RustCargoRouteKind::CurrentLibrary
                } else {
                    RustCargoRouteKind::Dependency
                },
                dependency_kind: Some(dependency_kind),
                target_predicate: None,
                target_unit_key: Some(row.unit_key),
            };
            topology
                .routes_by_manifest_and_name
                .entry((manifest.clone(), normalized_name))
                .or_default()
                .push(route);
        }
        topology.target_roots = topology.targets_by_root.keys().cloned().collect();
        topology.target_roots.sort();
        for routes in topology.routes_by_manifest_and_name.values_mut() {
            routes.sort_by(|left, right| {
                left.root_file
                    .cmp(&right.root_file)
                    .then_with(|| left.package.cmp(&right.package))
                    .then_with(|| left.target_unit_key.cmp(&right.target_unit_key))
            });
            routes.dedup();
        }
        for dependencies in topology.declared_dependencies_by_unit_and_name.values_mut() {
            dependencies.sort_by_key(|kind| *kind as u8);
            dependencies.dedup();
        }
        Self::finish_build_from_topology_while(module_route_facts, topology, paths, &keep_going)
    }

    fn finish_build_from_topology_while(
        module_route_facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
        topology: CargoManifestTopology,
        paths: &dyn RustRoutePathFacts,
        keep_going: &impl Fn() -> bool,
    ) -> Option<Self> {
        let mut edges = ModuleEdgeCache::new(paths);

        // Stage 1: which target roots reach which file, before any item macro
        // is known to expand. Only the reachability is taken from this walk;
        // the manifest half of the index does not depend on it, which is why
        // the topology is discovered once rather than once per walk.
        let physical_target_roots_by_file = topology.target_memberships_while(
            |file, is_crate_root, _target| {
                edges
                    .gate_free(file, module_route_facts, is_crate_root)
                    .iter()
                    .map(|edge| edge.file.clone())
                    .collect()
            },
            keep_going,
        )?;
        let files_by_target = files_by_target_root(&physical_target_roots_by_file, keep_going)?;

        // Stage 2: where each item macro is visible. `#[macro_use]` climbs to
        // the files that declare the definition's module and descends into
        // everything they declare after it, and both directions stop at the
        // target boundary -- so one file reached through two targets can see
        // different macros, and the walk is per target.
        let mut passthrough_by_target_and_file: HashMap<
            (ProjectFile, ProjectFile),
            HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
        > = HashMap::default();
        for (target, target_files) in &files_by_target {
            keep_going().then_some(())?;
            let mut children_by_file: HashMap<ProjectFile, Arc<Vec<RustExternalModuleChild>>> =
                HashMap::default();
            let mut parents_by_file: HashMap<ProjectFile, Vec<(ProjectFile, bool, usize)>> =
                HashMap::default();
            for file in target_files {
                keep_going().then_some(())?;
                if !module_route_facts.contains_key(file) {
                    continue;
                }
                let file_edges = edges.gate_free(file, module_route_facts, file == target);
                for edge in file_edges.iter() {
                    keep_going().then_some(())?;
                    if physical_target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        parents_by_file.entry(edge.file.clone()).or_default().push((
                            file.clone(),
                            edge.imports_macros,
                            edge.visibility_start_byte,
                        ));
                    }
                }
                children_by_file.insert(file.clone(), file_edges);
            }

            for definition_file in target_files {
                keep_going().then_some(())?;
                let Some(definition_facts) = module_route_facts.get(definition_file) else {
                    continue;
                };
                for definition in &definition_facts.item_macros {
                    keep_going().then_some(())?;
                    let mut visible_files: HashMap<ProjectFile, usize> = HashMap::default();
                    let mut pending = vec![(definition_file.clone(), definition.visible_after)];
                    while let Some((file, visible_after)) = pending.pop() {
                        keep_going().then_some(())?;
                        if visible_files
                            .get(&file)
                            .is_some_and(|known_start| *known_start <= visible_after)
                        {
                            continue;
                        }
                        visible_files.insert(file.clone(), visible_after);
                        let local_scope = (file == *definition_file)
                            .then_some((definition.scope_start, definition.scope_end));
                        if local_scope.is_none_or(|(start, end)| {
                            module_route_facts
                                .get(&file)
                                .and_then(RustModuleRouteFacts::file_extent)
                                .is_some_and(|extent| extent == (start, end))
                        }) && let Some(parents) = parents_by_file.get(&file)
                        {
                            pending.extend(
                                parents
                                    .iter()
                                    .filter(|(_, imports_macros, _)| *imports_macros)
                                    .map(|(parent, _, import_start)| {
                                        (parent.clone(), *import_start)
                                    }),
                            );
                        }
                        if let Some(children) = children_by_file.get(&file) {
                            pending.extend(
                                children
                                    .iter()
                                    .filter(|edge| {
                                        edge.declaration_start_byte >= visible_after
                                            && local_scope.is_none_or(|(start, end)| {
                                                start <= edge.declaration_start_byte
                                                    && edge.declaration_start_byte < end
                                            })
                                    })
                                    .map(|edge| (edge.file.clone(), 0)),
                            );
                        }
                    }
                    for (file, visible_after) in visible_files {
                        keep_going().then_some(())?;
                        let (scope_start, scope_end) = if file == *definition_file {
                            (definition.scope_start, definition.scope_end)
                        } else {
                            let Some(extent) = module_route_facts
                                .get(&file)
                                .and_then(RustModuleRouteFacts::file_extent)
                            else {
                                continue;
                            };
                            extent
                        };
                        passthrough_by_target_and_file
                            .entry((target.clone(), file))
                            .or_default()
                            .entry(definition.name.clone())
                            .or_default()
                            .push(RustVisibleItemMacroDefinition {
                                visible_after,
                                scope_start,
                                scope_end,
                                decoration: definition.decoration.clone(),
                            });
                    }
                }
            }
        }

        // Stage 3: a `#[macro_use] mod child;` re-exports the macros its parent
        // could see into the child, so the visible set has to be pushed down
        // the module tree until it stops growing.
        for (target, target_files) in &files_by_target {
            keep_going().then_some(())?;
            let mut pending = target_files.iter().cloned().collect::<VecDeque<_>>();
            let mut processed_binding_counts: HashMap<ProjectFile, usize> = HashMap::default();
            while let Some(file) = pending.pop_front() {
                keep_going().then_some(())?;
                let Some(facts) = module_route_facts.get(&file) else {
                    continue;
                };
                let key = (target.clone(), file.clone());
                let binding_count = passthrough_by_target_and_file
                    .get(&key)
                    .into_iter()
                    .flat_map(|bindings| bindings.values())
                    .map(Vec::len)
                    .sum();
                if processed_binding_counts.get(&file) == Some(&binding_count) {
                    continue;
                }
                processed_binding_counts.insert(file.clone(), binding_count);
                let bindings = passthrough_by_target_and_file
                    .get(&key)
                    .cloned()
                    .unwrap_or_default();
                let file_edges = if bindings.is_empty() {
                    edges.gate_free(&file, module_route_facts, file == *target)
                } else {
                    Arc::new(module_child_edges_with(
                        paths,
                        &file,
                        facts,
                        file == *target,
                        &bindings,
                    ))
                };
                for edge in file_edges.iter() {
                    keep_going().then_some(())?;
                    if physical_target_roots_by_file
                        .get(&edge.file)
                        .is_some_and(|roots| roots.contains(target))
                    {
                        continue;
                    }
                    let Some(child_facts) = module_route_facts.get(&edge.file) else {
                        continue;
                    };
                    let Some((child_start, child_end)) = child_facts.file_extent() else {
                        continue;
                    };
                    let child_bindings = passthrough_by_target_and_file
                        .entry((target.clone(), edge.file.clone()))
                        .or_default();
                    let before = child_bindings.values().map(Vec::len).sum::<usize>();
                    for (name, definitions) in &bindings {
                        keep_going().then_some(())?;
                        let Some(decoration) = rust_latest_visible_item_macro(
                            definitions,
                            edge.declaration_start_byte,
                        ) else {
                            continue;
                        };
                        let inherited = RustVisibleItemMacroDefinition {
                            visible_after: 0,
                            scope_start: child_start,
                            scope_end: child_end,
                            decoration,
                        };
                        let definitions = child_bindings.entry(name.clone()).or_default();
                        if !definitions.contains(&inherited) {
                            definitions.push(inherited);
                        }
                    }
                    for definition in &child_facts.item_macros {
                        keep_going().then_some(())?;
                        let local = RustVisibleItemMacroDefinition {
                            visible_after: definition.visible_after,
                            scope_start: definition.scope_start,
                            scope_end: definition.scope_end,
                            decoration: definition.decoration.clone(),
                        };
                        let definitions =
                            child_bindings.entry(definition.name.clone()).or_default();
                        if !definitions.contains(&local) {
                            definitions.push(local);
                        }
                    }
                    let after = child_bindings.values().map(Vec::len).sum::<usize>();
                    if after != before || !processed_binding_counts.contains_key(&edge.file) {
                        pending.push_back(edge.file.clone());
                    }
                }
            }
        }

        // Stage 4: the membership walk again, now with the macro-expanded
        // declarations, which is also where the declaration list the usage
        // walks read comes from.
        let no_passthrough_macros = HashMap::default();
        let mut external_module_declarations = Vec::new();
        let target_roots_by_file = topology.target_memberships_while(
            |file, is_crate_root, target| {
                let Some(facts) = module_route_facts.get(file) else {
                    return Vec::new();
                };
                let passthrough_macros = passthrough_by_target_and_file
                    .get(&(target.clone(), file.clone()))
                    .unwrap_or(&no_passthrough_macros);
                let file_edges = if passthrough_macros.is_empty() {
                    edges.gate_free(file, module_route_facts, is_crate_root)
                } else {
                    Arc::new(module_child_edges_with(
                        paths,
                        file,
                        facts,
                        is_crate_root,
                        passthrough_macros,
                    ))
                };
                external_module_declarations.extend(file_edges.iter().map(|edge| {
                    RustCargoModuleDeclaration {
                        declaring_file: file.clone(),
                        declaring_module: edge.declaring_module.clone(),
                        target_file: edge.file.clone(),
                        visibility: edge.visibility.clone(),
                        declaration_start_byte: edge.declaration_start_byte,
                        visibility_start_byte: edge.visibility_start_byte,
                        imports_macros: edge.imports_macros,
                        test_gated: edge.test_gated,
                    }
                }));
                file_edges.iter().map(|edge| edge.file.clone()).collect()
            },
            keep_going,
        )?;

        let mut index = topology.into_index(target_roots_by_file, keep_going)?;
        sort_and_dedup_external_module_declarations(&mut external_module_declarations);
        index.external_module_declarations = external_module_declarations;
        index.test_only_files = index.build_test_only_files_while(keep_going)?;
        Some(index)
    }

    pub fn candidates_in_same_target_root(
        &self,
        source_file: &ProjectFile,
        candidates: Vec<CodeUnit>,
    ) -> Option<Vec<CodeUnit>> {
        let source_roots = self.target_roots_by_file.get(source_file)?;
        let local: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                self.target_roots_by_file
                    .get(candidate.source())
                    .is_some_and(|candidate_roots| {
                        candidate_roots
                            .iter()
                            .any(|root| source_roots.contains(root))
                    })
            })
            .cloned()
            .collect();
        Some(local)
    }

    pub fn target_roots_for_file(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        self.target_roots_by_file
            .get(file)
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    /// Read a published unit's extern-root identity without discovering Cargo inputs.
    pub fn type_root_identity(&self, file: &ProjectFile, name: &str) -> Option<([u8; 32], String)> {
        let mut targets = self
            .target_roots_by_file
            .get(file)?
            .iter()
            .filter_map(|root| self.targets_by_root.get(root))
            .flatten();
        let first = targets.next()?;
        let unit = first.summary_unit_key?;
        if targets
            .any(|target| target.summary_unit_key != Some(unit) || target.edition != first.edition)
        {
            return None;
        }
        let normalized = normalize_crate_name(name);
        let kinds = self
            .declared_dependencies_by_unit_and_name
            .get(&(unit, normalized.clone()))?;
        if !kinds
            .iter()
            .any(|kind| cargo_dependency_available_to_target(*kind, first))
        {
            return None;
        }
        // The route index aggregates dependency destinations by manifest and
        // does not retain source-unit provenance. Cross-unit type identity is
        // deliberately unsupported here.
        Some((unit, first.edition.clone()))
    }

    pub fn file_uses_rust_2015_edition(&self, file: &ProjectFile) -> bool {
        let Some(roots) = self.target_roots_by_file.get(file) else {
            return false;
        };
        let mut targets = roots
            .iter()
            .filter_map(|root| self.targets_by_root.get(root))
            .flatten();
        let Some(first) = targets.next() else {
            return false;
        };
        first.edition == "2015" && targets.all(|target| target.edition == "2015")
    }

    pub fn has_available_declared_dependency(&self, file: &ProjectFile, route_name: &str) -> bool {
        let normalized = normalize_crate_name(route_name);
        self.target_roots_by_file.get(file).is_some_and(|roots| {
            roots.iter().any(|root| {
                self.targets_by_root
                    .get(root)
                    .into_iter()
                    .flatten()
                    .any(|target| {
                        let dependency_kinds = if let Some(unit_key) = target.summary_unit_key {
                            self.declared_dependencies_by_unit_and_name
                                .get(&(unit_key, normalized.clone()))
                        } else {
                            self.declared_dependencies_by_manifest_and_name
                                .get(&(target.manifest.clone(), normalized.clone()))
                        };
                        dependency_kinds.is_some_and(|kinds| {
                            kinds
                                .iter()
                                .copied()
                                .any(|kind| cargo_dependency_available_to_target(kind, target))
                        })
                    })
            })
        })
    }

    pub fn external_module_declarations(&self) -> &[RustCargoModuleDeclaration] {
        &self.external_module_declarations
    }

    /// Whether `file` is compiled only into test builds, because every route
    /// that reaches it passes through a `#[cfg(test)] mod ...;` declaration.
    ///
    /// This is the file-level half of Rust test detection (#1546). Rust has no
    /// test filename or directory convention for the sibling test-module layout
    /// (`#[cfg(test)] mod tests;` in `mod.rs`, tests in `tests.rs`), and the
    /// declared file holds no local evidence -- its plain helper functions carry
    /// no attribute at all. The evidence lives on the parent's declaration, so
    /// it can only be read off the module graph.
    pub fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.test_only_files.contains(file)
    }

    /// Files that no production build can reach.
    ///
    /// Rather than pushing test-ness down from the gated declarations, push
    /// *production reachability* down from the roots and take the complement.
    /// That is what makes the transitive case fall out for free: in
    /// `#[cfg(test)] mod tests;` -> `tests/mod.rs` -> un-gated `mod helpers;`
    /// -> `tests/helpers.rs`, the second edge carries no gate of its own, and
    /// `helpers.rs` is test-only purely because nothing production-reachable
    /// declares it.
    ///
    /// The seeds are every file that no external `mod` item declares -- crate
    /// and target roots, plus any file outside the module tree -- so a file is
    /// only ever classified test-only on positive evidence that some
    /// declaration reaches it.
    fn build_test_only_files_while(
        &self,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashSet<ProjectFile>> {
        let mut declared = HashSet::default();
        for declaration in &self.external_module_declarations {
            keep_going().then_some(())?;
            declared.insert(&declaration.target_file);
        }
        if declared.is_empty() {
            return Some(HashSet::default());
        }
        let mut production_children: HashMap<&ProjectFile, Vec<&ProjectFile>> = HashMap::default();
        let mut pending: Vec<&ProjectFile> = self.targets_by_root.keys().collect();
        for declaration in &self.external_module_declarations {
            keep_going().then_some(())?;
            if !declaration.test_gated {
                production_children
                    .entry(&declaration.declaring_file)
                    .or_default()
                    .push(&declaration.target_file);
            }
            if !declared.contains(&declaration.declaring_file) {
                pending.push(&declaration.declaring_file);
            }
        }
        let mut production: HashSet<&ProjectFile> = HashSet::default();
        while let Some(file) = pending.pop() {
            keep_going().then_some(())?;
            if !production.insert(file) {
                continue;
            }
            pending.extend(production_children.get(file).into_iter().flatten().copied());
        }
        let mut test_only = HashSet::default();
        for file in declared {
            keep_going().then_some(())?;
            if !production.contains(file) {
                test_only.insert(file.clone());
            }
        }
        Some(test_only)
    }

    pub fn files_that_can_reference_target_of(
        &self,
        target_file: &ProjectFile,
    ) -> Vec<ProjectFile> {
        let Some(target_roots) = self.target_roots_by_file.get(target_file) else {
            return Vec::new();
        };
        let mut files = target_roots
            .iter()
            .flat_map(|root| {
                self.files_by_reachable_root
                    .get(root)
                    .into_iter()
                    .flatten()
                    .cloned()
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    pub fn file_can_reference_target_of(
        &self,
        file: &ProjectFile,
        target_file: &ProjectFile,
    ) -> bool {
        self.target_roots_by_file
            .get(target_file)
            .is_some_and(|target_roots| {
                target_roots.iter().any(|root| {
                    self.files_by_reachable_root
                        .get(root)
                        .is_some_and(|files| files.binary_search(file).is_ok())
                })
            })
    }

    /// Every file that can name something in each target root, materialised
    /// per root.
    ///
    /// A file reaches its own target root and every root a Cargo route makes
    /// available to one of that root's targets. Which roots those are is a
    /// question about the root, not about the file, so it is answered once per
    /// root and then applied to that root's files (issue #1817). It used to be
    /// answered inside the per-file loop, by scanning every route entry in the
    /// workspace for each (file, root, target) triple.
    fn build_files_by_reachable_root_while(
        &self,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashMap<ProjectFile, Vec<ProjectFile>>> {
        let mut routes_by_manifest: HashMap<&Path, Vec<&RustCargoRoute>> = HashMap::default();
        for ((manifest, _), routes) in &self.routes_by_manifest_and_name {
            keep_going().then_some(())?;
            routes_by_manifest
                .entry(manifest.as_path())
                .or_default()
                .extend(routes);
        }
        let mut visible_roots_by_root: HashMap<&ProjectFile, Vec<&ProjectFile>> =
            HashMap::default();
        for (root, targets) in &self.targets_by_root {
            keep_going().then_some(())?;
            let mut visible = Vec::new();
            for target in targets {
                keep_going().then_some(())?;
                visible.extend(
                    routes_by_manifest
                        .get(target.manifest.as_path())
                        .into_iter()
                        .flatten()
                        .filter(|route| route_serves_target(route, target))
                        .map(|route| &route.root_file),
                );
            }
            visible.sort();
            visible.dedup();
            visible_roots_by_root.insert(root, visible);
        }
        note_workspace_file_sweep();
        let mut files_by_root: HashMap<&ProjectFile, HashSet<&ProjectFile>> = HashMap::default();
        for (file, target_roots) in &self.target_roots_by_file {
            keep_going().then_some(())?;
            for root in target_roots {
                keep_going().then_some(())?;
                files_by_root.entry(root).or_default().insert(file);
                for visible in visible_roots_by_root
                    .get(root)
                    .into_iter()
                    .flatten()
                    .copied()
                {
                    keep_going().then_some(())?;
                    files_by_root.entry(visible).or_default().insert(file);
                }
            }
        }
        let mut sorted = HashMap::default();
        for (root, files) in files_by_root {
            keep_going().then_some(())?;
            let mut files = files.into_iter().cloned().collect::<Vec<_>>();
            files.sort();
            sorted.insert(root.clone(), files);
        }
        Some(sorted)
    }

    /// [`Self::target_relation`] as the tri-state boolean the usage paths ask
    /// for: `None` when either side's target is unknown.
    pub fn files_share_target(&self, left: &ProjectFile, right: &ProjectFile) -> Option<bool> {
        match self.target_relation(left, right) {
            RustCargoTargetRelation::Shared => Some(true),
            RustCargoTargetRelation::Disjoint => Some(false),
            RustCargoTargetRelation::Unknown => None,
        }
    }

    pub fn target_relation(
        &self,
        left: &ProjectFile,
        right: &ProjectFile,
    ) -> RustCargoTargetRelation {
        let Some(left_roots) = self.target_roots_by_file.get(left) else {
            return RustCargoTargetRelation::Unknown;
        };
        let Some(right_roots) = self.target_roots_by_file.get(right) else {
            return RustCargoTargetRelation::Unknown;
        };
        if left_roots.iter().any(|root| right_roots.contains(root)) {
            RustCargoTargetRelation::Shared
        } else {
            RustCargoTargetRelation::Disjoint
        }
    }

    pub fn resolve_module_package(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        resolve_module_package_with(module_specifier, |name| {
            self.resolve_available_route(importing_file, name)
        })
    }

    pub fn resolve_module_package_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(String, RustCargoRouteKind)> {
        resolve_module_package_segments_with(segments, |name| {
            self.resolve_available_route(importing_file, name)
        })
    }

    pub fn resolve_crate_root_file(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<ProjectFile> {
        resolve_crate_root_file_with(module_specifier, |name| {
            self.resolve_available_route(importing_file, name)
        })
    }

    pub fn resolve_crate_root_file_segments_with_kind(
        &self,
        importing_file: &ProjectFile,
        segments: &[String],
    ) -> Option<(ProjectFile, RustCargoRouteKind)> {
        resolve_crate_root_file_segments_with(segments, |name| {
            self.resolve_available_route(importing_file, name)
        })
    }

    fn resolve_available_route(
        &self,
        file: &ProjectFile,
        route_name: &str,
    ) -> Option<RustCargoRoute> {
        let normalized = normalize_crate_name(route_name);
        match self.scoped_route_candidates(file, &normalized) {
            Some(candidates) => unique_scoped_route(candidates),
            None => {
                unique_unscoped_library_route(self.unscoped_library_route_candidates(&normalized))
            }
        }
    }

    /// Every route the file's targets can use under this normalized name,
    /// before the uniqueness check. `None` when the file belongs to no target
    /// of this index, which is the unscoped case.
    fn scoped_route_candidates(
        &self,
        file: &ProjectFile,
        normalized: &str,
    ) -> Option<Vec<RustCargoRoute>> {
        let target_roots = self.target_roots_by_file.get(file)?;
        let mut candidates = Vec::new();
        for root in target_roots {
            let Some(targets) = self.targets_by_root.get(root) else {
                continue;
            };
            for target in targets {
                candidates.extend(
                    self.routes_by_manifest_and_name
                        .get(&(target.manifest.clone(), normalized.to_owned()))
                        .into_iter()
                        .flatten()
                        .filter(|route| route_serves_target(route, target))
                        .cloned(),
                );
            }
        }
        Some(candidates)
    }

    /// The library roots the whole index exposes under this normalized name, as
    /// the crate-name question answers them per unit. Always complete.
    pub fn unscoped_libraries(&self, normalized: &str) -> RustUnscopedLibraries {
        RustRoutedAnswer::complete(
            self.unscoped_library_route_candidates(normalized)
                .into_iter()
                .map(|route| RustLibraryRoot {
                    root_file: route.root_file,
                    package: route.package,
                })
                .collect(),
        )
    }

    /// Every indexed route exposed under this normalized name, for an
    /// analyzed Rust file that belongs to no Cargo target, such as a
    /// checked-in standalone example.
    ///
    /// There is no dependency table to establish visibility for such a file.
    /// A unique indexed workspace library is still a structured best-effort
    /// answer; more than one physical library root with that exposed name
    /// remains ambiguous and fails closed. Files with known Cargo membership
    /// never use this path and retain strict dependency visibility.
    fn unscoped_library_route_candidates(&self, normalized: &str) -> Vec<RustCargoRoute> {
        self.routes_by_manifest_and_name
            .iter()
            .filter(|((_, name), _)| name == normalized)
            .flat_map(|(_, routes)| routes)
            .cloned()
            .collect()
    }

    /// Whether `file` shares a target root with `root`, or one of its roots'
    /// targets has a Cargo route to `root`. Answered from
    /// `files_by_reachable_root`, which is built once per index (issue #1817).
    fn file_reaches_root(&self, file: &ProjectFile, root: &ProjectFile) -> bool {
        self.files_by_reachable_root
            .get(root)
            .is_some_and(|files| files.binary_search(file).is_ok())
    }
}

/// The forward resolvers shared by the whole index and `RustFileRoutes`. They
/// differ only in where the route for a crate name comes from (the scoped
/// candidates, and for the whole index the unscoped fallback), which the
/// caller supplies as `route`.
fn resolve_module_package_with(
    module_specifier: &str,
    route: impl FnOnce(&str) -> Option<RustCargoRoute>,
) -> Option<String> {
    let (root, nested) = rust_external_module_route(module_specifier)?;
    let route = route(root)?;
    Some(append_module_package(route.package, nested.as_deref()))
}
fn resolve_module_package_segments_with(
    segments: &[String],
    route: impl FnOnce(&str) -> Option<RustCargoRoute>,
) -> Option<(String, RustCargoRouteKind)> {
    let (root, nested) = rust_external_module_segments(segments)?;
    let route = route(root)?;
    Some((
        append_module_package(route.package, nested.as_deref()),
        route.kind,
    ))
}
fn resolve_crate_root_file_with(
    module_specifier: &str,
    route: impl FnOnce(&str) -> Option<RustCargoRoute>,
) -> Option<ProjectFile> {
    let (root, nested) = rust_external_module_route(module_specifier)?;
    if nested.is_some() {
        return None;
    }
    Some(route(root)?.root_file)
}
fn resolve_crate_root_file_segments_with(
    segments: &[String],
    route: impl FnOnce(&str) -> Option<RustCargoRoute>,
) -> Option<(ProjectFile, RustCargoRouteKind)> {
    let (root, nested) = rust_external_module_segments(segments)?;
    if nested.is_some() {
        return None;
    }
    let route = route(root)?;
    Some((route.root_file, route.kind))
}

/// The whole index's uniqueness check over a candidate list: the same route
/// reached through several targets counts once, and a second distinct route
/// makes the name ambiguous.
fn unique_scoped_route(mut candidates: Vec<RustCargoRoute>) -> Option<RustCargoRoute> {
    candidates.sort_by(|left, right| {
        left.root_file
            .cmp(&right.root_file)
            .then_with(|| left.package.cmp(&right.package))
            .then_with(|| left.target_predicate.cmp(&right.target_predicate))
    });
    candidates.dedup_by(|duplicate, retained| {
        duplicate.root_file == retained.root_file
            && duplicate.package == retained.package
            && duplicate.kind == retained.kind
    });
    match candidates.as_slice() {
        [route] => Some(route.clone()),
        _ => None,
    }
}

fn unique_unscoped_library_route(mut candidates: Vec<RustCargoRoute>) -> Option<RustCargoRoute> {
    candidates.sort_by(|left, right| {
        left.root_file
            .cmp(&right.root_file)
            .then_with(|| left.package.cmp(&right.package))
    });
    candidates.dedup_by(|duplicate, retained| duplicate.root_file == retained.root_file);
    match candidates.as_slice() {
        [route] => {
            let mut route = route.clone();
            route.kind = RustCargoRouteKind::Dependency;
            Some(route)
        }
        _ => None,
    }
}

/// Whether a route listed under a manifest belongs to this target: it is the
/// target's own unit's route (or one every unit of the manifest shares) and the
/// route's dependency class is available to the target's kind.
fn route_serves_target(route: &RustCargoRoute, target: &RustCargoTarget) -> bool {
    route
        .target_unit_key
        .is_none_or(|unit_key| Some(unit_key) == target.summary_unit_key)
        && cargo_route_available_to_target(route, target)
}

fn sort_and_dedup_external_module_declarations(declarations: &mut Vec<RustCargoModuleDeclaration>) {
    declarations.sort_by(|left, right| {
        left.target_file
            .cmp(&right.target_file)
            .then_with(|| left.declaring_file.cmp(&right.declaring_file))
            .then_with(|| left.declaring_module.cmp(&right.declaring_module))
            .then_with(|| left.visibility.cmp(&right.visibility))
    });
    declarations.dedup();
}

fn cargo_route_available_to_target(route: &RustCargoRoute, target: &RustCargoTarget) -> bool {
    match route.dependency_kind {
        None => !matches!(
            target.kind,
            RustCargoTargetKind::Library | RustCargoTargetKind::Build
        ),
        Some(kind) => cargo_dependency_available_to_target(kind, target),
    }
}

fn summary_target_kind(target_kind: &str) -> Option<RustCargoTargetKind> {
    match target_kind {
        "lib" => Some(RustCargoTargetKind::Library),
        "bin" => Some(RustCargoTargetKind::Binary),
        "example" => Some(RustCargoTargetKind::Example),
        "test" => Some(RustCargoTargetKind::Test),
        "bench" => Some(RustCargoTargetKind::Bench),
        "build" => Some(RustCargoTargetKind::Build),
        "detached" => None,
        _ => panic!("unknown Rust summary target kind {target_kind:?}"),
    }
}

fn cargo_dependency_available_to_target(
    kind: RustCargoDependencyKind,
    target: &RustCargoTarget,
) -> bool {
    match kind {
        RustCargoDependencyKind::Normal => target.kind != RustCargoTargetKind::Build,
        RustCargoDependencyKind::Development => target.development_capable,
        RustCargoDependencyKind::Build => target.kind == RustCargoTargetKind::Build,
    }
}

/// The Cargo topology of the workspace: every manifest's crate, target,
/// dependency and edition identity, and the target roots those imply.
///
/// Discovered once per build (issue #1817). It used to be rediscovered inside
/// each of the two module-membership passes, which read and TOML-parsed every
/// manifest a second time and, far more expensively, searched the whole
/// analyzed file list once per crate for the files that crate's auto-discovered
/// targets are rooted at.
struct CargoManifestTopology {
    routes_by_manifest_and_name: HashMap<(PathBuf, String), Vec<RustCargoRoute>>,
    declared_dependencies_by_manifest_and_name:
        HashMap<(PathBuf, String), Vec<RustCargoDependencyKind>>,
    declared_dependencies_by_unit_and_name:
        HashMap<([u8; 32], String), Vec<RustCargoDependencyKind>>,
    targets_by_root: HashMap<ProjectFile, HashSet<RustCargoTarget>>,
    /// Every target root in the workspace, sorted. One membership walk is
    /// seeded from all of them at once: a walk frontier carries the target it
    /// came from, so per-crate walks and one shared walk reach the same
    /// (file, target) pairs.
    target_roots: Vec<ProjectFile>,
    analyzed: HashSet<ProjectFile>,
}

impl CargoManifestTopology {
    fn target_memberships_while(
        &self,
        module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<HashMap<ProjectFile, HashSet<ProjectFile>>> {
        cargo_target_memberships(
            &self.analyzed,
            &self.target_roots,
            module_children,
            keep_going,
        )
    }

    fn into_index(
        self,
        target_roots_by_file: HashMap<ProjectFile, HashSet<ProjectFile>>,
        keep_going: &impl Fn() -> bool,
    ) -> Option<RustCargoRouteIndex> {
        let mut index = RustCargoRouteIndex {
            routes_by_manifest_and_name: self.routes_by_manifest_and_name,
            declared_dependencies_by_manifest_and_name: self
                .declared_dependencies_by_manifest_and_name,
            declared_dependencies_by_unit_and_name: self.declared_dependencies_by_unit_and_name,
            target_roots_by_file,
            targets_by_root: self.targets_by_root,
            files_by_reachable_root: HashMap::default(),
            // Both are filled by `finish_build_from_topology_while` once the module edges exist;
            // the topology only knows the manifests.
            external_module_declarations: Vec::new(),
            test_only_files: HashSet::default(),
        };
        index.files_by_reachable_root = index.build_files_by_reachable_root_while(keep_going)?;
        Some(index)
    }
}

/// One file's module edges as they resolve with no macro gate satisfied.
///
/// The same `(file, is_crate_root)` pair is asked for by the first membership
/// walk, by every target the file belongs to while macro visibility is
/// computed, and again by the second walk for every file no passthrough macro
/// reaches -- which is nearly all of them. Each answer costs a `#[path]`
/// resolution per scope and an `exists()` per candidate file, so resolving it
/// once per pair is part of what keeps the build proportional to the workspace
/// rather than to the workspace times its Cargo targets (issue #1817).
struct ModuleEdgeCache<'a> {
    paths: &'a dyn RustRoutePathFacts,
    as_crate_root: HashMap<ProjectFile, Arc<Vec<RustExternalModuleChild>>>,
    as_module: HashMap<ProjectFile, Arc<Vec<RustExternalModuleChild>>>,
}

impl<'a> ModuleEdgeCache<'a> {
    fn new(paths: &'a dyn RustRoutePathFacts) -> Self {
        Self {
            paths,
            as_crate_root: HashMap::default(),
            as_module: HashMap::default(),
        }
    }

    fn gate_free(
        &mut self,
        file: &ProjectFile,
        module_route_facts: &HashMap<ProjectFile, RustModuleRouteFacts>,
        is_crate_root: bool,
    ) -> Arc<Vec<RustExternalModuleChild>> {
        let resolved = if is_crate_root {
            &mut self.as_crate_root
        } else {
            &mut self.as_module
        };
        if let Some(edges) = resolved.get(file) {
            return Arc::clone(edges);
        }
        let edges = Arc::new(
            module_route_facts
                .get(file)
                .map(|facts| {
                    module_child_edges_with(
                        self.paths,
                        file,
                        facts,
                        is_crate_root,
                        &HashMap::default(),
                    )
                })
                .unwrap_or_default(),
        );
        resolved.insert(file.clone(), Arc::clone(&edges));
        edges
    }
}

/// The files each target root owns, sorted: the inverse of the membership map.
///
/// Every per-target stage of the build iterates this instead of re-scanning the
/// whole analyzed file list for the files that belong to the target it is on,
/// which is what made the macro-visibility stage cost targets times files
/// (issue #1817).
fn files_by_target_root(
    target_roots_by_file: &HashMap<ProjectFile, HashSet<ProjectFile>>,
    keep_going: &impl Fn() -> bool,
) -> Option<HashMap<ProjectFile, Vec<ProjectFile>>> {
    note_workspace_file_sweep();
    let mut files_by_root: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
    for (file, roots) in target_roots_by_file {
        keep_going().then_some(())?;
        for root in roots {
            keep_going().then_some(())?;
            files_by_root
                .entry(root.clone())
                .or_default()
                .push(file.clone());
        }
    }
    for files in files_by_root.values_mut() {
        keep_going().then_some(())?;
        files.sort();
    }
    Some(files_by_root)
}

/// How far below its manifest directory an auto-discovered Cargo target can
/// sit. `auto_cargo_target_kind` matches relative paths of two, three or four
/// components and nothing else, which
/// `auto_target_paths_stay_within_the_grouped_depth` pins.
pub(crate) const AUTO_TARGET_MAX_DEPTH: usize = 4;

/// Which target roots reach which files, along `mod name;` edges.
fn cargo_target_memberships(
    analyzed: &HashSet<ProjectFile>,
    target_roots: &[ProjectFile],
    mut module_children: impl FnMut(&ProjectFile, bool, &ProjectFile) -> Vec<ProjectFile>,
    keep_going: &impl Fn() -> bool,
) -> Option<HashMap<ProjectFile, HashSet<ProjectFile>>> {
    let mut owners: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
    let mut pending = VecDeque::new();
    let mut visited = HashSet::default();
    for target in target_roots {
        keep_going().then_some(())?;
        owners
            .entry(target.clone())
            .or_default()
            .insert(target.clone());
        pending.push_back((target.clone(), target.clone(), true));
    }
    while let Some((file, target, is_crate_root)) = pending.pop_front() {
        keep_going().then_some(())?;
        if !visited.insert((file.clone(), target.clone(), is_crate_root)) {
            continue;
        }
        for child in module_children(&file, is_crate_root, &target) {
            keep_going().then_some(())?;
            if analyzed.contains(&child) {
                owners
                    .entry(child.clone())
                    .or_default()
                    .insert(target.clone());
                pending.push_back((child, target.clone(), false));
            }
        }
    }
    Some(owners)
}

/// One scope's resolved directories and qualified module name, for one live
/// file. Path-derived, so it is recomputed per file and never stored.
struct ResolvedModuleScope {
    /// Where a plain `mod name;` in this scope looks for its file. `None` when
    /// a `#[path]` on this scope or an enclosing one did not resolve, which
    /// drops every declaration below it exactly as the syntax walk did.
    module_directory: Option<PathBuf>,
    /// Where a `#[path = "..."]` written in this scope resolves from.
    path_directory: Option<PathBuf>,
    declaring_module: String,
}

/// Resolve one file's persisted module-route facts into the module edges the
/// index consumes.
///
/// This is the reader half of the canonical route facts published by
/// `parse_rust_file`, and it holds everything the stored rows deliberately do
/// not: the file's own location,
/// which decides the directory a `mod name;` searches; `#[path]` normalization,
/// which must run step by step because `canonicalize` resolves symbolic links
/// at every level; and the on-disk existence check that turns a declaration
/// into an edge.
fn module_child_edges_with(
    paths: &dyn RustRoutePathFacts,
    file: &ProjectFile,
    facts: &RustModuleRouteFacts,
    is_crate_root: bool,
    passthrough_macros: &HashMap<String, Vec<RustVisibleItemMacroDefinition>>,
) -> Vec<RustExternalModuleChild> {
    if facts.routes.is_empty() {
        return Vec::new();
    }
    let root = file.root();
    let parent = file.rel_path().parent().unwrap_or(Path::new(""));
    let stem = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let base_directory = if is_crate_root || stem == "mod" {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let package = paths.package_name(file);
    let mut scopes: Vec<ResolvedModuleScope> = Vec::with_capacity(facts.scopes.len());
    for scope in &facts.scopes {
        let resolved = match scope.parent {
            None => ResolvedModuleScope {
                module_directory: Some(base_directory.clone()),
                path_directory: Some(parent.to_path_buf()),
                declaring_module: package.clone(),
            },
            Some(index) => {
                assert!(
                    index < scopes.len(),
                    "module scope rows are stored in pre-order: {scope:?} in {facts:?}"
                );
                let enclosing = &scopes[index];
                let directory = match &scope.path_attribute {
                    Some(attribute) => enclosing.path_directory.as_ref().and_then(|base| {
                        paths.workspace_relative(root, base, Path::new(attribute))
                    }),
                    None => enclosing
                        .module_directory
                        .as_ref()
                        .map(|base| base.join(&scope.module_name)),
                };
                ResolvedModuleScope {
                    module_directory: directory.clone(),
                    path_directory: directory,
                    declaring_module: append_module_package(
                        enclosing.declaring_module.clone(),
                        Some(&scope.module_name),
                    ),
                }
            }
        };
        scopes.push(resolved);
    }

    let mut children = Vec::new();
    for route in &facts.routes {
        assert!(
            route.scope < scopes.len(),
            "module route names a scope it does not have: {route:?} in {facts:?}"
        );
        // A route written inside item-macro invocations is admitted when every
        // invocation is decided: its macro is a passthrough whose decoration
        // is known. The crate's module walk admits exactly those routes
        // (`rust_crate_module_walk.sql`). This index evaluates no profile, so
        // a decoration is treated as the route's own `cfg` is: a bare
        // `cfg(test)` marks the edge test-gated, and any other `cfg` is
        // admitted for the crate's walk to evaluate.
        let mut test_gated = route.test_gated;
        let mut decided = true;
        for gate in &route.gates {
            match passthrough_macros
                .get(&gate.macro_name)
                .and_then(|definitions| {
                    rust_latest_visible_item_macro(definitions, gate.invocation_start)
                }) {
                Some(Some(decoration)) => {
                    test_gated |= decoration == RustCfgCondition::Atom("test".to_owned());
                }
                Some(None) | None => {
                    decided = false;
                    break;
                }
            }
        }
        if !decided {
            continue;
        }
        let scope = &scopes[route.scope];
        match &route.path_attribute {
            Some(attribute) => {
                let Some(base) = scope.path_directory.as_ref() else {
                    continue;
                };
                let Some(relative) = paths.workspace_relative(root, base, Path::new(attribute))
                else {
                    continue;
                };
                push_module_child(
                    paths,
                    root,
                    relative,
                    route,
                    test_gated,
                    scope,
                    &mut children,
                );
            }
            None => {
                let Some(base) = scope.module_directory.as_ref() else {
                    continue;
                };
                for relative in [
                    base.join(&route.module_name).with_extension("rs"),
                    base.join(&route.module_name).join("mod.rs"),
                ] {
                    push_module_child(
                        paths,
                        root,
                        relative,
                        route,
                        test_gated,
                        scope,
                        &mut children,
                    );
                }
            }
        }
    }
    sort_and_merge_module_children(&mut children);
    children
}

/// Keep `relative` as a module edge when it names a file that exists.
fn push_module_child(
    paths: &dyn RustRoutePathFacts,
    root: &Path,
    relative: PathBuf,
    route: &RustModuleRouteFact,
    test_gated: bool,
    scope: &ResolvedModuleScope,
    children: &mut Vec<RustExternalModuleChild>,
) {
    let candidate = ProjectFile::new(root.to_path_buf(), relative);
    if !paths.file_exists(&candidate) {
        paths.deny_candidate(&candidate);
        return;
    }
    children.push(RustExternalModuleChild {
        file: candidate,
        declaring_module: scope.declaring_module.clone(),
        visibility: route.visibility.clone(),
        imports_macros: route.imports_macros,
        test_gated,
        declaration_start_byte: route.declaration_start,
        visibility_start_byte: if route.imports_macros {
            route.declaration_end
        } else {
            usize::MAX
        },
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustExternalModuleChild {
    file: ProjectFile,
    declaring_module: String,
    visibility: RustVisibility,
    imports_macros: bool,
    test_gated: bool,
    declaration_start_byte: usize,
    visibility_start_byte: usize,
}

/// Collapse repeated declarations of the same file into one edge.
///
/// Shared by every canonical module-route fact reader.
fn sort_and_merge_module_children(children: &mut Vec<RustExternalModuleChild>) {
    children.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.declaring_module.cmp(&right.declaring_module))
            .then_with(|| left.visibility.cmp(&right.visibility))
    });
    children.dedup_by(|duplicate, retained| {
        if duplicate.file == retained.file
            && duplicate.declaring_module == retained.declaring_module
            && duplicate.visibility == retained.visibility
        {
            retained.declaration_start_byte = retained
                .declaration_start_byte
                .min(duplicate.declaration_start_byte);
            if duplicate.imports_macros {
                retained.visibility_start_byte = retained
                    .visibility_start_byte
                    .min(duplicate.visibility_start_byte);
            }
            retained.imports_macros |= duplicate.imports_macros;
            // Mutually exclusive declarations of the same module
            // (`#[cfg(test)] mod x;` beside `#[cfg(not(test))] mod x;`) merge
            // into one edge here. The file is compiled outside tests as soon as
            // any one of them is un-gated, so the merged edge is gated only if
            // every declaration was.
            retained.test_gated &= duplicate.test_gated;
            true
        } else {
            false
        }
    });
}

fn rust_latest_visible_item_macro(
    definitions: &[RustVisibleItemMacroDefinition],
    invocation_start: usize,
) -> Option<Option<RustCfgCondition>> {
    let latest = definitions
        .iter()
        .filter(|definition| {
            definition.visible_after <= invocation_start
                && definition.scope_start <= invocation_start
                && invocation_start < definition.scope_end
        })
        .map(|definition| (definition.scope_start, definition.visible_after))
        .max()?;
    let mut matching = definitions.iter().filter(|definition| {
        definition.scope_start == latest.0
            && definition.visible_after == latest.1
            && definition.scope_start <= invocation_start
            && invocation_start < definition.scope_end
    });
    let decoration = matching.next()?.decoration.clone();
    matching
        .all(|definition| definition.decoration == decoration)
        .then_some(decoration)
}

/// The decoded `#[path = "..."]` value written on `module`, if any.
///
/// Kept as the decoded string rather than a `PathBuf` because this is what the
/// `rust_module_scopes` / `rust_module_routes` rows carry: the attribute is a
/// content fact, and turning it into a path is the reader's job.
/// Decode a static Rust string literal from its tree-sitter node.
///
/// `#[path]` and filesystem macros accept both cooked and raw strings. Decode
/// cooked escape nodes individually so consumers see the assigned path rather
/// than the literal's source spelling. This helper is public for structured
/// consumers that read paths from macro arguments.
pub fn rust_static_string_literal(literal: Node<'_>, source: &str) -> Option<String> {
    rust_static_string_literal_with_ranges(literal, source).map(|literal| literal.value)
}

/// Decoded literal text paired with source-backed unescaped content ranges.
/// Escape nodes still participate in decoding, but cannot masquerade as a
/// contiguous identifier spelling in the original file.
pub struct RustLiteralText {
    pub value: String,
    pub ranges: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>,
}

pub fn rust_static_string_literal_with_ranges(
    literal: Node<'_>,
    source: &str,
) -> Option<RustLiteralText> {
    if literal.has_error() {
        return None;
    }
    match literal.kind() {
        "raw_string_literal" => {
            let spelling = source.get(literal.start_byte()..literal.end_byte())?;
            if !spelling.starts_with('r') {
                return None;
            }
            let content = literal.named_child(0)?;
            (content.kind() == "string_content" && content.next_named_sibling().is_none()).then(
                || {
                    source
                        .get(content.start_byte()..content.end_byte())
                        .map(|text| RustLiteralText {
                            value: text.to_string(),
                            ranges: vec![(0..text.len(), content.byte_range())],
                        })
                },
            )?
        }
        "string_literal" => {
            let spelling = source.get(literal.start_byte()..literal.end_byte())?;
            if !spelling.starts_with('"') {
                return None;
            }
            let mut decoded = String::new();
            let mut ranges = Vec::new();
            let mut trim_continuation_whitespace = false;
            let mut cursor = literal.walk();
            for child in literal.named_children(&mut cursor) {
                let text = source.get(child.start_byte()..child.end_byte())?;
                match child.kind() {
                    "string_content" => {
                        let text = if trim_continuation_whitespace {
                            trim_continuation_whitespace = false;
                            text.trim_start_matches(char::is_whitespace)
                        } else {
                            text
                        };
                        let start = decoded.len();
                        ranges.push((
                            start..start + text.len(),
                            child.end_byte() - text.len()..child.end_byte(),
                        ));
                        decoded.push_str(text);
                    }
                    "escape_sequence" => match rust_cooked_string_escape(text)? {
                        RustCookedStringEscape::Character(character) => {
                            decoded.push(character);
                            trim_continuation_whitespace = false;
                        }
                        RustCookedStringEscape::LineContinuation => {
                            trim_continuation_whitespace = true;
                        }
                    },
                    _ => return None,
                }
            }
            Some(RustLiteralText {
                value: decoded,
                ranges,
            })
        }
        _ => None,
    }
}

pub(crate) fn rust_cooked_string_literal_has_invalid_escape(
    literal: Node<'_>,
    source: &str,
) -> bool {
    assert_eq!(literal.kind(), "string_literal");
    let mut cursor = literal.walk();
    literal.named_children(&mut cursor).any(|child| {
        if child.kind() != "escape_sequence" {
            return false;
        }
        let escape = source
            .get(child.start_byte()..child.end_byte())
            .expect("Rust escape node range is within its source");
        rust_cooked_string_escape(escape).is_none()
    })
}

enum RustCookedStringEscape {
    Character(char),
    LineContinuation,
}

fn rust_cooked_string_escape(escape: &str) -> Option<RustCookedStringEscape> {
    let escaped = escape.strip_prefix('\\')?;
    if escaped == "\n" || escaped == "\r\n" {
        return Some(RustCookedStringEscape::LineContinuation);
    }
    let character = match escaped {
        "n" => '\n',
        "r" => '\r',
        "t" => '\t',
        "0" => '\0',
        "\\" => '\\',
        "\"" => '"',
        "'" => '\'',
        _ if escaped.starts_with('x') => {
            let value = u8::from_str_radix(escaped.get(1..)?, 16).ok()?;
            if !value.is_ascii() {
                return None;
            }
            char::from(value)
        }
        _ if escaped.starts_with("u{") && escaped.ends_with('}') => {
            let value =
                u32::from_str_radix(escaped.get(2..escaped.len().checked_sub(1)?)?, 16).ok()?;
            char::from_u32(value)?
        }
        _ if escaped.starts_with('u') => {
            let value = u32::from_str_radix(escaped.get(1..)?, 16).ok()?;
            char::from_u32(value)?
        }
        _ => return None,
    };
    Some(RustCookedStringEscape::Character(character))
}

pub(crate) fn inferred_cargo_target_paths(
    kind: RustCargoTargetKind,
    name: &str,
    package_name: &str,
) -> Vec<PathBuf> {
    let name_path = Path::new(name);
    if !matches!(
        name_path.components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    ) {
        return Vec::new();
    }
    match kind {
        RustCargoTargetKind::Binary => {
            let mut paths = Vec::new();
            if normalize_crate_name(name) == normalize_crate_name(package_name) {
                paths.push(PathBuf::from("src/main.rs"));
            }
            paths.push(Path::new("src/bin").join(name).with_extension("rs"));
            paths.push(Path::new("src/bin").join(name).join("main.rs"));
            paths
        }
        RustCargoTargetKind::Example => vec![
            Path::new("examples").join(name).with_extension("rs"),
            Path::new("examples").join(name).join("main.rs"),
        ],
        RustCargoTargetKind::Test => vec![
            Path::new("tests").join(name).with_extension("rs"),
            Path::new("tests").join(name).join("main.rs"),
        ],
        RustCargoTargetKind::Bench => vec![
            Path::new("benches").join(name).with_extension("rs"),
            Path::new("benches").join(name).join("main.rs"),
        ],
        RustCargoTargetKind::Library | RustCargoTargetKind::Build => Vec::new(),
    }
}

pub(crate) enum CargoBuildScriptPathState {
    Path(PathBuf),
    Disabled,
    Invalid,
}

pub(crate) fn cargo_build_script_path_state(
    build: Option<&toml::Value>,
) -> CargoBuildScriptPathState {
    match build {
        Some(toml::Value::String(path)) => CargoBuildScriptPathState::Path(PathBuf::from(path)),
        Some(toml::Value::Boolean(false)) => CargoBuildScriptPathState::Disabled,
        Some(toml::Value::Boolean(true)) | None => {
            CargoBuildScriptPathState::Path(PathBuf::from("build.rs"))
        }
        Some(_) => CargoBuildScriptPathState::Invalid,
    }
}

pub(crate) fn cargo_library_autodiscovery_enabled(configured: Option<bool>) -> bool {
    configured.unwrap_or(true)
}

pub(crate) fn cargo_auto_target_enabled(
    configured: Option<bool>,
    edition_is_2015: bool,
    has_explicit_target: bool,
) -> bool {
    configured.unwrap_or(!edition_is_2015 || !has_explicit_target)
}

pub(crate) fn cargo_manifest_has_explicit_target(manifest: &RustCargoManifestDocument) -> bool {
    manifest.get("lib").is_some()
        || ["bin", "example", "test", "bench"].iter().any(|name| {
            manifest
                .get(name)
                .and_then(toml::Value::as_array)
                .is_some_and(|targets| !targets.is_empty())
        })
}

pub fn auto_cargo_target_kind(
    relative: &Path,
    bins: bool,
    examples: bool,
    tests: bool,
    benches: bool,
) -> Option<RustCargoTargetKind> {
    let components: Vec<_> = relative.components().collect();
    match components.as_slice() {
        [Component::Normal(directory), Component::Normal(file)] => {
            if bins && *directory == "src" && *file == "main.rs" {
                Some(RustCargoTargetKind::Binary)
            } else if Path::new(file).extension().is_some_and(|ext| ext == "rs") {
                match directory.to_str() {
                    Some("examples") if examples => Some(RustCargoTargetKind::Example),
                    Some("tests") if tests => Some(RustCargoTargetKind::Test),
                    Some("benches") if benches => Some(RustCargoTargetKind::Bench),
                    _ => None,
                }
            } else {
                None
            }
        }
        [
            Component::Normal(first),
            Component::Normal(second),
            Component::Normal(third),
        ] => {
            if bins
                && *first == "src"
                && *second == "bin"
                && Path::new(third).extension().is_some_and(|ext| ext == "rs")
            {
                Some(RustCargoTargetKind::Binary)
            } else if *third == "main.rs" {
                match first.to_str() {
                    Some("examples") if examples => Some(RustCargoTargetKind::Example),
                    Some("tests") if tests => Some(RustCargoTargetKind::Test),
                    Some("benches") if benches => Some(RustCargoTargetKind::Bench),
                    _ => None,
                }
            } else {
                None
            }
        }
        [
            Component::Normal(src),
            Component::Normal(bin),
            Component::Normal(_),
            Component::Normal(main),
        ] => (bins && *src == "src" && *bin == "bin" && *main == "main.rs")
            .then_some(RustCargoTargetKind::Binary),
        _ => None,
    }
}

pub(crate) fn cargo_dependency_table_kinds<T>(
    normal: T,
    development: T,
    build: T,
) -> [(&'static str, T); 3] {
    [
        ("dependencies", normal),
        ("dev-dependencies", development),
        ("build-dependencies", build),
    ]
}

pub use crate::selected_context::cargo_dependency_tables_with_kind;

pub fn effective_cargo_dependency<'a>(
    root: &Path,
    manifest_directory: &Path,
    manifest: &'a RustCargoManifestDocument,
    exposed_name: &str,
    dependency: &'a toml::Value,
    manifests: &'a HashMap<PathBuf, RustCargoManifestDocument>,
) -> Option<(&'a toml::map::Map<String, toml::Value>, PathBuf)> {
    let (dependency, directory) = cargo_dependency_value(
        root,
        manifest_directory,
        manifest,
        exposed_name,
        dependency,
        manifests,
    )?;
    Some((dependency.as_table()?, directory))
}

/// Resolve workspace inheritance without losing string-form requirements.
/// Member feature/optional settings remain on the raw member declaration.
pub fn cargo_dependency_value<'a>(
    root: &Path,
    manifest_directory: &Path,
    manifest: &'a RustCargoManifestDocument,
    exposed_name: &str,
    dependency: &'a toml::Value,
    manifests: &'a HashMap<PathBuf, RustCargoManifestDocument>,
) -> Option<(&'a toml::Value, PathBuf)> {
    let Some(table) = dependency.as_table() else {
        return Some((dependency, manifest_directory.to_path_buf()));
    };
    if !table
        .get("workspace")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
    {
        return Some((dependency, manifest_directory.to_path_buf()));
    }
    let workspace_directory =
        cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)?;
    let dependency = manifests
        .get(&workspace_directory)?
        .get("workspace")?
        .get("dependencies")?
        .get(exposed_name)?;
    Some((dependency, workspace_directory))
}

#[allow(clippy::too_many_arguments)]
pub fn cargo_dependency_directory_with(
    root: &Path,
    manifest_directory: &Path,
    manifest: &RustCargoManifestDocument,
    exposed_name: &str,
    raw_dependency: &toml::Value,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
    resolve_path: &mut impl FnMut(&Path, &Path) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let effective = cargo_dependency_value(
        root,
        manifest_directory,
        manifest,
        exposed_name,
        raw_dependency,
        manifests,
    );
    let dependency = effective
        .as_ref()
        .and_then(|(value, directory)| value.as_table().map(|table| (table, directory)));
    dependency
        .as_ref()
        .and_then(|(dependency, _)| dependency.get("path"))
        .and_then(toml::Value::as_str)
        .and_then(|path| {
            resolve_path(
                effective
                    .as_ref()
                    .map(|(_, base)| base.as_path())
                    .unwrap_or(manifest_directory),
                Path::new(path),
            )
        })
        .or_else(|| {
            // `[patch]` lives on the workspace manifest and in the Cargo
            // configuration read from the workspace root, and names the
            // package, not the exposed alias. Resolve both here so the patch
            // lookup below reads already-resolved inputs.
            let dependency = dependency.as_ref().map(|(dependency, _)| *dependency);
            let package_name = dependency
                .and_then(|dependency| dependency.get("package"))
                .and_then(toml::Value::as_str)
                .unwrap_or(exposed_name);
            let workspace_directory =
                cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)?;
            cargo_patched_dependency_directory(
                root,
                &workspace_directory,
                package_name,
                dependency,
                effective
                    .as_ref()
                    .map_or(raw_dependency, |(value, _)| *value),
                manifests,
                configuration,
                resolve_path,
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn cargo_patched_dependency_directory(
    root: &Path,
    workspace_directory: &Path,
    package_name: &str,
    dependency: Option<&toml::map::Map<String, toml::Value>>,
    raw_dependency: &toml::Value,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
    resolve_path: &mut impl FnMut(&Path, &Path) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let source_name = cargo_dependency_patch_source(dependency, raw_dependency)?;
    let configured = configuration.patches(workspace_directory, source_name);
    let manifest_patches = manifests
        .get(workspace_directory)
        .and_then(|manifest| manifest.get("patch"))
        .and_then(|patch| patch.get(source_name))
        .and_then(toml::Value::as_table);
    // A configuration patch replaces the manifest's patch of the same name,
    // as Cargo's `Workspace::root_patch` combines them. Each entry resolves
    // its `path` against the directory that defined it.
    let patches = configured
        .iter()
        .map(|patch| (patch.name.as_str(), &patch.entry, patch.base.as_path()))
        .chain(
            manifest_patches
                .into_iter()
                .flatten()
                .filter(|(name, _)| !configured.iter().any(|patch| patch.name == **name))
                .filter_map(|(name, patch)| {
                    Some((name.as_str(), patch.as_table()?, workspace_directory))
                }),
        );
    let version_requirement =
        match cargo_dependency_version_requirement(dependency, raw_dependency)? {
            Some(requirement) => Some(VersionReq::parse(requirement).ok()?),
            None => None,
        };
    let mut compatible_directories = patches
        .filter(|(patch_name, patch, _)| {
            *patch_name == package_name
                || patch.get("package").and_then(toml::Value::as_str) == Some(package_name)
        })
        .filter_map(|(_, patch, base)| {
            let path = patch.get("path")?.as_str().map(Path::new)?;
            let directory = resolve_path(base, path)?;
            let patched_manifest = manifests.get(&directory)?;
            let package = patched_manifest.get("package")?.as_table()?;
            if package.get("name")?.as_str()? != package_name {
                return None;
            }
            let patched_version =
                cargo_package_string(root, &directory, patched_manifest, manifests, "version")
                    .and_then(|version| Version::parse(&version).ok())?;
            version_requirement
                .as_ref()
                .is_none_or(|requirement| requirement.matches(&patched_version))
                .then_some(directory)
        })
        .collect::<Vec<_>>();
    compatible_directories.sort();
    compatible_directories.dedup();
    match compatible_directories.as_slice() {
        [directory] => Some(directory.clone()),
        _ => None,
    }
}

fn cargo_dependency_patch_source<'a>(
    dependency: Option<&'a toml::map::Map<String, toml::Value>>,
    raw_dependency: &'a toml::Value,
) -> Option<&'a str> {
    let table = dependency.or_else(|| raw_dependency.as_table());
    if table.is_some_and(|dependency| dependency.contains_key("path")) {
        return None;
    }
    if let Some(git) = table
        .and_then(|dependency| dependency.get("git"))
        .and_then(toml::Value::as_str)
    {
        return Some(git);
    }
    match table
        .and_then(|dependency| dependency.get("registry"))
        .and_then(toml::Value::as_str)
    {
        None | Some("crates-io") => Some("crates-io"),
        Some(_) => None,
    }
}

fn cargo_dependency_version_requirement<'a>(
    dependency: Option<&'a toml::map::Map<String, toml::Value>>,
    raw_dependency: &'a toml::Value,
) -> Option<Option<&'a str>> {
    let version = dependency
        .and_then(|dependency| dependency.get("version"))
        .and_then(toml::Value::as_str)
        .or_else(|| raw_dependency.as_str());
    if dependency.is_none() && raw_dependency.as_table().is_some() {
        return None;
    }
    Some(version)
}

pub fn cargo_package_string(
    root: &Path,
    manifest_directory: &Path,
    manifest: &RustCargoManifestDocument,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
    field: &str,
) -> Option<String> {
    let value = manifest.get("package")?.get(field)?;
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    if !value
        .as_table()
        .and_then(|value| value.get("workspace"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    cargo_workspace_manifest_directory(root, manifest_directory, manifest, manifests)
        .and_then(|workspace_directory| manifests.get(&workspace_directory))
        .and_then(|workspace| workspace.get("workspace"))
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get(field))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

pub fn cargo_workspace_manifest_directory(
    root: &Path,
    manifest_directory: &Path,
    manifest: &RustCargoManifestDocument,
    manifests: &HashMap<PathBuf, RustCargoManifestDocument>,
) -> Option<PathBuf> {
    let explicit_workspace = manifest
        .get("package")
        .and_then(|package| package.get("workspace"))
        .and_then(toml::Value::as_str)
        .and_then(|path| {
            root.join(manifest_directory)
                .join(path)
                .normalize()
                .strip_prefix(root.to_path_buf().normalize())
                .ok()
                .map(Path::to_path_buf)
        });
    explicit_workspace
        .or_else(|| {
            manifest_directory.ancestors().find_map(|directory| {
                manifests
                    .get(directory)
                    .filter(|manifest| manifest.get("workspace").is_some())
                    .map(|_| directory.to_path_buf())
            })
        })
        .or_else(|| {
            manifest
                .get("package")
                .is_some()
                .then(|| manifest_directory.to_path_buf())
        })
}

/// Cargo workspace exclusions are literal directories, including descendants.
/// Leading `.` components have the same meaning as when Cargo joins the path
/// to the workspace root. Member discovery and retained inventories share it.
pub(crate) fn cargo_workspace_exclude_covers(excluded: &Path, relative: &Path) -> bool {
    relative.starts_with(
        excluded
            .components()
            .filter(|part| *part != std::path::Component::CurDir)
            .collect::<PathBuf>(),
    )
}

pub(super) use crate::cargo_manifest::normalize_crate_name;

fn append_module_package(mut package: String, nested: Option<&str>) -> String {
    let Some(nested) = nested else {
        return package;
    };
    if !package.is_empty() {
        package.push('.');
    }
    package.push_str(nested);
    package
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::write_fixture_file as write;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Parser;

    // rust_case_fold_key panics when its passes do not settle. The fold maps
    // each character on its own, so a path settles once every character does:
    // check every scalar value settles within the key's pass budget.
    #[test]
    fn every_character_reaches_its_case_fold_key_within_the_pass_budget() {
        let unsettled: Vec<char> = (0..=char::MAX as u32)
            .filter_map(char::from_u32)
            .filter(|c| {
                let mut key = case_fold_pass(&c.to_string());
                for _ in 0..CASE_FOLD_EXTRA_PASSES {
                    let next = case_fold_pass(&key);
                    if next == key {
                        return false;
                    }
                    key = next;
                }
                true
            })
            .collect();
        assert!(unsettled.is_empty(), "{unsettled:?}");
    }

    fn coordinated_route_facts(file: &ProjectFile, source: &str) -> RustModuleRouteFacts {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        assert!(
            !tree.root_node().has_error(),
            "fixture must parse: {source}"
        );
        crate::declarations::parse_rust_file_with(
            &crate::crate_naming::RustCrateNamingCaches::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::retain_nothing(),
            ),
            file,
            source,
            &tree,
        )
        .rust_usage_facts
        .module_routes
    }

    fn inline_fixture_file() -> ProjectFile {
        ProjectFile::new(
            std::env::temp_dir()
                .canonicalize()
                .expect("absolute fixture root"),
            "bifrost-inline/src/lib.rs",
        )
    }

    /// Gating verdict for the single `mod_item` in `source`.
    fn module_is_test_gated(source: &str) -> bool {
        let file = inline_fixture_file();
        let facts = coordinated_route_facts(&file, source);
        facts
            .routes
            .iter()
            .find(|route| route.module_name == "tests")
            .map(|route| route.test_gated)
            .expect("fixture declares a tests module")
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: An absolute path inside the canonical workspace must normalize to a contained relative path, while a sibling/outside path fails; the symlink/escape integration fixtures do not cover an absolute in-root input."
    )]
    fn workspace_relative_paths_accept_contained_absolute_targets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(root.join("inside")).expect("inside directory");
        let root = root.canonicalize().expect("canonical root");
        let inside = root
            .join("inside")
            .canonicalize()
            .expect("canonical inside");
        let outside = temp.path().canonicalize().expect("canonical outside");

        let files = HashSet::default();
        let naming = crate::crate_naming::RustSelectedCargoNaming::from_naming_records(
            std::iter::empty(),
            &[],
        );
        let paths = SelectedRustRoutePathFacts::new(&files, &naming);
        assert_eq!(
            paths.workspace_relative(&root, Path::new("ignored"), &inside),
            Some(PathBuf::from("inside"))
        );
        assert_eq!(
            paths.workspace_relative(&root, Path::new("ignored"), &outside),
            None,
            "an absolute target outside the canonical workspace must remain rejected"
        );
    }

    #[test]
    #[hardwon(
        "36d2ca4645e4: Declarations for one child file under different owner modules or visibility are distinct facts; deduplicating by target alone would erase valid routes, and no source-driven test constructs that collision."
    )]
    fn external_module_declarations_deduplicate_by_full_sort_key() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let declaring_file = ProjectFile::new(root.clone(), "src/lib.rs");
        let target_file = ProjectFile::new(root, "src/child.rs");
        let declaration =
            |declaring_module: &str, visibility: RustVisibility| RustCargoModuleDeclaration {
                declaring_file: declaring_file.clone(),
                declaring_module: declaring_module.to_string(),
                target_file: target_file.clone(),
                visibility,
                declaration_start_byte: 0,
                visibility_start_byte: usize::MAX,
                imports_macros: false,
                test_gated: false,
            };
        let mut declarations = vec![
            declaration("crate.alpha", RustVisibility::Private),
            declaration("crate.beta", RustVisibility::Private),
            declaration("crate.alpha", RustVisibility::Private),
            declaration("crate.alpha", RustVisibility::Public),
        ];

        sort_and_dedup_external_module_declarations(&mut declarations);

        assert_eq!(declarations.len(), 3);
        assert_eq!(declarations[0].declaring_module, "crate.alpha");
        assert_eq!(declarations[1].declaring_module, "crate.alpha");
        assert_eq!(declarations[2].declaring_module, "crate.beta");
    }

    /// Every Rust file the fixture wrote, in the order an analyzed-file set
    /// presents them.
    fn analyzed_rust_files(root: &Path) -> Vec<ProjectFile> {
        let mut files = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("read fixture directory") {
                let path = entry.expect("fixture entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    let relative = path.strip_prefix(root).expect("relative fixture path");
                    files.push(ProjectFile::new(root.to_path_buf(), relative));
                }
            }
        }
        files.sort();
        files
    }

    /// The rows analysis would have written for each file, derived here by the
    /// same coordinated producer used by production parsing.
    fn route_facts_for(files: &[ProjectFile]) -> HashMap<ProjectFile, RustModuleRouteFacts> {
        let mut facts = HashMap::default();
        for file in files {
            let source = file.read_to_string().expect("read fixture file");
            facts.insert(file.clone(), coordinated_route_facts(file, &source));
        }
        facts
    }

    /// `crates` member crates, each with a library, a binary that shares the
    /// library's module files, and an integration test target, and `modules`
    /// module files each. The shape is deliberately uniform: what the sweep pin
    /// varies is the crate and target count, not the file count.
    fn synthetic_workspace(
        root: &Path,
        crates: usize,
        modules: usize,
    ) -> (Vec<ProjectFile>, HashMap<ProjectFile, RustModuleRouteFacts>) {
        let members: Vec<String> = (0..crates).map(|index| format!("\"c{index}\"")).collect();
        write(
            root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [{}]\nresolver = \"2\"\n",
                members.join(", ")
            ),
        );
        for index in 0..crates {
            let dependency = if index > 0 {
                format!(
                    "\n[dependencies]\nc{} = {{ path = \"../c{}\" }}\n",
                    index - 1,
                    index - 1
                )
            } else {
                String::new()
            };
            write(
                root,
                &format!("c{index}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"c{index}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{dependency}"
                ),
            );
            let declarations: String = (0..modules)
                .map(|module| format!("pub mod m{module};\n"))
                .collect();
            write(root, &format!("c{index}/src/lib.rs"), &declarations);
            write(root, &format!("c{index}/src/main.rs"), &declarations);
            for module in 0..modules {
                write(
                    root,
                    &format!("c{index}/src/m{module}.rs"),
                    "pub struct Marker;\n",
                );
            }
            write(root, &format!("c{index}/tests/t0.rs"), "mod helpers;\n");
            write(
                root,
                &format!("c{index}/tests/helpers.rs"),
                "pub fn helper() {}\n",
            );
        }
        let files = analyzed_rust_files(root);
        let facts = route_facts_for(&files);
        (files, facts)
    }

    /// The #1817 pin covers the per-target stages of the summary-row build.
    /// Its sweep count stays bounded independently of Cargo topology. The
    /// original commit holds the fail-before evidence for discovery orchestration.
    #[test]
    #[hardwon(
        "#1817: route construction repeated workspace-wide sweeps per crate and target, taking 9-19 seconds on rustc."
    )]
    fn a_cargo_route_build_sweeps_the_workspace_a_bounded_number_of_times() {
        let mut measured = Vec::new();
        for (crates, modules) in [(2usize, 24usize), (16usize, 3usize)] {
            let temp = tempfile::tempdir().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            let (files, facts) = synthetic_workspace(&root, crates, modules);
            let records = (0..crates)
                .map(|index| {
                    (
                        PathBuf::from(format!("c{index}/Cargo.toml")),
                        format!("c{index}"),
                        PathBuf::from("src/lib.rs"),
                    )
                })
                .collect::<Vec<_>>();
            let naming = crate::crate_naming::RustSelectedCargoNaming::from_naming_records(
                files.iter().map(|file| file.rel_path().to_path_buf()),
                &records,
            );
            let selected = files.iter().cloned().collect();
            let paths = SelectedRustRoutePathFacts::new(&selected, &naming);
            let rows =
                (0..crates)
                    .flat_map(|index| {
                        let root = &root;
                        [
                            ("lib", "src/lib.rs"),
                            ("bin", "src/main.rs"),
                            ("test", "tests/t0.rs"),
                            ("test", "tests/helpers.rs"),
                        ]
                        .into_iter()
                        .enumerate()
                        .map(move |(target, (kind, path))| RustCargoRouteSummaryRow {
                            unit_key: [(index * 4 + target) as u8; 32],
                            manifest_directory: Some(PathBuf::from(format!("c{index}"))),
                            target_kind: kind.to_string(),
                            crate_name: format!("c{index}"),
                            edition: "2021".to_string(),
                            development_capable: kind == "test",
                            root_file: Some(ProjectFile::new(
                                root.clone(),
                                format!("c{index}/{path}"),
                            )),
                            root_package: (kind == "lib").then(|| format!("c{index}")),
                            dependency_extern_name: None,
                            dependency_kind: None,
                            dependency_boundary: None,
                            dependency_unit_key: None,
                            dependency_target_kind: None,
                            dependency_root_file: None,
                            dependency_root_package: None,
                            dependency_manifest_directory: None,
                        })
                    })
                    .collect::<Vec<_>>();
            let sweeps = workspace_file_sweeps_of(|| {
                RustCargoRouteIndex::build_from_summary_rows_with_path_facts(
                    &files,
                    &facts,
                    &rows,
                    &paths,
                    &|| true,
                )
                .expect("composed summary index");
            });
            measured.push((crates, files.len(), sweeps));
        }
        let [(small_crates, _, small), (large_crates, _, large)] = measured.as_slice() else {
            unreachable!("two measurements: {measured:?}");
        };
        assert_eq!(
            small, large,
            "the sweep count must not depend on the crate count ({small_crates} against {large_crates} crates): {measured:?}"
        );
        assert!(
            *large <= 8,
            "the build must sweep the workspace a bounded number of times: {measured:?}"
        );
    }

    #[test]
    fn only_a_bare_cfg_test_attribute_gates_a_module_declaration() {
        assert!(module_is_test_gated("#[cfg(test)]\nmod tests;\n"));
        assert!(module_is_test_gated("#[cfg(test)] pub mod tests;\n"));
        assert!(
            module_is_test_gated("#[cfg(test)]\n#[allow(dead_code)]\nmod tests;\n"),
            "the gate may sit anywhere in the attribute run"
        );
        assert!(
            module_is_test_gated("#[cfg(test)]\n// the sibling test module\nmod tests;\n"),
            "comments do not participate in attribute attachment"
        );

        assert!(!module_is_test_gated("mod tests;\n"));
        assert!(!module_is_test_gated(
            "#[cfg(any(test, feature = \"test-support\"))]\nmod tests;\n"
        ));
        assert!(!module_is_test_gated("#[cfg(all(test))]\nmod tests;\n"));
        assert!(!module_is_test_gated("#[cfg(not(test))]\nmod tests;\n"));
        assert!(
            !module_is_test_gated("#[cfg(feature = \"test\")]\nmod tests;\n"),
            "a feature merely named `test` is not the `test` predicate"
        );
        assert!(
            !module_is_test_gated("#[cfg_attr(test, allow(dead_code))]\nmod tests;\n"),
            "`cfg_attr` re-gates other attributes; it does not gate the item"
        );
        assert!(
            !module_is_test_gated("#[test]\nmod tests;\n"),
            "a bare `#[test]` is a test-case attribute, not a compilation gate"
        );
    }
}
