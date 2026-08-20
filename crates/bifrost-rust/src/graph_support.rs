use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::common::node_ident_text;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    ALIAS_SUBSTITUTION_RULE, RewriteOutcome, RewriteStep, RewriteTrace,
};
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::analyzer::{CodeUnitIndex, default_parent_fq_name};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::profiling;
use std::cell::{OnceCell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

use crate::cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
use crate::crate_naming;
use crate::declarations::{rust_node_text, rust_package_name};
use crate::imports::{
    RustVisibility, resolve_rust_module_path_with_crate, rust_crate_root_package,
    rust_imports_with_visibility_from_use_declaration, rust_item_visibility,
    rust_target_kind_root_alternative,
};
use crate::lexical_scope::{parse_rust_tree, visible_import_binder_at};
use crate::usage::exported_targets_from_files;
use crate::usage_queries::RustDeclarationFacts;
use crate::usage_walks::RustWalkCaches;
use brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts;

/// The bounded indexes Rust's language logic resolves through, plus the core
/// capability traits it reads declarations with. The analyzer implements this
/// by forwarding to its own accessors; every free
/// function in this module and its siblings sees only this surface, so none of
/// them can reach back into the analyzer type.
///
/// The persisted usage facts are deliberately absent: the Cargo route
/// composition and the declaration walk take this trait, so neither can reach
/// the rows whose extraction they precede. Code that answers a usage question
/// takes [`RustFactSource`].
pub trait RustSource:
    CodeUnitIndex + ImportAnalysisProvider + TypeAliasProvider + TypeHierarchyProvider
{
    /// The same index this trait already extends, for handing to the free
    /// functions whose whole input is a declaration store.
    fn code_units(&self) -> &dyn CodeUnitIndex;

    /// The declaration's syntactic owner, which unlike
    /// [`CodeUnitIndex::parent_of`] never falls back to a definition-row lookup.
    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit>;

    /// The parsed tree and its source backing for `file`.
    ///
    /// The [`QueryToken`] is proof that a request scope is open, so the cache
    /// this reads is live (issue #2414 step 3).
    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<PreparedSyntaxTree>>;

    fn cargo_routes(&self) -> Arc<RustCargoRouteIndex>;

    /// [`Self::cargo_routes`], abandoning a cold build when `keep_going` stops
    /// permitting it. The usage-index build pays for this index on the same
    /// request thread, so a cancelled request must not be stuck behind it.
    /// `dyn` rather than a generic so the trait stays object-safe.
    fn cargo_routes_while(
        &self,
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<Arc<RustCargoRouteIndex>>;

    fn package_file_index(&self) -> Arc<RustPackageFileIndex>;

    fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder;

    fn export_index_of(&self, file: &ProjectFile) -> Arc<ExportIndex>;

    fn note_module_file_resolution(&self);

    /// Narrow instrumentation hook for the streaming reference-resolution
    /// complexity pins. Implementations count one requested export-name walk.
    fn note_export_name_canonicalization(&self);
}

/// The file-to-blob mapping in both directions, as an object-safe view.
///
/// A store-backed Rust answer starts from a blob oid an inverted lookup
/// returned and has to reach the live `ProjectFile`s that currently hold those
/// bytes, and the reverse. The mapping itself is `LiveSnapshot`, which lives in
/// `brokk-bifrost-analysis` and cannot be named here, so the analyzer hands
/// this view down instead.
pub trait RustLiveBlobs: Send + Sync {
    fn oid_for_path(&self, file: &ProjectFile) -> Option<git2::Oid>;
    fn paths_for_oid(&self, oid: git2::Oid) -> Vec<ProjectFile>;
}

/// [`RustSource`] plus the persisted per-file Rust usage facts, the bounded
/// caches the cross-file walks memoize into, and the facts query-scoped
/// reference contexts resolve lazily.
///
/// Everything here is something only the analyzer can answer: the store handle
/// behind the four inverted lookups, the live blob mapping, the caches it owns,
/// the catch-up that guarantees the rows exist before a walk reads them. Code
/// that runs before any of that
/// exists -- the Cargo route composition, the declaration walk -- takes
/// [`RustSource`] instead, so it cannot re-enter what it is filling.
pub trait RustFactSource: RustSource {
    /// One blob's persisted facts, memoized per `(generation, blob)`.
    ///
    /// `None` when the blob has no rows, which a caller treats as "no facts"
    /// rather than as an error; the catch-up is what makes that state narrow.
    fn rust_usage_facts_of_blob(&self, oid: git2::Oid) -> Option<Arc<RustUsageFacts>>;

    /// Blobs that import `module_path`, spelled exactly as written. Candidates,
    /// never answers -- see `usage_queries.rs` for the contract.
    fn rust_import_target_blobs(&self, module_path: &str) -> Vec<git2::Oid>;

    /// Blobs whose structured imports name `component` as an imported module
    /// or as the last component of the module path. Candidates, never answers.
    fn rust_module_import_candidate_blobs(&self, component: &str) -> Vec<git2::Oid>;

    /// Blobs that re-export `exported_name`.
    fn rust_export_blobs(&self, exported_name: &str) -> Vec<git2::Oid>;

    /// Blobs whose text mentions `identifier`, with the occurrence-context
    /// bitmask each one carries.
    fn rust_identifier_occurrence_blobs(&self, identifier: &str) -> Vec<(git2::Oid, u32)>;

    /// Blobs with an `include!` whose literal's last path component is
    /// `file_name`. The inverted direction of `rust_include_edges`, and the
    /// seed of an include-route walk.
    fn rust_include_blobs(&self, file_name: &str) -> Vec<git2::Oid>;

    /// Every blob that writes at least one `include!`. Bounded by the number of
    /// files that use the macro, not by the workspace.
    fn rust_include_host_blobs(&self) -> Vec<git2::Oid>;

    /// One file's declaration identities and their visibility domains, derived
    /// once per file and then served from the analyzer's bounded cache.
    fn rust_declaration_facts_of(&self, file: &ProjectFile) -> Arc<RustDeclarationFacts>;

    fn live_blobs(&self) -> Arc<dyn RustLiveBlobs>;

    fn walk_caches(&self) -> &Arc<RustWalkCaches>;

    /// Ensure every live Rust file's blob carries fact rows before a walk reads
    /// them. Runs at most once per analyzer generation.
    fn ensure_rust_facts_caught_up(&self);

    fn reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a>;

    fn reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>>;

    fn forward_reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a>;

    fn forward_reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>>;
}

#[derive(Clone, Copy, Debug)]
pub struct ReferenceContextInterrupted;

pub type ReferenceContextResult<T> = Result<T, ReferenceContextInterrupted>;

pub fn reference_context_checkpoint(progress: &dyn Fn() -> bool) -> ReferenceContextResult<()> {
    progress().then_some(()).ok_or(ReferenceContextInterrupted)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RustReferenceQuery {
    Bare(String),
    ScopedOwner(String),
}

/// Query-scoped reference resolution for Rust. Construction is deliberately
/// near-free; imports, declarations, and export closures are read only for the
/// names a caller actually asks about.
///
/// Rust node fqns are file-independent dotted module paths (`util.format_value`),
/// so a resolved value *is* the graph node key — projecting to the node fqn is the
/// identity. (For JS/TS, where fqns are bare, the resolved value must carry the
/// file; see the execplan's "Identity model".)
pub struct RustReferenceContext<'a> {
    rust: &'a dyn RustFactSource,
    /// Proof that the request scope this context serves is open. The context
    /// is per-query and per-file, so it carries the proof for the syntax reads
    /// its resolutions make (issue #2414 step 3).
    token: QueryToken<'a>,
    file: ProjectFile,
    forward: bool,
    keep_going: Box<dyn Fn() -> bool + 'a>,
    package: String,
    crate_package: String,
    binder: OnceCell<ImportBinder>,
    same_file: OnceCell<HashMap<String, String>>,
    memo: RefCell<HashMap<RustReferenceQuery, Option<String>>>,
}

impl std::fmt::Debug for RustReferenceContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustReferenceContext")
            .field("file", &self.file)
            .field("forward", &self.forward)
            .field("package", &self.package)
            .field("crate_package", &self.crate_package)
            .field("memo", &self.memo)
            .finish_non_exhaustive()
    }
}

impl<'a> RustReferenceContext<'a> {
    pub fn new(
        rust: &'a dyn RustFactSource,
        token: QueryToken<'a>,
        file: &ProjectFile,
        forward: bool,
        keep_going: Box<dyn Fn() -> bool + 'a>,
    ) -> Self {
        Self {
            rust,
            token,
            file: file.clone(),
            forward,
            keep_going,
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            binder: OnceCell::new(),
            same_file: OnceCell::new(),
            memo: RefCell::new(HashMap::default()),
        }
    }

    /// The request-scope proof this context was built with (issue #2414 step 3).
    pub fn token(&self) -> QueryToken<'a> {
        self.token
    }

    fn going(&self) -> bool {
        (self.keep_going)()
    }

    fn binder(&self) -> &ImportBinder {
        self.binder
            .get_or_init(|| self.rust.import_binder_of(&self.file))
    }

    fn same_file(&self) -> &HashMap<String, String> {
        self.same_file.get_or_init(|| {
            self.rust
                .declarations(&self.file)
                .into_iter()
                .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
                .collect()
        })
    }

    /// The callee fqn a bare `name` refers to: a named import, a same-file item,
    /// or a free function imported via `use path::func;` (the binder classifies
    /// the latter as a namespace whose resolved value is the function's own fqn).
    pub fn resolve_bare(&self, name: &str) -> Option<String> {
        self.answer(RustReferenceQuery::Bare(name.to_string()))
    }

    pub fn bare_names_resolving_to(&self, target_fqn: &str) -> HashSet<String> {
        let terminal = target_fqn.rsplit('.').next().unwrap_or(target_fqn);
        let mut candidates = HashSet::from_iter([terminal.to_string()]);
        candidates.extend(
            self.same_file()
                .iter()
                .filter(|(_, fqn)| *fqn == target_fqn)
                .map(|(name, _)| name.clone()),
        );
        candidates.extend(
            self.binder()
                .bindings
                .iter()
                .filter(|(_, binding)| {
                    matches!(binding.kind, ImportKind::Named | ImportKind::Namespace)
                })
                .map(|(local, _)| local.clone()),
        );
        candidates.extend(
            self.rust
                .export_index_of(&self.file)
                .exports_by_name
                .iter()
                .filter(|(exported, entry)| {
                    exported.as_str() == terminal
                        || matches!(entry, ExportEntry::ReexportedNamed { imported_name, .. } if imported_name == terminal)
                })
                .map(|(exported, _)| exported.clone()),
        );
        candidates
            .into_iter()
            .filter(|name| self.binds_target(name, target_fqn))
            .collect()
    }

    /// The callee fqn a `path::name` refers to: a module function via a namespace
    /// import, or an associated function on an imported / same-file type.
    pub fn resolve_scoped(&self, path: &str, name: &str) -> Option<String> {
        self.resolve_scoped_owner(path)
            .map(|owner| join_rust_fqn(&owner, name))
    }

    /// The owner fqn a scoped `path::name` begins from: a namespace import, a
    /// rooted module path, or an imported / same-file type.
    pub fn resolve_scoped_owner(&self, path: &str) -> Option<String> {
        self.answer(RustReferenceQuery::ScopedOwner(path.to_string()))
    }

    fn answer(&self, query: RustReferenceQuery) -> Option<String> {
        if let Some(cached) = self.memo.borrow().get(&query) {
            return cached.clone();
        }
        let answer = match &query {
            RustReferenceQuery::Bare(name) => self.compute_bare(name),
            RustReferenceQuery::ScopedOwner(path) => self.compute_scoped_owner(path),
        };
        self.memo.borrow_mut().insert(query, answer.clone());
        answer
    }

    fn compute_bare(&self, name: &str) -> Option<String> {
        self.going().then_some(())?;
        self.named_binding(name)
            .or_else(|| self.namespace_binding(name))
            .or_else(|| self.same_file().get(name).cloned())
            .or_else(|| self.glob_binding(name))
    }

    fn compute_scoped_owner(&self, path: &str) -> Option<String> {
        self.going().then_some(())?;
        if let Some(canonical) = self.scoped_binding(path) {
            return Some(canonical);
        }
        if let Some((module_path, item_name)) = path.rsplit_once("::")
            && let Some(package) = self.resolve_scoped_owner(module_path)
        {
            let resolved = join_rust_fqn(&package, item_name);
            // Direct Cargo test/bench/example targets own a private `crate::`
            // root, while `mod common;` can be physically shared at the target
            // kind root. Apply that fallback only to a rooted module prefix
            // with no private backing. Item paths continue through the normal
            // recursive owner/reexport tiers instead of being mistaken for a
            // complete module package.
            if is_rooted_rust_module_path(path)
                && let Some(shared) =
                    resolve_target_kind_root_module(self.rust, self.token, &self.file, &resolved)
            {
                return Some(shared);
            }
            return Some(resolved);
        }
        if let Some(package) = self.namespace_binding(path) {
            return Some(package);
        }
        if is_rooted_rust_module_path(path)
            && let Some(package) =
                resolve_rust_module_path_with_crate(&self.package, &self.crate_package, path)
        {
            return Some(package);
        }
        self.named_binding(path)
            .or_else(|| self.same_file().get(path).cloned())
            .or_else(|| self.glob_binding(path))
    }

    fn binds_target(&self, name: &str, target_fqn: &str) -> bool {
        self.named_binding(name).as_deref() == Some(target_fqn)
            || self.namespace_binding(name).as_deref() == Some(target_fqn)
            || self.same_file().get(name).map(String::as_str) == Some(target_fqn)
            || self.glob_binding(name).as_deref() == Some(target_fqn)
    }

    fn named_binding(&self, name: &str) -> Option<String> {
        if let Some(binding) = self.binder().bindings.get(name)
            && binding.kind == ImportKind::Named
            && let Some(imported) = binding.imported_name.as_deref()
        {
            let module_files =
                resolve_module_files(self.rust, self.token, &self.file, &binding.module_specifier);
            let resolved = self
                .canonical_export_fqn(&module_files, imported)
                .or_else(|| {
                    resolve_module_package(
                        self.rust,
                        self.token,
                        &self.file,
                        &binding.module_specifier,
                    )
                    .map(|package| join_rust_fqn(&package, imported))
                });
            if resolved.is_some() {
                return resolved;
            }
        }
        self.reexported_binding(name)
    }

    fn namespace_binding(&self, name: &str) -> Option<String> {
        let binding = self.binder().bindings.get(name)?;
        (binding.kind == ImportKind::Namespace)
            .then(|| {
                resolve_module_package(self.rust, self.token, &self.file, &binding.module_specifier)
            })
            .flatten()
    }

    fn reexported_binding(&self, name: &str) -> Option<String> {
        let export_index = self.rust.export_index_of(&self.file);
        if let Some(ExportEntry::ReexportedNamed {
            module_specifier,
            imported_name,
        }) = export_index.exports_by_name.get(name)
        {
            let module_files =
                resolve_module_files(self.rust, self.token, &self.file, module_specifier);
            let mut targets = self.exported_targets(&module_files, imported_name)?;
            if targets.is_empty() {
                targets.extend(rust_member_reexport_targets(
                    self.rust,
                    self.token,
                    &self.file,
                    module_specifier,
                    imported_name,
                ));
            }
            if targets.is_empty() {
                targets.extend(self.declaration_targets(&module_files, imported_name)?);
            }
            if let Some(fqn) = single_reexport_target_fqn(targets) {
                return Some(fqn);
            }
        }
        for star in &export_index.reexport_stars {
            self.going().then_some(())?;
            let module_files =
                resolve_module_files(self.rust, self.token, &self.file, &star.module_specifier);
            if !self.export_closure_exports(&module_files, name)? {
                continue;
            }
            let mut targets = self.exported_targets(&module_files, name)?;
            if targets.is_empty() {
                targets.extend(self.declaration_targets(&module_files, name)?);
            }
            if let Some(fqn) = single_reexport_target_fqn(targets) {
                return Some(fqn);
            }
        }
        None
    }

    fn glob_binding(&self, name: &str) -> Option<String> {
        let mut candidates = HashSet::default();
        for binding in self.binder().bindings.values() {
            if binding.kind != ImportKind::Glob {
                continue;
            }
            self.going().then_some(())?;
            let module_files =
                resolve_module_files(self.rust, self.token, &self.file, &binding.module_specifier);
            if self.export_closure_exports(&module_files, name)?
                && let Some(fqn) = self.canonical_export_fqn(&module_files, name)
            {
                candidates.insert(fqn);
            }
        }
        (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten()
    }

    fn scoped_binding(&self, path: &str) -> Option<String> {
        let (local, name) = path.split_once("::")?;
        if name.contains("::") {
            return None;
        }
        let binding = self.binder().bindings.get(local)?;
        if binding.kind != ImportKind::Namespace {
            return None;
        }
        let module_files =
            resolve_module_files(self.rust, self.token, &self.file, &binding.module_specifier);
        self.export_closure_exports(&module_files, name)?
            .then(|| self.canonical_export_fqn(&module_files, name))
            .flatten()
    }

    fn canonical_export_fqn(&self, module_files: &[ProjectFile], name: &str) -> Option<String> {
        canonical_export_fqn_from_files(
            self.rust,
            self.token,
            module_files,
            name,
            self.forward,
            &*self.keep_going,
        )
        .ok()
        .flatten()
    }

    fn exported_targets(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> Option<BTreeSet<(ProjectFile, String)>> {
        self.going().then_some(())?;
        if self.forward {
            forward_exported_targets_from_files_with_progress(
                self.rust,
                self.token,
                module_files,
                name,
                &*self.keep_going,
            )
            .ok()
        } else {
            Some(exported_targets_from_files(
                self.rust,
                self.token,
                module_files,
                name,
            ))
        }
    }

    fn declaration_targets(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> Option<Vec<(ProjectFile, String)>> {
        rust_declaration_targets_in_files_with_progress(
            self.rust.code_units(),
            module_files,
            name,
            &*self.keep_going,
        )
        .ok()
    }

    fn export_closure_exports(&self, module_files: &[ProjectFile], name: &str) -> Option<bool> {
        let mut visited = HashSet::default();
        let mut pending = module_files.to_vec();
        while let Some(file) = pending.pop() {
            self.going().then_some(())?;
            if !visited.insert(file.clone()) {
                continue;
            }
            let index = self.rust.export_index_of(&file);
            if index.exports_by_name.contains_key(name) {
                return Some(true);
            }
            for star in &index.reexport_stars {
                pending.extend(resolve_module_files(
                    self.rust,
                    self.token,
                    &file,
                    &star.module_specifier,
                ));
            }
        }
        Some(false)
    }
}

pub fn reference_context_of<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, false, Box::new(|| true))
}

pub fn reference_context_of_while<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
    keep_going: impl Fn() -> bool + 'a,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, false, Box::new(keep_going))
}

pub fn forward_reference_context_of<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, true, Box::new(|| true))
}

pub fn forward_reference_context_of_while<'a>(
    rust: &'a dyn RustFactSource,
    token: QueryToken<'a>,
    file: &ProjectFile,
    keep_going: impl Fn() -> bool + 'a,
) -> RustReferenceContext<'a> {
    RustReferenceContext::new(rust, token, file, true, Box::new(keep_going))
}

fn join_rust_fqn(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

/// The analyzed Rust files bucketed by their path-derived package name — the
/// indexed form of the two questions [`RustAnalyzer::resolve_module_files`] asks
/// of the workspace: "is this file analyzed?" and "which analyzed files spell
/// package `p`?".
///
/// Both were previously answered by materializing a fresh `BTreeSet` of every
/// analyzed file and recomputing the allocating `rust_package_name` for each of
/// them, *per call* — a whole-workspace sweep to answer a single-module question,
/// issued once per import binding per file per reference context (#1230 item 3).
/// The projection retains file identities and their path-derived package names
/// only: no declarations, file states, sources, or persisted rows, so it is a
/// pure reindex of data `get_analyzed_files` already returns and cannot change
/// what a resolution answers.
#[derive(Debug, Default)]
pub struct RustPackageFileIndex {
    /// Every analyzed file, in `get_analyzed_files` (sorted) order so membership
    /// is a binary search rather than a second owned copy of each file.
    files: Vec<ProjectFile>,
    /// Package name -> indices into `files`, ascending.
    by_package: HashMap<String, Vec<u32>>,
    /// Import crate name -> root package names, from nearby Cargo manifests.
    crate_packages_by_name: HashMap<String, Vec<String>>,
}

impl RustPackageFileIndex {
    pub fn build(files: BTreeSet<ProjectFile>) -> Self {
        let files: Vec<ProjectFile> = files.into_iter().collect();
        let mut by_package: HashMap<String, Vec<u32>> = HashMap::default();
        let mut crate_packages_by_name: HashMap<String, Vec<String>> = HashMap::default();
        for (index, file) in files.iter().enumerate() {
            let package = rust_package_name(file);
            by_package
                .entry(package.clone())
                .or_default()
                .push(u32::try_from(index).unwrap_or(u32::MAX));
            if let Some(crate_name) = manifest_crate_name(file) {
                let packages = crate_packages_by_name.entry(crate_name).or_default();
                if !packages.contains(&package) {
                    packages.push(package);
                }
            }
        }
        Self {
            files,
            by_package,
            crate_packages_by_name,
        }
    }

    pub fn contains(&self, file: &ProjectFile) -> bool {
        self.files.binary_search(file).is_ok()
    }

    pub fn files_in_package(&self, package: &str) -> impl Iterator<Item = &ProjectFile> {
        self.by_package
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|index| self.files.get(*index as usize))
    }

    fn crate_packages(&self, import_name: &str) -> &[String] {
        self.crate_packages_by_name
            .get(import_name)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

fn manifest_crate_name(file: &ProjectFile) -> Option<String> {
    let rel_path = file.rel_path();
    if !matches!(
        rel_path.file_name().and_then(|name| name.to_str()),
        Some("lib.rs" | "main.rs")
    ) {
        return None;
    }
    let source_dir = rel_path.parent()?;
    if source_dir.file_name().and_then(|name| name.to_str()) != Some("src") {
        return None;
    }
    let manifest =
        std::fs::read_to_string(file.root().join(source_dir.parent()?.join("Cargo.toml")))
            .ok()?
            .parse::<toml::Value>()
            .ok()?;
    let name = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(toml::Value::as_str)
        .or_else(|| {
            manifest
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(toml::Value::as_str)
        })?;
    Some(name.replace('-', "_"))
}

fn single_reexport_target_fqn(
    targets: impl IntoIterator<Item = (ProjectFile, String)>,
) -> Option<String> {
    let mut targets = targets.into_iter();
    let (target_file, target_name) = targets.next()?;
    targets
        .next()
        .is_none()
        .then(|| join_rust_fqn(&rust_package_name(&target_file), &target_name))
}

fn single_rust_target_fqn(
    index: &dyn CodeUnitIndex,
    targets: BTreeSet<(ProjectFile, String)>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    let mut fq_names = Vec::new();
    for (target_file, target_name) in targets {
        reference_context_checkpoint(progress)?;
        for unit in index.declarations(&target_file) {
            reference_context_checkpoint(progress)?;
            if unit.identifier() == target_name && is_rust_export_visible_declaration(index, &unit)
            {
                fq_names.push(unit.fq_name());
            }
        }
    }
    fq_names.sort();
    fq_names.dedup();
    Ok((fq_names.len() == 1).then(|| fq_names.remove(0)))
}

fn is_rooted_rust_module_path(path: &str) -> bool {
    path == "crate"
        || path == "self"
        || path == "super"
        || path.starts_with("crate::")
        || path.starts_with("self::")
        || path.starts_with("super::")
}

fn rust_declaration_targets_in_files(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
    name: &str,
) -> Vec<(ProjectFile, String)> {
    rust_declaration_targets_in_files_with_progress(index, files, name, &|| true)
        .expect("uninterrupted Rust declaration traversal")
}

fn rust_declaration_targets_in_files_with_progress(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
    name: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    let mut targets = Vec::new();
    for file in files {
        reference_context_checkpoint(progress)?;
        for unit in index.declarations(file) {
            reference_context_checkpoint(progress)?;
            if unit.identifier() == name {
                targets.push((file.clone(), unit.identifier().to_string()));
            }
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

pub fn resolve_visible_import_targets_forward(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    let mut targets =
        resolve_imported_export_from_binder_forward(rust, token, file, binder, reference);
    for (local_name, binding) in &binder.bindings {
        if local_name != reference || binding.kind != ImportKind::Named {
            continue;
        }
        let imported = binding.imported_name.as_deref().unwrap_or(reference);
        targets.extend(
            resolve_module_files(rust, token, file, &binding.module_specifier)
                .into_iter()
                .map(|target_file| (target_file, imported.to_string())),
        );
    }
    targets.sort();
    targets.dedup();
    targets
}

pub fn export_index_of_declarations(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
) -> ExportIndex {
    let _scope = profiling::scope("RustAnalyzer::export_index_of_declarations");
    let index_source = rust.code_units();
    let mut index = ExportIndex::empty();
    // Declaration visibility and re-exports are two projections of the same
    // file. Keep them on one prepared tree: the old path parsed the source
    // independently for visibility, then immediately requested the analyzer's
    // prepared syntax for `use` declarations.
    let prepared = rust.prepared_syntax(token, file);
    let export_visible = prepared.as_ref().map_or_else(
        || export_visible_declarations(index_source, file, declarations),
        |syntax| {
            export_visible_declarations_from_syntax(
                index_source,
                declarations,
                syntax.tree().root_node(),
                syntax.source(),
            )
        },
    );
    let mut external_visibility = HashMap::default();

    for code_unit in declarations {
        let identifier = code_unit.identifier().trim();
        if identifier.is_empty() || identifier.starts_with('_') {
            continue;
        }
        if !is_module_export_candidate(
            rust,
            file,
            code_unit,
            &export_visible,
            &mut external_visibility,
        ) {
            continue;
        }
        index.exports_by_name.insert(
            identifier.to_string(),
            ExportEntry::Local {
                local_name: identifier.to_string(),
            },
        );
    }

    if let Some(prepared) = prepared {
        let source = prepared.source();
        let root = prepared.tree().root_node();
        for index_in_root in 0..root.named_child_count() {
            let Some(node) = root.named_child(index_in_root) else {
                continue;
            };
            if node.kind() != "use_declaration" {
                continue;
            }
            for import in rust_imports_with_visibility_from_use_declaration(node, source) {
                if matches!(
                    import.visibility,
                    RustVisibility::Private | RustVisibility::SelfModule
                ) {
                    continue;
                }
                if import.info.is_wildcard {
                    if !import.path.is_empty() {
                        index.reexport_stars.push(ReexportStar {
                            module_specifier: import.path.join("::"),
                        });
                    }
                    continue;
                }
                let Some(imported_name) = import.path.last().cloned() else {
                    continue;
                };
                let Some(local_name) = import.info.local_name().map(str::to_string) else {
                    continue;
                };
                let module_specifier = import.path[..import.path.len() - 1].join("::");
                index.exports_by_name.insert(
                    local_name,
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    },
                );
            }
        }
    }

    index
}

/// The named/namespace/glob binder walk shared by the forward and inverted
/// export resolvers. `forward` selects which export walk answers a binding; the
/// rest of the traversal is identical, so the two entry points below wrap this
/// rather than duplicating it.
fn resolve_imported_export_from_binder_with_mode(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
    forward: bool,
) -> Vec<(ProjectFile, String)> {
    let index = rust.code_units();
    let mut targets = HashSet::default();
    let mut saw_explicit_binding = false;
    for (local_name, binding) in &binder.bindings {
        match binding.kind {
            ImportKind::Named if local_name == reference => {
                saw_explicit_binding = true;
                let imported = binding.imported_name.as_deref().unwrap_or(reference);
                let files = resolve_module_files(rust, token, file, &binding.module_specifier);
                targets.extend(if forward {
                    forward_exported_targets_from_files(rust, token, &files, imported)
                } else {
                    exported_targets_from_files(rust, token, &files, imported)
                });
                if targets.is_empty() {
                    targets.extend(rust_declaration_targets_in_files(index, &files, imported));
                }
            }
            ImportKind::Namespace if local_name == reference => {
                saw_explicit_binding = true;
                let Some((module_specifier, imported)) = binding.module_specifier.rsplit_once("::")
                else {
                    continue;
                };
                let files = resolve_module_files(rust, token, file, module_specifier);
                targets.extend(if forward {
                    forward_exported_targets_from_files(rust, token, &files, imported)
                } else {
                    exported_targets_from_files(rust, token, &files, imported)
                });
                if targets.is_empty() {
                    targets.extend(rust_declaration_targets_in_files(index, &files, imported));
                }
            }
            ImportKind::Named
            | ImportKind::Namespace
            | ImportKind::Default
            | ImportKind::CommonJsRequire
            | ImportKind::Glob => {}
        }
    }
    if saw_explicit_binding {
        let mut sorted: Vec<_> = targets.into_iter().collect();
        sorted.sort();
        return sorted;
    }
    for binding in binder.bindings.values() {
        if matches!(binding.kind, ImportKind::Glob) {
            let files = resolve_module_files(rust, token, file, &binding.module_specifier);
            targets.extend(if forward {
                forward_exported_targets_from_files(rust, token, &files, reference)
            } else {
                exported_targets_from_files(rust, token, &files, reference)
            });
        }
    }
    let mut sorted: Vec<_> = targets.into_iter().collect();
    sorted.sort();
    sorted
}

pub fn resolve_imported_export_from_binder_forward(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    resolve_imported_export_from_binder_with_mode(rust, token, file, binder, reference, true)
}

pub fn resolve_imported_export_from_binder(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    resolve_imported_export_from_binder_with_mode(rust, token, file, binder, reference, false)
}

/// Resolve a `use`-path module specifier (e.g. `crate::util`, `crate::svc`)
/// to the dotted package it names, relative to `importing_file`. This is the
/// `package_name` half of a `CodeUnit::fq_name()` for items in that module, so
/// the inverted usage-graph builder can turn `(module_specifier, name)` into a
/// callee fqn without re-deriving the path arithmetic.
pub fn resolve_module_package(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Option<String> {
    resolve_module_package_traced(rust, token, importing_file, module_specifier, None)
}

/// [`resolve_module_package`], recording the import-alias chase into `trace`.
///
/// This is the *same* resolution: `resolve_module_package` is this function
/// with no collector, so an instrumented run takes exactly the branches a
/// production run takes. Every recording site is a no-op when `trace` is
/// `None`, so an uninstrumented resolution allocates nothing for it.
///
/// The chase is the bounded rewrite domain `rust_import_alias` (#1480): the
/// semantic state key is the specifier's root (the rewrite replaces only the
/// root, so the specifier grows every hop and can never repeat), the declared
/// bound is the binder's rewritable root count, and the terminal outcome is
/// converged, cycle, or exceeded-budget.
pub fn resolve_module_package_traced(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
    mut trace: Option<&mut RewriteTrace>,
) -> Option<String> {
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);
    if is_rooted_rust_module_path(module_specifier) {
        return resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier);
    }
    if let Some(package) = rust
        .cargo_routes()
        .resolve_module_package(importing_file, module_specifier)
    {
        return Some(package);
    }
    // Only after cargo routing fails — the miss path, not the hot path — try
    // a `use <crate> as <alias>` module alias so the binder is built solely
    // for unresolved roots (issue #1089). Chained renames in one file can
    // cycle (`use a::b as c` plus `use c::d as a`: zellij overflowed the
    // rayon worker stack recursing through them, #1347). The rewrite
    // replaces only the root, so the specifier grows every hop and a
    // whole-string visited set never trips; the cycle lives in root space
    // (the binder maps each root to exactly one target, so revisiting a
    // root is deterministically an infinite loop). Chase iteratively,
    // bounded by the binder's root count; a repeated root stops expanding
    // and the last specifier falls through to the path arithmetic.
    let mut seen_roots = HashSet::default();
    // The visited roots in order, so a cycle can report the sequence that
    // closes it. Only filled while tracing; an uninstrumented run leaves this
    // an unallocated `Vec`.
    let mut visited_order: Vec<String> = Vec::new();
    // The binder's rewritable root count: the finite state space this chase
    // walks, and therefore its declared bound. Computed on the first rewrite
    // rather than up front, so a specifier that never engages the alias rule
    // pays nothing for it.
    let mut declared_bound: Option<usize> = None;
    let mut steps_taken = 0usize;
    let mut current = module_specifier.to_string();
    loop {
        let root = current.split("::").next().unwrap_or(current.as_str());
        if !seen_roots.insert(root.to_string()) {
            if let Some(trace) = trace.as_deref_mut() {
                trace.finish(RewriteOutcome::Cycle {
                    witness: cycle_witness(&visited_order, root),
                });
            }
            break;
        }
        if trace.is_some() {
            visited_order.push(root.to_string());
        }
        let Some(aliased) = rust_apply_import_alias(rust, importing_file, &current) else {
            if let Some(trace) = trace.as_deref_mut() {
                trace.finish(RewriteOutcome::Converged {
                    fixed_point: current.clone(),
                });
            }
            break;
        };
        // Each rewrite consumes one distinct binder root, so `steps_taken`
        // can never pass the bound while the visited set still admits a hop;
        // this guard is the contract's explicit budget terminal rather than a
        // reachable branch. Keeping it in the production path is deliberate:
        // the instrumented chase and the production chase are one loop.
        let bound = *declared_bound
            .get_or_insert_with(|| rust.import_binder_of(importing_file).bindings.len());
        if steps_taken >= bound {
            if let Some(trace) = trace.as_deref_mut() {
                trace.finish(RewriteOutcome::ExceededBudget {
                    explored: steps_taken,
                });
            }
            break;
        }
        steps_taken += 1;
        if let Some(trace) = trace.as_deref_mut() {
            trace.declare_bound(bound);
            trace.record_step(RewriteStep {
                state_key: root.to_string(),
                input: current.clone(),
                output: aliased.clone(),
                rule: ALIAS_SUBSTITUTION_RULE,
            });
        }
        if let Some(package) =
            resolve_import_alias_exported_module_package(rust, token, importing_file, &aliased)
        {
            finish_converged(trace, &aliased);
            return Some(package);
        }
        if is_rooted_rust_module_path(&aliased) {
            finish_converged(trace, &aliased);
            return resolve_rust_module_path_with_crate(&package, &crate_package, &aliased);
        }
        if let Some(package) = rust
            .cargo_routes()
            .resolve_module_package(importing_file, &aliased)
        {
            finish_converged(trace, &aliased);
            return Some(package);
        }
        current = aliased;
    }
    resolve_rust_module_path_with_crate(&package, &crate_package, &current)
}

/// The ordered state sequence that closes a cycle: the visited roots from the
/// first occurrence of the repeated root onwards, with that root appended so
/// the sequence's last state is the one it repeats.
fn cycle_witness(visited_order: &[String], repeated: &str) -> Vec<String> {
    let start = visited_order
        .iter()
        .position(|state| state == repeated)
        .unwrap_or(0);
    let mut witness: Vec<String> = visited_order[start..].to_vec();
    witness.push(repeated.to_string());
    witness
}

/// Record convergence on `fixed_point` when the chase is instrumented.
///
/// A chase that returns from inside the loop converged just as much as one
/// that falls through: it reached a specifier the routing resolved, and no
/// further rewrite was applied.
fn finish_converged(trace: Option<&mut RewriteTrace>, fixed_point: &str) {
    if let Some(trace) = trace {
        trace.finish(RewriteOutcome::Converged {
            fixed_point: fixed_point.to_string(),
        });
    }
}

fn resolve_import_alias_exported_module_package(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    aliased_specifier: &str,
) -> Option<String> {
    let segments = parse_symbol_path(Language::Rust, aliased_specifier);
    let (root, suffix) = segments.split_first()?;
    let suffix = (!suffix.is_empty()).then_some(suffix)?;
    if rust_apply_import_alias(rust, importing_file, root).is_some() {
        return None;
    }
    let mut files = resolve_module_files(rust, token, importing_file, root);
    if files.is_empty() {
        return None;
    }
    let mut package = None;
    for segment in suffix {
        let target = forward_exported_module_fqn(rust, token, &files, segment)?;
        package = Some(target.clone());
        files = resolve_module_files(rust, token, importing_file, &target);
        if files.is_empty() {
            return None;
        }
    }
    package
}

fn forward_exported_module_fqn(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    name: &str,
) -> Option<String> {
    let mut pending = module_files
        .iter()
        .cloned()
        .map(|file| (file, name.to_string(), false))
        .collect::<Vec<_>>();
    let mut visited = HashSet::default();
    let mut targets = BTreeSet::new();
    while let Some((file, name, reached_through_reexport)) = pending.pop() {
        if !visited.insert((file.clone(), name.clone(), reached_through_reexport)) {
            continue;
        }
        let export_index = rust.export_index_of(&file);
        match export_index.exports_by_name.get(&name) {
            Some(ExportEntry::Local { local_name }) => {
                targets.extend(
                    rust.definitions(&format!("{}.{}", rust_package_name(&file), local_name))
                        .filter(|unit| unit.is_module())
                        .map(|unit| unit.fq_name()),
                );
            }
            Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) => {
                pending.extend(
                    resolve_module_files(rust, token, &file, module_specifier)
                        .into_iter()
                        .map(|target| (target, imported_name.clone(), true)),
                );
            }
            Some(ExportEntry::Default { .. } | ExportEntry::ReexportedModule { .. }) => {}
            None if reached_through_reexport => {
                targets.extend(
                    rust.definitions(&format!("{}.{}", rust_package_name(&file), name))
                        .filter(|unit| unit.is_module())
                        .map(|unit| unit.fq_name()),
                );
            }
            None => {}
        }
        for ReexportStar { module_specifier } in &export_index.reexport_stars {
            pending.extend(
                resolve_module_files(rust, token, &file, module_specifier)
                    .into_iter()
                    .map(|target| (target, name.clone(), true)),
            );
        }
    }
    (targets.len() == 1)
        .then(|| targets.into_iter().next())
        .flatten()
}

/// Resolve one export name after the caller has resolved the module files.
/// split out so callers that resolve every export name of *one* module
/// specifier route the invariant `resolve_module_files` once instead of once
/// per name (#1230 item 4).
#[doc(hidden)]
pub fn canonical_export_fqn_from_files(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    name: &str,
    forward: bool,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    rust.note_export_name_canonicalization();
    let targets = if forward {
        forward_exported_targets_from_files_with_progress(
            rust,
            token,
            module_files,
            name,
            progress,
        )?
    } else {
        exported_targets_from_files(rust, token, module_files, name)
    };
    single_rust_target_fqn(rust.code_units(), targets, progress)
}

pub fn forward_export_fqn_from_files(
    rust: &dyn RustFactSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    name: &str,
) -> Option<String> {
    if let Some(fqn) =
        canonical_export_fqn_from_files(rust, token, module_files, name, true, &|| true)
            .expect("uninterrupted Rust export traversal")
    {
        return Some(fqn);
    }
    let mut member_fqns = BTreeSet::new();
    for file in module_files {
        let index = rust.export_index_of(file);
        let Some(ExportEntry::ReexportedNamed {
            module_specifier,
            imported_name,
        }) = index.exports_by_name.get(name)
        else {
            continue;
        };
        let Some(owner_fqn) = resolve_module_package(rust, token, file, module_specifier) else {
            continue;
        };
        let target_fqn = join_rust_fqn(&owner_fqn, imported_name);
        if rust.definitions(&target_fqn).next().is_some() {
            member_fqns.insert(target_fqn);
        }
    }
    (member_fqns.len() == 1)
        .then(|| member_fqns.into_iter().next())
        .flatten()
}

pub fn forward_exported_targets_from_files(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    export_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    forward_exported_targets_from_files_with_progress(
        rust,
        token,
        module_files,
        export_name,
        &|| true,
    )
    .expect("uninterrupted Rust export traversal")
}

fn forward_exported_targets_from_files_with_progress(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    module_files: &[ProjectFile],
    export_name: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<BTreeSet<(ProjectFile, String)>> {
    let mut targets = BTreeSet::new();
    let mut visited = HashSet::default();
    let mut pending: Vec<_> = module_files
        .iter()
        .cloned()
        .map(|file| (file, export_name.to_string(), false))
        .collect();
    while let Some((file, name, reached_through_reexport)) = pending.pop() {
        reference_context_checkpoint(progress)?;
        if !visited.insert((file.clone(), name.clone(), reached_through_reexport)) {
            continue;
        }
        let index = rust.export_index_of(&file);
        match index.exports_by_name.get(&name) {
            Some(ExportEntry::Local { local_name }) => {
                targets.insert((file.clone(), local_name.clone()));
            }
            Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) => {
                let module_files = resolve_module_files(rust, token, &file, module_specifier);
                if module_files.is_empty() {
                    targets.extend(rust_member_reexport_targets(
                        rust,
                        token,
                        &file,
                        module_specifier,
                        imported_name,
                    ));
                } else {
                    pending.extend(
                        module_files
                            .into_iter()
                            .map(|target_file| (target_file, imported_name.clone(), true)),
                    );
                }
            }
            Some(ExportEntry::Default {
                local_name: Some(local_name),
            }) => {
                targets.insert((file.clone(), local_name.clone()));
            }
            Some(ExportEntry::Default { local_name: None })
            | Some(ExportEntry::ReexportedModule { .. }) => {}
            None if reached_through_reexport => {
                for unit in rust.declarations(&file) {
                    reference_context_checkpoint(progress)?;
                    if unit.identifier() == name
                        && is_rust_export_visible_declaration(rust.code_units(), &unit)
                    {
                        targets.insert((file.clone(), unit.identifier().to_string()));
                    }
                }
            }
            None => {}
        }
        for star in &index.reexport_stars {
            pending.extend(
                resolve_module_files(rust, token, &file, &star.module_specifier)
                    .into_iter()
                    .map(|target_file| (target_file, name.clone(), true)),
            );
        }
    }
    Ok(targets)
}

pub fn rust_member_reexport_targets(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner_path: &str,
    member_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let Some(owner_fqn) = resolve_module_package(rust, token, file, owner_path) else {
        return BTreeSet::new();
    };
    let target_fqn = join_rust_fqn(&owner_fqn, member_name);
    rust.definitions(&target_fqn)
        .map(|candidate| {
            (
                candidate.source().clone(),
                candidate.identifier().to_string(),
            )
        })
        .collect()
}

/// Rewrite a leading aliased `use` segment in `module_specifier` to the
/// imported path. `use forc_pkg::{self as pkg}` makes `pkg` (and `pkg::Item`)
/// mean `forc_pkg` (`forc_pkg::Item`), while `use a::b as c` makes `c` mean
/// `a::b`. Every module resolver must first substitute the alias before
/// routing; otherwise the alias root is unknown and draws a false "not
/// indexed" boundary even though the path is in the workspace (issue #1089).
pub fn rust_apply_import_alias(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Option<String> {
    let (root, rest) = module_specifier
        .split_once("::")
        .map_or((module_specifier, None), |(root, rest)| (root, Some(rest)));
    if root.is_empty() || matches!(root, "crate" | "self" | "super") {
        return None;
    }
    let binder = rust.import_binder_of(importing_file);
    let binding = binder.bindings.get(root)?;
    rewrite_import_alias_binding(root, rest, binding)
}

fn rewrite_import_alias_binding(
    root: &str,
    rest: Option<&str>,
    binding: &ImportBinding,
) -> Option<String> {
    let imported_name = match binding.kind {
        ImportKind::Namespace if binding.imported_name.is_none() => None,
        ImportKind::Named => Some(binding.imported_name.as_deref()?),
        _ => return None,
    };
    let target = binding.module_specifier.as_str();
    // Only a genuine rename (`use path as alias`) where the alias spelling
    // differs from the imported module's own last segment; an ordinary
    // `use a::b` binding names its own last segment and must not be rewritten
    // (that would loop or mis-route).
    let target_last_segment = imported_name.or_else(|| target.rsplit("::").next());
    if target.is_empty() || target == root || target_last_segment == Some(root) {
        return None;
    }
    Some(match (imported_name, rest) {
        (Some(imported_name), Some(rest)) => format!("{target}::{imported_name}::{rest}"),
        (Some(imported_name), None) => format!("{target}::{imported_name}"),
        (None, Some(rest)) => format!("{target}::{rest}"),
        (None, None) => target.to_string(),
    })
}

pub fn resolve_module_files(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Vec<ProjectFile> {
    rust.note_module_file_resolution();
    let analyzed_files = rust.package_file_index();
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);
    let rooted = is_rooted_rust_module_path(module_specifier);
    if !rooted
        && let Some(root_file) = rust
            .cargo_routes()
            .resolve_crate_root_file(importing_file, module_specifier)
    {
        return if analyzed_files.contains(&root_file) {
            vec![root_file]
        } else {
            Vec::new()
        };
    }
    let Some(resolved_module) = (if rooted {
        resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier)
    } else {
        resolve_module_package(rust, token, importing_file, module_specifier)
    }) else {
        return rust_module_files_from_path(importing_file, module_specifier);
    };

    let mut files: Vec<_> = analyzed_files
        .files_in_package(&resolved_module)
        .cloned()
        .collect();
    // Only units that *are* the module's definition back it. A bodiless
    // `mod svc;` item is a forwarder living in the declaring file, so
    // extending with its source handed every consumer lib.rs alongside the
    // real content file (#1342). An inline `mod svc { ... }` keeps its own
    // file: there the declaring file genuinely is the defining file.
    files.extend(
        rust.definitions(&resolved_module)
            .filter(|code_unit| {
                code_unit.is_module()
                    && !is_external_module_declaration(rust, token, code_unit)
                    && (code_unit.source() == importing_file
                        || is_visible_module_path(rust.code_units(), code_unit))
            })
            .map(|code_unit| code_unit.source().clone()),
    );
    files.extend(rust_module_files_from_path(
        importing_file,
        module_specifier,
    ));
    files.sort();
    files.dedup();
    // Path-derived Rust package names are shared by independent Cargo
    // examples, benches, and binaries. Rooted paths are crate-relative, so
    // only disambiguate when the package lookup actually collided: retain
    // physically shared targets when known, otherwise preserve unknown
    // relationships conservatively, and never cross a proven-disjoint root.
    if rooted && files.len() > 1 {
        let routes = rust.cargo_routes();
        let mut shared = Vec::new();
        let mut unknown = Vec::new();
        for candidate in files {
            match routes.target_relation(importing_file, &candidate) {
                RustCargoTargetRelation::Shared => shared.push(candidate),
                RustCargoTargetRelation::Unknown => unknown.push(candidate),
                RustCargoTargetRelation::Disjoint => {}
            }
        }
        return if shared.is_empty() { unknown } else { shared };
    }
    files
}

/// Re-spell one rooted module prefix under a Cargo target's shared kind root.
/// The private target spelling wins whenever it has a physical file or an
/// inline declaration in the importing file. The shared spelling must be
/// backed by a file Cargo classifies as shared; unknown and disjoint roots are
/// never admitted here.
fn resolve_target_kind_root_module(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    importing_file: &ProjectFile,
    resolved: &str,
) -> Option<String> {
    let files = rust.package_file_index();
    let routes = rust.cargo_routes();
    if files.files_in_package(resolved).next().is_some()
        || rust.definitions(resolved).any(|unit| {
            unit.is_module()
                && !is_external_module_declaration(rust, token, &unit)
                && unit.source() == importing_file
        })
    {
        return None;
    }
    let declares_external_module = rust.definitions(resolved).any(|unit| {
        unit.is_module()
            && is_external_module_declaration(rust, token, &unit)
            && unit.source() == importing_file
    });
    if !declares_external_module {
        return None;
    }
    let alternative = rust_target_kind_root_alternative(importing_file, resolved)?;
    let has_shared_file = files.files_in_package(&alternative).any(|candidate| {
        routes.target_relation(importing_file, candidate) == RustCargoTargetRelation::Shared
    });
    has_shared_file.then_some(alternative)
}

pub fn exact_member(
    index: &dyn CodeUnitIndex,
    source_file: &ProjectFile,
    owner_name: &str,
    member_name: &str,
    _instance_receiver: bool,
) -> Option<CodeUnit> {
    index
        .declarations(source_file)
        .into_iter()
        .find(|code_unit| {
            code_unit.identifier() == member_name
                && index
                    .parent_of(code_unit)
                    .map(|parent| parent.identifier() == owner_name)
                    .unwrap_or(false)
        })
}

pub fn rust_usage_candidate_files(
    rust: &dyn RustSource,
    export_names: HashSet<String>,
    target: &CodeUnit,
) -> HashSet<ProjectFile> {
    let owner_source = rust
        .parent_of(target)
        .map(|owner| owner.source().clone())
        .unwrap_or_else(|| target.source().clone());
    let member_name = target.identifier().to_string();

    let project = rust.project();
    rust.referencing_files_of(&owner_source)
        .into_iter()
        .filter(|file| {
            project.read_source(file).ok().is_some_and(|source| {
                export_names.iter().any(|name| source.contains(name))
                    || source.contains(&member_name)
            })
        })
        .collect()
}

pub fn trait_implementer_names(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    trait_owner: &CodeUnit,
    _importer_file: &ProjectFile,
) -> HashSet<String> {
    let project = rust.project();
    rust.get_analyzed_files()
        .into_iter()
        .filter_map(|file| {
            let source = project.read_source(&file).ok()?;
            Some((file, source))
        })
        .flat_map(|(file, source)| {
            let binder = rust.import_binder_of(&file);
            trait_implementer_names_from_source(rust, token, trait_owner, &file, &source, &binder)
        })
        .collect()
}

pub fn rust_trait_member_implementations(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    trait_member: &CodeUnit,
) -> Option<Vec<CodeUnit>> {
    let trait_owner = rust.parent_of(trait_member)?;
    if !is_rust_trait_declaration(rust.code_units(), &trait_owner) {
        return None;
    }
    let member_kind = rust_trait_member_kind(rust, trait_member)?;
    let member_name = trait_member.identifier();

    let mut implementations = Vec::new();
    let mut seen = HashSet::default();
    for file in rust.get_analyzed_files() {
        let Ok(source) = rust.project().read_source(&file) else {
            continue;
        };
        let Some(tree) = parse_rust_tree(&source) else {
            continue;
        };
        for impl_item in named_descendants_of_kind(tree.root_node(), "impl_item") {
            let Some((trait_ref, _implementer)) = trait_impl_parts(impl_item, &source) else {
                continue;
            };
            let binder = visible_import_binder_at(&source, impl_item.start_byte());
            if !trait_reference_matches(rust, token, &trait_owner, &file, &trait_ref, &binder) {
                continue;
            }
            for member_node in rust_impl_member_nodes(impl_item, &source, member_name, member_kind)
            {
                let Some(candidate) = rust_declaration_for_exact_node(
                    rust.code_units(),
                    &file,
                    member_node,
                    member_name,
                    member_kind,
                ) else {
                    continue;
                };
                if seen.insert(candidate.clone()) {
                    implementations.push(candidate);
                }
            }
        }
    }
    Some(implementations)
}

pub fn is_rust_trait_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| {
        node.kind() == "trait_item"
    })
}

pub fn is_rust_trait_impl_member_declaration(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| {
        let mut parent = node.parent();
        while let Some(candidate) = parent {
            if candidate.kind() == "impl_item" {
                return candidate.child_by_field_name("trait").is_some();
            }
            parent = candidate.parent();
        }
        false
    })
}

pub fn is_rust_struct_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| {
        node.kind() == "struct_item"
    })
}

pub fn has_rust_value_constructor(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, source| {
        rust_value_constructor_visibilities(node, source).is_some()
    })
}

pub fn is_rust_enum_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| node.kind() == "enum_item")
}

pub fn is_rust_enum_variant_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| {
        node.kind() == "enum_variant"
    })
}

pub fn is_rust_const_or_static_declaration(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| {
        matches!(node.kind(), "const_item" | "static_item")
    })
}

pub fn is_rust_type_alias_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, _source| node.kind() == "type_item")
}

pub fn is_rust_macro_export_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    code_unit.is_macro()
        && rust_declaration_node_is(index, code_unit, |node, source| {
            node.kind() == "macro_definition"
                && rust_item_has_attribute(node, source, "macro_export")
        })
}

pub fn is_rust_public_like_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, source| {
        rust_visibility_text(node, source).is_some_and(|visibility| visibility.starts_with("pub"))
    })
}

pub fn rust_declaration_visibility(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
) -> RustVisibility {
    let Some(prepared) = rust.prepared_syntax(token, code_unit.source()) else {
        return RustVisibility::Private;
    };
    inspect_rust_named_declaration_node(
        rust.code_units(),
        code_unit,
        prepared.tree().root_node(),
        prepared.source(),
        crate::imports::rust_item_visibility,
    )
    .unwrap_or(RustVisibility::Private)
}

/// Whether the declaration's own visibility makes it part of the crate's
/// exported surface (`pub` / `pub`), unlike the looser
/// [`Self::is_rust_public_like_declaration`] which also accepts module-private
/// forms such as `pub(self)`.
pub fn is_rust_export_visible_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    is_export_public_declaration(index, code_unit)
}

pub fn is_export_public_declaration(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    rust_declaration_node_is(index, code_unit, |node, source| {
        rust_visibility_text(node, source).is_some_and(is_export_visibility)
    })
}

pub fn export_visible_declarations(
    index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
) -> HashSet<CodeUnit> {
    let Ok(source) = index.project().read_source(file) else {
        return HashSet::default();
    };
    let Some(tree) = parse_rust_tree(&source) else {
        return HashSet::default();
    };
    export_visible_declarations_from_syntax(index, declarations, tree.root_node(), &source)
}

fn export_visible_declarations_from_syntax(
    index: &dyn CodeUnitIndex,
    declarations: &BTreeSet<CodeUnit>,
    root: Node<'_>,
    source: &str,
) -> HashSet<CodeUnit> {
    declarations
        .iter()
        .filter(|code_unit| {
            rust_declaration_node(index, code_unit, root)
                .and_then(|node| rust_visibility_text(node, source))
                .is_some_and(is_export_visibility)
        })
        .cloned()
        .collect()
}

/// Check export visibility with a source-aware owner walk.
///
/// Rust permits separate Cargo targets to reuse the same module FQN. The
/// generic CodeUnitIndex parent lookup returns the first matching definition,
/// which can select a private module from a Python binding target instead of
/// the public module that owns this declaration. Keep the owner walk on the
/// declaration's Cargo target so export indexes do not lose valid symbols.
pub fn is_module_export_candidate(
    rust: &dyn RustSource,
    file: &ProjectFile,
    code_unit: &CodeUnit,
    export_visible: &HashSet<CodeUnit>,
    external_visibility: &mut HashMap<CodeUnit, bool>,
) -> bool {
    if !export_visible.contains(code_unit) {
        return false;
    }

    let mut current = code_unit.clone();
    loop {
        let parent = match rust_export_parent(rust, &current) {
            RustExportParent::Parent(parent) => parent,
            RustExportParent::Root => return true,
            RustExportParent::Ambiguous => return false,
        };
        let parent_is_export_visible = if parent.source() == file {
            export_visible.contains(&parent)
        } else if let Some(visible) = external_visibility.get(&parent) {
            *visible
        } else {
            let visible = is_export_public_declaration(rust.code_units(), &parent);
            external_visibility.insert(parent.clone(), visible);
            visible
        };
        if !parent.is_module() || !parent_is_export_visible {
            return false;
        }
        current = parent;
    }
}

enum RustExportParent {
    Parent(CodeUnit),
    Root,
    Ambiguous,
}

fn rust_export_parent(rust: &dyn RustSource, code_unit: &CodeUnit) -> RustExportParent {
    if let Some(parent) = rust.structural_parent_of(code_unit) {
        return RustExportParent::Parent(parent);
    }
    let Some(owner_fq_name) = default_parent_fq_name(code_unit) else {
        return RustExportParent::Root;
    };
    let mut candidates = rust
        .code_units()
        .definitions(&owner_fq_name)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return RustExportParent::Root;
    }
    if let Some(local) = rust
        .cargo_routes()
        .candidates_in_same_target_root(code_unit.source(), candidates.clone())
    {
        candidates = local;
    }
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [] => RustExportParent::Root,
        [parent] => RustExportParent::Parent(parent.clone()),
        _ => RustExportParent::Ambiguous,
    }
}

pub fn is_visible_module_path(index: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    let mut current = code_unit.clone();
    loop {
        if !current.is_module() || !is_export_public_declaration(index, &current) {
            return false;
        }
        let Some(parent) = index.parent_of(&current) else {
            return true;
        };
        current = parent;
    }
}

/// Whether this module unit is a bodiless `mod x;` item, which forwards to a
/// definition in another file rather than being one.
///
/// Reads the cached prepared syntax rather than `rust_declaration_node_is`'s
/// own read-and-parse: `resolve_module_files` asks this per resolution, and
/// #1230 made that path per-call cheap.
pub fn is_external_module_declaration(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
) -> bool {
    if !code_unit.is_module() {
        return false;
    }
    let Some(prepared) = rust.prepared_syntax(token, code_unit.source()) else {
        return false;
    };
    inspect_rust_named_declaration_node(
        rust.code_units(),
        code_unit,
        prepared.tree().root_node(),
        prepared.source(),
        |node, _| node.kind() == "mod_item" && node.child_by_field_name("body").is_none(),
    )
    .unwrap_or(false)
}

pub fn rust_declaration_node_is<F>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    predicate: F,
) -> bool
where
    F: for<'tree> Fn(Node<'tree>, &str) -> bool,
{
    let Ok(source) = index.project().read_source(code_unit.source()) else {
        return false;
    };
    let Some(tree) = parse_rust_tree(&source) else {
        return false;
    };
    inspect_rust_named_declaration_node(index, code_unit, tree.root_node(), &source, predicate)
        .unwrap_or(false)
}

/// Inspect the syntax node for a declaration, including an item written inside
/// one or more item-position macro invocations.
///
/// The ordinary Rust tree parses a macro argument as a token tree. The
/// declaration collector reparses item-shaped arguments and stores their exact
/// source ranges, so metadata readers must repeat that structured reparse. Each
/// loop reparses a smaller enclosing token tree. This keeps nested item macros
/// stack safe and preserves the original byte offsets.
pub fn inspect_rust_named_declaration_node<T>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'_>,
    source: &str,
    inspect: impl for<'tree> Fn(Node<'tree>, &str) -> T,
) -> Option<T> {
    if let Some(node) = rust_named_declaration_node(index, code_unit, root, source) {
        return Some(inspect(node, source));
    }

    let range = index.ranges(code_unit).into_iter().next()?;
    let mut region = enclosing_macro_token_tree_interior(root, range.start_byte, range.end_byte)?;
    loop {
        let tree = crate::lexical_scope::parse_rust_region_tree(source, region.0, region.1)?;
        let reparsed_root = tree.root_node();
        if let Some(node) = rust_named_declaration_node(index, code_unit, reparsed_root, source) {
            return Some(inspect(node, source));
        }
        let next =
            enclosing_macro_token_tree_interior(reparsed_root, range.start_byte, range.end_byte)?;
        if next == region {
            return None;
        }
        region = next;
    }
}

fn enclosing_macro_token_tree_interior(
    root: Node<'_>,
    start_byte: usize,
    end_byte: usize,
) -> Option<(usize, usize)> {
    let mut node = root.descendant_for_byte_range(start_byte, end_byte)?;
    loop {
        if node.kind() == "macro_invocation" {
            let arguments = crate::declarations::rust_macro_invocation_arguments(node)?;
            let open = arguments.child(0)?;
            let close = arguments.child(arguments.child_count().checked_sub(1)?)?;
            if matches!(open.kind(), "(" | "[" | "{")
                && matches!(close.kind(), ")" | "]" | "}")
                && open.end_byte() <= start_byte
                && end_byte <= close.start_byte()
            {
                return Some((open.end_byte(), close.start_byte()));
            }
        }
        node = node.parent()?;
    }
}

pub fn rust_named_declaration_node<'tree>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut node = rust_declaration_node(index, code_unit, root)?;
    loop {
        if node
            .child_by_field_name("name")
            .is_some_and(|name| rust_declaration_name_matches(name, source, code_unit.identifier()))
        {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn rust_declaration_name_matches(name: Node<'_>, source: &str, identifier: &str) -> bool {
    rust_node_text(name, source).trim() == identifier
}

#[cfg(test)]
mod declaration_name_tests {
    use super::*;

    #[test]
    fn public_raw_field_name_matches_its_canonical_identifier() {
        let source = r#"pub struct DbColumn {
    pub r#type: String,
    pub type_name: String,
}
"#;
        let tree = parse_rust_tree(source).expect("parse Rust fixture");
        let fields = named_descendants_of_kind(tree.root_node(), "field_declaration");
        let raw_field = fields
            .iter()
            .copied()
            .find(|field| {
                field
                    .child_by_field_name("name")
                    .and_then(|name| source.get(name.byte_range()))
                    == Some("r#type")
            })
            .expect("raw field declaration");
        let name = raw_field
            .child_by_field_name("name")
            .expect("raw field name");

        assert!(rust_declaration_name_matches(name, source, "type"));
        assert_eq!(rust_visibility_text(raw_field, source), Some("pub"));
        assert!(
            !rust_declaration_name_matches(name, source, "type_name"),
            "normalization must not widen a raw identifier to a prefix near miss"
        );
    }
}

pub fn rust_declaration_node<'tree>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'tree>,
) -> Option<Node<'tree>> {
    let ranges = index.ranges(code_unit);
    let range = ranges.first()?;
    root.descendant_for_byte_range(range.start_byte, range.end_byte)
}

fn rust_declaration_for_exact_node(
    index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    node: Node<'_>,
    member_name: &str,
    member_kind: RustTraitMemberKind,
) -> Option<CodeUnit> {
    index
        .declarations(file)
        .into_iter()
        .filter(|unit| unit.identifier() == member_name)
        .filter(|unit| rust_code_unit_kind_matches(unit, member_kind))
        .find(|unit| {
            index.ranges(unit).iter().any(|range| {
                range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
            })
        })
}

pub fn rust_associated_type_declaration_for_exact_node(
    index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    node: Node<'_>,
    member_name: &str,
) -> Option<CodeUnit> {
    rust_declaration_for_exact_node(
        index,
        file,
        node,
        member_name,
        RustTraitMemberKind::AssociatedType,
    )
}

/// The visibility constraints on the value constructor introduced by a tuple
/// or unit struct. Named-field structs are constructed in the type namespace
/// and therefore return `None`.
pub fn rust_value_constructor_visibilities(
    node: Node<'_>,
    source: &str,
) -> Option<Vec<RustVisibility>> {
    if node.kind() != "struct_item" {
        return None;
    }

    let mut visibilities = vec![rust_item_visibility(node, source)];
    match node.child_by_field_name("body") {
        None => {}
        Some(body) if body.kind() == "ordered_field_declaration_list" => {
            let mut pending_visibility = None;
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                match child.kind() {
                    "attribute_item"
                    | "inner_attribute_item"
                    | "line_comment"
                    | "block_comment" => {}
                    "visibility_modifier" => {
                        pending_visibility = Some(rust_visibility_modifier(child, source));
                    }
                    _ => visibilities
                        .push(pending_visibility.take().unwrap_or(RustVisibility::Private)),
                }
            }
        }
        Some(_) => return None,
    }

    if rust_item_has_attribute(node, source, "non_exhaustive") {
        visibilities.push(RustVisibility::Crate);
    }
    Some(visibilities)
}

fn rust_visibility_modifier(node: Node<'_>, source: &str) -> RustVisibility {
    crate::imports::rust_visibility_from_modifier(node, source)
}

fn rust_item_has_attribute(node: Node<'_>, source: &str, expected: &str) -> bool {
    let mut sibling = node.prev_named_sibling();
    while let Some(attribute_item) = sibling {
        if attribute_item.kind() != "attribute_item" {
            break;
        }
        let Some(attribute) = attribute_item.named_child(0) else {
            break;
        };
        let Some(path) = attribute.named_child(0) else {
            break;
        };
        if source.get(path.start_byte()..path.end_byte()) == Some(expected) {
            return true;
        }
        sibling = attribute_item.prev_named_sibling();
    }
    false
}

#[derive(Clone, Copy)]
enum RustTraitMemberKind {
    AssociatedType,
    Method,
}

fn rust_trait_member_kind(
    rust: &dyn RustSource,
    trait_member: &CodeUnit,
) -> Option<RustTraitMemberKind> {
    if trait_member.is_function() {
        return Some(RustTraitMemberKind::Method);
    }
    if trait_member.is_field() && rust.is_type_alias(trait_member) {
        return Some(RustTraitMemberKind::AssociatedType);
    }
    None
}

fn rust_code_unit_kind_matches(code_unit: &CodeUnit, member_kind: RustTraitMemberKind) -> bool {
    match member_kind {
        RustTraitMemberKind::AssociatedType => code_unit.is_field(),
        RustTraitMemberKind::Method => code_unit.is_function(),
    }
}

fn rust_impl_member_nodes<'tree>(
    impl_item: Node<'tree>,
    source: &'tree str,
    member_name: &str,
    member_kind: RustTraitMemberKind,
) -> Vec<Node<'tree>> {
    let Some(body) = impl_item.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|child| rust_impl_member_node_matches(*child, source, member_name, member_kind))
        .collect()
}

fn rust_impl_member_node_matches(
    node: Node<'_>,
    source: &str,
    member_name: &str,
    member_kind: RustTraitMemberKind,
) -> bool {
    let expected_kind = match member_kind {
        RustTraitMemberKind::AssociatedType => "type_item",
        RustTraitMemberKind::Method => "function_item",
    };
    node.kind() == expected_kind
        && node
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == member_name)
}

/// The files that can back the module at `relative_module`, relative to
/// `file`'s own directory: `name.rs`, `name/mod.rs`, and the two `src/`-rooted
/// forms a crate root uses.
pub fn rust_module_files_at(file: &ProjectFile, relative_module: &Path) -> Vec<ProjectFile> {
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        Path::new("src").join(relative_module).with_extension("rs"),
        Path::new("src").join(relative_module).join("mod.rs"),
    ] {
        let candidate = file.with_rel_path(rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub fn rust_module_files_from_path(file: &ProjectFile, module_specifier: &str) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_path(file, module_specifier) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub fn rust_module_files_from_segments(
    file: &ProjectFile,
    segments: &[String],
) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_segments(file, segments) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

pub fn rust_relative_module_segments(file: &ProjectFile, segments: &[String]) -> Option<PathBuf> {
    let (first, rest) = segments.split_first()?;
    let append = |base: &mut PathBuf, parts: &[String]| {
        for part in parts {
            base.push(part);
        }
    };
    let mut module = match first.as_str() {
        "crate" | "self" => {
            let mut path = PathBuf::new();
            append(&mut path, rest);
            path
        }
        "super" => {
            let mut path = file
                .parent()
                .parent()
                .unwrap_or(Path::new(""))
                .to_path_buf();
            let mut index = 0;
            while rest.get(index).is_some_and(|part| part == "super") {
                path.pop();
                index += 1;
            }
            append(&mut path, &rest[index..]);
            path
        }
        crate_name if Some(crate_name) == crate_naming::rust_file_crate_name(file).as_deref() => {
            let mut path = PathBuf::new();
            append(&mut path, rest);
            path
        }
        _ => {
            let parent = file.rel_path().parent().unwrap_or(Path::new(""));
            let stem = file.rel_path().file_stem()?.to_str()?;
            let mut path = if matches!(stem, "lib" | "main" | "mod") {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            append(&mut path, segments);
            path
        }
    };
    (!module.as_os_str().is_empty()).then_some(std::mem::take(&mut module))
}

pub fn rust_relative_module_path(file: &ProjectFile, module_specifier: &str) -> Option<PathBuf> {
    let module = module_specifier
        .strip_prefix("crate::")
        .or_else(|| module_specifier.strip_prefix("self::"))
        .map(PathBuf::from)
        .or_else(|| {
            module_specifier
                .strip_prefix("super::")
                .map(|rest| file.parent().parent().unwrap_or(Path::new("")).join(rest))
        })
        .or_else(|| {
            let (crate_name, rest) = module_specifier.split_once("::")?;
            (Some(crate_name) == crate_naming::rust_file_crate_name(file).as_deref())
                .then(|| rest.into())
        })
        .or_else(|| {
            let relative = PathBuf::from(module_specifier);
            if relative.as_os_str().is_empty() {
                return None;
            }
            let parent = file.rel_path().parent().unwrap_or(Path::new(""));
            let stem = file.rel_path().file_stem()?.to_str()?;
            let module_root = if matches!(stem, "lib" | "main" | "mod") {
                parent.to_path_buf()
            } else {
                parent.join(stem)
            };
            Some(module_root.join(relative))
        })?;
    Some(module.to_string_lossy().replace("::", "/").into())
}

fn rust_visibility_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .find(|child| child.kind() == "visibility_modifier")
        .and_then(|child| source.get(child.start_byte()..child.end_byte()))
        .map(str::trim)
}

fn is_export_visibility(visibility: &str) -> bool {
    let compact: String = visibility
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    compact == "pub" || compact == "pub(crate)" || compact.starts_with("pub(incrate")
}

fn named_descendants_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            matches.push(current);
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    matches.reverse();
    matches
}

fn trait_implementer_names_from_source(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
) -> Vec<String> {
    let Some(tree) = parse_rust_tree(source) else {
        return Vec::new();
    };
    let mut implementers = Vec::new();
    collect_trait_implementer_names(
        tree.root_node(),
        rust,
        token,
        trait_owner,
        impl_file,
        source,
        binder,
        &mut implementers,
    );
    implementers
}

#[allow(clippy::too_many_arguments)]
fn collect_trait_implementer_names(
    node: Node<'_>,
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
    implementers: &mut Vec<String>,
) {
    if node.kind() == "impl_item"
        && let Some((trait_ref, implementer)) = trait_impl_parts(node, source)
        && trait_reference_matches(rust, token, trait_owner, impl_file, &trait_ref, binder)
    {
        implementers.push(implementer);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_trait_implementer_names(
            child,
            rust,
            token,
            trait_owner,
            impl_file,
            source,
            binder,
            implementers,
        );
    }
}

fn trait_impl_parts(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let trait_node = node.child_by_field_name("trait")?;
    let type_node = node.child_by_field_name("type")?;
    Some((
        node_text(trait_node, source).to_string(),
        simple_type_name(type_node, source)?,
    ))
}

fn simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => Some(node_text(node, source).to_string()),
        "scoped_type_identifier" | "scoped_identifier" => node
            .child_by_field_name("name")
            .map(|name| node_text(name, source).to_string()),
        "generic_type" | "reference_type" => node
            .named_children(&mut node.walk())
            .find_map(|child| simple_type_name(child, source)),
        _ => node
            .named_children(&mut node.walk())
            .find_map(|child| simple_type_name(child, source)),
    }
}

/// Same identifier-kind-gated `r#` stripping as `declarations::rust_node_text`,
/// applied here too so trait/impl member-name matching agrees with
/// normalized declaration names (#1128).
fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_ident_text(
        node,
        source,
        true,
        &crate::declarations::RUST_IDENTIFIER_SIGIL,
    )
}

fn trait_reference_matches(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    trait_ref: &str,
    impl_binder: &ImportBinder,
) -> bool {
    if let Some((module_specifier, imported_name)) = trait_ref.rsplit_once("::") {
        return imported_name == trait_owner.identifier()
            && resolve_module_files(rust, token, impl_file, module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source());
    }

    if impl_file == trait_owner.source() && trait_ref == trait_owner.identifier() {
        return true;
    }

    impl_binder
        .bindings
        .get(trait_ref)
        .filter(|binding| binding.imported_name.as_deref() == Some(trait_owner.identifier()))
        .is_some_and(|binding| {
            resolve_module_files(rust, token, impl_file, &binding.module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source())
        })
}

pub fn resolve_direct_import_files(
    rust: &dyn RustSource,
    importing_file: &ProjectFile,
    segments: &[String],
) -> Vec<ProjectFile> {
    let analyzed_files = rust.package_file_index();
    let package = rust_package_name(importing_file);
    let crate_package = rust_crate_root_package(importing_file);

    for end in (1..=segments.len()).rev() {
        let prefix = &segments[..end];
        let module_specifier = prefix.join("::");
        let rooted = is_rooted_rust_module_path(&module_specifier);
        let resolved_modules = if rooted {
            resolve_rust_module_path_with_crate(&package, &crate_package, &module_specifier)
                .into_iter()
                .collect::<Vec<_>>()
        } else if let Some((root, nested)) = prefix.split_first()
            && !analyzed_files.crate_packages(root).is_empty()
        {
            let suffix = nested.join(".");
            analyzed_files
                .crate_packages(root)
                .iter()
                .map(|package| {
                    if suffix.is_empty() {
                        package.clone()
                    } else {
                        format!("{package}.{suffix}")
                    }
                })
                .collect()
        } else {
            resolve_rust_module_path_with_crate(&package, &crate_package, &module_specifier)
                .into_iter()
                .collect()
        };
        let files = resolved_modules
            .into_iter()
            .flat_map(|module| {
                analyzed_files
                    .files_in_package(&module)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if !files.is_empty() {
            return files;
        }
    }

    Vec::new()
}
