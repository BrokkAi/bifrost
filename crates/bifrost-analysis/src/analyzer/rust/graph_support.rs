use crate::analyzer::usages::{ExportEntry, ExportIndex, ImportBinder, ImportKind, ReexportStar};
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::cell::{OnceCell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

use super::RustAnalyzer;
use super::cargo_routes::RustCargoTargetRelation;
use super::declarations::rust_package_name;
use super::imports::{
    RustVisibility, resolve_rust_module_path_with_crate, rust_crate_root_package,
    rust_item_visibility,
};
use super::lexical_scope::{insert_rust_import_binding, parse_rust_tree, visible_import_binder_at};
use super::usage_queries::RustUsageQueries;

#[derive(Clone, Copy, Debug)]
struct ReferenceContextInterrupted;

type ReferenceContextResult<T> = Result<T, ReferenceContextInterrupted>;

fn reference_context_checkpoint(progress: &dyn Fn() -> bool) -> ReferenceContextResult<()> {
    progress().then_some(()).ok_or(ReferenceContextInterrupted)
}

/// One resolution question, as the per-context memo keys it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RustReferenceQuery {
    /// "what does the bare name `n` mean in this file?"
    Bare(String),
    /// "what owner does the written path `p` begin from in this file?"
    ScopedOwner(String),
}

/// Per-file reference resolution for Rust — the one primitive both usage paths
/// share. It answers what a name written in one file means, one name at a time.
///
/// Rust node fqns are file-independent dotted module paths (`util.format_value`),
/// so a resolved value *is* the graph node key — projecting to the node fqn is the
/// identity. (For JS/TS, where fqns are bare, the resolved value must carry the
/// file; see the execplan's "Identity model".)
///
/// This used to be a bundle of eagerly filled maps built once per file and cached
/// on the analyzer. The two expensive maps enumerated and canonically resolved the
/// entire export surface of every namespace- and glob-imported module,
/// transitively through `pub use *`, before the file was scanned — and the scan
/// only ever consults this type when the fact-backed `usage_reference_at` cannot
/// answer a site, which is a small minority of sites. On the rustc tree that
/// precomputation was 1,062 s of a 1,034 s usage-graph phase. It is now computed
/// per question: see `.agents/plans/usage-graph-streaming.md`.
///
/// Construction is therefore deliberately near-free — two path-derived strings —
/// with the import binder and the same-file declaration map built on first use.
/// A value of this type is a query-scoped view over `&RustAnalyzer`, not a cache
/// entry: it borrows the analyzer, and its memo dies with it.
pub struct RustReferenceContext<'a> {
    rust: &'a RustAnalyzer,
    file: ProjectFile,
    /// Which way re-export chains are walked. The forward direction follows
    /// `pub use` towards the declaration; the reverse direction is the inverted
    /// graph builder's view.
    forward: bool,
    /// The caller's keep-going predicate. Every per-site walk polls it, and an
    /// interrupted resolution answers `None` rather than a partial answer.
    keep_going: Box<dyn Fn() -> bool + 'a>,
    /// Dotted module/package name for the file this context resolves from.
    package: String,
    /// Dotted module/package name for this file's crate root.
    crate_package: String,
    binder: OnceCell<ImportBinder>,
    /// identifier -> fqn for items declared in this file.
    same_file: OnceCell<HashMap<String, String>>,
    /// Answers already computed for this file during this query. Bounded by the
    /// distinct names the caller asks about, and dropped with the context, so it
    /// needs no weight and cannot grow with the workspace.
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
    fn new(
        rust: &'a RustAnalyzer,
        file: &ProjectFile,
        forward: bool,
        keep_going: Box<dyn Fn() -> bool + 'a>,
    ) -> Self {
        Self {
            rust,
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            file: file.clone(),
            forward,
            keep_going,
            binder: OnceCell::new(),
            same_file: OnceCell::new(),
            memo: RefCell::new(HashMap::default()),
        }
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
            let mut same_file = HashMap::default();
            for unit in self.rust.declarations(&self.file) {
                same_file.insert(unit.identifier().to_string(), unit.fq_name());
            }
            same_file
        })
    }

    /// The callee fqn a bare `name` refers to: a named import, a same-file item,
    /// or a free function imported via `use path::func;` (the binder classifies
    /// the latter as a namespace whose resolved value is the function's own fqn).
    pub fn resolve_bare(&self, name: &str) -> Option<String> {
        self.answer(RustReferenceQuery::Bare(name.to_string()))
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

    /// Local names in this file that bind `target_fqn` — the inverse question,
    /// used to seed the scan's name gate.
    ///
    /// Every candidate is resolved and compared, so the answer is always the
    /// resolver's own. What differs from the other methods is which names are
    /// worth asking about, and that is decided by cost, not by guessing:
    ///
    /// Every explicit binder binding is asked, because a `use` path can rename
    /// on the way (`barrel` re-exports `wide::Gadget as Renamed`, and
    /// `use crate::barrel::Renamed;` therefore binds `wide.Gadget` under a name
    /// that shares no spelling with it). There is no cheap test for that, and
    /// the count is bounded by the file's import list.
    ///
    /// The names this file itself exports are filtered on the target's terminal
    /// identifier — the last dotted segment of `target_fqn` — because a
    /// re-export binds a declaration with that identifier, so an export whose
    /// own name and whose imported name are both something else cannot be it.
    /// A barrel module can re-export thousands of names and resolving all of
    /// them per candidate file is the cost this design exists to remove. The
    /// residual gap is a re-export of this file that renames at a hop deeper
    /// than the first; the frozen equivalence fixture covers the first-hop
    /// case, which is the one that occurs.
    ///
    /// The terminal itself is always a candidate: it covers plain imports,
    /// globs, star re-exports, and same-file declarations in one entry.
    ///
    /// A candidate counts when *any* of the four binding kinds binds it to the
    /// target, not when the winner of their precedence does. The two differ
    /// when one kind shadows another: `consumer.rs` declares `AlphaItem` and
    /// also glob-imports `cyclic_a::AlphaItem`, so the name binds both, and the
    /// scan's name gate wants to hear about both — narrowing to the shadowing
    /// declaration alone would drop the glob-imported target's hits.
    pub(crate) fn bare_names_resolving_to(&self, target_fqn: &str) -> HashSet<String> {
        let terminal = target_fqn.rsplit('.').next().unwrap_or(target_fqn);
        let mut candidates: HashSet<String> = HashSet::default();
        candidates.insert(terminal.to_string());
        for (name, fqn) in self.same_file() {
            if fqn == target_fqn {
                candidates.insert(name.clone());
            }
        }
        for (local, binding) in &self.binder().bindings {
            if matches!(binding.kind, ImportKind::Named | ImportKind::Namespace) {
                candidates.insert(local.clone());
            }
        }
        for (exported_name, entry) in &self.rust.export_index_of(&self.file).exports_by_name {
            let carries_terminal = exported_name == terminal
                || matches!(
                    entry,
                    ExportEntry::ReexportedNamed { imported_name, .. } if imported_name == terminal
                );
            if carries_terminal {
                candidates.insert(exported_name.clone());
            }
        }
        candidates
            .into_iter()
            .filter(|name| self.binds_target(name, target_fqn))
            .collect()
    }

    fn binds_target(&self, name: &str, target_fqn: &str) -> bool {
        self.named_binding(name).as_deref() == Some(target_fqn)
            || self.namespace_binding(name).as_deref() == Some(target_fqn)
            || self.same_file().get(name).map(String::as_str) == Some(target_fqn)
            || self.glob_binding(name).as_deref() == Some(target_fqn)
    }

    fn answer(&self, query: RustReferenceQuery) -> Option<String> {
        if let Some(cached) = self.memo.borrow().get(&query) {
            return cached.clone();
        }
        // Computed outside any borrow of the memo: `resolve_scoped_owner`
        // recurses on the path prefix and would otherwise re-enter it.
        let answer = match &query {
            RustReferenceQuery::Bare(name) => self.compute_bare(name),
            RustReferenceQuery::ScopedOwner(path) => self.compute_scoped_owner(path),
        };
        self.memo.borrow_mut().insert(query, answer.clone());
        answer
    }

    fn compute_bare(&self, name: &str) -> Option<String> {
        if !self.going() {
            return None;
        }
        self.named_binding(name)
            .or_else(|| self.namespace_binding(name))
            .or_else(|| self.same_file().get(name).cloned())
            .or_else(|| self.glob_binding(name))
    }

    fn compute_scoped_owner(&self, path: &str) -> Option<String> {
        if !self.going() {
            return None;
        }
        if let Some(canonical) = self.scoped_binding(path) {
            return Some(canonical);
        }
        if let Some((module_path, item_name)) = path.rsplit_once("::")
            && let Some(package) = self.resolve_scoped_owner(module_path)
        {
            return Some(join_rust_fqn(&package, item_name));
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

    /// `use path::Item;` for this one local name, falling through to this file's
    /// own re-export of the name when the binder has nothing to say — the two
    /// producers that used to fill the `named` map, in the same precedence.
    fn named_binding(&self, name: &str) -> Option<String> {
        if let Some(binding) = self.binder().bindings.get(name)
            && binding.kind == ImportKind::Named
            && let Some(imported) = binding.imported_name.as_deref()
        {
            let module_files = self
                .rust
                .resolve_module_files(&self.file, &binding.module_specifier);
            let resolved = self
                .canonical_export_fqn(&module_files, imported)
                .or_else(|| {
                    self.rust
                        .resolve_module_package(&self.file, &binding.module_specifier)
                        .map(|package| join_rust_fqn(&package, imported))
                });
            if resolved.is_some() {
                return resolved;
            }
        }
        self.reexported_binding(name)
    }

    /// `use crate::util;` for this one local name.
    fn namespace_binding(&self, name: &str) -> Option<String> {
        let binding = self.binder().bindings.get(name)?;
        (binding.kind == ImportKind::Namespace)
            .then(|| {
                self.rust
                    .resolve_module_package(&self.file, &binding.module_specifier)
            })
            .flatten()
    }

    /// A name this file itself re-exports: an explicit `pub use path::Item;`
    /// first, then the star re-exports in declaration order. Only a re-export
    /// resolving to exactly one target binds the name, which is the rule
    /// `insert_single_reexport_target` enforced.
    fn reexported_binding(&self, name: &str) -> Option<String> {
        let export_index = self.rust.export_index_of(&self.file);
        if let Some(ExportEntry::ReexportedNamed {
            module_specifier,
            imported_name,
        }) = export_index.exports_by_name.get(name)
        {
            let module_files = self.rust.resolve_module_files(&self.file, module_specifier);
            let mut targets = self.exported_targets(&module_files, imported_name)?;
            if targets.is_empty() {
                targets.extend(self.rust.rust_member_reexport_targets(
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
            if !self.going() {
                return None;
            }
            let module_files = self
                .rust
                .resolve_module_files(&self.file, &star.module_specifier);
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

    /// `use path::*;` for this one name. A glob binds a name only when exactly
    /// one glob import in the file canonicalizes it, so every glob binding is
    /// asked — but each is asked about this name alone, not about its whole
    /// export closure.
    fn glob_binding(&self, name: &str) -> Option<String> {
        let mut candidates: HashSet<String> = HashSet::default();
        for binding in self.binder().bindings.values() {
            if binding.kind != ImportKind::Glob {
                continue;
            }
            if !self.going() {
                return None;
            }
            let module_files = self
                .rust
                .resolve_module_files(&self.file, &binding.module_specifier);
            if !self.export_closure_exports(&module_files, name)? {
                continue;
            }
            if let Some(fqn) = self.canonical_export_fqn(&module_files, name) {
                candidates.insert(fqn);
            }
        }
        (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten()
    }

    /// `local::Name` where `local` is a namespace import — the one question the
    /// eager `scoped` map precomputed for every export name of every
    /// namespace-imported module. It matters because a module can re-export a
    /// name it does not declare: `use crate::barrel;` then `barrel::Widget` is
    /// `wide.Widget`, which path arithmetic alone would answer `barrel.Widget`.
    fn scoped_binding(&self, path: &str) -> Option<String> {
        let (local, name) = path.split_once("::")?;
        if name.contains("::") {
            return None;
        }
        let binding = self.binder().bindings.get(local)?;
        if binding.kind != ImportKind::Namespace {
            return None;
        }
        let module_files = self
            .rust
            .resolve_module_files(&self.file, &binding.module_specifier);
        self.export_closure_exports(&module_files, name)?
            .then(|| self.canonical_export_fqn(&module_files, name))
            .flatten()
    }

    fn canonical_export_fqn(&self, module_files: &[ProjectFile], name: &str) -> Option<String> {
        self.rust
            .canonical_export_fqn_from_files(module_files, name, self.forward, &*self.keep_going)
            .ok()
            .flatten()
    }

    fn exported_targets(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> Option<BTreeSet<(ProjectFile, String)>> {
        if self.forward {
            self.rust
                .forward_exported_targets_from_files_with_progress(
                    module_files,
                    name,
                    &*self.keep_going,
                )
                .ok()
        } else {
            Some(self.rust.exported_targets_from_files(module_files, name))
        }
    }

    fn declaration_targets(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> Option<Vec<(ProjectFile, String)>> {
        rust_declaration_targets_in_files_with_progress(
            self.rust,
            module_files,
            name,
            &*self.keep_going,
        )
        .ok()
    }

    /// Whether `name` is an export name anywhere in the star-re-export closure
    /// reachable from `module_files`.
    ///
    /// This is the membership half of what `collect_export_names_from_files`
    /// used to materialize in full, short-circuiting on the first hit and
    /// keeping the same visited set — which is what stops a `pub use *` cycle.
    /// The gate matters for equivalence, not only for cost: the export walk's
    /// declaration fallback can reach a declaration that is visible on its own
    /// but is not a module export, and the eager builders never asked about
    /// such a name because it was not in the enumerated closure.
    fn export_closure_exports(&self, module_files: &[ProjectFile], name: &str) -> Option<bool> {
        let mut visited: HashSet<ProjectFile> = HashSet::default();
        let mut pending: Vec<ProjectFile> = module_files.to_vec();
        while let Some(module_file) = pending.pop() {
            if !self.going() {
                return None;
            }
            if !visited.insert(module_file.clone()) {
                continue;
            }
            let export_index = self.rust.export_index_of(&module_file);
            if export_index.exports_by_name.contains_key(name) {
                return Some(true);
            }
            for star in &export_index.reexport_stars {
                pending.extend(
                    self.rust
                        .resolve_module_files(&module_file, &star.module_specifier),
                );
            }
        }
        Some(false)
    }
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
pub(super) struct RustPackageFileIndex {
    /// Every analyzed file, in `get_analyzed_files` (sorted) order so membership
    /// is a binary search rather than a second owned copy of each file.
    files: Vec<ProjectFile>,
    /// Package name -> indices into `files`, ascending.
    by_package: HashMap<String, Vec<u32>>,
}

impl RustPackageFileIndex {
    fn build(files: BTreeSet<ProjectFile>) -> Self {
        let files: Vec<ProjectFile> = files.into_iter().collect();
        let mut by_package: HashMap<String, Vec<u32>> = HashMap::default();
        for (index, file) in files.iter().enumerate() {
            by_package
                .entry(rust_package_name(file))
                .or_default()
                .push(u32::try_from(index).unwrap_or(u32::MAX));
        }
        Self { files, by_package }
    }

    pub(super) fn contains(&self, file: &ProjectFile) -> bool {
        self.files.binary_search(file).is_ok()
    }

    pub(super) fn files_in_package(&self, package: &str) -> impl Iterator<Item = &ProjectFile> {
        self.by_package
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|index| self.files.get(*index as usize))
    }
}

/// The fqn a re-export binds, when exactly one target backs it. A re-export
/// that resolves to two declarations binds nothing: the written name is
/// ambiguous and the resolver must not pick one.
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
    analyzer: &RustAnalyzer,
    targets: BTreeSet<(ProjectFile, String)>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    let mut fq_names = Vec::new();
    for (target_file, target_name) in targets {
        reference_context_checkpoint(progress)?;
        for unit in analyzer.declarations(&target_file) {
            reference_context_checkpoint(progress)?;
            if unit.identifier() == target_name
                && analyzer.is_rust_export_visible_declaration(&unit)
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
    analyzer: &RustAnalyzer,
    files: &[ProjectFile],
    name: &str,
) -> Vec<(ProjectFile, String)> {
    rust_declaration_targets_in_files_with_progress(analyzer, files, name, &|| true)
        .expect("uninterrupted Rust declaration traversal")
}

fn rust_declaration_targets_in_files_with_progress(
    analyzer: &RustAnalyzer,
    files: &[ProjectFile],
    name: &str,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Vec<(ProjectFile, String)>> {
    let mut targets = Vec::new();
    for file in files {
        reference_context_checkpoint(progress)?;
        for unit in analyzer.declarations(file) {
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

impl RustAnalyzer {
    pub(crate) fn resolve_visible_import_targets_forward(
        &self,
        file: &ProjectFile,
        binder: &crate::analyzer::usages::ImportBinder,
        reference: &str,
    ) -> Vec<(ProjectFile, String)> {
        let mut targets = self.resolve_imported_export_from_binder_forward(file, binder, reference);
        for (local_name, binding) in &binder.bindings {
            if local_name != reference || binding.kind != ImportKind::Named {
                continue;
            }
            let imported = binding.imported_name.as_deref().unwrap_or(reference);
            targets.extend(
                self.resolve_module_files(file, &binding.module_specifier)
                    .into_iter()
                    .map(|target_file| (target_file, imported.to_string())),
            );
        }
        targets.sort();
        targets.dedup();
        targets
    }

    /// The cached per-file export index. Shared by handle: the index is
    /// immutable for the analyzer instance's lifetime, and callers ask for it
    /// once per export name per pending file, so deep-cloning the whole map on
    /// every cache hit was pure waste (#1230 item 5).
    pub fn export_index_of(&self, file: &ProjectFile) -> Arc<ExportIndex> {
        if let Some(cached) = self.export_indexes.get(file) {
            return cached;
        }
        let declarations = self.declarations(file);
        let index = Arc::new(self.export_index_of_declarations(file, &declarations));
        self.export_indexes.insert(file.clone(), index.clone());
        index
    }

    pub(super) fn export_index_of_declarations(
        &self,
        file: &ProjectFile,
        declarations: &BTreeSet<CodeUnit>,
    ) -> ExportIndex {
        let _scope = crate::profiling::scope("RustAnalyzer::export_index_of_declarations");
        let mut index = ExportIndex::empty();
        let export_visible = self.export_visible_declarations(file, declarations);
        let mut external_visibility = HashMap::default();

        for code_unit in declarations {
            let identifier = code_unit.identifier().trim();
            if identifier.is_empty() || identifier.starts_with('_') {
                continue;
            }
            if !self.is_module_export_candidate(
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

        // Re-exports come from the persisted per-file facts rather than from a
        // fresh syntax tree: `pub use` is a per-file fact, and reading the rows
        // keeps this off the parse path entirely (ExecPlan
        // `.agents/plans/rust-usage-index-v2.md`, Milestone 2). Local exports
        // above stay declaration-driven, because whether a declaration is
        // visible outside its module is a visibility question over
        // `code_units`, not something the file's `use` list can answer.
        for export in RustUsageQueries::new(self).re_exports_of(file) {
            if export.is_glob {
                index.reexport_stars.push(ReexportStar {
                    module_specifier: export.source_path,
                });
                continue;
            }
            let (Some(local_name), Some(imported_name)) =
                (export.exported_name, export.imported_name)
            else {
                continue;
            };
            index.exports_by_name.insert(
                local_name,
                ExportEntry::ReexportedNamed {
                    module_specifier: export.source_path,
                    imported_name,
                },
            );
        }

        index
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(file) {
            insert_rust_import_binding(&mut binder, &import);
        }

        binder
    }

    pub(crate) fn resolve_imported_export_from_binder_forward(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
    ) -> Vec<(ProjectFile, String)> {
        self.resolve_imported_export_from_binder_with_mode(file, binder, reference, true)
    }

    pub(crate) fn resolve_imported_export_from_binder(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
    ) -> Vec<(ProjectFile, String)> {
        self.resolve_imported_export_from_binder_with_mode(file, binder, reference, false)
    }

    fn resolve_imported_export_from_binder_with_mode(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
        forward: bool,
    ) -> Vec<(ProjectFile, String)> {
        let mut targets = HashSet::default();
        let mut saw_explicit_binding = false;
        for (local_name, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named if local_name == reference => {
                    saw_explicit_binding = true;
                    let imported = binding.imported_name.as_deref().unwrap_or(reference);
                    let files = self.resolve_module_files(file, &binding.module_specifier);
                    targets.extend(if forward {
                        self.forward_exported_targets_from_files(&files, imported)
                    } else {
                        self.exported_targets_from_files(&files, imported)
                    });
                    if targets.is_empty() {
                        targets.extend(rust_declaration_targets_in_files(self, &files, imported));
                    }
                }
                ImportKind::Namespace if local_name == reference => {
                    saw_explicit_binding = true;
                    let Some((module_specifier, imported)) =
                        binding.module_specifier.rsplit_once("::")
                    else {
                        continue;
                    };
                    let files = self.resolve_module_files(file, module_specifier);
                    targets.extend(if forward {
                        self.forward_exported_targets_from_files(&files, imported)
                    } else {
                        self.exported_targets_from_files(&files, imported)
                    });
                    if targets.is_empty() {
                        targets.extend(rust_declaration_targets_in_files(self, &files, imported));
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
                let files = self.resolve_module_files(file, &binding.module_specifier);
                targets.extend(if forward {
                    self.forward_exported_targets_from_files(&files, reference)
                } else {
                    self.exported_targets_from_files(&files, reference)
                });
            }
        }
        let mut sorted: Vec<_> = targets.into_iter().collect();
        sorted.sort();
        sorted
    }

    /// Resolve a `use`-path module specifier (e.g. `crate::util`, `super::svc`)
    /// to the dotted package it names, relative to `importing_file`. This is the
    /// `package_name` half of a `CodeUnit::fq_name()` for items in that module, so
    /// the inverted usage-graph builder can turn `(module_specifier, name)` into a
    /// callee fqn without re-deriving the path arithmetic.
    pub fn resolve_module_package(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        let package = rust_package_name(importing_file);
        let crate_package = rust_crate_root_package(importing_file);
        if is_rooted_rust_module_path(module_specifier) {
            return resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier);
        }
        if let Some(package) = self
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
        let mut current = module_specifier.to_string();
        loop {
            let root = current.split("::").next().unwrap_or(current.as_str());
            if !seen_roots.insert(root.to_string()) {
                break;
            }
            let Some(aliased) = self.rust_apply_import_alias(importing_file, &current) else {
                break;
            };
            if is_rooted_rust_module_path(&aliased) {
                return resolve_rust_module_path_with_crate(&package, &crate_package, &aliased);
            }
            if let Some(package) = self
                .cargo_routes()
                .resolve_module_package(importing_file, &aliased)
            {
                return Some(package);
            }
            current = aliased;
        }
        resolve_rust_module_path_with_crate(&package, &crate_package, &current)
    }

    /// A per-file reference resolver for this query — the one primitive both the
    /// inverted usage-graph builder and the forward scan resolve references
    /// through.
    ///
    /// Constructing one is near-free and answers nothing by itself; each
    /// question is answered when it is asked. There is deliberately no analyzer
    /// cache behind this: a resolver borrows the analyzer, and the two weighted
    /// caches it replaces were the ones whose weigher omitted their two
    /// unbounded maps.
    pub fn reference_context_of(&self, file: &ProjectFile) -> RustReferenceContext<'_> {
        RustReferenceContext::new(self, file, false, Box::new(|| true))
    }

    /// [`Self::reference_context_of`] carrying the caller's keep-going
    /// predicate, so a cancelled query stops inside resolution instead of at
    /// the next checkpoint above it.
    pub(crate) fn reference_context_of_while<'a>(
        &'a self,
        file: &ProjectFile,
        keep_going: impl Fn() -> bool + 'a,
    ) -> RustReferenceContext<'a> {
        RustReferenceContext::new(self, file, false, Box::new(keep_going))
    }

    pub(crate) fn forward_reference_context_of(
        &self,
        file: &ProjectFile,
    ) -> RustReferenceContext<'_> {
        RustReferenceContext::new(self, file, true, Box::new(|| true))
    }

    pub(crate) fn forward_reference_context_of_while<'a>(
        &'a self,
        file: &ProjectFile,
        keep_going: impl Fn() -> bool + 'a,
    ) -> RustReferenceContext<'a> {
        RustReferenceContext::new(self, file, true, Box::new(keep_going))
    }

    /// The canonical declaration fqn one export `name` of `module_files` binds,
    /// following re-export chains in the requested direction.
    ///
    /// This is the unit of work the reference resolver spends: one name, one
    /// walk. The eager builders ran it once per export name of every
    /// namespace- and glob-imported module before a file was scanned, which is
    /// what `export_name_canonicalization_count` measures.
    fn canonical_export_fqn_from_files(
        &self,
        module_files: &[ProjectFile],
        name: &str,
        forward: bool,
        progress: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Option<String>> {
        self.note_export_name_canonicalization();
        let targets = if forward {
            self.forward_exported_targets_from_files_with_progress(module_files, name, progress)?
        } else {
            self.exported_targets_from_files(module_files, name)
        };
        single_rust_target_fqn(self, targets, progress)
    }

    pub(crate) fn forward_export_fqn_from_files(
        &self,
        module_files: &[ProjectFile],
        name: &str,
    ) -> Option<String> {
        if let Some(fqn) = self
            .canonical_export_fqn_from_files(module_files, name, true, &|| true)
            .expect("uninterrupted Rust export traversal")
        {
            return Some(fqn);
        }
        let mut member_fqns = BTreeSet::new();
        for file in module_files {
            let index = self.export_index_of(file);
            let Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) = index.exports_by_name.get(name)
            else {
                continue;
            };
            let Some(owner_fqn) = self.resolve_module_package(file, module_specifier) else {
                continue;
            };
            let target_fqn = join_rust_fqn(&owner_fqn, imported_name);
            if self.definitions(&target_fqn).next().is_some() {
                member_fqns.insert(target_fqn);
            }
        }
        (member_fqns.len() == 1)
            .then(|| member_fqns.into_iter().next())
            .flatten()
    }

    /// Every export name reachable from `module_files` through star
    /// re-exports. Only the frozen equivalence algorithm needs the whole set;
    /// the live resolver asks
    /// [`RustReferenceContext::export_closure_exports`] about one name and
    /// stops at the first hit.
    #[cfg(test)]
    fn collect_export_names_from_files(
        &self,
        module_files: &[ProjectFile],
        visited: &mut HashSet<ProjectFile>,
        names: &mut HashSet<String>,
        progress: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<()> {
        let mut pending = module_files.to_vec();
        while let Some(module_file) = pending.pop() {
            reference_context_checkpoint(progress)?;
            if !visited.insert(module_file.clone()) {
                continue;
            }
            let export_index = self.export_index_of(&module_file);
            names.extend(export_index.exports_by_name.keys().cloned());
            for star in &export_index.reexport_stars {
                pending.extend(self.resolve_module_files(&module_file, &star.module_specifier));
            }
        }
        Ok(())
    }

    fn forward_exported_targets_from_files(
        &self,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        self.forward_exported_targets_from_files_with_progress(module_files, export_name, &|| true)
            .expect("uninterrupted Rust export traversal")
    }

    fn forward_exported_targets_from_files_with_progress(
        &self,
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
            let index = self.export_index_of(&file);
            match index.exports_by_name.get(&name) {
                Some(ExportEntry::Local { local_name }) => {
                    targets.insert((file.clone(), local_name.clone()));
                }
                Some(ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                }) => {
                    let module_files = self.resolve_module_files(&file, module_specifier);
                    if module_files.is_empty() {
                        targets.extend(self.rust_member_reexport_targets(
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
                Some(ExportEntry::Default { local_name: None }) => {}
                None if reached_through_reexport => {
                    for unit in self.declarations(&file) {
                        reference_context_checkpoint(progress)?;
                        if unit.identifier() == name
                            && self.is_rust_export_visible_declaration(&unit)
                        {
                            targets.insert((file.clone(), unit.identifier().to_string()));
                        }
                    }
                }
                None => {}
            }
            for star in &index.reexport_stars {
                pending.extend(
                    self.resolve_module_files(&file, &star.module_specifier)
                        .into_iter()
                        .map(|target_file| (target_file, name.clone(), true)),
                );
            }
        }
        Ok(targets)
    }

    fn rust_member_reexport_targets(
        &self,
        file: &ProjectFile,
        owner_path: &str,
        member_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        let Some(owner_fqn) = self.resolve_module_package(file, owner_path) else {
            return BTreeSet::new();
        };
        let target_fqn = join_rust_fqn(&owner_fqn, member_name);
        self.definitions(&target_fqn)
            .map(|candidate| {
                (
                    candidate.source().clone(),
                    candidate.identifier().to_string(),
                )
            })
            .collect()
    }

    /// Rewrite a leading `use <crate> as <alias>` module-alias segment in
    /// `module_specifier` to the aliased crate/module. `use forc_pkg::{self as
    /// pkg}` makes `pkg` (and `pkg::Item`) mean `forc_pkg` (`forc_pkg::Item`),
    /// so every module resolver must first substitute the alias before routing —
    /// otherwise the alias root is unknown and draws a false "not indexed"
    /// boundary even though the crate is in the workspace (issue #1089).
    fn rust_apply_import_alias(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Option<String> {
        let (root, rest) = module_specifier
            .split_once("::")
            .map_or((module_specifier, None), |(root, rest)| (root, Some(rest)));
        if root.is_empty() || matches!(root, "crate" | "self" | "super") {
            return None;
        }
        let binder = self.import_binder_of(importing_file);
        let binding = binder.bindings.get(root)?;
        if binding.kind != ImportKind::Namespace || binding.imported_name.is_some() {
            return None;
        }
        let target = binding.module_specifier.as_str();
        // Only a genuine rename (`use path as alias`) where the alias spelling
        // differs from the imported module's own last segment; an ordinary
        // `use a::b` namespace binding names its own last segment and must not
        // be rewritten (that would loop or mis-route).
        if target.is_empty() || target == root || target.rsplit("::").next() == Some(root) {
            return None;
        }
        Some(match rest {
            Some(rest) => format!("{target}::{rest}"),
            None => target.to_string(),
        })
    }

    /// The analyzed-file listing bucketed by path-derived Rust package name,
    /// built at most once per analyzer instance. Same lifetime and invalidation
    /// as `cargo_routes` — both are pure projections of the analyzed-file set,
    /// so both are rebuilt by `update`/`update_all`/`clone_with_project` and by
    /// nothing else (#1230 item 3).
    pub(super) fn package_file_index(&self) -> Arc<RustPackageFileIndex> {
        self.package_file_index
            .get_or_init(|| Arc::new(RustPackageFileIndex::build(self.get_analyzed_files())))
            .clone()
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        self.note_module_file_resolution();
        let analyzed_files = self.package_file_index();
        let package = rust_package_name(importing_file);
        let crate_package = rust_crate_root_package(importing_file);
        let rooted = is_rooted_rust_module_path(module_specifier);
        if !rooted
            && let Some(root_file) = self
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
            self.resolve_module_package(importing_file, module_specifier)
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
            self.inner
                .definitions(&resolved_module)
                .filter(|code_unit| {
                    code_unit.is_module()
                        && !self.is_external_module_declaration(code_unit)
                        && (code_unit.source() == importing_file
                            || self.is_visible_module_path(code_unit))
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
            let routes = self.cargo_routes();
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

    pub fn exact_member(
        &self,
        source_file: &ProjectFile,
        owner_name: &str,
        member_name: &str,
        _instance_receiver: bool,
    ) -> Option<CodeUnit> {
        self.declarations(source_file)
            .into_iter()
            .find(|code_unit| {
                code_unit.identifier() == member_name
                    && self
                        .parent_of(code_unit)
                        .map(|parent| parent.identifier() == owner_name)
                        .unwrap_or(false)
            })
    }

    pub fn rust_usage_candidate_files(
        &self,
        export_names: HashSet<String>,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        let owner_source = self
            .parent_of(target)
            .map(|owner| owner.source().clone())
            .unwrap_or_else(|| target.source().clone());
        let member_name = target.identifier().to_string();

        let project = self.inner.project();
        self.referencing_files_of(&owner_source)
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
        &self,
        trait_owner: &CodeUnit,
        _importer_file: &ProjectFile,
    ) -> HashSet<String> {
        let project = self.inner.project();
        self.get_analyzed_files()
            .into_iter()
            .filter_map(|file| {
                let source = project.read_source(&file).ok()?;
                Some((file, source))
            })
            .flat_map(|(file, source)| {
                let binder = self.import_binder_of(&file);
                trait_implementer_names_from_source(self, trait_owner, &file, &source, &binder)
            })
            .collect()
    }

    pub fn rust_trait_member_implementations(
        &self,
        trait_member: &CodeUnit,
    ) -> Option<Vec<CodeUnit>> {
        let trait_owner = self.parent_of(trait_member)?;
        if !self.is_rust_trait_declaration(&trait_owner) {
            return None;
        }
        let member_kind = rust_trait_member_kind(self, trait_member)?;
        let member_name = trait_member.identifier();

        let mut implementations = Vec::new();
        let mut seen = HashSet::default();
        for file in self.get_analyzed_files() {
            let Ok(source) = self.inner.project().read_source(&file) else {
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
                if !trait_reference_matches(self, &trait_owner, &file, &trait_ref, &binder) {
                    continue;
                }
                for member_node in
                    rust_impl_member_nodes(impl_item, &source, member_name, member_kind)
                {
                    let Some(candidate) = self.rust_declaration_for_exact_node(
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

    pub fn is_rust_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "trait_item")
    }

    pub(crate) fn is_rust_trait_impl_member_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| {
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

    pub(crate) fn is_rust_struct_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "struct_item")
    }

    pub(crate) fn has_rust_value_constructor(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_value_constructor_visibilities(node, source).is_some()
        })
    }

    pub(crate) fn is_rust_enum_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "enum_item")
    }

    pub(crate) fn is_rust_const_or_static_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| {
            matches!(node.kind(), "const_item" | "static_item")
        })
    }

    pub(crate) fn is_rust_type_alias_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, _source| node.kind() == "type_item")
    }

    pub(crate) fn is_rust_macro_export_declaration(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_macro()
            && self.rust_declaration_node_is(code_unit, |node, source| {
                node.kind() == "macro_definition"
                    && rust_item_has_attribute(node, source, "macro_export")
            })
    }

    pub(crate) fn is_rust_public_like_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_visibility_text(node, source)
                .is_some_and(|visibility| visibility.starts_with("pub"))
        })
    }

    pub(super) fn rust_declaration_visibility(&self, code_unit: &CodeUnit) -> RustVisibility {
        let Some(prepared) = self.prepared_syntax(code_unit.source()) else {
            return RustVisibility::Private;
        };
        self.rust_named_declaration_node(code_unit, prepared.tree().root_node(), prepared.source())
            .map(|node| super::imports::rust_item_visibility(node, prepared.source()))
            .unwrap_or(RustVisibility::Private)
    }

    /// Whether the declaration's own visibility makes it part of the crate's
    /// exported surface (`pub` / `pub(crate)`), unlike the looser
    /// [`Self::is_rust_public_like_declaration`] which also accepts module-private
    /// forms such as `pub(self)`.
    pub(crate) fn is_rust_export_visible_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.is_export_public_declaration(code_unit)
    }

    fn is_export_public_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.rust_declaration_node_is(code_unit, |node, source| {
            rust_visibility_text(node, source).is_some_and(is_export_visibility)
        })
    }

    fn export_visible_declarations(
        &self,
        file: &ProjectFile,
        declarations: &BTreeSet<CodeUnit>,
    ) -> HashSet<CodeUnit> {
        let Ok(source) = self.inner.project().read_source(file) else {
            return HashSet::default();
        };
        let Some(tree) = parse_rust_tree(&source) else {
            return HashSet::default();
        };
        declarations
            .iter()
            .filter(|code_unit| {
                self.rust_declaration_node(code_unit, tree.root_node())
                    .and_then(|node| rust_visibility_text(node, &source))
                    .is_some_and(is_export_visibility)
            })
            .cloned()
            .collect()
    }

    fn is_module_export_candidate(
        &self,
        file: &ProjectFile,
        code_unit: &CodeUnit,
        export_visible: &HashSet<CodeUnit>,
        external_visibility: &mut HashMap<CodeUnit, bool>,
    ) -> bool {
        if !export_visible.contains(code_unit) {
            return false;
        }

        // Candidacy is decided by the owner chain's kinds: a module export must
        // be reachable through an unbroken run of export-visible modules. A
        // method or associated function owned by a type fails right here, and a
        // function nested in another function's body likewise, so no separate
        // callable guard belongs after this loop. One that keyed on an owner
        // merely existing rejected every free function declared in a named
        // submodule -- the whole point of `pub mod x;` (#1341).
        let mut current = code_unit.clone();
        while let Some(parent) = self.parent_of(&current) {
            let parent_is_export_visible = if parent.source() == file {
                export_visible.contains(&parent)
            } else if let Some(visible) = external_visibility.get(&parent) {
                *visible
            } else {
                let visible = self.is_export_public_declaration(&parent);
                external_visibility.insert(parent.clone(), visible);
                visible
            };
            if !parent.is_module() || !parent_is_export_visible {
                return false;
            }
            current = parent;
        }

        true
    }

    pub(super) fn is_visible_module_path(&self, code_unit: &CodeUnit) -> bool {
        let mut current = code_unit.clone();
        loop {
            if !current.is_module() || !self.is_export_public_declaration(&current) {
                return false;
            }
            let Some(parent) = self.parent_of(&current) else {
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
    pub(crate) fn is_external_module_declaration(&self, code_unit: &CodeUnit) -> bool {
        if !code_unit.is_module() {
            return false;
        }
        let Some(prepared) = self.prepared_syntax(code_unit.source()) else {
            return false;
        };
        self.rust_named_declaration_node(code_unit, prepared.tree().root_node(), prepared.source())
            .is_some_and(|node| {
                node.kind() == "mod_item" && node.child_by_field_name("body").is_none()
            })
    }

    fn rust_declaration_node_is<F>(&self, code_unit: &CodeUnit, predicate: F) -> bool
    where
        F: FnOnce(Node<'_>, &str) -> bool,
    {
        let Ok(source) = self.inner.project().read_source(code_unit.source()) else {
            return false;
        };
        let Some(tree) = parse_rust_tree(&source) else {
            return false;
        };
        self.rust_named_declaration_node(code_unit, tree.root_node(), &source)
            .map(|node| predicate(node, &source))
            .unwrap_or(false)
    }

    pub(super) fn rust_named_declaration_node<'tree>(
        &self,
        code_unit: &CodeUnit,
        root: Node<'tree>,
        source: &str,
    ) -> Option<Node<'tree>> {
        let mut node = self.rust_declaration_node(code_unit, root)?;
        loop {
            if node.child_by_field_name("name").is_some_and(|name| {
                source.get(name.start_byte()..name.end_byte()) == Some(code_unit.identifier())
            }) {
                return Some(node);
            }
            node = node.parent()?;
        }
    }

    fn rust_declaration_node<'tree>(
        &self,
        code_unit: &CodeUnit,
        root: Node<'tree>,
    ) -> Option<Node<'tree>> {
        let ranges = self.ranges(code_unit);
        let range = ranges.first()?;
        root.descendant_for_byte_range(range.start_byte, range.end_byte)
    }

    fn rust_declaration_for_exact_node(
        &self,
        file: &ProjectFile,
        node: Node<'_>,
        member_name: &str,
        member_kind: RustTraitMemberKind,
    ) -> Option<CodeUnit> {
        self.declarations(file)
            .into_iter()
            .filter(|unit| unit.identifier() == member_name)
            .filter(|unit| rust_code_unit_kind_matches(unit, member_kind))
            .find(|unit| {
                self.ranges(unit).iter().any(|range| {
                    range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
                })
            })
    }

    pub(crate) fn rust_associated_type_declaration_for_exact_node(
        &self,
        file: &ProjectFile,
        node: Node<'_>,
        member_name: &str,
    ) -> Option<CodeUnit> {
        self.rust_declaration_for_exact_node(
            file,
            node,
            member_name,
            RustTraitMemberKind::AssociatedType,
        )
    }
}

/// The visibility constraints on the value constructor introduced by a tuple
/// or unit struct. Named-field structs are constructed in the type namespace
/// and therefore return `None`.
pub(super) fn rust_value_constructor_visibilities(
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
                    "attribute_item" => {}
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
    super::imports::rust_visibility_from_modifier(node, source)
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
    analyzer: &RustAnalyzer,
    trait_member: &CodeUnit,
) -> Option<RustTraitMemberKind> {
    if trait_member.is_function() {
        return Some(RustTraitMemberKind::Method);
    }
    if trait_member.is_field() && analyzer.is_type_alias(trait_member) {
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

pub(super) fn rust_module_files_from_path(
    file: &ProjectFile,
    module_specifier: &str,
) -> Vec<ProjectFile> {
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

pub(super) fn rust_module_files_from_segments(
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

fn rust_relative_module_segments(file: &ProjectFile, segments: &[String]) -> Option<PathBuf> {
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
        crate_name if Some(crate_name) == rust_current_crate_name(file).as_deref() => {
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

fn rust_relative_module_path(file: &ProjectFile, module_specifier: &str) -> Option<PathBuf> {
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
            (Some(crate_name) == rust_current_crate_name(file).as_deref()).then(|| rest.into())
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

fn rust_current_crate_name(file: &ProjectFile) -> Option<String> {
    let manifest = file.root().join("Cargo.toml");
    let source = std::fs::read_to_string(manifest).ok()?;
    source.lines().find_map(|line| {
        let trimmed = line.trim();
        let value = trimmed.strip_prefix("name")?.trim_start();
        let value = value.strip_prefix('=')?.trim();
        value
            .trim_matches('"')
            .split('"')
            .next()
            .filter(|name| !name.is_empty())
            .map(|name| name.replace('-', "_"))
    })
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
    analyzer: &RustAnalyzer,
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
        analyzer,
        trait_owner,
        impl_file,
        source,
        binder,
        &mut implementers,
    );
    implementers
}

fn collect_trait_implementer_names(
    node: Node<'_>,
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
    implementers: &mut Vec<String>,
) {
    if node.kind() == "impl_item"
        && let Some((trait_ref, implementer)) = trait_impl_parts(node, source)
        && trait_reference_matches(analyzer, trait_owner, impl_file, &trait_ref, binder)
    {
        implementers.push(implementer);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_trait_implementer_names(
            child,
            analyzer,
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
    crate::analyzer::common::node_ident_text(
        node,
        source,
        true,
        &crate::analyzer::common::RUST_IDENTIFIER_SIGIL,
    )
}

fn trait_reference_matches(
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    trait_ref: &str,
    impl_binder: &ImportBinder,
) -> bool {
    if let Some((module_specifier, imported_name)) = trait_ref.rsplit_once("::") {
        return imported_name == trait_owner.identifier()
            && analyzer
                .resolve_module_files(impl_file, module_specifier)
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
            analyzer
                .resolve_module_files(impl_file, &binding.module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source())
        })
}

/// The closure-enumerating reference-context algorithm as it stood before the
/// per-site rewrite (`.agents/plans/usage-graph-streaming.md`), kept alive for
/// tests only so the rewrite can be pinned answer-for-answer against it.
///
/// This is the house idiom from #1793/#1817 in `cargo_routes.rs`: freeze the
/// algorithm being replaced, then assert the replacement agrees with it over a
/// fixture, rather than asserting a handful of hand-picked answers.
///
/// It deliberately calls the same leaf helpers the live path uses
/// (`canonical_export_fqn_from_files`, `collect_export_names_from_files`,
/// `forward_exported_targets_from_files_with_progress`). What is frozen is the
/// *composition*: enumerate every export name of every namespace- and
/// glob-imported module up front, versus resolve the one name a site wrote.
/// That composition is exactly what the rewrite changes and what design risk 2
/// names as the thing to prove equal.
#[cfg(test)]
pub(super) mod frozen {
    use super::*;

    #[derive(Debug, Default)]
    pub(super) struct FrozenReferenceContext {
        package: String,
        crate_package: String,
        named: HashMap<String, String>,
        namespace: HashMap<String, String>,
        scoped: HashMap<String, String>,
        glob: HashMap<String, String>,
        same_file: HashMap<String, String>,
    }

    impl FrozenReferenceContext {
        pub(super) fn resolve_bare(&self, name: &str) -> Option<&str> {
            self.named
                .get(name)
                .or_else(|| self.namespace.get(name))
                .or_else(|| self.same_file.get(name))
                .or_else(|| self.glob.get(name))
                .map(String::as_str)
        }

        pub(super) fn bare_names_resolving_to(&self, target_fqn: &str) -> HashSet<String> {
            self.named
                .iter()
                .chain(self.namespace.iter())
                .chain(self.same_file.iter())
                .chain(self.glob.iter())
                .filter(|&(_, fqn)| fqn == target_fqn)
                .map(|(name, _)| name.clone())
                .collect()
        }

        pub(super) fn resolve_scoped(&self, path: &str, name: &str) -> Option<String> {
            self.resolve_scoped_owner(path)
                .map(|owner| join_rust_fqn(&owner, name))
        }

        pub(super) fn resolve_scoped_owner(&self, path: &str) -> Option<String> {
            if let Some(canonical) = self.scoped.get(path) {
                return Some(canonical.clone());
            }
            if let Some((module_path, item_name)) = path.rsplit_once("::")
                && let Some(package) = self.resolve_scoped_owner(module_path)
            {
                return Some(join_rust_fqn(&package, item_name));
            }
            if let Some(package) = self.namespace.get(path) {
                return Some(package.clone());
            }
            if is_rooted_rust_module_path(path)
                && let Some(package) =
                    resolve_rust_module_path_with_crate(&self.package, &self.crate_package, path)
            {
                return Some(package);
            }
            self.named
                .get(path)
                .or_else(|| self.same_file.get(path))
                .or_else(|| self.glob.get(path))
                .cloned()
        }
    }

    fn insert_single_reexport_target(
        named: &mut HashMap<String, String>,
        exported_name: String,
        targets: BTreeSet<(ProjectFile, String)>,
    ) {
        if let Some(fqn) = single_reexport_target_fqn(targets) {
            named.entry(exported_name).or_insert(fqn);
        }
    }

    pub(super) fn build_frozen_reference_context(
        analyzer: &RustAnalyzer,
        file: &ProjectFile,
        forward: bool,
    ) -> FrozenReferenceContext {
        let go = &|| true;
        let binder = analyzer.import_binder_of(file);
        let mut same_file = HashMap::default();
        for unit in analyzer.declarations(file) {
            same_file.insert(unit.identifier().to_string(), unit.fq_name());
        }
        let mut named: HashMap<String, String> = HashMap::default();
        let mut namespace: HashMap<String, String> = HashMap::default();
        let mut scoped: HashMap<String, String> = HashMap::default();
        let mut glob_candidates: HashMap<String, HashSet<String>> = HashMap::default();
        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = &binding.imported_name {
                        let module_files =
                            analyzer.resolve_module_files(file, &binding.module_specifier);
                        let resolved = analyzer
                            .canonical_export_fqn_from_files(&module_files, imported, forward, go)
                            .expect("uninterrupted frozen export traversal")
                            .or_else(|| {
                                analyzer
                                    .resolve_module_package(file, &binding.module_specifier)
                                    .map(|package| join_rust_fqn(&package, imported))
                            });
                        if let Some(resolved) = resolved {
                            named.insert(local.clone(), resolved);
                        }
                    }
                }
                ImportKind::Namespace => {
                    if let Some(package) =
                        analyzer.resolve_module_package(file, &binding.module_specifier)
                    {
                        namespace.insert(local.clone(), package);
                    }
                    insert_namespace_export_bindings(
                        analyzer,
                        file,
                        local,
                        &binding.module_specifier,
                        forward,
                        &mut scoped,
                    );
                }
                ImportKind::Glob => collect_glob_reference_bindings(
                    analyzer,
                    file,
                    &binding.module_specifier,
                    forward,
                    &mut glob_candidates,
                ),
                ImportKind::Default | ImportKind::CommonJsRequire => {}
            }
        }
        insert_reexport_reference_bindings(analyzer, file, &mut named, forward);
        let glob = glob_candidates
            .into_iter()
            .filter_map(|(name, mut candidates)| {
                (candidates.len() == 1)
                    .then(|| (name, candidates.drain().next().expect("one glob candidate")))
            })
            .collect();
        FrozenReferenceContext {
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            named,
            namespace,
            scoped,
            glob,
            same_file,
        }
    }

    fn insert_namespace_export_bindings(
        analyzer: &RustAnalyzer,
        file: &ProjectFile,
        local: &str,
        module_specifier: &str,
        forward: bool,
        scoped: &mut HashMap<String, String>,
    ) {
        let go = &|| true;
        let module_files = analyzer.resolve_module_files(file, module_specifier);
        let mut names = HashSet::default();
        analyzer
            .collect_export_names_from_files(&module_files, &mut HashSet::default(), &mut names, go)
            .expect("uninterrupted frozen export-name traversal");
        for name in names {
            if let Some(fqn) = analyzer
                .canonical_export_fqn_from_files(&module_files, &name, forward, go)
                .expect("uninterrupted frozen export traversal")
            {
                scoped.insert(format!("{local}::{name}"), fqn);
            }
        }
    }

    fn collect_glob_reference_bindings(
        analyzer: &RustAnalyzer,
        file: &ProjectFile,
        module_specifier: &str,
        forward: bool,
        candidates: &mut HashMap<String, HashSet<String>>,
    ) {
        let go = &|| true;
        let module_files = analyzer.resolve_module_files(file, module_specifier);
        let mut names = HashSet::default();
        analyzer
            .collect_export_names_from_files(&module_files, &mut HashSet::default(), &mut names, go)
            .expect("uninterrupted frozen export-name traversal");
        for name in names {
            if let Some(fqn) = analyzer
                .canonical_export_fqn_from_files(&module_files, &name, forward, go)
                .expect("uninterrupted frozen export traversal")
            {
                candidates.entry(name).or_default().insert(fqn);
            }
        }
    }

    fn insert_reexport_reference_bindings(
        analyzer: &RustAnalyzer,
        file: &ProjectFile,
        named: &mut HashMap<String, String>,
        forward: bool,
    ) {
        let go = &|| true;
        let export_index = analyzer.export_index_of(file);
        for (exported_name, entry) in &export_index.exports_by_name {
            if let ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            } = entry
            {
                let module_files = analyzer.resolve_module_files(file, module_specifier);
                let mut targets = if forward {
                    analyzer
                        .forward_exported_targets_from_files_with_progress(
                            &module_files,
                            imported_name,
                            go,
                        )
                        .expect("uninterrupted frozen export traversal")
                } else {
                    analyzer.exported_targets_from_files(&module_files, imported_name)
                };
                if targets.is_empty() {
                    targets.extend(analyzer.rust_member_reexport_targets(
                        file,
                        module_specifier,
                        imported_name,
                    ));
                }
                if targets.is_empty() {
                    targets.extend(
                        rust_declaration_targets_in_files_with_progress(
                            analyzer,
                            &module_files,
                            imported_name,
                            go,
                        )
                        .expect("uninterrupted frozen declaration traversal"),
                    );
                }
                insert_single_reexport_target(named, exported_name.clone(), targets);
            }
        }

        for star in &export_index.reexport_stars {
            let module_files = analyzer.resolve_module_files(file, &star.module_specifier);
            let mut export_names = HashSet::default();
            analyzer
                .collect_export_names_from_files(
                    &module_files,
                    &mut HashSet::default(),
                    &mut export_names,
                    go,
                )
                .expect("uninterrupted frozen export-name traversal");
            for export_name in export_names {
                let mut targets = if forward {
                    analyzer
                        .forward_exported_targets_from_files_with_progress(
                            &module_files,
                            &export_name,
                            go,
                        )
                        .expect("uninterrupted frozen export traversal")
                } else {
                    analyzer.exported_targets_from_files(&module_files, &export_name)
                };
                if targets.is_empty() {
                    targets.extend(
                        rust_declaration_targets_in_files_with_progress(
                            analyzer,
                            &module_files,
                            &export_name,
                            go,
                        )
                        .expect("uninterrupted frozen declaration traversal"),
                    );
                }
                insert_single_reexport_target(named, export_name, targets);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;
    use std::cell::Cell;

    /// One crate exercising every reference form the per-site rewrite has to
    /// answer: named, aliased, namespace and glob imports; a re-export chain
    /// with a `pub use *` cycle (`cyclic_a` and `cyclic_b` star-import each
    /// other); a renaming re-export imported by its new name; macro-visibility
    /// gating; and a same-file declaration shadowing a glob-imported name.
    pub(super) const EQUIVALENCE_FIXTURE: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod wide;\n\
             pub mod barrel;\n\
             pub mod consumer;\n\
             pub mod cyclic_a;\n\
             pub mod cyclic_b;\n\
             pub mod macros;\n\
             pub struct RootType;\n",
        ),
        (
            "src/wide.rs",
            "pub struct Widget;\n\
             pub struct Gadget;\n\
             pub fn make_widget() -> Widget { Widget }\n\
             pub const LIMIT: usize = 3;\n\
             pub enum Mode { On, Off }\n\
             fn private_helper() {}\n",
        ),
        (
            "src/barrel.rs",
            "pub use crate::wide::Widget;\n\
             pub use crate::wide::Gadget as Renamed;\n\
             pub use crate::cyclic_a::*;\n",
        ),
        (
            "src/cyclic_a.rs",
            "pub use crate::cyclic_b::*;\n\
             pub struct AlphaItem;\n",
        ),
        (
            "src/cyclic_b.rs",
            "pub use crate::cyclic_a::*;\n\
             pub struct BetaItem;\n",
        ),
        (
            "src/macros.rs",
            "#[macro_export]\n\
             macro_rules! shout { () => {} }\n\
             pub fn use_macro() { crate::shout!(); }\n",
        ),
        (
            "src/consumer.rs",
            "use crate::wide;\n\
             use crate::barrel;\n\
             use crate::wide::Widget;\n\
             use crate::wide::Gadget as Alias;\n\
             use crate::barrel::Renamed;\n\
             use crate::barrel::*;\n\
             pub struct AlphaItem;\n\
             pub fn consume() {\n\
             \x20   let _a = Widget;\n\
             \x20   let _b = wide::make_widget();\n\
             \x20   let _c = Alias;\n\
             \x20   let _d = Renamed;\n\
             \x20   let _e = wide::LIMIT;\n\
             \x20   let _h = barrel::Widget;\n\
             \x20   let _i = barrel::Renamed;\n\
             \x20   let _f = AlphaItem;\n\
             \x20   let _g = BetaItem;\n\
             }\n",
        ),
    ];

    pub(super) const EQUIVALENCE_FILES: &[&str] = &[
        "src/lib.rs",
        "src/wide.rs",
        "src/barrel.rs",
        "src/cyclic_a.rs",
        "src/cyclic_b.rs",
        "src/macros.rs",
        "src/consumer.rs",
    ];

    /// Every name the fixture spells, plus names it does not, so a miss is
    /// pinned as firmly as a hit.
    pub(super) const EQUIVALENCE_NAMES: &[&str] = &[
        "Widget",
        "Gadget",
        "Renamed",
        "Alias",
        "AlphaItem",
        "BetaItem",
        "RootType",
        "Mode",
        "LIMIT",
        "wide",
        "barrel",
        "consumer",
        "cyclic_a",
        "cyclic_b",
        "macros",
        "make_widget",
        "private_helper",
        "use_macro",
        "consume",
        "shout",
        "crate",
        "self",
        "super",
        "absent_name",
    ];

    /// Prefixes probed as whole written paths. The two-segment entries are the
    /// point of the list: `barrel::Widget` is the case the eager `scoped` map
    /// exists for, because `barrel` re-exports `Widget` from `wide`, so path
    /// arithmetic alone would answer `barrel.Widget` where the canonical
    /// declaration is `wide.Widget`.
    pub(super) const EQUIVALENCE_PREFIXES: &[&str] = &[
        "wide",
        "barrel",
        "cyclic_a",
        "cyclic_b",
        "macros",
        "crate",
        "crate::wide",
        "crate::barrel",
        "self",
        "super",
        "Widget",
        "Alias",
        "absent_prefix",
        "wide::Widget",
        "wide::make_widget",
        "wide::absent_name",
        "barrel::Widget",
        "barrel::Renamed",
        "barrel::AlphaItem",
        "barrel::BetaItem",
        "barrel::absent_name",
        "cyclic_a::BetaItem",
        "crate::wide::Widget",
        "self::AlphaItem",
    ];

    pub(super) const EQUIVALENCE_TARGET_FQNS: &[&str] = &[
        "wide.Widget",
        "wide.Gadget",
        "wide.make_widget",
        "wide.LIMIT",
        "cyclic_a.AlphaItem",
        "cyclic_b.BetaItem",
        "consumer.AlphaItem",
        "wide",
        "barrel",
        "absent.Fqn",
    ];

    #[test]
    fn reference_resolution_matches_the_frozen_closure_algorithm() {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, EQUIVALENCE_FIXTURE);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();

        // An equivalence pin over answers that are all `None` proves nothing.
        // These five are the interesting shapes, and each one is an answer that
        // path arithmetic alone would get wrong: a name re-exported by the
        // namespace-imported module, a renaming re-export, a glob name reached
        // through a `pub use *` cycle, an aliased named import, and a same-file
        // declaration shadowing a glob-imported name.
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let anchors = analyzer.reference_context_of(&consumer);
        assert_eq!(
            anchors.resolve_scoped_owner("barrel::Widget").as_deref(),
            Some("wide.Widget")
        );
        assert_eq!(
            anchors.resolve_scoped_owner("barrel::Renamed").as_deref(),
            Some("wide.Gadget")
        );
        assert_eq!(
            anchors.resolve_bare("BetaItem").as_deref(),
            Some("cyclic_b.BetaItem")
        );
        assert_eq!(
            anchors.resolve_bare("Alias").as_deref(),
            Some("wide.Gadget")
        );
        assert_eq!(
            anchors.resolve_bare("AlphaItem").as_deref(),
            Some("consumer.AlphaItem")
        );

        for relative in EQUIVALENCE_FILES {
            let file = ProjectFile::new(root.clone(), relative);
            for forward in [false, true] {
                let frozen = frozen::build_frozen_reference_context(&analyzer, &file, forward);
                let live = if forward {
                    analyzer.forward_reference_context_of(&file)
                } else {
                    analyzer.reference_context_of(&file)
                };

                for name in EQUIVALENCE_NAMES {
                    assert_eq!(
                        live.resolve_bare(name),
                        frozen.resolve_bare(name).map(str::to_string),
                        "resolve_bare disagreed: file={relative} forward={forward} name={name}"
                    );
                }
                for prefix in EQUIVALENCE_PREFIXES {
                    assert_eq!(
                        live.resolve_scoped_owner(prefix),
                        frozen.resolve_scoped_owner(prefix),
                        "resolve_scoped_owner disagreed: \
                         file={relative} forward={forward} prefix={prefix}"
                    );
                    for name in EQUIVALENCE_NAMES {
                        assert_eq!(
                            live.resolve_scoped(prefix, name),
                            frozen.resolve_scoped(prefix, name),
                            "resolve_scoped disagreed: \
                             file={relative} forward={forward} prefix={prefix} name={name}"
                        );
                    }
                }
                for target_fqn in EQUIVALENCE_TARGET_FQNS {
                    let mut live_names: Vec<_> = live
                        .bare_names_resolving_to(target_fqn)
                        .into_iter()
                        .collect();
                    let mut frozen_names: Vec<_> = frozen
                        .bare_names_resolving_to(target_fqn)
                        .into_iter()
                        .collect();
                    live_names.sort();
                    frozen_names.sort();
                    assert_eq!(
                        live_names, frozen_names,
                        "bare_names_resolving_to disagreed: \
                         file={relative} forward={forward} target={target_fqn}"
                    );
                }
            }
        }
    }

    /// The export index is still shared by handle across a no-op update
    /// (#1230 item 5), and resolution answers the same afterwards.
    ///
    /// This replaces `forward_reference_context_is_reused_within_analyzer_generation`,
    /// which asserted `Arc::ptr_eq` between two calls because the context was a
    /// cached value. There is no context cache any more: a resolver is a
    /// query-scoped view over the analyzer, and the caches it replaced were the
    /// pair whose weigher omitted their two unbounded maps. What still has to
    /// hold is that the state a resolver reads is shared and survives a no-op
    /// update, which is what this asserts.
    #[test]
    fn forward_reference_resolution_survives_a_noop_update() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod exports;\n"),
                ("src/exports.rs", "pub use std::collections::HashMap;\n"),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/exports.rs");

        let first = analyzer
            .forward_reference_context_of(&file)
            .resolve_bare("HashMap");
        let index = analyzer.export_index_of(&file);
        assert!(
            Arc::ptr_eq(&index, &analyzer.export_index_of(&file)),
            "the export index is shared by handle, not deep-cloned per ask (#1230 item 5)"
        );

        let unrelated_watcher_noise = ProjectFile::new(
            fixture.project_root(),
            format!(".bifrost/cache/{}", crate::cache_db::cache_db_file_name()),
        );
        let updated = analyzer.update(&BTreeSet::from([file.clone(), unrelated_watcher_noise]));
        let after_noop_update = updated
            .forward_reference_context_of(&file)
            .resolve_bare("HashMap");

        assert_eq!(first, after_noop_update);
        assert!(updated.export_indexes.get(&file).is_some());
    }

    /// An interrupted resolution answers nothing, and the same resolver answers
    /// fully once the caller lets it run.
    ///
    /// This replaces `issue_1228_interrupted_forward_reference_context_is_not_cached`
    /// and `issue_1304_interrupted_inverted_reference_context_is_not_cached`,
    /// which asserted that an interrupted build published no cache entry. With
    /// no cache, "never publish a partial answer" is the surviving invariant and
    /// it is stronger here than it was: the old infallible entry point the scan
    /// used passed `&|| true` and could not be interrupted at all, whereas the
    /// predicate is now the caller's and is polled inside the walk. The two
    /// answers asserted are the ones those tests asserted.
    #[test]
    fn issue_1228_issue_1304_interrupted_reference_resolution_answers_nothing() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "src/lib.rs",
                    "pub mod exports;\nuse exports::{Alias, helper};\npub fn call(value: Alias) { helper(value); }\n",
                ),
                (
                    "src/exports.rs",
                    "pub struct Alias;\npub fn helper(_: Alias) {}\n",
                ),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");

        for forward in [false, true] {
            let interrupted = if forward {
                analyzer.forward_reference_context_of_while(&file, || false)
            } else {
                analyzer.reference_context_of_while(&file, || false)
            };
            assert_eq!(interrupted.resolve_bare("Alias"), None, "forward={forward}");
            assert_eq!(
                interrupted.resolve_bare("helper"),
                None,
                "forward={forward}"
            );
            assert_eq!(
                interrupted.resolve_scoped_owner("exports::Alias"),
                None,
                "forward={forward}"
            );

            // A predicate that stops partway must not be answered from a
            // half-finished walk either: the checks are counted so the
            // interruption lands inside resolution rather than before it.
            let checks = Cell::new(0usize);
            let partway = if forward {
                analyzer.forward_reference_context_of_while(&file, || {
                    let next = checks.get() + 1;
                    checks.set(next);
                    next < 4
                })
            } else {
                analyzer.reference_context_of_while(&file, || {
                    let next = checks.get() + 1;
                    checks.set(next);
                    next < 4
                })
            };
            let _ = partway.resolve_bare("Alias");
            assert!(checks.get() > 0, "resolution must poll the predicate");

            let complete = if forward {
                analyzer.forward_reference_context_of(&file)
            } else {
                analyzer.reference_context_of(&file)
            };
            assert_eq!(
                complete.resolve_bare("Alias").as_deref(),
                Some("exports.Alias"),
                "forward={forward}"
            );
            assert_eq!(
                complete.resolve_bare("helper").as_deref(),
                Some("exports.helper"),
                "forward={forward}"
            );
        }
    }
}
