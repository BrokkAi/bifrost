use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::common::node_ident_text;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportKind, ReexportStar,
};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::profiling;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

use crate::cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
use crate::declarations::rust_package_name;
use crate::imports::{
    RustVisibility, resolve_rust_module_path_with_crate, rust_crate_root_package,
    rust_imports_with_visibility_from_use_declaration, rust_item_visibility,
};
use crate::lexical_scope::{parse_rust_tree, visible_import_binder_at};
use crate::usage_index::{RustUsageIndex, exported_targets_from_files};

/// The memoized per-file products Rust's language logic resolves through, plus
/// the core capability traits it reads declarations with. The analyzer owns the
/// lazy cells and implements this by forwarding to its own accessors; every free
/// function in this module and its siblings sees only this surface, so none of
/// them can reach back into the analyzer type.
///
/// The usage index is deliberately absent: [`RustUsageIndex::build`] and
/// everything it calls take this trait, so the build cannot re-enter the cell it
/// is filling. Code that runs once the index exists takes [`RustUsageSource`].
pub trait RustAnalysisSource:
    CodeUnitIndex + ImportAnalysisProvider + TypeAliasProvider + TypeHierarchyProvider
{
    /// The same index this trait already extends, for handing to the free
    /// functions whose whole input is a declaration store.
    fn code_units(&self) -> &dyn CodeUnitIndex;

    /// The declaration's syntactic owner, which unlike
    /// [`CodeUnitIndex::parent_of`] never falls back to a definition-row lookup.
    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit>;

    fn prepared_syntax(&self, file: &ProjectFile) -> Option<Arc<PreparedSyntaxTree>>;

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
}

/// [`RustAnalysisSource`] plus the built usage index. Everything reached from
/// the inverted export walk needs it; the index build itself must not.
pub trait RustUsageSource: RustAnalysisSource {
    fn usage_index(&self) -> Arc<RustUsageIndex>;

    /// [`Self::usage_index`], abandoning a cold build when `keep_going` stops
    /// permitting it. A stopped build is not published, so the next
    /// uninterrupted caller still builds a complete index.
    fn usage_index_while(
        &self,
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<Arc<RustUsageIndex>>;

    fn reference_context_of(&self, file: &ProjectFile) -> Arc<RustReferenceContext>;

    /// [`Self::reference_context_of`], abandoning the build when `progress`
    /// reports the caller has stopped caring. The whole-workspace inverted pass
    /// uses this to drop work for files a filter has already rejected.
    fn reference_context_of_with_progress(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> Option<Arc<RustReferenceContext>>;

    /// The forward-scan counterpart of [`Self::reference_context_of`], built
    /// from the same binder but resolving through the forward export index.
    fn forward_reference_context_of(&self, file: &ProjectFile) -> Arc<RustReferenceContext>;

    fn forward_reference_context_of_with_progress(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> Option<Arc<RustReferenceContext>>;
}

#[derive(Clone, Copy, Debug)]
pub struct ReferenceContextInterrupted;

pub type ReferenceContextResult<T> = Result<T, ReferenceContextInterrupted>;

pub fn reference_context_checkpoint(progress: &dyn Fn() -> bool) -> ReferenceContextResult<()> {
    progress().then_some(()).ok_or(ReferenceContextInterrupted)
}

/// Per-file reference-resolution context for Rust — the one primitive both usage
/// paths share. Holds the binder-derived maps a reference resolves through, built
/// once per file and cached on the analyzer ([`RustAnalyzer::reference_context_of`]).
///
/// Rust node fqns are file-independent dotted module paths (`util.format_value`),
/// so a resolved value *is* the graph node key — projecting to the node fqn is the
/// identity. (For JS/TS, where fqns are bare, the resolved value must carry the
/// file; see the execplan's "Identity model".)
#[derive(Debug, Default)]
pub struct RustReferenceContext {
    /// Dotted module/package name for the file this context resolves from.
    package: String,
    /// Dotted module/package name for this file's crate root.
    crate_package: String,
    /// local name -> fqn for `use path::Item;` / `use path::func;` named bindings.
    pub named: HashMap<String, String>,
    /// local alias -> package for `use crate::util;` namespace bindings.
    pub namespace: HashMap<String, String>,
    /// scoped import path -> canonical declaration fqn for namespace imports
    /// whose members are re-exported from another module.
    scoped: HashMap<String, String>,
    /// local name -> canonical declaration fqn for unambiguous glob imports.
    glob: HashMap<String, String>,
    /// identifier -> fqn for items declared in this file.
    pub same_file: HashMap<String, String>,
}

impl RustReferenceContext {
    /// The callee fqn a bare `name` refers to: a named import, a same-file item,
    /// or a free function imported via `use path::func;` (the binder classifies
    /// the latter as a namespace whose resolved value is the function's own fqn).
    pub fn resolve_bare(&self, name: &str) -> Option<&str> {
        self.named
            .get(name)
            .or_else(|| self.namespace.get(name))
            .or_else(|| self.same_file.get(name))
            .or_else(|| self.glob.get(name))
            .map(String::as_str)
    }

    pub fn bare_names_resolving_to(&self, target_fqn: &str) -> HashSet<String> {
        self.named
            .iter()
            .chain(self.namespace.iter())
            .chain(self.same_file.iter())
            .chain(self.glob.iter())
            .filter(|&(_, fqn)| fqn == target_fqn)
            .map(|(name, _)| name.clone())
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
}

impl RustPackageFileIndex {
    pub fn build(files: BTreeSet<ProjectFile>) -> Self {
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

    fn contains(&self, file: &ProjectFile) -> bool {
        self.files.binary_search(file).is_ok()
    }

    fn files_in_package(&self, package: &str) -> impl Iterator<Item = &ProjectFile> {
        self.by_package
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|index| self.files.get(*index as usize))
    }
}

fn insert_single_reexport_target(
    named: &mut HashMap<String, String>,
    exported_name: String,
    targets: BTreeSet<(ProjectFile, String)>,
) {
    let mut targets = targets.into_iter();
    let Some((target_file, target_name)) = targets.next() else {
        return;
    };
    if targets.next().is_some() {
        return;
    }
    named
        .entry(exported_name)
        .or_insert_with(|| join_rust_fqn(&rust_package_name(&target_file), &target_name));
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
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    let mut targets = resolve_imported_export_from_binder_forward(rust, file, binder, reference);
    for (local_name, binding) in &binder.bindings {
        if local_name != reference || binding.kind != ImportKind::Named {
            continue;
        }
        let imported = binding.imported_name.as_deref().unwrap_or(reference);
        targets.extend(
            resolve_module_files(rust, file, &binding.module_specifier)
                .into_iter()
                .map(|target_file| (target_file, imported.to_string())),
        );
    }
    targets.sort();
    targets.dedup();
    targets
}

pub fn export_index_of_declarations(
    rust: &dyn RustAnalysisSource,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
) -> ExportIndex {
    let _scope = profiling::scope("RustAnalyzer::export_index_of_declarations");
    let index_source = rust.code_units();
    let mut index = ExportIndex::empty();
    let export_visible = export_visible_declarations(index_source, file, declarations);
    let mut external_visibility = HashMap::default();

    for code_unit in declarations {
        let identifier = code_unit.identifier().trim();
        if identifier.is_empty() || identifier.starts_with('_') {
            continue;
        }
        if !is_module_export_candidate(
            index_source,
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

    if let Some(prepared) = rust.prepared_syntax(file) {
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
    rust: &dyn RustUsageSource,
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
                let files = resolve_module_files(rust, file, &binding.module_specifier);
                targets.extend(if forward {
                    forward_exported_targets_from_files(rust, &files, imported)
                } else {
                    exported_targets_from_files(rust, &files, imported)
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
                let files = resolve_module_files(rust, file, module_specifier);
                targets.extend(if forward {
                    forward_exported_targets_from_files(rust, &files, imported)
                } else {
                    exported_targets_from_files(rust, &files, imported)
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
            let files = resolve_module_files(rust, file, &binding.module_specifier);
            targets.extend(if forward {
                forward_exported_targets_from_files(rust, &files, reference)
            } else {
                exported_targets_from_files(rust, &files, reference)
            });
        }
    }
    let mut sorted: Vec<_> = targets.into_iter().collect();
    sorted.sort();
    sorted
}

pub fn resolve_imported_export_from_binder_forward(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    resolve_imported_export_from_binder_with_mode(rust, file, binder, reference, true)
}

pub fn resolve_imported_export_from_binder(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    resolve_imported_export_from_binder_with_mode(rust, file, binder, reference, false)
}

/// Resolve a `use`-path module specifier (e.g. `crate::util`, `crate::svc`)
/// to the dotted package it names, relative to `importing_file`. This is the
/// `package_name` half of a `CodeUnit::fq_name()` for items in that module, so
/// the inverted usage-graph builder can turn `(module_specifier, name)` into a
/// callee fqn without re-deriving the path arithmetic.
pub fn resolve_module_package(
    rust: &dyn RustAnalysisSource,
    importing_file: &ProjectFile,
    module_specifier: &str,
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
    let mut current = module_specifier.to_string();
    loop {
        let root = current.split("::").next().unwrap_or(current.as_str());
        if !seen_roots.insert(root.to_string()) {
            break;
        }
        let Some(aliased) = rust_apply_import_alias(rust, importing_file, &current) else {
            break;
        };
        if is_rooted_rust_module_path(&aliased) {
            return resolve_rust_module_path_with_crate(&package, &crate_package, &aliased);
        }
        if let Some(package) = rust
            .cargo_routes()
            .resolve_module_package(importing_file, &aliased)
        {
            return Some(package);
        }
        current = aliased;
    }
    resolve_rust_module_path_with_crate(&package, &crate_package, &current)
}

pub fn build_reference_context_with_progress(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    forward: bool,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<RustReferenceContext> {
    let _scope = profiling::scope("RustAnalyzer::build_reference_context");
    reference_context_checkpoint(progress)?;
    let binder = rust.import_binder_of(file);
    reference_context_checkpoint(progress)?;
    let mut same_file = HashMap::default();
    for unit in rust.declarations(file) {
        reference_context_checkpoint(progress)?;
        same_file.insert(unit.identifier().to_string(), unit.fq_name());
    }
    let mut named: HashMap<String, String> = HashMap::default();
    let mut namespace: HashMap<String, String> = HashMap::default();
    let mut scoped: HashMap<String, String> = HashMap::default();
    let mut glob_candidates: HashMap<String, HashSet<String>> = HashMap::default();
    for (local, binding) in &binder.bindings {
        reference_context_checkpoint(progress)?;
        match binding.kind {
            ImportKind::Named => {
                if let Some(imported) = &binding.imported_name {
                    let resolved = canonical_export_fqn_with_progress(
                        rust,
                        file,
                        &binding.module_specifier,
                        imported,
                        forward,
                        progress,
                    )?
                    .or_else(|| {
                        resolve_module_package(rust, file, &binding.module_specifier)
                            .map(|package| join_rust_fqn(&package, imported))
                    });
                    if let Some(resolved) = resolved {
                        named.insert(local.clone(), resolved);
                    }
                }
            }
            ImportKind::Namespace => {
                if let Some(package) = resolve_module_package(rust, file, &binding.module_specifier)
                {
                    namespace.insert(local.clone(), package);
                }
                insert_namespace_export_bindings(
                    rust,
                    file,
                    local,
                    &binding.module_specifier,
                    forward,
                    &mut scoped,
                    progress,
                )?;
            }
            ImportKind::Glob => collect_glob_reference_bindings(
                rust,
                file,
                &binding.module_specifier,
                forward,
                &mut glob_candidates,
                progress,
            )?,
            ImportKind::Default | ImportKind::CommonJsRequire => {}
        }
    }
    insert_reexport_reference_bindings(rust, file, &mut named, forward, progress)?;
    reference_context_checkpoint(progress)?;
    let glob = glob_candidates
        .into_iter()
        .filter_map(|(name, mut candidates)| {
            (candidates.len() == 1)
                .then(|| (name, candidates.drain().next().expect("one glob candidate")))
        })
        .collect();
    Ok(RustReferenceContext {
        package: rust_package_name(file),
        crate_package: rust_crate_root_package(file),
        named,
        namespace,
        scoped,
        glob,
        same_file,
    })
}

fn canonical_export_fqn_with_progress(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    module_specifier: &str,
    name: &str,
    forward: bool,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    reference_context_checkpoint(progress)?;
    let module_files = resolve_module_files(rust, file, module_specifier);
    canonical_export_fqn_from_files(rust, &module_files, name, forward, progress)
}

/// The `(module_files, name)` half of [`Self::canonical_export_fqn_with_progress`],
/// split out so callers that resolve every export name of *one* module
/// specifier route the invariant `resolve_module_files` once instead of once
/// per name (#1230 item 4).
fn canonical_export_fqn_from_files(
    rust: &dyn RustUsageSource,
    module_files: &[ProjectFile],
    name: &str,
    forward: bool,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<Option<String>> {
    let targets = if forward {
        forward_exported_targets_from_files_with_progress(rust, module_files, name, progress)?
    } else {
        exported_targets_from_files(rust, module_files, name)
    };
    single_rust_target_fqn(rust.code_units(), targets, progress)
}

pub fn forward_export_fqn_from_files(
    rust: &dyn RustUsageSource,
    module_files: &[ProjectFile],
    name: &str,
) -> Option<String> {
    if let Some(fqn) = canonical_export_fqn_from_files(rust, module_files, name, true, &|| true)
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
        let Some(owner_fqn) = resolve_module_package(rust, file, module_specifier) else {
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

fn insert_namespace_export_bindings(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    local: &str,
    module_specifier: &str,
    forward: bool,
    scoped: &mut HashMap<String, String>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<()> {
    reference_context_checkpoint(progress)?;
    let module_files = resolve_module_files(rust, file, module_specifier);
    let mut names = HashSet::default();
    collect_export_names_from_files(
        rust,
        &module_files,
        &mut HashSet::default(),
        &mut names,
        progress,
    )?;
    for name in names {
        reference_context_checkpoint(progress)?;
        if let Some(fqn) =
            canonical_export_fqn_from_files(rust, &module_files, &name, forward, progress)?
        {
            scoped.insert(format!("{local}::{name}"), fqn);
        }
    }
    Ok(())
}

fn collect_glob_reference_bindings(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    module_specifier: &str,
    forward: bool,
    candidates: &mut HashMap<String, HashSet<String>>,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<()> {
    reference_context_checkpoint(progress)?;
    let module_files = resolve_module_files(rust, file, module_specifier);
    let mut names = HashSet::default();
    collect_export_names_from_files(
        rust,
        &module_files,
        &mut HashSet::default(),
        &mut names,
        progress,
    )?;
    for name in names {
        reference_context_checkpoint(progress)?;
        if let Some(fqn) =
            canonical_export_fqn_from_files(rust, &module_files, &name, forward, progress)?
        {
            candidates.entry(name).or_default().insert(fqn);
        }
    }
    Ok(())
}

fn insert_reexport_reference_bindings(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    named: &mut HashMap<String, String>,
    forward: bool,
    progress: &dyn Fn() -> bool,
) -> ReferenceContextResult<()> {
    reference_context_checkpoint(progress)?;
    let export_index = rust.export_index_of(file);
    for (exported_name, entry) in &export_index.exports_by_name {
        reference_context_checkpoint(progress)?;
        if let ExportEntry::ReexportedNamed {
            module_specifier,
            imported_name,
        } = entry
        {
            let module_files = resolve_module_files(rust, file, module_specifier);
            let mut targets = if forward {
                forward_exported_targets_from_files_with_progress(
                    rust,
                    &module_files,
                    imported_name,
                    progress,
                )?
            } else {
                exported_targets_from_files(rust, &module_files, imported_name)
            };
            if targets.is_empty() {
                targets.extend(rust_member_reexport_targets(
                    rust,
                    file,
                    module_specifier,
                    imported_name,
                ));
            }
            if targets.is_empty() {
                targets.extend(rust_declaration_targets_in_files_with_progress(
                    rust.code_units(),
                    &module_files,
                    imported_name,
                    progress,
                )?);
            }
            insert_single_reexport_target(named, exported_name.clone(), targets);
        }
    }

    for star in &export_index.reexport_stars {
        reference_context_checkpoint(progress)?;
        let module_files = resolve_module_files(rust, file, &star.module_specifier);
        let mut export_names = HashSet::default();
        collect_export_names_from_files(
            rust,
            &module_files,
            &mut HashSet::default(),
            &mut export_names,
            progress,
        )?;
        for export_name in export_names {
            reference_context_checkpoint(progress)?;
            let mut targets = if forward {
                forward_exported_targets_from_files_with_progress(
                    rust,
                    &module_files,
                    &export_name,
                    progress,
                )?
            } else {
                exported_targets_from_files(rust, &module_files, &export_name)
            };
            if targets.is_empty() {
                targets.extend(rust_declaration_targets_in_files_with_progress(
                    rust.code_units(),
                    &module_files,
                    &export_name,
                    progress,
                )?);
            }
            insert_single_reexport_target(named, export_name, targets);
        }
    }
    Ok(())
}

fn collect_export_names_from_files(
    rust: &dyn RustAnalysisSource,
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
        let export_index = rust.export_index_of(&module_file);
        names.extend(export_index.exports_by_name.keys().cloned());
        for star in &export_index.reexport_stars {
            pending.extend(resolve_module_files(
                rust,
                &module_file,
                &star.module_specifier,
            ));
        }
    }
    Ok(())
}

pub fn forward_exported_targets_from_files(
    rust: &dyn RustAnalysisSource,
    module_files: &[ProjectFile],
    export_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    forward_exported_targets_from_files_with_progress(rust, module_files, export_name, &|| true)
        .expect("uninterrupted Rust export traversal")
}

fn forward_exported_targets_from_files_with_progress(
    rust: &dyn RustAnalysisSource,
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
                let module_files = resolve_module_files(rust, &file, module_specifier);
                if module_files.is_empty() {
                    targets.extend(rust_member_reexport_targets(
                        rust,
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
                resolve_module_files(rust, &file, &star.module_specifier)
                    .into_iter()
                    .map(|target_file| (target_file, name.clone(), true)),
            );
        }
    }
    Ok(targets)
}

pub fn rust_member_reexport_targets(
    rust: &dyn RustAnalysisSource,
    file: &ProjectFile,
    owner_path: &str,
    member_name: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let Some(owner_fqn) = resolve_module_package(rust, file, owner_path) else {
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

/// Rewrite a leading `use <crate> as <alias>` module-alias segment in
/// `module_specifier` to the aliased crate/module. `use forc_pkg::{self as
/// pkg}` makes `pkg` (and `pkg::Item`) mean `forc_pkg` (`forc_pkg::Item`),
/// so every module resolver must first substitute the alias before routing —
/// otherwise the alias root is unknown and draws a false "not indexed"
/// boundary even though the crate is in the workspace (issue #1089).
pub fn rust_apply_import_alias(
    rust: &dyn RustAnalysisSource,
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

pub fn resolve_module_files(
    rust: &dyn RustAnalysisSource,
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
        resolve_module_package(rust, importing_file, module_specifier)
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
                    && !is_external_module_declaration(rust, code_unit)
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
    rust: &dyn RustAnalysisSource,
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
    rust: &dyn RustAnalysisSource,
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
            trait_implementer_names_from_source(rust, trait_owner, &file, &source, &binder)
        })
        .collect()
}

pub fn rust_trait_member_implementations(
    rust: &dyn RustAnalysisSource,
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
            if !trait_reference_matches(rust, &trait_owner, &file, &trait_ref, &binder) {
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
    rust: &dyn RustAnalysisSource,
    code_unit: &CodeUnit,
) -> RustVisibility {
    let Some(prepared) = rust.prepared_syntax(code_unit.source()) else {
        return RustVisibility::Private;
    };
    rust_named_declaration_node(
        rust.code_units(),
        code_unit,
        prepared.tree().root_node(),
        prepared.source(),
    )
    .map(|node| crate::imports::rust_item_visibility(node, prepared.source()))
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
    declarations
        .iter()
        .filter(|code_unit| {
            rust_declaration_node(index, code_unit, tree.root_node())
                .and_then(|node| rust_visibility_text(node, &source))
                .is_some_and(is_export_visibility)
        })
        .cloned()
        .collect()
}

pub fn is_module_export_candidate(
    index: &dyn CodeUnitIndex,
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
    while let Some(parent) = index.parent_of(&current) {
        let parent_is_export_visible = if parent.source() == file {
            export_visible.contains(&parent)
        } else if let Some(visible) = external_visibility.get(&parent) {
            *visible
        } else {
            let visible = is_export_public_declaration(index, &parent);
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
pub fn is_external_module_declaration(rust: &dyn RustAnalysisSource, code_unit: &CodeUnit) -> bool {
    if !code_unit.is_module() {
        return false;
    }
    let Some(prepared) = rust.prepared_syntax(code_unit.source()) else {
        return false;
    };
    rust_named_declaration_node(
        rust.code_units(),
        code_unit,
        prepared.tree().root_node(),
        prepared.source(),
    )
    .is_some_and(|node| node.kind() == "mod_item" && node.child_by_field_name("body").is_none())
}

pub fn rust_declaration_node_is<F>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    predicate: F,
) -> bool
where
    F: FnOnce(Node<'_>, &str) -> bool,
{
    let Ok(source) = index.project().read_source(code_unit.source()) else {
        return false;
    };
    let Some(tree) = parse_rust_tree(&source) else {
        return false;
    };
    rust_named_declaration_node(index, code_unit, tree.root_node(), &source)
        .map(|node| predicate(node, &source))
        .unwrap_or(false)
}

pub fn rust_named_declaration_node<'tree>(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    root: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut node = rust_declaration_node(index, code_unit, root)?;
    loop {
        if node.child_by_field_name("name").is_some_and(|name| {
            source.get(name.start_byte()..name.end_byte()) == Some(code_unit.identifier())
        }) {
            return Some(node);
        }
        node = node.parent()?;
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
    rust: &dyn RustAnalysisSource,
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
    rust: &dyn RustAnalysisSource,
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
    rust: &dyn RustAnalysisSource,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    source: &str,
    binder: &ImportBinder,
    implementers: &mut Vec<String>,
) {
    if node.kind() == "impl_item"
        && let Some((trait_ref, implementer)) = trait_impl_parts(node, source)
        && trait_reference_matches(rust, trait_owner, impl_file, &trait_ref, binder)
    {
        implementers.push(implementer);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_trait_implementer_names(
            child,
            rust,
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
    rust: &dyn RustAnalysisSource,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    trait_ref: &str,
    impl_binder: &ImportBinder,
) -> bool {
    if let Some((module_specifier, imported_name)) = trait_ref.rsplit_once("::") {
        return imported_name == trait_owner.identifier()
            && resolve_module_files(rust, impl_file, module_specifier)
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
            resolve_module_files(rust, impl_file, &binding.module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source())
        })
}
