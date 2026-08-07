//! Bounded, memoized cross-file walks over the per-file Rust usage facts.
//!
//! This is the third layer of `.agents/plans/rust-usage-index-v2.md`. Milestone
//! 2a made the per-file questions store-backed and 2b did the same for the
//! inverted-derivable ones; what is left in `RustUsageIndex` is the group that
//! is genuinely cross-file -- module-file resolution, physical ownership, alias
//! routes, effective module domains, forward import edges, export chains, and
//! macro scope visibility.
//!
//! Each of those was a workspace-wide map built wholesale at index-build time.
//! Here each is a walk from a seed, memoized in a bounded cache on the analyzer.
//! The analyzer instance IS the generation: `RustAnalyzer::update` and
//! `update_all` construct a fresh analyzer with fresh caches, so a cache living
//! here needs only the query key. That is the same argument the Milestone 2b
//! Decision Log records for `declaration_facts`, and it applies for the same
//! reason: every derivation below consults analyzer state (structural parents,
//! visibility, Cargo routes, the analyzed-file set), not only file bytes, so a
//! content-hash key would claim an invariance these values do not have.

use moka::sync::Cache;
use std::cell::{Cell, RefCell};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};

use super::RustAnalyzer;
use super::cache::{
    build_weighted_cache, weight_alias_routes, weight_forward_import_edges,
    weight_macro_scope_edges, weight_macro_visible_ranges, weight_module_bindings,
    weight_module_domains, weight_origin_routes, weight_project_file_list,
};
use super::cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
use super::declarations::rust_package_name;
use super::facts::RUST_OCCURRENCE_CODE;
use super::graph_support::{
    RustPackageFileIndex, rust_module_files_from_path, rust_module_files_from_segments,
};
use super::imports::{
    resolve_rust_module_path_with_crate, resolve_rust_module_segments_with_crate,
    rust_crate_root_package,
};
use super::usage_index::{
    Domain, ModuleKey, RustImportEdge, RustImportEdgeKind, RustImportExtent, RustMacroScopeEdge,
    RustMacroScopeKey, RustMacroScopeRanges, RustModuleAliasRoute, RustOriginRoute,
    RustResolvedModuleRoute, RustRouteProvenance, RustSymbolIdentity, RustSymbolNamespace,
    direct_import_scope_for_module, edge_matches_single_seed, edge_target_matches_exact_module,
    imported_identity_domain, rust_mod_item_has_macro_use,
};
use super::usage_queries::RustUsageQueries;

/// One module's bindings are asked for by `(file, module)`.
pub(super) type RustModuleBindingKey = (ProjectFile, ModuleKey);

/// The bounded caches the walks memoize into.
///
/// The plan names three: `module_resolution`, `export_chain` and `resolve`.
/// Those are three concerns, not three fields -- a `moka` cache is typed, so
/// each value shape needs its own. The grouping is:
///
/// * `module_resolution`: `module_files`, `owner_roots`, `module_domains`.
/// * `resolve`: `alias_routes` and the `forward_import_edges` they feed.
/// * `export_chain`: `module_bindings` and `origin_routes`, plus the macro
///   scope chain, which is the same walk over `mod` items rather than `use`
///   items.
///
/// Every key is the query alone. The analyzer instance is the generation:
/// `update` / `update_all` build a fresh analyzer with a fresh `RustWalkCaches`,
/// which is the correct invalidation for analyzer-derived state and the same
/// argument the Milestone 2b Decision Log records for `declaration_facts`.
pub(super) struct RustWalkCaches {
    module_files: Cache<String, Arc<Vec<ProjectFile>>>,
    owner_roots: Cache<ProjectFile, Arc<Vec<ProjectFile>>>,
    module_domains: Cache<ModuleKey, Option<Arc<Vec<Domain>>>>,
    alias_routes: Cache<ModuleKey, Arc<Vec<RustModuleAliasRoute>>>,
    forward_import_edges: Cache<ProjectFile, Arc<Vec<RustImportEdge>>>,
    module_bindings: Cache<RustModuleBindingKey, Arc<Vec<RustModuleBinding>>>,
    origin_routes: Cache<ProjectFile, Arc<HashMap<String, Vec<RustOriginRoute>>>>,
    macro_scope_edges: Cache<ProjectFile, Arc<Vec<RustMacroScopeEdge>>>,
    macro_visible_ranges: Cache<CodeUnit, Arc<RustMacroScopeRanges>>,
}

impl RustWalkCaches {
    pub(super) fn new(memo_budget: u64) -> Self {
        let share = memo_budget / 16;
        Self {
            module_files: build_weighted_cache(share, weight_project_file_list),
            owner_roots: build_weighted_cache(share, weight_project_file_list),
            module_domains: build_weighted_cache(share, weight_module_domains),
            alias_routes: build_weighted_cache(share, weight_alias_routes),
            forward_import_edges: build_weighted_cache(share, weight_forward_import_edges),
            module_bindings: build_weighted_cache(share, weight_module_bindings),
            origin_routes: build_weighted_cache(share, weight_origin_routes),
            macro_scope_edges: build_weighted_cache(share, weight_macro_scope_edges),
            macro_visible_ranges: build_weighted_cache(share, weight_macro_visible_ranges),
        }
    }
}

/// A view that answers the cross-file usage questions by walking, borrowing the
/// analyzer for its store handle, its Cargo routes, and its bounded caches.
///
/// Cheap to construct: everything expensive is behind a cache on the analyzer,
/// and the only per-walker state is the cycle bookkeeping the alias recursion
/// needs.
pub(super) struct RustUsageWalks<'a> {
    analyzer: &'a RustAnalyzer,
    queries: RustUsageQueries<'a>,
    cargo_routes: Arc<RustCargoRouteIndex>,
    files: Arc<RustPackageFileIndex>,
    caches: Arc<RustWalkCaches>,
    /// The best answer so far for each key whose computation is on this
    /// walker's stack. The v1 builds reached a fixed point by iterating the
    /// whole workspace; a recursion has to close its own cycles, and answering
    /// a cycle with the partial result is what makes the local iteration below
    /// converge on the same value.
    alias_partial: RefCell<HashMap<ModuleKey, Arc<Vec<RustModuleAliasRoute>>>>,
    /// Incremented whenever a cycle answered from a partial result. A value
    /// derived from a partial is correct for the frame that closed the cycle
    /// but not in general, so it must never reach the analyzer-level cache.
    alias_truncations: Cell<usize>,
    /// The same bookkeeping for the export-chain recursion: a re-export cycle
    /// (`a` publishes `b`'s name, `b` publishes `a`'s) has to terminate, and a
    /// module that imports from itself -- `pub(crate) use target_macro;` beside
    /// the `macro_rules!` it republishes -- is a cycle of length one.
    binding_partial: RefCell<HashMap<RustModuleBindingKey, Arc<Vec<RustModuleBinding>>>>,
    binding_truncations: Cell<usize>,
}

/// One name bound in one module, with the declaration it really names.
///
/// This is the per-module slice of what the v1 build derived globally: the
/// worklist in `build_origin_routes` seeded every declaration identity in the
/// workspace and pushed propagated aliases onto the same queue. Asking one
/// module what it binds is the same relation read from the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RustModuleBinding {
    pub(super) name: String,
    pub(super) namespace: RustSymbolNamespace,
    /// The declaration this name ultimately refers to, unchanged along a
    /// re-export chain.
    pub(super) origin: RustSymbolIdentity,
    pub(super) domain: Domain,
}

impl<'a> RustUsageWalks<'a> {
    pub(super) fn new(analyzer: &'a RustAnalyzer) -> Self {
        Self::with_cargo_routes(analyzer, analyzer.cargo_routes_for_usage())
    }

    /// The cancellable constructor. Cargo routes are the one input a walk
    /// cannot start without, and building them on a cold workspace is the step
    /// a cancelled candidate discovery has to be able to abandon.
    pub(super) fn new_while(
        analyzer: &'a RustAnalyzer,
        keep_going: &(impl Fn() -> bool + Sync),
    ) -> Option<Self> {
        Some(Self::with_cargo_routes(
            analyzer,
            analyzer.cargo_routes_for_usage_while(keep_going)?,
        ))
    }

    fn with_cargo_routes(
        analyzer: &'a RustAnalyzer,
        cargo_routes: Arc<RustCargoRouteIndex>,
    ) -> Self {
        Self {
            analyzer,
            queries: RustUsageQueries::new(analyzer),
            cargo_routes,
            files: analyzer.package_file_index(),
            caches: Arc::clone(analyzer.walk_caches()),
            alias_partial: RefCell::new(HashMap::default()),
            alias_truncations: Cell::new(0),
            binding_partial: RefCell::new(HashMap::default()),
            binding_truncations: Cell::new(0),
        }
    }

    pub(super) fn queries(&self) -> &RustUsageQueries<'a> {
        &self.queries
    }

    pub(super) fn cargo_routes(&self) -> &Arc<RustCargoRouteIndex> {
        &self.cargo_routes
    }

    /// Membership in the analyzed-file set. The v1 index carried its own `files`
    /// vector for exactly this test; the package index already holds the same
    /// listing in sorted order, so this is a binary search rather than a
    /// second copy.
    pub(super) fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.files.contains(file)
    }

    // ---------------------------------------------------------------- layer 1
    // Module-file resolution. `RustModuleFiles::by_package` was the analyzed
    // file listing bucketed by package name, which `RustPackageFileIndex`
    // already is, and `inline_by_name` was every module declaration keyed by
    // fq name, which is an indexed `code_units` lookup. Neither needs a new
    // index; both need the analyzed-set filter, because the store can offer a
    // declaration from a path that is no longer analyzed.

    /// The files that back the module named `package`.
    ///
    /// Two sources, matching the two maps `RustModuleFiles` built: the files
    /// whose path-derived package IS this module, and the files that declare a
    /// module of this fq name. The second lookup goes through the store's
    /// short-name index rather than `definitions(fq_name)`, because
    /// `definitions` keeps one declaration per fq name and two files can
    /// legitimately declare the same module path (see Surprises).
    pub(super) fn files_in_module_package(&self, package: &str) -> Arc<Vec<ProjectFile>> {
        if let Some(cached) = self.caches.module_files.get(package) {
            return cached;
        }
        let mut files: Vec<ProjectFile> = self.files.files_in_package(package).cloned().collect();
        if let Some(short_name) = package.rsplit('.').next().filter(|name| !name.is_empty()) {
            files.extend(
                self.analyzer
                    .lookup_candidates_by_identifier(short_name)
                    .into_iter()
                    .filter(|declaration| {
                        declaration.is_module() && declaration.fq_name() == package
                    })
                    .map(|declaration| declaration.source().clone())
                    .filter(|file| self.files.contains(file)),
            );
        }
        files.sort();
        files.dedup();
        let files = Arc::new(files);
        self.caches
            .module_files
            .insert(package.to_string(), Arc::clone(&files));
        files
    }

    pub(super) fn files_for_module(&self, module: &ModuleKey) -> Arc<Vec<ProjectFile>> {
        self.files_in_module_package(&module.package())
    }

    /// `RustModuleFiles::resolve`, verbatim over the lazy lookups.
    ///
    /// Deliberately not `RustAnalyzer::resolve_module_files`: that look-alike
    /// additionally drops external module declarations and disambiguates rooted
    /// collisions by Cargo target relation, so substituting it changes answers.
    pub(super) fn resolve(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        if let Some(root_file) = self
            .cargo_routes
            .resolve_crate_root_file(importing_file, module_specifier)
        {
            return if self.is_analyzed(&root_file) {
                vec![root_file]
            } else {
                Vec::new()
            };
        }
        let package = rust_package_name(importing_file);
        let crate_package = rust_crate_root_package(importing_file);
        let Some(resolved_module) = self
            .cargo_routes
            .resolve_module_package(importing_file, module_specifier)
            .or_else(|| {
                resolve_rust_module_path_with_crate(&package, &crate_package, module_specifier)
            })
        else {
            return rust_module_files_from_path(importing_file, module_specifier);
        };

        let mut files = self
            .files_in_module_package(&resolved_module)
            .as_ref()
            .clone();
        files.extend(rust_module_files_from_path(
            importing_file,
            module_specifier,
        ));
        files.sort();
        files.dedup();
        files
    }

    /// `RustModuleFiles::resolve_segments`: module resolution with no alias
    /// knowledge, the fallback the alias-aware form drops to.
    fn resolve_segments_plain(
        &self,
        importing_file: &ProjectFile,
        importing_module: &str,
        segments: &[String],
    ) -> Vec<RustResolvedModuleRoute> {
        if let Some((root_file, kind)) = self
            .cargo_routes
            .resolve_crate_root_file_segments_with_kind(importing_file, segments)
        {
            let Some((package, _)) = self
                .cargo_routes
                .resolve_module_package_segments_with_kind(importing_file, segments)
            else {
                return Vec::new();
            };
            if !self.is_analyzed(&root_file) {
                return Vec::new();
            }
            return vec![RustResolvedModuleRoute {
                target_module: ModuleKey::new(&root_file, &package),
                target_file: root_file,
                provenance: RustRouteProvenance::from(kind),
            }];
        }
        let crate_package = rust_crate_root_package(importing_file);
        if let Some((resolved_module, kind)) = self
            .cargo_routes
            .resolve_module_package_segments_with_kind(importing_file, segments)
        {
            let provenance = RustRouteProvenance::from(kind);
            return self
                .files_in_module_package(&resolved_module)
                .iter()
                .map(|file| RustResolvedModuleRoute {
                    target_module: ModuleKey::new(file, &resolved_module),
                    target_file: file.clone(),
                    provenance,
                })
                .collect();
        }

        let resolved_module = if matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            let Some(resolved) =
                resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
            else {
                return Vec::new();
            };
            resolved
        } else {
            let relative = ModuleKey::new(importing_file, importing_module).with_suffix(segments);
            if self.files_for_module(&relative).is_empty() {
                resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
                    .unwrap_or_else(|| relative.package())
            } else {
                relative.package()
            }
        };

        let mut files = self
            .files_in_module_package(&resolved_module)
            .as_ref()
            .clone();
        files.extend(rust_module_files_from_segments(importing_file, segments));
        files.sort();
        files.dedup();
        files.retain(|file| {
            self.cargo_routes.target_relation(importing_file, file)
                != RustCargoTargetRelation::Disjoint
        });
        files
            .into_iter()
            .map(|file| RustResolvedModuleRoute {
                target_module: ModuleKey::new(&file, &resolved_module),
                target_file: file,
                provenance: RustRouteProvenance::Local,
            })
            .collect()
    }

    // ---------------------------------------------------------------- layer 2
    // Alias routes. The v1 build was a fixed point over every import in the
    // workspace; the lazy form asks one question -- "what does the module named
    // K route to" -- and recurses only into the imports that could answer it.

    /// Every route registered under the module alias `alias`.
    ///
    /// An alias key is `owner module + local name`, so the files that can
    /// contribute are the files backing `owner module`, and the contributing
    /// bindings are that module's own module-scope `use` items: a named import
    /// binding `local name`, or a glob that republishes an alias of that name
    /// from the module it imports.
    pub(super) fn alias_routes_at(&self, alias: &ModuleKey) -> Arc<Vec<RustModuleAliasRoute>> {
        if let Some(cached) = self.caches.alias_routes.get(alias) {
            return cached;
        }
        if let Some(partial) = self.alias_partial.borrow().get(alias) {
            self.alias_truncations.set(self.alias_truncations.get() + 1);
            return Arc::clone(partial);
        }
        let truncations_before = self.alias_truncations.get();
        self.alias_partial
            .borrow_mut()
            .insert(alias.clone(), Arc::new(Vec::new()));
        let mut routes = Arc::new(self.compute_alias_routes(alias));
        // Only a cycle needs iterating: without one the recursion already saw
        // every input, exactly as the converged fixed point did. Routes only
        // accumulate, so equal length means the value stopped moving.
        if self.alias_truncations.get() != truncations_before {
            loop {
                self.alias_partial
                    .borrow_mut()
                    .insert(alias.clone(), Arc::clone(&routes));
                let next = Arc::new(self.compute_alias_routes(alias));
                let converged = next.len() == routes.len();
                routes = next;
                if converged {
                    break;
                }
            }
        }
        self.alias_partial.borrow_mut().remove(alias);
        if self.alias_truncations.get() == truncations_before {
            self.caches
                .alias_routes
                .insert(alias.clone(), Arc::clone(&routes));
        }
        routes
    }

    fn compute_alias_routes(&self, alias: &ModuleKey) -> Vec<RustModuleAliasRoute> {
        let (Some(owner), Some(name)) = (alias.parent(), alias.components.last().cloned()) else {
            return Vec::new();
        };
        let owner_package = owner.package();
        let mut routes: Vec<RustModuleAliasRoute> = Vec::new();
        for file in self.files_for_module(&owner).iter() {
            // Two files can share a package name across crates; only the file
            // whose own crate root matches declares this alias key.
            if ModuleKey::new(file, &owner_package) != owner {
                continue;
            }
            for binding in self.queries.import_bindings_of(file) {
                if !matches!(binding.extent, RustImportExtent::Module { .. })
                    || binding.owner_module != owner_package
                {
                    continue;
                }
                let Some(domain) = direct_import_scope_for_module(
                    file,
                    &owner_package,
                    binding.visibility.clone(),
                ) else {
                    continue;
                };
                if binding.is_glob {
                    for imported in self.resolve_segments(file, &owner_package, &binding.path) {
                        let inherited = self.alias_routes_at(
                            &imported
                                .target_module
                                .with_suffix(std::slice::from_ref(&name)),
                        );
                        for route in inherited
                            .iter()
                            .filter(|route| route.domain.contains_module(&imported.target_module))
                        {
                            let Some(effective) = route.domain.intersect(&domain) else {
                                continue;
                            };
                            push_unique(
                                &mut routes,
                                RustModuleAliasRoute {
                                    target_file: route.target_file.clone(),
                                    target_module: route.target_module.clone(),
                                    domain: effective,
                                    provenance: route.provenance,
                                },
                            );
                        }
                    }
                    continue;
                }
                if binding.local_name != name {
                    continue;
                }
                for resolved in self.resolve_segments(file, &owner_package, &binding.path) {
                    push_unique(
                        &mut routes,
                        RustModuleAliasRoute {
                            target_file: resolved.target_file,
                            target_module: resolved.target_module,
                            domain: domain.clone(),
                            provenance: resolved.provenance,
                        },
                    );
                }
            }
        }
        routes
    }

    /// `RustModuleAliasRoutes::resolve_segments`: alias-aware module resolution.
    ///
    /// The longest alias prefix wins, and it is chosen WITHOUT domain
    /// filtering, exactly as v1 chose it. Filtering first would let a private
    /// alias at a shorter prefix shadow the public one the source really means.
    /// If every route at the winning length is filtered out, the answer falls
    /// through to plain module resolution rather than to a shorter alias.
    pub(super) fn resolve_segments(
        &self,
        importing_file: &ProjectFile,
        importing_module: &str,
        segments: &[String],
    ) -> Vec<RustResolvedModuleRoute> {
        let crate_package = rust_crate_root_package(importing_file);
        let owner_relative = if segments.is_empty() {
            Some(importing_module.to_string())
        } else if matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            resolve_rust_module_segments_with_crate(importing_module, &crate_package, segments)
        } else {
            Some(if importing_module.is_empty() {
                segments.join(".")
            } else {
                format!("{importing_module}.{}", segments.join("."))
            })
        };
        if let Some(owner_relative) = owner_relative {
            let candidate = ModuleKey::new(importing_file, &owner_relative);
            let importing_key = ModuleKey::new(importing_file, importing_module);
            let longest = (1..=candidate.components.len()).rev().find_map(|length| {
                let prefix = ModuleKey {
                    crate_root: candidate.crate_root.clone(),
                    components: candidate.components[..length].to_vec(),
                };
                let routes = self.alias_routes_at(&prefix);
                (!routes.is_empty()).then_some((length, routes))
            });
            if let Some((length, alias_routes)) = longest {
                let suffix = &candidate.components[length..];
                let mut resolved = Vec::new();
                for route in alias_routes
                    .iter()
                    .filter(|route| route.domain.contains_module(&importing_key))
                {
                    let target_module = route.target_module.with_suffix(suffix);
                    let mut target_files = self.files_for_module(&target_module).as_ref().clone();
                    if suffix.is_empty() && !target_files.contains(&route.target_file) {
                        target_files.push(route.target_file.clone());
                    }
                    resolved.extend(
                        target_files
                            .into_iter()
                            .map(|file| RustResolvedModuleRoute {
                                target_file: file,
                                target_module: target_module.clone(),
                                provenance: route.provenance,
                            }),
                    );
                }
                sort_routes(&mut resolved);
                resolved.dedup();
                if !resolved.is_empty() {
                    return resolved;
                }
            }
        }

        self.resolve_segments_plain(importing_file, importing_module, segments)
            .into_iter()
            .filter(|route| self.is_analyzed(&route.target_file))
            .collect()
    }

    // ---------------------------------------------------------------- layer 0
    // Physical roots and crate roots: per-file predicates, no walk at all.

    pub(super) fn physical_root_of(&self, file: &ProjectFile) -> Option<ModuleKey> {
        self.is_analyzed(file)
            .then(|| ModuleKey::new(file, &rust_package_name(file)))
    }

    pub(super) fn is_actual_crate_root(&self, file: &ProjectFile) -> bool {
        self.is_analyzed(file)
            && (rust_package_name(file) == rust_crate_root_package(file)
                || self.cargo_routes.target_roots_for_file(file).contains(file))
    }

    // -------------------------------------------------------------- layer 1b
    // Physical ownership. The v1 build was a downward breadth-first walk from
    // every crate root along `mod name;` edges, materialising a root set for
    // every file in the workspace. Asking one file's question is an upward walk
    // instead, bounded by module nesting depth.

    /// The files `declaring_file` hands the module `declared` to.
    fn module_child_files(
        &self,
        declaring_file: &ProjectFile,
        declared: &ModuleKey,
    ) -> Vec<ProjectFile> {
        let mut children: Vec<ProjectFile> = self
            .files_for_module(declared)
            .iter()
            .filter(|file| {
                *file != declaring_file && self.physical_root_of(file).as_ref() == Some(declared)
            })
            .cloned()
            .collect();
        if let Some(physical_root) = self.physical_root_of(declaring_file)
            && let Some(relative) = declared
                .components
                .strip_prefix(physical_root.components.as_slice())
        {
            children.extend(
                rust_module_files_from_segments(declaring_file, relative)
                    .into_iter()
                    .filter(|file| file != declaring_file && self.is_analyzed(file)),
            );
        }
        children.sort();
        children.dedup();
        children
    }

    /// Every file `file` hands one of its `mod name;` declarations to.
    fn child_files_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let facts = self.queries.declaration_facts_of(file);
        let mut children = Vec::new();
        for identity in facts
            .identities
            .iter()
            .filter(|(declaration, identity)| {
                identity.namespace == RustSymbolNamespace::Module
                    && self.analyzer.is_external_module_declaration(declaration)
            })
            .map(|(_, identity)| identity)
        {
            let declared = identity
                .module
                .with_suffix(std::slice::from_ref(&identity.name));
            children.extend(self.module_child_files(&identity.file, &declared));
        }
        children.sort();
        children.dedup();
        children
    }

    /// A superset of the files that can declare `file` as one of their modules.
    ///
    /// Two sources, matching the two halves of the v1 child computation. The
    /// module half is one indexed lookup: a file backed by module M is handed
    /// out by a file backing M's parent. The path half has no index -- v1
    /// derived those children from the declaring file's own path -- so it is
    /// inverted here by walking `file`'s path back up, which yields at most
    /// four candidate declaring files per directory level. Every candidate is
    /// then verified against its real child set, so a superset is safe.
    fn parent_candidates_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let mut candidates: Vec<ProjectFile> = Vec::new();
        if let Some(root) = self.physical_root_of(file)
            && let Some(parent) = root.parent()
        {
            candidates.extend(self.files_for_module(&parent).iter().cloned());
        }
        candidates.extend(path_parent_candidates(file));
        candidates.retain(|candidate| candidate != file && self.is_analyzed(candidate));
        candidates.sort();
        candidates.dedup();
        candidates
    }

    /// The crate roots that own `file`, through any chain of `mod name;` edges.
    pub(super) fn owner_roots_of(&self, file: &ProjectFile) -> Arc<Vec<ProjectFile>> {
        if let Some(cached) = self.caches.owner_roots.get(file) {
            return cached;
        }
        let mut roots = Vec::new();
        let mut visited = HashSet::default();
        let mut pending = vec![file.clone()];
        while let Some(current) = pending.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if self.is_actual_crate_root(&current) {
                roots.push(current.clone());
            }
            for parent in self.parent_candidates_of(&current) {
                if self.child_files_of(&parent).contains(&current) {
                    pending.push(parent);
                }
            }
        }
        roots.sort();
        roots.dedup();
        let roots = Arc::new(roots);
        self.caches
            .owner_roots
            .insert(file.clone(), Arc::clone(&roots));
        roots
    }

    /// The crate a file belongs to when no analyzed file roots that crate. The
    /// v1 index precomputed this for every file; it reduces to one indexed
    /// package lookup, because an actual crate root is by definition a file
    /// whose package IS its crate root.
    pub(super) fn inferred_crate_of(&self, file: &ProjectFile) -> Option<String> {
        let root = self.physical_root_of(file)?;
        (!self.crate_is_rooted(&root.crate_root)).then_some(root.crate_root)
    }

    fn crate_is_rooted(&self, crate_root: &str) -> bool {
        self.files_in_module_package(crate_root)
            .iter()
            .any(|file| self.is_actual_crate_root(file))
    }

    pub(super) fn owners_intersect(&self, left: &ProjectFile, right: &ProjectFile) -> bool {
        let left_roots = self.owner_roots_of(left);
        let right_roots = self.owner_roots_of(right);
        left_roots.iter().any(|root| right_roots.contains(root)) || {
            let left_crate = self.inferred_crate_of(left);
            left_crate.is_some() && left_crate == self.inferred_crate_of(right)
        }
    }

    pub(super) fn owned_by(&self, file: &ProjectFile, root: &ProjectFile) -> bool {
        self.owner_roots_of(file).contains(root)
    }

    pub(super) fn has_owners(&self, file: &ProjectFile) -> bool {
        !self.owner_roots_of(file).is_empty() || self.inferred_crate_of(file).is_some()
    }

    // ------------------------------------------------------- module domains
    // `effective_module_domains` intersected each declared module's own domain
    // with its parent's, over the whole workspace at once. Walking one module's
    // parent chain answers the same question for one key.

    /// The domains `module` is declared with, before the parent chain narrows
    /// them. Empty when nothing declares it.
    fn direct_module_domains_of(&self, module: &ModuleKey) -> Vec<Domain> {
        let mut domains = Vec::new();
        if let Some(parent) = module.parent() {
            for file in self.files_for_module(&parent).iter() {
                domains.extend(
                    self.queries
                        .declaration_facts_of(file)
                        .declared_module_domains
                        .iter()
                        .filter(|(declared, _)| declared == module)
                        .map(|(_, domain)| domain.clone()),
                );
            }
        }
        for declaration in self.cargo_routes.external_module_declarations() {
            if !self.is_analyzed(&declaration.target_file)
                || ModuleKey::new(
                    &declaration.target_file,
                    &rust_package_name(&declaration.target_file),
                ) != *module
            {
                continue;
            }
            if let Some(domain) = direct_import_scope_for_module(
                &declaration.declaring_file,
                &declaration.declaring_module,
                declaration.visibility.clone(),
            ) {
                domains.push(domain);
            }
        }
        domains
    }

    /// `module_domains`: the declared domains narrowed by every enclosing
    /// module. `None` means the module is not declared anywhere, which is a
    /// different answer from "declared but reachable from nowhere".
    pub(super) fn effective_module_domains_of(
        &self,
        module: &ModuleKey,
    ) -> Option<Arc<Vec<Domain>>> {
        if let Some(cached) = self.caches.module_domains.get(module) {
            return cached;
        }
        let direct = self.direct_module_domains_of(module);
        let effective = (!direct.is_empty()).then(|| {
            let parent_domains = module
                .parent()
                .and_then(|parent| self.effective_module_domains_of(&parent))
                .unwrap_or_else(|| Arc::new(vec![Domain::Public]));
            Arc::new(
                direct
                    .iter()
                    .flat_map(|direct| {
                        parent_domains
                            .iter()
                            .filter_map(|parent| direct.intersect(parent))
                    })
                    .collect::<Vec<_>>(),
            )
        });
        self.caches
            .module_domains
            .insert(module.clone(), effective.clone());
        effective
    }
    // ---------------------------------------------------------------- layer 3
    // Forward import edges. `build_importer_reverse` produced these for every
    // file in the workspace and then bucketed them by target; one file's edges
    // are a per-file question once module resolution is lazy, and the reverse
    // direction becomes candidates-then-verify over them.

    /// Every import edge `file` originates, in source order.
    pub(super) fn forward_import_edges_of(&self, file: &ProjectFile) -> Arc<Vec<RustImportEdge>> {
        if let Some(cached) = self.caches.forward_import_edges.get(file) {
            return cached;
        }
        let mut edges: Vec<RustImportEdge> = Vec::new();
        for binding in self.queries.import_bindings_of(file) {
            let owner = &binding.owner_module;
            let propagate_alias = matches!(binding.extent, RustImportExtent::Module { .. });
            let Some(edge_domain) =
                direct_import_scope_for_module(file, owner, binding.visibility.clone())
            else {
                continue;
            };
            let template = |target: RustResolvedModuleRoute,
                            local_name: String,
                            kind: RustImportEdgeKind| RustImportEdge {
                importer: file.clone(),
                importer_module: binding.importer_module.clone(),
                extent: binding.extent.clone(),
                local_name,
                target_file: target.target_file,
                target_module: target.target_module,
                kind,
                propagate_alias,
                domain: edge_domain.clone(),
                namespace: None,
                provenance: target.provenance,
            };
            if binding.is_glob {
                for resolved in self.resolve_segments(file, owner, &binding.path) {
                    self.admit_import_edge(
                        &mut edges,
                        template(resolved, String::new(), RustImportEdgeKind::Glob),
                    );
                }
                continue;
            }
            let Some(imported_name) = binding.path.last().cloned() else {
                continue;
            };
            for resolved in
                self.resolve_segments(file, owner, &binding.path[..binding.path.len() - 1])
            {
                self.admit_import_edge(
                    &mut edges,
                    template(
                        resolved,
                        binding.local_name.clone(),
                        RustImportEdgeKind::Named(imported_name.clone()),
                    ),
                );
            }
            for resolved in self.resolve_segments(file, owner, &binding.path) {
                self.admit_import_edge(
                    &mut edges,
                    template(
                        resolved,
                        binding.local_name.clone(),
                        RustImportEdgeKind::Namespace,
                    ),
                );
            }
        }
        let edges = Arc::new(edges);
        self.caches
            .forward_import_edges
            .insert(file.clone(), Arc::clone(&edges));
        edges
    }

    /// `add_import_edge`: an edge only exists when the two files can actually
    /// see each other.
    fn admit_import_edge(&self, edges: &mut Vec<RustImportEdge>, edge: RustImportEdge) {
        let cross_file = edge.target_file != edge.importer;
        let owners_intersect = self.owners_intersect(&edge.importer, &edge.target_file)
            || (self
                .cargo_routes
                .target_relation(&edge.importer, &edge.target_file)
                == RustCargoTargetRelation::Shared
                && edge_target_matches_exact_module(&edge));
        let admitted = match edge.provenance {
            RustRouteProvenance::Local => !cross_file || owners_intersect,
            RustRouteProvenance::CurrentLibrary => {
                !cross_file
                    || owners_intersect
                    || (self.has_owners(&edge.importer) && self.has_owners(&edge.target_file))
            }
            RustRouteProvenance::Dependency => true,
        };
        if admitted {
            edges.push(edge);
        }
    }

    /// Files that could import `identity`, before verification.
    ///
    /// `importer_reverse` was keyed by target file, but the persisted import
    /// rows are keyed by the module path AS WRITTEN, and one module is written
    /// five different ways by five different importers. So the candidate set is
    /// the IntelliJ shape instead: the files whose text mentions a name the
    /// importer must have written, plus the spellings that name no module at
    /// all. Verification recomputes each candidate's forward edges.
    fn importer_candidates_for(&self, identity: &RustSymbolIdentity) -> Vec<ProjectFile> {
        let mut candidates = self
            .queries
            .files_mentioning(&identity.name, RUST_OCCURRENCE_CODE);
        self.extend_module_importer_candidates(
            &mut candidates,
            &identity.module,
            Some(&identity.file),
        );
        candidates.push(identity.file.clone());
        candidates.retain(|candidate| self.is_analyzed(candidate));
        candidates.sort();
        candidates.dedup();
        candidates
    }

    /// The candidate sources that do not depend on the imported name: a
    /// namespace or glob importer writes the module, not the item.
    fn extend_module_importer_candidates(
        &self,
        candidates: &mut Vec<ProjectFile>,
        module: &ModuleKey,
        target_file: Option<&ProjectFile>,
    ) {
        match module.components.last() {
            // A written module path ends in the module's own name.
            Some(last) => {
                candidates.extend(self.queries.files_mentioning(last, RUST_OCCURRENCE_CODE))
            }
            // A crate root has no name to mention: `use crate::*` and
            // `use other_crate;` are the shapes that reach it.
            None => {
                candidates.extend(self.queries.files_importing_module_path("crate"));
                candidates.extend(
                    target_file.into_iter().flat_map(|file| {
                        self.cargo_routes.files_that_can_reference_target_of(file)
                    }),
                );
            }
        }
        // `self::` and `super::` name a module without spelling it. The first
        // can only come from a file backing the module itself; the second is an
        // indexed lookup over the written path.
        candidates.extend(self.files_for_module(module).iter().cloned());
        candidates.extend(self.queries.files_importing_module_path("super"));
    }

    /// The import edges that bind `identity`, computed from candidate files
    /// rather than from a workspace-wide reverse map.
    pub(super) fn edges_binding_identity(
        &self,
        identity: &RustSymbolIdentity,
    ) -> Vec<RustImportEdge> {
        let mut edges = Vec::new();
        for candidate in self.importer_candidates_for(identity) {
            edges.extend(
                self.forward_import_edges_of(&candidate)
                    .iter()
                    .filter(|edge| edge_matches_single_seed(edge, identity))
                    .cloned(),
            );
        }
        edges
    }

    /// `module_importers`: the files with an import edge onto module `module`.
    pub(super) fn importers_of_module(&self, module: &ModuleKey) -> Vec<ProjectFile> {
        let mut candidates = Vec::new();
        // Every file backing the module can be a target, so a namespace import
        // of it may be written from anywhere the module name occurs.
        let targets = self.files_for_module(module);
        self.extend_module_importer_candidates(&mut candidates, module, targets.first());
        candidates.retain(|candidate| self.is_analyzed(candidate));
        candidates.sort();
        candidates.dedup();
        let mut importers: Vec<ProjectFile> = candidates
            .into_iter()
            .filter(|candidate| {
                self.forward_import_edges_of(candidate)
                    .iter()
                    .any(|edge| edge.target_module == *module)
            })
            .collect();
        importers.sort();
        importers.dedup();
        importers
    }

    // ---------------------------------------------------- export chain walks

    /// Every name bound in `module` of `file`, declared there or imported into
    /// it, with the declaration each name ultimately reaches.
    pub(super) fn bindings_at(
        &self,
        file: &ProjectFile,
        module: &ModuleKey,
    ) -> Arc<Vec<RustModuleBinding>> {
        let key = (file.clone(), module.clone());
        if let Some(cached) = self.caches.module_bindings.get(&key) {
            return cached;
        }
        if let Some(partial) = self.binding_partial.borrow().get(&key) {
            self.binding_truncations
                .set(self.binding_truncations.get() + 1);
            return Arc::clone(partial);
        }
        let truncations_before = self.binding_truncations.get();
        // The v1 worklist seeded every declaration in the workspace before it
        // propagated anything, so an import that republishes a name declared
        // beside it always found that declaration already present. Seeding the
        // cycle answer with the declared half reproduces that.
        self.binding_partial.borrow_mut().insert(
            key.clone(),
            Arc::new(self.declared_bindings_at(file, module)),
        );
        let mut bindings = Arc::new(self.compute_bindings_at(file, module));
        if self.binding_truncations.get() != truncations_before {
            loop {
                self.binding_partial
                    .borrow_mut()
                    .insert(key.clone(), Arc::clone(&bindings));
                let next = Arc::new(self.compute_bindings_at(file, module));
                let converged = next.len() == bindings.len();
                bindings = next;
                if converged {
                    break;
                }
            }
        }
        self.binding_partial.borrow_mut().remove(&key);
        if self.binding_truncations.get() == truncations_before {
            self.caches
                .module_bindings
                .insert(key, Arc::clone(&bindings));
        }
        bindings
    }

    /// The half of `bindings_at` that needs no other module: what this file
    /// declares in this module.
    fn declared_bindings_at(
        &self,
        file: &ProjectFile,
        module: &ModuleKey,
    ) -> Vec<RustModuleBinding> {
        let mut bindings: Vec<RustModuleBinding> = Vec::new();
        for (identity, domains) in self
            .queries
            .declaration_facts_of(file)
            .domains
            .iter()
            .filter(|(identity, _)| identity.module == *module)
        {
            for domain in domains {
                push_unique_binding(
                    &mut bindings,
                    RustModuleBinding {
                        name: identity.name.clone(),
                        namespace: identity.namespace,
                        origin: identity.clone(),
                        domain: domain.clone(),
                    },
                );
            }
        }
        bindings
    }

    fn compute_bindings_at(
        &self,
        file: &ProjectFile,
        module: &ModuleKey,
    ) -> Vec<RustModuleBinding> {
        let mut bindings = self.declared_bindings_at(file, module);
        for edge in self
            .forward_import_edges_of(file)
            .iter()
            .filter(|edge| edge.propagate_alias && edge.importer_module == *module)
        {
            let name = match &edge.kind {
                RustImportEdgeKind::Named(_) => Some(edge.local_name.clone()),
                RustImportEdgeKind::Glob => None,
                RustImportEdgeKind::Namespace | RustImportEdgeKind::Qualified(_) => continue,
            };
            for (target, incoming) in self.edge_targets(edge) {
                let Some(effective) = self.effective_import_domain(&target, &incoming.domain, edge)
                else {
                    continue;
                };
                push_unique_binding(
                    &mut bindings,
                    RustModuleBinding {
                        name: name.clone().unwrap_or_else(|| target.name.clone()),
                        namespace: target.namespace,
                        origin: incoming.origin,
                        domain: effective,
                    },
                );
            }
        }
        bindings
    }

    /// The bindings at an edge's target that the edge actually binds.
    fn edge_targets(&self, edge: &RustImportEdge) -> Vec<(RustSymbolIdentity, RustModuleBinding)> {
        self.bindings_at(&edge.target_file, &edge.target_module)
            .iter()
            .filter(|binding| match &edge.kind {
                RustImportEdgeKind::Named(name) => binding.name == *name,
                RustImportEdgeKind::Namespace | RustImportEdgeKind::Glob => true,
                RustImportEdgeKind::Qualified(_) => false,
            })
            .map(|binding| {
                (
                    RustSymbolIdentity {
                        file: edge.target_file.clone(),
                        module: edge.target_module.clone(),
                        name: binding.name.clone(),
                        namespace: binding.namespace,
                    },
                    binding.clone(),
                )
            })
            .collect()
    }

    /// The domain an imported name carries in the importing module, or `None`
    /// when the import cannot see it at all.
    fn effective_import_domain(
        &self,
        target: &RustSymbolIdentity,
        domain: &Domain,
        edge: &RustImportEdge,
    ) -> Option<Domain> {
        // A module-private alias may flow into descendant modules, including
        // modules backed by another file, but two files are never the same
        // module: without this guard lib.rs and main.rs collapse to one key.
        if matches!(domain, Domain::Module(module)
            if *module == target.module
                && *module == edge.importer_module
                && target.file != edge.importer)
        {
            return None;
        }
        if self
            .effective_module_domains_of(&edge.target_module)
            .is_some_and(|domains| {
                !domains
                    .iter()
                    .any(|domain| domain.contains_module(&edge.importer_module))
            })
        {
            return None;
        }
        let effective = imported_identity_domain(target, domain, edge)?;
        effective
            .contains_module(&edge.importer_module)
            .then_some(effective)
    }

    /// `origin_routes_by_file`: the paths one file can write to reach a
    /// declaration, keyed by the path's first segment.
    pub(super) fn origin_routes_of(
        &self,
        file: &ProjectFile,
    ) -> Arc<HashMap<String, Vec<RustOriginRoute>>> {
        if let Some(cached) = self.caches.origin_routes.get(file) {
            return cached;
        }
        let mut routes: HashMap<String, Vec<RustOriginRoute>> = HashMap::default();
        for edge in self.forward_import_edges_of(file).iter() {
            for (target, binding) in self.edge_targets(edge) {
                let Some(effective) = self.effective_import_domain(&target, &binding.domain, edge)
                else {
                    continue;
                };
                let path = match &edge.kind {
                    RustImportEdgeKind::Named(_) => vec![edge.local_name.clone()],
                    RustImportEdgeKind::Namespace => {
                        vec![edge.local_name.clone(), target.name.clone()]
                    }
                    RustImportEdgeKind::Glob => vec![target.name.clone()],
                    RustImportEdgeKind::Qualified(path) => path.clone(),
                };
                let first_segment = path
                    .first()
                    .expect("origin routes always have a non-empty path")
                    .clone();
                routes
                    .entry(first_segment)
                    .or_default()
                    .push(RustOriginRoute {
                        importer_module: edge.importer_module.clone(),
                        extent: edge.extent.clone(),
                        path,
                        namespace: target.namespace,
                        origin: binding.origin,
                        domain: effective,
                        provenance: edge.provenance,
                    });
            }
        }
        let routes = Arc::new(routes);
        self.caches
            .origin_routes
            .insert(file.clone(), Arc::clone(&routes));
        routes
    }

    // --------------------------------------------------------- macro scopes

    /// One file's macro scope edges: the `mod` items it declares, with the
    /// bytes at which each becomes visible and whether it imports macros.
    ///
    /// The v1 build produced these for every file up front, which meant opening
    /// every syntax tree in the workspace. Splitting the pass per file is what
    /// makes the macro walk pay only for the files it reaches.
    pub(super) fn macro_scope_edges_of(&self, file: &ProjectFile) -> Arc<Vec<RustMacroScopeEdge>> {
        if let Some(cached) = self.caches.macro_scope_edges.get(file) {
            return cached;
        }
        let mut edges = Vec::new();
        if let Some(prepared) = self.analyzer.prepared_syntax(file) {
            let source = prepared.source();
            let root_module = ModuleKey::new(file, &rust_package_name(file));
            let mut pending = vec![(prepared.tree().root_node(), root_module)];
            while let Some((node, owner)) = pending.pop() {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                for child in children.into_iter().rev() {
                    if child.kind() != "mod_item" {
                        pending.push((child, owner.clone()));
                        continue;
                    }
                    let Some(name) = child.child_by_field_name("name").and_then(|name| {
                        source
                            .get(name.start_byte()..name.end_byte())
                            .map(str::trim)
                            .map(crate::analyzer::common::strip_raw_identifier_prefix)
                            .filter(|name| !name.is_empty())
                    }) else {
                        continue;
                    };
                    let child_module = owner.with_suffix(&[name.to_string()]);
                    let parent = RustMacroScopeKey {
                        file: file.clone(),
                        module: owner.clone(),
                    };
                    let imports_macros = rust_mod_item_has_macro_use(child, source);
                    if let Some(body) = child.child_by_field_name("body") {
                        edges.push(RustMacroScopeEdge {
                            parent,
                            child: RustMacroScopeKey {
                                file: file.clone(),
                                module: child_module.clone(),
                            },
                            declaration_start: child.start_byte(),
                            visibility_start: child.end_byte(),
                            imports_macros,
                        });
                        pending.push((body, child_module));
                        continue;
                    }
                    for child_file in
                        self.files_for_module(&child_module)
                            .iter()
                            .filter(|child_file| {
                                *child_file != file && self.owners_intersect(file, child_file)
                            })
                    {
                        edges.push(RustMacroScopeEdge {
                            parent: parent.clone(),
                            child: RustMacroScopeKey {
                                file: child_file.clone(),
                                module: child_module.clone(),
                            },
                            declaration_start: child.start_byte(),
                            visibility_start: child.end_byte(),
                            imports_macros,
                        });
                    }
                }
            }
        }
        let edges = Arc::new(edges);
        self.caches
            .macro_scope_edges
            .insert(file.clone(), Arc::clone(&edges));
        edges
    }

    /// Scope edges whose child is `scope`. An inline module's parent is in the
    /// same file; a file-backed module's parent is one of the files backing the
    /// module above it.
    fn macro_scope_edges_into(&self, scope: &RustMacroScopeKey) -> Vec<RustMacroScopeEdge> {
        let mut declaring: Vec<ProjectFile> = vec![scope.file.clone()];
        if let Some(parent) = scope.module.parent() {
            declaring.extend(self.files_for_module(&parent).iter().cloned());
        }
        declaring.sort();
        declaring.dedup();
        declaring
            .into_iter()
            .flat_map(|file| {
                self.macro_scope_edges_of(&file)
                    .iter()
                    .filter(|edge| edge.child == *scope)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn macro_scope_edges_out_of(&self, scope: &RustMacroScopeKey) -> Vec<RustMacroScopeEdge> {
        self.macro_scope_edges_of(&scope.file)
            .iter()
            .filter(|edge| edge.parent == *scope)
            .cloned()
            .collect()
    }

    /// The macro-namespace identity a declaration introduces, if it is a macro
    /// at module scope at all.
    fn macro_identity_of(&self, declaration: &CodeUnit) -> Option<RustSymbolIdentity> {
        self.queries
            .declaration_facts_of(declaration.source())
            .identities
            .iter()
            .find(|(candidate, identity)| {
                candidate == declaration && identity.namespace == RustSymbolNamespace::Macro
            })
            .map(|(_, identity)| identity.clone())
    }

    fn macro_definitions_in_scope(
        &self,
        scope: &RustMacroScopeKey,
        name: &str,
    ) -> Vec<(CodeUnit, usize)> {
        self.queries
            .declaration_facts_of(&scope.file)
            .identities
            .iter()
            .filter(|(_, identity)| {
                identity.namespace == RustSymbolNamespace::Macro
                    && identity.module == scope.module
                    && identity.name == name
            })
            .filter_map(|(declaration, _)| {
                self.analyzer
                    .ranges(declaration)
                    .into_iter()
                    .map(|range| range.start_byte)
                    .min()
                    .map(|start| (declaration.clone(), start))
            })
            .collect()
    }

    /// `macro_visible_ranges` for one macro: the byte ranges in which it is in
    /// scope, per scope, walking its own scope graph outward instead of
    /// building every macro's ranges up front.
    pub(super) fn macro_visible_ranges_of(
        &self,
        declaration: &CodeUnit,
    ) -> Arc<RustMacroScopeRanges> {
        if let Some(cached) = self.caches.macro_visible_ranges.get(declaration) {
            return cached;
        }
        let mut visible: RustMacroScopeRanges = HashMap::default();
        if let Some(identity) = self.macro_identity_of(declaration)
            && let Some(definition_end) = self
                .analyzer
                .ranges(declaration)
                .into_iter()
                .map(|range| range.end_byte)
                .min()
        {
            let mut visited = HashSet::default();
            let mut pending = vec![(
                RustMacroScopeKey {
                    file: identity.file.clone(),
                    module: identity.module.clone(),
                },
                definition_end,
            )];
            while let Some((scope, visible_after)) = pending.pop() {
                if !visited.insert((scope.clone(), visible_after)) {
                    continue;
                }
                let shadow_start = self
                    .macro_definitions_in_scope(&scope, &identity.name)
                    .into_iter()
                    .filter(|(candidate, start)| {
                        candidate != declaration && *start >= visible_after
                    })
                    .map(|(_, start)| start)
                    .min()
                    .unwrap_or(usize::MAX);
                visible
                    .entry(scope.clone())
                    .or_default()
                    .push((visible_after, shadow_start));
                pending.extend(
                    self.macro_scope_edges_into(&scope)
                        .into_iter()
                        .filter(|edge| edge.imports_macros && edge.visibility_start < shadow_start)
                        .map(|edge| (edge.parent, edge.visibility_start)),
                );
                pending.extend(
                    self.macro_scope_edges_out_of(&scope)
                        .into_iter()
                        .filter(|edge| {
                            edge.declaration_start >= visible_after
                                && edge.declaration_start < shadow_start
                        })
                        .map(|edge| (edge.child, 0)),
                );
            }
        }
        let visible = Arc::new(visible);
        self.caches
            .macro_visible_ranges
            .insert(declaration.clone(), Arc::clone(&visible));
        visible
    }

    /// The identity one declaration introduces.
    ///
    /// The v1 `declaration_identities` map was a `HashMap<CodeUnit, _>` filled
    /// by `extend`, so a file that produced the same key twice kept the last
    /// entry; taking the last match here reproduces that.
    pub(super) fn identity_of(&self, declaration: &CodeUnit) -> Option<RustSymbolIdentity> {
        self.queries
            .declaration_facts_of(declaration.source())
            .identities
            .iter()
            .filter(|(candidate, _)| candidate == declaration)
            .map(|(_, identity)| identity.clone())
            .next_back()
    }

    /// The value-namespace identity a tuple struct or tuple variant's
    /// constructor introduces.
    pub(super) fn value_constructor_identity_of(
        &self,
        declaration: &CodeUnit,
    ) -> Option<RustSymbolIdentity> {
        self.queries
            .declaration_facts_of(declaration.source())
            .value_constructors
            .iter()
            .filter(|(candidate, _)| candidate == declaration)
            .map(|(_, identity)| identity.clone())
            .next_back()
    }

    /// `declaration_domains` for one identity: the visibility domains the
    /// declaring file gave it. `None` when that file declares no such identity.
    pub(super) fn declared_domains_of(&self, identity: &RustSymbolIdentity) -> Option<Vec<Domain>> {
        self.queries
            .declaration_facts_of(&identity.file)
            .domains
            .iter()
            .find(|(candidate, _)| candidate == identity)
            .map(|(_, domains)| domains.clone())
    }

    /// Macro declarations in the workspace named `name`. The v1 lookup scanned
    /// every macro's visible-range entry; this is the store's indexed short-name
    /// lookup plus the per-candidate check that the name really is a macro.
    pub(super) fn macro_declarations_named(&self, name: &str) -> Vec<CodeUnit> {
        self.analyzer
            .lookup_candidates_by_identifier(name)
            .into_iter()
            .filter(|candidate| {
                self.is_analyzed(candidate.source()) && self.macro_identity_of(candidate).is_some()
            })
            .collect()
    }
}

fn push_unique(routes: &mut Vec<RustModuleAliasRoute>, route: RustModuleAliasRoute) {
    if !routes.contains(&route) {
        routes.push(route);
    }
}

/// The v1 worklist visited each `(target, origin, domain)` triple once; the
/// same triple reached twice through different edges must not bind twice here
/// either.
fn push_unique_binding(bindings: &mut Vec<RustModuleBinding>, binding: RustModuleBinding) {
    if !bindings.contains(&binding) {
        bindings.push(binding);
    }
}

fn sort_routes(routes: &mut [RustResolvedModuleRoute]) {
    routes.sort_by(|left, right| {
        left.target_file
            .cmp(&right.target_file)
            .then_with(|| {
                left.target_module
                    .crate_root
                    .cmp(&right.target_module.crate_root)
            })
            .then_with(|| {
                left.target_module
                    .components
                    .cmp(&right.target_module.components)
            })
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
}

/// Declaring-file candidates derived from `file`'s own path.
///
/// `rust_module_files_from_segments` builds a child path as
/// `module_root / segments`, where `module_root` is the declaring file's
/// directory when its stem is `lib`, `main` or `mod` and its directory plus
/// stem otherwise, optionally under a `src` prefix. Inverting that for one
/// child means trying every prefix of the child's own module path as the
/// declaring file's `module_root`, which is four candidate files per level.
fn path_parent_candidates(file: &ProjectFile) -> Vec<ProjectFile> {
    let relative = file.rel_path();
    let Some(stem) = relative.file_stem().and_then(OsStr::to_str) else {
        return Vec::new();
    };
    let directory = relative.parent().unwrap_or(Path::new(""));
    let module_path: PathBuf = if stem == "mod" {
        directory.to_path_buf()
    } else {
        directory.join(stem)
    };
    let components: Vec<&OsStr> = module_path.iter().collect();
    let mut roots: Vec<&[&OsStr]> = vec![components.as_slice()];
    if components.first() == Some(&OsStr::new("src")) {
        roots.push(&components[1..]);
    }
    let mut candidates = Vec::new();
    for base in roots {
        for length in 0..base.len() {
            let mut prefix = PathBuf::new();
            for component in &base[..length] {
                prefix.push(component);
            }
            for declaring_stem in ["lib", "main", "mod"] {
                candidates.push(ProjectFile::new(
                    file.root().to_path_buf(),
                    prefix.join(format!("{declaring_stem}.rs")),
                ));
            }
            if length > 0 {
                candidates.push(ProjectFile::new(
                    file.root().to_path_buf(),
                    prefix.with_extension("rs"),
                ));
            }
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, TestProject};
    use std::collections::BTreeSet;

    fn project(files: &[(&str, &str)]) -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (rel, body) in files {
            ProjectFile::new(root.clone(), rel)
                .write(body)
                .expect("write fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        // Force the analysis pass that persists the per-file fact rows.
        let _ = analyzer.get_analyzed_files();
        (temp, analyzer)
    }

    fn file(analyzer: &RustAnalyzer, suffix: &str) -> ProjectFile {
        analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with(suffix))
            .unwrap_or_else(|| panic!("{suffix} is analyzed"))
    }

    fn identity_named(
        walks: &RustUsageWalks<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> RustSymbolIdentity {
        walks
            .queries()
            .identities_in_file_named(file, name)
            .into_iter()
            .map(|(identity, _)| identity)
            .find(|identity| identity.namespace == RustSymbolNamespace::Type)
            .unwrap_or_else(|| panic!("{name} is declared in {file:?}"))
    }

    /// An inverted hit is a candidate, never an answer, and for an import edge
    /// the thing that decides is module resolution: two files import a `Widget`
    /// and a third only mentions the name, but exactly one of those imports
    /// resolves to the module that declares the target.
    ///
    /// Returning the candidate set unverified passes the first assertion and
    /// fails the second, which is what makes this a regression guard rather
    /// than a restatement of the implementation.
    #[test]
    fn a_candidate_importer_whose_import_resolves_elsewhere_is_rejected() {
        let (_temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod service;\npub mod decoy;\npub mod consumer;\npub mod bystander;\npub mod impostor;\n",
            ),
            ("src/service.rs", "pub struct Widget;\n"),
            ("src/decoy.rs", "pub struct Widget;\n"),
            (
                "src/consumer.rs",
                "use crate::service::Widget;\npub fn take(_: Widget) {}\n",
            ),
            (
                "src/impostor.rs",
                "use crate::decoy::Widget;\npub fn take(_: Widget) {}\n",
            ),
            (
                "src/bystander.rs",
                "pub fn describe() -> &'static str { \"Widget\" }\npub struct Widget;\n",
            ),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let service = file(&analyzer, "service.rs");
        let consumer = file(&analyzer, "consumer.rs");
        let target = identity_named(&walks, &service, "Widget");

        let candidates = walks.importer_candidates_for(&target);
        assert!(
            candidates.contains(&file(&analyzer, "impostor.rs"))
                && candidates.contains(&file(&analyzer, "bystander.rs")),
            "the offered candidates must include the files this test rejects: {candidates:?}"
        );

        let importers: BTreeSet<ProjectFile> = walks
            .edges_binding_identity(&target)
            .into_iter()
            .map(|edge| edge.importer)
            .collect();
        assert_eq!(
            importers,
            BTreeSet::from([consumer]),
            "only the import that resolves to the declaring module binds the target"
        );
    }

    /// A walk result is memoized for the analyzer that produced it and for no
    /// longer. The analyzer instance is the generation: `update_all` builds a
    /// fresh one with fresh caches, which is the invalidation these
    /// analyzer-derived values actually have.
    #[test]
    fn walk_results_are_memoized_per_generation_and_retire_with_the_analyzer() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "pub mod service;\n"),
            ("src/service.rs", "pub struct Widget;\n"),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let first = walks.files_in_module_package("service");
        let second = RustUsageWalks::new(&analyzer).files_in_module_package("service");
        assert!(
            Arc::ptr_eq(&first, &second),
            "a second walker in the same generation must hit the cache"
        );
        // Both the file whose package IS the module and the file that
        // declares `mod service;` back it, which is what `RustModuleFiles`
        // held in its two maps.
        assert_eq!(
            *first,
            vec![file(&analyzer, "lib.rs"), file(&analyzer, "service.rs")],
            "files were {first:?}"
        );

        let updated = analyzer.update_all();
        let after = RustUsageWalks::new(&updated).files_in_module_package("service");
        assert!(
            !Arc::ptr_eq(&first, &after),
            "a generation bump must not serve the previous generation's entry"
        );
        assert_eq!(*after, *first, "the answer itself is unchanged");
    }

    /// The export-chain walk replaced a global worklist with recursion, so it
    /// owns the termination the worklist's `visited` set used to provide. Two
    /// modules that publish each other's name are a cycle; the walk must still
    /// return the declaration each name really reaches.
    #[test]
    fn an_export_chain_cycle_terminates_and_keeps_the_declared_origin() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "pub mod alpha;\npub mod beta;\n"),
            (
                "src/alpha.rs",
                "pub struct Value;\npub use crate::beta::Echo;\n",
            ),
            (
                "src/beta.rs",
                "pub struct Echo;\npub use crate::alpha::Value;\n",
            ),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let alpha = file(&analyzer, "alpha.rs");
        let beta = file(&analyzer, "beta.rs");
        let alpha_module = walks.physical_root_of(&alpha).expect("alpha is analyzed");

        let bindings = walks.bindings_at(&alpha, &alpha_module);
        let echo = bindings
            .iter()
            .find(|binding| {
                binding.name == "Echo" && binding.namespace == RustSymbolNamespace::Type
            })
            .expect("alpha republishes Echo");
        assert_eq!(
            echo.origin.file, beta,
            "the re-exported name keeps beta's declaration as its origin: {bindings:?}"
        );
    }

    /// A module that republishes a name declared beside it -- `pub(crate) use`
    /// next to the `macro_rules!` it renames -- reaches itself through its own
    /// import edge, which is a cycle of length one. The visibility upgrade the
    /// republication exists to give must survive that.
    ///
    /// This pins the answer, not the mechanism: the guard that fails when the
    /// cycle handling is removed is
    /// `usages_rust_graph_test::rust_graph_tracks_bare_macro_invocations_through_structured_visibility`,
    /// demonstrated failing before the fixed-point iteration landed.
    #[test]
    fn a_module_republishing_a_name_declared_beside_it_keeps_the_import_domain() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "#[macro_use]\npub mod defs;\npub mod user;\n"),
            (
                "src/defs.rs",
                "macro_rules! target { () => {}; }\npub(crate) use target;\n",
            ),
            ("src/user.rs", "use crate::defs::target;\n"),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let defs = file(&analyzer, "defs.rs");
        let defs_module = walks.physical_root_of(&defs).expect("defs is analyzed");

        let bindings = walks.bindings_at(&defs, &defs_module);
        let republished: Vec<_> = bindings
            .iter()
            .filter(|binding| {
                binding.name == "target" && binding.namespace == RustSymbolNamespace::Macro
            })
            .collect();
        assert!(
            republished
                .iter()
                .any(|binding| matches!(binding.domain, Domain::Crate(_))),
            "`pub(crate) use` must widen the macro past its own module: {bindings:?}"
        );
    }

    /// A deep re-export chain must not exhaust the stack. The walk recurses
    /// once per link, so this pins the depth the implementation is known to
    /// survive rather than asserting an unbounded guarantee.
    #[test]
    fn an_export_chain_survives_a_deep_re_export_ladder() {
        const LINKS: usize = 250;
        let mut files: Vec<(String, String)> = Vec::new();
        let mut lib = String::new();
        for index in 0..LINKS {
            lib.push_str(&format!("pub mod link{index};\n"));
        }
        files.push(("src/lib.rs".to_string(), lib));
        for index in 0..LINKS {
            let body = if index + 1 == LINKS {
                "pub struct Value;\n".to_string()
            } else {
                format!("pub use crate::link{}::Value;\n", index + 1)
            };
            files.push((format!("src/link{index}.rs"), body));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(rel, body)| (rel.as_str(), body.as_str()))
            .collect();
        let (_temp, analyzer) = project(&borrowed);
        let walks = RustUsageWalks::new(&analyzer);
        let head = file(&analyzer, "link0.rs");
        let tail = file(&analyzer, &format!("link{}.rs", LINKS - 1));
        let head_module = walks.physical_root_of(&head).expect("link0 is analyzed");

        let bindings = walks.bindings_at(&head, &head_module);
        let value = bindings
            .iter()
            .find(|binding| binding.name == "Value")
            .expect("the head of the ladder publishes Value");
        assert_eq!(
            value.origin.file, tail,
            "the whole ladder resolves to the one real declaration"
        );
    }

    /// The alias search stops at the longest prefix that has any route and does
    /// not fall back to a shorter alias, matching what the v1 fixed point did.
    /// Choosing the prefix before filtering by domain is what keeps a private
    /// alias from shadowing the public one the source means.
    #[test]
    fn the_longest_alias_prefix_wins_and_the_search_stops_there() {
        let (_temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod outer;\npub mod real;\npub mod other;\n",
            ),
            ("src/real.rs", "pub mod inner;\n"),
            ("src/real/inner.rs", "pub struct Deep;\n"),
            ("src/other.rs", "pub struct Shallow;\n"),
            (
                "src/outer.rs",
                "pub use crate::real as routed;\npub use crate::real::inner as routed_inner;\n",
            ),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let outer = file(&analyzer, "outer.rs");
        let outer_module = walks.physical_root_of(&outer).expect("outer is analyzed");

        let one = walks.alias_routes_at(&outer_module.with_suffix(&["routed".to_string()]));
        let two = walks.alias_routes_at(&outer_module.with_suffix(&["routed_inner".to_string()]));
        assert!(!one.is_empty() && !two.is_empty(), "{one:?} {two:?}");

        // `routed_inner` is a one-component alias, so the longest prefix of
        // `routed_inner` is itself and the route lands on `real::inner`, never
        // on the shorter `routed` alias.
        let resolved = walks.resolve_segments(
            &outer,
            &outer_module.package(),
            &["routed_inner".to_string()],
        );
        assert_eq!(
            resolved
                .iter()
                .map(|route| route.target_file.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([file(&analyzer, "real.rs"), file(&analyzer, "real/inner.rs"),]),
            "the alias routes to `real::inner`, backed by the file whose \
             package it is and by the file that declares it: {resolved:?}"
        );
        assert!(
            !resolved
                .iter()
                .any(|route| route.target_module.components == ["real"]),
            "the shorter `routed` alias must not answer: {resolved:?}"
        );
    }

    /// The point of the redesign: a usage question is indexed lookups plus
    /// bounded walks, never a pass over every declaration in the workspace.
    /// The counter is the `2ba5dda4` structural-pin idiom.
    #[test]
    fn a_usage_query_performs_no_whole_workspace_declaration_scan() {
        let (_temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod service;\npub mod consumer;\npub mod unrelated;\n",
            ),
            ("src/service.rs", "pub struct Widget;\n"),
            (
                "src/consumer.rs",
                "use crate::service::Widget;\npub fn take(_: Widget) {}\n",
            ),
            ("src/unrelated.rs", "pub struct Gadget;\n"),
        ]);
        let service = file(&analyzer, "service.rs");
        let target = analyzer
            .declarations(&service)
            .into_iter()
            .find(|declaration| declaration.identifier() == "Widget")
            .expect("Widget declaration");
        let roots = BTreeSet::from([target]);
        analyzer.reset_full_declaration_scan_count_for_test();

        let seeds = analyzer.usage_binding_seeds(&roots);
        let importers = analyzer.usage_importers(&seeds);

        assert!(
            importers.contains(&file(&analyzer, "consumer.rs")),
            "the query still answers: {importers:?}"
        );
        assert_eq!(
            analyzer.full_declaration_scan_count_for_test(),
            0,
            "a usage query must not scan every declaration in the workspace"
        );
    }
}
