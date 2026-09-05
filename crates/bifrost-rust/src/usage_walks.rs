//! Bounded, memoized cross-file walks over the per-file Rust usage facts.
//!
//! This is the third layer of `.agents/plans/rust-usage-index-v2.md`. Milestone
//! 2a made the per-file questions store-backed and 2b did the same for the
//! inverted-derivable ones; what this file carries is the group that is
//! genuinely cross-file -- module-file resolution, physical ownership, alias
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

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use moka::sync::Cache;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};

use crate::graph_support::RustFactSource;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::cache::{
    build_weighted_cache, weight_alias_routes, weight_binding_edges, weight_forward_import_edges,
    weight_include_routes, weight_macro_scope_edges, weight_macro_visible_ranges,
    weight_module_bindings, weight_module_declarations, weight_module_domains, weight_module_probe,
    weight_origin_routes, weight_project_file_list,
};
use crate::cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
use crate::graph_support::{
    RustPackageFileIndex, rust_module_files_at, rust_relative_module_path,
    rust_relative_module_segments,
};
use crate::imports::{
    resolve_rust_module_path_with_crate, resolve_rust_module_segments_with_crate,
    rust_target_kind_root_alternative,
};
use crate::lexical_scope::RustCfgCondition;
use crate::usage::{
    Domain, ModuleKey, RustImportEdge, RustImportEdgeKind, RustImportExtent, RustMacroScopeEdge,
    RustMacroScopeKey, RustMacroScopeRanges, RustModuleAliasRoute, RustOriginRoute,
    RustResolvedModuleRoute, RustRouteProvenance, RustSymbolIdentity, RustSymbolNamespace,
    direct_import_scope_for_module_with_identity, edge_target_matches_exact_module,
    imported_identity_domain, rust_mod_item_has_macro_use,
};
use crate::usage_queries::{RustImportBinding, RustUsageQueries};
use brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_CODE;

/// One module's bindings are asked for by `(file, module)`.
pub type RustModuleBindingKey = (ProjectFile, ModuleKey);

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
pub struct RustWalkCaches {
    module_files: Cache<String, Arc<Vec<ProjectFile>>>,
    /// Module declarations of one short name, grouped by the module package
    /// each names. Not a separate concern from `module_files`: it is the store
    /// half of that answer, keyed on what the store query is actually keyed on.
    module_declarations: Cache<String, Arc<HashMap<String, Vec<ProjectFile>>>>,
    /// Store lookups the grouped index has run, for the memo's pin. One per
    /// distinct module short name per generation, not one per module package.
    module_declaration_lookups: AtomicU64,
    /// The four-candidate filesystem probe, per candidate module path. Not a
    /// fourth concern: it is the leaf of `module_resolution`, split out only
    /// because its key is a path rather than a package name.
    module_probes: Cache<PathBuf, Arc<Vec<ProjectFile>>>,
    /// Probe executions, for the memo's pin. On the analyzer's own hot path the
    /// increment happens once per miss, not once per lookup.
    module_probe_computations: AtomicU64,
    /// Alias-aware module-route resolutions, for the memo's pin. The #2632
    /// regression pin: the re-export closure asks for the import edges binding
    /// one identity per importer of a name, and every ask used to re-resolve
    /// every candidate file's `use` paths, so this grew with importers squared
    /// rather than with import statements.
    route_resolutions: AtomicU64,
    owner_roots: Cache<ProjectFile, Arc<Vec<ProjectFile>>>,
    module_domains: Cache<ModuleKey, Option<Arc<Vec<Domain>>>>,
    alias_routes: Cache<ModuleKey, Arc<Vec<RustModuleAliasRoute>>>,
    forward_import_edges: Cache<ProjectFile, Arc<Vec<RustImportEdge>>>,
    binding_edges: Cache<RustSymbolIdentity, Arc<Vec<RustImportEdge>>>,
    module_bindings: Cache<RustModuleBindingKey, Arc<Vec<RustModuleBinding>>>,
    origin_routes: Cache<ProjectFile, Arc<HashMap<String, Vec<RustOriginRoute>>>>,
    macro_scope_edges: Cache<ProjectFile, Arc<Vec<RustMacroScopeEdge>>>,
    macro_visible_ranges: Cache<CodeUnit, Arc<RustMacroScopeRanges>>,
    /// Composed include-expansion routes, per included file. The backward walk
    /// that fills it is in `usage_includes.rs`; the cache lives here with every
    /// other cross-file walk's, so it retires with the analyzer generation.
    pub include_routes: Cache<ProjectFile, Arc<Vec<crate::usage_includes::RustIncludeRoute>>>,
}

impl RustWalkCaches {
    pub fn new(memo_budget: u64) -> Self {
        let share = memo_budget / 16;
        Self {
            module_files: build_weighted_cache(share, weight_project_file_list),
            module_declarations: build_weighted_cache(share, weight_module_declarations),
            module_declaration_lookups: AtomicU64::new(0),
            owner_roots: build_weighted_cache(share, weight_project_file_list),
            module_domains: build_weighted_cache(share, weight_module_domains),
            alias_routes: build_weighted_cache(share, weight_alias_routes),
            forward_import_edges: build_weighted_cache(share, weight_forward_import_edges),
            binding_edges: build_weighted_cache(share, weight_binding_edges),
            module_bindings: build_weighted_cache(share, weight_module_bindings),
            origin_routes: build_weighted_cache(share, weight_origin_routes),
            macro_scope_edges: build_weighted_cache(share, weight_macro_scope_edges),
            macro_visible_ranges: build_weighted_cache(share, weight_macro_visible_ranges),
            module_probes: build_weighted_cache(share, weight_module_probe),
            include_routes: build_weighted_cache(share, weight_include_routes),
            module_probe_computations: AtomicU64::new(0),
            route_resolutions: AtomicU64::new(0),
        }
    }

    /// How many times the four-candidate filesystem probe actually ran, for the
    /// memo's regression pin.
    pub fn module_probe_computations(&self) -> u64 {
        self.module_probe_computations.load(AtomicOrdering::Relaxed)
    }

    /// How many workspace declaration lookups the module-declaration index has
    /// run. The #2622 regression pin: this grew with the number of module
    /// PACKAGES asked about, while the store query it issues is keyed on the
    /// module's short NAME alone.
    pub fn module_declaration_lookups(&self) -> u64 {
        self.module_declaration_lookups
            .load(AtomicOrdering::Relaxed)
    }

    /// How many alias-aware module-route resolutions the walks have run. The
    /// #2632 regression pin: see [`Self::route_resolutions`]'s field comment.
    pub fn route_resolutions(&self) -> u64 {
        self.route_resolutions.load(AtomicOrdering::Relaxed)
    }
}

/// A view that answers the cross-file usage questions by walking, borrowing the
/// analyzer for its store handle, its Cargo routes, and its bounded caches.
///
/// Cheap to construct: everything expensive is behind a cache on the analyzer,
/// and the only per-walker state is the cycle bookkeeping the alias recursion
/// needs.
pub struct RustUsageWalks<'a> {
    analyzer: &'a dyn RustFactSource,
    /// Proof that the request scope this walker serves is open. The walker is
    /// a per-query object whose lifetime is inside the scope's, so it carries
    /// the proof for the syntax reads its walks make (issue #2414 step 3).
    token: QueryToken<'a>,
    queries: RustUsageQueries<'a>,
    cargo_routes: Arc<RustCargoRouteIndex>,
    files: Arc<RustPackageFileIndex>,
    pub caches: Arc<RustWalkCaches>,
    /// The request's cooperative-cancellation predicate, when the caller
    /// supplied one. Every unbounded loop below polls it, and no cache is
    /// written after it trips: a scan whose budget expired must stop doing
    /// work, and the truncated answer it was holding must not be memoized for
    /// the rest of the generation.
    keep_going: Option<&'a (dyn Fn() -> bool + Sync)>,
    /// The alias recursion's cycle state. The v1 builds reached a fixed point
    /// by iterating the whole workspace; a recursion has to close its own
    /// cycles, which is what [`CycleWalk`] does.
    alias_walk: RefCell<CycleWalk<ModuleKey, Arc<Vec<RustModuleAliasRoute>>>>,
    /// The same for the export-chain recursion: a re-export cycle (`a`
    /// publishes `b`'s name, `b` publishes `a`'s) has to terminate, and a
    /// module that imports from itself -- `pub(crate) use target_macro;` beside
    /// the `macro_rules!` it republishes -- is a cycle of length one.
    binding_walk: RefCell<CycleWalk<RustModuleBindingKey, Arc<Vec<RustModuleBinding>>>>,
    /// How many times a fixed-point body ran, for the #1809 regression pin.
    computations: Cell<usize>,
}

/// The state of one memoized fixed-point walk over a graph that can contain
/// cycles.
///
/// The rule is dependency-driven chaotic iteration over everything the root
/// reaches. A nested lookup records a dependency and returns the value known
/// so far instead of consuming another Rust stack frame. When that value
/// grows, its dependents return to the explicit work queue. Both walks
/// accumulate their results through `push_unique`, so values only ever grow;
/// an empty queue is therefore the fixed point and every computed key can be
/// memoized together.
///
/// What this replaces, and why it had to: the first form answered a re-entry
/// from a partial and then iterated THAT frame to a local fixed point, keeping
/// its result out of the analyzer cache because it came out of a partial. In a
/// cycle every member does both, so every member re-runs its whole subtree
/// twice or more and nothing is ever memoized -- the cost is exponential in
/// the cycle. Measured on the synthetic fixture in this file's tests, one
/// `bindings_at` on eight modules importing three neighbours each ran the
/// recursion body 25,214 times and grew about fourfold per added module, which
/// is issue #1809's ">600 s at twenty-four modules".
struct CycleWalk<K, V> {
    /// The value so far for every key this walk has reached.
    partial: HashMap<K, V>,
    /// Keys whose computation has completed at least once.
    resolved: HashSet<K>,
    /// Keys waiting to be computed. `queued` makes enqueueing idempotent.
    queue: VecDeque<K>,
    queued: HashSet<K>,
    /// Reverse dependency edges used to revisit a key when one of its inputs
    /// grows. A key can depend on itself in a one-module re-export cycle.
    dependents: HashMap<K, HashSet<K>>,
    /// The key whose compute body is currently running, if any. Nested calls
    /// to `resolve_with_cycles` use this to register a dependency instead of
    /// recursing.
    current: Option<K>,
    /// Whether this walk owns the active explicit work queue. A nested lookup
    /// on the same walk is a dependency request; a top-level lookup starts a
    /// new queue.
    running: bool,
}

impl<K, V> Default for CycleWalk<K, V> {
    fn default() -> Self {
        Self {
            partial: HashMap::default(),
            resolved: HashSet::default(),
            queue: VecDeque::new(),
            queued: HashSet::default(),
            dependents: HashMap::default(),
            current: None,
            running: false,
        }
    }
}

/// What [`resolve_with_cycles`] hands back.
enum CycleAnswer<K, V> {
    /// The outermost frame closed its walk: `value` is final, and so is every
    /// `(key, value)` in `settled`.
    Settled { value: V, settled: Vec<(K, V)> },
    /// A value from a walk that is still running, or one that cancellation cut
    /// short. Correct for the frame that asked; not correct in general, so it
    /// must not reach the analyzer cache.
    Provisional(V),
}

/// Resolve `key` under [`CycleWalk`]'s explicit work-queue rule.
///
/// `compute` asks this function for the keys it depends on. While the queue is
/// running, those nested calls register reverse dependency edges and return
/// partial values rather than recursing. `seed` supplies the first partial
/// value -- for the export chain that is the module's own declarations, which
/// is what the v1 worklist seeded before it propagated anything.
fn resolve_with_cycles<K, V>(
    walk: &RefCell<CycleWalk<K, Arc<Vec<V>>>>,
    key: &K,
    cancelled: &dyn Fn() -> bool,
    seed: &dyn Fn(&K) -> Vec<V>,
    compute: &dyn Fn(&K) -> Vec<V>,
) -> CycleAnswer<K, Arc<Vec<V>>>
where
    K: Clone + Eq + std::hash::Hash,
{
    // A nested request is a dependency edge, not a recursive call. Return the
    // value currently known for the dependency and queue it for computation.
    if walk.borrow().running {
        let dependency = key.clone();
        let seeded = {
            let state = walk.borrow();
            (!state.partial.contains_key(&dependency)).then(|| Arc::new(seed(&dependency)))
        };
        let mut state = walk.borrow_mut();
        if let Some(value) = seeded {
            state.partial.insert(dependency.clone(), value);
        }
        let parent = state
            .current
            .clone()
            .expect("nested cycle lookup must have an active work item");
        state
            .dependents
            .entry(dependency.clone())
            .or_default()
            .insert(parent);
        if !state.resolved.contains(&dependency) && state.queued.insert(dependency.clone()) {
            // Work newly discovered dependencies before older pending work.
            // This keeps an acyclic export ladder linear while retaining the
            // same monotone chaotic fixed point for cycles.
            state.queue.push_front(dependency);
        }
        return CycleAnswer::Provisional(Arc::clone(&state.partial[key]));
    }

    {
        let mut state = walk.borrow_mut();
        state.running = true;
        state.partial.insert(key.clone(), Arc::new(seed(key)));
        state.queue.push_back(key.clone());
        state.queued.insert(key.clone());
    }

    let mut first_item = true;
    loop {
        let next = walk.borrow_mut().queue.pop_front();
        let Some(next) = next else { break };
        walk.borrow_mut().queued.remove(&next);
        // Preserve the old cancellation behavior: the root frame is allowed
        // to return its seed/declarations, but no queued dependency may start
        // after the request has expired.
        if !first_item && cancelled() {
            break;
        }
        first_item = false;
        walk.borrow_mut().current = Some(next.clone());
        let value = compute(&next);
        let dependents = {
            let mut state = walk.borrow_mut();
            state.current = None;
            state.resolved.insert(next.clone());
            let value = Arc::new(value);
            let grew = state
                .partial
                .insert(next.clone(), Arc::clone(&value))
                .is_none_or(|previous| previous.len() != value.len());
            if grew {
                state.dependents.get(&next).cloned().unwrap_or_default()
            } else {
                HashSet::default()
            }
        };
        if !dependents.is_empty() {
            let mut state = walk.borrow_mut();
            for dependent in dependents {
                if state.queued.insert(dependent.clone()) {
                    state.queue.push_front(dependent);
                }
            }
        }
    }

    let mut state = walk.borrow_mut();
    // A cancelled walk stopped with unfinished queue work, so its values are
    // truncated rather than converged and nothing may be published.
    let settled = if cancelled() {
        Vec::new()
    } else {
        state
            .resolved
            .iter()
            .map(|settled| (settled.clone(), Arc::clone(&state.partial[settled])))
            .collect()
    };
    let value = Arc::clone(&state.partial[key]);
    state.partial.clear();
    state.resolved.clear();
    state.queue.clear();
    state.queued.clear();
    state.dependents.clear();
    state.current = None;
    state.running = false;
    CycleAnswer::Settled { value, settled }
}

/// One name bound in one module, with the declaration it really names.
///
/// This is the per-module slice of what the v1 build derived globally: the
/// worklist in `build_origin_routes` seeded every declaration identity in the
/// workspace and pushed propagated aliases onto the same queue. Asking one
/// module what it binds is the same relation read from the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustModuleBinding {
    pub name: String,
    pub namespace: RustSymbolNamespace,
    /// The declaration this name ultimately refers to, unchanged along a
    /// re-export chain.
    pub origin: RustSymbolIdentity,
    pub domain: Domain,
}

impl<'a> RustUsageWalks<'a> {
    pub fn new(analyzer: &'a dyn RustFactSource, token: QueryToken<'a>) -> Self {
        Self::with_cargo_routes(analyzer, token, analyzer.cargo_routes(), None)
    }

    /// The request-scope proof this walker was built with (issue #2414 step 3).
    pub fn token(&self) -> QueryToken<'a> {
        self.token
    }

    /// The cancellable constructor. Cargo routes are the one input a walk
    /// cannot start without, and building them on a cold workspace is the step
    /// a cancelled candidate discovery has to be able to abandon -- but the
    /// walks themselves are the longer unbounded region, so the predicate is
    /// kept and polled by every loop below rather than being consumed here.
    pub fn new_while(
        analyzer: &'a dyn RustFactSource,
        token: QueryToken<'a>,
        keep_going: &'a (impl Fn() -> bool + Sync),
    ) -> Option<Self> {
        Some(Self::with_cargo_routes(
            analyzer,
            token,
            analyzer.cargo_routes_while(keep_going)?,
            Some(keep_going),
        ))
    }

    /// Every walk starts here, which is why the catch-up does too: a walk
    /// answers from persisted fact rows, so a live blob without rows would be
    /// silently absent from the answer rather than slow. ExecPlan Milestone 3;
    /// one atomic probe once the generation has settled.
    fn with_cargo_routes(
        analyzer: &'a dyn RustFactSource,
        token: QueryToken<'a>,
        cargo_routes: Arc<RustCargoRouteIndex>,
        keep_going: Option<&'a (dyn Fn() -> bool + Sync)>,
    ) -> Self {
        analyzer.ensure_rust_facts_caught_up();
        Self {
            analyzer,
            token,
            queries: RustUsageQueries::new(analyzer),
            cargo_routes,
            files: analyzer.package_file_index(),
            caches: Arc::clone(analyzer.walk_caches()),
            keep_going,
            alias_walk: RefCell::new(CycleWalk::default()),
            binding_walk: RefCell::new(CycleWalk::default()),
            computations: Cell::new(0),
        }
    }

    /// The request asked this walk to stop.
    ///
    /// Every loop that can visit an unbounded number of candidates polls this,
    /// and every cache write is gated on it. A truncated answer is a correct
    /// thing to return to a caller that is about to report `Cancelled`, and a
    /// catastrophic thing to memoize for the rest of the generation.
    pub fn cancelled(&self) -> bool {
        self.keep_going.is_some_and(|keep_going| !keep_going())
    }

    /// How many times a cycle-closing recursion body ran on this walker. The
    /// #1809 regression pin: on a cyclic module graph this used to grow
    /// exponentially in the number of modules.
    pub fn recursion_computations(&self) -> usize {
        self.computations.get()
    }

    pub fn queries(&self) -> &RustUsageQueries<'a> {
        &self.queries
    }

    /// Number of files whose persisted import rows this walk has decoded.
    /// Cyclic fixed-point rounds should reuse one query-scoped decode per file.
    pub fn import_binding_computations(&self) -> u64 {
        self.queries.import_binding_computations()
    }

    pub fn cargo_routes(&self) -> &Arc<RustCargoRouteIndex> {
        &self.cargo_routes
    }

    /// Membership in the analyzed-file set. The v1 index carried its own `files`
    /// vector for exactly this test; the package index answers it from its own
    /// membership set, which is one precomputed hash rather than the ~15
    /// `ProjectFile::cmp` calls a binary search over the sorted listing cost.
    pub fn is_analyzed(&self, file: &ProjectFile) -> bool {
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
    pub fn files_in_module_package(&self, package: &str) -> Arc<Vec<ProjectFile>> {
        if let Some(cached) = self.caches.module_files.get(package) {
            return cached;
        }
        let mut files: Vec<ProjectFile> = self.files.files_in_package(package).cloned().collect();
        if let Some(short_name) = package.rsplit('.').next().filter(|name| !name.is_empty()) {
            files.extend(
                self.module_declarations_named(short_name)
                    .get(package)
                    .into_iter()
                    .flatten()
                    .cloned(),
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

    /// Every analyzed file that declares a module named `short_name`, grouped
    /// by the module package the declaration names.
    ///
    /// `files_in_module_package` memoizes its answer per module PACKAGE, but
    /// the store lookup behind it is keyed on the module's short NAME: it reads
    /// every declaration in the workspace spelled `short_name` and keeps the
    /// ones whose fq name is the package asked for. Issue #2622 measured that
    /// mismatch: one whole-workspace usage scan asked about 29,014 distinct
    /// module packages -- most of them speculative ancestor candidates the
    /// alias walk synthesizes and no file declares -- and each ask paid its own
    /// candidate query and `CodeUnit` hydration, about half the scan's CPU.
    /// Grouping the query's own key makes it one lookup per short name.
    fn module_declarations_named(
        &self,
        short_name: &str,
    ) -> Arc<HashMap<String, Vec<ProjectFile>>> {
        if let Some(cached) = self.caches.module_declarations.get(short_name) {
            return cached;
        }
        self.caches
            .module_declaration_lookups
            .fetch_add(1, AtomicOrdering::Relaxed);
        let mut by_package: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for declaration in self.analyzer.lookup_candidates_by_identifier(short_name) {
            if !declaration.is_module() || !self.files.contains(declaration.source()) {
                continue;
            }
            by_package
                .entry(declaration.fq_name())
                .or_default()
                .push(declaration.source().clone());
        }
        let by_package = Arc::new(by_package);
        self.caches
            .module_declarations
            .insert(short_name.to_string(), Arc::clone(&by_package));
        by_package
    }

    pub fn files_for_module(&self, module: &ModuleKey) -> Arc<Vec<ProjectFile>> {
        self.files_in_module_package(&module.package())
    }

    /// `rust_module_files_from_path`, memoized.
    pub fn probed_module_files_from_path(
        &self,
        file: &ProjectFile,
        module_specifier: &str,
    ) -> Arc<Vec<ProjectFile>> {
        match rust_relative_module_path(file, module_specifier) {
            Some(relative_module) => self.probe_module_files(file, relative_module),
            None => Arc::new(Vec::new()),
        }
    }

    /// `rust_module_files_from_segments`, memoized.
    pub fn probed_module_files_from_segments(
        &self,
        file: &ProjectFile,
        segments: &[String],
    ) -> Arc<Vec<ProjectFile>> {
        match rust_relative_module_segments(file, segments) {
            Some(relative_module) => self.probe_module_files(file, relative_module),
            None => Arc::new(Vec::new()),
        }
    }

    /// The four-candidate filesystem probe for one module path.
    ///
    /// Every import specifier in every file asks for one of these, and the
    /// answers repeat heavily: a crate's modules are named by many of its
    /// files. Uncached this is four `ProjectFile` constructions and four
    /// `exists()` syscalls per ask. The empty answer is memoized too -- most
    /// probes find nothing, so that is the case worth keeping.
    fn probe_module_files(
        &self,
        file: &ProjectFile,
        relative_module: PathBuf,
    ) -> Arc<Vec<ProjectFile>> {
        if let Some(cached) = self.caches.module_probes.get(&relative_module) {
            return cached;
        }
        let files = Arc::new(rust_module_files_at(file, &relative_module));
        self.caches
            .module_probe_computations
            .fetch_add(1, AtomicOrdering::Relaxed);
        self.caches
            .module_probes
            .insert(relative_module, Arc::clone(&files));
        files
    }

    /// `RustModuleFiles::resolve`, verbatim over the lazy lookups.
    ///
    /// Deliberately not `RustAnalyzer::resolve_module_files`: that look-alike
    /// additionally drops external module declarations and disambiguates rooted
    /// collisions by Cargo target relation, so substituting it changes answers.
    pub fn resolve(
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
        let identity = self.queries.path_identity_of(importing_file);
        let package = &identity.package;
        let crate_package = &identity.crate_root_package;
        let Some(resolved_module) = self
            .cargo_routes
            .resolve_module_package(importing_file, module_specifier)
            .or_else(|| {
                resolve_rust_module_path_with_crate(package, crate_package, module_specifier)
            })
        else {
            return self
                .probed_module_files_from_path(importing_file, module_specifier)
                .as_ref()
                .clone();
        };

        let mut files = self
            .files_in_module_package(&resolved_module)
            .as_ref()
            .clone();
        files.extend(
            self.probed_module_files_from_path(importing_file, module_specifier)
                .iter()
                .cloned(),
        );
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
                target_module: self.queries.module_key_of(&root_file, &package),
                target_file: root_file,
                provenance: RustRouteProvenance::from(kind),
            }];
        }
        let crate_package = &self
            .queries
            .path_identity_of(importing_file)
            .crate_root_package;
        if let Some((resolved_module, kind)) = self
            .cargo_routes
            .resolve_module_package_segments_with_kind(importing_file, segments)
        {
            let provenance = RustRouteProvenance::from(kind);
            return self
                .files_in_module_package(&resolved_module)
                .iter()
                .map(|file| RustResolvedModuleRoute {
                    target_module: self.queries.module_key_of(file, &resolved_module),
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
                resolve_rust_module_segments_with_crate(importing_module, crate_package, segments)
            else {
                return Vec::new();
            };
            resolved
        } else {
            let relative = self
                .queries
                .module_key_of(importing_file, importing_module)
                .with_suffix(segments);
            if self.files_for_module(&relative).is_empty() {
                resolve_rust_module_segments_with_crate(importing_module, crate_package, segments)
                    .unwrap_or_else(|| relative.package())
            } else {
                relative.package()
            }
        };

        let mut files = self
            .files_in_module_package(&resolved_module)
            .as_ref()
            .clone();
        files.extend(
            self.probed_module_files_from_segments(importing_file, segments)
                .iter()
                .cloned(),
        );
        files.sort();
        files.dedup();
        let mut routes = files
            .into_iter()
            .map(|file| RustResolvedModuleRoute {
                target_module: self.queries.module_key_of(&file, &resolved_module),
                target_file: file,
                provenance: RustRouteProvenance::Local,
            })
            .collect::<Vec<_>>();
        // Second candidate for a target root file: the same name spelled under
        // the kind root, where the modules shared with sibling targets live.
        // Appended, so the target's own route still comes first.
        if let Some(alternative) = self.kind_root_alternative(importing_file, &resolved_module) {
            for file in self.files_in_module_package(&alternative).iter() {
                if routes.iter().all(|route| route.target_file != *file) {
                    routes.push(RustResolvedModuleRoute {
                        target_module: self.queries.module_key_of(file, &alternative),
                        target_file: file.clone(),
                        provenance: RustRouteProvenance::Local,
                    });
                }
            }
        }
        let rooted_path = matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        );
        routes.retain(|route| {
            let relation = self
                .cargo_routes
                .target_relation(importing_file, &route.target_file);
            if rooted_path {
                relation == RustCargoTargetRelation::Shared
                    || self.owners_intersect(importing_file, &route.target_file)
            } else {
                relation != RustCargoTargetRelation::Disjoint
            }
        });
        routes
    }

    /// Re-spell `package` -- a name resolved against `importing_file`'s own
    /// `crate::` root -- under the kind root shared with its sibling targets,
    /// when that names files and the own-root spelling did not.
    ///
    /// This is the second half of the target-root chain: `crate::common::x` and
    /// `common::x` in `benches/b.rs` first mean this bench's own `common`, and
    /// only then the `benches/common/mod.rs` every bench shares.
    fn kind_root_alternative(&self, importing_file: &ProjectFile, package: &str) -> Option<String> {
        let alternative = rust_target_kind_root_alternative(importing_file, package)?;
        (!self.files_in_module_package(&alternative).is_empty()).then_some(alternative)
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
    pub fn alias_routes_at(&self, alias: &ModuleKey) -> Arc<Vec<RustModuleAliasRoute>> {
        if let Some(cached) = self.caches.alias_routes.get(alias) {
            return cached;
        }
        match resolve_with_cycles(
            &self.alias_walk,
            alias,
            &|| self.cancelled(),
            &|_| Vec::new(),
            &|key| self.compute_alias_routes(key),
        ) {
            CycleAnswer::Provisional(routes) => routes,
            CycleAnswer::Settled { value, settled } => {
                for (key, routes) in settled {
                    self.caches.alias_routes.insert(key, routes);
                }
                value
            }
        }
    }

    fn compute_alias_routes(&self, alias: &ModuleKey) -> Vec<RustModuleAliasRoute> {
        self.computations.set(self.computations.get() + 1);
        let (Some(owner), Some(name)) = (alias.parent(), alias.components.last().cloned()) else {
            return Vec::new();
        };
        let owner_package = owner.package();
        let mut routes: Vec<RustModuleAliasRoute> = Vec::new();
        for file in self.files_for_module(&owner).iter() {
            if self.cancelled() {
                break;
            }
            // Two files can share a package name across crates; only the file
            // whose own crate root matches declares this alias key.
            if self.queries.module_key_of(file, &owner_package) != owner {
                continue;
            }
            for binding in self.queries.import_bindings_of(file).iter() {
                if !matches!(binding.extent, RustImportExtent::Module { .. })
                    || binding.owner_module != owner_package
                {
                    continue;
                }
                let path_identity = self.queries.path_identity_of(file);
                let Some(domain) = direct_import_scope_for_module_with_identity(
                    &owner_package,
                    binding.visibility.clone(),
                    self.cargo_routes.target_roots_for_file(file).contains(file),
                    &path_identity,
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
    pub fn resolve_segments(
        &self,
        importing_file: &ProjectFile,
        importing_module: &str,
        segments: &[String],
    ) -> Vec<RustResolvedModuleRoute> {
        self.caches
            .route_resolutions
            .fetch_add(1, AtomicOrdering::Relaxed);
        // Resolve bare paths against the physical module graph first. A child
        // module with the same name as an ancestor alias owns that path in
        // Rust's module namespace, so the ancestor walk below must not reach
        // past it. Cargo paths keep their routed provenance.
        if !segments.is_empty()
            && !matches!(
                segments.first().map(String::as_str),
                Some("crate" | "self" | "super")
            )
        {
            let direct = self.resolve_segments_plain(importing_file, importing_module, segments);
            if !direct.is_empty() {
                return direct;
            }
        }
        let crate_package = &self
            .queries
            .path_identity_of(importing_file)
            .crate_root_package;
        let owner_relative = if segments.is_empty() {
            Some(importing_module.to_string())
        } else if matches!(
            segments.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            resolve_rust_module_segments_with_crate(importing_module, crate_package, segments)
        } else {
            None
        };
        let importing_key = self.queries.module_key_of(importing_file, importing_module);
        // A module alias is visible in its declaring module and in every child
        // module, so a relative path is tried against the current module first
        // and then against each lexical ancestor. Without the ancestor walk an
        // `extern crate dep as alias;` at a crate root is invisible to any
        // nested module, which is where test modules write it. A rooted path
        // (`crate::`, `self::`, `super::`) names exactly one owner and takes no
        // ancestors.
        let owner_candidates = match owner_relative {
            Some(owner_relative) => {
                vec![self.queries.module_key_of(importing_file, &owner_relative)]
            }
            None => (0..=importing_key.components.len())
                .rev()
                .map(|length| ModuleKey {
                    crate_root: importing_key.crate_root.clone(),
                    components: importing_key.components[..length]
                        .iter()
                        .cloned()
                        .chain(segments.iter().cloned())
                        .collect(),
                })
                .collect(),
        };
        for candidate in owner_candidates {
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

    pub fn physical_root_of(&self, file: &ProjectFile) -> Option<ModuleKey> {
        self.is_analyzed(file).then(|| {
            self.queries
                .module_key_of(file, &self.queries.path_identity_of(file).package)
        })
    }

    pub fn is_actual_crate_root(&self, file: &ProjectFile) -> bool {
        if !self.is_analyzed(file) {
            return false;
        }
        let identity = self.queries.path_identity_of(file);
        identity.package == identity.crate_root_package
            || self.cargo_routes.target_roots_for_file(file).contains(file)
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
                self.probed_module_files_from_segments(declaring_file, relative)
                    .iter()
                    .filter(|file| *file != declaring_file && self.is_analyzed(file))
                    .cloned(),
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
                    && crate::graph_support::is_external_module_declaration(
                        self.analyzer,
                        self.token,
                        declaration,
                    )
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
    pub fn owner_roots_of(&self, file: &ProjectFile) -> Arc<Vec<ProjectFile>> {
        if let Some(cached) = self.caches.owner_roots.get(file) {
            return cached;
        }
        let mut roots = Vec::new();
        let mut visited = HashSet::default();
        let mut pending = vec![file.clone()];
        while let Some(current) = pending.pop() {
            if self.cancelled() {
                break;
            }
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
        if !self.cancelled() {
            self.caches
                .owner_roots
                .insert(file.clone(), Arc::clone(&roots));
        }
        roots
    }

    /// The crate a file belongs to when no analyzed file roots that crate. The
    /// v1 index precomputed this for every file; it reduces to one indexed
    /// package lookup, because an actual crate root is by definition a file
    /// whose package IS its crate root.
    pub fn inferred_crate_of(&self, file: &ProjectFile) -> Option<String> {
        let root = self.physical_root_of(file)?;
        (!self.crate_is_rooted(&root.crate_root)).then_some(root.crate_root)
    }

    fn crate_is_rooted(&self, crate_root: &str) -> bool {
        self.files_in_module_package(crate_root)
            .iter()
            .any(|file| self.is_actual_crate_root(file))
    }

    pub fn owners_intersect(&self, left: &ProjectFile, right: &ProjectFile) -> bool {
        if self.cargo_routes.target_relation(left, right) == RustCargoTargetRelation::Disjoint {
            return false;
        }
        let left_roots = self.owner_roots_of(left);
        let right_roots = self.owner_roots_of(right);
        if !left_roots.is_empty() || !right_roots.is_empty() {
            left_roots.iter().any(|root| right_roots.contains(root))
        } else {
            let left_crate = self.inferred_crate_of(left);
            left_crate.is_some() && left_crate == self.inferred_crate_of(right)
        }
    }

    pub fn owned_by(&self, file: &ProjectFile, root: &ProjectFile) -> bool {
        self.owner_roots_of(file).contains(root)
    }

    pub fn has_owners(&self, file: &ProjectFile) -> bool {
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
        // Every external `mod name;` in the workspace, so this is the one loop
        // here whose length is the workspace rather than the walk.
        for declaration in self.cargo_routes.external_module_declarations() {
            if self.cancelled() {
                break;
            }
            if !self.is_analyzed(&declaration.target_file)
                || self.queries.module_key_of(
                    &declaration.target_file,
                    &self
                        .queries
                        .path_identity_of(&declaration.target_file)
                        .package,
                ) != *module
            {
                continue;
            }
            let path_identity = self.queries.path_identity_of(&declaration.declaring_file);
            if let Some(domain) = direct_import_scope_for_module_with_identity(
                &declaration.declaring_module,
                declaration.visibility.clone(),
                self.is_actual_crate_root(&declaration.declaring_file),
                &path_identity,
            ) {
                domains.push(domain);
            }
        }
        domains
    }

    /// `module_domains`: the declared domains narrowed by every enclosing
    /// module. `None` means the module is not declared anywhere, which is a
    /// different answer from "declared but reachable from nowhere".
    pub fn effective_module_domains_of(&self, module: &ModuleKey) -> Option<Arc<Vec<Domain>>> {
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
        if !self.cancelled() {
            self.caches
                .module_domains
                .insert(module.clone(), effective.clone());
        }
        effective
    }
    // ---------------------------------------------------------------- layer 3
    // Forward import edges. `build_importer_reverse` produced these for every
    // file in the workspace and then bucketed them by target; one file's edges
    // are a per-file question once module resolution is lazy, and the reverse
    // direction becomes candidates-then-verify over them.

    /// Every import edge `file` originates, in source order.
    pub fn forward_import_edges_of(&self, file: &ProjectFile) -> Arc<Vec<RustImportEdge>> {
        if let Some(cached) = self.caches.forward_import_edges.get(file) {
            return cached;
        }
        let mut edges: Vec<RustImportEdge> = Vec::new();
        for binding in self.queries.import_bindings_of(file).iter() {
            if self.cancelled() {
                break;
            }
            self.append_forward_import_edges(file, binding, &mut edges);
        }
        let edges = Arc::new(edges);
        if !self.cancelled() {
            self.caches
                .forward_import_edges
                .insert(file.clone(), Arc::clone(&edges));
        }
        edges
    }

    fn append_forward_import_edges(
        &self,
        file: &ProjectFile,
        binding: &RustImportBinding,
        edges: &mut Vec<RustImportEdge>,
    ) {
        let owner = &binding.owner_module;
        let propagate_alias = matches!(binding.extent, RustImportExtent::Module { .. });
        let path_identity = self.queries.path_identity_of(file);
        let Some(edge_domain) = direct_import_scope_for_module_with_identity(
            owner,
            binding.visibility.clone(),
            self.cargo_routes.target_roots_for_file(file).contains(file),
            &path_identity,
        ) else {
            return;
        };
        let template = |target: RustResolvedModuleRoute,
                        local_name: String,
                        kind: RustImportEdgeKind| RustImportEdge {
            importer: file.clone(),
            importer_module: binding.importer_module.clone(),
            extent: binding.extent.clone(),
            source_path: binding.path.clone(),
            local_name,
            target_file: target.target_file,
            target_module: target.target_module,
            kind,
            propagate_alias,
            domain: edge_domain.clone(),
            namespace: None,
            provenance: target.provenance,
            cfg_condition: binding.cfg_condition.clone(),
        };
        if binding.is_glob {
            for resolved in self.resolve_segments(file, owner, &binding.path) {
                self.admit_import_edge(
                    edges,
                    template(resolved, String::new(), RustImportEdgeKind::Glob),
                );
            }
            return;
        }
        let Some(imported_name) = binding.path.last().cloned() else {
            return;
        };
        // `extern crate dep as tk;` binds only the crate namespace. Giving
        // it a named edge would also bind whatever `dep` names in this
        // module, so `tk::Item` would reach a same-named local `mod dep`.
        if !binding.is_extern_crate {
            for resolved in
                self.resolve_segments(file, owner, &binding.path[..binding.path.len() - 1])
            {
                self.admit_import_edge(
                    edges,
                    template(
                        resolved,
                        binding.local_name.clone(),
                        RustImportEdgeKind::Named(imported_name.clone()),
                    ),
                );
            }
        }
        for resolved in self.resolve_segments(file, owner, &binding.path) {
            self.admit_import_edge(
                edges,
                template(
                    resolved,
                    binding.local_name.clone(),
                    RustImportEdgeKind::Namespace,
                ),
            );
        }
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
                && edge_target_matches_exact_module(
                    &edge,
                    &self
                        .queries
                        .path_identity_of(&edge.target_file)
                        .crate_root_package,
                ));
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
    pub fn importer_candidates_for(&self, identity: &RustSymbolIdentity) -> Vec<ProjectFile> {
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
            // A structured import either imports the module by this name or
            // writes a module path ending in it. Ordinary code mentions cannot
            // produce an import edge and need not enter semantic verification.
            Some(last) => candidates.extend(
                self.queries
                    .files_importing_module_component(last)
                    .into_iter()
                    .filter(|candidate| {
                        self.queries
                            .import_bindings_of(candidate)
                            .iter()
                            .any(|binding| {
                                binding_names_module_component(binding, last)
                                    && self.binding_could_reach_module(candidate, binding, module)
                            })
                    }),
            ),
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
        // indexed lookup over the written path, then a structured owner check.
        candidates.extend(self.files_for_module(module).iter().cloned());
        candidates.extend(self.parent_module_importer_candidates(module));
    }

    /// Files with an exact `super` import whose lexical module is a child of
    /// `module`.
    ///
    /// The inverted lookup is deliberately only the first step: `super` is
    /// common across a workspace, but its meaning is completely determined by
    /// the persisted import owner's composed module key. Inspecting those rows
    /// is much cheaper than resolving every candidate's full forward edges.
    fn parent_module_importer_candidates(&self, module: &ModuleKey) -> Vec<ProjectFile> {
        self.queries
            .files_importing_module_path("super")
            .into_iter()
            .filter(|candidate| {
                let file_module = self
                    .queries
                    .module_key_of(candidate, &self.queries.path_identity_of(candidate).package);
                file_module == *module || file_module.parent().as_ref() == Some(module)
            })
            .filter(|candidate| {
                self.queries
                    .import_bindings_of(candidate)
                    .iter()
                    .any(|binding| {
                        let imports_from_parent = if binding.is_glob {
                            binding.path.as_slice() == ["super"]
                        } else {
                            binding.path.len() == 2 && binding.path[0] == "super"
                        };
                        imports_from_parent
                            && binding.importer_module.parent().as_ref() == Some(module)
                    })
            })
            .collect()
    }

    /// Whether a binding's module-bearing path can reach `module` without
    /// performing the full alias and file-resolution walk.
    ///
    /// Rooted paths have one structural interpretation, so a mismatch is a
    /// proof that the binding is irrelevant. Bare paths may resolve through a
    /// visible alias or an ancestor module and remain candidates for the full
    /// verifier.
    fn binding_could_reach_module(
        &self,
        candidate: &ProjectFile,
        binding: &RustImportBinding,
        module: &ModuleKey,
    ) -> bool {
        if !matches!(
            binding.path.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            return true;
        }
        let crate_package = &self.queries.path_identity_of(candidate).crate_root_package;
        let module_path_end = if binding.is_glob {
            binding.path.len()
        } else {
            binding.path.len().saturating_sub(1)
        };
        [module_path_end, binding.path.len()]
            .into_iter()
            .filter(|end| *end > 0)
            .any(|end| {
                resolve_rust_module_segments_with_crate(
                    &binding.owner_module,
                    crate_package,
                    &binding.path[..end],
                )
                .is_some_and(|resolved| self.queries.module_key_of(candidate, &resolved) == *module)
            })
    }

    /// The import edges that bind `identity`, computed from candidate files
    /// rather than from a workspace-wide reverse map.
    ///
    /// A candidate's edges are the candidate's forward import edges: which
    /// module a `use` reaches is a property of the writing file, not of the
    /// identity being asked about. Selecting from
    /// [`Self::forward_import_edges_of`] therefore resolves each candidate's
    /// module routes once per generation and answers every later identity from
    /// that memo. The re-export closure in `usage.rs` asks this question once
    /// per importer of a widely imported name -- 328 identities named
    /// `WorkspaceAnalyzer` over the same 291 candidates on this repository
    /// (#2632) -- so resolving per identity made the closure quadratic in the
    /// import count and spent 39 s of a 47 s scan re-deriving routes it had
    /// already derived.
    pub fn edges_binding_identity(&self, identity: &RustSymbolIdentity) -> Vec<RustImportEdge> {
        let _scope = brokk_bifrost_core::profiling::scope("rust_usage_walks::binding_edges");
        if let Some(cached) = self.caches.binding_edges.get(identity) {
            return cached.as_ref().clone();
        }
        let mut edges = Vec::new();
        let candidates = self.importer_candidates_for(identity);
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "rust binding identity={} candidates={}",
                identity.name,
                candidates.len(),
            )
        });
        for candidate in candidates {
            if self.cancelled() {
                break;
            }
            edges.extend(
                self.forward_import_edges_of(&candidate)
                    .iter()
                    .filter(|edge| edge_binds_identity(edge, identity))
                    .cloned(),
            );
        }
        if !self.cancelled() {
            self.caches
                .binding_edges
                .insert(identity.clone(), Arc::new(edges.clone()));
        }
        edges
    }

    /// `module_importers`: the files with an import edge onto module `module`.
    pub fn importers_of_module(&self, module: &ModuleKey) -> Vec<ProjectFile> {
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
            .take_while(|_| !self.cancelled())
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
    pub fn bindings_at(
        &self,
        file: &ProjectFile,
        module: &ModuleKey,
    ) -> Arc<Vec<RustModuleBinding>> {
        let key = (file.clone(), module.clone());
        if let Some(cached) = self.caches.module_bindings.get(&key) {
            return cached;
        }
        // The v1 worklist seeded every declaration in the workspace before it
        // propagated anything, so an import that republishes a name declared
        // beside it always found that declaration already present. Seeding the
        // cycle answer with the declared half reproduces that.
        match resolve_with_cycles(
            &self.binding_walk,
            &key,
            &|| self.cancelled(),
            &|key| self.declared_bindings_at(&key.0, &key.1),
            &|key| self.compute_bindings_at(&key.0, &key.1),
        ) {
            CycleAnswer::Provisional(bindings) => bindings,
            CycleAnswer::Settled { value, settled } => {
                for (key, bindings) in settled {
                    self.caches.module_bindings.insert(key, bindings);
                }
                value
            }
        }
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
        self.computations.set(self.computations.get() + 1);
        let mut bindings = self.declared_bindings_at(file, module);
        for edge in self
            .forward_import_edges_of(file)
            .iter()
            .filter(|edge| edge.propagate_alias && edge.importer_module == *module)
        {
            if self.cancelled() {
                break;
            }
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
    pub fn origin_routes_of(
        &self,
        file: &ProjectFile,
    ) -> Arc<HashMap<String, Vec<RustOriginRoute>>> {
        if let Some(cached) = self.caches.origin_routes.get(file) {
            return cached;
        }
        let mut routes: HashMap<String, Vec<RustOriginRoute>> = HashMap::default();
        for edge in self.forward_import_edges_of(file).iter() {
            if self.cancelled() {
                break;
            }
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
                        is_glob_import: matches!(edge.kind, RustImportEdgeKind::Glob),
                        namespace: target.namespace,
                        origin: binding.origin,
                        domain: effective,
                        provenance: edge.provenance,
                        cfg_condition: edge.cfg_condition.clone(),
                    });
            }
        }
        let routes = Arc::new(routes);
        if !self.cancelled() {
            self.caches
                .origin_routes
                .insert(file.clone(), Arc::clone(&routes));
        }
        routes
    }

    // --------------------------------------------------------- macro scopes

    /// One file's macro scope edges: the `mod` items it declares, with the
    /// bytes at which each becomes visible and whether it imports macros.
    ///
    /// The v1 build produced these for every file up front, which meant opening
    /// every syntax tree in the workspace. Splitting the pass per file is what
    /// makes the macro walk pay only for the files it reaches.
    pub fn macro_scope_edges_of(&self, file: &ProjectFile) -> Arc<Vec<RustMacroScopeEdge>> {
        if let Some(cached) = self.caches.macro_scope_edges.get(file) {
            return cached;
        }
        let mut edges = Vec::new();
        if let Some(prepared) = self.analyzer.prepared_syntax(self.token, file) {
            let source = prepared.source();
            let root_module = self
                .queries
                .module_key_of(file, &self.queries.path_identity_of(file).package);
            let mut pending = vec![(prepared.tree().root_node(), root_module)];
            while let Some((node, owner)) = pending.pop() {
                if self.cancelled() {
                    break;
                }
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
                            .map(brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix)
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
        if !self.cancelled() {
            self.caches
                .macro_scope_edges
                .insert(file.clone(), Arc::clone(&edges));
        }
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
    pub fn macro_visible_ranges_of(&self, declaration: &CodeUnit) -> Arc<RustMacroScopeRanges> {
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
                if self.cancelled() {
                    break;
                }
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
        if !self.cancelled() {
            self.caches
                .macro_visible_ranges
                .insert(declaration.clone(), Arc::clone(&visible));
        }
        visible
    }

    /// The identity one declaration introduces.
    ///
    /// The v1 `declaration_identities` map was a `HashMap<CodeUnit, _>` filled
    /// by `extend`, so a file that produced the same key twice kept the last
    /// entry; taking the last match here reproduces that.
    pub fn identity_of(&self, declaration: &CodeUnit) -> Option<RustSymbolIdentity> {
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
    pub fn value_constructor_identity_of(
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
    pub fn declared_domains_of(&self, identity: &RustSymbolIdentity) -> Option<Vec<Domain>> {
        self.queries
            .declaration_facts_of(&identity.file)
            .domains
            .iter()
            .find(|(candidate, _)| candidate == identity)
            .map(|(_, domains)| domains.clone())
    }

    /// `declaration_cfg_conditions` for one identity: the `#[cfg(...)]`
    /// predicates the declaring file's items for it were written under.
    ///
    /// An identity the declaring file does not carry proves nothing about its
    /// guard, so the caller reads the absent answer as `Unknown` rather than as
    /// `Always`.
    pub fn declared_cfg_conditions_of(
        &self,
        identity: &RustSymbolIdentity,
    ) -> Option<Vec<RustCfgCondition>> {
        self.queries
            .declaration_facts_of(&identity.file)
            .cfg_conditions
            .iter()
            .find(|(candidate, _)| candidate == identity)
            .map(|(_, conditions)| conditions.clone())
    }

    /// Macro declarations in the workspace named `name`. The v1 lookup scanned
    /// every macro's visible-range entry; this is the store's indexed short-name
    /// lookup plus the per-candidate check that the name really is a macro.
    pub fn macro_declarations_named(&self, name: &str) -> Vec<CodeUnit> {
        self.analyzer
            .lookup_candidates_by_identifier(name)
            .into_iter()
            .take_while(|_| !self.cancelled())
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

fn binding_names_module_component(binding: &RustImportBinding, component: &str) -> bool {
    binding
        .path
        .last()
        .is_some_and(|path_component| path_component == component)
        || (!binding.is_glob
            && binding.path.len() > 1
            && binding.path[binding.path.len() - 2] == component)
}

/// Whether one forward import edge binds `identity`.
///
/// An edge binds an identity when it reaches the identity's declaring module in
/// its declaring file. A named edge additionally carries the name it imported,
/// and only the identity of that name is bound; a glob or namespace edge binds
/// whatever the module exports, so the reaching test is the whole test.
fn edge_binds_identity(edge: &RustImportEdge, identity: &RustSymbolIdentity) -> bool {
    if edge.target_file != identity.file || edge.target_module != identity.module {
        return false;
    }
    match &edge.kind {
        RustImportEdgeKind::Named(imported_name) => imported_name == &identity.name,
        RustImportEdgeKind::Glob
        | RustImportEdgeKind::Namespace
        | RustImportEdgeKind::Qualified(_) => true,
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
/// `probed_module_files_from_segments` builds a child path as
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
                candidates.push(file.with_rel_path(prefix.join(format!("{declaring_stem}.rs"))));
            }
            if length > 0 {
                candidates.push(file.with_rel_path(prefix.with_extension("rs")));
            }
        }
    }
    candidates
}
