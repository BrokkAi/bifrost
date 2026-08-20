//! Include-expansion routes, composed backwards from per-blob rows.
//!
//! Rust's `include!("path")` splices another file's tokens into a host. The
//! included file keeps its own physical identity in the declaration index, but
//! its imports resolve at the host, so a usage found in an included file has to
//! be attributed through the host's crate, module and import bindings. That
//! attribution is a [`RustIncludeRoute`].
//!
//! The v1 index built every route in the workspace eagerly, forwards: seed one
//! route per (file, owning root), then breadth-first along include edges,
//! threading the module package and the accumulated host bindings, and key the
//! resulting map by the INCLUDED file. That is a whole-workspace materialization
//! and it is exactly what usage v2 removes.
//!
//! Here the same relation is read backwards, one question at a time. For the
//! forward build,
//!
//! ```text
//! routes(T) = { compose(R, E) : H --E--> T, R in seeds(H) + routes(H) }
//! ```
//!
//! which is a recursion on `T` that needs only T's includers -- so the question
//! "what are this file's include routes" costs the includers it actually has,
//! not the workspace.
//!
//! Finding those includers is the same candidate-then-verify contract
//! `usage_queries.rs` documents for `rust_identifier_occurrences`.
//! `rust_include_edges` is indexed by `file_name`, the literal's last path
//! component, which answers "which blobs include something called this" --
//! CANDIDATES. Each candidate is confirmed by resolving that candidate's own
//! stored `relative_path` against that candidate's own directory and comparing
//! to the file being asked about, so verification touches one row per candidate
//! and the cost is the number of files that include a file of that name.
//!
//! The upward walk is iterative with an explicit queue and bounded by the same
//! `(host_file, route)` visited set the forward build relies on for the same
//! cycle. Its result is memoized per included file in `RustWalkCaches`, which
//! retires with the analyzer generation like every other cross-file walk cache.

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::rust_facts::{RustIncludeBindingKind, RustIncludeEdgeFact};
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinding, ImportKind};
use brokk_bifrost_core::analyzer::{Language, ProjectFile};
use brokk_bifrost_core::hash::HashSet;

use crate::graph_support::RustFactSource;
use crate::imports::rust_crate_root_package;
use crate::lexical_scope::lexical_package_at;
use crate::usage::{ModuleKey, RustSymbolIdentity, RustSymbolNamespace};
use crate::usage_walks::RustUsageWalks;

/// The lexical owner route for a physical file consumed by `include!(...)`.
///
/// The declaration index keeps the included file's physical identity. Rust
/// resolves its imports at the macro host, so this route carries the crate and
/// module package that the included tokens inherit from that host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RustIncludeRoute {
    pub root_file: ProjectFile,
    pub crate_package: String,
    pub module_package: String,
    pub host_bindings: Vec<RustIncludeHostBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RustIncludeHostBinding {
    pub local_name: String,
    pub module_specifier: String,
    pub imported_name: Option<String>,
    pub module_package: String,
    pub scope_start: usize,
    pub kind: RustIncludeBindingKind,
}

impl RustIncludeHostBinding {
    /// The binding shape the shared import vocabulary speaks, for the callers
    /// that hand a host binding to a general resolver.
    pub fn import_kind(&self) -> ImportKind {
        match self.kind {
            RustIncludeBindingKind::Named => ImportKind::Named,
            RustIncludeBindingKind::Namespace => ImportKind::Namespace,
            RustIncludeBindingKind::Glob => ImportKind::Glob,
        }
    }
}

/// The include routes of one file, composed on demand.
///
/// Cheap to construct: the walk it wraps is memoized on the analyzer, so a
/// repeated question inside one request costs a cache probe.
pub struct RustIncludeRoutes<'a> {
    analyzer: &'a dyn RustFactSource,
    walks: RustUsageWalks<'a>,
}

impl<'a> RustIncludeRoutes<'a> {
    pub fn new(analyzer: &'a dyn RustFactSource, token: QueryToken<'a>) -> Self {
        Self {
            analyzer,
            walks: RustUsageWalks::new(analyzer, token),
        }
    }

    /// Every include route that reaches `file`, in a stable order.
    ///
    /// Empty for the overwhelmingly common case of a file nothing includes, at
    /// the cost of one indexed seek on `rust_include_edges.file_name`.
    pub fn include_routes_for(&self, file: &ProjectFile) -> Arc<Vec<RustIncludeRoute>> {
        if let Some(cached) = self.analyzer.walk_caches().include_routes.get(file) {
            return cached;
        }
        let routes = Arc::new(self.compose_include_routes(file));
        self.analyzer
            .walk_caches()
            .include_routes
            .insert(file.clone(), Arc::clone(&routes));
        routes
    }

    /// Every analyzed file that some other file splices in with `include!`.
    ///
    /// The inverse-scan file selection needs this before it can decide which
    /// files to read: a file spliced into a host is not reachable through the
    /// ordinary module graph, so it would otherwise be invisible. It is a scan
    /// of `rust_include_edges`, whose row count is the number of `include!`
    /// invocations in the workspace, and it materializes only the resolved
    /// target paths -- no route is composed here.
    pub fn all_included_files(&self) -> Vec<ProjectFile> {
        let live = self.analyzer.live_blobs();
        let mut included = Vec::new();
        for oid in self.analyzer.rust_include_host_blobs() {
            for host in live.paths_for_oid(oid) {
                let Some(facts) = self.analyzer.rust_usage_facts_of_blob(oid) else {
                    continue;
                };
                for edge in &facts.include_edges {
                    if let Some(target) = resolve_include_target(&host, &edge.relative_path) {
                        included.push(target);
                    }
                }
            }
        }
        included.sort();
        included.dedup();
        included
    }

    /// The backward walk itself.
    ///
    /// One explicit queue over `(included file, pending route to extend)`. A
    /// frame pops an included file, finds its verified includers, and for each
    /// one either emits a finished route (from that includer's own seeds) or
    /// pushes the includer back on the queue to have ITS includers found -- the
    /// nested-include case. The visited set is on `(host_file, edge_start)`,
    /// which is what terminates a cyclic `include!` chain.
    fn compose_include_routes(&self, file: &ProjectFile) -> Vec<RustIncludeRoute> {
        let mut routes = Vec::new();
        // Each frame is (file whose includers to find, the suffix of the route
        // already composed below it). `suffix` is applied outermost-last, so it
        // is built in reverse and folded once a seed is reached.
        let mut pending: VecDeque<(ProjectFile, Vec<(ProjectFile, RustIncludeEdgeFact)>)> =
            VecDeque::new();
        pending.push_back((file.clone(), Vec::new()));
        let mut visited: HashSet<(ProjectFile, usize)> = HashSet::default();
        while let Some((included, suffix)) = pending.pop_front() {
            if self.walks.cancelled() {
                break;
            }
            for (host, edge) in self.verified_includers_of(&included) {
                if !visited.insert((host.clone(), edge.include_start)) {
                    continue;
                }
                let mut chain = suffix.clone();
                chain.push((host.clone(), edge));
                for seed in self.seed_routes_of(&host) {
                    if let Some(route) = self.fold_chain(seed, &chain) {
                        routes.push(route);
                    }
                }
                pending.push_back((host, chain));
            }
        }
        routes.sort();
        routes.dedup();
        routes
    }

    /// Apply an include chain to a seed route, outermost host first.
    ///
    /// `chain` is ordered innermost-first, the order the backward walk
    /// discovered it, so it is folded in reverse: the outermost host's splice
    /// decides the module package the next one inherits, exactly as the forward
    /// build threaded it.
    fn fold_chain(
        &self,
        seed: RustIncludeRoute,
        chain: &[(ProjectFile, RustIncludeEdgeFact)],
    ) -> Option<RustIncludeRoute> {
        let mut route = seed;
        for (host, edge) in chain.iter().rev() {
            route = self.compose(route, host, edge)?;
        }
        Some(route)
    }

    /// Extend `route` across one include edge written in `host`.
    fn compose(
        &self,
        route: RustIncludeRoute,
        host: &ProjectFile,
        edge: &RustIncludeEdgeFact,
    ) -> Option<RustIncludeRoute> {
        let prepared = self.analyzer.prepared_syntax(self.walks.token(), host)?;
        let module_package =
            lexical_package_at(&route.module_package, prepared.source(), edge.include_start);
        let mut host_bindings = route.host_bindings;
        for binding in &edge.host_bindings {
            // A named or namespace binding shadows an earlier binding of the
            // same local name; a glob binds no name and can only add.
            if binding.kind != RustIncludeBindingKind::Glob {
                host_bindings.retain(|existing| {
                    existing.kind == RustIncludeBindingKind::Glob
                        || existing.local_name != binding.local_name
                });
            }
            host_bindings.push(RustIncludeHostBinding {
                local_name: binding.local_name.clone(),
                module_specifier: binding.module_specifier.clone(),
                imported_name: binding.imported_name.clone(),
                module_package: module_package.clone(),
                scope_start: binding.scope_start,
                kind: binding.kind,
            });
        }
        host_bindings.sort_by(|left, right| {
            left.local_name
                .cmp(&right.local_name)
                .then_with(|| left.module_specifier.cmp(&right.module_specifier))
        });
        host_bindings.dedup();
        Some(RustIncludeRoute {
            root_file: route.root_file,
            crate_package: route.crate_package,
            module_package,
            host_bindings,
        })
    }

    /// The routes `host` owns before any include is applied: one per owning
    /// root, which is where the Cargo and module provenance enter.
    fn seed_routes_of(&self, host: &ProjectFile) -> Vec<RustIncludeRoute> {
        let mut roots: HashSet<ProjectFile> = HashSet::default();
        if self.walks.is_actual_crate_root(host) {
            roots.insert(host.clone());
        }
        roots.extend(self.walks.owner_roots_of(host).iter().cloned());
        roots.extend(self.analyzer.cargo_routes().target_roots_for_file(host));
        let mut roots: Vec<_> = roots.into_iter().collect();
        roots.sort();
        roots
            .into_iter()
            .map(|root| {
                let crate_package = rust_crate_root_package(&root);
                let module_package = if root == *host {
                    crate_package.clone()
                } else {
                    self.walks
                        .physical_root_of(host)
                        .map(|module| module.package())
                        .unwrap_or_else(|| crate::declarations::rust_package_name(host))
                };
                RustIncludeRoute {
                    root_file: root,
                    crate_package,
                    module_package,
                    host_bindings: Vec::new(),
                }
            })
            .collect()
    }

    /// The files that actually `include!` `target`, with the edge that does it.
    ///
    /// The indexed seek answers by last path component, which is a candidate
    /// set; each candidate is confirmed by resolving its own stored literal
    /// against its own directory. Nothing here reads a file the candidate set
    /// did not name.
    fn verified_includers_of(
        &self,
        target: &ProjectFile,
    ) -> Vec<(ProjectFile, RustIncludeEdgeFact)> {
        let Some(file_name) = target.rel_path().file_name().and_then(|name| name.to_str()) else {
            return Vec::new();
        };
        let mut verified = Vec::new();
        for host in self.walks.queries().files_with_include_named(file_name) {
            if self.walks.cancelled() {
                break;
            }
            let Some(facts) = self.walks.queries().facts_of(&host) else {
                continue;
            };
            for edge in &facts.include_edges {
                if edge.file_name != file_name {
                    continue;
                }
                if resolve_include_target(&host, &edge.relative_path).as_ref() != Some(target) {
                    continue;
                }
                verified.push((host.clone(), edge.clone()));
            }
        }
        verified.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.include_start.cmp(&right.1.include_start))
        });
        verified
    }

    /// Resolve one host's `include!` literal against that host's own directory.
    fn module_routes_through(
        &self,
        route: &RustIncludeRoute,
        source: &str,
        scope_start: usize,
        module_specifier: &str,
    ) -> Vec<crate::usage::RustResolvedModuleRoute> {
        let lexical_package = lexical_package_at(&route.module_package, source, scope_start);
        let segments = parse_symbol_path(Language::Rust, module_specifier);
        self.walks
            .resolve_segments(&route.root_file, &lexical_package, &segments)
    }

    /// Resolve an import binder through an include route to canonical value
    /// identities. The export walk keeps glob and re-export resolution in the
    /// same module and Cargo graph as normal Rust usage analysis.
    pub fn include_import_target_identities(
        &self,
        route: &RustIncludeRoute,
        source: &str,
        scope_start: usize,
        binding: &ImportBinding,
        target_identifier: &str,
    ) -> HashSet<RustSymbolIdentity> {
        if binding.kind == ImportKind::Namespace {
            let segments = parse_symbol_path(Language::Rust, &binding.module_specifier);
            let Some((target_name, module_segments)) = segments.split_last() else {
                return HashSet::default();
            };
            let module_specifier = module_segments.join("::");
            return self
                .module_routes_through(route, source, scope_start, &module_specifier)
                .into_iter()
                .filter_map(|resolved| {
                    self.value_identity_in(
                        &resolved.target_file,
                        &resolved.target_module,
                        target_name,
                    )
                })
                .collect();
        }
        let Some(imported_name) = (match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref(),
            ImportKind::Glob => Some(target_identifier),
            _ => None,
        }) else {
            return HashSet::default();
        };
        let mut targets = HashSet::default();
        for resolved in
            self.module_routes_through(route, source, scope_start, &binding.module_specifier)
        {
            let module_files = vec![resolved.target_file.clone()];
            for (target_file, target_name) in
                self.walks
                    .export_targets_from_files(self.analyzer, &module_files, imported_name)
            {
                targets.extend(self.value_identities_named_in(&target_file, &target_name));
            }
            if let Some(identity) = self.value_identity_in(
                &resolved.target_file,
                &resolved.target_module,
                imported_name,
            ) {
                targets.insert(identity);
            }
        }
        targets
    }

    /// Resolve a qualified path whose first segment comes from a host import.
    pub fn include_path_target_identities(
        &self,
        route: &RustIncludeRoute,
        binding: &RustIncludeHostBinding,
        suffix: &[&str],
    ) -> HashSet<RustSymbolIdentity> {
        let module_segments = parse_symbol_path(Language::Rust, &binding.module_specifier);
        if module_segments.is_empty() {
            return HashSet::default();
        }
        let mut member_segments = Vec::new();
        if let Some(imported_name) = &binding.imported_name {
            if imported_name.is_empty() {
                return HashSet::default();
            }
            member_segments.push(imported_name.clone());
        }
        for segment in suffix {
            if segment.is_empty() {
                return HashSet::default();
            }
            member_segments.push((*segment).to_string());
        }
        let Some((target_name, owner_segments)) = member_segments.split_last() else {
            return HashSet::default();
        };
        let mut segments = module_segments;
        segments.extend(owner_segments.iter().cloned());
        let module_specifier = segments.join("::");
        self.module_routes_through(route, "", 0, &module_specifier)
            .into_iter()
            .filter_map(|resolved| {
                self.value_identity_in(&resolved.target_file, &resolved.target_module, target_name)
            })
            .collect()
    }

    /// The value-namespace identity `file` declares as `name` in `module`.
    fn value_identity_in(
        &self,
        file: &ProjectFile,
        module: &ModuleKey,
        name: &str,
    ) -> Option<RustSymbolIdentity> {
        self.walks
            .queries()
            .identities_in_file_named(file, name)
            .into_iter()
            .map(|(identity, _)| identity)
            .find(|identity| {
                identity.namespace == RustSymbolNamespace::Value && identity.module == *module
            })
    }

    /// Every value-namespace identity `file` declares as `name`, in any module.
    fn value_identities_named_in(&self, file: &ProjectFile, name: &str) -> Vec<RustSymbolIdentity> {
        self.walks
            .queries()
            .identities_in_file_named(file, name)
            .into_iter()
            .map(|(identity, _)| identity)
            .filter(|identity| identity.namespace == RustSymbolNamespace::Value)
            .collect()
    }
}

/// Resolve one `include!` literal against the including file's own directory.
///
/// The stored literal is content-derived and the host's directory is not, which
/// is why this is the reader's job and not the writer's.
pub fn resolve_include_target(host: &ProjectFile, relative_path: &str) -> Option<ProjectFile> {
    let relative = Path::new(relative_path);
    if relative_path.is_empty() || relative.is_absolute() {
        return None;
    }
    Some(ProjectFile::new(
        host.root().to_path_buf(),
        host.parent().join(relative),
    ))
}
