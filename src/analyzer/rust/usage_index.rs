//! Analyzer-level re-export + importer index for Rust, so both usage paths
//! resolve references through analyzer state. Built once from the analyzer's own
//! export and import projections plus a compact module-file routing index, and
//! cached on [`RustAnalyzer`] (dropped on `update`/`update_all` like the other
//! caches).
//!
//! Forward export seeds follow re-export chains
//! ([`RustUsageIndex::seeds_for_target`]); the reverse importer index narrows the
//! candidate file set ([`RustUsageIndex::importers_of_seeds`]) and resolves which
//! local names in an importer bind a seed
//! ([`RustUsageIndex::matching_edges_for_importer`]).

use crate::analyzer::usages::{ExportEntry, ExportIndex, ImportBinder, ImportKind};
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use super::RustAnalyzer;
use super::cargo_routes::RustCargoRouteIndex;
use super::declarations::rust_package_name;
use super::graph_support::rust_module_files_from_path;
use super::imports::{resolve_rust_module_path_with_crate, rust_crate_root_package};

/// How a local binding in an importer refers to its target: a named import
/// (`use path::Item;`) or a namespace import (`use crate::module;`). A glob
/// (`use path::*;`) carries no single name, so it is lowered to one `Named` edge
/// per export of the target file in [`build_importer_reverse`] rather than getting
/// its own variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RustImportEdgeKind {
    Named(String),
    Namespace,
}

#[derive(Debug, Clone)]
pub(super) struct RustImportEdge {
    pub(super) importer: ProjectFile,
    pub(super) local_name: String,
    pub(super) target_file: ProjectFile,
    pub(super) kind: RustImportEdgeKind,
}

pub(crate) struct RustBindingSeeds {
    identities: BTreeSet<(ProjectFile, String)>,
    edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>>,
}

impl RustBindingSeeds {
    pub(crate) fn identities(&self) -> &BTreeSet<(ProjectFile, String)> {
        &self.identities
    }
}

/// Re-export and reverse-import indices over the Rust workspace.
#[derive(Debug, Default)]
pub(super) struct RustUsageIndex {
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    importer_reverse: HashMap<ProjectFile, Vec<RustImportEdge>>,
    module_files: RustModuleFiles,
}

#[derive(Debug, Default)]
struct RustModuleFiles {
    files: Vec<ProjectFile>,
    by_package: HashMap<String, Vec<usize>>,
    inline_by_name: HashMap<String, Vec<(usize, bool)>>,
    cargo_routes: Arc<RustCargoRouteIndex>,
}

impl RustModuleFiles {
    /// Compact routing projection over the same file/declaration pass already
    /// required for export and import indices. It retains file IDs and module
    /// names only, never persisted rows, file states, declarations, or source.
    fn new(files: &[ProjectFile], cargo_routes: Arc<RustCargoRouteIndex>) -> Self {
        let mut routing = Self {
            files: files.to_vec(),
            cargo_routes,
            ..Self::default()
        };
        for (file_id, file) in files.iter().enumerate() {
            routing
                .by_package
                .entry(rust_package_name(file))
                .or_default()
                .push(file_id);
        }
        routing
    }

    fn index_inline_modules(
        &mut self,
        analyzer: &RustAnalyzer,
        file_id: usize,
        declarations: &BTreeSet<crate::analyzer::CodeUnit>,
    ) {
        for declaration in declarations {
            if declaration.is_module() {
                self.inline_by_name
                    .entry(declaration.short_name().to_string())
                    .or_default()
                    .push((file_id, analyzer.is_visible_module_path(declaration)));
            }
        }
    }

    fn resolve(&self, importing_file: &ProjectFile, module_specifier: &str) -> Vec<ProjectFile> {
        if let Some(root_file) = self
            .cargo_routes
            .resolve_crate_root_file(importing_file, module_specifier)
        {
            return self
                .files
                .iter()
                .filter(|file| *file == &root_file)
                .cloned()
                .collect();
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
            .by_package
            .get(&resolved_module)
            .into_iter()
            .flatten()
            .map(|file_id| self.files[*file_id].clone())
            .collect::<Vec<_>>();
        if let Some(inline) = self.inline_by_name.get(&resolved_module) {
            files.extend(
                inline
                    .iter()
                    .filter(|(file_id, visible)| {
                        &self.files[*file_id] == importing_file || *visible
                    })
                    .map(|(file_id, _)| self.files[*file_id].clone()),
            );
        }
        files.extend(rust_module_files_from_path(
            importing_file,
            module_specifier,
        ));
        files.sort();
        files.dedup();
        files
    }
}

impl RustUsageIndex {
    pub(super) fn build(analyzer: &RustAnalyzer) -> Self {
        let files: Vec<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = HashMap::default();
        let mut binders_by_file: HashMap<ProjectFile, ImportBinder> = HashMap::default();
        let mut module_files = RustModuleFiles::new(&files, analyzer.cargo_routes());
        for (file_id, file) in files.iter().enumerate() {
            let declarations = analyzer.declarations(file);
            exports_by_file.insert(
                file.clone(),
                analyzer.export_index_of_declarations(file, &declarations),
            );
            binders_by_file.insert(file.clone(), analyzer.import_binder_of(file));
            module_files.index_inline_modules(analyzer, file_id, &declarations);
        }

        let mut reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>> =
            HashMap::default();
        let mut star_reexports: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        for (file, exports) in &exports_by_file {
            for (exported_name, entry) in &exports.exports_by_name {
                match entry {
                    ExportEntry::Local { local_name } => {
                        let Some(binder) = binders_by_file.get(file) else {
                            continue;
                        };
                        let Some(binding) = binder.bindings.get(local_name) else {
                            continue;
                        };
                        let Some(imported_name) = binding.imported_name.as_ref() else {
                            continue;
                        };
                        for resolved_file in module_files.resolve(file, &binding.module_specifier) {
                            reexport_edges
                                .entry((resolved_file, imported_name.clone()))
                                .or_default()
                                .push((file.clone(), exported_name.clone()));
                        }
                    }
                    ExportEntry::Default { .. } => {}
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => {
                        for resolved_file in module_files.resolve(file, module_specifier) {
                            reexport_edges
                                .entry((resolved_file, imported_name.clone()))
                                .or_default()
                                .push((file.clone(), exported_name.clone()));
                        }
                    }
                }
            }
            for star in &exports.reexport_stars {
                for resolved_file in module_files.resolve(file, &star.module_specifier) {
                    star_reexports
                        .entry(resolved_file)
                        .or_default()
                        .push(file.clone());
                }
            }
        }

        let importer_reverse =
            build_importer_reverse(&module_files, &files, &binders_by_file, &exports_by_file);

        Self {
            exports_by_file,
            reexport_edges,
            star_reexports,
            importer_reverse,
            module_files,
        }
    }

    /// Export seeds for `target_short` defined in `target_file`, following
    /// re-export chains (`pub use`) across files.
    pub(super) fn seeds_for_target(
        &self,
        target_file: &ProjectFile,
        target_short: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        let mut seeds: BTreeSet<(ProjectFile, String)> = BTreeSet::new();

        if let Some(exports) = self.exports_by_file.get(target_file) {
            for (exported_name, entry) in &exports.exports_by_name {
                let local = match entry {
                    ExportEntry::Local { local_name } => Some(local_name.as_str()),
                    ExportEntry::Default { local_name } => local_name.as_deref(),
                    ExportEntry::ReexportedNamed { .. } => None,
                };
                if let Some(local_name) = local
                    && local_name == target_short
                {
                    seeds.insert((target_file.clone(), exported_name.clone()));
                }
            }
        }

        // Bootstrap the re-export walk from the definition point as well. An item in
        // a private `mod` exposes nothing through its own file's export index, yet
        // still reaches the crate's public API via a `pub use` re-export; since
        // `reexport_edges` is keyed by the defining file, walking from the definition
        // discovers those sites. The bootstrap node is only retained as a seed when
        // it actually reaches a re-export — an unexported, never-re-exported item
        // resolves to no seeds, so it is not treated as graph-visible.
        let bootstrap = (target_file.clone(), target_short.to_string());
        let bootstrap_is_own_export = seeds.contains(&bootstrap);

        let mut reexport_seeds: BTreeSet<(ProjectFile, String)> = BTreeSet::new();
        let mut visited: BTreeSet<(ProjectFile, String)> = seeds.clone();
        visited.insert(bootstrap.clone());
        let mut frontier: VecDeque<(ProjectFile, String)> = visited.iter().cloned().collect();
        while let Some(seed) = frontier.pop_front() {
            if let Some(reexports) = self.reexport_edges.get(&seed) {
                for next in reexports {
                    reexport_seeds.insert(next.clone());
                    if visited.insert(next.clone()) {
                        frontier.push_back(next.clone());
                    }
                }
            }
            if let Some(star_files) = self.star_reexports.get(&seed.0) {
                for star_file in star_files {
                    let next = (star_file.clone(), seed.1.clone());
                    reexport_seeds.insert(next.clone());
                    if visited.insert(next.clone()) {
                        frontier.push_back(next);
                    }
                }
            }
        }

        let reached_reexport = !reexport_seeds.is_empty();
        seeds.extend(reexport_seeds);
        if !bootstrap_is_own_export && reached_reexport {
            seeds.insert(bootstrap);
        }

        seeds
    }

    /// Files that import one of the `seeds` (plus the seed files themselves) —
    /// the candidate set the forward scan narrows to. Named imports are followed
    /// transitively because a private parent-module import can itself be imported
    /// by a child module without becoming a public re-export.
    pub(super) fn importers_of_seeds(&self, seeds: &RustBindingSeeds) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = seeds.edges_by_importer.keys().cloned().collect();
        out.extend(seeds.identities.iter().map(|(file, _)| file.clone()));
        out
    }

    fn matching_edges_for_importer<'a>(
        &self,
        importer: &ProjectFile,
        seeds: &'a RustBindingSeeds,
    ) -> impl Iterator<Item = &'a RustImportEdge> {
        seeds.edges_by_importer.get(importer).into_iter().flatten()
    }

    fn binding_seeds(&self, seeds: &BTreeSet<(ProjectFile, String)>) -> RustBindingSeeds {
        let mut identities = seeds.clone();
        let mut edges_by_importer: HashMap<ProjectFile, Vec<RustImportEdge>> = HashMap::default();
        let mut pending: VecDeque<_> = seeds.iter().cloned().collect();
        while let Some((target_file, target_name)) = pending.pop_front() {
            let Some(edges) = self.importer_reverse.get(&target_file) else {
                continue;
            };
            let forward_exported = self.seed_is_forward_exported(&target_file, &target_name);
            for edge in edges {
                if !edge_matches_single_seed(edge, &target_file, &target_name) {
                    continue;
                }
                if matches!(edge.kind, RustImportEdgeKind::Named(_))
                    && !forward_exported
                    && !rust_module_is_descendant(&target_file, &edge.importer)
                {
                    continue;
                }
                edges_by_importer
                    .entry(edge.importer.clone())
                    .or_default()
                    .push(edge.clone());
                if matches!(edge.kind, RustImportEdgeKind::Named(_)) {
                    let alias = (edge.importer.clone(), edge.local_name.clone());
                    if identities.insert(alias.clone()) {
                        pending.push_back(alias);
                    }
                }
            }
        }
        RustBindingSeeds {
            identities,
            edges_by_importer,
        }
    }

    fn seed_is_forward_exported(&self, file: &ProjectFile, name: &str) -> bool {
        let mut pending = vec![(file.clone(), name.to_string())];
        let mut visited = HashSet::default();
        while let Some((file, name)) = pending.pop() {
            if !visited.insert((file.clone(), name.clone())) {
                continue;
            }
            let Some(index) = self.exports_by_file.get(&file) else {
                continue;
            };
            for star in &index.reexport_stars {
                pending.extend(
                    self.module_files
                        .resolve(&file, &star.module_specifier)
                        .into_iter()
                        .map(|target| (target, name.clone())),
                );
            }
            match index.exports_by_name.get(&name) {
                Some(ExportEntry::Local { .. }) => return true,
                Some(ExportEntry::ReexportedNamed { .. }) => return true,
                Some(ExportEntry::Default {
                    local_name: Some(_),
                }) => return true,
                Some(ExportEntry::Default { local_name: None }) => {}
                None => {}
            }
        }
        false
    }

    pub(super) fn export_targets_from_files(
        &self,
        analyzer: &RustAnalyzer,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        enum Work {
            Visit(ProjectFile, String),
            DeclarationFallback {
                files: Vec<ProjectFile>,
                name: String,
                target_count: usize,
            },
        }

        let mut targets = BTreeSet::new();
        let mut visited = HashSet::default();
        let mut pending = module_files
            .iter()
            .rev()
            .map(|file| Work::Visit(file.clone(), export_name.to_string()))
            .collect::<Vec<_>>();
        while let Some(work) = pending.pop() {
            let (module_file, export_name) = match work {
                Work::DeclarationFallback {
                    files,
                    name,
                    target_count,
                } => {
                    if targets.len() == target_count {
                        targets.extend(rust_declaration_targets_in_files(analyzer, &files, &name));
                    }
                    continue;
                }
                Work::Visit(file, name) => (file, name),
            };
            if !visited.insert((module_file.clone(), export_name.clone())) {
                continue;
            }
            let Some(index) = self.exports_by_file.get(&module_file) else {
                continue;
            };

            for star in index.reexport_stars.iter().rev() {
                let files = self
                    .module_files
                    .resolve(&module_file, &star.module_specifier);
                pending.extend(
                    files
                        .into_iter()
                        .rev()
                        .map(|file| Work::Visit(file, export_name.clone())),
                );
            }

            if let Some(entry) = index.exports_by_name.get(&export_name) {
                match entry {
                    ExportEntry::Local { local_name } => {
                        targets.insert((module_file, local_name.clone()));
                    }
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => {
                        let files = self.module_files.resolve(&module_file, module_specifier);
                        pending.push(Work::DeclarationFallback {
                            files: files.clone(),
                            name: imported_name.clone(),
                            target_count: targets.len(),
                        });
                        pending.extend(
                            files
                                .into_iter()
                                .rev()
                                .map(|file| Work::Visit(file, imported_name.clone())),
                        );
                    }
                    ExportEntry::Default { .. } => {}
                }
            }
        }
        targets
    }
}

fn rust_declaration_targets_in_files(
    analyzer: &RustAnalyzer,
    files: &[ProjectFile],
    name: &str,
) -> Vec<(ProjectFile, String)> {
    let mut targets: Vec<_> = files
        .iter()
        .flat_map(|file| {
            analyzer
                .declarations(file)
                .into_iter()
                .filter(move |unit| unit.identifier() == name)
                .map(|unit| (file.clone(), unit.identifier().to_string()))
        })
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

fn rust_module_is_descendant(module_file: &ProjectFile, candidate: &ProjectFile) -> bool {
    if module_file == candidate {
        return true;
    }
    let module = rust_package_name(module_file);
    let candidate = rust_package_name(candidate);
    if module.is_empty() {
        return !candidate.is_empty();
    }
    candidate
        .strip_prefix(&module)
        .is_some_and(|suffix| suffix.starts_with('.'))
}

impl RustAnalyzer {
    /// The cached re-export/importer index, built once per analyzer generation.
    fn usage_index(&self) -> &RustUsageIndex {
        self.usage_index.get_or_init(|| RustUsageIndex::build(self))
    }

    /// Export seeds for the target, following `pub use` re-export chains.
    pub(crate) fn usage_seeds(
        &self,
        target_file: &ProjectFile,
        target_short: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        self.usage_index()
            .seeds_for_target(target_file, target_short)
    }

    /// Candidate files: those importing a seed, plus the seed files themselves.
    pub(crate) fn usage_importers(&self, seeds: &RustBindingSeeds) -> HashSet<ProjectFile> {
        self.usage_index().importers_of_seeds(seeds)
    }

    /// Canonical local binding identities for a target, including named private
    /// imports that can be imported again by descendant modules.
    pub(crate) fn usage_binding_seeds(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> RustBindingSeeds {
        self.usage_index().binding_seeds(seeds)
    }

    /// `(direct_names, qualified_names)` — local names that bind a seed directly
    /// (`use path::Item;`) and exact paths that reach a seed through a namespace
    /// binding (`use crate_name;` followed by `crate_name::Item`).
    pub(crate) fn usage_binding_names(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
    ) -> (HashSet<String>, HashSet<String>) {
        let mut direct = HashSet::default();
        let mut qualified = HashSet::default();
        let index = self.usage_index();
        for edge in index.matching_edges_for_importer(file, seeds) {
            match &edge.kind {
                RustImportEdgeKind::Namespace => {
                    qualified.extend(
                        seeds
                            .identities
                            .iter()
                            .filter(|(target_file, _)| target_file == &edge.target_file)
                            .map(|(_, target_name)| format!("{}::{target_name}", edge.local_name)),
                    );
                }
                RustImportEdgeKind::Named(_) => {
                    direct.insert(edge.local_name.clone());
                }
            }
        }
        (direct, qualified)
    }

    /// All local names in `file` binding a seed (direct or namespace) — the
    /// owner-binding names the member scan keys on.
    pub(crate) fn usage_binding_local_names(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
    ) -> HashSet<String> {
        self.usage_index()
            .matching_edges_for_importer(file, seeds)
            .map(|edge| edge.local_name.clone())
            .collect()
    }

    pub(crate) fn exported_targets_from_files(
        &self,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        self.usage_index()
            .export_targets_from_files(self, module_files, export_name)
    }
}

fn edge_matches_single_seed(
    edge: &RustImportEdge,
    target_file: &ProjectFile,
    target_name: &str,
) -> bool {
    if &edge.target_file != target_file {
        return false;
    }
    match &edge.kind {
        RustImportEdgeKind::Named(name) => name == target_name,
        RustImportEdgeKind::Namespace => true,
    }
}

fn build_importer_reverse(
    module_files: &RustModuleFiles,
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
) -> HashMap<ProjectFile, Vec<RustImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<RustImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            for target_file in module_files.resolve(file, &binding.module_specifier) {
                // A glob `use path::*;` binds every export of the target file as a
                // named edge (local name == export name), mirroring the graph it
                // replaces.
                if matches!(binding.kind, ImportKind::Glob) {
                    let Some(exports) = exports_by_file.get(&target_file) else {
                        continue;
                    };
                    for export_name in exports.exports_by_name.keys() {
                        reverse
                            .entry(target_file.clone())
                            .or_default()
                            .push(RustImportEdge {
                                importer: file.clone(),
                                local_name: export_name.clone(),
                                target_file: target_file.clone(),
                                kind: RustImportEdgeKind::Named(export_name.clone()),
                            });
                    }
                    continue;
                }
                let kind = match (binding.kind, binding.imported_name.as_deref()) {
                    (ImportKind::Namespace, _) => RustImportEdgeKind::Namespace,
                    (ImportKind::Named, Some(name)) => RustImportEdgeKind::Named(name.to_string()),
                    (ImportKind::Named, None) => RustImportEdgeKind::Named(local_name.clone()),
                    // Rust binders never emit Default/CommonJsRequire.
                    (ImportKind::Default, _)
                    | (ImportKind::CommonJsRequire, _)
                    | (ImportKind::Glob, _) => continue,
                };
                reverse
                    .entry(target_file.clone())
                    .or_default()
                    .push(RustImportEdge {
                        importer: file.clone(),
                        local_name: local_name.clone(),
                        target_file,
                        kind,
                    });
            }
        }
    }
    reverse
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::ExportEntry;
    use crate::analyzer::{Language, TestProject};

    fn project_file(root: &std::path::Path, index: usize) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), format!("src/m{index}.rs"))
    }

    fn analyzer_for(root: &std::path::Path) -> RustAnalyzer {
        RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
    }

    fn reexport_chain(
        root: &std::path::Path,
        len: usize,
        cyclic: bool,
    ) -> (RustUsageIndex, Vec<ProjectFile>) {
        let files = (0..len)
            .map(|index| project_file(root, index))
            .collect::<Vec<_>>();
        let mut exports_by_file = HashMap::default();
        let mut by_package = HashMap::default();
        for (index, file) in files.iter().enumerate() {
            by_package.insert(format!("m{index}"), vec![index]);
            let entry = if index + 1 < len {
                ExportEntry::ReexportedNamed {
                    module_specifier: format!("crate::m{}", index + 1),
                    imported_name: "Value".to_string(),
                }
            } else if cyclic {
                ExportEntry::ReexportedNamed {
                    module_specifier: "crate::m0".to_string(),
                    imported_name: "Value".to_string(),
                }
            } else {
                ExportEntry::Local {
                    local_name: "Value".to_string(),
                }
            };
            exports_by_file.insert(
                file.clone(),
                ExportIndex {
                    exports_by_name: [("Value".to_string(), entry)].into_iter().collect(),
                    reexport_stars: Vec::new(),
                },
            );
        }
        (
            RustUsageIndex {
                exports_by_file,
                module_files: RustModuleFiles {
                    files: files.clone(),
                    by_package,
                    inline_by_name: HashMap::default(),
                    cargo_routes: Arc::new(RustCargoRouteIndex::default()),
                },
                ..RustUsageIndex::default()
            },
            files,
        )
    }

    #[test]
    fn export_target_walk_handles_deep_reexport_chains_without_recursion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let (index, files) = reexport_chain(&root, 5_000, false);

        assert_eq!(
            index.export_targets_from_files(&analyzer, &files[..1], "Value"),
            BTreeSet::from([(files[4_999].clone(), "Value".to_string())])
        );
    }

    #[test]
    fn export_target_walk_terminates_on_deep_reexport_cycle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let (index, files) = reexport_chain(&root, 5_000, true);

        assert!(
            index
                .export_targets_from_files(&analyzer, &files[..1], "Value")
                .is_empty()
        );
    }

    #[test]
    fn module_file_snapshot_preserves_package_inline_and_path_candidates() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let importer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let module_file = ProjectFile::new(root.clone(), "src/service.rs");
        let inline_file = ProjectFile::new(root.clone(), "src/lib.rs");
        let snapshot = RustModuleFiles {
            files: vec![module_file.clone(), inline_file.clone()],
            by_package: [("service".to_string(), vec![0])].into_iter().collect(),
            inline_by_name: [("service".to_string(), vec![(1, true)])]
                .into_iter()
                .collect(),
            cargo_routes: Arc::new(RustCargoRouteIndex::default()),
        };

        assert_eq!(snapshot.files.len(), 2);
        assert_eq!(snapshot.by_package.values().map(Vec::len).sum::<usize>(), 1);
        assert_eq!(
            snapshot
                .inline_by_name
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            1
        );

        let resolved = snapshot.resolve(&importer, "crate::service");
        assert!(resolved.contains(&module_file));
        assert!(resolved.contains(&inline_file));
    }
}
