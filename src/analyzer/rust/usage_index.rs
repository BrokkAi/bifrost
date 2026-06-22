//! Analyzer-level re-export + importer index for Rust, so both usage paths
//! resolve references through analyzer state. Built once from the analyzer's own
//! `export_index_of` / `import_binder_of` / `resolve_module_files` and cached on
//! [`RustAnalyzer`] (dropped on `update`/`update_all` like the other caches).
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

use super::RustAnalyzer;

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

/// Re-export and reverse-import indices over the Rust workspace.
#[derive(Debug, Default)]
pub(super) struct RustUsageIndex {
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    importer_reverse: HashMap<ProjectFile, Vec<RustImportEdge>>,
}

impl RustUsageIndex {
    pub(super) fn build(analyzer: &RustAnalyzer) -> Self {
        let files: Vec<ProjectFile> = analyzer.get_analyzed_files().into_iter().collect();
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = HashMap::default();
        let mut binders_by_file: HashMap<ProjectFile, ImportBinder> = HashMap::default();
        for file in &files {
            exports_by_file.insert(file.clone(), analyzer.export_index_of(file));
            binders_by_file.insert(file.clone(), analyzer.import_binder_of(file));
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
                        for resolved_file in
                            analyzer.resolve_module_files(file, &binding.module_specifier)
                        {
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
                        for resolved_file in analyzer.resolve_module_files(file, module_specifier) {
                            reexport_edges
                                .entry((resolved_file, imported_name.clone()))
                                .or_default()
                                .push((file.clone(), exported_name.clone()));
                        }
                    }
                }
            }
            for star in &exports.reexport_stars {
                for resolved_file in analyzer.resolve_module_files(file, &star.module_specifier) {
                    star_reexports
                        .entry(resolved_file)
                        .or_default()
                        .push(file.clone());
                }
            }
        }

        let importer_reverse =
            build_importer_reverse(analyzer, &files, &binders_by_file, &exports_by_file);

        Self {
            exports_by_file,
            reexport_edges,
            star_reexports,
            importer_reverse,
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

        let mut frontier: VecDeque<(ProjectFile, String)> = seeds.iter().cloned().collect();
        while let Some(seed) = frontier.pop_front() {
            if let Some(reexports) = self.reexport_edges.get(&seed) {
                for next in reexports {
                    if seeds.insert(next.clone()) {
                        frontier.push_back(next.clone());
                    }
                }
            }
            if let Some(star_files) = self.star_reexports.get(&seed.0) {
                for star_file in star_files {
                    let next = (star_file.clone(), seed.1.clone());
                    if seeds.insert(next.clone()) {
                        frontier.push_back(next);
                    }
                }
            }
        }

        seeds
    }

    /// Files that import one of the `seeds` (plus the seed files themselves) —
    /// the candidate set the forward scan narrows to.
    pub(super) fn importers_of_seeds(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = HashSet::default();
        for (target_file, _) in seeds {
            if let Some(edges) = self.importer_reverse.get(target_file) {
                for edge in edges {
                    out.insert(edge.importer.clone());
                }
            }
            out.insert(target_file.clone());
        }
        out
    }

    /// The import edges in `importer` that bind one of the `seeds`.
    pub(super) fn matching_edges_for_importer(
        &self,
        importer: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> Vec<RustImportEdge> {
        let mut matches = Vec::new();
        for (target_file, _) in seeds {
            let Some(edges) = self.importer_reverse.get(target_file) else {
                continue;
            };
            matches.extend(
                edges
                    .iter()
                    .filter(|edge| &edge.importer == importer && edge_matches_seed(edge, seeds))
                    .cloned(),
            );
        }
        matches
    }

    pub(super) fn export_targets_from_files(
        &self,
        analyzer: &RustAnalyzer,
        module_files: &[ProjectFile],
        export_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        let mut targets = BTreeSet::new();
        let mut visited = HashSet::default();
        for module_file in module_files {
            self.export_targets_in_file(
                analyzer,
                module_file,
                export_name,
                &mut visited,
                &mut targets,
            );
        }
        targets
    }

    fn export_targets_in_file(
        &self,
        analyzer: &RustAnalyzer,
        module_file: &ProjectFile,
        export_name: &str,
        visited: &mut HashSet<(ProjectFile, String)>,
        targets: &mut BTreeSet<(ProjectFile, String)>,
    ) {
        if !visited.insert((module_file.clone(), export_name.to_string())) {
            return;
        }
        let Some(index) = self.exports_by_file.get(module_file) else {
            return;
        };
        if let Some(entry) = index.exports_by_name.get(export_name) {
            match entry {
                ExportEntry::Local { local_name } => {
                    targets.insert((module_file.clone(), local_name.clone()));
                }
                ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                } => {
                    for file in analyzer.resolve_module_files(module_file, module_specifier) {
                        self.export_targets_in_file(
                            analyzer,
                            &file,
                            imported_name,
                            visited,
                            targets,
                        );
                    }
                }
                ExportEntry::Default { .. } => {}
            }
        }
        for star in &index.reexport_stars {
            for file in analyzer.resolve_module_files(module_file, &star.module_specifier) {
                self.export_targets_in_file(analyzer, &file, export_name, visited, targets);
            }
        }
    }
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
    pub(crate) fn usage_importers(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<ProjectFile> {
        self.usage_index().importers_of_seeds(seeds)
    }

    /// `(direct_names, namespace_names)` — the local names in `file` that bind a
    /// seed directly (`use path::Item;`) vs. as a namespace (`use crate::module;`).
    pub(crate) fn usage_binding_names(
        &self,
        file: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> (HashSet<String>, HashSet<String>) {
        let mut direct = HashSet::default();
        let mut namespace = HashSet::default();
        for edge in self.usage_index().matching_edges_for_importer(file, seeds) {
            match edge.kind {
                RustImportEdgeKind::Namespace => {
                    namespace.insert(edge.local_name);
                }
                RustImportEdgeKind::Named(_) => {
                    direct.insert(edge.local_name);
                }
            }
        }
        (direct, namespace)
    }

    /// All local names in `file` binding a seed (direct or namespace) — the
    /// owner-binding names the member scan keys on.
    pub(crate) fn usage_binding_local_names(
        &self,
        file: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<String> {
        self.usage_index()
            .matching_edges_for_importer(file, seeds)
            .into_iter()
            .map(|edge| edge.local_name)
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

fn edge_matches_seed(edge: &RustImportEdge, seeds: &BTreeSet<(ProjectFile, String)>) -> bool {
    match &edge.kind {
        RustImportEdgeKind::Named(name) => {
            seeds.contains(&(edge.target_file.clone(), name.clone()))
        }
        RustImportEdgeKind::Namespace => seeds.iter().any(|(file, _)| file == &edge.target_file),
    }
}

fn build_importer_reverse(
    analyzer: &RustAnalyzer,
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
            for target_file in analyzer.resolve_module_files(file, &binding.module_specifier) {
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
