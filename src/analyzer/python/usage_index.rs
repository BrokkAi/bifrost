//! Analyzer-level re-export + importer index for Python, so both usage paths
//! resolve references through analyzer state. Built once from the analyzer's own
//! module index + `export_index_of` / `import_binder_of` and cached on
//! [`PythonAnalyzer`] (dropped on `update`/`update_all` like the other caches).
//!
//! Forward export seeds follow re-export chains
//! ([`PythonUsageIndex::seeds_for_target`]), and the reverse importer index
//! resolves which local names in an importer bind a seed
//! ([`PythonUsageIndex::matching_edges_for_importer`]). Candidate-file narrowing
//! stays in the forward path's scoped import closure (`PythonProjectGraph`), not
//! here. Module resolution reuses the analyzer's existing [`python_module_name`]
//! + [`resolve_python_relative_module`].

use crate::analyzer::usages::{
    ExportEntry, ExportIndex, ImportBinder, ImportEdge, ImportEdgeKind, ImportKind,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;
use std::collections::{BTreeSet, VecDeque};

use super::PythonAnalyzer;
use super::declarations::python_module_name;
use super::imports::resolve_python_relative_module;

/// Re-export and reverse-import indices over the Python workspace.
#[derive(Debug, Default)]
pub(crate) struct PythonUsageIndex {
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
}

/// Resolve a module specifier to the files defining it: a leading-dot specifier
/// is made absolute against the importing file's package, then looked up in the
/// module index.
fn resolve_module(
    module_index: &HashMap<String, Vec<ProjectFile>>,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Vec<ProjectFile> {
    let resolved_module = if module_specifier.starts_with('.') {
        resolve_python_relative_module(importing_file, module_specifier)
    } else {
        Some(module_specifier.to_string())
    };
    let Some(resolved_module) = resolved_module else {
        return Vec::new();
    };
    module_index
        .get(&resolved_module)
        .cloned()
        .unwrap_or_default()
}

impl PythonUsageIndex {
    fn build(analyzer: &PythonAnalyzer) -> Self {
        let _scope = crate::profiling::scope("PythonUsageIndex::build");
        let mut files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Python)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        files.sort();
        files.dedup();

        let mut module_index: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for file in &files {
            module_index
                .entry(python_module_name(file))
                .or_default()
                .push(file.clone());
        }
        for resolved in module_index.values_mut() {
            resolved.sort();
            resolved.dedup();
        }

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
                            resolve_module(&module_index, file, &binding.module_specifier)
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
                        for resolved_file in resolve_module(&module_index, file, module_specifier) {
                            reexport_edges
                                .entry((resolved_file, imported_name.clone()))
                                .or_default()
                                .push((file.clone(), exported_name.clone()));
                        }
                    }
                }
            }
            for star in &exports.reexport_stars {
                for resolved_file in resolve_module(&module_index, file, &star.module_specifier) {
                    star_reexports
                        .entry(resolved_file)
                        .or_default()
                        .push(file.clone());
                }
            }
        }

        let importer_reverse =
            build_importer_reverse(&module_index, &files, &binders_by_file, &exports_by_file);

        Self {
            exports_by_file,
            reexport_edges,
            star_reexports,
            importer_reverse,
        }
    }

    fn seeds_for_target(
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

    fn matching_edges_for_importer(
        &self,
        importer: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> Vec<ImportEdge> {
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
}

fn edge_matches_seed(edge: &ImportEdge, seeds: &BTreeSet<(ProjectFile, String)>) -> bool {
    match &edge.kind {
        ImportEdgeKind::Named(name) => seeds.contains(&(edge.target_file.clone(), name.clone())),
        ImportEdgeKind::Default => {
            seeds.contains(&(edge.target_file.clone(), "default".to_string()))
        }
        ImportEdgeKind::Namespace => seeds.iter().any(|(file, _)| file == &edge.target_file),
        ImportEdgeKind::CommonJsRequire(export_name) => {
            seeds.contains(&(edge.target_file.clone(), export_name.clone()))
        }
    }
}

fn build_importer_reverse(
    module_index: &HashMap<String, Vec<ProjectFile>>,
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
) -> HashMap<ProjectFile, Vec<ImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<ImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            for target_file in resolve_module(module_index, file, &binding.module_specifier) {
                // A glob `from m import *` binds every export of the target file
                // as a named edge, mirroring the graph it replaces.
                if matches!(binding.kind, ImportKind::Glob) {
                    let Some(exports) = exports_by_file.get(&target_file) else {
                        continue;
                    };
                    for export_name in exports.exports_by_name.keys() {
                        reverse
                            .entry(target_file.clone())
                            .or_default()
                            .push(ImportEdge {
                                importer: file.clone(),
                                local_name: export_name.clone(),
                                target_file: target_file.clone(),
                                kind: ImportEdgeKind::Named(export_name.clone()),
                            });
                    }
                    continue;
                }
                let kind = match (binding.kind, binding.imported_name.as_deref()) {
                    (ImportKind::Default, _) => ImportEdgeKind::Default,
                    (ImportKind::Namespace, _) => ImportEdgeKind::Namespace,
                    (ImportKind::Named, Some(name)) => ImportEdgeKind::Named(name.to_string()),
                    (ImportKind::Named, None) => ImportEdgeKind::Named(local_name.clone()),
                    // Python binders never emit CommonJsRequire; glob handled above.
                    (ImportKind::CommonJsRequire, _) | (ImportKind::Glob, _) => continue,
                };
                reverse
                    .entry(target_file.clone())
                    .or_default()
                    .push(ImportEdge {
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

impl PythonAnalyzer {
    /// The cached re-export/importer index, built once per analyzer generation.
    fn usage_index(&self) -> &PythonUsageIndex {
        self.usage_index
            .get_or_init(|| PythonUsageIndex::build(self))
    }

    /// Export seeds for the target, following re-export chains.
    pub(crate) fn usage_seeds(
        &self,
        target_file: &ProjectFile,
        target_short: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        self.usage_index()
            .seeds_for_target(target_file, target_short)
    }

    /// The import edges in `importer` that bind one of the `seeds`.
    pub(crate) fn usage_matching_edges(
        &self,
        importer: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> Vec<ImportEdge> {
        self.usage_index()
            .matching_edges_for_importer(importer, seeds)
    }
}
