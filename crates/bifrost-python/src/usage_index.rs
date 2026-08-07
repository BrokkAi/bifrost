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

use brokk_bifrost_core::analyzer::usages::local_inference::LocalBindingsSnapshot;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind,
};
use brokk_bifrost_core::analyzer::usages::{ImportEdge, ImportEdgeKind};
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use crate::declarations::python_module_name;
use crate::graph_support::{
    PythonSource, PythonUsageSource, export_index_from_file_facts, import_binder_from_imports,
};
use crate::imports::{module_replacement_of, resolve_python_relative_module};

/// Re-export and reverse-import indices over the Python workspace.
#[derive(Debug, Default)]
pub struct PythonUsageIndex {
    module_index: HashMap<String, Vec<ProjectFile>>,
    exports_by_file: HashMap<ProjectFile, Arc<ExportIndex>>,
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
    module_binding_timelines: Mutex<HashMap<ProjectFile, Arc<ModuleBindingTimeline>>>,
    scope_facts_by_file: Mutex<HashMap<ProjectFile, Arc<PythonScopeFacts>>>,
}

pub type ModuleBindingTimeline = HashMap<String, Vec<ModuleBindingEvent>>;
pub type PythonScopeFacts = HashMap<CodeUnit, LocalBindingsSnapshot<String>>;

#[derive(Clone, Debug)]
pub struct ModuleBindingEvent {
    pub visible_from: usize,
    pub conditional: bool,
    pub kind: ModuleBindingEventKind,
}

#[derive(Clone, Debug)]
pub enum ModuleBindingEventKind {
    ImportModule(String),
    FromImport {
        module: String,
        imported_name: String,
    },
    Other,
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

fn is_sys_namespace_binding(binding: &ImportBinding) -> bool {
    binding.kind == ImportKind::Namespace
        && binding
            .namespace_imported_module
            .as_deref()
            .unwrap_or(&binding.module_specifier)
            == "sys"
}

impl PythonUsageIndex {
    /// Takes [`PythonSource`], not [`PythonUsageSource`]: the cell this
    /// build fills is only reachable through the latter, so the narrower
    /// parameter is what stops the build from re-entering it.
    pub fn build(python: &dyn PythonSource) -> Self {
        let _scope = brokk_bifrost_core::profiling::scope("PythonUsageIndex::build");
        let mut files: Vec<ProjectFile> = python
            .project()
            .analyzable_files(Language::Python)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        files.sort();
        files.dedup();

        let mut module_index: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        let mut exports_by_file: HashMap<ProjectFile, Arc<ExportIndex>> = HashMap::default();
        let mut binders_by_file: HashMap<ProjectFile, Arc<ImportBinder>> = HashMap::default();
        let mut replacement_modules: HashMap<ProjectFile, String> = HashMap::default();
        python.visit_file_facts(&files, &mut |file, facts| {
            let module_name = facts
                .and_then(|facts| {
                    facts
                        .top_level_declarations()
                        .iter()
                        .find(|unit| unit.is_module())
                })
                .map(|unit| unit.fq_name().to_string())
                .unwrap_or_else(|| python_module_name(file));
            module_index
                .entry(module_name.clone())
                .or_default()
                .push(file.clone());
            if let Some(facts) = facts {
                let binder = Arc::new(import_binder_from_imports(python, file, facts.imports()));
                if binder.bindings.values().any(is_sys_namespace_binding)
                    && let Some(replacement) = module_replacement_of(python, file, facts.source())
                {
                    replacement_modules.insert(file.clone(), replacement.target_module);
                }
                exports_by_file.insert(
                    file.clone(),
                    Arc::new(export_index_from_file_facts(
                        python,
                        file,
                        facts,
                        &module_name,
                        &binder,
                    )),
                );
                binders_by_file.insert(file.clone(), binder);
            } else {
                exports_by_file.insert(file.clone(), python.export_index_of(file));
                let binder = python.import_binder_of(file);
                if binder.bindings.values().any(is_sys_namespace_binding)
                    && let Ok(source) = python.project().read_source(file)
                    && let Some(replacement) = module_replacement_of(python, file, &source)
                {
                    replacement_modules.insert(file.clone(), replacement.target_module);
                }
                binders_by_file.insert(file.clone(), binder);
            }
        });
        for resolved in module_index.values_mut() {
            resolved.sort();
            resolved.dedup();
        }

        let mut raw_replacements: HashMap<ProjectFile, ProjectFile> = HashMap::default();
        for (file, target_module) in replacement_modules {
            let mut targets = resolve_module(&module_index, &file, &target_module);
            if targets.len() != 1 {
                continue;
            }
            let target = targets.pop().expect("one module replacement target");
            if target != file {
                raw_replacements.insert(file, target);
            }
        }

        let mut canonical_replacements: HashMap<ProjectFile, ProjectFile> = HashMap::default();
        for file in raw_replacements.keys() {
            if let Some(target) = canonical_module_replacement(file, &raw_replacements) {
                canonical_replacements.insert(file.clone(), target);
            }
        }
        for resolved in module_index.values_mut() {
            let mut seen = HashSet::default();
            resolved.retain_mut(|file| {
                if let Some(canonical) = canonical_replacements.get(file) {
                    *file = canonical.clone();
                }
                seen.insert(file.clone())
            });
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
                    // A re-exported module is a terminal binding: it carries
                    // no member name, so it opens no name-to-name edge.
                    ExportEntry::Default { .. } | ExportEntry::ReexportedModule { .. } => {}
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
            module_index,
            exports_by_file,
            reexport_edges,
            star_reexports,
            importer_reverse,
            module_binding_timelines: Mutex::new(HashMap::default()),
            scope_facts_by_file: Mutex::new(HashMap::default()),
        }
    }

    pub fn seeds_for_target(
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
                    ExportEntry::ReexportedNamed { .. } | ExportEntry::ReexportedModule { .. } => {
                        None
                    }
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
            if !seed.1.starts_with('_')
                && let Some(star_files) = self.star_reexports.get(&seed.0)
            {
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

    pub fn matching_edges_for_importer(
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

    pub fn importer_files_for_seeds(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<ProjectFile> {
        let mut importers = HashSet::default();
        for (target_file, _) in seeds {
            let Some(edges) = self.importer_reverse.get(target_file) else {
                continue;
            };
            importers.extend(
                edges
                    .iter()
                    .filter(|edge| edge_matches_seed(edge, seeds))
                    .map(|edge| edge.importer.clone()),
            );
        }
        importers
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        resolve_module(&self.module_index, importing_file, module_specifier)
    }

    pub fn module_binding_timeline(
        &self,
        file: &ProjectFile,
        build: impl FnOnce() -> ModuleBindingTimeline,
    ) -> Arc<ModuleBindingTimeline> {
        if let Some(cached) = self
            .module_binding_timelines
            .lock()
            .expect("Python module-binding timeline cache mutex poisoned")
            .get(file)
            .cloned()
        {
            return cached;
        }

        let timeline = Arc::new(build());
        self.module_binding_timelines
            .lock()
            .expect("Python module-binding timeline cache mutex poisoned")
            .entry(file.clone())
            .or_insert_with(|| timeline.clone())
            .clone()
    }

    pub fn scope_facts(
        &self,
        file: &ProjectFile,
        build: impl FnOnce() -> PythonScopeFacts,
    ) -> Arc<PythonScopeFacts> {
        if let Some(cached) = self
            .scope_facts_by_file
            .lock()
            .expect("Python scope-facts cache mutex poisoned")
            .get(file)
            .cloned()
        {
            return cached;
        }

        let facts = Arc::new(build());
        self.scope_facts_by_file
            .lock()
            .expect("Python scope-facts cache mutex poisoned")
            .entry(file.clone())
            .or_insert_with(|| facts.clone())
            .clone()
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

fn canonical_module_replacement(
    file: &ProjectFile,
    replacements: &HashMap<ProjectFile, ProjectFile>,
) -> Option<ProjectFile> {
    let mut seen = BTreeSet::new();
    let mut current = file.clone();
    while let Some(target) = replacements.get(&current) {
        if !seen.insert(current) {
            return None;
        }
        current = target.clone();
    }
    Some(current)
}

fn build_importer_reverse(
    module_index: &HashMap<String, Vec<ProjectFile>>,
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, Arc<ImportBinder>>,
    exports_by_file: &HashMap<ProjectFile, Arc<ExportIndex>>,
) -> HashMap<ProjectFile, Vec<ImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<ImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            let imported_module = binding
                .namespace_imported_module
                .as_deref()
                .unwrap_or(&binding.module_specifier);
            for target_file in resolve_module(module_index, file, imported_module) {
                // A glob `from m import *` binds every export of the target file
                // as a named edge, mirroring the graph it replaces.
                if matches!(binding.kind, ImportKind::Glob) {
                    let Some(exports) = exports_by_file.get(&target_file) else {
                        continue;
                    };
                    for export_name in exports.exports_by_name.keys() {
                        if export_name.starts_with('_') {
                            continue;
                        }
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

/// Export seeds for the target, following re-export chains.
pub fn usage_seeds(
    python: &dyn PythonUsageSource,
    target_file: &ProjectFile,
    target_short: &str,
) -> BTreeSet<(ProjectFile, String)> {
    python
        .usage_index()
        .seeds_for_target(target_file, target_short)
}

/// The import edges in `importer` that bind one of the `seeds`.
pub fn usage_matching_edges(
    python: &dyn PythonUsageSource,
    importer: &ProjectFile,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> Vec<ImportEdge> {
    python
        .usage_index()
        .matching_edges_for_importer(importer, seeds)
}

pub fn usage_importer_files(
    python: &dyn PythonUsageSource,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> HashSet<ProjectFile> {
    python.usage_index().importer_files_for_seeds(seeds)
}

pub fn usage_resolve_module_files(
    python: &dyn PythonUsageSource,
    importing_file: &ProjectFile,
    module_specifier: &str,
) -> Vec<ProjectFile> {
    python
        .usage_index()
        .resolve_module_files(importing_file, module_specifier)
}

pub fn usage_module_binding_timeline(
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    build: impl FnOnce() -> ModuleBindingTimeline,
) -> Arc<ModuleBindingTimeline> {
    python.usage_index().module_binding_timeline(file, build)
}

pub fn usage_scope_facts(
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    build: impl FnOnce() -> PythonScopeFacts,
) -> Arc<PythonScopeFacts> {
    python.usage_index().scope_facts(file, build)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_replacement_chains_canonicalize_and_cycles_are_rejected() {
        let root = tempfile::tempdir().expect("temporary project root");
        let first = ProjectFile::new(root.path(), "first.py");
        let second = ProjectFile::new(root.path(), "second.py");
        let canonical = ProjectFile::new(root.path(), "canonical.py");
        let chain = HashMap::from_iter([
            (first.clone(), second.clone()),
            (second.clone(), canonical.clone()),
        ]);

        assert_eq!(
            canonical_module_replacement(&first, &chain),
            Some(canonical)
        );

        let cycle = HashMap::from_iter([(first.clone(), second.clone()), (second, first.clone())]);
        assert_eq!(canonical_module_replacement(&first, &cycle), None);
    }

    #[test]
    fn module_binding_timeline_is_reused_within_index_generation() {
        let root = tempfile::tempdir().expect("temporary project root");
        let file = ProjectFile::new(root.path(), "consumer.py");
        let index = PythonUsageIndex::default();
        let first = index.module_binding_timeline(&file, || {
            ModuleBindingTimeline::from_iter([(
                "target".to_string(),
                vec![ModuleBindingEvent {
                    visible_from: 12,
                    conditional: false,
                    kind: ModuleBindingEventKind::Other,
                }],
            )])
        });
        let second = index.module_binding_timeline(&file, || {
            panic!("cached timeline should avoid rebuilding the file")
        });

        assert!(Arc::ptr_eq(&first, &second));

        let first_facts = index.scope_facts(&file, PythonScopeFacts::default);
        let second_facts = index.scope_facts(&file, || {
            panic!("cached scope facts should avoid rebuilding the file")
        });
        assert!(Arc::ptr_eq(&first_facts, &second_facts));
    }
}
