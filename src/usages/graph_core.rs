use crate::analyzer::ProjectFile;
use crate::hash::{HashMap, HashSet, set_with_capacity};
use crate::usages::model::{ExportEntry, ExportIndex, ImportBinder, ImportKind};
use std::collections::{BTreeSet, VecDeque};

#[derive(Debug, Clone)]
pub struct ImportEdge {
    pub importer: ProjectFile,
    pub local_name: String,
    pub target_file: ProjectFile,
    pub kind: ImportEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportEdgeKind {
    Named(String),
    Default,
    Namespace,
}

pub struct ProjectUsageGraph {
    files: Vec<ProjectFile>,
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    seed_index: HashMap<String, Vec<(ProjectFile, String)>>,
    importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
}

impl ProjectUsageGraph {
    pub fn build<ResolveFn>(
        files: Vec<ProjectFile>,
        exports_by_file: HashMap<ProjectFile, ExportIndex>,
        binders_by_file: &HashMap<ProjectFile, ImportBinder>,
        mut resolve_module: ResolveFn,
    ) -> Self
    where
        ResolveFn: FnMut(&ProjectFile, &str) -> Vec<ProjectFile>,
    {
        let mut reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>> =
            HashMap::default();
        let mut star_reexports: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        let mut seed_index: HashMap<String, Vec<(ProjectFile, String)>> = HashMap::default();

        for (file, exports) in &exports_by_file {
            for (exported_name, entry) in &exports.exports_by_name {
                let local = match entry {
                    ExportEntry::Local { local_name } => Some(local_name.clone()),
                    ExportEntry::Default { local_name } => local_name.clone(),
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => {
                        for resolved_file in resolve_module(file, module_specifier) {
                            reexport_edges
                                .entry((resolved_file, imported_name.clone()))
                                .or_default()
                                .push((file.clone(), exported_name.clone()));
                        }
                        None
                    }
                };
                if let Some(local_name) = local {
                    seed_index
                        .entry(local_name.clone())
                        .or_default()
                        .push((file.clone(), exported_name.clone()));
                    if local_name != *exported_name {
                        seed_index
                            .entry(exported_name.clone())
                            .or_default()
                            .push((file.clone(), exported_name.clone()));
                    }
                } else {
                    seed_index
                        .entry(exported_name.clone())
                        .or_default()
                        .push((file.clone(), exported_name.clone()));
                }
            }
            for star in &exports.reexport_stars {
                for resolved_file in resolve_module(file, &star.module_specifier) {
                    star_reexports
                        .entry(resolved_file)
                        .or_default()
                        .push(file.clone());
                }
            }
        }

        let importer_reverse = build_importer_reverse(&files, binders_by_file, &mut resolve_module);

        Self {
            files,
            exports_by_file,
            reexport_edges,
            star_reexports,
            seed_index,
            importer_reverse,
        }
    }

    pub fn empty() -> Self {
        Self {
            files: Vec::new(),
            exports_by_file: HashMap::default(),
            reexport_edges: HashMap::default(),
            star_reexports: HashMap::default(),
            seed_index: HashMap::default(),
            importer_reverse: HashMap::default(),
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
                    ExportEntry::ReexportedNamed { .. } => None,
                };
                if let Some(local_name) = local
                    && local_name == target_short
                {
                    seeds.insert((target_file.clone(), exported_name.clone()));
                }
            }
        }

        if let Some(matches) = self.seed_index.get(target_short) {
            for (file, exported_name) in matches {
                seeds.insert((file.clone(), exported_name.clone()));
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

    pub fn importers_of_seeds(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = set_with_capacity(self.files.len().min(64));
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

    pub fn matching_edges_for_importer(
        &self,
        importer: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> Vec<ImportEdge> {
        let Some(edges) = self.importer_reverse.get(importer) else {
            return Vec::new();
        };
        edges
            .iter()
            .filter(|edge| edge_matches_seed(edge, seeds))
            .cloned()
            .collect()
    }
}

fn edge_matches_seed(edge: &ImportEdge, seeds: &BTreeSet<(ProjectFile, String)>) -> bool {
    match &edge.kind {
        ImportEdgeKind::Named(name) => seeds.contains(&(edge.target_file.clone(), name.clone())),
        ImportEdgeKind::Default => {
            seeds.contains(&(edge.target_file.clone(), "default".to_string()))
        }
        ImportEdgeKind::Namespace => seeds.iter().any(|(file, _)| file == &edge.target_file),
    }
}

fn build_importer_reverse<ResolveFn>(
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    resolve_module: &mut ResolveFn,
) -> HashMap<ProjectFile, Vec<ImportEdge>>
where
    ResolveFn: FnMut(&ProjectFile, &str) -> Vec<ProjectFile>,
{
    let mut reverse: HashMap<ProjectFile, Vec<ImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            for target_file in resolve_module(file, &binding.module_specifier) {
                let kind = match (binding.kind, binding.imported_name.as_deref()) {
                    (ImportKind::Default, _) => ImportEdgeKind::Default,
                    (ImportKind::Namespace, _) => ImportEdgeKind::Namespace,
                    (ImportKind::Named, Some(name)) => ImportEdgeKind::Named(name.to_string()),
                    (ImportKind::Named, None) => ImportEdgeKind::Named(local_name.clone()),
                };
                let edge = ImportEdge {
                    importer: file.clone(),
                    local_name: local_name.clone(),
                    target_file: target_file.clone(),
                    kind,
                };
                reverse.entry(target_file).or_default().push(edge);
            }
        }
    }
    reverse
}
