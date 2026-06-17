use crate::analyzer::usages::common::language_for_target_filtered;
use crate::analyzer::usages::js_ts_graph::extractor::{
    compute_export_index, compute_import_binder,
};
use crate::analyzer::usages::model::{ExportEntry, ExportIndex, ImportBinder, ImportKind};
use crate::analyzer::usages::{ImportEdge, ImportEdgeKind};
use crate::analyzer::{
    AliasResolver, CodeUnit, IAnalyzer, Language, ProjectFile, resolve_js_ts_module_specifier,
};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use tree_sitter::{Parser, Tree};

/// Cached parse for one source file. `source` is held alongside the `Tree` so AST byte
/// ranges remain valid for the lifetime of the graph (and so the scan phase can reuse
/// the parse result without re-reading the file).
pub(super) struct ParsedFile {
    pub(super) source: Arc<String>,
    pub(super) tree: Tree,
    /// Byte offsets of each line start, computed once at parse time so the
    /// inverted edge scan can attribute references to lines without recomputing.
    pub(super) line_starts: Vec<usize>,
}

pub(crate) struct JsTsProjectGraph {
    /// Parsed source + tree per file. Reused by the scan phase to avoid double parsing.
    pub(super) parsed: HashMap<ProjectFile, ParsedFile>,
    /// JS/TS-owned re-export + importer index, built from the per-file
    /// export/import indices + analyzer-level module resolution
    /// (`resolve_js_ts_module_specifier` + tsconfig aliases), so the forward scan
    /// resolves seeds + importer edges without a cross-file graph.
    pub(super) exports_by_file: HashMap<ProjectFile, ExportIndex>,
    pub(super) reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    pub(super) direct_reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    pub(super) star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    pub(super) direct_star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    pub(super) importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
}

pub(super) fn build_js_ts_graph(analyzer: &dyn IAnalyzer, language: Language) -> JsTsProjectGraph {
    let files = collect_jsts_files(analyzer, language);
    let parser_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => {
            return JsTsProjectGraph {
                parsed: HashMap::default(),
                exports_by_file: HashMap::default(),
                reexport_edges: HashMap::default(),
                direct_reexport_edges: HashMap::default(),
                star_reexports: HashMap::default(),
                direct_star_reexports: HashMap::default(),
                importer_reverse: HashMap::default(),
            };
        }
    };

    let parsed_files: Vec<(ProjectFile, ParsedFile, ExportIndex, ImportBinder)> = files
        .par_iter()
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            let mut parser = Parser::new();
            parser.set_language(&parser_language).ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            let exports = compute_export_index(&source, &tree);
            let binder = compute_import_binder(&source, &tree);
            let line_starts = crate::text_utils::compute_line_starts(&source);
            Some((
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                    line_starts,
                },
                exports,
                binder,
            ))
        })
        .collect();

    let mut parsed: HashMap<ProjectFile, ParsedFile> = map_with_capacity(parsed_files.len());
    let mut exports_by_file: HashMap<ProjectFile, ExportIndex> =
        map_with_capacity(parsed_files.len());
    let mut binders_by_file: HashMap<ProjectFile, ImportBinder> =
        map_with_capacity(parsed_files.len());

    for (file, parsed_file, exports, binder) in parsed_files {
        parsed.insert(file.clone(), parsed_file);
        exports_by_file.insert(file.clone(), exports);
        binders_by_file.insert(file, binder);
    }

    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let resolve = |file: &ProjectFile, module_specifier: &str| {
        resolve_js_ts_module_specifier(file, module_specifier, language, Some(&aliases))
    };
    let (reexport_edges, direct_reexport_edges, star_reexports, direct_star_reexports) =
        build_reexport_edges(&exports_by_file, &binders_by_file, &resolve);
    let importer_reverse =
        build_importer_reverse(&files, &binders_by_file, &exports_by_file, &resolve);

    JsTsProjectGraph {
        parsed,
        exports_by_file,
        reexport_edges,
        direct_reexport_edges,
        star_reexports,
        direct_star_reexports,
        importer_reverse,
    }
}

impl JsTsProjectGraph {
    /// Export seeds for `target_short` in `target_file`, following named and star
    /// re-export chains across files.
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

    /// Files that import one of the `seeds` (plus the seed files themselves) — the
    /// candidate set the forward scan narrows to.
    pub(super) fn importers_of_seeds(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = set_with_capacity(self.parsed.len().min(64));
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

#[allow(clippy::type_complexity)]
fn build_reexport_edges(
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    resolve: &impl Fn(&ProjectFile, &str) -> Vec<ProjectFile>,
) -> (
    HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    HashMap<ProjectFile, Vec<ProjectFile>>,
    HashMap<ProjectFile, Vec<ProjectFile>>,
) {
    let mut reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>> =
        HashMap::default();
    let mut direct_reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>> =
        HashMap::default();
    let mut star_reexports: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
    let mut direct_star_reexports: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
    for (file, exports) in exports_by_file {
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
                    for resolved_file in resolve(file, &binding.module_specifier) {
                        direct_reexport_edges
                            .entry((file.clone(), exported_name.clone()))
                            .or_default()
                            .push((resolved_file.clone(), imported_name.clone()));
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
                    for resolved_file in resolve(file, module_specifier) {
                        direct_reexport_edges
                            .entry((file.clone(), exported_name.clone()))
                            .or_default()
                            .push((resolved_file.clone(), imported_name.clone()));
                        reexport_edges
                            .entry((resolved_file, imported_name.clone()))
                            .or_default()
                            .push((file.clone(), exported_name.clone()));
                    }
                }
            }
        }
        for star in &exports.reexport_stars {
            for resolved_file in resolve(file, &star.module_specifier) {
                direct_star_reexports
                    .entry(file.clone())
                    .or_default()
                    .push(resolved_file.clone());
                star_reexports
                    .entry(resolved_file)
                    .or_default()
                    .push(file.clone());
            }
        }
    }
    (
        reexport_edges,
        direct_reexport_edges,
        star_reexports,
        direct_star_reexports,
    )
}

fn build_importer_reverse(
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
    resolve: &impl Fn(&ProjectFile, &str) -> Vec<ProjectFile>,
) -> HashMap<ProjectFile, Vec<ImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<ImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            for target_file in resolve(file, &binding.module_specifier) {
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
                if matches!(binding.kind, ImportKind::CommonJsRequire) {
                    let Some(exports) = exports_by_file.get(&target_file) else {
                        continue;
                    };
                    if exports.exports_by_name.contains_key("default") {
                        reverse
                            .entry(target_file.clone())
                            .or_default()
                            .push(ImportEdge {
                                importer: file.clone(),
                                local_name: local_name.clone(),
                                target_file: target_file.clone(),
                                kind: ImportEdgeKind::Default,
                            });
                    }
                    for export_name in exports.exports_by_name.keys() {
                        reverse
                            .entry(target_file.clone())
                            .or_default()
                            .push(ImportEdge {
                                importer: file.clone(),
                                local_name: local_name.clone(),
                                target_file: target_file.clone(),
                                kind: ImportEdgeKind::CommonJsRequire(export_name.clone()),
                            });
                    }
                    continue;
                }

                let kind = match (binding.kind, binding.imported_name.as_deref()) {
                    (ImportKind::Default, _) => ImportEdgeKind::Default,
                    (ImportKind::Namespace, _) => ImportEdgeKind::Namespace,
                    (ImportKind::CommonJsRequire, _) => {
                        unreachable!("commonjs require handled above")
                    }
                    (ImportKind::Glob, _) => unreachable!("glob handled above"),
                    (ImportKind::Named, Some(name)) => ImportEdgeKind::Named(name.to_string()),
                    (ImportKind::Named, None) => ImportEdgeKind::Named(local_name.clone()),
                };
                let edge = ImportEdge {
                    importer: file.clone(),
                    local_name: local_name.clone(),
                    target_file,
                    kind,
                };
                reverse
                    .entry(edge.target_file.clone())
                    .or_default()
                    .push(edge);
            }
        }
    }
    reverse
}

fn collect_jsts_files(analyzer: &dyn IAnalyzer, language: Language) -> Vec<ProjectFile> {
    let mut result: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(language)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
    result.sort();
    result.dedup();
    result
}

pub(super) fn target_language(target: &CodeUnit) -> Language {
    language_for_target_filtered(target, |lang| {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    })
}

pub(super) fn top_level_identifier(target: &CodeUnit) -> &str {
    // For nested members like `BaseClass.foo`, the top-level identifier is `BaseClass`.
    target
        .short_name()
        .split('.')
        .next()
        .unwrap_or(target.short_name())
}

pub(super) fn member_name(target: &CodeUnit) -> Option<String> {
    // Anything past the first dot is treated as the member chain. We strip TS-specific
    // `$static` suffix to align with the original syntactic name.
    let parts: Vec<&str> = target.short_name().split('.').collect();
    if parts.len() <= 1 {
        return None;
    }
    let last = parts.last().copied()?;
    Some(last.trim_end_matches("$static").to_string())
}

pub(super) fn is_static_member(target: &CodeUnit) -> bool {
    target.short_name().ends_with("$static")
}
