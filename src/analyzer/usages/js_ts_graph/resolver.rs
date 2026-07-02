use crate::analyzer::js_ts::syntax::compute_import_binder;
use crate::analyzer::usages::common::language_for_target_filtered;
use crate::analyzer::usages::js_ts_graph::extractor::compute_export_index;
use crate::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind,
};
use crate::analyzer::usages::parsed_tree::js_ts_tree_sitter_language_for_file;
use crate::analyzer::usages::reexport_seeds;
use crate::analyzer::usages::{ImportEdge, ImportEdgeKind};
use crate::analyzer::{
    AliasResolver, CodeUnit, IAnalyzer, Language, ProjectFile, resolve_js_ts_module_specifier,
};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use tree_sitter::Parser;

/// JS/TS resolution maps for one language: a re-export + importer index built from the
/// per-file export/import indices plus analyzer-level module resolution
/// (`resolve_js_ts_module_specifier` + tsconfig aliases), so the forward scan resolves
/// seeds + importer edges without a cross-file graph. Plain data (no syntax trees), so it
/// can be cached on the analyzer and reused across queries.
#[derive(Default, Clone)]
pub(crate) struct JsTsUsageIndex {
    pub(super) exports_by_file: HashMap<ProjectFile, ExportIndex>,
    pub(super) binders_by_file: HashMap<ProjectFile, ImportBinder>,
    pub(super) reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    pub(super) direct_reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    pub(super) star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    pub(super) direct_star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    pub(super) importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
}

/// Build the cacheable [`JsTsUsageIndex`] for one language: parse every file once to
/// derive its export/import indices, then build the re-export + importer maps — dropping
/// the syntax trees as soon as the per-file indices are computed (the maps are the only
/// thing the analyzer caches; the scan phase re-parses its candidate files on demand).
pub(crate) fn build_jsts_usage_index(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> JsTsUsageIndex {
    let files = collect_jsts_files(analyzer, language);
    if tree_sitter_language_for(language).is_none() {
        return JsTsUsageIndex::default();
    }

    let per_file: Vec<(ProjectFile, ExportIndex, ImportBinder)> = files
        .par_iter()
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            let mut parser = Parser::new();
            let file_language = js_ts_tree_sitter_language_for_file(file, language)?;
            parser.set_language(&file_language).ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            let exports = compute_export_index(&source, &tree);
            let binder = compute_import_binder(&source, &tree);
            // `tree`/`source` drop here — only the per-file indices outlive the parse.
            Some((file.clone(), exports, binder))
        })
        .collect();

    let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = map_with_capacity(per_file.len());
    let mut binders_by_file: HashMap<ProjectFile, ImportBinder> = map_with_capacity(per_file.len());
    for (file, exports, binder) in per_file {
        exports_by_file.insert(file.clone(), exports);
        binders_by_file.insert(file, binder);
    }

    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let resolve = |file: &ProjectFile, module_specifier: &str| {
        resolve_js_ts_module_specifier(file, module_specifier, language, Some(&aliases))
    };
    let (reexport_edges, direct_reexport_edges, star_reexports, direct_star_reexports) =
        build_reexport_edges(&exports_by_file, &binders_by_file, &resolve);
    let importer_reverse = build_importer_reverse(
        &files,
        &binders_by_file,
        &exports_by_file,
        &direct_reexport_edges,
        &direct_star_reexports,
        &resolve,
    );

    JsTsUsageIndex {
        exports_by_file,
        reexport_edges,
        direct_reexport_edges,
        star_reexports,
        direct_star_reexports,
        importer_reverse,
        binders_by_file,
    }
}

impl JsTsUsageIndex {
    /// Resolve `exported_name` as exported by `module_files` to concrete local
    /// declarations, following named re-export chains and `export *` barrels.
    pub(crate) fn local_bindings_for_exported_name(
        &self,
        module_files: &[ProjectFile],
        exported_name: &str,
    ) -> BTreeSet<(ProjectFile, String)> {
        let mut resolved = BTreeSet::new();
        let mut visited = HashSet::default();
        let mut frontier: VecDeque<(ProjectFile, String)> = module_files
            .iter()
            .cloned()
            .map(|file| (file, exported_name.to_string()))
            .collect();

        while let Some((file, name)) = frontier.pop_front() {
            if !visited.insert((file.clone(), name.clone())) {
                continue;
            }

            if let Some(targets) = self
                .direct_reexport_edges
                .get(&(file.clone(), name.clone()))
            {
                for target in targets {
                    frontier.push_back(target.clone());
                }
                continue;
            }

            if let Some(exports) = self.exports_by_file.get(&file)
                && let Some(entry) = exports.exports_by_name.get(&name)
            {
                match entry {
                    ExportEntry::Local { local_name } => {
                        resolved.insert((file, local_name.clone()));
                    }
                    ExportEntry::Default { local_name } => {
                        resolved.insert((
                            file,
                            local_name.clone().unwrap_or_else(|| "default".to_string()),
                        ));
                    }
                    ExportEntry::ReexportedNamed { .. } => {}
                }
                continue;
            }

            // Per ES module semantics, `export * from` does not forward default.
            if name != "default"
                && let Some(target_files) = self.direct_star_reexports.get(&file)
            {
                for target_file in target_files {
                    frontier.push_back((target_file.clone(), name.clone()));
                }
            }
        }

        resolved
    }

    pub(crate) fn import_binding(
        &self,
        importer: &ProjectFile,
        local_name: &str,
    ) -> Option<&ImportBinding> {
        self.binders_by_file.get(importer)?.bindings.get(local_name)
    }

    /// Export seeds for `target_short`/`target_name` in `target_file`, following named
    /// and star re-export chains across files. Member targets only match the owner
    /// export when the analyzer reports that owner as the declaration parent.
    pub(super) fn seeds_for_target(
        &self,
        target_file: &ProjectFile,
        target_short: &str,
        target_name: &str,
        owner_seed_allowed: bool,
    ) -> BTreeSet<(ProjectFile, String)> {
        reexport_seeds::seeds_for_target(
            &self.exports_by_file,
            &self.reexport_edges,
            &self.star_reexports,
            target_file,
            target_short,
            target_name,
            owner_seed_allowed,
        )
    }

    /// Files that import one of the `seeds` (plus the seed files themselves) — the
    /// candidate set the forward scan narrows to.
    pub(super) fn importers_of_seeds(
        &self,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = set_with_capacity(self.importer_reverse.len().min(64));
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
        reexport_seeds::matching_edges_for_importer(&self.importer_reverse, importer, seeds)
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
                    if let Some((module_specifier, imported_name)) =
                        imported_member_reexport_target(local_name, binder)
                    {
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
                        continue;
                    }
                    let Some(binding) = binder.bindings.get(local_name) else {
                        continue;
                    };
                    if binding.kind == ImportKind::CommonJsRequire
                        && binding.imported_name.is_none()
                    {
                        for resolved_file in resolve(file, &binding.module_specifier) {
                            let Some(target_exports) = exports_by_file.get(&resolved_file) else {
                                continue;
                            };
                            for nested_export in target_exports.exports_by_name.keys() {
                                if nested_export == "default" {
                                    continue;
                                }
                                let exported_member = format!("{exported_name}.{nested_export}");
                                direct_reexport_edges
                                    .entry((file.clone(), exported_member.clone()))
                                    .or_default()
                                    .push((resolved_file.clone(), nested_export.clone()));
                                reexport_edges
                                    .entry((resolved_file.clone(), nested_export.clone()))
                                    .or_default()
                                    .push((file.clone(), exported_member));
                            }
                        }
                        continue;
                    }
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

fn imported_member_reexport_target<'a>(
    local_name: &str,
    binder: &'a ImportBinder,
) -> Option<(&'a str, String)> {
    let (object_name, member_name) = local_name.split_once('.')?;
    let binding = binder.bindings.get(object_name)?;
    match binding.kind {
        ImportKind::CommonJsRequire | ImportKind::Namespace => {
            Some((binding.module_specifier.as_str(), member_name.to_string()))
        }
        ImportKind::Default | ImportKind::Named | ImportKind::Glob => None,
    }
}

fn build_importer_reverse(
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
    direct_reexport_edges: &HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    direct_star_reexports: &HashMap<ProjectFile, Vec<ProjectFile>>,
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
                    for (reexport_file, export_name) in direct_reexport_edges.keys() {
                        if reexport_file != &target_file {
                            continue;
                        }
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
                    if let Some(star_targets) = direct_star_reexports.get(&target_file) {
                        for star_target in star_targets {
                            for export_name in export_names_for_file(
                                star_target,
                                exports_by_file,
                                direct_reexport_edges,
                            ) {
                                reverse
                                    .entry(target_file.clone())
                                    .or_default()
                                    .push(ImportEdge {
                                        importer: file.clone(),
                                        local_name: local_name.clone(),
                                        target_file: target_file.clone(),
                                        kind: ImportEdgeKind::CommonJsRequire(export_name),
                                    });
                            }
                        }
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

fn export_names_for_file(
    file: &ProjectFile,
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
    direct_reexport_edges: &HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(exports) = exports_by_file.get(file) {
        names.extend(exports.exports_by_name.keys().cloned());
    }
    names.extend(
        direct_reexport_edges
            .keys()
            .filter(|(reexport_file, _)| reexport_file == file)
            .map(|(_, export_name)| export_name.clone()),
    );
    names
}

pub(super) fn collect_jsts_files(analyzer: &dyn IAnalyzer, language: Language) -> Vec<ProjectFile> {
    let mut result: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(language)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
    result.sort();
    result.dedup();
    result
}

/// The default tree-sitter grammar for a JS/TS language, or `None` for anything else.
pub(super) fn tree_sitter_language_for(language: Language) -> Option<tree_sitter::Language> {
    match language {
        Language::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        _ => None,
    }
}

pub(super) fn target_language(target: &CodeUnit) -> Language {
    language_for_target_filtered(target, |lang| {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    })
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
