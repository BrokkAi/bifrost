use crate::analyzer::go::packages::{canonical_go_package_name, read_go_module_path};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::go_graph::extractor::{first_named_child, type_ref_from_node};
use crate::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind,
};
use crate::analyzer::usages::parsed_tree::parse_tree_sitter_file;
use crate::analyzer::usages::{ImportEdge, ImportEdgeKind};
use crate::analyzer::{
    CodeUnit, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock};
use tree_sitter::{Node, Parser, Tree};

pub(crate) struct ParsedFile {
    pub(super) source: Arc<String>,
    pub(super) tree: Tree,
    /// Byte offsets of each line start, computed once at parse time so the
    /// per-symbol scan does not recompute them for every symbol that scans this
    /// file.
    pub(super) line_starts: Vec<usize>,
    package_name: String,
}

/// Workspace-wide cache of parsed Go files, keyed by file.
///
/// `usage_graph` resolves callers for every symbol in the workspace, and each
/// per-symbol query rebuilds a [`GoProjectGraph`] over an overlapping set of
/// candidate files. Parsing the same file once per symbol that touches it is the
/// dominant cost on real repos (re-parsing the same files thousands of times).
/// Pre-parsing every file once and sharing the trees behind `Arc` collapses that
/// to a single parse per file while leaving the per-query graph construction
/// (import binders, module resolution) scoped to the candidate set, so there is
/// no quadratic blow-up in import resolution.
pub(crate) type ParsedFileCache = HashMap<ProjectFile, Arc<ParsedFile>>;

pub(crate) struct GoProjectGraph {
    pub(super) parsed: HashMap<ProjectFile, Arc<ParsedFile>>,
    /// Go-owned re-export + importer index, built from the analyzer's
    /// exports/binders + Go's own module resolution (`resolve_go_module`), so the
    /// forward scan resolves seeds + importer edges without a cross-file graph.
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
    /// Retained so the inverted whole-workspace edge builder can resolve a file's
    /// imports to package names without rescanning every parsed file.
    dir_index: ParentDirIndex,
    module_path: Option<String>,
}

impl GoProjectGraph {
    pub(super) fn parsed_file(&self, file: &ProjectFile) -> Option<&ParsedFile> {
        self.parsed.get(file).map(|parsed| parsed.as_ref())
    }

    /// The file's canonical (module-qualified) package name, matching the
    /// `package_name` half of the analyzer's `CodeUnit::fq_name()` so the inverted
    /// scan's callee fqns line up with the graph's nodes.
    pub(super) fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.parsed
            .get(file)
            .map(|parsed| canonical_go_package_name(file, &parsed.package_name))
    }

    /// Resolve `file`'s imports to the workspace package names they bind, so the
    /// inverted scan can turn a `pkg.Symbol` reference into a candidate node fqn.
    /// Returns `(alias -> package names, dot-imported package names)`. External
    /// (non-workspace) imports resolve to nothing and are simply absent.
    pub(super) fn namespace_packages(
        &self,
        analyzer: &GoAnalyzer,
        file: &ProjectFile,
    ) -> (HashMap<String, Vec<String>>, Vec<String>) {
        namespace_packages_from(
            analyzer,
            file,
            &self.dir_index,
            self.module_path.as_deref(),
            |target| {
                self.parsed
                    .get(target)
                    .map(|parsed| parsed.package_name.clone())
            },
        )
    }

    pub(super) fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        _target: &CodeUnit,
        _spec: &TargetSpec,
    ) -> HashSet<ProjectFile> {
        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| self.parsed.contains_key(*file))
            .cloned()
            .collect();
        files
    }

    /// Export seeds for `target_short` in `target_file`, following re-export
    /// chains. Go has no re-export aliasing, so the chain walk is a no-op and this
    /// is the file's own matching local exports — but it mirrors the graph it
    /// replaces so behavior is identical.
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
    resolve: &impl Fn(&str) -> Vec<ProjectFile>,
) -> (
    HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    HashMap<ProjectFile, Vec<ProjectFile>>,
) {
    let mut reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>> =
        HashMap::default();
    let mut star_reexports: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
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
                    for resolved_file in resolve(&binding.module_specifier) {
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
                    for resolved_file in resolve(module_specifier) {
                        reexport_edges
                            .entry((resolved_file, imported_name.clone()))
                            .or_default()
                            .push((file.clone(), exported_name.clone()));
                    }
                }
            }
        }
        for star in &exports.reexport_stars {
            for resolved_file in resolve(&star.module_specifier) {
                star_reexports
                    .entry(resolved_file)
                    .or_default()
                    .push(file.clone());
            }
        }
    }
    (reexport_edges, star_reexports)
}

fn build_importer_reverse_go(
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
    resolve: &impl Fn(&str) -> Vec<ProjectFile>,
) -> HashMap<ProjectFile, Vec<ImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<ImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            for target_file in resolve(&binding.module_specifier) {
                // A dot-import (`import . "pkg"`) binds every export of the target
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
                    (ImportKind::Namespace, _) => ImportEdgeKind::Namespace,
                    (ImportKind::Named, Some(name)) => ImportEdgeKind::Named(name.to_string()),
                    (ImportKind::Named, None) => ImportEdgeKind::Named(local_name.clone()),
                    // Go binders only emit Namespace/Glob.
                    (ImportKind::Default, _)
                    | (ImportKind::CommonJsRequire, _)
                    | (ImportKind::Glob, _) => continue,
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

/// Read and tree-sitter parse a single Go file. Returns `None` if the file
/// cannot be read, the grammar fails to load, or parsing fails.
/// Tree-free resolution metadata for the whole-workspace inverted edge build:
/// each file's Go `package` clause name, the parent-dir index, and the module
/// path. Built by parsing each file once to read its package clause and dropping
/// the tree, so the edge build holds no syntax trees — they are re-parsed on
/// demand inside the per-file walk and dropped immediately. Mirrors the JS/TS
/// [`JsTsUsageIndex`]. The tree-holding [`GoProjectGraph`] still backs the
/// per-symbol query and `get_definition` paths, which read node text from trees.
///
/// [`JsTsUsageIndex`]: crate::analyzer::usages::js_ts_graph::JsTsUsageIndex
pub(crate) struct GoEdgeIndex {
    package_names: HashMap<ProjectFile, String>,
    constructor_return_types: HashMap<String, Vec<String>>,
    dir_index: ParentDirIndex,
    module_path: Option<String>,
}

impl GoEdgeIndex {
    pub(super) fn files(&self) -> impl Iterator<Item = &ProjectFile> {
        self.package_names.keys()
    }

    /// The file's canonical (module-qualified) package name; see
    /// [`GoProjectGraph::package_name_of`].
    pub(super) fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.package_names
            .get(file)
            .map(|name| canonical_go_package_name(file, name))
    }

    /// See [`GoProjectGraph::namespace_packages`]; resolves target package names
    /// from the tree-free per-file map instead of retained parse trees.
    pub(super) fn namespace_packages(
        &self,
        analyzer: &GoAnalyzer,
        file: &ProjectFile,
    ) -> (HashMap<String, Vec<String>>, Vec<String>) {
        namespace_packages_from(
            analyzer,
            file,
            &self.dir_index,
            self.module_path.as_deref(),
            |target| self.package_names.get(target).cloned(),
        )
    }

    pub(super) fn constructor_return_types(&self, callee: &str) -> Option<&Vec<String>> {
        self.constructor_return_types.get(callee)
    }
}

/// Build the tree-free [`GoEdgeIndex`] over `files`: read each Go file's package
/// clause (parsing then dropping the tree, so peak live trees during the build are
/// bounded by the rayon worker count), then index parent directories for module
/// resolution. `None` when there are no Go files.
pub(crate) fn build_go_edge_index(files: &[ProjectFile]) -> Option<GoEdgeIndex> {
    let go_files: Vec<ProjectFile> = files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .collect();
    let module_path = read_go_module_path(go_files.first()?.root());

    let summaries: Vec<_> = go_files
        .par_iter()
        .filter_map(|file| Some((file.clone(), summarize_go_file(file)?)))
        .collect();
    let package_names: HashMap<ProjectFile, String> = summaries
        .iter()
        .map(|(file, summary)| (file.clone(), summary.package_name.clone()))
        .collect();
    let mut constructor_return_types: HashMap<String, Vec<String>> = HashMap::default();
    for (file, summary) in &summaries {
        let package_fqn = canonical_go_package_name(file, &summary.package_name);
        for (function, owner) in &summary.constructor_returns {
            constructor_return_types
                .entry(format!("{package_fqn}.{function}"))
                .or_default()
                .push(format!("{package_fqn}.{owner}"));
        }
    }
    for return_types in constructor_return_types.values_mut() {
        return_types.sort();
        return_types.dedup();
    }

    let dir_index = build_parent_dir_index(package_names.keys());

    Some(GoEdgeIndex {
        package_names,
        constructor_return_types,
        dir_index,
        module_path,
    })
}

struct GoFileSummary {
    package_name: String,
    constructor_returns: Vec<(String, String)>,
}

/// Parse `file` solely to read tree-free edge metadata, dropping the tree before
/// returning. `None` when the file is unreadable, empty, or unparseable — the same
/// skip-on-failure contract as the shared `parse_tree_sitter_file` it reuses.
fn summarize_go_file(file: &ProjectFile) -> Option<GoFileSummary> {
    let parsed = parse_tree_sitter_file(file, &tree_sitter_go::LANGUAGE.into())?;
    let root = parsed.tree.root_node();
    Some(GoFileSummary {
        package_name: package_name(root, &parsed.source),
        constructor_returns: collect_constructor_returns(root, &parsed.source),
    })
}

fn collect_constructor_returns(root: Node<'_>, source: &str) -> Vec<(String, String)> {
    let mut returns = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "function_declaration" {
            continue;
        }
        let (Some(name_node), Some(result)) = (
            child.child_by_field_name("name"),
            child.child_by_field_name("result"),
        ) else {
            continue;
        };
        let Some(owner) = first_result_type_ref(result, source)
            .filter(|ty| ty.qualifier.is_none())
            .and_then(|ty| ty.name)
        else {
            continue;
        };
        returns.push((node_text(name_node, source).to_string(), owner));
    }
    returns
}

/// Resolve `file`'s imports to the workspace package names they bind, given a
/// lookup from a resolved target file to its `package` clause name. Shared by the
/// tree-holding [`GoProjectGraph`] and the tree-free [`GoEdgeIndex`] so the two
/// cannot drift; see [`GoProjectGraph::namespace_packages`] for the contract.
fn namespace_packages_from(
    analyzer: &GoAnalyzer,
    file: &ProjectFile,
    dir_index: &ParentDirIndex,
    module_path: Option<&str>,
    target_package_name: impl Fn(&ProjectFile) -> Option<String>,
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut by_alias: HashMap<String, Vec<String>> = HashMap::default();
    let mut dot_imports: Vec<String> = Vec::new();
    for import in analyzer.import_info_of(file) {
        let alias = import.alias.as_deref();
        if alias == Some("_") {
            continue;
        }
        let Some(path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        let resolved = resolve_go_module(&path, dir_index, module_path);
        // Each resolved package is `(clause name, canonical fqn prefix)`: the
        // source refers to it by its `package` clause name (`row`), while the
        // node fqn it must map to uses the canonical, module-qualified path
        // (`example.com/.../row`).
        let mut packages: Vec<(String, String)> = resolved
            .iter()
            .filter_map(|target| {
                let clause = target_package_name(target)?;
                let canonical = canonical_go_package_name(target, &clause);
                (!clause.is_empty() && !canonical.is_empty()).then_some((clause, canonical))
            })
            .collect();
        packages.sort();
        packages.dedup();
        if packages.is_empty() {
            continue;
        }
        let canonicals = || packages.iter().map(|(_, canonical)| canonical.clone());
        match alias {
            Some(".") => dot_imports.extend(canonicals()),
            Some(explicit) => by_alias
                .entry(default_go_import_local_name(explicit))
                .or_default()
                .extend(canonicals()),
            None => {
                // A plain import is referred to by its package-clause name;
                // map that local name to the canonical node fqn prefix.
                for (clause, canonical) in packages {
                    by_alias.entry(clause).or_default().push(canonical);
                }
            }
        }
    }
    for names in by_alias.values_mut() {
        names.sort();
        names.dedup();
    }
    dot_imports.sort();
    dot_imports.dedup();
    (by_alias, dot_imports)
}

fn parse_go_file(file: &ProjectFile) -> Option<ParsedFile> {
    let source = file.read_to_string().ok()?;
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let package_name = package_name(tree.root_node(), &source);
    let line_starts = crate::text_utils::compute_line_starts(&source);
    Some(ParsedFile {
        source: Arc::new(source),
        tree,
        line_starts,
        package_name,
    })
}

/// Parse every Go file in `files` once, in parallel, into a shared cache that
/// per-symbol [`build_go_graph`] calls can reuse instead of re-parsing.
pub(crate) fn preparse_go_files(files: &[ProjectFile]) -> ParsedFileCache {
    files
        .par_iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .filter_map(|file| Some((file.clone(), Arc::new(parse_go_file(file)?))))
        .collect()
}

pub(super) fn build_go_graph(
    analyzer: &GoAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target_file: &ProjectFile,
    cache: Option<&ParsedFileCache>,
) -> GoProjectGraph {
    let mut parsed: HashMap<ProjectFile, Arc<ParsedFile>> = HashMap::default();
    let mut files = Vec::new();
    let mut module_path = None;
    let scoped_files: BTreeSet<ProjectFile> = candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .chain(std::iter::once(target_file.clone()))
        .collect();

    for file in scoped_files {
        if language_for_file(&file) != Language::Go {
            continue;
        }
        if module_path.is_none() {
            module_path = read_go_module_path(file.root());
        }
        let parsed_file = match cache.and_then(|cache| cache.get(&file).cloned()) {
            Some(parsed_file) => parsed_file,
            None => match parse_go_file(&file) {
                Some(parsed_file) => Arc::new(parsed_file),
                None => continue,
            },
        };
        files.push(file.clone());
        parsed.insert(file, parsed_file);
    }

    let dir_index = build_parent_dir_index(parsed.keys());

    let mut exports_by_file = HashMap::default();
    let mut binders_by_file = HashMap::default();
    for file in &files {
        exports_by_file.insert(file.clone(), export_index_of(analyzer, file));
        binders_by_file.insert(
            file.clone(),
            import_binder_of(analyzer, file, &parsed, &dir_index, module_path.as_deref()),
        );
    }

    let resolve = |module: &str| resolve_go_module(module, &dir_index, module_path.as_deref());
    let (reexport_edges, star_reexports) =
        build_reexport_edges(&exports_by_file, &binders_by_file, &resolve);
    let importer_reverse =
        build_importer_reverse_go(&files, &binders_by_file, &exports_by_file, &resolve);

    GoProjectGraph {
        parsed,
        exports_by_file,
        reexport_edges,
        star_reexports,
        importer_reverse,
        dir_index,
        module_path,
    }
}

/// Build the whole-workspace Go usage graph once (parse + binders + importer
/// graph) so a bulk caller (`usage_graph`) can share it across every per-symbol
/// query instead of rebuilding the import graph for each symbol's candidate set —
/// the rebuild is quadratic in candidate count and the dominant cost at scale.
pub(crate) fn build_workspace_go_graph(
    analyzer: &GoAnalyzer,
    files: &[ProjectFile],
    cache: Option<&ParsedFileCache>,
) -> Option<GoProjectGraph> {
    let target_file = files
        .iter()
        .find(|file| language_for_file(file) == Language::Go)?;
    let all_files: HashSet<ProjectFile> = files.iter().cloned().collect();
    Some(build_go_graph(analyzer, &all_files, target_file, cache))
}

fn export_index_of(analyzer: &GoAnalyzer, file: &ProjectFile) -> ExportIndex {
    let mut index = ExportIndex::empty();
    for unit in analyzer.declarations(file) {
        if unit.is_module() {
            continue;
        }
        index.exports_by_name.insert(
            unit.identifier().to_string(),
            ExportEntry::Local {
                local_name: unit.identifier().to_string(),
            },
        );
    }
    index
}

fn import_binder_of(
    analyzer: &GoAnalyzer,
    file: &ProjectFile,
    parsed: &HashMap<ProjectFile, Arc<ParsedFile>>,
    dir_index: &ParentDirIndex,
    module_path: Option<&str>,
) -> ImportBinder {
    let mut binder = ImportBinder::empty();
    for import in analyzer.import_info_of(file) {
        if import.alias.as_deref() == Some("_") {
            continue;
        }
        let Some(path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        match import.alias.as_deref() {
            Some(".") => {
                binder.bindings.insert(
                    "*".to_string(),
                    ImportBinding {
                        module_specifier: path,
                        kind: ImportKind::Glob,
                        imported_name: None,
                    },
                );
            }
            _ => {
                let locals = match import.alias.clone() {
                    Some(alias) => vec![default_go_import_local_name(&alias)],
                    None => {
                        let resolved = resolve_go_module(&path, dir_index, module_path);
                        let mut names: Vec<_> = resolved
                            .iter()
                            .filter_map(|target| parsed.get(target))
                            .map(|target| target.package_name.clone())
                            .filter(|name| !name.is_empty())
                            .collect();
                        names.sort();
                        names.dedup();
                        if names.is_empty() && is_local_like_go_import(&path, module_path) {
                            names.push(default_go_import_local_name(
                                import.identifier.as_deref().unwrap_or(path.as_str()),
                            ));
                        }
                        names
                    }
                };
                for local in locals {
                    binder.bindings.insert(
                        local,
                        ImportBinding {
                            module_specifier: path.clone(),
                            kind: ImportKind::Namespace,
                            imported_name: None,
                        },
                    );
                }
            }
        }
    }
    binder
}

/// Maps a normalized parent directory to the parsed files it contains, so a Go
/// import resolves to its package's files with a couple of map lookups instead of
/// scanning every parsed file. Building this once is what makes a whole-workspace
/// graph build linear rather than quadratic in the file count.
type ParentDirIndex = HashMap<String, Vec<ProjectFile>>;

fn build_parent_dir_index<'a>(files: impl Iterator<Item = &'a ProjectFile>) -> ParentDirIndex {
    let mut index: ParentDirIndex = HashMap::default();
    for file in files {
        let parent = file.parent().to_string_lossy().replace('\\', "/");
        index.entry(parent).or_default().push(file.clone());
    }
    index
}

fn resolve_go_module(
    module: &str,
    dir_index: &ParentDirIndex,
    module_path: Option<&str>,
) -> Vec<ProjectFile> {
    let local_rel = local_go_import_rel_path(module, module_path);
    let vendor_rel = format!("vendor/{}", module.trim_matches('/'));
    let mut resolved: Vec<ProjectFile> = Vec::new();
    if let Some(files) = dir_index.get(&vendor_rel) {
        resolved.extend(files.iter().cloned());
    }
    // `local_rel == Some("")` means the import refers to the module root, whose
    // files have an empty parent — the `index.get("")` lookup covers that case.
    if let Some(rel) = local_rel.as_ref()
        && let Some(files) = dir_index.get(rel)
    {
        resolved.extend(files.iter().cloned());
    }
    resolved.sort();
    resolved.dedup();
    resolved
}

fn local_go_import_rel_path(import_path: &str, module_path: Option<&str>) -> Option<String> {
    let import_path = import_path.trim().trim_matches('/');
    if let Some(relative) = import_path.strip_prefix("./") {
        return Some(relative.trim_matches('/').to_string());
    }
    if import_path == "." {
        return Some(String::new());
    }
    let module_path = module_path?.trim_matches('/');
    if import_path == module_path {
        return Some(String::new());
    }
    import_path
        .strip_prefix(&format!("{module_path}/"))
        .map(|suffix| suffix.trim_matches('/').to_string())
}

fn is_local_like_go_import(import_path: &str, module_path: Option<&str>) -> bool {
    local_go_import_rel_path(import_path, module_path).is_some()
        || import_path.starts_with("./")
        || import_path == "."
}

fn package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if matches!(package_child.kind(), "package_identifier" | "identifier") {
                return node_text(package_child, source).to_string();
            }
        }
    }
    String::new()
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) identifier: String,
    pub(super) owner: Option<String>,
    top_level_seeds: Option<BTreeSet<(ProjectFile, String)>>,
    owner_seeds: Option<BTreeSet<(ProjectFile, String)>>,
    owner_constructor_names: HashSet<String>,
}

impl TargetSpec {
    pub(super) fn new(analyzer: &GoAnalyzer, graph: &GoProjectGraph, target: &CodeUnit) -> Self {
        let identifier = target.identifier().to_string();
        let owner = owner_name(target);
        let top_level_seeds = if owner.is_none() || is_module_field(target) {
            let seeds = graph.seeds_for_target(target.source(), &identifier);
            (!seeds.is_empty()).then_some(seeds)
        } else {
            None
        };
        let owner_seeds = owner.as_ref().and_then(|owner| {
            let mut seeds = graph.seeds_for_target(target.source(), owner);
            if seeds.is_empty() && analyzer.parent_of(target).is_some() {
                seeds.insert((target.source().clone(), owner.clone()));
            }
            (!seeds.is_empty()).then_some(seeds)
        });
        let owner_constructor_names = owner
            .as_ref()
            .map(|owner| collect_owner_constructor_names(graph, owner, target.source()))
            .unwrap_or_default();

        Self {
            target: target.clone(),
            identifier,
            owner,
            top_level_seeds,
            owner_seeds,
            owner_constructor_names,
        }
    }

    pub(super) fn has_scan_seed(&self) -> bool {
        self.top_level_seeds.is_some() || self.owner_seeds.is_some()
    }

    pub(super) fn identifier(&self) -> &str {
        &self.identifier
    }

    pub(super) fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub(super) fn is_member(&self) -> bool {
        self.owner.is_some() && !is_module_field(&self.target)
    }

    /// Whether `name` is a package-level function in the owner type's package whose
    /// result is the owner type (e.g. `NewService` for `Service`), so a local bound
    /// to its return value can be seeded as the owner receiver.
    pub(super) fn is_owner_constructor(&self, name: &str) -> bool {
        self.owner_constructor_names.contains(name)
    }
}

/// Names of package-level functions in the owner type's package whose first result
/// is the owner type. A local bound to `NewOwner()` (or `pkg.NewOwner()`) then
/// carries the owner type, so value-receiver method calls on it resolve on the
/// graph path instead of silently returning no hits (#232).
fn collect_owner_constructor_names(
    graph: &GoProjectGraph,
    owner: &str,
    owner_source: &ProjectFile,
) -> HashSet<String> {
    let mut names = HashSet::default();
    // A Go package is a single directory, so scope the scan to the owner source's
    // directory via the prebuilt index rather than walking every parsed file — the
    // bulk `usage_graph` path resolves many targets over the whole workspace and the
    // surrounding code keeps that linear by construction.
    let parent = owner_source.parent().to_string_lossy().replace('\\', "/");
    let Some(package_files) = graph.dir_index.get(&parent) else {
        return names;
    };
    for file in package_files {
        if !same_go_package(graph, file, owner_source) {
            continue;
        }
        let Some(parsed) = graph.parsed_file(file) else {
            continue;
        };
        let root = parsed.tree.root_node();
        let source = parsed.source.as_str();
        let mut cursor = root.walk();
        for child in root.named_children(&mut cursor) {
            if child.kind() != "function_declaration" {
                continue;
            }
            let (Some(name_node), Some(result)) = (
                child.child_by_field_name("name"),
                child.child_by_field_name("result"),
            ) else {
                continue;
            };
            if result_names_owner_type(result, source, owner) {
                names.insert(node_text(name_node, source).to_string());
            }
        }
    }
    names
}

/// Whether the `result` node of a function declaration names the owner type as its
/// (first) return value. Handles a bare type, a pointer type, and the common
/// `(Owner, error)` tuple idiom by inspecting the first component.
fn result_names_owner_type(result: Node<'_>, source: &str, owner: &str) -> bool {
    let names_owner = |ty: &TypeRef| ty.qualifier.is_none() && ty.name.as_deref() == Some(owner);
    first_result_type_ref(result, source).is_some_and(|ty| names_owner(&ty))
}

fn first_result_type_ref(result: Node<'_>, source: &str) -> Option<TypeRef> {
    if let Some(ty) = type_ref_from_node(result, source) {
        return Some(ty);
    }
    if result.kind() == "parameter_list"
        && let Some(first) = first_named_child(result)
    {
        let type_node = first.child_by_field_name("type").unwrap_or(first);
        return type_ref_from_node(type_node, source);
    }
    None
}

fn owner_name(target: &CodeUnit) -> Option<String> {
    if is_module_field(target) {
        return None;
    }
    let short = target.short_name();
    short
        .rsplit_once('.')
        .map(|(owner, _)| owner.to_string())
        .filter(|owner| !owner.is_empty())
}

fn is_module_field(target: &CodeUnit) -> bool {
    target.is_field() && target.short_name().starts_with("_module_.")
}

pub(super) struct ScanBindings {
    direct_names: HashSet<String>,
    pub(super) namespace_names: HashSet<String>,
    owner_direct_names: HashSet<String>,
    owner_namespace_names: HashSet<String>,
}

impl ScanBindings {
    pub(super) fn new(graph: &GoProjectGraph, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut direct_names = HashSet::default();
        let mut namespace_names = HashSet::default();
        if let Some(seeds) = &spec.top_level_seeds {
            for edge in graph.matching_edges_for_importer(file, seeds) {
                match edge.kind {
                    ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_) => {
                        namespace_names.insert(edge.local_name);
                    }
                    ImportEdgeKind::Named(_) | ImportEdgeKind::Default => {
                        direct_names.insert(edge.local_name);
                    }
                }
            }
        }
        if same_go_package(graph, file, spec.target.source()) {
            direct_names.insert(spec.identifier.clone());
        }

        let mut owner_direct_names = HashSet::default();
        let mut owner_namespace_names = HashSet::default();
        if let Some(seeds) = &spec.owner_seeds {
            for edge in graph.matching_edges_for_importer(file, seeds) {
                match edge.kind {
                    ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_) => {
                        owner_namespace_names.insert(edge.local_name);
                    }
                    ImportEdgeKind::Named(_) | ImportEdgeKind::Default => {
                        if let Some(owner) = &spec.owner {
                            owner_direct_names.insert(owner.clone());
                        }
                    }
                }
            }
        }
        if same_go_package(graph, file, spec.target.source())
            && let Some(owner) = &spec.owner
        {
            owner_direct_names.insert(owner.clone());
        }

        Self {
            direct_names,
            namespace_names,
            owner_direct_names,
            owner_namespace_names,
        }
    }

    pub(super) fn matches_direct_target(&self, text: &str) -> bool {
        self.direct_names.contains(text)
    }

    /// Whether the owner type is referable by a bare (unqualified) name in this
    /// file — true in the owner's own package and through dot imports — so a bare
    /// constructor call like `NewOwner()` resolves to the owner type here.
    pub(super) fn owner_referable_directly(&self) -> bool {
        !self.owner_direct_names.is_empty()
    }

    /// Whether `qualifier` is an import name bound to the owner type's package, so a
    /// qualified constructor call like `pkg.NewOwner()` resolves to the owner type.
    pub(super) fn owner_namespace_contains(&self, qualifier: &str) -> bool {
        self.owner_namespace_names.contains(qualifier)
    }

    pub(super) fn matches_owner_type(&self, ty: &TypeRef) -> bool {
        let Some(owner) = ty.name.as_deref() else {
            return false;
        };
        if ty.qualifier.is_none() && self.owner_direct_names.contains(owner) {
            return true;
        }
        ty.qualifier
            .as_ref()
            .is_some_and(|qualifier| self.owner_namespace_names.contains(qualifier))
    }
}

pub(super) struct TypeRef {
    pub(super) qualifier: Option<String>,
    pub(super) name: Option<String>,
}

fn same_go_package(graph: &GoProjectGraph, left: &ProjectFile, right: &ProjectFile) -> bool {
    if left.parent() != right.parent() {
        return false;
    }
    let Some(left_parsed) = graph.parsed.get(left) else {
        return false;
    };
    let Some(right_parsed) = graph.parsed.get(right) else {
        return false;
    };
    left_parsed.package_name == right_parsed.package_name
}

pub(in crate::analyzer::usages) fn extract_go_import_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim();
    trimmed
        .split_whitespace()
        .next_back()
        .map(|path| {
            path.trim_matches('"')
                .trim_matches('`')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|path| !path.is_empty())
}

pub(in crate::analyzer::usages) fn default_go_import_local_name(
    import_path_or_identifier: &str,
) -> String {
    let tail = import_path_or_identifier
        .rsplit('/')
        .next()
        .unwrap_or(import_path_or_identifier);
    VERSION_SUFFIX_RE.replace(tail, "").to_string()
}

pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

static VERSION_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.v\d+$").expect("valid Go module version suffix regex"));
