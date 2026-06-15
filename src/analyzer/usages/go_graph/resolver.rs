use crate::analyzer::go::packages::{canonical_go_package_name, read_go_module_path};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::graph_core::{ImportEdgeKind, ProjectUsageGraph};
use crate::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind,
};
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language,
    MultiAnalyzer, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use tree_sitter::{Node, Parser, Tree};

pub(super) fn resolve_go_analyzer(analyzer: &dyn IAnalyzer) -> Option<&GoAnalyzer> {
    if let Some(go) = (analyzer as &dyn std::any::Any).downcast_ref::<GoAnalyzer>() {
        return Some(go);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Go) {
        Some(AnalyzerDelegate::Go(go)) => Some(go),
        _ => None,
    }
}

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
    usage_graph: ProjectUsageGraph,
    /// Retained so the inverted whole-workspace edge builder can resolve a file's
    /// imports to package names without rescanning every parsed file.
    dir_index: ParentDirIndex,
    module_path: Option<String>,
}

impl GoProjectGraph {
    pub(super) fn parsed_files(&self) -> impl Iterator<Item = &ProjectFile> {
        self.parsed.keys()
    }

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
            let resolved = resolve_go_module(&path, &self.dir_index, self.module_path.as_deref());
            let mut package_names: Vec<String> = resolved
                .iter()
                .filter_map(|target| {
                    let parsed = self.parsed.get(target)?;
                    Some(canonical_go_package_name(target, &parsed.package_name))
                })
                .filter(|name| !name.is_empty())
                .collect();
            package_names.sort();
            package_names.dedup();
            if package_names.is_empty() {
                continue;
            }
            match alias {
                Some(".") => dot_imports.extend(package_names),
                Some(explicit) => by_alias
                    .entry(default_go_import_local_name(explicit))
                    .or_default()
                    .extend(package_names),
                None => {
                    // A plain import binds each resolved package under its own
                    // package-clause name, which is also the node fqn prefix.
                    for name in package_names {
                        by_alias.entry(name.clone()).or_default().push(name);
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
}

/// Read and tree-sitter parse a single Go file. Returns `None` if the file
/// cannot be read, the grammar fails to load, or parsing fails.
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

    let dir_index = build_parent_dir_index(&parsed);

    let mut exports_by_file = HashMap::default();
    let mut binders_by_file = HashMap::default();
    for file in &files {
        exports_by_file.insert(file.clone(), export_index_of(analyzer, file));
        binders_by_file.insert(
            file.clone(),
            import_binder_of(analyzer, file, &parsed, &dir_index, module_path.as_deref()),
        );
    }

    let usage_graph = ProjectUsageGraph::build(
        files,
        exports_by_file,
        &binders_by_file,
        |_importer, module| resolve_go_module(module, &dir_index, module_path.as_deref()),
    );

    GoProjectGraph {
        parsed,
        usage_graph,
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

fn build_parent_dir_index(parsed: &HashMap<ProjectFile, Arc<ParsedFile>>) -> ParentDirIndex {
    let mut index: ParentDirIndex = HashMap::default();
    for file in parsed.keys() {
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
}

impl TargetSpec {
    pub(super) fn new(analyzer: &GoAnalyzer, graph: &GoProjectGraph, target: &CodeUnit) -> Self {
        let identifier = target.identifier().to_string();
        let owner = owner_name(target);
        let top_level_seeds = if owner.is_none() || is_module_field(target) {
            let seeds = graph
                .usage_graph
                .seeds_for_target(target.source(), &identifier);
            (!seeds.is_empty()).then_some(seeds)
        } else {
            None
        };
        let owner_seeds = owner.as_ref().and_then(|owner| {
            let mut seeds = graph.usage_graph.seeds_for_target(target.source(), owner);
            if seeds.is_empty() && analyzer.parent_of(target).is_some() {
                seeds.insert((target.source().clone(), owner.clone()));
            }
            (!seeds.is_empty()).then_some(seeds)
        });

        Self {
            target: target.clone(),
            identifier,
            owner,
            top_level_seeds,
            owner_seeds,
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
            for edge in graph.usage_graph.matching_edges_for_importer(file, seeds) {
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
            for edge in graph.usage_graph.matching_edges_for_importer(file, seeds) {
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

fn extract_go_import_path(raw_import: &str) -> Option<String> {
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

fn default_go_import_local_name(import_path_or_identifier: &str) -> String {
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
