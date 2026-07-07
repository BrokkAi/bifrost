use crate::analyzer::go::go_field_declaration_is_embedded;
use crate::analyzer::go::packages::{canonical_go_package_name, read_go_module_path};
use crate::analyzer::usages::common::language_for_file;
pub(super) use crate::analyzer::usages::common::node_text;
use crate::analyzer::usages::go_graph::extractor::{
    field_owner_token, first_named_child, type_ref_from_node,
};
use crate::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind,
};
use crate::analyzer::usages::reexport_seeds;
use crate::analyzer::usages::{ImportEdge, ImportEdgeKind};
use crate::analyzer::{
    CodeUnit, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
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
        reexport_seeds::seeds_for_target(
            &self.exports_by_file,
            &self.reexport_edges,
            &self.star_reexports,
            target_file,
            target_short,
            // Go has no member exports, so short-name matching applies: the member-aware
            // params are neutral (owner seeding always allowed).
            target_short,
            true,
        )
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

/// Tree-free resolution metadata for the whole-workspace inverted edge build:
/// package names/import resolution, constructor-return facts, direct members,
/// and embedded-field promotion links. Built by parsing each file once and then
/// dropping every tree, so edge scans retain only compact maps; source trees are
/// re-parsed on demand inside each per-file walk and dropped immediately.
/// Mirrors the JS/TS [`JsTsUsageIndex`]. The tree-holding [`GoProjectGraph`]
/// still backs the per-symbol query and `get_definition` paths, which read node
/// text from trees.
///
/// [`JsTsUsageIndex`]: crate::analyzer::usages::js_ts_graph::JsTsUsageIndex
pub(crate) struct GoEdgeIndex {
    package_names: HashMap<ProjectFile, String>,
    constructor_return_types: HashMap<String, Vec<String>>,
    direct_member_fqns: HashMap<String, HashMap<String, Vec<String>>>,
    embedded_field_type_fqns: HashMap<String, Vec<String>>,
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

    pub(super) fn direct_member_fqns(&self, owner_fqn: &str, member: &str) -> &[String] {
        self.direct_member_fqns
            .get(owner_fqn)
            .and_then(|members| members.get(member))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(super) fn embedded_field_type_fqns(&self, owner_fqn: &str) -> &[String] {
        self.embedded_field_type_fqns
            .get(owner_fqn)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(super) fn unique_member_fqn(&self, owner_fqn: &str, member: &str) -> Option<String> {
        let direct = |owner: &str, member: &str| self.direct_member_fqns(owner, member).to_vec();
        let embedded = |owner: &str| self.embedded_field_type_fqns(owner).to_vec();
        match go_unique_indexed_member_candidate_at_nearest_depth(
            owner_fqn, member, &direct, &embedded,
        ) {
            GoIndexedMemberLookup::Unique(candidate) => Some(candidate),
            GoIndexedMemberLookup::Missing | GoIndexedMemberLookup::Ambiguous => None,
        }
    }
}

/// Build the tree-free [`GoEdgeIndex`] over `files`: parse each Go file once to
/// collect package clauses, constructor-return facts, and embedded-member
/// promotion metadata, then drop those trees before returning. `None` when there
/// are no Go files.
pub(crate) fn build_go_edge_index(
    analyzer: &GoAnalyzer,
    files: &[ProjectFile],
) -> Option<GoEdgeIndex> {
    let go_files: Vec<ProjectFile> = files
        .iter()
        .filter(|file| language_for_file(file) == Language::Go)
        .cloned()
        .collect();
    let module_path = read_go_module_path(go_files.first()?.root());

    let parsed_files: Vec<_> = go_files
        .par_iter()
        .filter_map(|file| Some((file.clone(), parse_go_file(file)?)))
        .collect();
    if parsed_files.is_empty() {
        return None;
    }
    let package_names: HashMap<ProjectFile, String> = parsed_files
        .iter()
        .map(|(file, parsed)| (file.clone(), parsed.package_name.clone()))
        .collect();
    let mut constructor_return_types: HashMap<String, Vec<String>> = HashMap::default();
    for (file, parsed) in &parsed_files {
        let package_fqn = canonical_go_package_name(file, &parsed.package_name);
        for (function, owner) in
            collect_constructor_returns(parsed.tree.root_node(), &parsed.source)
        {
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
    let indexed_files: Vec<ProjectFile> =
        parsed_files.iter().map(|(file, _)| file.clone()).collect();
    let type_fqns = collect_go_type_fqns(analyzer, &indexed_files);
    let direct_member_fqns = collect_go_direct_member_fqns(analyzer, &indexed_files);
    let embedded_field_type_fqns = collect_go_embedded_field_type_fqns(
        analyzer,
        &parsed_files,
        &package_names,
        &dir_index,
        module_path.as_deref(),
        &type_fqns,
    );

    Some(GoEdgeIndex {
        package_names,
        constructor_return_types,
        direct_member_fqns,
        embedded_field_type_fqns,
        dir_index,
        module_path,
    })
}

fn collect_go_type_fqns(analyzer: &GoAnalyzer, files: &[ProjectFile]) -> HashSet<String> {
    let mut type_fqns = HashSet::default();
    for file in files {
        for unit in analyzer.declarations(file) {
            if unit.is_class() {
                type_fqns.insert(unit.fq_name());
            }
        }
    }
    type_fqns
}

fn collect_go_direct_member_fqns(
    analyzer: &GoAnalyzer,
    files: &[ProjectFile],
) -> HashMap<String, HashMap<String, Vec<String>>> {
    let mut members: HashMap<String, HashMap<String, Vec<String>>> = HashMap::default();
    for file in files {
        for unit in analyzer.declarations(file) {
            if !(unit.is_function() || unit.is_field()) {
                continue;
            }
            let fqn = unit.fq_name();
            let Some((owner, member)) = fqn.rsplit_once('.') else {
                continue;
            };
            members
                .entry(owner.to_string())
                .or_default()
                .entry(member.to_string())
                .or_default()
                .push(fqn);
        }
    }
    members
}

fn collect_go_embedded_field_type_fqns(
    analyzer: &GoAnalyzer,
    parsed_files: &[(ProjectFile, ParsedFile)],
    package_names: &HashMap<ProjectFile, String>,
    dir_index: &ParentDirIndex,
    module_path: Option<&str>,
    type_fqns: &HashSet<String>,
) -> HashMap<String, Vec<String>> {
    let mut embedded_by_owner: HashMap<String, Vec<String>> = HashMap::default();
    let resolver = GoEdgeTypeResolver {
        analyzer,
        package_names,
        dir_index,
        module_path,
        type_fqns,
    };
    for (file, parsed) in parsed_files {
        if !package_names.contains_key(file) {
            continue;
        }
        for field in analyzer.declarations(file).filter(|unit| unit.is_field()) {
            let Some(type_text) = go_embedded_field_unit_type_text(analyzer, field, Some(parsed))
            else {
                continue;
            };
            let field_fqn = field.fq_name();
            let Some((owner_fqn, _)) = field_fqn.rsplit_once('.') else {
                continue;
            };
            let Some(embedded_fqn) =
                resolver.resolve_field_type_fqn(field.source(), owner_fqn, &type_text)
            else {
                continue;
            };
            embedded_by_owner
                .entry(owner_fqn.to_string())
                .or_default()
                .push(embedded_fqn);
        }
    }
    embedded_by_owner
}

pub(crate) fn go_embedded_field_unit_type_text(
    analyzer: &dyn IAnalyzer,
    field: &CodeUnit,
    parsed: Option<&ParsedFile>,
) -> Option<String> {
    let parsed_file;
    let parsed = match parsed {
        Some(parsed) => parsed,
        None => {
            parsed_file = parse_go_file(field.source())?;
            &parsed_file
        }
    };
    if !go_field_unit_is_embedded(analyzer, field, parsed) {
        return None;
    }
    let field_name = field.identifier().to_string();
    let type_text = go_field_unit_type_text(analyzer, field, &field_name)?;
    let simple = go_simple_type_name(&type_text)?;
    (simple == field_name).then_some(type_text)
}

fn go_field_unit_is_embedded(
    analyzer: &dyn IAnalyzer,
    field: &CodeUnit,
    parsed: &ParsedFile,
) -> bool {
    let Some(range) = analyzer.ranges(field).first() else {
        return false;
    };
    let Some(node) = parsed
        .tree
        .root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)
    else {
        return false;
    };
    go_enclosing_field_declaration(node).is_some_and(go_field_declaration_is_embedded)
}

fn go_enclosing_field_declaration(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "field_declaration" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

struct GoEdgeTypeResolver<'a> {
    analyzer: &'a GoAnalyzer,
    package_names: &'a HashMap<ProjectFile, String>,
    dir_index: &'a ParentDirIndex,
    module_path: Option<&'a str>,
    type_fqns: &'a HashSet<String>,
}

impl GoEdgeTypeResolver<'_> {
    fn resolve_field_type_fqn(
        &self,
        file: &ProjectFile,
        owner_fqn: &str,
        type_text: &str,
    ) -> Option<String> {
        if let Some((Some(qualifier), name)) = go_type_name_parts(type_text) {
            let (namespaces, _) = namespace_packages_from(
                self.analyzer,
                file,
                self.dir_index,
                self.module_path,
                |target| self.package_names.get(target).cloned(),
            );
            return namespaces.get(qualifier).and_then(|packages| {
                packages.iter().find_map(|package| {
                    let fqn = format!("{package}.{name}");
                    self.type_fqns.contains(&fqn).then_some(fqn)
                })
            });
        }
        let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
        let name = go_simple_type_name(type_text)?;
        let fqn = format!("{package}.{name}");
        self.type_fqns.contains(&fqn).then_some(fqn)
    }
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

pub(crate) fn resolve_go_import_namespaces(
    analyzer: &GoAnalyzer,
    file: &ProjectFile,
    package_names: &HashMap<ProjectFile, String>,
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let dir_index = build_parent_dir_index(package_names.keys());
    let module_path = read_go_module_path(file.root());
    namespace_packages_from(
        analyzer,
        file,
        &dir_index,
        module_path.as_deref(),
        |target| package_names.get(target).cloned(),
    )
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
    compatible_receiver_types: BTreeSet<(ProjectFile, String)>,
    field_owner_direct_names: HashMap<String, HashSet<String>>,
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
        let compatible_receiver_types = owner
            .as_ref()
            .map(|owner| {
                collect_compatible_receiver_types(
                    analyzer,
                    graph,
                    target,
                    target.source(),
                    owner,
                    &identifier,
                )
            })
            .unwrap_or_default();
        let field_owner_direct_names =
            collect_field_owner_direct_names(graph, &compatible_receiver_types);
        let owner_seeds = (!compatible_receiver_types.is_empty()).then(|| {
            let mut seeds = BTreeSet::new();
            for (file, receiver) in &compatible_receiver_types {
                let receiver_seeds = graph.seeds_for_target(file, receiver);
                if receiver_seeds.is_empty() && analyzer.parent_of(target).is_some() {
                    seeds.insert((file.clone(), receiver.clone()));
                } else {
                    seeds.extend(receiver_seeds);
                }
            }
            seeds
        });
        let mut owner_constructor_names = HashSet::default();
        for (receiver_file, receiver) in &compatible_receiver_types {
            owner_constructor_names.extend(collect_owner_constructor_names(
                graph,
                receiver,
                receiver_file,
            ));
        }
        Self {
            target: target.clone(),
            identifier,
            owner,
            top_level_seeds,
            owner_seeds,
            compatible_receiver_types,
            field_owner_direct_names,
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

fn collect_compatible_receiver_types(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    target: &CodeUnit,
    owner_source: &ProjectFile,
    owner: &str,
    method: &str,
) -> BTreeSet<(ProjectFile, String)> {
    let mut receivers = BTreeSet::from([(owner_source.clone(), owner.to_string())]);
    if let Some(target_signature) = target_method_signature(graph, owner_source, owner, method) {
        for (file, parsed) in &graph.parsed {
            if !same_go_package(graph, file, owner_source) {
                continue;
            }
            let root = parsed.tree.root_node();
            let source = parsed.source.as_str();
            let mut cursor = root.walk();
            for child in root.named_children(&mut cursor) {
                if child.kind() != "type_declaration" {
                    continue;
                }
                collect_interface_types_with_method(
                    child,
                    source,
                    method,
                    &target_signature,
                    file,
                    &mut receivers,
                );
            }
        }
    }
    collect_promoted_receiver_types(analyzer, graph, target, method, &mut receivers);
    receivers
}

fn collect_promoted_receiver_types(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    target: &CodeUnit,
    member: &str,
    receivers: &mut BTreeSet<(ProjectFile, String)>,
) {
    let target_fqn = target.fq_name();
    for unit in graph_declarations(analyzer, graph) {
        if !unit.is_class() || unit.fq_name() == target_fqn {
            continue;
        }
        let direct =
            |owner: &str, member: &str| graph_direct_member_fqns(analyzer, graph, owner, member);
        let embedded = |owner: &str| graph_embedded_field_type_fqns(analyzer, graph, owner);
        if matches!(
            go_unique_indexed_member_candidate_at_nearest_depth(
                &unit.fq_name(),
                member,
                &direct,
                &embedded,
            ),
            GoIndexedMemberLookup::Unique(candidate) if candidate == target_fqn
        ) {
            receivers.insert((unit.source().clone(), unit.short_name().to_string()));
        }
    }
}

fn graph_declarations(analyzer: &GoAnalyzer, graph: &GoProjectGraph) -> Vec<CodeUnit> {
    let mut units = Vec::new();
    for file in graph.parsed.keys() {
        units.extend(analyzer.declarations(file).cloned());
    }
    units
}

fn graph_direct_member_fqns(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    owner_fqn: &str,
    member: &str,
) -> Vec<String> {
    let member_fqn = format!("{owner_fqn}.{member}");
    graph_declarations(analyzer, graph)
        .into_iter()
        .filter(|unit| (unit.is_function() || unit.is_field()) && unit.fq_name() == member_fqn)
        .map(|unit| unit.fq_name())
        .collect()
}

fn graph_direct_children(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    owner_fqn: &str,
) -> Vec<CodeUnit> {
    let prefix = format!("{owner_fqn}.");
    graph_declarations(analyzer, graph)
        .into_iter()
        .filter(|unit| {
            unit.fq_name()
                .strip_prefix(&prefix)
                .is_some_and(|suffix| !suffix.contains('.'))
        })
        .collect()
}

fn graph_embedded_field_type_fqns(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    owner_fqn: &str,
) -> Vec<String> {
    graph_direct_children(analyzer, graph, owner_fqn)
        .into_iter()
        .filter_map(|field| {
            let parsed = graph.parsed_file(field.source())?;
            let type_text = go_embedded_field_unit_type_text(analyzer, &field, Some(parsed))?;
            go_resolve_graph_field_type_fqn(analyzer, graph, owner_fqn, field.source(), &type_text)
        })
        .collect()
}

fn go_resolve_graph_field_type_fqn(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    owner_fqn: &str,
    field_file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if let Some(fqn) =
        go_resolve_graph_qualified_type_from_file(analyzer, graph, field_file, type_text)
    {
        return Some(fqn);
    }
    let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
    let name = go_simple_type_name(type_text)?;
    let fqn = format!("{package}.{name}");
    graph_fqn_exists(analyzer, graph, &fqn).then_some(fqn)
}

fn go_resolve_graph_qualified_type_from_file(
    analyzer: &GoAnalyzer,
    graph: &GoProjectGraph,
    file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    let (Some(qualifier), name) = go_type_name_parts(type_text)? else {
        return None;
    };
    let (namespaces, _) = graph.namespace_packages(analyzer, file);
    namespaces.get(qualifier).and_then(|packages| {
        packages.iter().find_map(|package| {
            let fqn = format!("{package}.{name}");
            graph_fqn_exists(analyzer, graph, &fqn).then_some(fqn)
        })
    })
}

fn graph_fqn_exists(analyzer: &GoAnalyzer, graph: &GoProjectGraph, fqn: &str) -> bool {
    graph_declarations(analyzer, graph)
        .iter()
        .any(|unit| unit.fq_name() == fqn)
}

fn target_method_signature(
    graph: &GoProjectGraph,
    owner_source: &ProjectFile,
    owner: &str,
    method: &str,
) -> Option<String> {
    let parent = owner_source.parent().to_string_lossy().replace('\\', "/");
    let package_files = graph.dir_index.get(&parent)?;
    for file in package_files {
        if !same_go_package(graph, file, owner_source) {
            continue;
        }
        let Some(parsed) = graph.parsed_file(file) else {
            continue;
        };
        let mut cursor = parsed.tree.root_node().walk();
        for child in parsed.tree.root_node().named_children(&mut cursor) {
            if child.kind() != "method_declaration" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            if node_text(name_node, parsed.source.as_str()) != method {
                continue;
            }
            let Some(receiver) = child.child_by_field_name("receiver") else {
                continue;
            };
            let Some(receiver_type) = first_receiver_type_ref(receiver, parsed.source.as_str())
            else {
                continue;
            };
            if receiver_type.qualifier.is_none() && receiver_type.name.as_deref() == Some(owner) {
                return Some(method_signature(child, parsed.source.as_str()));
            }
        }
    }
    None
}

fn first_receiver_type_ref(receiver: Node<'_>, source: &str) -> Option<TypeRef> {
    let mut cursor = receiver.walk();
    receiver
        .named_children(&mut cursor)
        .find(|child| child.kind() == "parameter_declaration")
        .and_then(|param| param.child_by_field_name("type"))
        .and_then(|type_node| type_ref_from_node(type_node, source))
}

fn collect_interface_types_with_method(
    node: Node<'_>,
    source: &str,
    method: &str,
    target_signature: &str,
    file: &ProjectFile,
    receivers: &mut BTreeSet<(ProjectFile, String)>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "type_spec" | "type_alias" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let Some(type_node) = child.child_by_field_name("type") else {
                    continue;
                };
                if type_node.kind() == "interface_type"
                    && interface_declares_method(type_node, source, method, target_signature)
                {
                    receivers.insert((file.clone(), node_text(name_node, source).to_string()));
                }
            }
            "type_spec_list" => collect_interface_types_with_method(
                child,
                source,
                method,
                target_signature,
                file,
                receivers,
            ),
            _ => {}
        }
    }
}

fn interface_declares_method(
    node: Node<'_>,
    source: &str,
    method: &str,
    target_signature: &str,
) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "method_elem"
            && current
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == method)
            && method_signature(current, source) == target_signature
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn method_signature(node: Node<'_>, source: &str) -> String {
    let mut parts = Vec::new();
    if let Some(parameters) = node.child_by_field_name("parameters") {
        parts.push(format!(
            "params({})",
            parameter_type_texts(parameters, source).join(",")
        ));
    }
    if let Some(result) = node.child_by_field_name("result") {
        let result_types = if result.kind() == "parameter_list" {
            parameter_type_texts(result, source)
        } else {
            vec![normalized_type_text(result, source)]
        };
        parts.push(format!("results({})", result_types.join(",")));
    }
    parts.join(" ")
}

fn parameter_type_texts(node: Node<'_>, source: &str) -> Vec<String> {
    let mut types = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let Some(type_node) = child.child_by_field_name("type") else {
            continue;
        };
        let count = parameter_name_count(child).max(1);
        types.extend(std::iter::repeat_n(
            normalized_type_text(type_node, source),
            count,
        ));
    }
    types
}

fn parameter_name_count(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
        .count()
}

fn normalized_type_text(node: Node<'_>, source: &str) -> String {
    node_text(node, source)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn collect_field_owner_direct_names(
    graph: &GoProjectGraph,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
) -> HashMap<String, HashSet<String>> {
    let mut by_owner = HashMap::default();
    let Some((anchor_file, _)) = compatible_receiver_types.first() else {
        return by_owner;
    };
    let parent = anchor_file.parent().to_string_lossy().replace('\\', "/");
    let Some(package_files) = graph.dir_index.get(&parent) else {
        return by_owner;
    };
    for type_file in package_files {
        if !same_go_package(graph, anchor_file, type_file) {
            continue;
        }
        let Some(parsed) = graph.parsed_file(type_file) else {
            continue;
        };
        let mut cursor = parsed.tree.root_node().walk();
        for child in parsed.tree.root_node().named_children(&mut cursor) {
            if child.kind() != "type_declaration" {
                continue;
            }
            collect_struct_fields_with_compatible_types(
                graph,
                type_file,
                parsed.source.as_str(),
                child,
                compatible_receiver_types,
                &mut by_owner,
            );
        }
    }
    by_owner
}

fn collect_struct_fields_with_compatible_types(
    graph: &GoProjectGraph,
    type_file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
    by_owner: &mut HashMap<String, HashSet<String>>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "type_spec" | "type_alias" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let Some(type_node) = child.child_by_field_name("type") else {
                    continue;
                };
                if type_node.kind() != "struct_type" {
                    continue;
                }
                let owner = node_text(name_node, source).to_string();
                let fields = struct_fields_with_compatible_types(
                    graph,
                    type_file,
                    source,
                    type_node,
                    compatible_receiver_types,
                );
                if !fields.is_empty() {
                    by_owner.insert(owner, fields);
                }
            }
            "type_spec_list" => collect_struct_fields_with_compatible_types(
                graph,
                type_file,
                source,
                child,
                compatible_receiver_types,
                by_owner,
            ),
            _ => {}
        }
    }
}

fn struct_fields_with_compatible_types(
    graph: &GoProjectGraph,
    type_file: &ProjectFile,
    source: &str,
    struct_node: Node<'_>,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
) -> HashSet<String> {
    let mut fields = HashSet::default();
    let mut stack = vec![struct_node];
    while let Some(current) = stack.pop() {
        if current.kind() == "field_declaration"
            && let Some(type_node) = current.child_by_field_name("type")
            && let Some(ty) = type_ref_from_node(type_node, source)
            && type_ref_matches_compatible_receiver(
                graph,
                type_file,
                &ty,
                compatible_receiver_types,
            )
        {
            let mut names = current.walk();
            for name_node in current.children_by_field_name("name", &mut names) {
                fields.insert(node_text(name_node, source).to_string());
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    fields
}

fn type_ref_matches_compatible_receiver(
    graph: &GoProjectGraph,
    type_file: &ProjectFile,
    ty: &TypeRef,
    compatible_receiver_types: &BTreeSet<(ProjectFile, String)>,
) -> bool {
    let Some(name) = ty.name.as_deref() else {
        return false;
    };
    if ty.qualifier.is_none() {
        return compatible_receiver_types
            .iter()
            .any(|(receiver_file, receiver)| {
                receiver == name && same_go_package(graph, type_file, receiver_file)
            });
    }
    false
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

pub(crate) fn go_indexed_member_candidates_at_nearest_depth<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
) -> Option<(usize, Vec<T>)> {
    let mut path = HashSet::default();
    go_indexed_member_candidates_at_nearest_depth_with_path(
        owner_fqn, member, direct, embedded, &mut path,
    )
}

fn go_indexed_member_candidates_at_nearest_depth_with_path<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
    path: &mut HashSet<String>,
) -> Option<(usize, Vec<T>)> {
    if !path.insert(owner_fqn.to_string()) {
        return None;
    }
    let result = go_indexed_member_candidates_at_nearest_depth_inner(
        owner_fqn, member, direct, embedded, path,
    );
    path.remove(owner_fqn);
    result
}

fn go_indexed_member_candidates_at_nearest_depth_inner<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
    path: &mut HashSet<String>,
) -> Option<(usize, Vec<T>)> {
    let direct_candidates = direct(owner_fqn, member);
    if !direct_candidates.is_empty() {
        return Some((0, direct_candidates));
    }

    let mut best_depth = usize::MAX;
    let mut best_candidates = Vec::new();
    for embedded_owner in embedded(owner_fqn) {
        let Some((depth, candidates)) = go_indexed_member_candidates_at_nearest_depth_with_path(
            &embedded_owner,
            member,
            direct,
            embedded,
            path,
        ) else {
            continue;
        };
        let promoted_depth = depth + 1;
        match promoted_depth.cmp(&best_depth) {
            std::cmp::Ordering::Less => {
                best_depth = promoted_depth;
                best_candidates = candidates;
            }
            std::cmp::Ordering::Equal => best_candidates.extend(candidates),
            std::cmp::Ordering::Greater => {}
        }
    }

    (best_depth != usize::MAX).then_some((best_depth, best_candidates))
}

pub(crate) enum GoIndexedMemberLookup<T> {
    Missing,
    Unique(T),
    Ambiguous,
}

pub(crate) fn go_unique_indexed_member_candidate_at_nearest_depth<T: Clone>(
    owner_fqn: &str,
    member: &str,
    direct: &impl Fn(&str, &str) -> Vec<T>,
    embedded: &impl Fn(&str) -> Vec<String>,
) -> GoIndexedMemberLookup<T> {
    match go_indexed_member_candidates_at_nearest_depth(owner_fqn, member, direct, embedded) {
        None => GoIndexedMemberLookup::Missing,
        Some((_depth, candidates)) if candidates.len() == 1 => {
            let candidate = candidates
                .into_iter()
                .next()
                .expect("candidate count checked");
            GoIndexedMemberLookup::Unique(candidate)
        }
        Some((_depth, _candidates)) => GoIndexedMemberLookup::Ambiguous,
    }
}

fn go_field_unit_type_text(
    analyzer: &dyn IAnalyzer,
    field_unit: &CodeUnit,
    field: &str,
) -> Option<String> {
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(field_unit).iter().next().cloned())?;
    let trimmed = signature.trim();
    if let Some(type_text) = trimmed
        .strip_prefix(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(type_text.to_string());
    }
    let simple = go_simple_type_name(trimmed)?;
    (simple == field).then(|| trimmed.to_string())
}

pub(crate) fn go_simple_type_name(type_text: &str) -> Option<&str> {
    go_type_name_parts(type_text).map(|(_, name)| name)
}

pub(crate) fn go_type_name_parts(type_text: &str) -> Option<(Option<&str>, &str)> {
    let trimmed = type_text
        .trim()
        .trim_start_matches('*')
        .trim_start_matches("[]")
        .trim();
    let raw = trimmed
        .split(['[', '{', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or(trimmed);
    let (qualifier, name) = raw
        .rsplit_once('.')
        .map(|(qualifier, name)| (Some(qualifier.trim()), name))
        .unwrap_or((None, raw));
    let name = name.trim();
    (!name.is_empty()).then_some((qualifier.filter(|value| !value.is_empty()), name))
}

pub(super) struct ScanBindings {
    direct_names: HashSet<String>,
    pub(super) namespace_names: HashSet<String>,
    owner_direct_names: HashSet<String>,
    owner_namespace_names: HashSet<String>,
    owner_namespace_type_names: HashMap<String, HashSet<String>>,
    field_owner_direct_names: HashMap<String, HashSet<String>>,
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
        let mut owner_namespace_type_names: HashMap<String, HashSet<String>> = HashMap::default();
        for (receiver_file, receiver) in &spec.compatible_receiver_types {
            if same_go_package(graph, file, receiver_file) {
                owner_direct_names.insert(receiver.clone());
            }
            let receiver_seeds = graph.seeds_for_target(receiver_file, receiver);
            for edge in graph.matching_edges_for_importer(file, &receiver_seeds) {
                if matches!(
                    edge.kind,
                    ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_)
                ) {
                    owner_namespace_type_names
                        .entry(edge.local_name)
                        .or_default()
                        .insert(receiver.clone());
                }
            }
        }
        let field_owner_direct_names = if same_go_package(graph, file, spec.target.source()) {
            spec.field_owner_direct_names.clone()
        } else {
            HashMap::default()
        };

        Self {
            direct_names,
            namespace_names,
            owner_direct_names,
            owner_namespace_names,
            owner_namespace_type_names,
            field_owner_direct_names,
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
        ty.qualifier.as_ref().is_some_and(|qualifier| {
            self.owner_namespace_type_names
                .get(qualifier)
                .is_some_and(|owners| owners.contains(owner))
        })
    }

    pub(super) fn receiver_tokens_for_type(&self, ty: &TypeRef) -> Vec<String> {
        let mut tokens = Vec::new();
        if self.matches_owner_type(ty) {
            tokens.push(crate::analyzer::usages::go_graph::extractor::OWNER_TOKEN.to_string());
        }
        if ty.qualifier.is_none()
            && let Some(name) = ty.name.as_deref()
            && let Some(fields) = self.field_owner_direct_names.get(name)
        {
            tokens.extend(fields.iter().map(|field| field_owner_token(field)));
        }
        tokens.sort();
        tokens.dedup();
        tokens
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

pub(crate) fn extract_go_import_path(raw_import: &str) -> Option<String> {
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

pub(crate) fn default_go_import_local_name(import_path_or_identifier: &str) -> String {
    let tail = import_path_or_identifier
        .rsplit('/')
        .next()
        .unwrap_or(import_path_or_identifier);
    VERSION_SUFFIX_RE.replace(tail, "").to_string()
}

static VERSION_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.v\d+$").expect("valid Go module version suffix regex"));
