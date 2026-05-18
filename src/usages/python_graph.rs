use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
    Range,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::graph_core::{ImportEdge, ImportEdgeKind, ProjectUsageGraph};
use crate::usages::model::{ExportIndex, FuzzyResult, ImportBinder, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tree_sitter::{Node, Parser, Tree};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct PythonExportUsageGraphStrategy {
    _private: (),
}

impl PythonExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Python
    }
}

impl UsageAnalyzer for PythonExportUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        if overloads.is_empty() {
            return FuzzyResult::empty_success();
        }

        let target = &overloads[0];
        if target_language(target) != Language::Python {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "PythonExportUsageGraphStrategy: target is not Python".to_string(),
            };
        }

        let Some(py) = resolve_python_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "PythonExportUsageGraphStrategy: analyzer does not expose PythonAnalyzer"
                    .to_string(),
            };
        };

        let graph = build_python_graph(py, candidate_files, target.source());
        let seed_names = infer_export_names(py, target);
        if seed_names.is_empty() {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "PythonExportUsageGraphStrategy: no export seed resolved".to_string(),
            };
        }

        let mut seeds = BTreeSet::new();
        for seed_name in seed_names {
            seeds.extend(
                graph
                    .usage_graph
                    .seeds_for_target(target.source(), &seed_name),
            );
        }
        if seeds.is_empty() {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "PythonExportUsageGraphStrategy: export graph produced no seeds"
                    .to_string(),
            };
        }

        let scan_files = graph.scan_files(candidate_files, target.source());

        let hits = scan_files_for_seeds(analyzer, &graph, &scan_files, target, &seeds);
        let hits: BTreeSet<UsageHit> = hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();

        if hits.len() > max_usages {
            return FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            };
        }

        FuzzyResult::success(target.clone(), hits)
    }
}

fn resolve_python_analyzer(analyzer: &dyn IAnalyzer) -> Option<&PythonAnalyzer> {
    if let Some(py) = (analyzer as &dyn std::any::Any).downcast_ref::<PythonAnalyzer>() {
        return Some(py);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Python) {
        Some(AnalyzerDelegate::Python(py)) => Some(py),
        _ => None,
    }
}

fn target_language(target: &CodeUnit) -> Language {
    target
        .source()
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn infer_export_names(analyzer: &PythonAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if (target.is_function() || target.is_field())
        && let Some(owner_name) = owner_name(target)
    {
        let owner_exports = infer_export_names_for_local(analyzer, target.source(), &owner_name);
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    infer_export_names_for_local(analyzer, target.source(), target.identifier())
}

fn infer_export_names_for_local(
    analyzer: &PythonAnalyzer,
    file: &ProjectFile,
    local_name: &str,
) -> BTreeSet<String> {
    let index = analyzer.export_index_of(file);
    let mut export_names = BTreeSet::new();
    if index.exports_by_name.contains_key(local_name) {
        export_names.insert(local_name.to_string());
    }
    for (export_name, entry) in index.exports_by_name {
        if matches!(entry, crate::usages::ExportEntry::Local { local_name: ref name } if name == local_name)
        {
            export_names.insert(export_name);
        }
    }
    export_names
}

fn owner_name(target: &CodeUnit) -> Option<String> {
    let short_name = target.short_name();
    let last_dot = short_name.rfind('.')?;
    (last_dot > 0).then(|| short_name[..last_dot].to_string())
}

struct ParsedFile {
    source: Arc<String>,
    tree: Tree,
}

struct PythonProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
    usage_graph: ProjectUsageGraph,
    scoped_files: HashSet<ProjectFile>,
}

impl PythonProjectGraph {
    fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> HashSet<ProjectFile> {
        candidate_files
            .iter()
            .filter(|file| self.scoped_files.contains(*file))
            .cloned()
            .chain(std::iter::once(target_file.clone()))
            .collect()
    }
}

struct PythonGraphAdapter<'a> {
    analyzer: &'a PythonAnalyzer,
    module_index: HashMap<String, Vec<ProjectFile>>,
}

impl<'a> PythonGraphAdapter<'a> {
    fn new(analyzer: &'a PythonAnalyzer) -> Self {
        let python_files = collect_python_files(analyzer);
        let mut module_index: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for file in python_files {
            module_index
                .entry(python_module_name(&file))
                .or_default()
                .push(file);
        }
        for files in module_index.values_mut() {
            files.sort();
            files.dedup();
        }

        Self {
            analyzer,
            module_index,
        }
    }

    fn build_graph(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> PythonProjectGraph {
        let parser_language = tree_sitter_python::LANGUAGE.into();
        let mut scoped_files: HashSet<ProjectFile> = candidate_files.iter().cloned().collect();
        scoped_files.insert(target_file.clone());

        let mut frontier: VecDeque<ProjectFile> = scoped_files.iter().cloned().collect();
        let mut parsed: HashMap<ProjectFile, ParsedFile> = HashMap::default();
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = HashMap::default();
        let mut binders_by_file: HashMap<ProjectFile, ImportBinder> = HashMap::default();

        while let Some(file) = frontier.pop_front() {
            if parsed.contains_key(&file) {
                continue;
            }

            let Ok(source) = file.read_to_string() else {
                continue;
            };
            if source.is_empty() {
                continue;
            }

            let mut parser = Parser::new();
            if parser.set_language(&parser_language).is_err() {
                continue;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                continue;
            };

            let exports = self.analyzer.export_index_of(&file);
            let binder = self.analyzer.import_binder_of(&file);
            self.enqueue_frontier_files(&file, &exports, &binder, &mut scoped_files, &mut frontier);

            parsed.insert(
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                },
            );
            exports_by_file.insert(file.clone(), exports);
            binders_by_file.insert(file, binder);
        }

        let files: Vec<ProjectFile> = parsed.keys().cloned().collect();
        let usage_graph =
            ProjectUsageGraph::build(files, exports_by_file, &binders_by_file, |file, module| {
                self.resolve_module(file, module)
            });

        PythonProjectGraph {
            parsed,
            usage_graph,
            scoped_files,
        }
    }

    fn enqueue_frontier_files(
        &self,
        file: &ProjectFile,
        exports: &ExportIndex,
        binder: &ImportBinder,
        scoped_files: &mut HashSet<ProjectFile>,
        frontier: &mut VecDeque<ProjectFile>,
    ) {
        for entry in exports.exports_by_name.values() {
            if let crate::usages::ExportEntry::ReexportedNamed {
                module_specifier, ..
            } = entry
            {
                self.extend_scope(file, module_specifier, scoped_files, frontier);
            }
        }
        for star in &exports.reexport_stars {
            self.extend_scope(file, &star.module_specifier, scoped_files, frontier);
        }
        for binding in binder.bindings.values() {
            self.extend_scope(file, &binding.module_specifier, scoped_files, frontier);
        }
    }

    fn extend_scope(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
        scoped_files: &mut HashSet<ProjectFile>,
        frontier: &mut VecDeque<ProjectFile>,
    ) {
        for resolved in self.resolve_module(importing_file, module_specifier) {
            if scoped_files.insert(resolved.clone()) {
                frontier.push_back(resolved);
            }
        }
    }

    fn resolve_module(
        &self,
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
        self.module_index
            .get(&resolved_module)
            .cloned()
            .unwrap_or_default()
    }
}

fn build_python_graph(
    analyzer: &PythonAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target_file: &ProjectFile,
) -> PythonProjectGraph {
    PythonGraphAdapter::new(analyzer).build_graph(candidate_files, target_file)
}

fn collect_python_files(analyzer: &PythonAnalyzer) -> Vec<ProjectFile> {
    let mut files: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(Language::Python)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
    files.sort();
    files.dedup();
    files
}

fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    graph: &PythonProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(target).to_string();
    let target_member = member_name(target);
    let files_vec: Vec<&ProjectFile> = files.iter().collect();
    let parser_language = tree_sitter_python::LANGUAGE.into();

    files_vec.par_iter().for_each(|file| {
        let owned_source: Option<Arc<String>>;
        let owned_tree: Option<Tree>;
        let (source_str, tree_ref) = if let Some(parsed) = graph.parsed.get(*file) {
            (parsed.source.as_str(), &parsed.tree)
        } else {
            let Ok(source) = file.read_to_string() else {
                return;
            };
            if source.is_empty() {
                return;
            }
            let mut parser = Parser::new();
            if parser.set_language(&parser_language).is_err() {
                return;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                return;
            };
            owned_source = Some(Arc::new(source));
            owned_tree = Some(tree);
            (
                owned_source.as_deref().unwrap().as_str(),
                owned_tree.as_ref().unwrap(),
            )
        };

        let edges = graph.usage_graph.matching_edges_for_importer(file, seeds);
        let local_conflicts = collect_top_level_conflicts(tree_ref.root_node(), source_str);

        let mut local_hits = BTreeSet::new();
        let line_starts = compute_line_starts(source_str);
        let target_self_file = *file == target.source();

        let mut scan_ctx = ScanCtx {
            file,
            source: source_str,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            edges: &edges,
            target_self_file,
            local_conflicts: &local_conflicts,
            hits: &mut local_hits,
        };

        scan_node(tree_ref.root_node(), &mut scan_ctx);

        if !local_hits.is_empty() {
            let mut sink = collected
                .lock()
                .expect("usage hit collector mutex poisoned");
            sink.extend(local_hits);
        }
    });

    collected
        .into_inner()
        .expect("usage hit collector mutex poisoned")
}

struct ScanCtx<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    analyzer: &'a dyn IAnalyzer,
    target_short: &'a str,
    target_member: Option<&'a str>,
    edges: &'a [ImportEdge],
    target_self_file: bool,
    local_conflicts: &'a HashSet<String>,
    hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn binds_target(&self, ident: &str) -> bool {
        if !self.target_self_file && self.local_conflicts.contains(ident) {
            return false;
        }
        if self.edges.iter().any(|edge| edge.local_name == ident) {
            return true;
        }
        self.target_self_file && ident == self.target_short
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "import_from_statement" => continue,
            "identifier" => handle_identifier_candidate(node, ctx),
            "attribute" => handle_attribute_candidate(node, ctx),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn handle_identifier_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.target_member.is_some() {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() || !ctx.binds_target(text) || is_declaration_identifier(node) {
        return;
    }
    record_hit(node, ctx);
}

fn handle_attribute_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(object) = node.child_by_field_name("object") else {
        return;
    };
    let Some(attribute) = node.child_by_field_name("attribute") else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let attribute_text = slice(attribute, ctx.source);
    if let Some(member) = ctx.target_member
        && ctx.binds_target(object_text)
        && attribute_text == member
    {
        record_hit(attribute, ctx);
    }

    let namespace_match = ctx.edges.iter().any(|edge| {
        matches!(edge.kind, ImportEdgeKind::Namespace) && edge.local_name == object_text
    });
    if namespace_match && attribute_text == ctx.target_short {
        record_hit(attribute, ctx);
    }
}

fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    if start_byte >= end_byte {
        return;
    }

    let line_idx = find_line_index_for_offset(ctx.line_starts, start_byte);
    let snippet = build_snippet(ctx.source, ctx.line_starts, line_idx);
    let range = Range {
        start_byte,
        end_byte,
        start_line: line_idx,
        end_line: line_idx,
    };

    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };

    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        line_idx + 1,
        start_byte,
        end_byte,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        snippet,
    ));
}

fn build_snippet(source: &str, line_starts: &[usize], line_idx: usize) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let line_count = line_starts.len();
    let snippet_start = line_idx.saturating_sub(SNIPPET_CONTEXT_LINES);
    let snippet_end = line_idx
        .saturating_add(SNIPPET_CONTEXT_LINES)
        .min(line_count.saturating_sub(1));

    let mut buf = String::new();
    for idx in snippet_start..=snippet_end {
        let start = line_starts[idx];
        let end = if idx + 1 < line_count {
            line_starts[idx + 1]
        } else {
            source.len()
        };
        let line = source[start..end]
            .trim_end_matches('\n')
            .trim_end_matches('\r');
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(line);
    }
    buf
}

fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn top_level_identifier(target: &CodeUnit) -> &str {
    target
        .short_name()
        .split('.')
        .next()
        .unwrap_or(target.short_name())
}

fn member_name(target: &CodeUnit) -> Option<String> {
    let parts: Vec<&str> = target.short_name().split('.').collect();
    (parts.len() > 1).then(|| parts.last().unwrap().to_string())
}

fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let parent_kind = parent.kind();
    if matches!(
        parent_kind,
        "class_definition" | "function_definition" | "parameters"
    ) && parent
        .child_by_field_name("name")
        .map(|name| name.id() == node.id())
        .unwrap_or(false)
    {
        return true;
    }

    if matches!(
        parent_kind,
        "aliased_import" | "import_from_statement" | "import_statement"
    ) {
        return true;
    }

    parent_kind == "assignment"
        && parent
            .child_by_field_name("left")
            .map(|left| {
                left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
            })
            .unwrap_or(false)
}

fn collect_top_level_conflicts(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut conflicts = HashSet::default();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "class_definition" | "function_definition" => {
                if let Some(name) = child.child_by_field_name("name") {
                    let text = slice(name, source).trim();
                    if !text.is_empty() {
                        conflicts.insert(text.to_string());
                    }
                }
            }
            "expression_statement" => {
                if let Some(assignment) = child.named_child(0)
                    && assignment.kind() == "assignment"
                    && let Some(left) = assignment.child_by_field_name("left")
                {
                    collect_assigned_identifiers(left, source, &mut conflicts);
                }
            }
            _ => {}
        }
    }
    conflicts
}

fn collect_assigned_identifiers(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            let text = slice(node, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
            continue;
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn python_module_name(file: &ProjectFile) -> String {
    python_module_info(file).module_qualified_package()
}

struct PythonModuleInfo {
    package_name: String,
    module_name: String,
}

impl PythonModuleInfo {
    fn module_qualified_package(&self) -> String {
        if self.package_name.is_empty() {
            self.module_name.clone()
        } else {
            format!("{}.{}", self.package_name, self.module_name)
        }
    }
}

fn python_module_info(file: &ProjectFile) -> PythonModuleInfo {
    let raw_package = python_package_name_for_file(file);
    let module_name = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string();

    if module_name == "__init__" && !raw_package.is_empty() {
        if let Some((package_name, last_segment)) = raw_package.rsplit_once('.') {
            return PythonModuleInfo {
                package_name: package_name.to_string(),
                module_name: last_segment.to_string(),
            };
        }
        return PythonModuleInfo {
            package_name: String::new(),
            module_name: raw_package,
        };
    }

    PythonModuleInfo {
        package_name: raw_package,
        module_name,
    }
}

fn python_package_name_for_file(file: &ProjectFile) -> String {
    let Some(parent_rel) = file.rel_path().parent() else {
        return String::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return String::new();
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    let Some(package_root_rel) = effective_package_root_rel else {
        return dotted_path(parent_rel);
    };

    let Some(import_root_rel) = package_root_rel.parent() else {
        return dotted_path(parent_rel);
    };

    dotted_path(
        import_root_rel
            .strip_prefix("")
            .ok()
            .and_then(|_| parent_rel.strip_prefix(import_root_rel).ok())
            .unwrap_or(parent_rel),
    )
}

fn dotted_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn resolve_python_relative_module(source_file: &ProjectFile, module_expr: &str) -> Option<String> {
    let level = module_expr.chars().take_while(|ch| *ch == '.').count();
    let suffix = module_expr[level..].trim_matches('.');
    let current_package = python_current_package(source_file);
    let mut parts: Vec<_> = current_package
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    if level == 0 {
        return Some(module_expr.to_string());
    }
    if level > 0 {
        if level - 1 > parts.len() {
            return None;
        }
        parts.truncate(parts.len() - (level - 1));
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').map(str::to_string));
    }
    Some(parts.join("."))
}

fn python_current_package(source_file: &ProjectFile) -> String {
    let module = python_module_name(source_file);
    if source_file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        == Some("__init__.py")
    {
        module
    } else {
        module
            .rsplit_once('.')
            .map(|(package, _)| package.to_string())
            .unwrap_or_default()
    }
}
