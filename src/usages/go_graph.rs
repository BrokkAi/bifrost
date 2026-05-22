use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language,
    MultiAnalyzer, ProjectFile, Range,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::graph_core::{ImportEdgeKind, ProjectUsageGraph};
use crate::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::usages::model::{
    ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding, ImportKind, UsageHit,
};
use crate::usages::traits::UsageAnalyzer;
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, Mutex};
use tree_sitter::{Node, Parser, Tree};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;
const OWNER_TOKEN: &str = "__go_target_owner__";

#[derive(Default)]
pub struct GoUsageGraphStrategy {
    _private: (),
}

impl GoUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Go
    }
}

impl UsageAnalyzer for GoUsageGraphStrategy {
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
        if target_language(target) != Language::Go {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "GoUsageGraphStrategy: target is not Go".to_string(),
            };
        }

        let Some(go) = resolve_go_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "GoUsageGraphStrategy: analyzer does not expose GoAnalyzer".to_string(),
            };
        };

        let graph = build_go_graph(go);
        let target_spec = TargetSpec::new(go, &graph, target);
        if !target_spec.has_scan_seed() {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "GoUsageGraphStrategy: no graph seed resolved".to_string(),
            };
        }

        let scan_files = graph.scan_files(candidate_files, target, &target_spec);
        let hits = scan_files_for_target(analyzer, &graph, scan_files, &target_spec);
        let hits: BTreeSet<_> = hits
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

fn resolve_go_analyzer(analyzer: &dyn IAnalyzer) -> Option<&GoAnalyzer> {
    if let Some(go) = (analyzer as &dyn std::any::Any).downcast_ref::<GoAnalyzer>() {
        return Some(go);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Go) {
        Some(AnalyzerDelegate::Go(go)) => Some(go),
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

struct ParsedFile {
    source: Arc<String>,
    tree: Tree,
    package_name: String,
}

struct GoProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
    usage_graph: ProjectUsageGraph,
}

impl GoProjectGraph {
    fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target: &CodeUnit,
        spec: &TargetSpec,
    ) -> HashSet<ProjectFile> {
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| self.parsed.contains_key(*file))
            .cloned()
            .collect();
        files.insert(target.source().clone());

        if let Some(seeds) = &spec.top_level_seeds {
            files.extend(self.usage_graph.importers_of_seeds(seeds));
        }
        if let Some(seeds) = &spec.owner_seeds {
            files.extend(self.usage_graph.importers_of_seeds(seeds));
        }

        files.retain(|file| {
            file == target.source()
                || candidate_files.contains(file)
                || same_go_package(self, file, target.source())
        });
        files
    }
}

fn build_go_graph(analyzer: &GoAnalyzer) -> GoProjectGraph {
    let parser_language = tree_sitter_go::LANGUAGE.into();
    let mut parsed = HashMap::default();
    let mut exports_by_file = HashMap::default();
    let mut binders_by_file = HashMap::default();
    let mut files = Vec::new();

    for file in analyzer.get_analyzed_files() {
        if target_language_file(&file) != Language::Go {
            continue;
        }
        let Ok(source) = file.read_to_string() else {
            continue;
        };
        let mut parser = Parser::new();
        if parser.set_language(&parser_language).is_err() {
            continue;
        }
        let Some(tree) = parser.parse(source.as_str(), None) else {
            continue;
        };

        let package_name = package_name(tree.root_node(), &source);
        exports_by_file.insert(file.clone(), export_index_of(analyzer, &file));
        binders_by_file.insert(file.clone(), import_binder_of(analyzer, &file));
        files.push(file.clone());
        parsed.insert(
            file,
            ParsedFile {
                source: Arc::new(source),
                tree,
                package_name,
            },
        );
    }

    let usage_graph = ProjectUsageGraph::build(
        files,
        exports_by_file,
        &binders_by_file,
        |importer, module| resolve_go_module(importer, module, &parsed),
    );

    GoProjectGraph {
        parsed,
        usage_graph,
    }
}

fn target_language_file(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
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

fn import_binder_of(analyzer: &GoAnalyzer, file: &ProjectFile) -> ImportBinder {
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
                let local = import
                    .alias
                    .clone()
                    .or_else(|| import.identifier.clone())
                    .unwrap_or_else(|| {
                        path.rsplit('/').next().unwrap_or(path.as_str()).to_string()
                    });
                binder.bindings.insert(
                    local,
                    ImportBinding {
                        module_specifier: path,
                        kind: ImportKind::Namespace,
                        imported_name: None,
                    },
                );
            }
        }
    }
    binder
}

fn resolve_go_module(
    _importer: &ProjectFile,
    module: &str,
    parsed: &HashMap<ProjectFile, ParsedFile>,
) -> Vec<ProjectFile> {
    let mut resolved: Vec<_> = parsed
        .keys()
        .filter(|candidate| {
            let parent = candidate.parent().to_string_lossy().replace('\\', "/");
            parent == module
                || module.ends_with(&format!("/{parent}"))
                || parent.ends_with(&format!("/{module}"))
        })
        .cloned()
        .collect();
    resolved.sort();
    resolved.dedup();
    resolved
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

#[derive(Clone)]
struct TargetSpec {
    target: CodeUnit,
    identifier: String,
    owner: Option<String>,
    top_level_seeds: Option<BTreeSet<(ProjectFile, String)>>,
    owner_seeds: Option<BTreeSet<(ProjectFile, String)>>,
}

impl TargetSpec {
    fn new(analyzer: &GoAnalyzer, graph: &GoProjectGraph, target: &CodeUnit) -> Self {
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

    fn has_scan_seed(&self) -> bool {
        self.top_level_seeds.is_some() || self.owner_seeds.is_some()
    }

    fn is_member(&self) -> bool {
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

fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    graph: &GoProjectGraph,
    files: HashSet<ProjectFile>,
    spec: &TargetSpec,
) -> BTreeSet<UsageHit> {
    let hits = Mutex::new(BTreeSet::new());
    let files: Vec<_> = files.into_iter().collect();

    files.par_iter().for_each(|file| {
        let Some(parsed) = graph.parsed.get(file) else {
            return;
        };
        let source = parsed.source.as_str();
        let line_starts = compute_line_starts(source);
        let scan_bindings = ScanBindings::new(graph, file, spec);
        let mut local_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts: &line_starts,
            analyzer,
            spec,
            bindings: scan_bindings,
            hits: &mut local_hits,
        };
        let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
        scan_node(parsed.tree.root_node(), &mut ctx, &mut locals);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Go graph collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Go graph collector")
}

struct ScanBindings {
    direct_names: HashSet<String>,
    namespace_names: HashSet<String>,
    owner_direct_names: HashSet<String>,
    owner_namespace_names: HashSet<String>,
}

impl ScanBindings {
    fn new(graph: &GoProjectGraph, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut direct_names = HashSet::default();
        let mut namespace_names = HashSet::default();
        if let Some(seeds) = &spec.top_level_seeds {
            for edge in graph.usage_graph.matching_edges_for_importer(file, seeds) {
                match edge.kind {
                    ImportEdgeKind::Namespace => {
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
                    ImportEdgeKind::Namespace => {
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

    fn matches_direct_target(&self, text: &str) -> bool {
        self.direct_names.contains(text)
    }

    fn matches_owner_type(&self, ty: &TypeRef) -> bool {
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

struct ScanCtx<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    analyzer: &'a dyn IAnalyzer,
    spec: &'a TargetSpec,
    bindings: ScanBindings,
    hits: &'a mut BTreeSet<UsageHit>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    match node.kind() {
        "import_declaration" => return,
        "function_declaration" | "method_declaration" => {
            locals.enter_scope();
            seed_parameters(node, ctx, locals);
            scan_children(node, ctx, locals);
            locals.exit_scope();
            return;
        }
        "block" | "block_statement" => {
            locals.enter_scope();
            scan_children(node, ctx, locals);
            locals.exit_scope();
            return;
        }
        "parameter_declaration" => {
            seed_parameter_declaration(node, ctx, locals);
        }
        "var_declaration" | "short_var_declaration" | "assignment_statement" => {
            seed_local_bindings(node, ctx, locals);
        }
        "selector_expression" | "qualified_type" => {
            scan_selector_like(node, ctx, locals);
        }
        "identifier" | "type_identifier" => {
            scan_direct_identifier(node, ctx);
        }
        _ => {}
    }

    scan_children(node, ctx, locals);
}

fn scan_children(node: Node<'_>, ctx: &mut ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx, locals);
    }
}

fn seed_parameters(node: Node<'_>, ctx: &ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_list" {
            let mut params = child.walk();
            for param in child.named_children(&mut params) {
                if param.kind() == "parameter_declaration" {
                    seed_parameter_declaration(param, ctx, locals);
                }
            }
        }
    }
}

fn seed_parameter_declaration(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    if !type_ref_from_node(type_node, ctx.source)
        .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
    {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            locals.seed_symbol(
                node_text(child, ctx.source).to_string(),
                OWNER_TOKEN.to_string(),
            );
        }
    }
}

fn seed_local_bindings(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let text = node_text(node, ctx.source);
    for caps in VAR_TYPED_RE.captures_iter(text) {
        if type_ref_from_captures(&caps, "qualifier", "name")
            .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
            && let Some(var) = caps.name("var")
        {
            locals.seed_symbol(var.as_str().to_string(), OWNER_TOKEN.to_string());
        }
    }
    for caps in CONSTRUCTED_RE.captures_iter(text) {
        if type_ref_from_captures(&caps, "qualifier", "name")
            .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
            && let Some(var) = caps.name("var")
        {
            locals.seed_symbol(var.as_str().to_string(), OWNER_TOKEN.to_string());
        }
    }
    for caps in ALIAS_RE.captures_iter(text) {
        let Some(lhs) = caps.name("lhs") else {
            continue;
        };
        let Some(rhs) = caps.name("rhs") else {
            continue;
        };
        locals.alias_symbol(lhs.as_str().to_string(), rhs.as_str());
    }
}

fn scan_selector_like(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) {
    let Some((qualifier, field_node)) = selector_parts(node, ctx.source) else {
        return;
    };
    let field = node_text(field_node, ctx.source);
    if field != ctx.spec.identifier {
        return;
    }

    if ctx.spec.is_member() {
        if locals
            .resolve_symbol(&qualifier)
            .as_precise()
            .is_some_and(|targets| targets.contains(OWNER_TOKEN))
        {
            record_hit(field_node, ctx);
        }
        return;
    }

    if ctx.bindings.namespace_names.contains(&qualifier) {
        record_hit(field_node, ctx);
    }
}

fn scan_direct_identifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.is_member() || is_definition_identifier(node) {
        return;
    }
    let text = node_text(node, ctx.source);
    if ctx.bindings.matches_direct_target(text) {
        record_hit(node, ctx);
    }
}

fn selector_parts<'a>(node: Node<'a>, source: &str) -> Option<(String, Node<'a>)> {
    let qualifier_node = node
        .child_by_field_name("operand")
        .or_else(|| node.child_by_field_name("package"))
        .or_else(|| first_named_child(node))?;
    let field_node = node
        .child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| last_named_child(node))?;
    Some((node_text(qualifier_node, source).to_string(), field_node))
}

#[derive(Default)]
struct TypeRef {
    qualifier: Option<String>,
    name: Option<String>,
}

fn type_ref_from_node(node: Node<'_>, source: &str) -> Option<TypeRef> {
    match node.kind() {
        "type_identifier" | "identifier" => Some(TypeRef {
            qualifier: None,
            name: Some(node_text(node, source).to_string()),
        }),
        "qualified_type" | "selector_expression" => {
            let (qualifier, field) = selector_parts(node, source)?;
            Some(TypeRef {
                qualifier: Some(qualifier),
                name: Some(node_text(field, source).to_string()),
            })
        }
        "pointer_type" | "slice_type" | "array_type" | "generic_type" | "parenthesized_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| type_ref_from_node(child, source))
        }
        _ => None,
    }
}

fn type_ref_from_captures(
    caps: &regex::Captures<'_>,
    qualifier: &str,
    name: &str,
) -> Option<TypeRef> {
    Some(TypeRef {
        qualifier: caps.name(qualifier).map(|m| m.as_str().to_string()),
        name: caps.name(name).map(|m| m.as_str().to_string()),
    })
}

fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(ctx.line_starts, start),
        end_line: find_line_index_for_offset(ctx.line_starts, end),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        range.start_line + 1,
        start,
        end,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(ctx.source, ctx.line_starts, start, end),
    ));
}

fn build_snippet(source: &str, line_starts: &[usize], start: usize, end: usize) -> String {
    let start_line = find_line_index_for_offset(line_starts, start);
    let end_line = find_line_index_for_offset(line_starts, end);
    let snippet_start_line = start_line.saturating_sub(SNIPPET_CONTEXT_LINES);
    let snippet_end_line = end_line + SNIPPET_CONTEXT_LINES + 1;

    let snippet_start = *line_starts.get(snippet_start_line).unwrap_or(&0);
    let snippet_end = line_starts
        .get(snippet_end_line)
        .copied()
        .unwrap_or(source.len());

    source[snippet_start..snippet_end].trim().to_string()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn is_definition_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "package_clause"
            | "import_spec"
            | "function_declaration"
            | "method_declaration"
            | "type_spec"
            | "type_alias"
            | "var_spec"
            | "const_spec"
            | "field_declaration"
            | "method_elem"
            | "parameter_declaration"
            | "short_var_declaration"
    ) && node
        .parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        .is_some_and(|name| {
            name.start_byte() == node.start_byte() && name.end_byte() == node.end_byte()
        })
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

static VAR_TYPED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bvar\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s+\*?(?:(?P<qualifier>[A-Za-z_][A-Za-z0-9_]*)\.)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    )
    .expect("valid Go typed var regex")
});
static CONSTRUCTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*&?\s*(?:(?P<qualifier>[A-Za-z_][A-Za-z0-9_]*)\.)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|\()",
    )
    .expect("valid Go constructed value regex")
});
static ALIAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*:=\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*)\b")
        .expect("valid Go alias regex")
});
