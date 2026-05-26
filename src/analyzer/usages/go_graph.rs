use crate::analyzer::common::{language_for_file, language_for_target};
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::graph_core::{ImportEdgeKind, ProjectUsageGraph};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{
    ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding, ImportKind, UsageHit,
};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language,
    MultiAnalyzer, ProjectFile, Range,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{
    compute_line_starts, find_line_index_for_offset, trimmed_snippet_around_range,
};
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, Mutex};
use tree_sitter::{Node, Parser, Tree};

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
        language_for_target(target) == Language::Go
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Go {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Go"),
                "GoUsageGraphStrategy",
            );
        }

        let Some(go) = resolve_go_analyzer(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose GoAnalyzer",
                ),
                "GoUsageGraphStrategy",
            );
        };

        let graph = build_go_graph(go, candidate_files, target.source());
        let target_spec = TargetSpec::new(go, &graph, target);
        if !target_spec.has_scan_seed() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("no graph seed resolved"),
                "GoUsageGraphStrategy",
            );
        }

        let scan_files = graph.scan_files(candidate_files, target, &target_spec);
        let hits = scan_files_for_target(analyzer, &graph, scan_files, &target_spec);
        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();

        if hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
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
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
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

fn build_go_graph(
    analyzer: &GoAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target_file: &ProjectFile,
) -> GoProjectGraph {
    let parser_language = tree_sitter_go::LANGUAGE.into();
    let mut parsed = HashMap::default();
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

    let mut exports_by_file = HashMap::default();
    let mut binders_by_file = HashMap::default();
    for file in &files {
        exports_by_file.insert(file.clone(), export_index_of(analyzer, file));
        binders_by_file.insert(
            file.clone(),
            import_binder_of(analyzer, file, &parsed, module_path.as_deref()),
        );
    }

    let usage_graph = ProjectUsageGraph::build(
        files,
        exports_by_file,
        &binders_by_file,
        |importer, module| resolve_go_module(importer, module, &parsed, module_path.as_deref()),
    );

    GoProjectGraph {
        parsed,
        usage_graph,
    }
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
    parsed: &HashMap<ProjectFile, ParsedFile>,
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
                        let resolved = resolve_go_module(file, &path, parsed, module_path);
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

fn resolve_go_module(
    _importer: &ProjectFile,
    module: &str,
    parsed: &HashMap<ProjectFile, ParsedFile>,
    module_path: Option<&str>,
) -> Vec<ProjectFile> {
    let local_rel = local_go_import_rel_path(module, module_path);
    let vendor_rel = format!("vendor/{}", module.trim_matches('/'));
    let mut resolved: Vec<_> = parsed
        .keys()
        .filter(|candidate| {
            let parent = candidate.parent().to_string_lossy().replace('\\', "/");
            parent == vendor_rel
                || local_rel
                    .as_ref()
                    .is_some_and(|rel| parent == *rel || (rel.is_empty() && parent.is_empty()))
        })
        .cloned()
        .collect();
    resolved.sort();
    resolved.dedup();
    resolved
}

fn read_go_module_path(root: &std::path::Path) -> Option<String> {
    let contents = std::fs::read_to_string(root.join("go.mod")).ok()?;
    contents.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("module ")
            .map(str::trim)
            .filter(|module| !module.is_empty())
            .map(str::to_string)
    })
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
        "var_declaration" | "short_var_declaration" => {
            declare_local_names(node, ctx, locals);
            seed_local_bindings(node, ctx, locals);
        }
        "assignment_statement" => {
            seed_local_bindings(node, ctx, locals);
        }
        "selector_expression" | "qualified_type" => {
            scan_selector_like(node, ctx, locals);
        }
        "identifier" | "type_identifier" => {
            scan_direct_identifier(node, ctx, locals);
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
    let parameter_names = parameter_names(node, ctx.source);
    let Some(type_node) = node.child_by_field_name("type") else {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    };
    if !type_ref_from_node(type_node, ctx.source)
        .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
    {
        for name in parameter_names {
            locals.declare_shadow(name);
        }
        return;
    }
    for name in parameter_names {
        locals.seed_symbol(name, OWNER_TOKEN.to_string());
    }
}

fn parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(child, source).to_string());
        }
    }
    out
}

fn declare_local_names(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    for name in declared_names(node, ctx.source) {
        locals.declare_shadow(name);
    }
}

fn seed_local_bindings(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "var_declaration" => {
            seed_typed_var_lines(node, ctx, locals);
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "var_spec" {
                    seed_var_spec(child, ctx, locals);
                }
            }
        }
        "var_spec" => seed_var_spec(node, ctx, locals),
        "short_var_declaration" | "assignment_statement" => seed_assignment_like(node, ctx, locals),
        _ => {}
    }
}

fn seed_typed_var_lines(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let text = node_text(node, ctx.source);
    for caps in VAR_TYPED_LIST_RE.captures_iter(text) {
        let ty = TypeRef {
            qualifier: caps.name("qualifier").map(|m| m.as_str().to_string()),
            name: caps.name("name").map(|m| m.as_str().to_string()),
        };
        if !ctx.bindings.matches_owner_type(&ty) {
            continue;
        }
        let Some(vars) = caps.name("vars") else {
            continue;
        };
        for name in vars
            .as_str()
            .split(',')
            .map(str::trim)
            .filter(|name| *name != "_" && IDENT_RE.is_match(name))
        {
            locals.seed_symbol(name.to_string(), OWNER_TOKEN.to_string());
        }
    }
}

fn declared_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "var_declaration" => {
            let mut out = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "var_spec" {
                    out.extend(declared_names(child, source));
                }
            }
            out
        }
        "var_spec" => var_spec_names(node, source),
        "short_var_declaration" => lhs_identifiers(node, source),
        _ => Vec::new(),
    }
}

fn seed_var_spec(node: Node<'_>, ctx: &ScanCtx<'_>, locals: &mut LocalInferenceEngine<String>) {
    let names = var_spec_names(node, ctx.source);
    if names.is_empty() {
        return;
    }

    if node
        .child_by_field_name("type")
        .and_then(|type_node| type_ref_from_node(type_node, ctx.source))
        .is_some_and(|ty| ctx.bindings.matches_owner_type(&ty))
    {
        for name in names {
            locals.seed_symbol(name, OWNER_TOKEN.to_string());
        }
        return;
    }

    seed_names_from_values(names, rhs_expressions(node), ctx, locals);
}

fn seed_assignment_like(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    seed_names_from_values(
        lhs_identifiers(node, ctx.source),
        rhs_expressions(node),
        ctx,
        locals,
    );
}

fn seed_names_from_values(
    names: Vec<String>,
    values: Vec<Node<'_>>,
    ctx: &ScanCtx<'_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    if names.is_empty() || values.is_empty() {
        return;
    }

    for (name, value) in names.iter().zip(values.iter()) {
        if expression_matches_owner_type(*value, ctx) {
            locals.seed_symbol(name.clone(), OWNER_TOKEN.to_string());
        } else if is_identifier_node(*value) {
            locals.alias_symbol(name.clone(), node_text(*value, ctx.source));
        }
    }
}

fn var_spec_names(node: Node<'_>, source: &str) -> Vec<String> {
    let boundary = node
        .child_by_field_name("type")
        .or_else(|| node.child_by_field_name("value"))
        .map(|child| child.start_byte())
        .unwrap_or(node.end_byte());
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= boundary {
            continue;
        }
        if is_identifier_node(child) {
            let name = node_text(child, source);
            if name != "_" {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn lhs_identifiers(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(left) = node
        .child_by_field_name("left")
        .or_else(|| first_named_child(node))
    else {
        return Vec::new();
    };
    identifiers_in_node(left, source)
        .into_iter()
        .filter(|name| name != "_")
        .collect()
}

fn rhs_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(right) = node
        .child_by_field_name("right")
        .or_else(|| last_named_child(node))
    else {
        return Vec::new();
    };
    if right.kind() == "expression_list" {
        let mut cursor = right.walk();
        let children: Vec<_> = right.named_children(&mut cursor).collect();
        if !children.is_empty() {
            return children;
        }
    }
    vec![right]
}

fn identifiers_in_node(node: Node<'_>, source: &str) -> Vec<String> {
    if is_identifier_node(node) {
        return vec![node_text(node, source).to_string()];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_identifier_node(child) {
            out.push(node_text(child, source).to_string());
        }
    }
    out
}

fn expression_matches_owner_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if type_ref_from_node(node, ctx.source).is_some_and(|ty| ctx.bindings.matches_owner_type(&ty)) {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| expression_matches_owner_type(child, ctx))
}

fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "package_identifier"
    )
}

fn scan_selector_like(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) {
    let Some((qualifier, qualifier_node, field_node)) = selector_parts(node, ctx.source) else {
        return;
    };
    let field = node_text(field_node, ctx.source);
    if field != ctx.spec.identifier {
        return;
    }

    if ctx.spec.is_member() {
        let receiver = receiver_symbol_from_qualifier(&qualifier);
        if locals
            .resolve_symbol(receiver)
            .as_precise()
            .is_some_and(|targets| targets.contains(OWNER_TOKEN))
        {
            record_hit(field_node, ctx);
        }
        return;
    }

    if ctx.bindings.namespace_names.contains(&qualifier)
        && !locals.is_shadowed(&qualifier)
        && !is_definition_identifier(qualifier_node, ctx.source)
    {
        record_hit(field_node, ctx);
    }
}

fn scan_direct_identifier(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    locals: &LocalInferenceEngine<String>,
) {
    if ctx.spec.is_member() || is_definition_identifier(node, ctx.source) {
        return;
    }
    let text = node_text(node, ctx.source);
    if ctx.bindings.matches_direct_target(text) && !locals.is_shadowed(text) {
        record_hit(node, ctx);
    }
}

fn selector_parts<'a>(node: Node<'a>, source: &str) -> Option<(String, Node<'a>, Node<'a>)> {
    let qualifier_node = node
        .child_by_field_name("operand")
        .or_else(|| node.child_by_field_name("package"))
        .or_else(|| first_named_child(node))?;
    let field_node = node
        .child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| last_named_child(node))?;
    Some((
        node_text(qualifier_node, source).to_string(),
        qualifier_node,
        field_node,
    ))
}

fn receiver_symbol_from_qualifier(qualifier: &str) -> &str {
    qualifier
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_start_matches(['*', '&'])
        .trim()
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
            let (qualifier, _qualifier_node, field) = selector_parts(node, source)?;
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
    ctx.hits.insert(usage_hit(
        ctx.file,
        range.start_line,
        start,
        end,
        enclosing,
        trimmed_snippet_around_range(
            ctx.source,
            ctx.line_starts,
            start,
            end,
            SNIPPET_CONTEXT_LINES,
        ),
    ));
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

fn is_definition_identifier(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if has_ancestor_kind(node, "literal_value") && next_non_whitespace_is_colon(node, source) {
        return true;
    }
    if parent.kind() == "keyed_element"
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| same_node(key, node))
    {
        return true;
    }
    if parent.kind() == "field_declaration"
        && parent.child_by_field_name("type").is_some_and(|ty| {
            node.start_byte() < ty.start_byte()
                && parent
                    .child_by_field_name("name")
                    .is_none_or(|name| same_node(name, node) || node.end_byte() <= ty.start_byte())
        })
    {
        return true;
    }
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

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn next_non_whitespace_is_colon(node: Node<'_>, source: &str) -> bool {
    source
        .get(node.end_byte()..)
        .and_then(|rest| rest.chars().find(|ch| !ch.is_whitespace()))
        == Some(':')
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

static VAR_TYPED_LIST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^\s*(?:var\s+)?(?P<vars>[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)\s+\*?(?:(?P<qualifier>[A-Za-z_][A-Za-z0-9_]*)\.)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    )
    .expect("valid Go typed var-list regex")
});
static IDENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid Go identifier regex"));
static VERSION_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.v\d+$").expect("valid Go module version suffix regex"));
