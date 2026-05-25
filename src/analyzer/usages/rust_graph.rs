use crate::analyzer::usages::graph_core::{ImportEdgeKind, ProjectUsageGraph};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{FuzzyResult, ReferenceGraphResult, UsageHit};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, Range,
    RustAnalyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, Mutex};
use tree_sitter::{Node, Parser, Tree};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct RustExportUsageGraphStrategy {
    _private: (),
}

impl RustExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Rust
    }

    pub fn find_export_usages(
        analyzer: &RustAnalyzer,
        defining_file: &ProjectFile,
        export_name: &str,
        query_target: Option<&CodeUnit>,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> ReferenceGraphResult {
        let external_frontier_specifiers =
            unresolved_external_frontier_specifiers(analyzer, defining_file, export_name);
        let hits = query_target
            .map(|target| {
                Self::new()
                    .find_usages(
                        analyzer,
                        std::slice::from_ref(target),
                        candidate_files,
                        max_usages,
                    )
                    .all_hits()
            })
            .unwrap_or_default();

        ReferenceGraphResult {
            hits,
            external_frontier_specifiers,
        }
    }
}

impl UsageAnalyzer for RustExportUsageGraphStrategy {
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
        if target_language(target) != Language::Rust {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "RustExportUsageGraphStrategy: target is not Rust".to_string(),
            };
        }

        let Some(rust) = resolve_rust_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "RustExportUsageGraphStrategy: analyzer does not expose RustAnalyzer"
                    .to_string(),
            };
        };

        let graph = build_rust_graph(rust);
        let seeds = infer_graph_seeds(rust, &graph, target);

        let hits = if seeds.is_empty() && supports_same_file_local_scan(rust, target) {
            scan_files_for_target(
                analyzer,
                &graph,
                [target.source().clone()].into_iter().collect(),
                target,
                None,
            )
        } else if seeds.is_empty() {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "RustExportUsageGraphStrategy: no export seed resolved".to_string(),
            };
        } else if is_member_target(rust, target) {
            if !is_graph_visible_member_target(rust, target) {
                return FuzzyResult::success(target.clone(), BTreeSet::new());
            }
            let scan_files = effective_scan_files(rust, &graph, candidate_files, target, &seeds);
            scan_files_for_member_target(analyzer, &graph, rust, scan_files, target, &seeds)
        } else {
            let scan_files = effective_scan_files(rust, &graph, candidate_files, target, &seeds);
            scan_files_for_target(analyzer, &graph, scan_files, target, Some(&seeds))
        };

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

fn resolve_rust_analyzer(analyzer: &dyn IAnalyzer) -> Option<&RustAnalyzer> {
    if let Some(rust) = (analyzer as &dyn std::any::Any).downcast_ref::<RustAnalyzer>() {
        return Some(rust);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Rust) {
        Some(AnalyzerDelegate::Rust(rust)) => Some(rust),
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

fn supports_same_file_local_scan(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    target.is_function() && analyzer.parent_of(target).is_none()
}

fn is_member_target(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    (target.is_function() || target.is_field()) && analyzer.parent_of(target).is_some()
}

fn is_trait_owner(rust: &RustAnalyzer, owner: &CodeUnit) -> bool {
    rust.get_source(owner, false)
        .or_else(|| rust.get_skeleton_header(owner))
        .map(|source| {
            let trimmed = source.trim_start();
            trimmed.starts_with("pub trait ") || trimmed.starts_with("trait ")
        })
        .unwrap_or(false)
}

fn is_public_like_declaration(rust: &RustAnalyzer, code_unit: &CodeUnit) -> bool {
    rust.get_source(code_unit, false)
        .or_else(|| rust.get_skeleton_header(code_unit))
        .map(|source| {
            let trimmed = source.trim_start();
            trimmed.starts_with("pub ")
                || trimmed.starts_with("pub(")
                || trimmed.starts_with("pub(crate)")
                || trimmed.starts_with("pub(in ")
        })
        .unwrap_or(false)
}

fn is_graph_visible_member_target(rust: &RustAnalyzer, target: &CodeUnit) -> bool {
    if is_public_like_declaration(rust, target) {
        return true;
    }

    let Some(owner) = rust.parent_of(target) else {
        return false;
    };
    if !is_public_like_declaration(rust, &owner) {
        return false;
    }

    let owner_source = rust
        .get_source(&owner, false)
        .or_else(|| rust.get_skeleton_header(&owner))
        .unwrap_or_default();
    let trimmed = owner_source.trim_start();

    (trimmed.starts_with("pub trait ") && target.is_function())
        || (trimmed.starts_with("pub enum ") && target.is_field())
}

fn infer_graph_seeds(
    analyzer: &RustAnalyzer,
    graph: &RustProjectGraph,
    target: &CodeUnit,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = BTreeSet::new();
    let nested_module_target = analyzer
        .parent_of(target)
        .is_some_and(|parent| parent.is_module());
    for seed_name in infer_export_names(analyzer, target) {
        let resolved = graph
            .usage_graph
            .seeds_for_target(target.source(), &seed_name);
        if resolved.is_empty() && nested_module_target {
            seeds.insert((target.source().clone(), seed_name));
        } else {
            seeds.extend(resolved);
        }
    }

    if seeds.is_empty()
        && let Some(parent) = analyzer.parent_of(target)
        && parent.is_module()
        && parent.source() != target.source()
        && is_public_like_declaration(analyzer, target)
    {
        let parent_index = analyzer.export_index_of(parent.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            seeds.insert((parent.source().clone(), target.identifier().to_string()));
        }
    }

    seeds
}

fn infer_export_names(analyzer: &RustAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if (target.is_function() || target.is_field())
        && let Some(owner) = analyzer.parent_of(target)
    {
        let owner_exports =
            infer_export_names_for_local(analyzer, owner.source(), owner.identifier());
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    let mut export_names =
        infer_export_names_for_local(analyzer, target.source(), target.identifier());
    if !export_names.is_empty() {
        return export_names;
    }

    if let Some(owner) = analyzer.parent_of(target)
        && owner.is_module()
        && owner.source() != target.source()
    {
        let parent_index = analyzer.export_index_of(owner.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            export_names.insert(target.identifier().to_string());
        }
    }

    if target.is_function() && analyzer.parent_of(target).is_none() {
        return [target.identifier().to_string()].into_iter().collect();
    }

    BTreeSet::new()
}

fn infer_export_names_for_local(
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    local_name: &str,
) -> BTreeSet<String> {
    let index = analyzer.export_index_of(file);
    let mut export_names = BTreeSet::new();
    if index.exports_by_name.contains_key(local_name) {
        export_names.insert(local_name.to_string());
    }
    for (export_name, entry) in index.exports_by_name {
        if matches!(entry, crate::analyzer::usages::ExportEntry::Local { local_name: ref name } if name == local_name)
        {
            export_names.insert(export_name);
        }
    }
    export_names
}

fn unresolved_external_frontier_specifiers(
    analyzer: &RustAnalyzer,
    defining_file: &ProjectFile,
    export_name: &str,
) -> BTreeSet<String> {
    let mut frontier = BTreeSet::new();
    let index = analyzer.export_index_of(defining_file);

    if let Some(crate::analyzer::usages::ExportEntry::ReexportedNamed {
        module_specifier, ..
    }) = index.exports_by_name.get(export_name)
        && analyzer
            .resolve_module_files(defining_file, module_specifier)
            .is_empty()
        && let Some(external) = external_frontier_specifier(module_specifier)
    {
        frontier.insert(external);
    }

    for star in &index.reexport_stars {
        if analyzer
            .resolve_module_files(defining_file, &star.module_specifier)
            .is_empty()
            && let Some(external) = external_frontier_specifier(&star.module_specifier)
        {
            frontier.insert(external);
        }
    }

    frontier
}

fn external_frontier_specifier(module_specifier: &str) -> Option<String> {
    let root = module_specifier
        .split("::")
        .find(|segment| !segment.is_empty())?
        .trim();
    (!matches!(root, "crate" | "self" | "super") && !root.is_empty()).then(|| root.to_string())
}

struct ParsedFile {
    source: Arc<String>,
    tree: Tree,
}

struct RustProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
    usage_graph: ProjectUsageGraph,
}

fn build_rust_graph(analyzer: &RustAnalyzer) -> RustProjectGraph {
    let files: Vec<_> = analyzer.get_analyzed_files().into_iter().collect();
    let parsed_files: Vec<_> = files
        .par_iter()
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            let exports = analyzer.export_index_of(file);
            let binder = analyzer.import_binder_of(file);
            Some((
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                },
                exports,
                binder,
            ))
        })
        .collect();

    let mut parsed = HashMap::default();
    let mut exports_by_file = HashMap::default();
    let mut binders_by_file = HashMap::default();

    for (file, parsed_file, exports, binder) in parsed_files {
        parsed.insert(file.clone(), parsed_file);
        exports_by_file.insert(file.clone(), exports);
        binders_by_file.insert(file, binder);
    }

    let usage_graph = ProjectUsageGraph::build(
        files,
        exports_by_file,
        &binders_by_file,
        |file, module_specifier| analyzer.resolve_module_files(file, module_specifier),
    );

    RustProjectGraph {
        parsed,
        usage_graph,
    }
}

fn effective_scan_files(
    analyzer: &RustAnalyzer,
    graph: &RustProjectGraph,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> HashSet<ProjectFile> {
    let analyzed = analyzer.get_analyzed_files();
    let filtered_candidates: HashSet<_> = candidate_files
        .iter()
        .filter(|file| analyzed.contains(*file))
        .cloned()
        .collect();

    if !candidate_files.is_empty() && filtered_candidates.is_empty() {
        return [target.source().clone()].into_iter().collect();
    }

    if !filtered_candidates.is_empty() {
        return filtered_candidates;
    }

    graph
        .usage_graph
        .importers_of_seeds(seeds)
        .into_iter()
        .chain(std::iter::once(target.source().clone()))
        .collect()
}

fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    graph: &RustProjectGraph,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: Option<&BTreeSet<(ProjectFile, String)>>,
) -> BTreeSet<UsageHit> {
    let target_short = target.identifier().to_string();
    let parser_language = tree_sitter_rust::LANGUAGE.into();
    let hits = Mutex::new(BTreeSet::new());
    let files_vec: Vec<_> = files.into_iter().collect();

    files_vec.par_iter().for_each(|file| {
        let owned_source: Option<Arc<String>>;
        let owned_tree: Option<Tree>;
        let (source, tree) = if let Some(parsed) = graph.parsed.get(file) {
            (parsed.source.as_str(), &parsed.tree)
        } else {
            let Ok(source) = file.read_to_string() else {
                return;
            };
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
                owned_source.as_deref().expect("owned source").as_str(),
                owned_tree.as_ref().expect("owned tree"),
            )
        };

        let line_starts = compute_line_starts(source);
        let (direct_names, namespace_names) = match seeds {
            Some(seeds) => graph
                .usage_graph
                .matching_edges_for_importer(file, seeds)
                .into_iter()
                .fold(
                    (HashSet::default(), HashSet::default()),
                    |(mut direct, mut namespaces), edge| {
                        match edge.kind {
                            ImportEdgeKind::Namespace => {
                                namespaces.insert(edge.local_name);
                            }
                            ImportEdgeKind::Named(_) | ImportEdgeKind::Default => {
                                direct.insert(edge.local_name);
                            }
                        }
                        (direct, namespaces)
                    },
                ),
            None => (HashSet::default(), HashSet::default()),
        };
        let target_self_file = file == target.source();

        let mut local_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            direct_names: &direct_names,
            namespace_names: &namespace_names,
            shadowed_names: detect_shadowed_names(
                source,
                &direct_names,
                &namespace_names,
                &target_short,
                target_self_file,
            ),
            target_self_file,
            hits: &mut local_hits,
        };
        scan_node(tree.root_node(), &mut ctx);
        record_module_qualified_hits(&mut ctx);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust graph collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Rust graph collector")
}

struct ScanCtx<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    analyzer: &'a dyn IAnalyzer,
    target_short: &'a str,
    direct_names: &'a HashSet<String>,
    namespace_names: &'a HashSet<String>,
    shadowed_names: HashSet<String>,
    target_self_file: bool,
    hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn matches_identifier(&self, text: &str) -> bool {
        (self.direct_names.contains(text) && !self.shadowed_names.contains(text))
            || (self.target_self_file
                && text == self.target_short
                && !self.shadowed_names.contains(text))
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "use_declaration" => return,
        "identifier" | "type_identifier" => {
            let text = node
                .utf8_text(ctx.source.as_bytes())
                .ok()
                .map(str::trim)
                .unwrap_or_default();
            if ctx.matches_identifier(text) && !is_shadowed_identifier(text, node, ctx) {
                record_hit(node, ctx);
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
    }
}

fn is_shadowed_identifier(text: &str, node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.shadowed_names.contains(text) {
        return true;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    ctx.analyzer
        .find_nearest_declaration(ctx.file, start, end, text)
        .is_some_and(|decl| {
            decl.identifier == text
                && (decl.range.start_byte != start || decl.range.end_byte != end)
        })
}

fn detect_shadowed_names(
    source: &str,
    direct_names: &HashSet<String>,
    namespace_names: &HashSet<String>,
    target_short: &str,
    target_self_file: bool,
) -> HashSet<String> {
    let mut names = direct_names.clone();
    names.extend(namespace_names.iter().cloned());
    if target_self_file {
        names.insert(target_short.to_string());
    }

    names
        .into_iter()
        .filter(|name| {
            let ident = regex::escape(name);
            let patterns = if target_self_file && name == target_short {
                vec![format!(r"\blet\s+{}\b", ident)]
            } else {
                vec![
                    format!(r"\blet\s+{}\b", ident),
                    format!(r"\bstruct\s+{}\b", ident),
                    format!(r"\benum\s+{}\b", ident),
                    format!(r"\btype\s+{}\b", ident),
                    format!(r"\bfn\s+{}\b", ident),
                ]
            };
            patterns.iter().any(|pattern| {
                Regex::new(pattern)
                    .ok()
                    .is_some_and(|re| re.is_match(source))
            })
        })
        .collect()
}

fn record_module_qualified_hits(ctx: &mut ScanCtx<'_>) {
    for name in ctx.namespace_names {
        if ctx.shadowed_names.contains(name) {
            continue;
        }
        let pattern = format!(
            r"\b{}\s*::\s*{}\b",
            regex::escape(name),
            regex::escape(ctx.target_short)
        );
        let Ok(re) = Regex::new(&pattern) else {
            continue;
        };
        for matched in re.find_iter(ctx.source) {
            let matched_text = matched.as_str();
            let Some(local_offset) = matched_text.rfind(ctx.target_short) else {
                continue;
            };
            let start = matched.start() + local_offset;
            let end = start + ctx.target_short.len();
            let range = Range {
                start_byte: start,
                end_byte: end,
                start_line: find_line_index_for_offset(ctx.line_starts, start),
                end_line: find_line_index_for_offset(ctx.line_starts, end),
            };
            let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
                continue;
            };
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
    }
}

fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start_line = find_line_index_for_offset(ctx.line_starts, node.start_byte());
    let end_line = find_line_index_for_offset(ctx.line_starts, node.end_byte());
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line,
        end_line,
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        start_line + 1,
        node.start_byte(),
        node.end_byte(),
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(
            ctx.source,
            ctx.line_starts,
            node.start_byte(),
            node.end_byte(),
        ),
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

static LET_TYPED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid typed let regex")
});
static LET_CONSTRUCTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)(?:::\s*([A-Za-z_][A-Za-z0-9_]*))?\s*(?:\{|\(|\.)",
    )
        .expect("valid constructed let regex")
});
static LET_ALIAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")
        .expect("valid alias let regex")
});
static PARAM_TYPED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid typed param regex")
});
static TYPE_ALIAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")
        .expect("valid type alias regex")
});
static OPTION_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*Option<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>")
        .expect("valid option field regex")
});
static SELF_FIELD_AS_REF_LET_ELSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\blet\s+Some\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*self\.([A-Za-z_][A-Za-z0-9_]*)\.as_ref\(\)\s*else",
    )
    .expect("valid self field as_ref let-else regex")
});

fn scan_files_for_member_target(
    analyzer: &dyn IAnalyzer,
    graph: &RustProjectGraph,
    rust: &RustAnalyzer,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageHit> {
    let Some(owner) = rust.parent_of(target) else {
        return BTreeSet::new();
    };
    let member_name = regex::escape(target.identifier());
    let hits = Mutex::new(BTreeSet::new());

    files.par_iter().for_each(|file| {
        let Ok(source) = file.read_to_string() else {
            return;
        };
        let line_starts = compute_line_starts(&source);
        let owner_local_names: HashSet<String> = if file == target.source() {
            [owner.identifier().to_string()].into_iter().collect()
        } else {
            graph
                .usage_graph
                .matching_edges_for_importer(file, seeds)
                .into_iter()
                .map(|edge| edge.local_name)
                .collect()
        };
        let trait_owner = is_trait_owner(rust, &owner);
        let receiver_type_names = if trait_owner {
            rust.trait_implementer_names(&owner, file)
        } else {
            owner_local_names.clone()
        };
        if owner_local_names.is_empty() && receiver_type_names.is_empty() {
            return;
        }
        let self_like_constructors = self_like_constructor_names(rust, &owner);
        let receiver_names =
            infer_receiver_names(&source, &receiver_type_names, &self_like_constructors);
        let static_owner_names: Vec<_> = owner_local_names
            .iter()
            .map(|name| regex::escape(name))
            .collect();
        if receiver_names.is_empty() && static_owner_names.is_empty() {
            return;
        }

        let call_re = if receiver_names.is_empty() {
            None
        } else {
            let pattern = format!(r"\b({})\.{}\s*\(", receiver_names.join("|"), member_name);
            Regex::new(&pattern).ok()
        };
        let static_pattern = format!(r"\b({})::{}\b", static_owner_names.join("|"), member_name);
        let static_re = Regex::new(&static_pattern).ok();

        let mut local_hits = BTreeSet::new();
        if let Some(call_re) = call_re {
            for captures in call_re.captures_iter(&source) {
                let Some(matched) = captures.get(0) else {
                    continue;
                };
                let Some(receiver_name) = captures.get(1).map(|receiver| receiver.as_str()) else {
                    continue;
                };
                let start = matched.end().saturating_sub(target.identifier().len() + 1);
                let end = matched.end().saturating_sub(1);
                let range = Range {
                    start_byte: start,
                    end_byte: end,
                    start_line: find_line_index_for_offset(&line_starts, start),
                    end_line: find_line_index_for_offset(&line_starts, end),
                };
                let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) else {
                    continue;
                };
                let receiver_mismatched = analyzer
                    .get_source(&enclosing, false)
                    .map(|enclosing_source| {
                        receiver_explicitly_mismatched(
                            &source,
                            &enclosing_source,
                            &receiver_type_names,
                            receiver_name,
                        )
                    })
                    .unwrap_or(false);
                if receiver_mismatched {
                    continue;
                }
                local_hits.insert(UsageHit::new(
                    file.clone(),
                    range.start_line + 1,
                    start,
                    end,
                    enclosing,
                    GRAPH_HIT_CONFIDENCE,
                    build_snippet(&source, &line_starts, start, end),
                ));
            }
        }
        if let Some(static_re) = static_re {
            for matched in static_re.find_iter(&source) {
                let start = matched.end().saturating_sub(target.identifier().len());
                let end = matched.end();
                let range = Range {
                    start_byte: start,
                    end_byte: end,
                    start_line: find_line_index_for_offset(&line_starts, start),
                    end_line: find_line_index_for_offset(&line_starts, end),
                };
                let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) else {
                    continue;
                };
                local_hits.insert(UsageHit::new(
                    file.clone(),
                    range.start_line + 1,
                    start,
                    end,
                    enclosing,
                    GRAPH_HIT_CONFIDENCE,
                    build_snippet(&source, &line_starts, start, end),
                ));
            }
        }

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust member collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Rust member collector")
}

fn self_like_constructor_names(rust: &RustAnalyzer, owner: &CodeUnit) -> HashSet<String> {
    rust.get_all_declarations()
        .into_iter()
        .filter(|code_unit| code_unit.source() == owner.source())
        .filter(|code_unit| code_unit.is_function())
        .filter(|code_unit| {
            rust.parent_of(code_unit)
                .map(|parent| parent == *owner)
                .unwrap_or(false)
        })
        .filter_map(|code_unit| {
            let source = rust.get_source(&code_unit, false)?;
            let (_, return_ty) = source.split_once("->")?;
            let normalized: String = return_ty.chars().filter(|ch| !ch.is_whitespace()).collect();
            (normalized.contains("Self")
                || normalized.contains(owner.identifier())
                || normalized.contains("Result<Self")
                || normalized.contains(&format!("Result<{}", owner.identifier())))
            .then(|| code_unit.identifier().to_string())
        })
        .collect()
}

fn expanded_receiver_type_names(
    source: &str,
    owner_local_names: &HashSet<String>,
) -> HashSet<String> {
    let mut owner_type_names = owner_local_names.clone();

    loop {
        let mut changed = false;
        for captures in TYPE_ALIAS_RE.captures_iter(source) {
            let Some(alias) = captures.get(1) else {
                continue;
            };
            let Some(target) = captures.get(2) else {
                continue;
            };
            if owner_type_names.contains(target.as_str())
                && owner_type_names.insert(alias.as_str().to_string())
            {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    owner_type_names
}

fn receiver_explicitly_mismatched(
    file_source: &str,
    enclosing_source: &str,
    owner_local_names: &HashSet<String>,
    receiver_name: &str,
) -> bool {
    let owner_type_names = expanded_receiver_type_names(file_source, owner_local_names);

    for captures in PARAM_TYPED_RE.captures_iter(enclosing_source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if name.as_str() == receiver_name {
            return !owner_type_names.contains(ty.as_str());
        }
    }

    for captures in LET_TYPED_RE.captures_iter(enclosing_source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if name.as_str() == receiver_name {
            return !owner_type_names.contains(ty.as_str());
        }
    }

    false
}

fn infer_receiver_names(
    source: &str,
    owner_local_names: &HashSet<String>,
    self_like_constructors: &HashSet<String>,
) -> Vec<String> {
    let owner_type_names = expanded_receiver_type_names(source, owner_local_names);
    let bindings = collect_receiver_bindings(source, &owner_type_names, self_like_constructors);
    let mut receivers: Vec<_> = bindings
        .snapshot()
        .matching_symbols(|target| owner_type_names.contains(target))
        .into_iter()
        .collect();
    receivers.sort();
    receivers
}

fn collect_receiver_bindings(
    source: &str,
    owner_type_names: &HashSet<String>,
    self_like_constructors: &HashSet<String>,
) -> LocalInferenceEngine<String> {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());

    let option_field_types: HashMap<String, String> = OPTION_FIELD_RE
        .captures_iter(source)
        .filter_map(|captures| {
            Some((
                captures.get(1)?.as_str().to_string(),
                captures.get(2)?.as_str().to_string(),
            ))
        })
        .collect();

    for captures in LET_TYPED_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if owner_type_names.contains(ty.as_str()) {
            engine.seed_symbol(name.as_str().to_string(), ty.as_str().to_string());
        }
    }

    for captures in LET_CONSTRUCTED_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        let constructor_name = captures.get(3).map(|name| name.as_str());
        let allowed_constructor =
            constructor_name.is_none_or(|name| self_like_constructors.contains(name));
        if owner_type_names.contains(ty.as_str()) && allowed_constructor {
            engine.seed_symbol(name.as_str().to_string(), ty.as_str().to_string());
        }
    }

    for captures in PARAM_TYPED_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if owner_type_names.contains(ty.as_str()) {
            engine.seed_symbol(name.as_str().to_string(), ty.as_str().to_string());
        }
    }

    for captures in SELF_FIELD_AS_REF_LET_ELSE_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(field_name) = captures.get(2) else {
            continue;
        };
        if option_field_types
            .get(field_name.as_str())
            .is_some_and(|ty| owner_type_names.contains(ty))
            && let Some(ty) = option_field_types.get(field_name.as_str())
        {
            engine.seed_symbol(name.as_str().to_string(), ty.clone());
        }
    }

    let aliases: Vec<_> = LET_ALIAS_RE
        .captures_iter(source)
        .filter_map(|captures| {
            Some((
                captures.get(1)?.as_str().to_string(),
                captures.get(2)?.as_str().to_string(),
            ))
        })
        .collect();
    engine.apply_aliases_until_stable(aliases);

    engine
}
