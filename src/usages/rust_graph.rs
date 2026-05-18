use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, Range,
    RustAnalyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::graph_core::ProjectUsageGraph;
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
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

fn infer_graph_seeds(
    analyzer: &RustAnalyzer,
    graph: &RustProjectGraph,
    target: &CodeUnit,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = BTreeSet::new();
    for seed_name in infer_export_names(analyzer, target) {
        seeds.extend(
            graph
                .usage_graph
                .seeds_for_target(target.source(), &seed_name),
        );
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

    let export_names = infer_export_names_for_local(analyzer, target.source(), target.identifier());
    if !export_names.is_empty() {
        return export_names;
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
        if matches!(entry, crate::usages::ExportEntry::Local { local_name: ref name } if name == local_name)
        {
            export_names.insert(export_name);
        }
    }
    export_names
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
        let local_names: HashSet<String> = match seeds {
            Some(seeds) => graph
                .usage_graph
                .matching_edges_for_importer(file, seeds)
                .into_iter()
                .map(|edge| edge.local_name)
                .collect(),
            None => HashSet::default(),
        };
        let target_self_file = file == target.source();

        let mut local_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            bound_names: &local_names,
            target_self_file,
            hits: &mut local_hits,
        };
        scan_node(tree.root_node(), &mut ctx);

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
    bound_names: &'a HashSet<String>,
    target_self_file: bool,
    hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn matches_identifier(&self, text: &str) -> bool {
        self.bound_names.contains(text) || (self.target_self_file && text == self.target_short)
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
            if ctx.matches_identifier(text) {
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
    Regex::new(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|::)")
        .expect("valid constructed let regex")
});
static PARAM_TYPED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid typed param regex")
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
        if owner_local_names.is_empty() {
            return;
        }

        let receiver_names = infer_receiver_names(&source, &owner_local_names);
        if receiver_names.is_empty() {
            return;
        }

        let pattern = format!(r"\b({})\.{}\s*\(", receiver_names.join("|"), member_name);
        let Ok(call_re) = Regex::new(&pattern) else {
            return;
        };

        let mut local_hits = BTreeSet::new();
        for captures in call_re.captures_iter(&source) {
            let Some(matched) = captures.get(0) else {
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

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust member collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Rust member collector")
}

fn infer_receiver_names(source: &str, owner_local_names: &HashSet<String>) -> Vec<String> {
    let mut receivers = BTreeSet::new();

    for captures in LET_TYPED_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if owner_local_names.contains(ty.as_str()) {
            receivers.insert(name.as_str().to_string());
        }
    }

    for captures in LET_CONSTRUCTED_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if owner_local_names.contains(ty.as_str()) {
            receivers.insert(name.as_str().to_string());
        }
    }

    for captures in PARAM_TYPED_RE.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let Some(ty) = captures.get(2) else {
            continue;
        };
        if owner_local_names.contains(ty.as_str()) {
            receivers.insert(name.as_str().to_string());
        }
    }

    receivers.into_iter().collect()
}
