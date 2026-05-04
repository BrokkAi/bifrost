//! JS/TS export-usage reference graph (Phase 7 of the usages port).
//!
//! Mirrors brokk's `JsTsExportUsageReferenceGraph` and `JsTsExportUsageExtractor`. Where
//! brokk's pipeline drives the JDT/LLM disambiguator, bifrost is tree-sitter only — the
//! graph here resolves on syntax + import binders alone, and falls back to the regex
//! analyzer when it cannot infer a seed.
//!
//! Pipeline overview:
//! 1. Per-file [`ExportIndex`]: tree-sitter walk that captures local exports, named
//!    re-exports, star re-exports, default exports, class members, and heritage edges.
//! 2. Per-file [`ImportBinder`]: extracts default/named/namespace import bindings.
//! 3. Project indices (lazy, cached on the strategy):
//!    - reverse re-export index: `(target_file, exported_name) -> {(reexporting_file, alias)}`
//!    - reverse export-seed index: `(short_name) -> {(file, exported_name)}` for fast seed
//!      inference from a target's identifier.
//!    - heritage index: child class name -> resolved parent code unit.
//! 4. Reference traversal: for the target's seed exports, walk the import-reverse index to
//!    find files that bind a local name to the export, then AST-scan those files for
//!    identifier / member / type / heritage references that resolve back to the target.
//!
//! Compared with brokk's Java implementation this port keeps the structural shape but
//! deliberately simplifies several edge cases (alias chains across deep re-export trees,
//! TS namespace member resolution beyond one hop, ambiguous JSX intrinsic filtering). The
//! strategy is conservative: when it cannot confidently resolve a candidate it reports
//! [`FuzzyResult::Failure`] so [`UsageFinder`](super::UsageFinder) falls back to the regex
//! analyzer and the user still sees results.

use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::model::{
    ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding, ImportKind, UsageHit,
};
use crate::usages::traits::UsageAnalyzer;
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use tree_sitter::{Node, Parser, Tree};

/// Graph-strategy hits land at the maximum confidence the regex analyzer also uses.
const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
/// Lines of context to include before/after a match in [`UsageHit::snippet`].
const SNIPPET_CONTEXT_LINES: usize = 3;

// ===================================================================================
// Strategy
// ===================================================================================

/// JS/TS export-graph usage analyzer. Resolves usages of a JavaScript or TypeScript
/// `CodeUnit` by walking the export/import graph rather than scanning text.
///
/// Wraps an inner fallback (`fallback`) that the strategy delegates to whenever it
/// cannot infer a seed (target language is non-JS/TS, target file isn't analyzable, no
/// local exports match the target identifier, etc.). The fallback is typically the
/// [`RegexUsageAnalyzer`](super::RegexUsageAnalyzer).
pub struct JsTsExportUsageGraphStrategy {
    fallback: Box<dyn UsageAnalyzer>,
    indices: OnceLock<ProjectGraph>,
}

impl JsTsExportUsageGraphStrategy {
    pub fn new<A: UsageAnalyzer + 'static>(fallback: A) -> Self {
        Self {
            fallback: Box::new(fallback),
            indices: OnceLock::new(),
        }
    }

    /// Returns true when the target is a JavaScript or TypeScript code unit and lives in
    /// a file the graph can analyze.
    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) != Language::None
    }
}

impl UsageAnalyzer for JsTsExportUsageGraphStrategy {
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
        let language = target_language(target);
        if language == Language::None {
            return self
                .fallback
                .find_usages(analyzer, overloads, candidate_files, max_usages);
        }

        let graph = self
            .indices
            .get_or_init(|| ProjectGraph::build(analyzer, language));

        let seeds = graph.seeds_for_target(target);
        if seeds.is_empty() {
            return self
                .fallback
                .find_usages(analyzer, overloads, candidate_files, max_usages);
        }

        let importers = graph.importers_of_seeds(&seeds);
        let scan_files: HashSet<ProjectFile> =
            candidate_files.iter().cloned().chain(importers).collect();

        let hits = scan_files_for_seeds(analyzer, graph, &scan_files, target, &seeds);
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

fn target_language(target: &CodeUnit) -> Language {
    target
        .source()
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .filter(|lang| matches!(lang, Language::JavaScript | Language::TypeScript))
        .unwrap_or(Language::None)
}

// ===================================================================================
// Project-wide graph indices
// ===================================================================================

/// Project-wide indices computed once per [`JsTsExportUsageGraphStrategy`] invocation.
struct ProjectGraph {
    /// Files we've actually analyzed (JS or TS depending on the target language).
    files: Vec<ProjectFile>,
    /// Per-file export index, keyed by file.
    exports_by_file: HashMap<ProjectFile, ExportIndex>,
    /// Reverse re-export edges: for each `(target_file, exported_name)` find every
    /// `(reexporting_file, exposed_alias)` that re-exports it.
    reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    /// Star re-exports: `target_file -> {reexporting_file}`.
    star_reexports: HashMap<ProjectFile, Vec<ProjectFile>>,
    /// Reverse seed index: `short_name -> Vec<(defining_file, exported_name)>`. Used to
    /// pick the seed exports for an arbitrary target without scanning every export
    /// table.
    seed_index: HashMap<String, Vec<(ProjectFile, String)>>,
    /// Importer reverse index: `target_file -> edges`. Each edge captures one binding
    /// in an importing file that resolves back to `target_file`.
    importer_reverse: HashMap<ProjectFile, Vec<ImportEdge>>,
}

#[derive(Debug, Clone)]
struct ImportEdge {
    /// File where the import is declared.
    importer: ProjectFile,
    /// Local binding name created by the import.
    local_name: String,
    /// Resolved target file (after path resolution).
    target_file: ProjectFile,
    /// What was imported: a specific exported name, the default export, or "*"/wildcard.
    kind: ImportEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ImportEdgeKind {
    Named(String),
    Default,
    Namespace,
}

impl ProjectGraph {
    fn build(analyzer: &dyn IAnalyzer, language: Language) -> Self {
        let files = collect_jsts_files(analyzer, language);
        let parser_language = match language {
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            _ => return ProjectGraph::empty(),
        };

        let parsed: Vec<(ProjectFile, ExportIndex, ImportBinder)> = files
            .par_iter()
            .filter_map(|file| {
                let source = file.read_to_string().ok()?;
                let mut parser = Parser::new();
                parser.set_language(&parser_language).ok()?;
                let tree = parser.parse(source.as_str(), None)?;
                let exports = compute_export_index(file, &source, &tree);
                let binder = compute_import_binder(&source, &tree);
                Some((file.clone(), exports, binder))
            })
            .collect();

        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> =
            map_with_capacity(parsed.len());
        let mut binders_by_file: HashMap<ProjectFile, ImportBinder> =
            map_with_capacity(parsed.len());

        for (file, exports, binder) in parsed.into_iter() {
            exports_by_file.insert(file.clone(), exports);
            binders_by_file.insert(file, binder);
        }

        let mut reexport_edges: HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>> =
            HashMap::default();
        let mut star_reexports: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
        let mut seed_index: HashMap<String, Vec<(ProjectFile, String)>> = HashMap::default();

        let files_vec: Vec<ProjectFile> = files.to_vec();

        for (file, exports) in &exports_by_file {
            for (exported_name, entry) in &exports.exports_by_name {
                let local = match entry {
                    ExportEntry::Local { local_name } => Some(local_name.clone()),
                    ExportEntry::Default { local_name } => local_name.clone(),
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => {
                        let resolved = resolve_module_specifier(file, module_specifier, language);
                        for resolved_file in resolved {
                            reexport_edges
                                .entry((resolved_file, imported_name.clone()))
                                .or_default()
                                .push((file.clone(), exported_name.clone()));
                        }
                        None
                    }
                };
                if let Some(local_name) = local {
                    seed_index
                        .entry(local_name.clone())
                        .or_default()
                        .push((file.clone(), exported_name.clone()));
                    if local_name != *exported_name {
                        seed_index
                            .entry(exported_name.clone())
                            .or_default()
                            .push((file.clone(), exported_name.clone()));
                    }
                } else {
                    seed_index
                        .entry(exported_name.clone())
                        .or_default()
                        .push((file.clone(), exported_name.clone()));
                }
            }
            for star in &exports.reexport_stars {
                let resolved = resolve_module_specifier(file, &star.module_specifier, language);
                for resolved_file in resolved {
                    star_reexports
                        .entry(resolved_file)
                        .or_default()
                        .push(file.clone());
                }
            }
        }

        let importer_reverse = build_importer_reverse(&files_vec, &binders_by_file, language);

        Self {
            files: files_vec,
            exports_by_file,
            reexport_edges,
            star_reexports,
            seed_index,
            importer_reverse,
        }
    }

    fn empty() -> Self {
        Self {
            files: Vec::new(),
            exports_by_file: HashMap::default(),
            reexport_edges: HashMap::default(),
            star_reexports: HashMap::default(),
            seed_index: HashMap::default(),
            importer_reverse: HashMap::default(),
        }
    }

    /// All `(file, exported_name)` seed exports that resolve to the target's identity.
    /// Includes the direct export(s) at the target's source file plus any transitive
    /// re-exports reachable via the re-export graph.
    fn seeds_for_target(&self, target: &CodeUnit) -> BTreeSet<(ProjectFile, String)> {
        let mut seeds: BTreeSet<(ProjectFile, String)> = BTreeSet::new();

        let target_short = top_level_identifier(target);

        // Direct seeds: every export entry in the target's defining file whose local name
        // matches the target's short identifier.
        if let Some(exports) = self.exports_by_file.get(target.source()) {
            for (exported_name, entry) in &exports.exports_by_name {
                let local = match entry {
                    ExportEntry::Local { local_name } => Some(local_name.as_str()),
                    ExportEntry::Default { local_name } => local_name.as_deref(),
                    ExportEntry::ReexportedNamed { .. } => None,
                };
                if let Some(local_name) = local
                    && local_name == target_short
                {
                    seeds.insert((target.source().clone(), exported_name.clone()));
                }
            }
        }

        // Augment via the seed index: any file that exports the same short name. This
        // catches default exports of `target_short` as well as re-export aliases.
        if let Some(matches) = self.seed_index.get(target_short) {
            for (file, exported_name) in matches {
                seeds.insert((file.clone(), exported_name.clone()));
            }
        }

        // Transitive re-export expansion: BFS over reexport_edges so importers who only
        // see the alias resolve back to the original target.
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

    /// Files that import any of the supplied seeds (after re-export resolution).
    fn importers_of_seeds(&self, seeds: &BTreeSet<(ProjectFile, String)>) -> HashSet<ProjectFile> {
        let mut out: HashSet<ProjectFile> = set_with_capacity(self.files.len().min(64));
        for (target_file, _) in seeds {
            if let Some(edges) = self.importer_reverse.get(target_file) {
                for edge in edges {
                    out.insert(edge.importer.clone());
                }
            }
            // Also keep the target file itself — usages within the same file count.
            out.insert(target_file.clone());
        }
        out
    }

    /// Returns the import edges originating in `importer` whose resolved
    /// `(target_file, kind)` matches one of the seeds.
    fn matching_edges_for_importer(
        &self,
        importer: &ProjectFile,
        seeds: &BTreeSet<(ProjectFile, String)>,
    ) -> Vec<ImportEdge> {
        let Some(edges) = self.importer_reverse.get(importer) else {
            return Vec::new();
        };
        edges
            .iter()
            .filter(|edge| edge_matches_seed(edge, seeds, self))
            .cloned()
            .collect()
    }
}

fn edge_matches_seed(
    edge: &ImportEdge,
    seeds: &BTreeSet<(ProjectFile, String)>,
    graph: &ProjectGraph,
) -> bool {
    match &edge.kind {
        ImportEdgeKind::Named(name) => seeds.contains(&(edge.target_file.clone(), name.clone())),
        ImportEdgeKind::Default => {
            seeds.contains(&(edge.target_file.clone(), "default".to_string()))
        }
        ImportEdgeKind::Namespace => {
            // Namespace import binds the entire module — match if any seed lives in the
            // target file. Member-level resolution is handled by the candidate scanner.
            seeds.iter().any(|(file, _)| file == &edge.target_file) || {
                let _ = graph;
                false
            }
        }
    }
}

fn collect_jsts_files(analyzer: &dyn IAnalyzer, language: Language) -> Vec<ProjectFile> {
    let mut result: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(language)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
    // Cross-language workspaces also analyze JSX as JS and TSX as TS — extension list is
    // already handled by `analyzable_files`, no additional widening required.
    result.sort();
    result.dedup();
    result
}

fn build_importer_reverse(
    files: &[ProjectFile],
    binders_by_file: &HashMap<ProjectFile, ImportBinder>,
    language: Language,
) -> HashMap<ProjectFile, Vec<ImportEdge>> {
    let mut reverse: HashMap<ProjectFile, Vec<ImportEdge>> = HashMap::default();
    for file in files {
        let Some(binder) = binders_by_file.get(file) else {
            continue;
        };
        for (local_name, binding) in &binder.bindings {
            let resolved = resolve_module_specifier(file, &binding.module_specifier, language);
            for target_file in resolved {
                let kind = match (binding.kind, binding.imported_name.as_deref()) {
                    (ImportKind::Default, _) => ImportEdgeKind::Default,
                    (ImportKind::Namespace, _) => ImportEdgeKind::Namespace,
                    (ImportKind::Named, Some(name)) => ImportEdgeKind::Named(name.to_string()),
                    (ImportKind::Named, None) => ImportEdgeKind::Named(local_name.clone()),
                };
                let edge = ImportEdge {
                    importer: file.clone(),
                    local_name: local_name.clone(),
                    target_file: target_file.clone(),
                    kind,
                };
                reverse.entry(target_file).or_default().push(edge);
            }
        }
    }
    reverse
}

/// Resolve a relative module specifier against the importing file. Mirrors
/// `resolve_js_ts_import_paths` in `javascript_analyzer.rs` (kept private there). Only
/// resolves `./` and `../` paths against the project root — bare specifiers (npm
/// modules) are intentionally ignored.
fn resolve_module_specifier(
    source_file: &ProjectFile,
    module_specifier: &str,
    language: Language,
) -> Vec<ProjectFile> {
    if !module_specifier.starts_with('.') {
        return Vec::new();
    }
    let parent = source_file.parent();
    let base = parent.join(module_specifier);
    let mut candidates: Vec<ProjectFile> = Vec::new();
    let extensions = language.extensions();

    if base.extension().is_some() {
        let file = ProjectFile::new(source_file.root().to_path_buf(), base.clone());
        if file.exists() {
            candidates.push(file);
        }
    } else {
        for ext in extensions {
            let with_ext = base.with_extension(ext);
            let direct = ProjectFile::new(source_file.root().to_path_buf(), with_ext);
            if direct.exists() {
                candidates.push(direct);
            }
            let index = base.join(format!("index.{ext}"));
            let index_file = ProjectFile::new(source_file.root().to_path_buf(), index);
            if index_file.exists() {
                candidates.push(index_file);
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

// ===================================================================================
// Per-file scanning
// ===================================================================================

fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    graph: &ProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(target).to_string();
    let target_member = member_name(target);

    let language = target_language(target);
    let parser_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => return BTreeSet::new(),
    };

    let files_vec: Vec<&ProjectFile> = files.iter().collect();

    files_vec.par_iter().for_each(|file| {
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

        let edges = graph.matching_edges_for_importer(file, seeds);

        let mut local_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let line_starts = compute_line_starts(&source);

        let target_self_file = *file == target.source();

        let mut scan_ctx = ScanCtx {
            file,
            source: &source,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            edges: &edges,
            target_self_file,
            hits: &mut local_hits,
        };

        scan_node(tree.root_node(), &mut scan_ctx);

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
    /// Top-level identifier (the class/function/field's own name component).
    target_short: &'a str,
    /// For members, the member name (e.g. `foo` in `BaseClass.foo`); otherwise None.
    target_member: Option<&'a str>,
    /// Import edges from this file that resolve to the target's seed set.
    edges: &'a [ImportEdge],
    /// True when this scan is over the target's own defining file (used to also catch
    /// in-file references that don't go through an import binding).
    target_self_file: bool,
    hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn binds_target(&self, ident: &str) -> bool {
        if self.edges.iter().any(|edge| edge.local_name == ident) {
            return true;
        }
        // In the target's own file, the bare class/function name is itself a reference
        // worth reporting (covers `BaseClass.foo()` and `extends BaseClass` written in
        // the same file).
        self.target_self_file && ident == self.target_short
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let kind = node.kind();

    // Skip import statements outright — bindings declared there are not usages.
    if matches!(
        kind,
        "import_statement"
            | "import_clause"
            | "import_specifier"
            | "namespace_import"
            | "export_clause"
            | "export_specifier"
    ) {
        return;
    }

    match kind {
        "identifier" | "type_identifier" | "shorthand_property_identifier" => {
            handle_identifier_candidate(node, ctx);
        }
        "member_expression" => handle_member_expression(node, ctx),
        "new_expression" => handle_new_expression(node, ctx),
        "class_heritage" | "extends_clause" => handle_heritage(node, ctx),
        "jsx_opening_element" | "jsx_self_closing_element" => handle_jsx_element(node, ctx),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
    }
}

fn handle_identifier_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let text = slice(node, ctx.source);
    if text.is_empty() {
        return;
    }
    if !ctx.binds_target(text) {
        return;
    }
    if is_declaration_identifier(node) {
        return;
    }
    if is_property_key_in_member(node) {
        return;
    }
    record_hit(node, ctx);
}

fn handle_member_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    // member_expression has `object` (expr) and `property` (property_identifier).
    let Some(object) = node.child_by_field_name("object") else {
        return;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let property_text = slice(property, ctx.source);

    // `Namespace.Foo` style access — namespace binds to target's file, property matches
    // the target's own short name (or the requested member).
    let namespace_match = ctx.edges.iter().any(|edge| {
        matches!(edge.kind, ImportEdgeKind::Namespace) && edge.local_name == object_text
    });
    if namespace_match && property_text == ctx.target_short {
        record_hit(property, ctx);
        return;
    }

    // `BaseClass.staticMethod()` style — object binds to the target's parent class, the
    // property is the requested member.
    if let Some(member) = ctx.target_member
        && ctx.binds_target(object_text)
        && property_text == member
    {
        record_hit(property, ctx);
    }
}

fn handle_new_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(constructor) = node.child_by_field_name("constructor") else {
        return;
    };
    let text = slice(constructor, ctx.source);
    if text.is_empty() {
        return;
    }
    // `new Foo(...)` — Foo could be either a bare identifier or a member expression.
    if constructor.kind() == "identifier" || constructor.kind() == "type_identifier" {
        if ctx.binds_target(text) {
            record_hit(constructor, ctx);
        }
    } else if constructor.kind() == "member_expression" {
        // Already handled by handle_member_expression visit.
    }
}

fn handle_heritage(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let text = slice(child, ctx.source);
        if !text.is_empty() && ctx.binds_target(text) {
            record_hit(child, ctx);
        }
    }
}

fn handle_jsx_element(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let text = slice(name_node, ctx.source);
    if text.is_empty() {
        return;
    }
    if let Some(last) = text.rsplit('.').next()
        && ctx.binds_target(last)
    {
        record_hit(name_node, ctx);
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

// ===================================================================================
// AST predicates
// ===================================================================================

fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let parent_kind = parent.kind();
    if matches!(
        parent_kind,
        "variable_declarator"
            | "function_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration"
            | "method_definition"
            | "method_signature"
            | "abstract_method_signature"
            | "public_field_definition"
            | "property_signature"
            | "field_definition"
            | "import_specifier"
            | "namespace_import"
            | "import_clause"
            | "labeled_statement"
            | "function_signature"
    ) {
        if let Some(name_node) = parent.child_by_field_name("name")
            && name_node.id() == node.id()
        {
            return true;
        }
        // import_specifier has shape `name as alias`; both sides are declarations.
        if matches!(
            parent_kind,
            "import_specifier" | "namespace_import" | "import_clause"
        ) {
            return true;
        }
    }
    if parent_kind == "formal_parameters"
        || parent_kind == "required_parameter"
        || parent_kind == "optional_parameter"
        || parent_kind == "rest_pattern"
    {
        return true;
    }
    false
}

fn is_property_key_in_member(node: Node<'_>) -> bool {
    // Avoid double-counting: when scanning a member_expression we report the property
    // node directly. The recursive walk also visits the property child, so we must
    // suppress the visit-time report (handled in handle_member_expression by reporting
    // and short-circuiting in the parent visitor for those patterns).
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    parent
        .child_by_field_name("property")
        .map(|p| p.id() == node.id())
        .unwrap_or(false)
}

fn top_level_identifier(target: &CodeUnit) -> &str {
    // For nested members like `BaseClass.foo`, the top-level identifier is `BaseClass`.
    target
        .short_name()
        .split('.')
        .next()
        .unwrap_or(target.short_name())
}

fn member_name(target: &CodeUnit) -> Option<String> {
    // Anything past the first dot is treated as the member chain. We strip TS-specific
    // `$static` suffix to align with the original syntactic name.
    let parts: Vec<&str> = target.short_name().split('.').collect();
    if parts.len() <= 1 {
        return None;
    }
    let last = parts.last().copied()?;
    Some(last.trim_end_matches("$static").to_string())
}

// ===================================================================================
// ExportIndex extraction
// ===================================================================================

fn compute_export_index(_file: &ProjectFile, source: &str, tree: &Tree) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let root = tree.root_node();

    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        match child.kind() {
            "export_statement" => visit_export_statement(child, source, &mut index),
            "class_declaration" | "abstract_class_declaration" | "interface_declaration" => {
                collect_class_metadata(child, source, &mut index, false);
            }
            _ => {}
        }
    }

    index
}

fn visit_export_statement(node: Node<'_>, source: &str, index: &mut ExportIndex) {
    // `export_clause` and `namespace_export` are direct named children, NOT accessible
    // via a `clause` field — find them by iterating named children.
    let export_clause_child = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|c| c.kind() == "export_clause")
    };

    // export {a, b} from "..."  /  export * from "..."  / export ... from
    if let Some(source_node) = node.child_by_field_name("source") {
        let module_specifier = unquote(slice(source_node, source));
        if let Some(clause) = export_clause_child {
            let mut cursor = clause.walk();
            for spec in clause.named_children(&mut cursor) {
                if spec.kind() != "export_specifier" {
                    continue;
                }
                let imported_name = spec
                    .child_by_field_name("name")
                    .map(|n| slice(n, source).to_string())
                    .unwrap_or_default();
                let exported_name = spec
                    .child_by_field_name("alias")
                    .map(|n| slice(n, source).to_string())
                    .unwrap_or_else(|| imported_name.clone());
                if imported_name.is_empty() || exported_name.is_empty() {
                    continue;
                }
                index.exports_by_name.insert(
                    exported_name,
                    ExportEntry::ReexportedNamed {
                        module_specifier: module_specifier.clone(),
                        imported_name,
                    },
                );
            }
        } else {
            // No clause => `export * from "..."`.
            index
                .reexport_stars
                .push(crate::usages::model::ReexportStar { module_specifier });
        }
        return;
    }

    // `export { a, b as c }` (no module specifier => re-binding locals).
    if let Some(clause) = export_clause_child {
        let mut cursor = clause.walk();
        for spec in clause.named_children(&mut cursor) {
            if spec.kind() != "export_specifier" {
                continue;
            }
            let local_name = spec
                .child_by_field_name("name")
                .map(|n| slice(n, source).to_string())
                .unwrap_or_default();
            let exported_name = spec
                .child_by_field_name("alias")
                .map(|n| slice(n, source).to_string())
                .unwrap_or_else(|| local_name.clone());
            if local_name.is_empty() || exported_name.is_empty() {
                continue;
            }
            index
                .exports_by_name
                .insert(exported_name, ExportEntry::Local { local_name });
        }
        return;
    }

    // `export default <expr-or-decl>` and `export <decl>`.
    let is_default = node
        .children(&mut node.walk())
        .any(|child| !child.is_named() && slice(child, source) == "default");

    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "function_declaration"
            | "function_signature" => {
                if let Some(name_node) = declaration.child_by_field_name("name") {
                    let name = slice(name_node, source).to_string();
                    if !name.is_empty() {
                        if is_default {
                            index.exports_by_name.insert(
                                "default".to_string(),
                                ExportEntry::Default {
                                    local_name: Some(name.clone()),
                                },
                            );
                        }
                        index
                            .exports_by_name
                            .insert(name.clone(), ExportEntry::Local { local_name: name });
                    }
                }
                collect_class_metadata(declaration, source, index, true);
            }
            "lexical_declaration" | "variable_declaration" => {
                let mut cursor = declaration.walk();
                for declarator in declaration.named_children(&mut cursor) {
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(name_node) = declarator.child_by_field_name("name") else {
                        continue;
                    };
                    let name = slice(name_node, source).to_string();
                    if name.is_empty() {
                        continue;
                    }
                    index
                        .exports_by_name
                        .insert(name.clone(), ExportEntry::Local { local_name: name });
                }
            }
            "enum_declaration" | "type_alias_declaration" | "internal_module" => {
                if let Some(name_node) = declaration.child_by_field_name("name") {
                    let name = slice(name_node, source).to_string();
                    if !name.is_empty() {
                        index
                            .exports_by_name
                            .insert(name.clone(), ExportEntry::Local { local_name: name });
                    }
                }
            }
            _ if is_default => {
                index.exports_by_name.insert(
                    "default".to_string(),
                    ExportEntry::Default { local_name: None },
                );
            }
            _ => {}
        }
        return;
    }

    if is_default {
        // `export default expr;` with no declaration child — anonymous default.
        index.exports_by_name.insert(
            "default".to_string(),
            ExportEntry::Default { local_name: None },
        );
    }
}

fn collect_class_metadata(node: Node<'_>, source: &str, index: &mut ExportIndex, _exported: bool) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let class_name = slice(name_node, source).to_string();
    if class_name.is_empty() {
        return;
    }

    // Heritage: `class Foo extends Bar {}` and `class Foo extends Bar implements Baz {}`.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "class_heritage" | "extends_clause") {
            collect_heritage_edges(child, source, &class_name, index);
        }
    }

    // Class members (methods + fields).
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            let (kind_opt, static_member) = match member.kind() {
                "method_definition" | "method_signature" | "abstract_method_signature" => (
                    Some(crate::analyzer::CodeUnitType::Function),
                    is_static_member(member, source),
                ),
                "field_definition"
                | "public_field_definition"
                | "property_signature"
                | "index_signature" => (
                    Some(crate::analyzer::CodeUnitType::Field),
                    is_static_member(member, source),
                ),
                _ => (None, false),
            };
            let Some(kind) = kind_opt else { continue };
            let Some(member_name_node) = member.child_by_field_name("name") else {
                continue;
            };
            let member_name = slice(member_name_node, source)
                .trim_matches('"')
                .to_string();
            if member_name.is_empty() {
                continue;
            }
            index
                .class_members
                .insert(crate::usages::model::ClassMember {
                    owner_class_name: class_name.clone(),
                    member_name,
                    static_member,
                    kind,
                });
        }
    }
}

fn collect_heritage_edges(node: Node<'_>, source: &str, child_name: &str, index: &mut ExportIndex) {
    // class_heritage shape:
    //   - JS:   class_heritage > <expression>            (direct identifier or member_expression)
    //   - TS:   class_heritage > extends_clause > value:<expression>  + implements_clause > <type>
    // Recurse into each child looking for the first identifier-shaped node. Trim to
    // the rightmost segment so `Pkg.Base` resolves to `Base`.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let target = if child.kind() == "extends_clause" {
            child.child_by_field_name("value").unwrap_or(child)
        } else {
            child
        };
        if let Some(name) = first_identifier_in(target, source) {
            let trimmed = name.rsplit('.').next().unwrap_or(&name).to_string();
            if !trimmed.is_empty() {
                index
                    .heritage_edges
                    .insert(crate::usages::model::HeritageEdge {
                        child_name: child_name.to_string(),
                        parent_name: trimmed,
                    });
            }
        }
    }
}

fn first_identifier_in(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let s = slice(node, source).trim().to_string();
            (!s.is_empty()).then_some(s)
        }
        "member_expression" => {
            // Pkg.Sub.Base => grab the entire dotted path so `Pkg.Base` is preserved
            // for the caller to trim.
            let s = slice(node, source).trim().to_string();
            (!s.is_empty()).then_some(s)
        }
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| first_identifier_in(child, source))
        }
    }
}

fn is_static_member(node: Node<'_>, source: &str) -> bool {
    let head = slice(node, source).split(['{', ';']).next().unwrap_or("");
    head.split_whitespace().any(|token| token == "static")
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    let stripped = trimmed
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|t| t.strip_suffix('\''))
        });
    stripped.unwrap_or(trimmed).to_string()
}

// ===================================================================================
// ImportBinder extraction
// ===================================================================================

fn compute_import_binder(source: &str, tree: &Tree) -> ImportBinder {
    let mut binder = ImportBinder::empty();
    let root = tree.root_node();

    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if child.kind() == "import_statement" {
            visit_import_statement(child, source, &mut binder);
        }
    }
    binder
}

fn visit_import_statement(node: Node<'_>, source: &str, binder: &mut ImportBinder) {
    let Some(source_node) = node.child_by_field_name("source") else {
        return;
    };
    let module_specifier = unquote(slice(source_node, source));
    if module_specifier.is_empty() {
        return;
    }

    // import_clause holds default/namespace/named bindings. Side-effect imports
    // (`import "./x";`) have no clause and therefore no bindings.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "import_clause" {
            continue;
        }
        let mut clause_cursor = child.walk();
        for clause_child in child.named_children(&mut clause_cursor) {
            match clause_child.kind() {
                "identifier" => {
                    let local = slice(clause_child, source).to_string();
                    if !local.is_empty() {
                        binder.bindings.insert(
                            local,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                kind: ImportKind::Default,
                                imported_name: None,
                            },
                        );
                    }
                }
                "namespace_import" => {
                    // namespace_import has a single identifier child (no field name).
                    let mut ns_cursor = clause_child.walk();
                    let identifier = clause_child
                        .named_children(&mut ns_cursor)
                        .find(|n| n.kind() == "identifier")
                        .map(|n| slice(n, source).to_string());
                    if let Some(local) = identifier
                        && !local.is_empty()
                    {
                        binder.bindings.insert(
                            local,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                kind: ImportKind::Namespace,
                                imported_name: None,
                            },
                        );
                    }
                }
                "named_imports" => {
                    let mut spec_cursor = clause_child.walk();
                    for spec in clause_child.named_children(&mut spec_cursor) {
                        if spec.kind() != "import_specifier" {
                            continue;
                        }
                        let imported_name = spec
                            .child_by_field_name("name")
                            .map(|n| slice(n, source).to_string());
                        let alias = spec
                            .child_by_field_name("alias")
                            .map(|n| slice(n, source).to_string());
                        let local_name = alias
                            .clone()
                            .or_else(|| imported_name.clone())
                            .unwrap_or_default();
                        if local_name.is_empty() {
                            continue;
                        }
                        binder.bindings.insert(
                            local_name,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                kind: ImportKind::Named,
                                imported_name,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    fn parse_ts(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn export_index_named_export() {
        let src = "export class Foo {}\nexport function bar() {}";
        let tree = parse_js(src);
        let dummy = ProjectFile::new(std::env::temp_dir(), "x.js");
        let idx = compute_export_index(&dummy, src, &tree);
        assert!(idx.exports_by_name.contains_key("Foo"));
        assert!(idx.exports_by_name.contains_key("bar"));
    }

    #[test]
    fn export_index_named_reexport() {
        let src = "export { Foo as Bar } from './other';";
        let tree = parse_js(src);
        let dummy = ProjectFile::new(std::env::temp_dir(), "x.js");
        let idx = compute_export_index(&dummy, src, &tree);
        match idx.exports_by_name.get("Bar") {
            Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) => {
                assert_eq!(module_specifier, "./other");
                assert_eq!(imported_name, "Foo");
            }
            other => panic!("expected ReexportedNamed, got {other:?}"),
        }
    }

    #[test]
    fn import_binder_named_default_namespace() {
        let src = r#"
            import Foo, { bar as baz } from "./mod";
            import * as ns from "./other";
        "#;
        let tree = parse_js(src);
        let binder = compute_import_binder(src, &tree);
        assert_eq!(
            binder.bindings.get("Foo").map(|b| b.kind),
            Some(ImportKind::Default)
        );
        assert_eq!(
            binder.bindings.get("baz").map(|b| b.kind),
            Some(ImportKind::Named)
        );
        assert_eq!(
            binder.bindings.get("ns").map(|b| b.kind),
            Some(ImportKind::Namespace)
        );
    }

    #[test]
    fn class_metadata_heritage_and_members() {
        let src = "export class Child extends Parent { foo() {} bar = 1; static qux() {} }";
        let tree = parse_ts(src);
        let dummy = ProjectFile::new(std::env::temp_dir(), "x.ts");
        let idx = compute_export_index(&dummy, src, &tree);
        let edges: Vec<_> = idx.heritage_edges.iter().collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].child_name, "Child");
        assert_eq!(edges[0].parent_name, "Parent");
        let names: BTreeSet<_> = idx
            .class_members
            .iter()
            .map(|m| (m.member_name.clone(), m.static_member))
            .collect();
        assert!(names.contains(&("foo".to_string(), false)));
        assert!(names.contains(&("qux".to_string(), true)));
    }
}
