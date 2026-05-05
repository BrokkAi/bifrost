//! JS/TS export-usage reference graph (Phase 7 of the usages port).
//!
//! Mirrors brokk's `JsTsExportUsageReferenceGraph` and `JsTsExportUsageExtractor`. Where
//! brokk's pipeline drives the JDT/LLM disambiguator, bifrost is tree-sitter only — the
//! graph here resolves on syntax + import binders alone, and signals
//! [`FuzzyResult::Failure`] when it cannot infer a seed so the caller can fall back to
//! the regex analyzer.
//!
//! Pipeline overview:
//! 1. Per-file [`ExportIndex`]: tree-sitter walk that captures local exports, named
//!    re-exports, star re-exports, and default exports.
//! 2. Per-file [`ImportBinder`]: extracts default/named/namespace import bindings from
//!    ESM `import` statements.
//! 3. Project indices, rebuilt per query so file edits are picked up immediately:
//!    - reverse re-export index: `(target_file, exported_name) -> {(reexporting_file, alias)}`
//!    - reverse export-seed index: `(short_name) -> {(file, exported_name)}` for fast seed
//!      inference from a target's identifier.
//! 4. Reference traversal: for the target's seed exports, walk the import-reverse index to
//!    find files that bind a local name to the export, then AST-scan those files for
//!    identifier / member / type / heritage references that resolve back to the target.
//!
//! Scope notes:
//! - **ESM only.** `require(...)` calls and `module.exports = …` assignments are not
//!   walked. Mixed-ESM/CJS projects fall back to the regex analyzer for any CJS-only
//!   edges. CJS support is tracked as future work alongside richer module resolution
//!   (`package.json` `exports`, tsconfig `paths`).
//! - **Per-call indices.** No cross-call cache: each query rebuilds the graph for the
//!   target's language. This keeps results consistent after file edits at the cost of
//!   re-parsing JS/TS files on every query. Hosts with stable file sets that need lower
//!   latency (e.g. an LSP server) should layer their own cache around the strategy.

use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, Range, resolve_js_ts_module_specifier,
};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::model::{
    ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding, ImportKind, UsageHit,
};
use crate::usages::traits::UsageAnalyzer;
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
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
/// The strategy is stateless: it rebuilds its project graph for every query. When it
/// cannot infer a seed it returns [`FuzzyResult::Failure`] so the caller (typically
/// [`UsageFinder`](super::UsageFinder)) can route the query to its regex analyzer.
#[derive(Default)]
pub struct JsTsExportUsageGraphStrategy {
    _private: (),
}

impl JsTsExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
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
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "JsTsExportUsageGraphStrategy: target is not JS/TS".to_string(),
            };
        }

        let graph = ProjectGraph::build(analyzer, language);

        let seeds = graph.seeds_for_target(target);
        if seeds.is_empty() {
            return FuzzyResult::Failure {
                fq_name: target.fq_name().to_string(),
                reason: "JsTsExportUsageGraphStrategy: no export seed resolved".to_string(),
            };
        }

        let importers = graph.importers_of_seeds(&seeds);
        let scan_files: HashSet<ProjectFile> =
            candidate_files.iter().cloned().chain(importers).collect();

        let hits = scan_files_for_seeds(analyzer, &graph, &scan_files, target, &seeds, language);
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

/// Cached parse for one source file. `source` is held alongside the `Tree` so AST byte
/// ranges remain valid for the lifetime of the graph (and so the scan phase can reuse
/// the parse result without re-reading the file).
struct ParsedFile {
    source: Arc<String>,
    tree: Tree,
}

/// Project-wide indices computed once per [`JsTsExportUsageGraphStrategy::find_usages`].
struct ProjectGraph {
    /// Files we've actually analyzed (JS or TS depending on the target language).
    files: Vec<ProjectFile>,
    /// Parsed source + tree per file. Reused by the scan phase to avoid double parsing.
    parsed: HashMap<ProjectFile, ParsedFile>,
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

        let parsed_files: Vec<(ProjectFile, ParsedFile, ExportIndex, ImportBinder)> = files
            .par_iter()
            .filter_map(|file| {
                let source = file.read_to_string().ok()?;
                let mut parser = Parser::new();
                parser.set_language(&parser_language).ok()?;
                let tree = parser.parse(source.as_str(), None)?;
                let exports = compute_export_index(&source, &tree);
                let binder = compute_import_binder(&source, &tree);
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

        let mut parsed: HashMap<ProjectFile, ParsedFile> = map_with_capacity(parsed_files.len());
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> =
            map_with_capacity(parsed_files.len());
        let mut binders_by_file: HashMap<ProjectFile, ImportBinder> =
            map_with_capacity(parsed_files.len());

        for (file, parsed_file, exports, binder) in parsed_files.into_iter() {
            parsed.insert(file.clone(), parsed_file);
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
                        let resolved =
                            resolve_js_ts_module_specifier(file, module_specifier, language);
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
                let resolved =
                    resolve_js_ts_module_specifier(file, &star.module_specifier, language);
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
            parsed,
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
            parsed: HashMap::default(),
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
            .filter(|edge| edge_matches_seed(edge, seeds))
            .cloned()
            .collect()
    }
}

fn edge_matches_seed(edge: &ImportEdge, seeds: &BTreeSet<(ProjectFile, String)>) -> bool {
    match &edge.kind {
        ImportEdgeKind::Named(name) => seeds.contains(&(edge.target_file.clone(), name.clone())),
        ImportEdgeKind::Default => {
            seeds.contains(&(edge.target_file.clone(), "default".to_string()))
        }
        ImportEdgeKind::Namespace => {
            // Namespace import binds the entire module — match if any seed lives in the
            // target file. Member-level resolution is handled by the candidate scanner.
            seeds.iter().any(|(file, _)| file == &edge.target_file)
        }
    }
}

fn collect_jsts_files(analyzer: &dyn IAnalyzer, language: Language) -> Vec<ProjectFile> {
    let mut result: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(language)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
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
            let resolved =
                resolve_js_ts_module_specifier(file, &binding.module_specifier, language);
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

// ===================================================================================
// Per-file scanning
// ===================================================================================

fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    graph: &ProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
    language: Language,
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(target).to_string();
    let target_member = member_name(target);

    let parser_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => return BTreeSet::new(),
    };

    let files_vec: Vec<&ProjectFile> = files.iter().collect();

    files_vec.par_iter().for_each(|file| {
        // Reuse the build-phase parse when available; only fall back to a fresh parse
        // for ad-hoc candidates that weren't part of the project graph (e.g. a text
        // search candidate outside the analyzer's analyzable set).
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

        let edges = graph.matching_edges_for_importer(file, seeds);

        let mut local_hits: BTreeSet<UsageHit> = BTreeSet::new();
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

fn handle_jsx_element(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let text = slice(name_node, ctx.source);
    if text.is_empty() {
        return;
    }
    // For qualified JSX names (`<Foo.Bar />`), narrow the recorded range to the
    // rightmost identifier so LSP clients highlight just `Bar`. The descent will
    // visit the leaf identifier directly when it isn't a member_expression child;
    // by recording here we ensure JSX qualifications show up regardless.
    if let Some((rightmost, leaf_text)) = rightmost_jsx_identifier(name_node, ctx.source)
        && ctx.binds_target(leaf_text)
    {
        record_hit(rightmost, ctx);
    }
}

/// Walks a JSX element name (identifier or member_expression) and returns the rightmost
/// identifier node together with its text. For `<Foo.Bar />` the leaf is `Bar`.
fn rightmost_jsx_identifier<'a>(node: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str)> {
    match node.kind() {
        "identifier" | "type_identifier" | "property_identifier" => {
            let text = slice(node, source);
            (!text.is_empty()).then_some((node, text))
        }
        // `Foo.Bar` is a `member_expression` (or `jsx_member_expression` in some
        // grammars) — descend into the rightmost named child.
        _ => {
            let property = node.child_by_field_name("property");
            if let Some(property) = property {
                return rightmost_jsx_identifier(property, source);
            }
            let mut last = None;
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                last = Some(child);
            }
            last.and_then(|child| rightmost_jsx_identifier(child, source))
        }
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
    if matches!(
        parent_kind,
        "formal_parameters"
            | "required_parameter"
            | "optional_parameter"
            | "rest_pattern"
            | "object_pattern"
            | "array_pattern"
            | "pair_pattern"
            | "assignment_pattern"
            | "shorthand_property_identifier_pattern"
    ) {
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

fn compute_export_index(source: &str, tree: &Tree) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let root = tree.root_node();

    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if child.kind() == "export_statement" {
            visit_export_statement(child, source, &mut index);
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

    #[test]
    fn export_index_named_export() {
        let src = "export class Foo {}\nexport function bar() {}";
        let tree = parse_js(src);
        let idx = compute_export_index(src, &tree);
        assert!(idx.exports_by_name.contains_key("Foo"));
        assert!(idx.exports_by_name.contains_key("bar"));
    }

    #[test]
    fn export_index_named_reexport() {
        let src = "export { Foo as Bar } from './other';";
        let tree = parse_js(src);
        let idx = compute_export_index(src, &tree);
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
}
