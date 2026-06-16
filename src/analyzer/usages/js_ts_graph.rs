//! JS/TS export-usage reference graph (Phase 7 of the usages port).
//!
//! Mirrors brokk's `JsTsExportUsageReferenceGraph` and `JsTsExportUsageExtractor`. Where
//! brokk's pipeline drives the JDT/LLM disambiguator, bifrost is tree-sitter only — the
//! graph here resolves on syntax + import binders alone, and reports an internal
//! fallback-safe outcome when it cannot infer a seed so the caller can fall back to
//! the regex analyzer.
//!
//! Pipeline overview:
//! 1. Per-file [`ExportIndex`]: tree-sitter walk that captures local exports, named
//!    re-exports, star re-exports, default exports, and structured CommonJS export
//!    assignments.
//! 2. Per-file [`ImportBinder`]: extracts default/named/namespace import bindings from
//!    ESM `import` statements and structured CommonJS `require(...)` declarations.
//! 3. Project indices, rebuilt per query so file edits are picked up immediately:
//!    - reverse re-export index: `(target_file, exported_name) -> {(reexporting_file, alias)}`
//!    - reverse export-seed index: `(short_name) -> {(file, exported_name)}` for fast seed
//!      inference from a target's identifier.
//! 4. Reference traversal: for the target's seed exports, walk the import-reverse index to
//!    find files that bind a local name to the export, then AST-scan those files for
//!    identifier / member / type / heritage references that resolve back to the target.
//!
//! Scope notes:
//! - **Structured local modules only.** Static relative ESM specifiers and CommonJS
//!   `require(...)` calls are walked, plus non-relative specifiers that match a
//!   `tsconfig.json`/`jsconfig.json` path alias (`@/...`, resolved via `AliasResolver`).
//!   Dynamic requires, bare package specifiers, and `package.json` `exports` remain
//!   outside this graph.
//! - **Per-call indices.** No cross-call cache: each query rebuilds the graph for the
//!   target's language. This keeps results consistent after file edits at the cost of
//!   re-parsing JS/TS files on every query. Hosts with stable file sets that need lower
//!   latency (e.g. an LSP server) should layer their own cache around the strategy.

mod extractor;
mod hits;
mod inverted;
mod resolver;

use crate::analyzer::usages::js_ts_graph::extractor::scan_files_for_seeds;
use crate::analyzer::usages::js_ts_graph::resolver::{
    build_js_ts_graph, target_language, top_level_identifier,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

use crate::analyzer::usages::inverted_edges::UsageEdges;

/// Build the whole JS/TS `caller -> callee` edge set in a single inverted pass per
/// language present, merging TypeScript and JavaScript. Returns `None` when the
/// workspace has no JS/TS files. `nodes`/`keep_file` mirror the Go builder; see
/// [`inverted`].
pub(crate) fn build_jsts_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync + Copy,
{
    let mut edges: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    let mut truncated: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut any = false;

    for language in [Language::TypeScript, Language::JavaScript] {
        let has_files = analyzer
            .project()
            .analyzable_files(language)
            .map(|set| set.into_iter().next().is_some())
            .unwrap_or(false);
        if !has_files {
            continue;
        }
        any = true;
        let graph = build_js_ts_graph(analyzer, language);
        let result = inverted::build_jsts_edges(analyzer, &graph, nodes, keep_file);
        for (key, weight) in result.edges {
            *edges.entry(key).or_insert(0) += weight;
        }
        for (callee, total) in result.truncated {
            *truncated.entry(callee).or_insert(0) += total;
        }
    }

    any.then_some(UsageEdges { edges, truncated })
}

/// JS/TS export-graph usage analyzer. Resolves usages of a JavaScript or TypeScript
/// `CodeUnit` by walking the export/import graph rather than scanning text.
///
/// Stateless: rebuilds its project graph per query.
#[derive(Default)]
pub struct JsTsExportUsageGraphStrategy;

impl JsTsExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    /// Returns true when the target is a JavaScript or TypeScript code unit and lives in
    /// a file the graph can analyze.
    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) != Language::None
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
        let language = target_language(target);
        if language == Language::None {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not JS/TS"),
                "JsTsExportUsageGraphStrategy",
            );
        }

        let graph = build_js_ts_graph(analyzer, language);
        let seeds = graph.seeds_for_target(target.source(), top_level_identifier(target));
        if seeds.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("no export seed resolved"),
                "JsTsExportUsageGraphStrategy",
            );
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
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
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
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
    }
}
