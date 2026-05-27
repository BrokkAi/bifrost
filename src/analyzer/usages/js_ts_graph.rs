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

mod extractor;
mod hits;
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

/// JS/TS export-graph usage analyzer. Resolves usages of a JavaScript or TypeScript
/// `CodeUnit` by walking the export/import graph rather than scanning text.
///
/// The strategy is stateless: it rebuilds its project graph for every query. When it
/// cannot infer a seed it returns an internal fallback-safe outcome so the caller
/// (typically [`UsageFinder`](super::UsageFinder)) can route the query to its regex analyzer.
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

        let seeds = graph
            .usage_graph
            .seeds_for_target(target.source(), top_level_identifier(target));
        if seeds.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("no export seed resolved"),
                "JsTsExportUsageGraphStrategy",
            );
        }

        let importers = graph.usage_graph.importers_of_seeds(&seeds);
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
