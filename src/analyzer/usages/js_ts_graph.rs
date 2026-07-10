//! JS/TS export-usage reference graph (Phase 7 of the usages port).
//!
//! Mirrors brokk's `JsTsExportUsageReferenceGraph` and `JsTsExportUsageExtractor`. Where
//! brokk's pipeline drives the JDT/LLM disambiguator, bifrost is tree-sitter only — the
//! graph here resolves on syntax + import binders alone, and reports an internal
//! fallback-safe outcome when it cannot infer a seed.
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
mod receiver_analysis;
mod resolver;

/// The cacheable JS/TS resolution index and its tree-free builder, exposed so the
/// TypeScript and JavaScript analyzers can cache one per language.
pub(in crate::analyzer::usages) use receiver_analysis::JsTsReceiverFactProvider;
pub(crate) use resolver::{JsTsUsageIndex, build_jsts_usage_index};

use crate::analyzer::usages::common::analyzed_files_for_language;
use crate::analyzer::usages::js_ts_graph::extractor::scan_files_for_seeds;
use crate::analyzer::usages::js_ts_graph::resolver::{is_static_member, target_language};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitSurface, UsageProof};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{
    UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, JavascriptAnalyzer, Language, ProjectFile, TypescriptAnalyzer,
    resolve_analyzer,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(in crate::analyzer::usages) use crate::analyzer::js_ts::syntax::compute_import_binder as compute_jsts_import_binder;
use crate::analyzer::usages::inverted_edges::CallSite;
use crate::analyzer::usages::inverted_edges::UsageEdgeWeights;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::inverted_edges::UsageNodeKey;
pub(crate) use inverted::{JsTsScopedNodeStatus, JsTsScopedUsageEdges};

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
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JsTsEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

/// Borrow the analyzer-cached [`JsTsUsageIndex`] for `language` off the concrete TS/JS
/// analyzer behind `analyzer`, building it on first use. `None` when the analyzer does
/// not expose the matching JS/TS analyzer.
pub(in crate::analyzer::usages) fn cached_jsts_index(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<Arc<JsTsUsageIndex>> {
    match language {
        Language::TypeScript => {
            Some(resolve_analyzer::<TypescriptAnalyzer>(analyzer)?.jsts_usage_index())
        }
        Language::JavaScript => {
            Some(resolve_analyzer::<JavascriptAnalyzer>(analyzer)?.jsts_usage_index())
        }
        _ => None,
    }
}

/// JS/TS resolves usages off the project file set rather than a single concrete
/// analyzer — it spans the TypeScript and JavaScript analyzers — so these resolvers
/// hold no borrowed analyzer in this form.
pub(crate) struct JsTsQueryResolver;

impl<'a> UsageQueryResolver<'a> for JsTsQueryResolver {
    fn try_new(_analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self)
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let language = target_language(target);
        if language == Language::None {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not JS/TS"),
                "JsTsExportUsageGraphStrategy",
            );
        }

        let Some(index) = cached_jsts_index(analyzer, language) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose a JS/TS analyzer",
                ),
                "JsTsExportUsageGraphStrategy",
            );
        };
        let target_seed = target_seed_identifier(analyzer, target);
        let owner_seed_allowed = is_static_member(target)
            || !target.short_name().contains('.')
            || analyzer.parent_of(target).is_some();
        let seeds = index.seeds_for_target(
            target.source(),
            &target_seed,
            target.short_name(),
            owner_seed_allowed,
        );
        let scan_hits = if seeds.is_empty() {
            let mut scan_files: HashSet<ProjectFile> =
                scan_scope.candidate_files().iter().cloned().collect();
            if scan_scope.allows(target.source()) {
                scan_files.insert(target.source().clone());
            }

            scan_files_for_seeds(
                analyzer,
                index.as_ref(),
                &scan_files,
                target,
                &BTreeSet::new(),
                language,
                scan_scope.cancellation(),
            )
        } else {
            let candidate_files = scan_scope.candidate_files();
            let importers = index.importers_of_seeds(&seeds);
            let mut scan_files: HashSet<ProjectFile> = candidate_files.iter().cloned().collect();
            scan_files.extend(importers.into_iter().filter(|file| scan_scope.allows(file)));
            if scan_scope.allows(target.source()) {
                scan_files.insert(target.source().clone());
            }

            scan_files_for_seeds(
                analyzer,
                index.as_ref(),
                &scan_files,
                target,
                &seeds,
                language,
                scan_scope.cancellation(),
            )
        };
        let (hits, unproven_hits): (BTreeSet<UsageHit>, BTreeSet<UsageHit>) = scan_hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .partition(|hit| hit.proof == UsageProof::Proven);

        let external_hit_count = hits
            .iter()
            .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
            .count();
        if external_hit_count > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_hit_count,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
    }
}

pub(crate) struct JsTsEdgeResolver;

impl<'a> UsageEdgeResolver<'a> for JsTsEdgeResolver {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let has_jsts = [Language::TypeScript, Language::JavaScript]
            .iter()
            .any(|language| !analyzed_files_for_language(analyzer, *language).is_empty());
        has_jsts.then_some(Self)
    }

    fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let mut edges: std::collections::BTreeMap<(String, String), Vec<CallSite>> =
            std::collections::BTreeMap::new();
        let mut truncated: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut unproven_inbound: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();

        for language in [Language::TypeScript, Language::JavaScript] {
            if analyzed_files_for_language(analyzer, language).is_empty() {
                continue;
            }
            let result = inverted::build_jsts_edges(analyzer, language, nodes, &keep_file);
            for (key, sites) in result.edges {
                edges.entry(key).or_default().extend(sites);
            }
            for (callee, total) in result.truncated {
                *truncated.entry(callee).or_insert(0) += total;
            }
            for (callee, total) in result.unproven_inbound {
                *unproven_inbound.entry(callee).or_insert(0) += total;
            }
        }

        // TS and JS are distinct files, so per-language sites for a shared edge key
        // never overlap; re-sort after concatenating the two runs for determinism.
        for sites in edges.values_mut() {
            sites.sort();
        }

        UsageEdges {
            edges,
            truncated,
            unproven_inbound,
        }
    }
}

/// Build the whole JS/TS `caller -> callee` edge set using file-scoped node
/// identity, so same-name exports in different files do not cross-match.
pub(crate) fn build_jsts_scoped_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<UsageNodeKey>,
    keep_file: F,
) -> Option<JsTsScopedUsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync + Copy,
{
    let mut edges: std::collections::BTreeMap<(UsageNodeKey, UsageNodeKey), usize> =
        std::collections::BTreeMap::new();
    let mut truncated: std::collections::BTreeMap<UsageNodeKey, usize> =
        std::collections::BTreeMap::new();
    let mut unproven_inbound: std::collections::BTreeMap<UsageNodeKey, usize> =
        std::collections::BTreeMap::new();
    let mut node_status: std::collections::BTreeMap<UsageNodeKey, JsTsScopedNodeStatus> =
        std::collections::BTreeMap::new();
    let mut any = false;

    for language in [Language::TypeScript, Language::JavaScript] {
        if analyzed_files_for_language(analyzer, language).is_empty() {
            continue;
        }
        any = true;
        let language_nodes: HashSet<UsageNodeKey> = nodes
            .iter()
            .filter(|key| crate::analyzer::common::language_for_file(&key.file) == language)
            .cloned()
            .collect();
        if language_nodes.is_empty() {
            continue;
        }
        let Some(index) = cached_jsts_index(analyzer, language) else {
            continue;
        };
        let result = inverted::build_jsts_scoped_edges(
            analyzer,
            index.as_ref(),
            language,
            &language_nodes,
            keep_file,
        );
        for (key, weight) in result.edges.edges {
            *edges.entry(key).or_insert(0) += weight;
        }
        for (callee, total) in result.edges.truncated {
            *truncated.entry(callee).or_insert(0) += total;
        }
        for (callee, total) in result.edges.unproven_inbound {
            *unproven_inbound.entry(callee).or_insert(0) += total;
        }
        node_status.extend(result.node_status);
    }

    any.then_some(JsTsScopedUsageEdges {
        edges: UsageEdgeWeights {
            edges,
            truncated,
            unproven_inbound,
        },
        node_status,
    })
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
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(resolver) = JsTsQueryResolver::try_new(analyzer) else {
            let fq_name = overloads.first().map(CodeUnit::fq_name).unwrap_or_default();
            return GraphUsageOutcome::fallback_safe(
                fq_name,
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose a JS/TS analyzer",
                ),
                "JsTsExportUsageGraphStrategy",
            );
        };
        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

fn target_seed_identifier(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> String {
    if let Some(parent) = analyzer.parent_of(target)
        && !parent.is_module()
        && !parent.is_file_scope()
    {
        return parent.identifier().trim_end_matches("$static").to_string();
    }
    if is_static_member(target)
        && let Some((owner, _)) = target.short_name().rsplit_once('.')
        && let Some(owner_name) = owner.rsplit('.').next()
    {
        return owner_name.to_string();
    }
    target.identifier().trim_end_matches("$static").to_string()
}

impl UsageAnalyzer for JsTsExportUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}
