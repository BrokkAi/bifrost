mod extractor;
mod hits;
mod inverted;
mod reference;
mod resolver;

use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_target};
use crate::analyzer::usages::go_graph::extractor::scan_files_for_target;
use crate::analyzer::usages::go_graph::resolver::{
    GoEdgeIndex, GoProjectGraph, TargetSpec, build_go_edge_index, build_go_graph,
};
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{
    UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{CodeUnit, GoAnalyzer, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
pub(in crate::analyzer::usages) use reference::{
    GoReferenceResolution, resolve_go_reference_with_namespaces,
};
use std::collections::BTreeSet;

pub(in crate::analyzer::usages) use resolver::extract_go_import_path;
pub(crate) use resolver::{
    GoIndexedMemberLookup, default_go_import_local_name, go_embedded_field_unit_type_text,
    go_simple_type_name, go_type_name_parts, go_unique_indexed_member_candidate_at_nearest_depth,
    resolve_go_import_namespaces,
};

/// Build the whole Go `caller -> callee` edge set in a single inverted pass over
/// the workspace (see [`inverted`]). Returns `None` when the analyzer exposes no
/// Go files. `nodes` is the set of node fqns and `keep_file` drops out-of-scope
/// caller files; the per-file definition ranges used to exclude self-declarations
/// are derived inside the shared driver.
pub(crate) fn build_go_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = GoEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) struct GoQueryResolver<'a> {
    go: &'a GoAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for GoQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            go: resolve_analyzer::<GoAnalyzer>(analyzer)?,
        })
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
        let candidate_files = scan_scope.candidate_files();
        let graph = build_go_graph(
            self.go,
            candidate_files,
            target.source(),
            scan_scope.cancellation(),
        );
        if scan_scope.is_cancelled() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }
        resolve_with_graph(
            analyzer,
            self.go,
            &graph,
            overloads,
            candidate_files,
            scan_scope,
            max_usages,
        )
    }
}

pub(crate) struct GoEdgeResolver {
    index: GoEdgeIndex,
}

impl<'a> UsageEdgeResolver<'a> for GoEdgeResolver {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Go);
        if files.is_empty() {
            return None;
        }
        // A tree-free resolution index; the per-file walk re-parses on demand and
        // drops each tree, so the whole-workspace build retains no syntax trees.
        let index = build_go_edge_index(go, &files)?;
        Some(Self { index })
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
        inverted::build_go_edges(analyzer, &self.index, nodes, keep_file)
    }
}

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
        scan_scope: &UsageScanScope<'_>,
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

        let Some(resolver) = GoQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose GoAnalyzer",
                ),
                "GoUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

/// Resolve a single symbol's callers against an already-built [`GoProjectGraph`].
/// Shared by the per-query path (`scan_usages`) and the shared-graph bulk path
/// (`usage_graph`); only the graph's construction differs between them.
fn resolve_with_graph(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    graph: &GoProjectGraph,
    overloads: &[CodeUnit],
    candidate_files: &HashSet<ProjectFile>,
    scan_scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> GraphUsageOutcome {
    let target = &overloads[0];
    let target_spec = TargetSpec::new(go, graph, target);
    if !target_spec.has_scan_seed() {
        return GraphUsageOutcome::fallback_safe(
            target.fq_name(),
            GraphFailureReason::NoGraphSeed("no graph seed resolved"),
            "GoUsageGraphStrategy",
        );
    }

    let mut scan_files = graph.scan_files(candidate_files, target, &target_spec);
    if scan_scope.is_authoritative() {
        scan_files.retain(|file| scan_scope.allows(file));
    }
    let scan_result = scan_files_for_target(
        analyzer,
        graph,
        scan_files,
        &target_spec,
        scan_scope.cancellation(),
    );
    let hits: BTreeSet<_> = scan_result
        .hits
        .into_iter()
        .filter(|hit| &hit.enclosing != target)
        .collect();
    let unproven_hits: BTreeSet<_> = scan_result
        .unproven_hits
        .into_iter()
        .filter(|hit| &hit.enclosing != target)
        .collect();

    if hits.len() > max_usages {
        return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
            short_name: target.short_name().to_string(),
            total_callsites: hits.len(),
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

impl UsageAnalyzer for GoUsageGraphStrategy {
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
