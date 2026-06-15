mod extractor;
mod hits;
mod inverted;
mod resolver;

use crate::analyzer::GoAnalyzer;
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::go_graph::extractor::scan_files_for_target;
use crate::analyzer::usages::go_graph::resolver::{
    GoProjectGraph, TargetSpec, build_go_graph, build_workspace_go_graph, preparse_go_files,
    resolve_go_analyzer,
};
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

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
    let go = resolve_go_analyzer(analyzer)?;
    let files: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(Language::Go)
        .ok()?
        .into_iter()
        .collect();
    if files.is_empty() {
        return None;
    }
    let cache = preparse_go_files(&files);
    let graph = build_workspace_go_graph(go, &files, Some(&cache))?;
    Some(inverted::build_go_edges(
        analyzer, go, &graph, nodes, keep_file,
    ))
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

        let graph = build_go_graph(go, candidate_files, target.source(), None);
        resolve_with_graph(analyzer, go, &graph, overloads, candidate_files, max_usages)
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

    let scan_files = graph.scan_files(candidate_files, target, &target_spec);
    let hits = scan_files_for_target(analyzer, graph, scan_files, &target_spec);
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
