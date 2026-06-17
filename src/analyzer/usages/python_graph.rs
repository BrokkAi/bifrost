mod extractor;
mod hits;
mod inverted;
mod resolver;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::python_graph::extractor::{build_python_graph, scan_files_for_seeds};
use crate::analyzer::usages::python_graph::resolver::{
    infer_export_names, resolve_python_analyzer,
};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) use extractor::PythonProjectGraph;

/// Build the whole Python `caller -> callee` edge set in a single inverted pass
/// over the workspace (see [`inverted`]). Returns `None` when there are no Python
/// files. `nodes`/`keep_file` mirror the Go builder.
pub(crate) fn build_python_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let py = resolve_python_analyzer(analyzer)?;
    let graph = build_python_workspace_graph(analyzer)?;
    Some(inverted::build_python_edges(
        analyzer, py, &graph, nodes, keep_file,
    ))
}

/// Build the Python project graph once over the whole workspace so a bulk caller
/// (`usage_graph`) can share it across every per-symbol query instead of
/// rebuilding it (re-parsing the candidate closure) for each symbol. Module
/// resolution is index-backed, so the one-time full build stays linear. `None`
/// when there are no Python files.
pub(crate) fn build_python_workspace_graph(
    analyzer: &dyn IAnalyzer,
) -> Option<Arc<PythonProjectGraph>> {
    let py = resolve_python_analyzer(analyzer)?;
    let files: HashSet<ProjectFile> = analyzer
        .project()
        .analyzable_files(Language::Python)
        .ok()?
        .into_iter()
        .collect();
    let target = files.iter().next()?.clone();
    Some(Arc::new(build_python_graph(py, &files, &target)))
}

#[derive(Default)]
pub struct PythonExportUsageGraphStrategy;

impl PythonExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Python
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
        if language_for_target(target) != Language::Python {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Python"),
                "PythonExportUsageGraphStrategy",
            );
        }

        let Some(py) = resolve_python_analyzer(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose PythonAnalyzer",
                ),
                "PythonExportUsageGraphStrategy",
            );
        };

        let graph = build_python_graph(py, candidate_files, target.source());
        let seed_names = infer_export_names(py, target);
        if seed_names.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("no export seed resolved"),
                "PythonExportUsageGraphStrategy",
            );
        }

        let mut seeds = BTreeSet::new();
        for seed_name in seed_names {
            seeds.extend(py.usage_seeds(target.source(), &seed_name));
        }
        if seeds.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("export graph produced no seeds"),
                "PythonExportUsageGraphStrategy",
            );
        }

        let scan_files = graph.scan_files(candidate_files, target.source());

        let hits = scan_files_for_seeds(analyzer, py, &graph, &scan_files, target, &seeds);
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

impl UsageAnalyzer for PythonExportUsageGraphStrategy {
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
