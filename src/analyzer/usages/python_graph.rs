mod extractor;
mod hits;
mod inverted;
mod resolver;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::python_graph::extractor::{build_python_graph, scan_files_for_seeds};
use crate::analyzer::usages::python_graph::resolver::{infer_export_names, infer_usage_seeds};
use crate::analyzer::usages::traits::{
    UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, PythonAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(in crate::analyzer::usages) use extractor::{
    collect_assigned_identifiers, collect_scope_facts_from_parsed_source, enclosing_scope_facts,
    is_declaration_identifier, slice as python_slice,
};
pub(in crate::analyzer::usages) use resolver::resolve_receiver_type;

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
    let resolver = PythonEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) struct PythonQueryResolver<'a> {
    py: &'a PythonAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for PythonQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            py: resolve_analyzer::<PythonAnalyzer>(analyzer)?,
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
        let py = self.py;
        let candidate_files = scan_scope.candidate_files();

        let graph = build_python_graph(py, candidate_files, target.source());
        let seed_names = infer_export_names(py, target);
        if seed_names.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("no export seed resolved"),
                "PythonExportUsageGraphStrategy",
            );
        }

        let seeds = infer_usage_seeds(py, target, seed_names);
        if seeds.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("export graph produced no seeds"),
                "PythonExportUsageGraphStrategy",
            );
        }

        let mut scan_files = graph.scan_files(candidate_files, target.source());
        if scan_scope.is_authoritative() {
            scan_files.retain(|file| scan_scope.allows(file));
        }

        let scan_result = scan_files_for_seeds(
            analyzer,
            py,
            &graph,
            &scan_files,
            target,
            &seeds,
            scan_scope.cancellation(),
        );
        let hits: BTreeSet<UsageHit> = scan_result
            .hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();
        let unproven_hits: BTreeSet<UsageHit> = scan_result
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
}

pub(crate) struct PythonEdgeResolver<'a> {
    py: &'a PythonAnalyzer,
}

impl<'a> UsageEdgeResolver<'a> for PythonEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
        // No Python files → no edges to build; mirror the other languages' guard.
        if py.get_analyzed_files().is_empty() {
            return None;
        }
        Some(Self { py })
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
        inverted::build_python_edges(analyzer, self.py, nodes, keep_file)
    }
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
        scan_scope: &UsageScanScope<'_>,
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

        let Some(resolver) = PythonQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose PythonAnalyzer",
                ),
                "PythonExportUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
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
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}
