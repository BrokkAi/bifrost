mod extractor;
mod hits;
mod resolver;

use crate::analyzer::usages::common::language_for_target;
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

#[derive(Default)]
pub struct PythonExportUsageGraphStrategy {
    _private: (),
}

impl PythonExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
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
            seeds.extend(
                graph
                    .usage_graph
                    .seeds_for_target(target.source(), &seed_name),
            );
        }
        if seeds.is_empty() {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::NoGraphSeed("export graph produced no seeds"),
                "PythonExportUsageGraphStrategy",
            );
        }

        let scan_files = graph.scan_files(candidate_files, target.source());

        let hits = scan_files_for_seeds(analyzer, &graph, &scan_files, target, &seeds);
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
