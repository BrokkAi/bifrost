mod extractor;
mod hits;
mod resolver;

use crate::analyzer::usages::common::{language_for_file, language_for_target};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::php_graph::extractor::scan_file;
use crate::analyzer::usages::php_graph::resolver::{
    PhpHierarchyIndex, TargetKind, TargetSpec, resolve_php_analyzer,
};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

#[derive(Default)]
pub struct PhpUsageGraphStrategy {
    _private: (),
}

impl PhpUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Php
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
        if language_for_target(target) != Language::Php {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not PHP"),
                "PhpUsageGraphStrategy",
            );
        }

        let Some(php) = resolve_php_analyzer(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose PhpAnalyzer",
                ),
                "PhpUsageGraphStrategy",
            );
        };

        let Some(spec) = TargetSpec::from_target(php, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("unsupported target shape"),
                "PhpUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Php)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let hierarchy = matches!(spec.kind, TargetKind::Method | TargetKind::Field)
            .then(|| PhpHierarchyIndex::build(php, &files));
        let empty_hierarchy = PhpHierarchyIndex::default();
        let hierarchy = hierarchy.as_ref().unwrap_or(&empty_hierarchy);
        let mut hits = BTreeSet::new();
        for file in files {
            scan_file(php, analyzer, &file, &spec, hierarchy, &mut hits);
            if hits.len() > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
                });
            }
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

impl UsageAnalyzer for PhpUsageGraphStrategy {
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
