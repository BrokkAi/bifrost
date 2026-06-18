mod extractor;
mod hits;
mod inverted;
mod jvm_scala;
mod resolver;
mod shared;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::java_graph::resolver::{
    TargetKind, TargetSpec, resolve_java_analyzer,
};
use crate::analyzer::usages::java_graph::shared::{JavaEdgeResolver, JavaQueryResolver};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;

pub(crate) fn build_java_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JavaEdgeResolver::new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JavaDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
    static_imports_present: bool,
    scala_files_present: bool,
) -> JavaDeadCodeBulkEligibility {
    let Some(java) = resolve_java_analyzer(analyzer) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(spec) = TargetSpec::from_target(java, target) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type if scala_files_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Type => JavaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Method if static_imports_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Method if overloaded_fqns.contains(target.fq_name().as_str()) => {
            JavaDeadCodeBulkEligibility::NeedsPrecise
        }
        TargetKind::Method => JavaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Constructor | TargetKind::Field => JavaDeadCodeBulkEligibility::NeedsPrecise,
    }
}

#[derive(Default)]
pub struct JavaUsageGraphStrategy {
    _private: (),
}

impl JavaUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Java
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
        if language_for_target(target) != Language::Java {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Java"),
                "JavaUsageGraphStrategy",
            );
        }

        let Some(resolver) = JavaQueryResolver::new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose JavaAnalyzer",
                ),
                "JavaUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, target, candidate_files, max_usages)
    }
}

impl UsageAnalyzer for JavaUsageGraphStrategy {
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
