mod extractor;
mod hits;
mod inverted;
mod jvm_scala;
mod resolver;
pub(super) mod return_type;
mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::java_graph::resolver::{TargetKind, TargetSpec};
use crate::analyzer::usages::java_graph::shared::{JavaEdgeResolver, JavaQueryResolver};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;

pub(in crate::analyzer::usages) use resolver::signature_arity as java_signature_arity;

pub(crate) fn build_java_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JavaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_java_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JavaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

/// Collect hits on a JVM *type* target declared in another JVM language from
/// Java and Scala source.
///
/// The mirror of `kotlin_graph::scan_kotlin_files_for_jvm_type`. Java's scan and
/// its Scala scanner both resolve a written type name through the file's own
/// import and package rules against the realm-wide declaration index, so what a
/// Kotlin class needs from them is the file set, not new resolution.
///
/// Type targets only, for the same reason as the Kotlin direction: a member
/// reference binds by the *target* language's member-lookup rules, and answering
/// one language's member question with another's would be guessing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_jvm_files_for_foreign_type(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    max_usages: usize,
    hits: &mut std::collections::BTreeSet<crate::analyzer::usages::model::UsageHit>,
    unproven_hits: &mut std::collections::BTreeSet<crate::analyzer::usages::model::UsageHit>,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded || !target.is_class() {
        return;
    }
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return;
    };
    let Some(spec) = TargetSpec::from_target(java, target) else {
        return;
    };
    let mut state = extractor::ScanState {
        max_usages,
        hits,
        unproven_hits,
        raw_match_count,
        limit_exceeded,
    };
    let method_return_cache = std::sync::Mutex::new(crate::hash::HashMap::default());
    let method_anonymous_return_cache = std::sync::Mutex::new(crate::hash::HashMap::default());
    let file_return_cache = std::sync::Mutex::new(crate::hash::HashMap::default());
    let return_caches = extractor::ReturnTypeCaches {
        method_return: &method_return_cache,
        method_anonymous_return: &method_anonymous_return_cache,
        file_return: &file_return_cache,
    };
    let mut java_files: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| crate::analyzer::usages::common::language_for_file(file) == Language::Java)
        .cloned()
        .collect();
    java_files.sort();
    for file in java_files {
        extractor::scan_file(java, analyzer, &file, &spec, &return_caches, &mut state);
        if *state.limit_exceeded {
            return;
        }
    }
    jvm_scala::scan_scala_files_for_java_target(analyzer, candidate_files, &spec, &mut state, None);
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
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(spec) = TargetSpec::from_target(java, target) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type if scala_files_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Type => JavaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Method if scala_files_present => JavaDeadCodeBulkEligibility::NeedsPrecise,
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
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Java
    }
}

impl GraphUsageAnalyzer for JavaUsageGraphStrategy {
    fn find_graph_usages(
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
        if language_for_target(target) != Language::Java {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Java"),
                "JavaUsageGraphStrategy",
            );
        }

        let Some(resolver) = JavaQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose JavaAnalyzer",
                ),
                "JavaUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
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
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}
