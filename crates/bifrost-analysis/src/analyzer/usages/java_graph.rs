//! The analysis-side wrappers over [`brokk_bifrost_jvm::java::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the inverted pass's fan-out and its two `FileState` decoders, the
//! Java-to-Scala cross-language scan, and the dead-code bulk routing predicate.

mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::java_graph::shared::{JavaEdgeResolver, JavaQueryResolver};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile,
    resolve_analyzer,
};
use crate::hash::HashSet;
use brokk_bifrost_jvm::java::graph::JavaGraphSource;
use brokk_bifrost_jvm::java::graph::extractor::{self, ReturnTypeCaches, ScanState};
use brokk_bifrost_jvm::java::graph::inverted::{
    JavaEdgeScanCaches, scan_file as scan_inverted_file,
};
use brokk_bifrost_jvm::java::graph::resolver::{TargetKind, TargetSpec};
use brokk_bifrost_jvm::java::graph::return_type::{
    FileReturnCache, MethodAnonymousReturnCache, MethodReturnCache,
};
use std::sync::Mutex;

pub(in crate::analyzer::usages) use brokk_bifrost_jvm::java::graph::resolver::signature_arity as java_signature_arity;

/// Run `visit` with the [`JavaGraphSource`] built from the *dispatching*
/// analyzer.
///
/// A callback rather than a constructor because the definition-index accessor is
/// itself a borrowed closure: `analyzer.global_usage_definition_index()` returns
/// a handle that borrows the analyzer and merges one shard per delegate, and the
/// Java side takes it lazily so a scan that never reaches a realm-wide lookup
/// never pays for the merge.
pub(in crate::analyzer::usages) fn with_java_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    visit: impl FnOnce(JavaGraphSource<'_>) -> R,
) -> R {
    let definitions = |consume: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| {
        consume(&analyzer.global_usage_definition_index());
    };
    let import_statements = |file: &ProjectFile| analyzer.import_statements(file);
    visit(JavaGraphSource {
        index: analyzer,
        hierarchy: analyzer.type_hierarchy_provider(),
        definitions: &definitions,
        import_statements: &import_statements,
    })
}

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
    let mut state = ScanState {
        max_usages,
        hits,
        unproven_hits,
        raw_match_count,
        limit_exceeded,
    };
    let method_return_cache = Mutex::new(crate::hash::HashMap::default());
    let method_anonymous_return_cache = Mutex::new(crate::hash::HashMap::default());
    let file_return_cache = Mutex::new(crate::hash::HashMap::default());
    let return_caches = ReturnTypeCaches {
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
    with_java_graph_source(analyzer, |graph| {
        for file in java_files {
            extractor::scan_file(java, &graph, &file, &spec, &return_caches, &mut state);
            if *state.limit_exceeded {
                return;
            }
        }
        scan_scala_files_for_java_target(analyzer, candidate_files, &spec, &mut state, None);
    });
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

/// Collect hits on a Java target from Scala source, when the workspace has a
/// Scala analyzer to read Scala's own imports and declarations with.
///
/// The scan itself is [`brokk_bifrost_jvm::java::graph::jvm_scala`]; what stays
/// here is the downcast that produces its `ScalaSource`.
pub(in crate::analyzer::usages) fn scan_scala_files_for_java_target(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut brokk_bifrost_jvm::java::graph::extractor::ScanState<'_>,
    cancellation: Option<&crate::cancellation::CancellationToken>,
) {
    let Some(scala) = resolve_analyzer::<crate::analyzer::ScalaAnalyzer>(analyzer) else {
        return;
    };
    brokk_bifrost_jvm::java::graph::jvm_scala::scan_scala_files_for_java_target(
        analyzer,
        scala,
        candidate_files,
        spec,
        state,
        cancellation,
    );
}

/// The whole-workspace inverted pass: the shared driver's parallel fan-out plus
/// on-demand parsing, with
/// [`brokk_bifrost_jvm::java::graph::inverted::scan_file`] resolving each file.
///
/// The two per-file indexes are built here rather than crate-side because both
/// have a `FileState` fast path, and `FileState` is analysis-crate-private
/// (Ruby's `forward_owner_relation_facts` precedent: decode on this side, hand
/// the decoded facts across).
fn build_java_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    files: &[ProjectFile],
    file_states: &crate::hash::HashMap<
        ProjectFile,
        crate::analyzer::tree_sitter_analyzer::FileState,
    >,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: crate::analyzer::usages::inverted_edges::UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    use crate::analyzer::usages::inverted_edges::{
        ClassRangeIndex, build_edge_output, build_file_declarations,
        build_file_declarations_from_state, class_range_index_from_state,
        parse_and_collect_with_declarations,
    };

    let language = tree_sitter_java::LANGUAGE.into();
    let method_return_cache: MethodReturnCache = Mutex::new(crate::hash::HashMap::default());
    let method_anonymous_return_cache: MethodAnonymousReturnCache =
        Mutex::new(crate::hash::HashMap::default());
    let file_return_cache: FileReturnCache = Mutex::new(crate::hash::HashMap::default());
    let caches = JavaEdgeScanCaches {
        method_return: &method_return_cache,
        method_anonymous_return: &method_anonymous_return_cache,
        file_return: &file_return_cache,
    };
    with_java_graph_source(analyzer, |graph| {
        build_edge_output(files, keep_file, |file| {
            let state = file_states.get(file);
            let declarations = state
                .map(build_file_declarations_from_state)
                .unwrap_or_else(|| build_file_declarations(analyzer, file));
            let class_ranges = state
                .map(class_range_index_from_state)
                .unwrap_or_else(|| ClassRangeIndex::build(analyzer, file));
            parse_and_collect_with_declarations(file, nodes, &language, declarations, |input| {
                scan_inverted_file(java, &graph, file, input, class_ranges, &caches)
            })
        })
    })
}
