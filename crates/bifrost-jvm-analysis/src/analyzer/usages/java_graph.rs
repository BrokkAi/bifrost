//! The analysis-side wrappers over [`brokk_bifrost_jvm::java::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the inverted pass's fan-out and its two `FileState` decoders, the
//! Java-to-Scala cross-language scan, and the dead-code bulk routing predicate.

use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
mod shared;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

use brokk_bifrost_analysis::analyzer::usages::common::with_relational_frontier;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::EdgeNodeDomain;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use crate::analyzer::usages::java_graph::shared::JavaEdgeResolver;

use crate::analyzer::usages::java_graph::shared::JavaQueryResolver;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use crate::analyzer::JavaAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_jvm::java::graph::JavaGraphSource;
use brokk_bifrost_jvm::java::graph::extractor::{
    self, JavaFileEvidenceBuildOutcome, JavaFileEvidenceOmission, JavaFileUsageEvidence,
    OwnedReturnTypeCaches, ScanState,
};
use brokk_bifrost_jvm::java::graph::inverted::{
    JavaEdgeScanCaches, scan_file as scan_inverted_file,
};
use brokk_bifrost_jvm::java::graph::resolver::{TargetKind, TargetSpec};
use brokk_bifrost_jvm::java::graph::return_type::{
    FileReturnCache, MethodAnonymousReturnCache, MethodReturnCache,
};

/// Run `visit` with the [`JavaGraphSource`] built from the *dispatching*
/// analyzer.
///
/// A callback rather than a constructor because the request-local relational
/// frontier is valid only while its owned graph computation is being evaluated.
pub(crate) fn with_java_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    mut visit: impl FnMut(JavaGraphSource<'_>) -> R,
) -> R {
    let scope = AnalyzerQueryScope::new(analyzer);
    with_relational_frontier(analyzer, "Java", |frontier| {
        visit(JavaGraphSource {
            token: scope.token(),
            index: analyzer,
            hierarchy: analyzer.type_hierarchy_provider(),
            relational_definitions: frontier,
        })
    })
}

/// Build one Java file's exact, uncapped evidence inside the shared relational
/// frontier. The returned value owns every row and can therefore be handed to
/// a snapshot cache without retaining request-local mutable state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_java_file_usage_evidence(
    relational_session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    return_caches: &OwnedReturnTypeCaches,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> JavaFileEvidenceBuildOutcome {
    let outcome = relational_session.resolve_owned("java_semantic_scan", |frontier| {
        let graph = JavaGraphSource {
            token,
            index: analyzer,
            hierarchy: analyzer.type_hierarchy_provider(),
            relational_definitions: frontier.as_ref(),
        };
        extractor::scan_file_evidence(
            java,
            token,
            &graph,
            file,
            spec,
            &return_caches.caches(),
            cancellation,
        )
    });
    match outcome {
        brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Complete(
            evidence,
        ) => evidence,
        brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Cancelled => {
            JavaFileEvidenceBuildOutcome::Cancelled
        }
        brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Failed(_) => {
            JavaFileEvidenceBuildOutcome::Omitted(JavaFileEvidenceOmission::RelationalFrontier)
        }
    }
}

pub(crate) fn merge_java_file_evidence(evidence: JavaFileUsageEvidence, state: &mut ScanState<'_>) {
    merge_java_evidence_into_state(
        evidence.hits,
        evidence.unproven_hits,
        evidence.raw_match_count,
        state,
    );
}

/// Adapt the JVM-owned producer result to the snapshot cache's owned value.
///
/// The cache deliberately has its own representation so it can account for
/// retained bytes without making the language crate depend on analysis. This
/// conversion is the only boundary between those representations; omitted
/// and cancelled producer outcomes remain non-publishable cache outcomes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_java_file_cache_evidence(
    relational_session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    return_caches: &OwnedReturnTypeCaches,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceBuildOutcome{
    match build_java_file_usage_evidence(
        relational_session,
        analyzer,
        java,
        token,
        file,
        spec,
        return_caches,
        cancellation,
    ) {
        JavaFileEvidenceBuildOutcome::Complete(evidence) => {
            brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceBuildOutcome::Complete(
                brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaFileUsageEvidence::new(
                    evidence.hits,
                    evidence.unproven_hits,
                    evidence.raw_match_count,
                ),
            )
        }
        JavaFileEvidenceBuildOutcome::Omitted(reason) => {
            brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceBuildOutcome::Omitted(
                match reason {
                    JavaFileEvidenceOmission::SourceRead => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::SourceRead
                    }
                    JavaFileEvidenceOmission::ParserSetup => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::ParserSetup
                    }
                    JavaFileEvidenceOmission::Parse => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::Parse
                    }
                    JavaFileEvidenceOmission::StoreProvider => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::StoreProvider
                    }
                    JavaFileEvidenceOmission::ClassRange => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::ClassRange
                    }
                    JavaFileEvidenceOmission::RelationalFrontier => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::RelationalFrontier
                    }
                    JavaFileEvidenceOmission::UnavailableCapability => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::UnavailableCapability
                    }
                    JavaFileEvidenceOmission::InternalSafetyCap => {
                        brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceOmission::InternalSafetyCap
                    }
                },
            )
        }
        JavaFileEvidenceBuildOutcome::Cancelled => {
            brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceBuildOutcome::Cancelled
        }
    }
}

pub(crate) fn merge_java_cached_file_evidence(
    evidence: &brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaFileUsageEvidence,
    state: &mut ScanState<'_>,
) {
    merge_java_evidence_into_state(
        evidence.hits.iter().cloned(),
        evidence.unproven_hits.iter().cloned(),
        evidence.raw_match_count,
        state,
    );
}

fn merge_java_evidence_into_state(
    hits: impl IntoIterator<Item = brokk_bifrost_core::analyzer::usages::model::UsageHit>,
    unproven_hits: impl IntoIterator<Item = brokk_bifrost_core::analyzer::usages::model::UsageHit>,
    raw_match_count: usize,
    state: &mut ScanState<'_>,
) {
    state.hits.extend(hits);
    state.unproven_hits.extend(unproven_hits);
    *state.raw_match_count += raw_match_count;
    *state.limit_exceeded =
        brokk_bifrost_core::analyzer::usages::common::external_usage_hit_count(state.hits)
            > state.max_usages;
}

pub(crate) fn build_java_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    with_java_edge_resolver(analyzer, |resolver| {
        resolver.build_edges(analyzer, nodes, keep_file)
    })
}

pub(crate) fn build_rooted_java_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    with_java_edge_resolver(analyzer, |resolver| {
        resolver.build_rooted_edges(analyzer, callers, keep_file)
    })
}

pub(crate) fn build_java_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    with_java_edge_resolver(analyzer, |resolver| {
        resolver.build_edge_weights(analyzer, nodes, keep_file)
    })
}

fn with_java_edge_resolver<'a, T>(
    analyzer: &'a dyn IAnalyzer,
    build: impl FnOnce(JavaEdgeResolver<'a>) -> T,
) -> Option<T> {
    let resolver = JavaEdgeResolver::try_new(analyzer)?;
    Some(build(resolver))
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
    token: QueryToken<'_>,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    max_usages: usize,
    hits: &mut std::collections::BTreeSet<brokk_bifrost_core::analyzer::usages::model::UsageHit>,
    unproven_hits: &mut std::collections::BTreeSet<
        brokk_bifrost_core::analyzer::usages::model::UsageHit,
    >,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded || !target.is_class() {
        return;
    }
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return;
    };
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    let relational_session =
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
            analyzer,
            &cancellation,
        );
    let Some(spec) = TargetSpec::from_targets(java, std::slice::from_ref(target)) else {
        return;
    };
    let mut state = ScanState {
        max_usages,
        hits,
        unproven_hits,
        raw_match_count,
        limit_exceeded,
    };
    let mut java_files: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| {
            brokk_bifrost_core::analyzer::common::language_for_file(file) == Language::Java
        })
        .cloned()
        .collect();
    java_files.sort();
    let return_caches = OwnedReturnTypeCaches::new(java.read_capability());
    for file in &java_files {
        match build_java_file_usage_evidence(
            &relational_session,
            analyzer,
            java,
            token,
            file,
            &spec,
            &return_caches,
            &cancellation,
        ) {
            JavaFileEvidenceBuildOutcome::Complete(evidence) => {
                merge_java_file_evidence(evidence, &mut state);
            }
            JavaFileEvidenceBuildOutcome::Omitted(reason) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!("Java file evidence omitted for {:?}: {reason:?}", file)
                });
                return;
            }
            JavaFileEvidenceBuildOutcome::Cancelled => return,
        }
        if *state.limit_exceeded {
            return;
        }
    }
    scan_scala_files_for_java_target(analyzer, candidate_files, &spec, &mut state, None);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JavaDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    _token: QueryToken<'_>,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
    static_imports_present: bool,
    scala_files_present: bool,
) -> JavaDeadCodeBulkEligibility {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(kind) = TargetSpec::kind_for_target(java, target) else {
        return JavaDeadCodeBulkEligibility::NeedsPrecise;
    };
    match kind {
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
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            JavaQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Java,
                unsupported_target: "target is not Java",
                missing_analyzer: "analyzer does not expose JavaAnalyzer",
                strategy: "JavaUsageGraphStrategy",
            },
        )
    }
}

/// Collect hits on a Java target from Scala source, when the workspace has a
/// Scala analyzer to read Scala's own imports and declarations with.
///
/// The scan is the Scala query walk itself (#1859): the walk types receivers,
/// the foreign catalog matches the owner's normalized fqn plus the member name
/// under Java's own arity rules, and a receiver that cannot be typed lands in
/// the unproven channel. What stays here is the downcast that produces the
/// scan's `ScalaSource`.
///
/// `false` when the Scala frontier failed, so the Scala half of the answer is
/// incomplete.
pub(crate) fn scan_scala_files_for_java_target(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut brokk_bifrost_jvm::java::graph::extractor::ScanState<'_>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> bool {
    let Some(scala) = resolve_analyzer::<crate::analyzer::ScalaAnalyzer>(analyzer) else {
        return true;
    };
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return true;
    };
    scan_scala_files_for_foreign_target(
        analyzer,
        scala,
        java,
        candidate_files,
        spec,
        state,
        cancellation,
    )
}

/// One foreign catalog for the Java (or other JVM-language) target family,
/// then the ordinary per-file Scala query scan on the query's relational
/// frontier, with a hit sink that also keeps unproven receiver references.
/// The walk's realm questions -- is this spelling a Java or Kotlin class? --
/// go through the same frontier, so they batch in its barriers instead of
/// costing one synchronous store read per candidate spelling.
fn scan_scala_files_for_foreign_target(
    analyzer: &dyn IAnalyzer,
    scala: &crate::analyzer::ScalaAnalyzer,
    java: &JavaAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut brokk_bifrost_jvm::java::graph::extractor::ScanState<'_>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
) -> bool {
    use brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome;

    use crate::analyzer::usages::scala_graph::shared::ScalaFrontierScan;

    use crate::analyzer::usages::scala_graph::shared::ScalaFrontierSeedOutcome;

    use crate::analyzer::usages::scala_graph::shared::foreign_jvm_languages;

    use crate::analyzer::usages::scala_graph::shared::prepare_scala_files;
    use brokk_bifrost_jvm::scala::graph::query::{ScalaFileEligibility, ScalaQueryTargetCatalog};

    // Subtype receivers (#1859): a receiver typed as a descendant of the Java
    // owner dispatches to the inherited member, so the catalog's owner set is
    // the receiver set plus every descendant the dispatching analyzer can see.
    // The realm hierarchy is one-directional: a Scala class extending a Java
    // base records no ancestor edge, so a Scala-subclass receiver stays a
    // documented miss until that hierarchy work lands.
    let mut receiver_owners = spec.receiver_owner_fq_names.clone();
    if matches!(spec.kind, TargetKind::Method | TargetKind::Field)
        && let Some(hierarchy) = analyzer.type_hierarchy_provider()
    {
        for descendant in hierarchy.get_descendants(&spec.owner) {
            if descendant.is_class() {
                receiver_owners.insert(descendant.fq_name());
            }
        }
    }
    let catalog = ScalaQueryTargetCatalog::build_foreign_jvm(spec, java, &receiver_owners);
    let member_name = spec.member_name.as_str();
    let owner_name = spec.owner.identifier();
    let mut files: Vec<(ProjectFile, ScalaFileEligibility)> = candidate_files
        .iter()
        .filter(|file| {
            brokk_bifrost_core::analyzer::common::language_for_file(file) == Language::Scala
        })
        .cloned()
        .map(|file| (file, ScalaFileEligibility::All))
        .collect();
    files.sort_by(|(left, _), (right, _)| left.cmp(right));
    let uncancelled = brokk_bifrost_core::cancellation::CancellationToken::new();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let scan = match ScalaFrontierScan::seed(scala, analyzer, cancellation) {
        ScalaFrontierSeedOutcome::Ready(scan) => scan,
        ScalaFrontierSeedOutcome::Cancelled => return true,
        ScalaFrontierSeedOutcome::Failed(reason) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!("Scala scan for a JVM target skipped: {reason}")
            });
            return false;
        }
    };
    // The retired scanner's cheap gate: a file that spells neither the
    // member nor its owner cannot reference the target.
    let prepared = prepare_scala_files(analyzer, scala, files, cancellation, |source| {
        source.contains(member_name) || source.contains(owner_name)
    });
    let scan_files: Vec<ProjectFile> = prepared.iter().map(|file| file.file.clone()).collect();
    scan.prefetch_file_facts(&scan_files);
    let realm_languages = foreign_jvm_languages(analyzer);
    let scope = AnalyzerQueryScope::new(analyzer);
    let results = match scan.scan(
        analyzer,
        scope.token(),
        &prepared,
        &catalog,
        1,
        state.max_usages,
        Some(&realm_languages),
        true,
    ) {
        RelationalItemFrontierOutcome::Complete(results) => {
            results.into_iter().map(Some).collect::<Vec<_>>()
        }
        RelationalItemFrontierOutcome::Cancelled(results) => results,
        RelationalItemFrontierOutcome::Failed(error) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "Scala file frontier failed for a JVM target: {}",
                    error.message()
                )
            });
            return false;
        }
    };
    for file_scan in results.into_iter().flatten() {
        for target_hits in file_scan.hits {
            state.hits.extend(target_hits);
        }
        state.unproven_hits.extend(file_scan.unproven_hits);
        *state.limit_exceeded |= file_scan.limit_exceeded;
    }
    true
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
    file_states: &brokk_bifrost_core::hash::HashMap<
        ProjectFile,
        brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
    >,
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> Output
where
    Output: brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();

    use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_edge_output;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_file_declarations_from_state_with_file_scope;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_file_declarations_with_file_scope;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::class_range_index_from_state;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::parse_and_collect_with_declarations_and_domain;

    let language = tree_sitter_java::LANGUAGE.into();
    let method_return_cache: MethodReturnCache = Default::default();
    let method_anonymous_return_cache: MethodAnonymousReturnCache = Default::default();
    let file_return_cache: FileReturnCache = Default::default();
    let reads = java.read_capability();
    let caches = JavaEdgeScanCaches {
        reads: &reads,
        method_return: &method_return_cache,
        method_anonymous_return: &method_anonymous_return_cache,
        file_return: &file_return_cache,
    };
    with_java_graph_source(analyzer, |graph| {
        build_edge_output(files, &keep_file, |file| {
            let state = file_states.get(file);
            let include_file_scope =
                brokk_bifrost_analysis::analyzer::common::is_java_module_descriptor_file(file);
            let mut declarations = state
                .map(|state| {
                    build_file_declarations_from_state_with_file_scope(state, include_file_scope)
                })
                .unwrap_or_else(|| {
                    build_file_declarations_with_file_scope(analyzer, file, include_file_scope)
                });
            if include_file_scope {
                let file_scope = CodeUnit::file_scope(file.clone());
                let file_scope_key = file_scope.fq_name();
                if !declarations
                    .enclosers
                    .iter()
                    .any(|(_, _, key)| key == &file_scope_key)
                    && let Some(source) = analyzer.indexed_source(file)
                {
                    declarations.add_file_scope(file_scope, source.len());
                }
            }
            let class_ranges = state
                .map(class_range_index_from_state)
                .unwrap_or_else(|| ClassRangeIndex::build(analyzer, file));
            parse_and_collect_with_declarations_and_domain(
                file,
                domain,
                ParseSpec::whole(&language),
                declarations,
                |input| scan_inverted_file(java, token, &graph, file, input, class_ranges, &caches),
            )
        })
    })
}

#[cfg(test)]
mod relational_inverted_tests {

    use crate::analyzer::usages::java_graph::*;

    use crate::analyzer::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_core::analyzer::usages::model::{FuzzyResult, UsageHitKind, UsageProof};
    use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
    use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6942: scan_node recursion depth followed source nesting"
    )]
    fn java_scan_node_deep_parentheses_are_stack_safe() {
        let depth = 3000;
        let source = format!(
            "class Target {{ int run() {{ int value = {}0{}; Target ref = null; return value; }} }}",
            "(".repeat(depth),
            ")".repeat(depth)
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let mut wrappers = 0;
        brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder(
            tree.root_node(),
            true,
            |node| {
                if node.kind() == "parenthesized_expression" {
                    wrappers += 1;
                }
                brokk_bifrost_core::analyzer::tree_walk::WalkControl::Continue
            },
        );
        assert_eq!(wrappers, depth);
        eprintln!("scan_node: parsed {wrappers} parenthesized expressions");
        let project = InlineTestProject::with_language(Language::Java)
            .file("Target.java", &source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let target = analyzer
            .get_definitions("Target")
            .into_iter()
            .find(CodeUnit::is_class)
            .unwrap();
        let spec = TargetSpec::from_target(&analyzer, &target).unwrap();
        let file = project.file("Target.java");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    with_java_graph_source(&analyzer, |graph| {
                        let caches = OwnedReturnTypeCaches::new(analyzer.read_capability());
                        let outcome = extractor::scan_file_evidence(
                            &analyzer,
                            graph.token,
                            &graph,
                            &file,
                            &spec,
                            &caches.caches(),
                            &brokk_bifrost_core::cancellation::CancellationToken::new(),
                        );
                        let JavaFileEvidenceBuildOutcome::Complete(evidence) = outcome else {
                            panic!("scan did not complete");
                        };
                        assert!(
                            !evidence.hits.is_empty(),
                            "the reference after the nested expression must be visited"
                        );
                    });
                })
                .unwrap()
                .join()
                .unwrap();
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "65ea4f91bb3b: Java inverse references omitted physical copies that shared an FQN"
    )]
    fn java_type_reference_reaches_each_duplicate_source_copy() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "copy-one/api/Owner.java",
                "package api; public class Owner {}\n",
            )
            .file(
                "copy-two/api/Owner.java",
                "package api; public class Owner {}\n",
            )
            .file(
                "consumer/app/Consumer.java",
                "package app; import api.Owner; public class Consumer { Owner value; }\n",
            )
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let targets: Vec<_> = analyzer
            .get_definitions("api.Owner")
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
        assert_eq!(2, targets.len());
        let candidates = analyzer
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let scan_scope = UsageScanScope::new(&candidates);

        for target in &targets {
            let outcome = JavaUsageGraphStrategy::new()
                .find_graph_usages(&analyzer, std::slice::from_ref(target), &scan_scope, 100)
                .into_fuzzy_result();
            let FuzzyResult::Success {
                hits_by_overload, ..
            } = &outcome
            else {
                panic!("expected complete Java type usages for {target:?}: {outcome:#?}");
            };
            let target_hits = hits_by_overload.get(target).unwrap_or_else(|| {
                panic!("missing hit bucket for {target:?}: {hits_by_overload:#?}")
            });
            assert!(
                target_hits
                    .iter()
                    .any(|hit| hit.kind == UsageHitKind::Reference
                        && hit.proof == UsageProof::Proven
                        && hit.snippet.contains("Owner value")),
                "each physical source copy must receive the proven FQ reference: {outcome:#?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4271: a Java comment in the argument list shifted inverse overload arity"
    )]
    fn java_inverse_receiver_overload_arity_ignores_comment_extra_node() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "app/Owner.java",
                "package app;\n\
                 class PairResult { void target() {} }\n\
                 class TripleResult { void target() {} }\n\
                 public class Owner {\n\
                     PairResult foo(Object a, Object b) { return null; }\n\
                     TripleResult foo(Object a, Object b, Object c) { return null; }\n\
                     void caller(Object a, Object b) { foo(a /* note */, b).target(); }\n\
                 }\n",
            )
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let target = analyzer
            .get_definitions("app.PairResult.target")
            .into_iter()
            .find(CodeUnit::is_function)
            .expect("two-argument overload result method");
        let three_argument_target = analyzer
            .get_definitions("app.TripleResult.target")
            .into_iter()
            .find(CodeUnit::is_function)
            .expect("three-argument overload result method");
        let caller = analyzer
            .get_definitions("app.Owner.caller")
            .into_iter()
            .find(CodeUnit::is_function)
            .expect("caller method");
        let pair_fqn = target.fq_name();
        let triple_fqn = three_argument_target.fq_name();
        let caller_fqn = caller.fq_name();
        let graph = build_java_usage_edges(
            &analyzer,
            &HashSet::from_iter([pair_fqn.clone(), triple_fqn.clone(), caller_fqn]),
            |_| true,
        )
        .expect("Java inverse usage graph");
        assert!(
            graph.edges.keys().any(|(_, callee)| callee == &pair_fqn),
            "the commented two-argument call must resolve through PairResult"
        );
        assert!(
            !graph.edges.keys().any(|(_, callee)| callee == &triple_fqn),
            "the commented two-argument call must not resolve through TripleResult"
        );
    }

    #[test]
    fn java_path_scoped_method_scan_reuses_answers_without_global_descendant_index() {
        const CANDIDATE_COUNT: usize = 24;
        const UNRELATED_COUNT: usize = 64;

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "Service.java")
            .write("package api; public class Service { public void run() {} }\n")
            .expect("write Java target");
        let mut candidates = HashSet::default();
        for index in 0..CANDIDATE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("Consumer{index}.java"));
            file.write(format!(
                "package app; import api.Service;\n\
                 class Consumer{index} {{\n\
                     Service service = new Service();\n\
                     void call() {{ service.run(); }}\n\
                 }}\n"
            ))
            .expect("write Java consumer");
            candidates.insert(file);
        }
        for index in 0..UNRELATED_COUNT {
            let file = ProjectFile::new(root.clone(), format!("Unrelated{index}.java"));
            file.write(format!(
                "package unrelated;\n\
                 class Other{index} {{}}\n\
                 class Unrelated{index} {{ Other{index} value; }}\n"
            ))
            .expect("write unrelated Java candidate");
            candidates.insert(file);
        }
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "api.Service.run")
            .expect("fixture declares Service.run");
        let scope = UsageScanScope::new(&candidates);
        analyzer.reset_hierarchy_query_counts_for_test();
        let before = analyzer.relational_batch_reader_checkouts_for_test();

        let outcome = JavaUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scope, 1000)
            .into_fuzzy_result();

        let reader_checkouts = analyzer.relational_batch_reader_checkouts_for_test() - before;
        assert_eq!(
            analyzer.hierarchy_bulk_hydration_count_for_test(),
            0,
            "a path-scoped method scan must not build the workspace descendant index"
        );
        assert!(
            outcome.all_hits_including_imports().len() >= CANDIDATE_COUNT,
            "every candidate must retain its structured type reference: {outcome:?}"
        );
        assert!(
            reader_checkouts < CANDIDATE_COUNT,
            "one path-scoped query must skip ASTs without the target terminal and reuse converged answers for relevant files: {reader_checkouts} reader checkouts for {} candidates",
            CANDIDATE_COUNT + UNRELATED_COUNT,
        );
    }
}

#[cfg(test)]
mod return_cache_read_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::project_reads::ReadCapability;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
    use brokk_bifrost_jvm::java::graph::extractor::ReturnTypeCaches;
    use brokk_bifrost_jvm::java::graph::return_type::{
        JavaReturnTypeContext, method_return_type_for_owner_fqn,
    };
    use brokk_bifrost_jvm::java::graph_support::JavaSource;

    // The selector already owns its method declaration, as a converged
    // relational frontier does. Selecting it must not incidentally record the
    // return-facts file and mask a missing memo replay.
    struct SelectedMethod<'a> {
        java: &'a JavaAnalyzer,
        frontier: &'a dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier,
        method: CodeUnit,
        file: &'a ProjectFile,
        root: tree_sitter::Node<'a>,
        caches: ReturnTypeCaches<'a>,
    }
    impl JavaReturnTypeContext for SelectedMethod<'_> {
        fn read_capability(&self) -> &ReadCapability {
            self.caches.reads
        }
        fn java(&self) -> &dyn JavaSource {
            self.java
        }
        fn relational_definitions(
            &self,
        ) -> &dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier {
            self.frontier
        }
        fn call_answering_units(&self, owner: &str, name: &str, arity: usize) -> Vec<CodeUnit> {
            assert_eq!((owner, name, arity), ("lib.Factory", "make", 0));
            vec![self.method.clone()]
        }
        fn file(&self) -> &ProjectFile {
            self.file
        }
        fn source(&self) -> &str {
            "package app; class Caller {}"
        }
        fn root(&self) -> tree_sitter::Node<'_> {
            self.root
        }
        fn method_return_cache(&self) -> &MethodReturnCache {
            self.caches.method_return
        }
        fn method_anonymous_return_cache(&self) -> &MethodAnonymousReturnCache {
            self.caches.method_anonymous_return
        }
        fn file_return_cache(&self) -> &FileReturnCache {
            self.caches.file_return
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: Java return-type hits lost the other file's source-fact reads"
    )]
    fn return_type_hits_replay_cross_file_inputs() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file(
                "lib/Factory.java",
                "package lib; class Factory { static class Product {} static Product make() { return null; } }",
            )
            .file("app/Caller.java", "package app; class Caller {}")
            .build();
        let java = JavaAnalyzer::new(project.project_arc());
        let method = java
            .all_declarations()
            .find(|unit| unit.is_function() && unit.identifier() == "make")
            .unwrap();
        let file = project.file("app/Caller.java");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse("package app; class Caller {}", None).unwrap();
        let owner = OwnedReturnTypeCaches::new(java.read_capability());
        with_java_graph_source(&java, |graph| {
            let context = SelectedMethod {
                java: &java,
                frontier: graph.relational_definitions,
                method: method.clone(),
                file: &file,
                root: tree.root_node(),
                caches: owner.caches(),
            };
            let read = |context: &SelectedMethod<'_>| {
                let result = method_return_type_for_owner_fqn(
                    "lib.Factory",
                    graph.token,
                    "make",
                    0,
                    context,
                );
                assert_eq!(
                    result,
                    ReceiverAnalysisOutcome::Precise(vec!["lib.Factory.Product".to_owned()])
                );
            };
            read(&context);
            let (_, method_reads) = capture_query_reads(&java, || read(&context));
            // A fresh method memo forces the independently warm file-facts
            // memo to supply its own receipt in the next capture.
            let method_cache = MethodReturnCache::default();
            let anonymous_cache = MethodAnonymousReturnCache::default();
            let context = SelectedMethod {
                caches: ReturnTypeCaches {
                    reads: context.caches.reads,
                    method_return: &method_cache,
                    method_anonymous_return: &anonymous_cache,
                    file_return: context.caches.file_return,
                },
                ..context
            };
            let (_, file_reads) = capture_query_reads(&java, || read(&context));
            for reads in [method_reads, file_reads] {
                assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
                assert!(
                    reads.keys().iter().any(|key| matches!(key,
                        ReadKey::File { rel_path, .. } if rel_path.as_ref() == "lib/Factory.java"
                    )),
                    "each warm return projection must replay its file: {reads:?}"
                );
            }
        });
    }
}
