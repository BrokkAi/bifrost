//! The two Kotlin usage resolvers — one per usage path.
//!
//! `usages/traits.rs` defines one resolver trait per usage path and requires one
//! impl of each per graph language, so that "both usage paths share one target
//! model" is a contract rather than a convention. [`KotlinQueryResolver`]
//! answers "who uses *this* declaration?" for `scan_usages`, LSP references, and
//! rename; [`KotlinEdgeResolver`] builds the whole `caller -> callee` edge set in
//! one inverted pass for `usage_graph`, `callers`/`callees`, relevance ranking,
//! and dead code. Both drive the same receiver typing, member lookup, and name
//! ladder through `super::resolver::KotlinResolutionCtx`.

use crate::analyzer::usages::kotlin_graph::KotlinFileScanOutput;

use brokk_bifrost_jvm::kotlin::graph::KotlinGraphSource;

use crate::analyzer::usages::kotlin_graph::PreparedKotlinScanFile;

use crate::analyzer::usages::kotlin_graph::kotlin_target_spec_replayable;

use crate::analyzer::usages::kotlin_graph::prepare_kotlin_scan_files;

use crate::analyzer::usages::kotlin_graph::scan_kotlin_files_replayable;

use crate::analyzer::usages::kotlin_graph::with_kotlin_graph_source;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

use brokk_bifrost_core::analyzer::common::language_for_file;

use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::EdgeNodeDomain;

use brokk_bifrost_core::analyzer::usages::inverted_edges::FileDeclarations;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_core::analyzer::usages::model::UsageHit;

use brokk_bifrost_core::analyzer::usages::outcome::GraphFailureReason;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;

use brokk_bifrost_core::analyzer::usages::parsed_tree::ParsedTreeFile;

use brokk_bifrost_core::analyzer::usages::parsed_tree::parse_tree_sitter_file;

use brokk_bifrost_core::analyzer::usages::parsed_tree::parse_tree_sitter_source;

use brokk_bifrost_analysis::analyzer::usages::traits::UsageQueryResolver;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use crate::analyzer::KotlinAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_jvm::kotlin::graph::inverted::scan_file as scan_inverted_file;
use brokk_bifrost_jvm::kotlin::graph::resolver::TargetSpec;
use std::collections::BTreeSet;

/// Resolves usages of one Kotlin target within a candidate file set.
///
/// Carries no state: everything a scan needs is derived per file, and the only
/// job of [`UsageQueryResolver::try_new`] here is the capability check — an
/// analyzer that cannot produce a `KotlinAnalyzer` cannot answer a Kotlin query,
/// and the strategy reports that as a missing capability rather than as an
/// absence of references.
pub(crate) struct KotlinQueryResolver;

impl<'a> UsageQueryResolver<'a> for KotlinQueryResolver {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        resolve_analyzer::<KotlinAnalyzer>(analyzer).map(|_| Self)
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let uncancelled = brokk_bifrost_core::cancellation::CancellationToken::new();
        let cancellation = scan_scope.cancellation().unwrap_or(&uncancelled);
        let relational_session =
            brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
                analyzer,
                cancellation,
            );
        let _spec_scope = brokk_bifrost_core::profiling::scope("kotlin_graph::target_spec");
        let spec =
            match kotlin_target_spec_replayable(&relational_session, analyzer, token, overloads) {
                brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Complete(Some(spec)) => spec,
                brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Complete(None) => {
                    return GraphUsageOutcome::fallback_safe(
                        target.fq_name(),
                        GraphFailureReason::UnsupportedTargetShape(
                            "Kotlin target has no indexed owner to resolve references against",
                        ),
                        "KotlinUsageGraphStrategy",
                    );
                }
                brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Cancelled => {
                    return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
                }
                brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Failed(_) => {
                    return GraphUsageOutcome::fallback_safe(
                        target.fq_name(),
                        GraphFailureReason::UnsupportedTargetShape(
                            "the Kotlin relational target frontier failed",
                        ),
                        "KotlinUsageGraphStrategy",
                    );
                }
            };
        drop(_spec_scope);

        let _select_scope = brokk_bifrost_core::profiling::scope("kotlin_graph::select_files");
        let mut files: HashSet<ProjectFile> = scan_scope
            .candidate_files()
            .iter()
            .filter(|file| language_for_file(file) == Language::Kotlin)
            .cloned()
            .collect();
        // The declaration's own file is always in scope: a type is regularly
        // referenced beside its own declaration, and omitting it would report
        // those references as absent rather than as out of scope.
        if language_for_file(target.source()) == Language::Kotlin
            && scan_scope.allows(target.source())
        {
            files.insert(target.source().clone());
        }
        let mut ordered: Vec<ProjectFile> = files.into_iter().collect();
        // Deterministic file order, so a truncated result truncates the same way
        // on every run.
        ordered.sort();
        drop(_select_scope);

        let _prepare_scope = brokk_bifrost_core::profiling::scope("kotlin_graph::prepare_files");
        let prepared_files = prepare_kotlin_scan_files(analyzer, &ordered);
        drop(_prepare_scope);

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        match scan_and_merge_kotlin_files(
            &relational_session,
            analyzer,
            token,
            &prepared_files,
            &spec,
            max_usages,
            &mut hits,
            &mut unproven_hits,
            &mut raw_match_count,
            &mut limit_exceeded,
        ) {
            KotlinPreparedScanStatus::Complete | KotlinPreparedScanStatus::Cancelled => {}
            KotlinPreparedScanStatus::Failed => {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape(
                        "the Kotlin relational file frontier failed",
                    ),
                    "KotlinUsageGraphStrategy",
                );
            }
        };
        // A Kotlin class is equally nameable from Java and Scala source, and the
        // three languages share one candidate space, so find-references on a
        // Kotlin type must see those call sites too (#1239 milestone 4).
        if !scan_scope.is_cancelled() {
            let _cross_scope = brokk_bifrost_core::profiling::scope("kotlin_graph::scan_jvm_files");
            crate::analyzer::usages::java_graph::scan_jvm_files_for_foreign_type(
                analyzer,
                token,
                scan_scope.candidate_files(),
                target,
                max_usages,
                &mut hits,
                &mut unproven_hits,
                &mut raw_match_count,
                &mut limit_exceeded,
            );
        }

        let external_callsites =
            brokk_bifrost_core::analyzer::usages::common::external_usage_hit_count(&hits);
        if limit_exceeded || external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        // A reference the scan could not prove is reported in its own channel
        // rather than as a proven hit or as silence. A type reference never
        // lands there — a written type either resolves to the target or does not,
        // with no receiver to be uncertain about — but a call through a receiver
        // whose type could not be established does.
        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven_limit(
            target.clone(),
            hits,
            unproven_hits,
            scan_scope.max_unproven(),
        ))
    }
}

/// Collect hits on a Java or Scala *type* target from Kotlin source.
///
/// Java, Scala, and Kotlin share one candidate space, so a Kotlin file naming a
/// Java class is a real usage of it — and before this, a Java find-references
/// simply did not see it. The scan is the ordinary Kotlin one: the target model
/// is language-agnostic (a class is a class), and the Kotlin name ladder already
/// resolves against the realm-wide declaration index, so the only thing that
/// changes is which files it runs over.
///
/// Restricted to type targets on purpose. A member reference needs the target
/// language's own member-lookup rules, and answering `Java.method` with Kotlin's
/// would be guessing; Java's existing Scala scanner draws the same line.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_kotlin_files_for_jvm_type(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    max_usages: usize,
    hits: &mut BTreeSet<UsageHit>,
    unproven_hits: &mut BTreeSet<UsageHit>,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
) {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    if *limit_exceeded || !target.is_class() {
        return;
    }
    if resolve_analyzer::<KotlinAnalyzer>(analyzer).is_none() {
        return;
    }
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    let relational_session =
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
            analyzer,
            &cancellation,
        );
    let brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome::Complete(Some(
        spec,
    )) = kotlin_target_spec_replayable(
        &relational_session,
        analyzer,
        token,
        std::slice::from_ref(target),
    )
    else {
        return;
    };
    let mut ordered: Vec<ProjectFile> = candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Kotlin)
        .cloned()
        .collect();
    ordered.sort();
    let prepared_files = prepare_kotlin_scan_files(analyzer, &ordered);
    scan_and_merge_kotlin_files(
        &relational_session,
        analyzer,
        token,
        &prepared_files,
        &spec,
        max_usages,
        hits,
        unproven_hits,
        raw_match_count,
        limit_exceeded,
    );
}

enum KotlinPreparedScanStatus {
    Complete,
    Cancelled,
    Failed,
}

#[allow(clippy::too_many_arguments)]
fn scan_and_merge_kotlin_files(
    relational_session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    prepared_files: &[PreparedKotlinScanFile],
    spec: &TargetSpec,
    max_usages: usize,
    hits: &mut BTreeSet<UsageHit>,
    unproven_hits: &mut BTreeSet<UsageHit>,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
) -> KotlinPreparedScanStatus {
    match scan_kotlin_files_replayable(
        relational_session,
        analyzer,
        token,
        prepared_files,
        spec,
        max_usages,
    ) {
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Complete(results) => {
            merge_kotlin_scan_results(
                results.into_iter().map(Some),
                hits,
                unproven_hits,
                raw_match_count,
                limit_exceeded,
                max_usages,
            );
            KotlinPreparedScanStatus::Complete
        }
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Cancelled(results) => {
            merge_kotlin_scan_results(
                results,
                hits,
                unproven_hits,
                raw_match_count,
                limit_exceeded,
                max_usages,
            );
            KotlinPreparedScanStatus::Cancelled
        }
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Failed(_) => {
            KotlinPreparedScanStatus::Failed
        }
    }
}

fn merge_kotlin_scan_results(
    results: impl IntoIterator<Item = Option<KotlinFileScanOutput>>,
    hits: &mut BTreeSet<UsageHit>,
    unproven_hits: &mut BTreeSet<UsageHit>,
    raw_match_count: &mut usize,
    limit_exceeded: &mut bool,
    max_usages: usize,
) {
    for (file_hits, file_unproven_hits, file_raw_match_count, file_limit_exceeded) in
        results.into_iter().flatten()
    {
        hits.extend(file_hits);
        unproven_hits.extend(file_unproven_hits);
        *raw_match_count += file_raw_match_count;
        *limit_exceeded |= file_limit_exceeded;
    }
    *limit_exceeded |=
        brokk_bifrost_core::analyzer::usages::common::external_usage_hit_count(hits) > max_usages;
}

/// Builds the whole Kotlin `caller -> callee` edge set in one inverted pass.
///
/// The file states are prefetched in bulk rather than hydrated one at a time.
/// That matters for a reason the Scala builder learned first: pulling each file
/// through the per-file LRU during a whole-workspace build evicts the cache a
/// user's interactive queries depend on, so a `usage_graph` call would leave
/// every subsequent `scan_usages` cold.
pub(crate) struct KotlinEdgeResolver<'a> {
    files: Vec<ProjectFile>,
    kotlin: &'a KotlinAnalyzer,
}

struct PreparedKotlinEdgeFile {
    file: ProjectFile,
    parsed: ParsedTreeFile,
    declarations: FileDeclarations,
    class_ranges: ClassRangeIndex,
}

fn clone_file_declarations(declarations: &FileDeclarations) -> FileDeclarations {
    FileDeclarations {
        enclosers: declarations.enclosers.clone(),
        definitions: declarations.definitions.clone(),
    }
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](brokk_bifrost_analysis::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> KotlinEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let kotlin = resolve_analyzer::<KotlinAnalyzer>(analyzer)?;
        let files = brokk_bifrost_analysis::analyzer::usages::common::analyzable_usage_graph_files(
            analyzer,
            Language::Kotlin,
        )?;
        Some(Self { files, kotlin })
    }

    #[cfg(test)]
    pub(crate) fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files =
            brokk_bifrost_analysis::analyzer::usages::common::select_usage_graph_files(
                &self.files,
                &keep_file,
            );
        let file_states = self
            .kotlin
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_kotlin_edges(
            analyzer,
            token,
            &self.files,
            &file_states,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files =
            brokk_bifrost_analysis::analyzer::usages::common::select_usage_graph_files(
                &self.files,
                &keep_file,
            );
        let file_states = self
            .kotlin
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_kotlin_edges(
            analyzer,
            token,
            &self.files,
            &file_states,
            EdgeNodeDomain::Rooted(callers),
            keep_file,
        )
    }

    pub(crate) fn build_inbound_edges_with_completeness<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callees: &HashSet<String>,
        keep_file: F,
    ) -> Option<UsageEdgeBuildResult<UsageEdges>>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let mut selected_files =
            brokk_bifrost_analysis::analyzer::usages::common::select_usage_graph_files(
                &self.files,
                &keep_file,
            );
        selected_files.sort_unstable();
        let file_states = self
            .kotlin
            .bulk_file_states(selected_files.clone(), BulkFileStateSource::Omit);
        build_kotlin_inbound_edges_with_completeness(
            analyzer,
            token,
            &selected_files,
            &file_states,
            EdgeNodeDomain::Inbound(callees),
        )
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files =
            brokk_bifrost_analysis::analyzer::usages::common::select_usage_graph_files(
                &self.files,
                &keep_file,
            );
        let file_states = self
            .kotlin
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_kotlin_edges(
            analyzer,
            token,
            &self.files,
            &file_states,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }
}

fn build_kotlin_inbound_edges_with_completeness(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    files: &[ProjectFile],
    file_states: &HashMap<ProjectFile, FileState>,
    domain: EdgeNodeDomain<'_>,
) -> Option<UsageEdgeBuildResult<UsageEdges>> {
    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_file_declarations_from_state;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::class_range_index_from_state;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::collect_file_edges_with_domain;

    let cancellation = analyzer.active_query_cancellation()?;
    if cancellation.is_cancelled() {
        return None;
    }
    let language = brokk_bifrost_jvm::kotlin::language::LANGUAGE.into();
    let mut omitted_files = Vec::new();
    let mut prepared_files = Vec::with_capacity(files.len());
    for file in files {
        if cancellation.is_cancelled() {
            return None;
        }
        let Some(state) = file_states.get(file) else {
            omitted_files.push(file.clone());
            continue;
        };
        let parsed = if state.source.is_empty() {
            parse_tree_sitter_file(file, ParseSpec::whole(&language))
        } else {
            parse_tree_sitter_source(state.source.clone(), ParseSpec::whole(&language))
        };
        let Some(parsed) = parsed else {
            omitted_files.push(file.clone());
            continue;
        };
        let declarations = build_file_declarations_from_state(state);
        let class_ranges = class_range_index_from_state(state);
        prepared_files.push(PreparedKotlinEdgeFile {
            file: file.clone(),
            parsed,
            declarations,
            class_ranges,
        });
    }

    let session =
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
            analyzer,
            &cancellation,
        );
    let per_file = match session.resolve_owned_items(
        "kotlin_inbound_edge_scan",
        &prepared_files,
        |prepared, frontier| {
            let graph = KotlinGraphSource {
                index: analyzer,
                hierarchy: analyzer.type_hierarchy_provider(),
                imports: analyzer.import_analysis_provider(),
                relational_definitions: frontier.as_ref(),
            };
            collect_file_edges_with_domain(
                &prepared.file,
                domain,
                &prepared.parsed,
                clone_file_declarations(&prepared.declarations),
                |input| {
                    brokk_bifrost_jvm::kotlin::graph::inverted::scan_file(
                        &graph,
                        token,
                        &prepared.file,
                        input,
                        prepared.class_ranges.clone(),
                    )
                },
            )
        },
    ) {
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Complete(results) => {
            results
        }
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Cancelled(_) => {
            return None;
        }
        brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Failed(_) => {
            return None;
        }
    };
    omitted_files.sort_unstable();
    omitted_files.dedup();
    let output = brokk_bifrost_analysis::analyzer::usages::inverted_edges::merge_and_cap(per_file);
    if omitted_files.is_empty() {
        Some(UsageEdgeBuildResult::Complete(output))
    } else {
        Some(UsageEdgeBuildResult::Uncacheable {
            output,
            omitted_files,
        })
    }
}

/// The whole-workspace inverted pass: the shared driver's parallel fan-out plus
/// on-demand parsing, with
/// [`brokk_bifrost_jvm::kotlin::graph::inverted::scan_file`] resolving each file.
///
/// The two per-file indexes are built here rather than crate-side because both
/// have a `FileState` fast path, and `FileState` is analysis-crate-private
/// (Ruby's `forward_owner_relation_facts` precedent: decode on this side, hand
/// the decoded facts across).
fn build_kotlin_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    files: &[ProjectFile],
    file_states: &HashMap<ProjectFile, FileState>,
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> Output
where
    Output: brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_edge_output;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_file_declarations;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_file_declarations_from_state;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::class_range_index_from_state;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::parse_and_collect_with_declarations_and_domain;

    let language = brokk_bifrost_jvm::kotlin::language::LANGUAGE.into();
    build_edge_output(files, keep_file, |file| {
        with_kotlin_graph_source(analyzer, |graph| {
            let state = file_states.get(file);
            let declarations = state
                .map(build_file_declarations_from_state)
                .unwrap_or_else(|| build_file_declarations(analyzer, file));
            let class_ranges = state
                .map(class_range_index_from_state)
                .unwrap_or_else(|| ClassRangeIndex::build(analyzer, file));
            parse_and_collect_with_declarations_and_domain(
                file,
                domain,
                ParseSpec::whole(&language),
                declarations,
                |input| scan_inverted_file(&graph, token, file, input, class_ranges),
            )
        })
    })
}
