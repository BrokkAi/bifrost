use super::inverted::{
    ProjectTypes, parse_scala_query_file, scan_edge_file, scan_scala_query_tree,
};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeNodeDomain, UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges,
    build_edge_output, build_file_declarations_from_declaration_ranges_filtered,
    class_range_index_from_declaration_ranges,
    parse_source_and_collect_with_declarations_and_domain,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::parsed_tree::ParseSpec;
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, Language, ProjectFile, Range, ScalaAnalyzer,
    resolve_analyzer,
};
use crate::hash::HashMap;
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use brokk_bifrost_core::analyzer::BoundedDefinitionLookup;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::scala::graph::query::{
    ScalaCatalogBuildError, ScalaFileEligibility, ScalaQueryHitSink, ScalaQueryTargetCatalog,
};
use brokk_bifrost_jvm::scala::graph_support::ScalaWorkspaceSource;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(super) struct ScalaEdgeGraph {
    pub(super) files: Vec<ProjectFile>,
    pub(super) types: Arc<ProjectTypes>,
}

/// Drive a whole-workspace inverted Scala edge build over the resolver-owned
/// file set.
///
/// The fan-out stays on this side of the seam, as it does for C++:
/// `build_edge_output` and `parse_source_and_collect_with_declarations` are the
/// shared, language-agnostic driver, and only the per-file Scala walk crossed.
/// Both per-file inputs the driver needs -- the declaration spans and the class
/// ranges -- come out of the same `ScalaFileFacts` the walk reads, so they are
/// built once here and the class-range index is handed on.
fn build_scala_edges<Output, F>(
    scala: &ScalaAnalyzer,
    token: QueryToken<'_>,
    graph: &ScalaEdgeGraph,
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = brokk_bifrost_jvm::scala::language::LANGUAGE.into();
    build_edge_output(&graph.files, keep_file, |file| {
        let state = graph.types.bulk_file_state(file)?;
        // Synthetic anonymous classes are not public graph nodes. Do not let
        // their ranges hide references from the enclosing callable. Their
        // named members remain eligible callers through their own ranges.
        let declarations = build_file_declarations_from_declaration_ranges_filtered(
            &state.declarations,
            &state.ranges,
            |unit| !(unit.is_class() && unit.is_synthetic()),
        );
        let class_ranges =
            class_range_index_from_declaration_ranges(&state.declarations, &state.ranges);
        parse_source_and_collect_with_declarations_and_domain(
            graph.types.source_for_file(scala, file)?,
            file,
            domain,
            ParseSpec::whole(&language),
            declarations,
            |input| scan_edge_file(scala, token, &graph.types, file, state, class_ranges, input),
        )
    })
}

pub(crate) struct ScalaQueryResolver<'a> {
    scala: &'a ScalaAnalyzer,
}

/// The dispatching analyzer, in the shape
/// [`brokk_bifrost_jvm::scala::graph::query`] asks for.
///
/// A borrowed newtype rather than a bare `&dyn IAnalyzer`: a `dyn IAnalyzer`
/// cannot be unsized to the workspace-source trait object expected by the JVM
/// graph crate.
pub(in crate::analyzer::usages) struct ScalaDispatch<'a>(
    pub(in crate::analyzer::usages) &'a dyn IAnalyzer,
);

impl ScalaWorkspaceSource for ScalaDispatch<'_> {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.0.enclosing_code_unit(file, range)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.0.ranges(code_unit)
    }

    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        crate::analyzer::AnalyzerDefinitionLookup::new(self.0, Language::None)
            .by_normalized_fqn(normalized)
    }
}

struct ScalaFrontierDispatch<'a> {
    types: &'a ProjectTypes,
    file: &'a ProjectFile,
    file_scope_range: Range,
}

impl ScalaWorkspaceSource for ScalaFrontierDispatch<'_> {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        let state = self.types.bulk_file_state(file)?;
        crate::analyzer::tree_sitter_analyzer::enclosing_code_unit_from_declaration_ranges(
            &state.declarations,
            &state.ranges,
            range,
        )
        .or_else(|| {
            (file == self.file
                && range.start_byte < range.end_byte
                && self.file_scope_range.contains(range))
            .then(|| CodeUnit::file_scope(file.clone()))
        })
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        if code_unit.is_file_scope() && code_unit.source() == self.file {
            return vec![self.file_scope_range];
        }
        self.types
            .bulk_file_state(code_unit.source())
            .and_then(|state| state.ranges.get(code_unit))
            .cloned()
            .unwrap_or_default()
    }

    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        self.types.definitions_by_normalized_fqn(normalized)
    }
}

impl<'a> UsageQueryResolver<'a> for ScalaQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            scala: resolve_analyzer::<ScalaAnalyzer>(analyzer)?,
        })
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
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let candidate_files = scan_scope.candidate_files();
        let scoped_files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Scala)
            .cloned()
            .collect();
        let uncancelled = crate::CancellationToken::new();
        let cancellation = scan_scope.cancellation().unwrap_or(&uncancelled);
        let workspace_files = match analyzer.project().analyzable_files(Language::Scala) {
            Ok(files) => files.into_iter().collect::<Vec<_>>(),
            Err(_) => {
                return GraphUsageOutcome::fallback_safe(
                    overloads[0].fq_name(),
                    GraphFailureReason::UnsupportedTargetShape(
                        "the Scala workspace file set is unavailable",
                    ),
                    "ScalaUsageGraphStrategy",
                );
            }
        };
        let relational_session =
            crate::analyzer::relational_frontier::RelationalFrontierSession::new(
                analyzer,
                cancellation,
            );
        let file_states = self
            .scala
            .bulk_file_states(workspace_files, BulkFileStateSource::Omit);
        let unresolved_seed = self.scala.project_types_seed_from_file_states(file_states);
        let resolved_seed = match relational_session.resolve_owned("scala_hierarchy", |frontier| {
            self.scala
                .build_project_types_from_frontier(frontier, unresolved_seed.clone())
                .resolved_seed()
        }) {
            crate::analyzer::RelationalFrontierOutcome::Complete(seed) => seed,
            crate::analyzer::RelationalFrontierOutcome::Cancelled => {
                return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
            }
            crate::analyzer::RelationalFrontierOutcome::Failed(_) => {
                return GraphUsageOutcome::fallback_safe(
                    overloads[0].fq_name(),
                    GraphFailureReason::UnsupportedTargetShape(
                        "the Scala hierarchy frontier failed",
                    ),
                    "ScalaUsageGraphStrategy",
                );
            }
        };
        let catalog = match relational_session.resolve_owned("scala_target_catalog", |frontier| {
            let types = self
                .scala
                .build_project_types_from_frontier(frontier, resolved_seed.clone());
            ScalaQueryTargetCatalog::build(
                self.scala,
                token,
                &types,
                overloads,
                scan_scope.cancellation(),
            )
        }) {
            crate::analyzer::RelationalFrontierOutcome::Complete(Ok(catalog)) => catalog,
            crate::analyzer::RelationalFrontierOutcome::Complete(Err(
                ScalaCatalogBuildError::Cancelled,
            ))
            | crate::analyzer::RelationalFrontierOutcome::Cancelled => {
                return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
            }
            crate::analyzer::RelationalFrontierOutcome::Complete(Err(
                ScalaCatalogBuildError::UnsupportedTarget(target),
            )) => {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                    "ScalaUsageGraphStrategy",
                );
            }
            crate::analyzer::RelationalFrontierOutcome::Failed(_) => {
                return GraphUsageOutcome::fallback_safe(
                    overloads[0].fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("the Scala target frontier failed"),
                    "ScalaUsageGraphStrategy",
                );
            }
        };
        let mut files: HashMap<ProjectFile, ScalaFileEligibility> = scoped_files
            .iter()
            .cloned()
            .map(|file| (file, ScalaFileEligibility::All))
            .collect();
        for (target_id, target) in overloads.iter().enumerate() {
            if scan_scope.allows(target.source()) && !scoped_files.contains(target.source()) {
                match files.entry(target.source().clone()) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(ScalaFileEligibility::Only(HashSet::from_iter([target_id])));
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if let ScalaFileEligibility::Only(targets) = entry.get_mut() {
                            targets.insert(target_id);
                        }
                    }
                }
            }
        }
        let mut files = files.into_iter().collect::<Vec<_>>();
        files.sort_by(|(left, _), (right, _)| left.cmp(right));
        let mut prepared_files = Vec::with_capacity(files.len());
        for (file, eligibility) in files {
            if scan_scope.is_cancelled() {
                break;
            }
            let Some(source) = analyzer.indexed_source(&file) else {
                continue;
            };
            let Some(tree) = parse_scala_query_file(self.scala, &source) else {
                continue;
            };
            let class_ranges = ClassRangeIndex::build(analyzer, &file);
            let line_starts = compute_line_starts(&source);
            prepared_files.push((file, eligibility, source, tree, class_ranges, line_starts));
        }
        let relevant_names = catalog.relevant_names();
        crate::profiling::note_with(|| {
            format!(
                "scala_query prepared_files={} relevant_names={}",
                prepared_files.len(),
                relevant_names.len()
            )
        });
        let file_results = relational_session.resolve_owned_items(
            "scala_semantic_scan",
            &prepared_files,
            |(file, eligibility, source, tree, class_ranges, line_starts), frontier| {
                let types = self
                    .scala
                    .build_project_types_from_frontier(frontier, resolved_seed.clone());
                let dispatch = ScalaFrontierDispatch {
                    types: &types,
                    file,
                    file_scope_range: Range {
                        start_byte: 0,
                        end_byte: source.len(),
                        start_line: 0,
                        end_line: line_starts.len().saturating_sub(1),
                    },
                };
                let mut file_hits = vec![BTreeSet::new(); overloads.len()];
                let mut file_observed_hits = BTreeSet::new();
                let mut sink = ScalaQueryHitSink {
                    analyzer: &dispatch,
                    scala: self.scala,
                    file,
                    source,
                    class_ranges: class_ranges.clone(),
                    line_starts: line_starts.clone(),
                    catalog: &catalog,
                    eligibility,
                    hits: &mut file_hits,
                    observed_hits: &mut file_observed_hits,
                    unproven_hits: None,
                    enclosing_cache: HashMap::default(),
                    relevant_names: relevant_names.clone(),
                    allow_all_names: false,
                    max_usages,
                    limit_exceeded: false,
                };
                scan_scala_query_tree(
                    self.scala,
                    token,
                    &types,
                    &dispatch,
                    file,
                    source,
                    tree,
                    class_ranges.clone(),
                    &mut sink,
                    scan_scope.cancellation(),
                );
                let file_limit_exceeded = sink.limit_exceeded;
                drop(sink);
                (file_hits, file_observed_hits, file_limit_exceeded)
            },
        );
        let file_results = match file_results {
            crate::analyzer::relational_frontier::RelationalItemFrontierOutcome::Complete(
                results,
            ) => results.into_iter().map(Some).collect(),
            crate::analyzer::relational_frontier::RelationalItemFrontierOutcome::Cancelled(
                results,
            ) => results,
            crate::analyzer::relational_frontier::RelationalItemFrontierOutcome::Failed(error) => {
                crate::profiling::note_with(|| {
                    format!("Scala file frontier failed: {}", error.message())
                });
                return GraphUsageOutcome::fallback_safe(
                    overloads[0].fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("a Scala file frontier failed"),
                    "ScalaUsageGraphStrategy",
                );
            }
        };
        let mut hits = vec![BTreeSet::new(); overloads.len()];
        let mut observed_hits = BTreeSet::new();
        let mut limit_exceeded = false;
        for (file_hits, file_observed_hits, file_limit_exceeded) in
            file_results.into_iter().flatten()
        {
            for (target_hits, file_target_hits) in hits.iter_mut().zip(file_hits) {
                target_hits.extend(file_target_hits);
            }
            observed_hits.extend(file_observed_hits);
            limit_exceeded |= file_limit_exceeded;
        }
        // A Scala class is equally nameable from Kotlin source, and the three JVM
        // languages share one candidate space, so find-references on a Scala type
        // must see its Kotlin call sites too (#1239 milestone 4). Kotlin's own
        // scan resolves those names, so what is added here is the file set.
        if !limit_exceeded
            && !scan_scope.is_cancelled()
            && let Some(target) = overloads.first().filter(|target| target.is_class())
        {
            let mut cross_unproven = BTreeSet::new();
            let mut cross_raw = 0usize;
            crate::analyzer::usages::kotlin_graph::scan_kotlin_files_for_jvm_type(
                analyzer,
                candidate_files,
                target,
                max_usages,
                &mut hits[0],
                &mut cross_unproven,
                &mut cross_raw,
                &mut limit_exceeded,
            );
            observed_hits.extend(hits[0].iter().cloned());
        }

        let external_callsites =
            crate::analyzer::usages::common::external_usage_hit_count(&observed_hits);
        if limit_exceeded || external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: overloads[0].short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: observed_hits,
            });
        }
        let hits_by_overload = overloads.iter().cloned().zip(hits).collect();

        GraphUsageOutcome::Resolved(FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload: HashMap::default(),
            unproven_total_by_overload: HashMap::default(),
        })
    }
}

pub(crate) struct ScalaEdgeResolver<'a> {
    scala: &'a ScalaAnalyzer,
    graph: ScalaEdgeGraph,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> ScalaEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Scala)
            .ok()?
            .into_iter()
            .collect();
        let file_states = scala.bulk_file_states(files.clone(), BulkFileStateSource::Include);
        let types = Arc::new(scala.build_project_types_from_file_states(file_states));

        Some(Self {
            scala,
            graph: ScalaEdgeGraph { files, types },
        })
    }

    #[cfg(test)]
    pub(crate) fn build_edges<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges(
            self.scala,
            token,
            &self.graph,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges(
            self.scala,
            token,
            &self.graph,
            EdgeNodeDomain::Rooted(callers),
            keep_file,
        )
    }

    pub(crate) fn build_inbound_edges<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callees: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges(
            self.scala,
            token,
            &self.graph,
            EdgeNodeDomain::Inbound(callees),
            keep_file,
        )
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges(
            self.scala,
            token,
            &self.graph,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }
}
