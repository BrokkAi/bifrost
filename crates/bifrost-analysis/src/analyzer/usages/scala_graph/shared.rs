use super::inverted::{ProjectTypes, scan_edge_file, scan_scala_query_file};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output,
    build_file_declarations_from_declaration_ranges, class_range_index_from_declaration_ranges,
    parse_source_and_collect_with_declarations,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, Language, ProjectFile, Range, ScalaAnalyzer,
    resolve_analyzer,
};
use crate::hash::HashMap;
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
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
    graph: &ScalaEdgeGraph,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = brokk_bifrost_jvm::scala::language::LANGUAGE.into();
    build_edge_output(&graph.files, keep_file, |file| {
        let state = graph.types.bulk_file_state(file)?;
        let declarations =
            build_file_declarations_from_declaration_ranges(&state.declarations, &state.ranges);
        let class_ranges =
            class_range_index_from_declaration_ranges(&state.declarations, &state.ranges);
        parse_source_and_collect_with_declarations(
            graph.types.source_for_file(scala, file)?,
            file,
            nodes,
            &language,
            declarations,
            |input| scan_edge_file(scala, &graph.types, file, state, class_ranges, input),
        )
    })
}

pub(crate) struct ScalaQueryResolver<'a> {
    scala: &'a ScalaAnalyzer,
}

/// The dispatching analyzer, in the shape
/// [`brokk_bifrost_jvm::scala::graph::query`] asks for.
///
/// A borrowed newtype rather than a bare `&dyn IAnalyzer` for the reason
/// `CppDispatch` carries: a `dyn IAnalyzer` cannot be unsized to another trait
/// object, and one of the three questions -- the merged `DefinitionIndexHandle`
/// -- is built per call and so can never be lent out as a `&dyn` at all.
struct ScalaDispatch<'a>(&'a dyn IAnalyzer);

impl ScalaWorkspaceSource for ScalaDispatch<'_> {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.0.enclosing_code_unit(file, range)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.0.ranges(code_unit)
    }

    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        self.0
            .global_usage_definition_index()
            .by_normalized_fqn(normalized)
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
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let candidate_files = scan_scope.candidate_files();
        let scoped_files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Scala)
            .cloned()
            .collect();
        let catalog = match ScalaQueryTargetCatalog::build(
            self.scala,
            overloads,
            scan_scope.cancellation(),
        ) {
            Ok(catalog) => catalog,
            Err(ScalaCatalogBuildError::Cancelled) => {
                return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
            }
            Err(ScalaCatalogBuildError::UnsupportedTarget(target)) => {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
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
        let mut hits = vec![BTreeSet::new(); overloads.len()];
        let mut observed_hits = BTreeSet::new();
        let mut limit_exceeded = false;
        let dispatch = ScalaDispatch(analyzer);
        for (file, eligibility) in &files {
            if scan_scope.is_cancelled() {
                break;
            }
            let Some(source) = analyzer.indexed_source(file) else {
                continue;
            };
            let mut sink = ScalaQueryHitSink {
                analyzer: &dispatch,
                scala: self.scala,
                file,
                source: &source,
                class_ranges: ClassRangeIndex::build(analyzer, file),
                line_starts: compute_line_starts(&source),
                catalog: &catalog,
                eligibility,
                hits: &mut hits,
                observed_hits: &mut observed_hits,
                enclosing_cache: HashMap::default(),
                relevant_names: catalog.relevant_names(),
                allow_all_names: false,
                max_usages,
                limit_exceeded: false,
            };
            scan_scala_query_file(
                self.scala,
                analyzer,
                file,
                &source,
                &mut sink,
                scan_scope.cancellation(),
            );
            if sink.limit_exceeded {
                limit_exceeded = true;
                break;
            }
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
        let types = Arc::new(crate::analyzer::scala::build_scala_project_types(
            file_states,
        ));

        Some(Self {
            scala,
            graph: ScalaEdgeGraph { files, types },
        })
    }

    pub(crate) fn build_edges<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges(self.scala, &self.graph, nodes, keep_file)
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges(self.scala, &self.graph, nodes, keep_file)
    }
}
