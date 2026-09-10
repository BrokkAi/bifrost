use super::inverted::{
    ProjectTypes, parse_scala_query_file, scan_edge_file, scan_scala_query_tree,
};
use crate::analyzer::relational_frontier::{
    RelationalFrontierSession, RelationalItemFrontierOutcome,
};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeNodeDomain, UsageEdgeBuildOutput, UsageEdgeBuildResult, UsageEdgeWeights,
    UsageEdges, build_edge_output, build_edge_output_with_completeness,
    build_file_declarations_from_declaration_ranges_filtered,
    class_range_index_from_declaration_ranges,
    parse_source_and_collect_with_declarations_and_domain,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::parsed_tree::ParseSpec;
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, Language, ProjectFile, Range,
    RelationalDefinitionFrontier, RelationalFrontierOutcome, ScalaAnalyzer, resolve_analyzer,
    sort_units,
};
use crate::hash::HashMap;
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use brokk_bifrost_core::analyzer::BoundedDefinitionLookup;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::scala::graph::inverted::ScalaProjectTypesSeed;
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
            |input| {
                scan_edge_file(
                    scala,
                    token,
                    &graph.types,
                    file,
                    &state,
                    class_ranges,
                    input,
                )
            },
        )
    })
}

fn build_scala_edges_with_completeness<Output, F>(
    scala: &ScalaAnalyzer,
    token: QueryToken<'_>,
    graph: &ScalaEdgeGraph,
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> UsageEdgeBuildResult<Output>
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = brokk_bifrost_jvm::scala::language::LANGUAGE.into();
    build_edge_output_with_completeness(&graph.files, keep_file, |file| {
        let state = graph.types.bulk_file_state(file)?;
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
            |input| {
                scan_edge_file(
                    scala,
                    token,
                    &graph.types,
                    file,
                    &state,
                    class_ranges,
                    input,
                )
            },
        )
    })
}

pub(crate) struct ScalaQueryResolver<'a> {
    scala: &'a ScalaAnalyzer,
}

/// The foreign JVM realm a Scala walk consults for names its own index does
/// not hold (#1859): the workspace's other JVM languages, read through the
/// scan's replayable frontier so the realm questions batch in the frontier's
/// barriers instead of costing one synchronous store read per candidate
/// spelling.
struct ForeignJvmRealm<'a> {
    analyzer: &'a dyn IAnalyzer,
    languages: &'a [Language],
    frontier: Arc<dyn RelationalDefinitionFrontier>,
}

impl ForeignJvmRealm<'_> {
    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        let mut units = Vec::new();
        for language in self.languages {
            let lookup = crate::analyzer::AnalyzerDefinitionLookup::on_frontier(
                self.analyzer,
                *language,
                Arc::clone(&self.frontier),
            );
            units.extend(lookup.by_normalized_fqn(normalized));
        }
        units
    }
}

/// The JVM languages other than Scala that this workspace analyzes: the realm
/// a Java (or Kotlin) target's Scala call sites are typed against.
pub(in crate::analyzer::usages) fn foreign_jvm_languages(
    analyzer: &dyn IAnalyzer,
) -> Vec<Language> {
    analyzer
        .languages()
        .into_iter()
        .filter(|language| matches!(language, Language::Java | Language::Kotlin))
        .collect()
}

/// The walk's view of the workspace during one frontier evaluation: the
/// per-item `ProjectTypes`, the file being walked, and (for a foreign
/// target) the realm its untyped names are checked against.
struct ScalaFrontierDispatch<'a> {
    types: &'a ProjectTypes,
    file: &'a ProjectFile,
    file_scope_range: Range,
    realm: Option<ForeignJvmRealm<'a>>,
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
            .and_then(|state| state.ranges.get(code_unit).cloned())
            .unwrap_or_default()
    }

    fn definitions_by_normalized_fqn(&self, normalized: &str) -> Vec<CodeUnit> {
        let mut units = self.types.definitions_by_normalized_fqn(normalized);
        if let Some(realm) = &self.realm {
            units.extend(realm.definitions_by_normalized_fqn(normalized));
            sort_units(&mut units);
            units.dedup();
        }
        units
    }
}

/// One Scala file prepared for a frontier scan: what the per-file walk needs
/// that is built once, outside the replayable evaluation.
pub(in crate::analyzer::usages) struct PreparedScalaFile {
    pub(in crate::analyzer::usages) file: ProjectFile,
    eligibility: ScalaFileEligibility,
    source: String,
    tree: tree_sitter::Tree,
    class_ranges: ClassRangeIndex,
    line_starts: Vec<usize>,
}

/// Read, parse and index the files one frontier scan walks. `keep_source` is
/// the caller's cheap gate on the file text; a file it rejects is not
/// prepared.
pub(in crate::analyzer::usages) fn prepare_scala_files(
    analyzer: &dyn IAnalyzer,
    scala: &ScalaAnalyzer,
    files: Vec<(ProjectFile, ScalaFileEligibility)>,
    cancellation: &crate::CancellationToken,
    keep_source: impl Fn(&str) -> bool,
) -> Vec<PreparedScalaFile> {
    let mut prepared = Vec::with_capacity(files.len());
    for (file, eligibility) in files {
        if cancellation.is_cancelled() {
            break;
        }
        let Some(source) = analyzer.indexed_source(&file) else {
            continue;
        };
        if !keep_source(&source) {
            continue;
        }
        let Some(tree) = parse_scala_query_file(scala, &source) else {
            continue;
        };
        let class_ranges = ClassRangeIndex::build(analyzer, &file);
        let line_starts = compute_line_starts(&source);
        prepared.push(PreparedScalaFile {
            file,
            eligibility,
            source,
            tree,
            class_ranges,
            line_starts,
        });
    }
    prepared
}

/// What one file's walk produced, per target.
pub(in crate::analyzer::usages) struct ScalaFileScan {
    pub(in crate::analyzer::usages) hits: Vec<BTreeSet<UsageHit>>,
    pub(in crate::analyzer::usages) observed_hits: BTreeSet<UsageHit>,
    pub(in crate::analyzer::usages) unproven_hits: BTreeSet<UsageHit>,
    pub(in crate::analyzer::usages) limit_exceeded: bool,
}

/// One usage query's Scala frontier: the relational session plus the resolved
/// seed every later phase builds its per-item `ProjectTypes` from. The Scala
/// strategy and the Java-target scan of Scala files share it, so a Java
/// target's Scala call sites are resolved by exactly the walk a Scala
/// target's are, on the same batched reads.
pub(in crate::analyzer::usages) struct ScalaFrontierScan<'a> {
    scala: &'a ScalaAnalyzer,
    cancellation: &'a crate::CancellationToken,
    session: RelationalFrontierSession<'a>,
    resolved_seed: ScalaProjectTypesSeed,
}

pub(in crate::analyzer::usages) enum ScalaFrontierSeedOutcome<'a> {
    Ready(ScalaFrontierScan<'a>),
    Cancelled,
    Failed(&'static str),
}

impl<'a> ScalaFrontierScan<'a> {
    /// The workspace-wide sweep derives the seed's type-namespace structures
    /// in bounded chunks; per-file facts for the files the query actually
    /// touches rehydrate lazily through the seed (#3142). The hierarchy pass
    /// resolves the seed once; the inputs it carried are dropped after.
    pub(in crate::analyzer::usages) fn seed(
        scala: &'a ScalaAnalyzer,
        analyzer: &'a dyn IAnalyzer,
        cancellation: &'a crate::CancellationToken,
    ) -> ScalaFrontierSeedOutcome<'a> {
        let workspace_files = match analyzer.project().analyzable_files(Language::Scala) {
            Ok(files) => files.into_iter().collect::<Vec<_>>(),
            Err(_) => {
                return ScalaFrontierSeedOutcome::Failed(
                    "the Scala workspace file set is unavailable",
                );
            }
        };
        let session = RelationalFrontierSession::new(analyzer, cancellation);
        let unresolved_seed = scala.project_types_query_seed(&workspace_files);
        let resolved_seed = match session.resolve_owned("scala_hierarchy", |frontier| {
            scala
                .build_project_types_from_frontier(frontier, unresolved_seed.clone())
                .resolved_seed()
        }) {
            RelationalFrontierOutcome::Complete(seed) => seed,
            RelationalFrontierOutcome::Cancelled => return ScalaFrontierSeedOutcome::Cancelled,
            RelationalFrontierOutcome::Failed(_) => {
                return ScalaFrontierSeedOutcome::Failed("the Scala hierarchy frontier failed");
            }
        };
        drop(unresolved_seed);
        ScalaFrontierSeedOutcome::Ready(Self {
            scala,
            cancellation,
            session,
            resolved_seed,
        })
    }

    /// One frontier pass over the resolved seed's `ProjectTypes`.
    pub(in crate::analyzer::usages) fn resolve_types<T>(
        &self,
        phase: &'static str,
        mut evaluate: impl FnMut(&ProjectTypes) -> T,
    ) -> RelationalFrontierOutcome<T> {
        self.session.resolve_owned(phase, |frontier| {
            let types = self
                .scala
                .build_project_types_from_frontier(frontier, self.resolved_seed.clone());
            evaluate(&types)
        })
    }

    /// Warm the scan set's per-file facts in batched reads ahead of the
    /// parallel walk, so a file's first touch is a memory hit rather than a
    /// store read on the scan's critical path.
    pub(in crate::analyzer::usages) fn prefetch_file_facts(&self, files: &[ProjectFile]) {
        self.resolved_seed.prefetch_file_facts(files);
    }

    /// Walk every prepared file on the frontier. `realm_languages` is the
    /// foreign JVM realm a non-Scala target's untyped names are checked
    /// against (`None` for a Scala target); `keep_unproven` keeps the receiver
    /// references the walk could not type instead of dropping them.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::analyzer::usages) fn scan(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        prepared: &[PreparedScalaFile],
        catalog: &ScalaQueryTargetCatalog,
        target_count: usize,
        max_usages: usize,
        realm_languages: Option<&[Language]>,
        keep_unproven: bool,
    ) -> RelationalItemFrontierOutcome<ScalaFileScan> {
        let relevant_names = catalog.relevant_names();
        crate::profiling::note_with(|| {
            format!(
                "scala_query prepared_files={} relevant_names={}",
                prepared.len(),
                relevant_names.len()
            )
        });
        self.session
            .resolve_owned_items("scala_semantic_scan", prepared, |item, frontier| {
                let types = self.scala.build_project_types_from_frontier(
                    Arc::clone(&frontier),
                    self.resolved_seed.clone(),
                );
                let dispatch = ScalaFrontierDispatch {
                    types: &types,
                    file: &item.file,
                    file_scope_range: Range {
                        start_byte: 0,
                        end_byte: item.source.len(),
                        start_line: 0,
                        end_line: item.line_starts.len().saturating_sub(1),
                    },
                    realm: realm_languages.map(|languages| ForeignJvmRealm {
                        analyzer,
                        languages,
                        frontier,
                    }),
                };
                let mut hits = vec![BTreeSet::new(); target_count];
                let mut observed_hits = BTreeSet::new();
                let mut unproven_hits = BTreeSet::new();
                let mut sink = ScalaQueryHitSink {
                    analyzer: &dispatch,
                    scala: self.scala,
                    file: &item.file,
                    source: &item.source,
                    class_ranges: item.class_ranges.clone(),
                    line_starts: item.line_starts.clone(),
                    catalog,
                    eligibility: &item.eligibility,
                    hits: &mut hits,
                    observed_hits: &mut observed_hits,
                    unproven_hits: keep_unproven.then_some(&mut unproven_hits),
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
                    &item.file,
                    &item.source,
                    &item.tree,
                    item.class_ranges.clone(),
                    &mut sink,
                    Some(self.cancellation),
                );
                let limit_exceeded = sink.limit_exceeded;
                drop(sink);
                ScalaFileScan {
                    hits,
                    observed_hits,
                    unproven_hits,
                    limit_exceeded,
                }
            })
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
        let scan = match ScalaFrontierScan::seed(self.scala, analyzer, cancellation) {
            ScalaFrontierSeedOutcome::Ready(scan) => scan,
            ScalaFrontierSeedOutcome::Cancelled => {
                return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
            }
            ScalaFrontierSeedOutcome::Failed(reason) => {
                return GraphUsageOutcome::fallback_safe(
                    overloads[0].fq_name(),
                    GraphFailureReason::UnsupportedTargetShape(reason),
                    "ScalaUsageGraphStrategy",
                );
            }
        };
        let catalog = match scan.resolve_types("scala_target_catalog", |types| {
            ScalaQueryTargetCatalog::build(
                self.scala,
                token,
                types,
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
        let scan_files: Vec<ProjectFile> = files.iter().map(|(file, _)| file.clone()).collect();
        scan.prefetch_file_facts(&scan_files);
        let prepared_files =
            prepare_scala_files(analyzer, self.scala, files, cancellation, |_| true);
        let file_results = match scan.scan(
            analyzer,
            token,
            &prepared_files,
            &catalog,
            overloads.len(),
            max_usages,
            None,
            false,
        ) {
            RelationalItemFrontierOutcome::Complete(results) => {
                results.into_iter().map(Some).collect()
            }
            RelationalItemFrontierOutcome::Cancelled(results) => results,
            RelationalItemFrontierOutcome::Failed(error) => {
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
        for file_scan in file_results.into_iter().flatten() {
            for (target_hits, file_target_hits) in hits.iter_mut().zip(file_scan.hits) {
                target_hits.extend(file_target_hits);
            }
            observed_hits.extend(file_scan.observed_hits);
            limit_exceeded |= file_scan.limit_exceeded;
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

    pub(crate) fn build_inbound_edges_with_completeness<F>(
        &self,
        _analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callees: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeBuildResult<UsageEdges>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_scala_edges_with_completeness(
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
