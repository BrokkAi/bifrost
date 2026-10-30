//! Kotlin structured reference, usage, and call graphs (issue #1239).
//!
//! Answers "who uses this Kotlin declaration?" from the Kotlin tree-sitter syntax
//! tree and the analyzer's indexed declarations. Nothing here recovers structure
//! by scanning source text, and nothing reports a reference it could not prove:
//! a reference whose identity cannot be established is recorded as *unproven*,
//! which keeps "we don't know" from collapsing into either "yes" or "no".
//!
//! # Where this sits
//!
//! Java, Scala, and Kotlin share one usage *candidate space* — the `Jvm`
//! ecosystem in `crate::analyzer::usages::workspace_graph` — because they compile
//! to one classpath and can name one another's types directly. Kotlin has been a
//! passive member of that space since issue #1237: Java and Scala references can
//! resolve *onto* Kotlin declarations. This module is what makes the realm
//! symmetric by giving Kotlin source references of its own.
//!
//! # Modelled on Java, not Scala
//!
//! Kotlin's identity model is Java's: dotted package-qualified fully-qualified
//! names, arity-distinguished overloads, an ancestor chain for inherited members.
//! Scala's usage graph is several times larger because Scala has `given`/`using`,
//! implicit conversions, `apply`/`unapply` extractors, export clauses, and union
//! types, none of which Kotlin has. So the module structure here mirrors
//! `super::java_graph` — a target model, a forward scan, a hit recorder — while
//! the syntax it reads comes from [`brokk_bifrost_jvm::kotlin::syntax`], shared
//! with the #1238 definition resolver so navigation and usages cannot drift
//! apart.
//!
//! # What this answers
//!
//! Both usage paths. The *query* path ([`shared::KotlinQueryResolver`]) answers
//! "who uses this declaration?" for `scan_usages`, LSP references, and
//! reference-rewriting rename: a reference to a Kotlin type, constructor,
//! function, or property resolves through inheritance, companions, objects,
//! extensions, and receiver chains, with same-owner and unproven references in
//! their own channels. The *edge* path ([`shared::KotlinEdgeResolver`]) builds
//! the whole `caller -> callee` set in one inverted pass, for `usage_graph`,
//! `callers`/`callees`, relevance ranking, and dead-code detection.
//!
//! Both directions share their entire resolution backbone through
//! [`brokk_bifrost_jvm::kotlin::graph::resolver::KotlinResolutionCtx`], so
//! find-references and `usage_graph` cannot disagree about which declaration a
//! call means.
//!
//! Cross-language: a *type* query crosses the realm both ways — a Kotlin class's
//! Java and Scala call sites are reported, and Kotlin files are scanned for Java
//! and Scala class targets. A *member* reference does not cross: which
//! declaration `receiver.member` binds to is decided by the target language's
//! own member-lookup rules, and answering one language's question with another's
//! would be a guess (#1239).

mod shared;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

pub(crate) use crate::analyzer::usages::kotlin_graph::shared::scan_kotlin_files_for_jvm_type;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

use brokk_bifrost_analysis::analyzer::usages::common::with_relational_frontier;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use crate::analyzer::usages::kotlin_graph::shared::KotlinEdgeResolver;

use crate::analyzer::usages::kotlin_graph::shared::KotlinQueryResolver;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_jvm::kotlin::graph::KotlinGraphSource;
use brokk_bifrost_jvm::kotlin::graph::extractor::{ScanState, scan_parsed_file};
use brokk_bifrost_jvm::kotlin::graph::resolver::TargetSpec;

#[cfg(test)]
use crate::inline_project;

fn kotlin_graph_source<'a>(
    analyzer: &'a dyn IAnalyzer,
    relational_definitions: &'a dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier,
) -> KotlinGraphSource<'a> {
    KotlinGraphSource {
        reads: brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            crate::analyzer::kotlin::KotlinAnalyzer,
        >(analyzer)
        .expect("a Kotlin graph requires its language analyzer")
        .read_capability(),
        index: analyzer,
        hierarchy: analyzer.type_hierarchy_provider(),
        imports: analyzer.import_analysis_provider(),
        relational_definitions,
    }
}

/// Run `visit` with the [`KotlinGraphSource`] built from the *dispatching*
/// analyzer.
///
/// A callback rather than a constructor because the request-local relational
/// frontier is valid only while its owned graph computation is being evaluated.
fn with_kotlin_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    mut visit: impl FnMut(KotlinGraphSource<'_>) -> R,
) -> R {
    with_relational_frontier(analyzer, "Kotlin", |frontier| {
        visit(kotlin_graph_source(analyzer, frontier))
    })
}

pub(crate) fn kotlin_target_spec_replayable(
    relational_session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    targets: &[CodeUnit],
) -> brokk_bifrost_core::analyzer::definition_lookup::RelationalFrontierOutcome<
    Option<brokk_bifrost_jvm::kotlin::graph::resolver::TargetSpec>,
> {
    relational_session.resolve_owned("kotlin_target_spec", |frontier| {
        brokk_bifrost_jvm::kotlin::graph::resolver::TargetSpec::from_targets(
            &kotlin_graph_source(analyzer, frontier.as_ref()),
            token,
            targets,
        )
    })
}

/// A candidate file read and parsed once, so the barrier scan below replays
/// only resolution work when a file's frontier discovers a new dependency
/// layer.
pub(crate) struct PreparedKotlinScanFile {
    pub(crate) file: ProjectFile,
    pub(crate) parsed: brokk_bifrost_core::analyzer::usages::parsed_tree::ParsedTreeFile,
}

/// Read and parse each candidate once, preferring the indexed overlay text
/// over the on-disk text exactly as the per-file scan did. Unreadable and
/// empty files scan as nothing, so they prepare as nothing.
pub(crate) fn prepare_kotlin_scan_files(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
) -> Vec<PreparedKotlinScanFile> {
    use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;

    use brokk_bifrost_core::analyzer::usages::parsed_tree::parse_tree_sitter_source;
    let language = brokk_bifrost_jvm::kotlin::language::LANGUAGE.into();
    files
        .iter()
        .filter_map(|file| {
            let source = analyzer
                .indexed_source(file)
                .or_else(|| analyzer.project().read_source(file).ok())?;
            let parsed = parse_tree_sitter_source(source, ParseSpec::whole(&language))?;
            Some(PreparedKotlinScanFile {
                file: file.clone(),
                parsed,
            })
        })
        .collect()
}

/// One file's owned scan result: proven hits, unproven hits, the raw match
/// count, and whether this file alone exceeded the usage limit.
pub(crate) type KotlinFileScanOutput = (
    std::collections::BTreeSet<brokk_bifrost_core::analyzer::usages::model::UsageHit>,
    std::collections::BTreeSet<brokk_bifrost_core::analyzer::usages::model::UsageHit>,
    usize,
    bool,
);

/// Scan every prepared file against `spec` over immutable frontier snapshots.
///
/// The per-file sequential loop this replaces converged each file's frontier
/// on its own -- one SQL barrier per newly discovered layer per file, all on
/// the caller thread -- so a whole-workspace Kotlin scan paid hundreds of
/// serial batches and zero file concurrency. Item barriers evaluate files in
/// parallel, deduplicate every pass's missing questions into one batch, and
/// replay only the files that observed a miss (#2886 scan-path milestone).
pub(crate) fn scan_kotlin_files_replayable(
    relational_session: &brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    prepared: &[PreparedKotlinScanFile],
    spec: &TargetSpec,
    max_usages: usize,
) -> brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome<
    KotlinFileScanOutput,
> {
    relational_session.resolve_owned_items("kotlin_file_scan", prepared, |prepared, frontier| {
        let mut hits = std::collections::BTreeSet::new();
        let mut unproven_hits = std::collections::BTreeSet::new();
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };
        scan_parsed_file(
            &kotlin_graph_source(analyzer, frontier.as_ref()),
            token,
            &prepared.file,
            &prepared.parsed.source,
            &prepared.parsed.line_starts,
            prepared.parsed.tree.root_node(),
            spec,
            &mut state,
        );
        (hits, unproven_hits, raw_match_count, limit_exceeded)
    })
}

/// Every Kotlin `caller -> callee` edge whose callee is one of `nodes`.
#[cfg(test)]
pub(crate) fn build_kotlin_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = KotlinEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, token, nodes, keep_file))
}

pub(crate) fn build_rooted_kotlin_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = KotlinEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_rooted_edges(analyzer, token, callers, keep_file))
}

pub(crate) fn build_inbound_kotlin_usage_edges_with_completeness(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callees: &HashSet<String>,
) -> Option<UsageEdgeBuildResult<UsageEdges>> {
    let resolver = KotlinEdgeResolver::try_new(analyzer)?;
    resolver.build_inbound_edges_with_completeness(analyzer, token, callees, |_| true)
}

/// The same edge set as [`build_kotlin_usage_edges`], weighted by call site.
pub(crate) fn build_kotlin_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = KotlinEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, token, nodes, keep_file))
}

#[derive(Default)]
pub struct KotlinUsageGraphStrategy {
    _private: (),
}

impl KotlinUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Kotlin
    }
}

impl GraphUsageAnalyzer for KotlinUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            KotlinQueryResolver,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Kotlin,
                unsupported_target: "target is not Kotlin",
                missing_analyzer: "analyzer does not expose KotlinAnalyzer",
                strategy: "KotlinUsageGraphStrategy",
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::usages::kotlin_graph::*;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use crate::analyzer::KotlinAnalyzer;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    fn kotlin_path_scoped_method_fixture(
        candidate_count: usize,
    ) -> (KotlinAnalyzer, CodeUnit, HashSet<ProjectFile>) {
        let fixture = (0..candidate_count)
            .fold(
                inline_project::InlineTestProject::with_language(Language::Kotlin).file(
                    "Service.kt",
                    "package api\n\nclass Service { fun run() {} }\n",
                ),
                |fixture, index| {
                    fixture.file(
                        format!("Consumer{index}.kt"),
                        format!(
                            "package app\n\nimport api.Service\n\n\
                         class Consumer{index} {{\n\
                             private val service = Service()\n\n\
                             fun call() {{ service.run() }}\n\
                         }}\n"
                        ),
                    )
                },
            )
            .build();
        let analyzer = KotlinAnalyzer::new(fixture.project_arc());
        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "api.Service.run")
            .expect("fixture declares Service.run");
        let candidates = (0..candidate_count)
            .map(|index| ProjectFile::new(fixture.root(), format!("Consumer{index}.kt")))
            .collect();
        (analyzer, target, candidates)
    }

    #[test]
    #[hardwon(
        "#2883: Twenty-four real Kotlin callers resolve while the path-scoped query reuses relational answers"
    )]
    fn kotlin_path_scoped_method_scan_reuses_relational_answers() {
        const CANDIDATE_COUNT: usize = 24;

        let (analyzer, target, candidates) = kotlin_path_scoped_method_fixture(CANDIDATE_COUNT);
        let scan_scope = UsageScanScope::new(&candidates);
        let before = analyzer.relational_batch_reader_checkouts_for_test();

        let outcome = KotlinUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scan_scope, 1000)
            .into_fuzzy_result();

        let reader_checkouts = analyzer.relational_batch_reader_checkouts_for_test() - before;
        assert_eq!(
            outcome.all_hits_including_imports().len(),
            CANDIDATE_COUNT,
            "every candidate must retain its structured call reference: {outcome:?}"
        );
        assert!(
            reader_checkouts < CANDIDATE_COUNT,
            "one path-scoped Kotlin query must reuse relational answers: {reader_checkouts} reader checkouts for {CANDIDATE_COUNT} candidates"
        );
    }

    /// Cost pin for #2883. A relational batch merges the file states that
    /// override persisted rows, which is the workspace's open overlays. With no
    /// overlay open it must materialize none of them, however many file states
    /// the analyzer has cached -- the walk used to visit every cached state and
    /// deep-clone the survivors, so a warm scan cost more than a cold one.
    #[test]
    #[hardwon(
        "#2883: After warming the Kotlin scan, a second query reuses file state instead of rematerializing candidates"
    )]
    fn kotlin_warm_scan_materializes_no_cached_file_states() {
        const CANDIDATE_COUNT: usize = 12;

        let (analyzer, target, candidates) = kotlin_path_scoped_method_fixture(CANDIDATE_COUNT);
        let scan_scope = UsageScanScope::new(&candidates);
        let scan = || {
            KotlinUsageGraphStrategy::new()
                .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scan_scope, 1000)
                .into_fuzzy_result()
        };

        // The first scan is what warms the file-state caches with every
        // candidate; the second is the warm request the pin is about.
        assert_eq!(scan().all_hits_including_imports().len(), CANDIDATE_COUNT);
        analyzer.reset_authoritative_file_state_reads_for_test();
        let outcome = scan();

        assert_eq!(
            outcome.all_hits_including_imports().len(),
            CANDIDATE_COUNT,
            "the warm scan must still find every reference: {outcome:?}"
        );
        assert_eq!(
            analyzer.authoritative_file_state_reads_for_test(),
            0,
            "a workspace with no overlay open must materialize no file state to answer a relational batch"
        );
    }

    /// An empty selected file is scanned, not omitted.
    ///
    /// An empty source parses to a childless root and contributes no edges,
    /// which is an exact per-file result rather than a missing one. This test
    /// used to assert the opposite -- that `Empty.kt` made the graph
    /// uncacheable -- because the on-demand parse refused an empty source. Every
    /// language on the completeness-tracking driver then refused its whole graph
    /// over an empty file, which is how `usage_graph` came to fail on any Python
    /// package with an empty `__init__.py`. The driver's genuine fail-closed
    /// behavior, on a file whose scan really did produce nothing, is pinned by
    /// `inverted_edges::tests::incomplete_file_results_are_observable_and_never_published`.
    #[test]
    #[hardwon(
        "e91fd3a11f33: an empty selected file must yield an empty scan result instead of making the graph incomplete"
    )]
    fn kotlin_inbound_bulk_build_scans_an_empty_selected_file() {
        let fixture = inline_project::InlineTestProject::with_language(Language::Kotlin)
            .file(
                "Service.kt",
                "package api\n\nclass Service { fun run() {} }\n",
            )
            .file(
                "Consumer.kt",
                "package app\n\nimport api.*\n\nclass Consumer { fun call(service: Service) { service.run() } }\n",
            )
            .file("Empty.kt", "")
            .build();
        let analyzer = KotlinAnalyzer::new(fixture.project_arc());
        let cancellation = CancellationToken::new();
        let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
        let callees = HashSet::from_iter(["api.Service.run".to_string()]);

        let result =
            build_inbound_kotlin_usage_edges_with_completeness(&analyzer, scope.token(), &callees)
                .expect("active query cancellation should permit the Kotlin bulk build");
        let UsageEdgeBuildResult::Complete(edges) = result else {
            panic!("an empty selected file must not make the graph uncacheable");
        };
        assert!(edges.edges.contains_key(&(
            "app.Consumer.call".to_string(),
            "api.Service.run".to_string()
        )));
    }
    /// A whole-workspace edge build reads every file's declarations in *bulk*,
    /// and never pulls a file through the per-file LRU more than once.
    ///
    /// Scala's builder learned the first half: hydrating each file through the
    /// LRU during a whole-workspace build evicts the entries a user's
    /// interactive queries depend on, so one `usage_graph` call would leave
    /// every subsequent `scan_usages` cold.
    ///
    /// Kotlin reaches *one* LRU hydration per file that Scala and Java do not,
    /// and the bound is asserted rather than hidden. Both of those builders
    /// resolve entirely through workspace-wide indexes; Kotlin additionally
    /// reads per-*declaration* published facts — an overload's arities, a
    /// companion marker, a callee's return type — which are keyed by declaration
    /// rather than by file and so go through the declaring file's state. That
    /// pulls each file in once and then hits the transient cache, which is why
    /// the bound below is one per file and not one per declaration. Per-
    /// declaration facts are still read through each declaring file's state.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn kotlin_usage_graph_bulk_fetch_hydrates_each_file_at_most_once() {
        const FILE_COUNT: usize = 132;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("C{index}.kt"));
            file.write(format!(
                "package bulk\n\nopen class Base{index} {{\n\n    fun run(): Int {{\n        return {index}\n    }}\n}}\n\nclass C{index} : Base{index}() {{\n\n    fun call(other: Base{index}): Int {{\n        return other.run()\n    }}\n}}\n"
            ))
            .unwrap();
        }
        let project = TestProject::new(root, Language::Kotlin);
        let mut analyzer = KotlinAnalyzer::new(Arc::new(project.clone()));
        let warm_file = ProjectFile::new(project.root().to_path_buf(), "C0.kt");

        analyzer.clear_retained_file_states_for_test();
        analyzer.reset_full_hydration_count_for_test();
        assert!(!analyzer.declarations(&warm_file).is_empty());
        let lru_after_warm = analyzer.full_hydration_count_for_test();
        assert_eq!(lru_after_warm, 1);

        let nodes: HashSet<String> = analyzer
            .all_declarations()
            .map(|unit| unit.fq_name())
            .collect();
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            lru_after_warm,
            "declaration cataloging must not hydrate through the LRU path"
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let edges = build_kotlin_usage_edges(&analyzer, token, &nodes, |_| true)
            .expect("kotlin usage graph should build");
        assert!(
            edges
                .edges
                .contains_key(&("bulk.C0.call".to_string(), "bulk.Base0.run".to_string())),
            "the build must still produce the edges it is being measured on"
        );
        let full_after_build = analyzer.full_hydration_count_for_test();
        assert!(
            full_after_build <= FILE_COUNT,
            "whole-workspace graph build must hydrate at most once per file, got {full_after_build} for {FILE_COUNT} files"
        );
        assert_eq!(
            analyzer.bulk_hydration_count_for_test(),
            FILE_COUNT,
            "bulk hydrations should be exactly one per file"
        );

        assert!(!analyzer.declarations(&warm_file).is_empty());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            full_after_build,
            "a point query after the build must be served from cache, not re-hydrated"
        );
    }
}
