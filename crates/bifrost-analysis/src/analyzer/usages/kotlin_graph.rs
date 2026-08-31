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
//! would be a guess. See `.agents/plans/kotlin-usage-graph-1239.md`.

mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

pub(crate) use shared::scan_kotlin_files_for_jvm_type;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeBuildResult, UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::kotlin_graph::shared::{KotlinEdgeResolver, KotlinQueryResolver};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_jvm::kotlin::graph::KotlinGraphSource;
use brokk_bifrost_jvm::kotlin::graph::extractor::{ScanState, scan_file};
use brokk_bifrost_jvm::kotlin::graph::resolver::TargetSpec;

#[cfg(test)]
use crate::inline_project;

fn kotlin_graph_source<'a>(
    analyzer: &'a dyn IAnalyzer,
    relational_definitions: &'a dyn brokk_bifrost_core::analyzer::RelationalDefinitionFrontier,
) -> KotlinGraphSource<'a> {
    KotlinGraphSource {
        index: analyzer,
        hierarchy: analyzer.type_hierarchy_provider(),
        type_alias: analyzer.type_alias_provider(),
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
    let cancellation = crate::CancellationToken::new();
    match crate::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        &cancellation,
        |frontier| visit(kotlin_graph_source(analyzer, frontier)),
    ) {
        crate::analyzer::RelationalFrontierOutcome::Complete(result) => result,
        crate::analyzer::RelationalFrontierOutcome::Cancelled => {
            unreachable!("an uncancelled Kotlin helper frontier cannot cancel")
        }
        crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
            panic!("Kotlin relational helper frontier failed: {error:?}")
        }
    }
}

pub(super) fn kotlin_target_spec_replayable(
    relational_session: &crate::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    targets: &[CodeUnit],
) -> crate::analyzer::RelationalFrontierOutcome<
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

pub(super) fn scan_kotlin_file_replayable(
    relational_session: &crate::analyzer::relational_frontier::RelationalFrontierSession<'_>,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) -> crate::analyzer::RelationalFrontierOutcome<()> {
    let initial_hits = state.hits.clone();
    let initial_unproven_hits = state.unproven_hits.clone();
    let initial_raw_match_count = *state.raw_match_count;
    let initial_limit_exceeded = *state.limit_exceeded;
    let max_usages = state.max_usages;
    let outcome = relational_session.resolve_owned("kotlin_file_scan", |frontier| {
        let mut hits = initial_hits.clone();
        let mut unproven_hits = initial_unproven_hits.clone();
        let mut raw_match_count = initial_raw_match_count;
        let mut limit_exceeded = initial_limit_exceeded;
        let mut provisional = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };
        scan_file(
            &kotlin_graph_source(analyzer, frontier.as_ref()),
            token,
            file,
            spec,
            &mut provisional,
        );
        (hits, unproven_hits, raw_match_count, limit_exceeded)
    });
    match outcome {
        crate::analyzer::RelationalFrontierOutcome::Complete((
            hits,
            unproven_hits,
            raw_match_count,
            limit_exceeded,
        )) => {
            *state.hits = hits;
            *state.unproven_hits = unproven_hits;
            *state.raw_match_count = raw_match_count;
            *state.limit_exceeded = limit_exceeded;
            crate::analyzer::RelationalFrontierOutcome::Complete(())
        }
        crate::analyzer::RelationalFrontierOutcome::Cancelled => {
            crate::analyzer::RelationalFrontierOutcome::Cancelled
        }
        crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
            crate::analyzer::RelationalFrontierOutcome::Failed(error)
        }
    }
}

/// Whether `unit` is a Kotlin `companion object`.
///
/// A wrapper over
/// [`brokk_bifrost_jvm::kotlin::graph::resolver::is_companion_object`] that
/// builds the graph source: the definition route asks this from a `&dyn
/// IAnalyzer` and stays in this crate until the `ResolutionSession` band moves.
pub(crate) fn is_companion_object(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    with_kotlin_graph_source(analyzer, |graph| {
        brokk_bifrost_jvm::kotlin::graph::resolver::is_companion_object(&graph, unit)
    })
}

/// Whether `unit` is a Kotlin `typealias`.
///
/// The same wrapping as [`is_companion_object`]: the definition ladder (#1238)
/// asks this from a `&dyn IAnalyzer`, and the alias marker itself lives behind
/// the graph source's type-alias provider (#2696).
pub(crate) fn is_kotlin_type_alias(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    with_kotlin_graph_source(analyzer, |graph| {
        brokk_bifrost_jvm::kotlin::graph::resolver::is_kotlin_type_alias(&graph, unit)
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
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Kotlin {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Kotlin"),
                "KotlinUsageGraphStrategy",
            );
        }

        let Some(resolver) = KotlinQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose KotlinAnalyzer",
                ),
                "KotlinUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{KotlinAnalyzer, Project, TestProject};
    use std::sync::Arc;

    #[test]
    fn kotlin_forward_type_and_member_resolution_builds_no_global_definition_shard() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "Service.kt")
            .write("package api\n\nclass Service { fun run() {} }\n")
            .expect("write Kotlin service");
        let consumer = ProjectFile::new(root.clone(), "Consumer.kt");
        consumer
            .write(
                "package app\n\nimport api.*\n\n\
                 class Consumer { fun call(service: Service) { service.run() } }\n",
            )
            .expect("write Kotlin fixture");
        let analyzer = KotlinAnalyzer::new(Arc::new(TestProject::new(root, Language::Kotlin)));
        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "api.Service.run")
            .expect("fixture declares Service.run");
        let candidates = HashSet::from_iter([consumer]);
        let scan_scope = UsageScanScope::new(&candidates);

        let outcome = KotlinUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scan_scope, 100)
            .into_fuzzy_result();

        assert_eq!(outcome.all_hits_including_imports().len(), 1, "{outcome:?}");
    }

    #[test]
    fn kotlin_path_scoped_method_scan_reuses_relational_answers() {
        const CANDIDATE_COUNT: usize = 24;

        let fixture = (0..CANDIDATE_COUNT)
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
        let candidates = (0..CANDIDATE_COUNT)
            .map(|index| ProjectFile::new(fixture.root(), format!("Consumer{index}.kt")))
            .collect::<HashSet<_>>();
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

    #[test]
    fn kotlin_inverted_type_and_member_resolution_uses_relational_lookup() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "Service.kt")
            .write("package api\n\nclass Service { fun run() {} }\n")
            .expect("write Kotlin service");
        ProjectFile::new(root.clone(), "Consumer.kt")
            .write(
                "package app\n\nimport api.*\n\n\
                 class Consumer { fun call(service: Service) { service.run() } }\n",
            )
            .expect("write Kotlin consumer");
        let analyzer = KotlinAnalyzer::new(Arc::new(TestProject::new(root, Language::Kotlin)));
        let nodes = analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect::<HashSet<_>>();
        let scope = AnalyzerQueryScope::new(&analyzer);

        let edges = build_kotlin_usage_edges(&analyzer, scope.token(), &nodes, |_| true)
            .expect("Kotlin edge resolver should be available");

        assert!(
            edges.edges.keys().any(|(caller, callee)| {
                caller == "app.Consumer.call" && callee == "api.Service.run"
            }),
            "typed receiver call must resolve through relational name and member questions: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn kotlin_inbound_bulk_build_converges_with_one_request_local_frontier() {
        let fixture = inline_project::InlineTestProject::with_language(Language::Kotlin)
            .file(
                "Service.kt",
                "package api\n\nclass Service { fun run() {} }\n",
            )
            .file(
                "Consumer.kt",
                "package app\n\nimport api.*\n\nclass Consumer { fun call(service: Service) { service.run() } }\n",
            )
            .build();
        let analyzer = KotlinAnalyzer::new(fixture.project_arc());
        let cancellation = CancellationToken::new();
        let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
        let callees = HashSet::from_iter(["api.Service.run".to_string()]);

        let result =
            build_inbound_kotlin_usage_edges_with_completeness(&analyzer, scope.token(), &callees)
                .expect("active query cancellation should permit the Kotlin bulk build");
        let UsageEdgeBuildResult::Complete(edges) = result else {
            panic!("complete fixture must not produce omitted-file evidence");
        };

        assert!(edges.edges.contains_key(&(
            "app.Consumer.call".to_string(),
            "api.Service.run".to_string()
        )));
        assert!(edges.truncated.is_empty());
        assert!(edges.unproven_inbound.is_empty());
    }

    #[test]
    fn kotlin_inbound_bulk_build_fails_closed_when_pre_cancelled() {
        let fixture = inline_project::InlineTestProject::with_language(Language::Kotlin)
            .file(
                "Service.kt",
                "package api\n\nclass Service { fun run() {} }\n",
            )
            .build();
        let analyzer = KotlinAnalyzer::new(fixture.project_arc());
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancellation);
        let callees = HashSet::from_iter(["api.Service.run".to_string()]);

        assert!(
            build_inbound_kotlin_usage_edges_with_completeness(&analyzer, scope.token(), &callees,)
                .is_none()
        );
    }

    #[test]
    fn kotlin_inbound_bulk_build_fails_closed_on_selected_parse_miss() {
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
        let UsageEdgeBuildResult::Uncacheable {
            output,
            omitted_files,
        } = result
        else {
            panic!("an empty selected file must make the graph uncacheable");
        };
        assert_eq!(omitted_files, vec![fixture.file("Empty.kt")]);
        assert!(output.edges.contains_key(&(
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
    /// the bound below is one per file and not one per declaration. Closing it
    /// needs the per-declaration facts to be readable out of the bulk states,
    /// which is recorded as a follow-up in
    /// `.agents/plans/kotlin-usage-graph-1239.md`.
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
        let analyzer = KotlinAnalyzer::new(Arc::new(project.clone()));
        let warm_file = ProjectFile::new(project.root().to_path_buf(), "C0.kt");

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
