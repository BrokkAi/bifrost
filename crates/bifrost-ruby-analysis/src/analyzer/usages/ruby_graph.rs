//! Receiver-aware Ruby usage resolution.
//!
//! Ruby remains dynamic, so this strategy only emits graph hits when parser and
//! analyzer facts prove the target. Same-name calls with unknown receivers are
//! returned in the unproven usage tier so callers can treat them as
//! inconclusive evidence instead of query failure.

use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
mod shared;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_core::analyzer::common::language_for_file;

use brokk_bifrost_ruby::declarations::parse_ruby_tree;

use brokk_bifrost_analysis::analyzer::usages::common::classify_recursive_hits;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::EdgeNodeDomain;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildOutput;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_edge_output_with_completeness;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::build_file_declarations;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::parse_source_and_collect_with_declarations_and_domain;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_core::analyzer::usages::outcome::GraphFailureReason;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_analysis::analyzer::usages::traits::UsageQueryResolver;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::RubyAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::text_utils::compute_line_starts;
use brokk_bifrost_ruby::graph::RubyGraphSource;
use brokk_bifrost_ruby::graph::extractor::RubyFileScan;
use brokk_bifrost_ruby::graph::resolver::RubySemanticIndex;
use brokk_bifrost_ruby::graph::resolver::RubyTargetSpec;
use std::collections::BTreeSet;

use crate::analyzer::usages::ruby_graph::shared::RubyEdgeResolver;

const STRATEGY: &str = "RubyUsageGraphStrategy";

/// Run `visit` with the [`RubyGraphSource`] built from the *dispatching*
/// analyzer.
///
/// A callback rather than a constructor because the request-local bounded
/// lookup borrows the dispatching analyzer and must outlive every synchronous
/// Ruby resolution performed by `visit`.
pub(crate) fn with_ruby_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    visit: impl FnOnce(RubyGraphSource<'_>) -> R,
) -> R {
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::None);
    let definitions = |consume: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| {
        consume(&support);
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    visit(RubyGraphSource {
        token: scope.token(),
        index: analyzer,
        definitions: &definitions,
    })
}

/// The whole-workspace inverted pass: the shared driver's parallel fan-out plus
/// on-demand parsing, with [`brokk_bifrost_ruby::graph::inverted::scan_file`]
/// resolving each file.
fn build_ruby_edges<Output, F>(
    graph: RubyGraphSource<'_>,
    analyzer: &dyn IAnalyzer,
    ruby: &RubyAnalyzer,
    files: &[ProjectFile],
    domain: EdgeNodeDomain<'_>,
    keep_file: F,
) -> Option<Output>
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_ruby::LANGUAGE.into();
    let result = build_edge_output_with_completeness(files, keep_file, |file| {
        let visible_files =
            RubySemanticIndex::build_for_lookup(graph, ruby).visible_files_from(file)?;
        let source = analyzer.project().read_source(file).ok()?;
        if !analyzer.indexed_source_matches(file, &source) {
            return None;
        }
        let declarations = build_file_declarations(analyzer, file);
        parse_source_and_collect_with_declarations_and_domain(
            source,
            file,
            domain,
            ParseSpec::whole(&language),
            declarations,
            |input| {
                graph.with_definitions(|support| {
                    brokk_bifrost_ruby::graph::inverted::scan_file(
                        graph,
                        ruby,
                        support,
                        file,
                        input,
                        visible_files,
                    )
                })
            },
        )
    });
    match result {
        UsageEdgeBuildResult::Complete(output) => Some(output),
        UsageEdgeBuildResult::Uncacheable { omitted_files, .. } => {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "Ruby edge inputs are unavailable: {omitted_files:?}"
                )),
            );
            None
        }
    }
}

pub fn build_ruby_usage_edges(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdges> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    resolver.build_edges(analyzer, nodes, keep_file)
}

pub(crate) fn build_rooted_ruby_usage_edges(
    analyzer: &dyn IAnalyzer,
    callers: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdges> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    resolver.build_rooted_edges(analyzer, callers, keep_file)
}

pub(crate) fn build_ruby_usage_edge_weights(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdgeWeights> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    resolver.build_edges(analyzer, nodes, keep_file)
}

/// Ruby's implementation of the shared query-path contract.
///
/// Candidate planning is owned by [`UsageFinder`]. In particular, Zeitwerk
/// references are admitted from the persisted identifier index before either
/// budget runs; this resolver never expands its scan set after admission.
/// Cancellation returns the hits accumulated so far as a success so a partial
/// scan cannot be mistaken for proven absence.
pub(crate) struct RubyQueryResolver<'a> {
    ruby: &'a RubyAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for RubyQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            ruby: resolve_analyzer::<RubyAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        with_ruby_graph_source(analyzer, |graph| {
            self.find_usages_with(graph, analyzer, overloads, scan_scope, max_usages)
        })
    }
}

impl RubyQueryResolver<'_> {
    fn find_usages_with(
        &self,
        graph: RubyGraphSource<'_>,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let ruby = self.ruby;
        let Some(spec) = RubyTargetSpec::from_target(&graph, ruby, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                STRATEGY,
            );
        };

        if !ruby.canonical_sources_ready() {
            return GraphUsageOutcome::terminal_failure(
                target.fq_name(),
                GraphFailureReason::UnavailableCanonicalFacts("Ruby source facts are unavailable"),
                STRATEGY,
            );
        }
        let semantic = RubySemanticIndex::build(graph, ruby, &spec);
        let scan_files = scan_scope.candidate_files();

        let mut hits = BTreeSet::new();
        let mut unproven_hits = BTreeSet::new();
        for file in scan_files {
            if scan_scope.is_cancelled() {
                break;
            }
            if language_for_file(file) != Language::Ruby {
                continue;
            }
            let Ok(source) = analyzer.project().read_source(file) else {
                continue;
            };
            let Some(tree) = parse_ruby_tree(&source) else {
                continue;
            };
            let line_starts = compute_line_starts(&source);
            let Some(visible_files) = semantic.visible_files_from(file) else {
                return GraphUsageOutcome::terminal_failure(
                    target.fq_name(),
                    GraphFailureReason::UnavailableCanonicalFacts(
                        "Ruby load closure is unavailable",
                    ),
                    STRATEGY,
                );
            };
            graph.with_definitions(|support| {
                let mut scan = RubyFileScan {
                    index: analyzer,
                    semantic: &semantic,
                    support,
                    file,
                    source: &source,
                    line_starts: &line_starts,
                    visible_files,
                    spec: &spec,
                    hits: &mut hits,
                    unproven_hits: &mut unproven_hits,
                };
                scan.scan(tree.root_node());
            });
        }

        // A proven hit inside the target itself is a recursive call (#1638):
        // kept, classified `SelfReceiver`. The unproven channel still drops
        // them -- an unproven recursive call is not evidence of anything.
        let hits = classify_recursive_hits(analyzer, hits, &spec.target);
        let unproven_hits: BTreeSet<_> = unproven_hits
            .into_iter()
            .filter(|hit| hit.enclosing != spec.target)
            .collect();

        let external_callsites =
            brokk_bifrost_core::analyzer::usages::common::external_usage_hit_count(&hits);
        if external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: spec.target.short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven_limit(
            spec.target.clone(),
            hits,
            unproven_hits,
            scan_scope.max_unproven(),
        ))
    }
}

#[derive(Default)]
pub struct RubyUsageGraphStrategy;

impl RubyUsageGraphStrategy {
    pub const fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Ruby
    }
}

impl GraphUsageAnalyzer for RubyUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            RubyQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Ruby,
                unsupported_target: "target is not Ruby",
                missing_analyzer: "Ruby analyzer is unavailable",
                strategy: STRATEGY,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    pub(super) use super::test_support::*;

    use crate::analyzer::usages::ruby_graph::*;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_core::cancellation::CancellationToken;
    use std::path::PathBuf;

    fn proven_hit_owners(outcome: &GraphUsageOutcome) -> Vec<String> {
        match outcome {
            GraphUsageOutcome::Resolved(FuzzyResult::Success {
                hits_by_overload, ..
            }) => hits_by_overload
                .values()
                .flat_map(|hits| hits.iter())
                .map(|hit| hit.enclosing.fq_name())
                .collect(),
            other => panic!("expected a resolved success, got {other:?}"),
        }
    }

    /// Ruby breaks its scan loop on cancellation and returns what it already proved.
    /// The sibling resolvers discard partial work and return `empty_success`; adopting
    /// that here would turn a cancelled query into a false "0 usages".
    #[test]
    fn cancellation_keeps_the_hits_the_scan_already_proved() {
        let callers: Vec<(String, String)> = (0..6)
            .map(|index| {
                (
                    format!("app/controllers/caller_{index}_controller.rb"),
                    format!(
                        "class Caller{index}Controller\n  def show\n    User.build\n  end\nend\n"
                    ),
                )
            })
            .collect();
        let mut files = vec![
            (
                "Gemfile",
                "source \"https://rubygems.org\"\ngem \"rails\"\n",
            ),
            (
                "app/models/user.rb",
                "class User\n  def self.build\n    new\n  end\nend\n",
            ),
        ];
        files.extend(
            callers
                .iter()
                .map(|(path, source)| (path.as_str(), source.as_str())),
        );
        let (_temp, root) = write_project(&files);
        let analyzer = ruby_analyzer(&root);
        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");
        let strategy = RubyUsageGraphStrategy::new();
        let candidates = analyzer.analyzed_files().into_iter().collect();

        let complete = proven_hit_owners(&strategy.find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&candidates),
            100,
        ))
        .len();
        assert_eq!(complete, callers.len(), "every caller must be provable");

        // `cancel_after_checks_for_test` counts `is_cancelled()` calls, one per scanned
        // file, so sweeping the count visits the window where the loop has proved some
        // hits but not all. Scan order over the file set is unspecified, hence the sweep.
        let partial = (1..=callers.len() + 2)
            .find_map(|checks| {
                let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
                let outcome = strategy.find_graph_usages(
                    &analyzer,
                    std::slice::from_ref(&target),
                    &UsageScanScope::with_cancellation(&candidates, &cancellation),
                    100,
                );
                let hits = proven_hit_owners(&outcome).len();
                (hits > 0 && hits < complete).then_some(hits)
            })
            .expect("a cancelled Ruby scan must report the hits it already proved");
        assert!(partial < complete);
    }

    // Restored Ruby usage-query gates and bounded-query behavior.

    #[test]
    fn zeitwerk_candidates_are_planned_without_global_reference_indexes() {
        let (_temp, root) = zeitwerk_project();
        let analyzer = ruby_analyzer(&root);
        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");

        assert!(!analyzer.global_semantic_index_initialized_for_test());
        let query = brokk_bifrost_analysis::analyzer::usages::finder::UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            100,
            100,
        );
        assert!(
            query
                .result
                .all_hits()
                .iter()
                .any(|hit| hit.enclosing.fq_name().contains("show")),
            "the indexed planner must admit the Zeitwerk referrer: {:?}",
            query.result.all_hits()
        );
        assert!(
            !analyzer.global_semantic_index_initialized_for_test(),
            "a target query must not materialize the repository-wide Ruby semantic index"
        );
    }

    #[test]
    fn exceeding_the_usage_cap_resolves_to_too_many_callsites() {
        let (_temp, root) = zeitwerk_project();
        let analyzer = ruby_analyzer(&root);
        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");
        let candidates = analyzer.analyzed_files().into_iter().collect();

        let outcome = RubyUsageGraphStrategy::new().find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&candidates),
            0,
        );
        match outcome {
            GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name,
                total_callsites,
                limit,
                sample_hits,
            }) => {
                assert_eq!(short_name, target.short_name());
                assert_eq!(total_callsites, 1);
                assert_eq!(limit, 0);
                assert_eq!(sample_hits.len(), 1);
            }
            other => panic!("expected a resolved TooManyCallsites, got {other:?}"),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
