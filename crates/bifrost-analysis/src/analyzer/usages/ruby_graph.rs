//! Receiver-aware Ruby usage resolution.
//!
//! Ruby remains dynamic, so this strategy only emits graph hits when parser and
//! analyzer facts prove the target. Same-name calls with unknown receivers are
//! returned in the unproven usage tier so callers can treat them as
//! inconclusive evidence instead of query failure.

use crate::analyzer::usages::parsed_tree::ParseSpec;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

use crate::analyzer::common::language_for_file;
use crate::analyzer::ruby::parse_ruby_tree;
use crate::analyzer::usages::common::{classify_recursive_hits, language_for_target};
use crate::analyzer::usages::inverted_edges::{
    EdgeNodeDomain, UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output,
    parse_and_collect_with_domain,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    AnalyzerDefinitionLookup, BoundedDefinitionLookup, CodeUnit, IAnalyzer, Language, ProjectFile,
    RubyAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use brokk_bifrost_ruby::graph::RubyGraphSource;
use brokk_bifrost_ruby::graph::extractor::RubyFileScan;
use brokk_bifrost_ruby::graph::resolver::RubySemanticIndex;
use brokk_bifrost_ruby::graph::resolver::RubyTargetSpec;
use std::collections::BTreeSet;

use self::shared::RubyEdgeResolver;

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
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_ruby::LANGUAGE.into();
    build_edge_output(files, keep_file, |file| {
        parse_and_collect_with_domain(
            analyzer,
            file,
            domain,
            ParseSpec::whole(&language),
            |input| {
                graph.with_definitions(|support| {
                    brokk_bifrost_ruby::graph::inverted::scan_file(
                        graph, ruby, support, file, input,
                    )
                })
            },
        )
    })
}

pub fn build_ruby_usage_edges(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdges> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_rooted_ruby_usage_edges(
    analyzer: &dyn IAnalyzer,
    callers: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdges> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_rooted_edges(analyzer, callers, keep_file))
}

pub(crate) fn build_ruby_usage_edge_weights(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdgeWeights> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
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
            let visible_files = semantic.visible_files_from(file);
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

        let external_callsites = crate::analyzer::usages::common::external_usage_hit_count(&hits);
        if external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: spec.target.short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            spec.target.clone(),
            hits,
            unproven_hits,
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
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        if language_for_target(target) != Language::Ruby {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Ruby"),
                STRATEGY,
            );
        }
        let Some(resolver) = RubyQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability("Ruby analyzer is unavailable"),
                STRATEGY,
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::model::UsageAnalysisDiagnostic;
    use crate::analyzer::{CodeUnitIndex, CodeUnitType, PythonAnalyzer, TestProject};
    use crate::cancellation::CancellationToken;
    use std::path::{Path, PathBuf};

    fn write_project(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        for (path, contents) in files {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().expect("file has a parent"))
                .expect("create parent dir");
            std::fs::write(full, contents).expect("write fixture file");
        }
        (temp, root)
    }

    /// A Rails-shaped Zeitwerk layout: `UsersController#show` references `User.build`
    /// with no `require`, so only the autoload graph connects the two files.
    fn zeitwerk_project() -> (tempfile::TempDir, PathBuf) {
        write_project(&[
            (
                "Gemfile",
                "source \"https://rubygems.org\"\ngem \"rails\"\n",
            ),
            (
                "app/models/user.rb",
                "class User\n  def self.build\n    new\n  end\nend\n",
            ),
            (
                "app/controllers/users_controller.rb",
                "class UsersController\n  def show\n    User.build\n  end\nend\n",
            ),
        ])
    }

    fn ruby_analyzer(root: &Path) -> RubyAnalyzer {
        RubyAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Ruby))
    }

    fn declaration(analyzer: &dyn IAnalyzer, file: &ProjectFile, identifier: &str) -> CodeUnit {
        analyzer
            .declarations(file)
            .into_iter()
            .find(|unit| unit.identifier() == identifier)
            .unwrap_or_else(|| panic!("fixture declares {identifier} in {file:?}"))
    }

    fn fallback_diagnostic(outcome: GraphUsageOutcome) -> UsageAnalysisDiagnostic {
        match outcome {
            GraphUsageOutcome::FallbackSafe(diagnostic) => diagnostic,
            other => panic!("expected a fallback-safe outcome, got {other:?}"),
        }
    }

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

    /// The three gate strings and the strategy label are a stable contract of the Ruby
    /// path: the capability message in particular is deliberately *not* the siblings'
    /// "analyzer does not expose XAnalyzer" wording.
    #[test]
    fn the_three_ruby_gates_keep_their_exact_diagnostics() {
        let (_temp, root) = zeitwerk_project();
        let analyzer = ruby_analyzer(&root);
        let candidates = HashSet::default();
        let scope = UsageScanScope::new(&candidates);
        let strategy = RubyUsageGraphStrategy::new();

        let python_target = CodeUnit::new(
            ProjectFile::new(root.clone(), PathBuf::from("app/models/user.py")),
            CodeUnitType::Function,
            "app.models.user",
            "build",
        );
        let language_gate = fallback_diagnostic(strategy.find_graph_usages(
            &analyzer,
            &[python_target],
            &scope,
            100,
        ));
        assert_eq!(language_gate.strategy, "RubyUsageGraphStrategy");
        assert_eq!(language_gate.reason_kind, "unsupported_target_language");
        assert_eq!(
            language_gate.reason,
            "RubyUsageGraphStrategy: target is not Ruby"
        );

        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");
        let not_ruby_analyzer =
            PythonAnalyzer::from_project(TestProject::new(root.clone(), Language::Python));
        let capability_gate = fallback_diagnostic(strategy.find_graph_usages(
            &not_ruby_analyzer,
            std::slice::from_ref(&target),
            &scope,
            100,
        ));
        assert_eq!(capability_gate.strategy, "RubyUsageGraphStrategy");
        assert_eq!(capability_gate.reason_kind, "missing_analyzer_capability");
        assert_eq!(
            capability_gate.reason,
            "RubyUsageGraphStrategy: Ruby analyzer is unavailable"
        );

        let macro_target = CodeUnit::new(user_file, CodeUnitType::Macro, "", "User.build");
        let shape_gate = fallback_diagnostic(strategy.find_graph_usages(
            &analyzer,
            &[macro_target],
            &scope,
            100,
        ));
        assert_eq!(shape_gate.strategy, "RubyUsageGraphStrategy");
        assert_eq!(shape_gate.reason_kind, "unsupported_target_shape");
        assert_eq!(
            shape_gate.reason,
            "RubyUsageGraphStrategy: target shape is unsupported"
        );
    }

    /// The shared planner admits Zeitwerk consumers from persisted identifier
    /// facts before the budgets run. Ruby execution neither builds the old
    /// whole-workspace reference map nor the global semantic inversion.
    #[test]
    fn zeitwerk_candidates_are_planned_without_global_reference_indexes() {
        let (_temp, root) = zeitwerk_project();
        let analyzer = ruby_analyzer(&root);
        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");

        assert!(!analyzer.global_semantic_index_initialized_for_test());
        let query = crate::analyzer::usages::UsageFinder::new().query(
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

    /// The cap is a `Resolved` outcome carrying `TooManyCallsites`, not a failure
    /// variant, so callers see a guardrail rather than a broken query.
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
