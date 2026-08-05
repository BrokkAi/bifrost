//! Receiver-aware Ruby usage resolution.
//!
//! Ruby remains dynamic, so this strategy only emits graph hits when parser and
//! analyzer facts prove the target. Same-name calls with unknown receivers are
//! returned in the unproven usage tier so callers can treat them as
//! inconclusive evidence instead of query failure.

mod shared;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;

use crate::analyzer::common::language_for_file;
use crate::analyzer::ruby::parse_ruby_tree;
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{
    UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output, parse_and_collect,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, IAnalyzer, Language, ProjectFile, RubyAnalyzer,
    resolve_analyzer,
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
/// A callback rather than a constructor because the definition-index accessor is
/// itself a borrowed closure: `analyzer.global_usage_definition_index()` returns
/// a handle that borrows the analyzer, and the Ruby side takes it lazily so the
/// diagnostics pass -- which builds a `RubySemanticIndex` and never resolves a
/// factory return -- never pays for the build.
pub(crate) fn with_ruby_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    visit: impl FnOnce(RubyGraphSource<'_>) -> R,
) -> R {
    let definitions = |consume: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| {
        consume(&analyzer.global_usage_definition_index());
    };
    visit(RubyGraphSource {
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
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_ruby::LANGUAGE.into();
    build_edge_output(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |input| {
            let support = analyzer.global_usage_definition_index();
            brokk_bifrost_ruby::graph::inverted::scan_file(graph, ruby, &support, file, input)
        })
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

pub(crate) fn build_ruby_usage_edge_weights(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdgeWeights> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

/// Ruby's implementation of the shared query-path contract. Two divergences from the
/// sibling resolvers are deliberate and load-bearing rather than oversights, so a later
/// normalization pass must not quietly erase them:
///
/// * the scan set is augmented *after* the caller's budget has already been enforced,
///   with the target's own source and Zeitwerk's referring files (each still gated by
///   `UsageScanScope::allows`), so an implicit-autoload reference survives a `max_files`
///   or `max_source_bytes` truncation that would otherwise drop it;
/// * cancellation returns the hits accumulated so far as a success, where the siblings
///   discard partial work and return `FuzzyResult::empty_success`.
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
        let mut scan_files = scan_scope.candidate_files().clone();
        if scan_scope.allows(target.source()) {
            scan_files.insert(target.source().clone());
        }
        scan_files.extend(
            ruby.zeitwerk_reference_files_for_identifier(&spec.member_name)
                .into_iter()
                .filter(|file| scan_scope.allows(file)),
        );

        let mut hits = BTreeSet::new();
        let mut unproven_hits = BTreeSet::new();
        for file in &scan_files {
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
            let support = analyzer.global_usage_definition_index();
            let mut scan = RubyFileScan {
                index: analyzer,
                semantic: &semantic,
                support: &support,
                file,
                source: &source,
                line_starts: &line_starts,
                visible_files,
                spec: &spec,
                hits: &mut hits,
                unproven_hits: &mut unproven_hits,
            };
            scan.scan(tree.root_node());
        }

        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| hit.enclosing != spec.target)
            .collect();
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

impl UsageAnalyzer for RubyUsageGraphStrategy {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::model::UsageAnalysisDiagnostic;
    use crate::analyzer::{CodeUnitType, PythonAnalyzer, TestProject};
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
        let scope = UsageScanScope::new(&candidates, false);
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

    /// Scan-time augmentation: the target's own source and Zeitwerk's referring files
    /// join the scan set after budget enforcement, so an empty candidate set still finds
    /// the autoload reference. An authoritative scope is a hard boundary, and
    /// `UsageScanScope::allows` gates both additions back out.
    #[test]
    fn zeitwerk_and_target_source_join_the_scan_set_unless_the_scope_forbids_them() {
        let (_temp, root) = zeitwerk_project();
        let analyzer = ruby_analyzer(&root);
        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");
        let strategy = RubyUsageGraphStrategy::new();
        let empty = HashSet::default();

        let augmented = strategy.find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&empty, false),
            100,
        );
        assert!(
            proven_hit_owners(&augmented)
                .iter()
                .any(|fq_name| fq_name.contains("show")),
            "an empty candidate set must still reach the Zeitwerk referrer, got {:?}",
            proven_hit_owners(&augmented)
        );

        let gated = strategy.find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&empty, true),
            100,
        );
        assert!(
            proven_hit_owners(&gated).is_empty(),
            "an authoritative empty scope forbids both additions, got {:?}",
            proven_hit_owners(&gated)
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
        let empty = HashSet::default();

        let complete = proven_hit_owners(&strategy.find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&empty, false),
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
                    &UsageScanScope::with_cancellation(&empty, false, &cancellation),
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
        let empty = HashSet::default();

        let outcome = RubyUsageGraphStrategy::new().find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::new(&empty, false),
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
