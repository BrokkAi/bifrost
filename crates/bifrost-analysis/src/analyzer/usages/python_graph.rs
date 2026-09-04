//! The analysis-side wrappers over [`brokk_bifrost_python::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), and the inverted pass's fan-out -- `build_edge_output` and
//! `parse_and_collect` are the shared, language-agnostic driver.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::usages::parsed_tree::ParseSpec;
use crate::analyzer::usages::traits::GraphUsageAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

use crate::analyzer::usages::common::{classify_recursive_hits, language_for_target};
use crate::analyzer::usages::inverted_edges::{
    EdgeNodeDomain, UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output,
    parse_and_collect_with_domain,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{
    CandidateUsageHits, GraphFailureReason, GraphUsageOutcome, union_candidate_usages,
};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, PythonAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use brokk_bifrost_python::graph::PythonGraphSource;
use brokk_bifrost_python::graph::extractor::{build_python_graph, scan_files_for_seeds};
use brokk_bifrost_python::graph::inverted::PythonEdgeScan;
use brokk_bifrost_python::graph::resolver::{infer_export_names, infer_usage_seeds};
use brokk_bifrost_python::usage_index::usage_importer_files;
use std::sync::Arc;

pub(in crate::analyzer::usages) use brokk_bifrost_python::graph::extractor::{
    collect_module_binding_timeline, collect_scope_facts_from_parsed_source, enclosing_scope_facts,
    is_declaration_identifier, slice as python_slice,
};
pub(in crate::analyzer::usages) use brokk_bifrost_python::graph::resolver::resolve_receiver_type;

/// Run `visit` with the [`PythonGraphSource`] built from the *dispatching*
/// analyzer.
///
pub(in crate::analyzer::usages) fn with_python_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    mut visit: impl FnMut(PythonGraphSource<'_>) -> R,
) -> R {
    let scope = AnalyzerQueryScope::new(analyzer);
    let cancellation = crate::CancellationToken::new();
    match crate::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        &cancellation,
        |frontier| {
            visit(PythonGraphSource {
                token: scope.token(),
                index: analyzer,
                hierarchy: analyzer.type_hierarchy_provider(),
                imports: analyzer.import_analysis_provider(),
                definitions: frontier,
            })
        },
    ) {
        crate::analyzer::RelationalFrontierOutcome::Complete(result) => result,
        crate::analyzer::RelationalFrontierOutcome::Cancelled => {
            unreachable!("an uncancelled Python helper frontier cannot cancel")
        }
        crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
            panic!("Python relational helper frontier failed: {error:?}")
        }
    }
}

/// The whole-workspace inverted pass: the shared driver's parallel fan-out plus
/// on-demand parsing, with [`PythonEdgeScan::scan_file`] resolving each file.
///
/// Trees are parsed on demand inside the per-file walk and dropped when the
/// closure returns, so live trees are bounded by the worker count rather than
/// the workspace size (#200).
///
/// The relational frontier opens once for the whole fan-out, not once per file:
/// [`resolve_relational_frontier`](crate::analyzer::relational_frontier::resolve_relational_frontier)
/// is called around `build_edge_output`, the same placement `with_java_graph_source`
/// uses, so a question one file's scan raises can be answered in the same batch as
/// every other file's, instead of paying its own round trip per file.
fn build_python_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    domain: EdgeNodeDomain<'_>,
    targets: Option<&HashSet<String>>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = py.get_analyzed_files().into_iter().collect();
    let language = tree_sitter_python::LANGUAGE.into();
    let scan = targets.map_or_else(PythonEdgeScan::new_rooted, |targets| {
        PythonEdgeScan::new(domain.callers(), targets)
    });
    let scope = AnalyzerQueryScope::new(analyzer);
    let cancellation = crate::CancellationToken::new();
    match crate::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        &cancellation,
        |frontier| {
            let graph = PythonGraphSource {
                token: scope.token(),
                index: analyzer,
                hierarchy: analyzer.type_hierarchy_provider(),
                imports: analyzer.import_analysis_provider(),
                definitions: frontier,
            };
            build_edge_output(&files, &keep_file, |file| {
                parse_and_collect_with_domain(
                    analyzer,
                    file,
                    domain,
                    ParseSpec::whole(&language),
                    |input| scan.scan_file(&graph, py, file, input),
                )
            })
        },
    ) {
        crate::analyzer::RelationalFrontierOutcome::Complete(edges) => edges,
        crate::analyzer::RelationalFrontierOutcome::Cancelled => {
            unreachable!("an uncancelled Python edge frontier cannot cancel")
        }
        crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
            panic!("Python relational edge frontier failed: {error:?}")
        }
    }
}

pub(crate) fn build_rooted_python_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PythonEdgeResolver::try_new(analyzer)?;
    Some(build_python_edges(
        analyzer,
        resolver.py,
        EdgeNodeDomain::Rooted(callers),
        None,
        keep_file,
    ))
}

/// Build caller nodes for the whole Python graph while resolving only the
/// requested callee targets. Dead-code analysis needs every declaration as a
/// possible caller, but only inbound edges for its bounded candidate set.
/// Build and retain the exact Python inverse graph for a stable caller domain
/// and bounded callee target set. Bulk consumers can repeat the same query
/// without reparsing the workspace while retaining target-gated resolution.
pub(crate) fn build_cached_python_usage_edges_for_targets(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    targets: &HashSet<String>,
) -> Option<Arc<UsageEdges>> {
    let py = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    let edges = py.usage_edges_for_targets(nodes, targets, || {
        let resolver = PythonEdgeResolver::try_new(analyzer)
            .expect("resolved Python analyzer must construct a Python edge resolver");
        build_python_edges(
            analyzer,
            resolver.py,
            EdgeNodeDomain::Closed(nodes),
            Some(targets),
            |_| true,
        )
    });
    Some(edges)
}

pub(crate) fn build_python_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PythonEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

pub(crate) fn python_usage_candidate_files(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> HashSet<ProjectFile> {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return HashSet::default();
    };
    let export_names = infer_export_names(py, target);
    if export_names.is_empty() {
        return HashSet::default();
    }
    let seeds = infer_usage_seeds(py, target, export_names);
    usage_importer_files(py, &seeds)
}

/// The strategy name every Python usage diagnostic reports.
const PYTHON_STRATEGY: &str = "PythonExportUsageGraphStrategy";

pub(crate) struct PythonQueryResolver<'a> {
    py: &'a PythonAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for PythonQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            py: resolve_analyzer::<PythonAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let py = self.py;
        let candidate_files = scan_scope.candidate_files();
        let scope = AnalyzerQueryScope::new(analyzer);
        let uncancelled = crate::CancellationToken::new();
        let cancellation = scan_scope.cancellation().unwrap_or(&uncancelled);

        // One reference can name several declarations -- two vendored copies of
        // a package give their modules the same import path, so every item in
        // them carries the same fully qualified name (#1791). The graph is
        // seeded from the candidate's own file, so each candidate gets its own
        // scan and the group answers with their union.
        union_candidate_usages(overloads, max_usages, |target| {
            let graph =
                build_python_graph(candidate_files, target.source(), scan_scope.cancellation());
            if scan_scope.is_cancelled() {
                return Ok(CandidateUsageHits::default());
            }
            let seed_names = infer_export_names(py, target);
            if seed_names.is_empty() {
                return Err(GraphFailureReason::NoGraphSeed("no export seed resolved")
                    .diagnostic(target.fq_name(), PYTHON_STRATEGY));
            }

            let seeds = infer_usage_seeds(py, target, seed_names);
            if seeds.is_empty() {
                return Err(
                    GraphFailureReason::NoGraphSeed("export graph produced no seeds")
                        .diagnostic(target.fq_name(), PYTHON_STRATEGY),
                );
            }

            let mut scan_files = graph.scan_files(candidate_files, target.source());
            scan_files.retain(|file| scan_scope.allows(file));

            let scan_result =
                match crate::analyzer::relational_frontier::resolve_relational_frontier(
                    analyzer,
                    cancellation,
                    |frontier| {
                        let source = PythonGraphSource {
                            token: scope.token(),
                            index: analyzer,
                            hierarchy: analyzer.type_hierarchy_provider(),
                            imports: analyzer.import_analysis_provider(),
                            definitions: frontier,
                        };
                        scan_files_for_seeds(
                            &source,
                            py,
                            &graph,
                            &scan_files,
                            target,
                            &seeds,
                            scan_scope.cancellation(),
                        )
                    },
                ) {
                    crate::analyzer::RelationalFrontierOutcome::Complete(result) => result,
                    crate::analyzer::RelationalFrontierOutcome::Cancelled => {
                        return Ok(CandidateUsageHits::default());
                    }
                    crate::analyzer::RelationalFrontierOutcome::Failed(_) => {
                        return Err(GraphFailureReason::UnsupportedTargetShape(
                            "the relational Python scan frontier failed",
                        )
                        .diagnostic(target.fq_name(), PYTHON_STRATEGY));
                    }
                };
            // A proven hit inside the target itself is a recursive call (#1638):
            // kept, classified `SelfReceiver`. The unproven channel still drops
            // them -- an unproven recursive call is not evidence of anything.
            Ok(CandidateUsageHits {
                hits: classify_recursive_hits(analyzer, scan_result.hits, target),
                unproven_hits: scan_result
                    .unproven_hits
                    .into_iter()
                    .filter(|hit| &hit.enclosing != target)
                    .collect(),
            })
        })
    }
}

pub(crate) struct PythonEdgeResolver<'a> {
    py: &'a PythonAnalyzer,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> PythonEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
        // No Python files → no edges to build; mirror the other languages' guard.
        if py.get_analyzed_files().is_empty() {
            return None;
        }
        Some(Self { py })
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_python_edges(
            analyzer,
            self.py,
            EdgeNodeDomain::Closed(nodes),
            Some(nodes),
            keep_file,
        )
    }
}

#[derive(Default)]
pub struct PythonExportUsageGraphStrategy;

impl PythonExportUsageGraphStrategy {
    pub const fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Python
    }
}

impl GraphUsageAnalyzer for PythonExportUsageGraphStrategy {
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
        if language_for_target(target) != Language::Python {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Python"),
                PYTHON_STRATEGY,
            );
        }

        let Some(resolver) = PythonQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose PythonAnalyzer",
                ),
                PYTHON_STRATEGY,
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_cached_python_usage_edges_for_targets, build_rooted_python_usage_edges};
    use crate::analyzer::usages::python_graph::with_python_graph_source;
    use crate::analyzer::{AnalyzerQueryScope, AnalyzerTestHooks, QueryScope};
    use crate::analyzer::{CodeUnitIndex, Language, PythonAnalyzer, TestProject};
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_python::graph::extractor::{
        collect_scope_facts_from_parsed_source, with_callable_return_type_lookup_counter_for_test,
    };
    use brokk_bifrost_python::graph_support::PythonSource;
    use std::fs;

    /// The imported-factory return-type walk must read the analyzer's prepared
    /// syntax, not clone the file source and build its own parser per class
    /// member.
    ///
    /// Both counter arms are asserted. `reparsed == 0` alone would pass
    /// vacuously on a fixture that never reaches the walk, so `prepared > 0`
    /// is what proves the walk ran at all.
    #[test]
    fn imported_factory_return_walk_uses_prepared_syntax_not_a_reparse() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let write = |path: &str, contents: &str| {
            let full = root.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).expect("create parent directories");
            }
            fs::write(&full, contents).expect("write fixture");
        };
        write(
            "models.py",
            "class User:\n    @property\n    def normalized_name(self) -> str:\n        return \"n\"\n\n    @classmethod\n    def guest(cls) -> \"User\":\n        return cls()\n",
        );
        let consumer_source = "from models import User\n\n\ndef run():\n    user = User.guest()\n    return user.normalized_name\n";
        write("consumer.py", consumer_source);

        let analyzer = PythonAnalyzer::from_project(TestProject::new(root, Language::Python));
        assert!(
            !analyzer
                .get_definitions("models.User.normalized_name")
                .is_empty(),
            "fixture should index the property under its module-qualified name"
        );
        let consumer = analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.to_string().ends_with("consumer.py"))
            .expect("consumer file");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &consumer)
            .expect("consumer prepared syntax");

        let (_facts, counts) = with_callable_return_type_lookup_counter_for_test(|| {
            with_python_graph_source(&analyzer, |graph| {
                collect_scope_facts_from_parsed_source(
                    &graph,
                    &analyzer,
                    &consumer,
                    prepared.source(),
                    prepared.tree().root_node(),
                )
            })
        });

        assert!(
            counts.prepared > 0,
            "fixture must exercise the return-type walk: {counts:?}"
        );
        assert_eq!(
            counts.reparsed, 0,
            "return-type extraction must reuse the analyzer's prepared syntax rather than reparsing the file per class member: {counts:?}"
        );
    }

    /// The rooted (whole-workspace, no fixed target set) scan defers every
    /// existence check to `PyScan::resolve_pending` and answers them from one
    /// `prefetch_definitions` batch. This exercises all three deferred
    /// shapes end to end -- a plain call, a namespace-imported module call, and
    /// an inherited-member call that only resolves through the ancestor
    /// fallback -- plus a negative case, proving the deferral changed only
    /// when each check runs, not what it decides.
    #[test]
    fn rooted_scan_resolves_direct_namespace_and_inherited_callees() {
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "base.py",
                "class Base:\n    def greet(self):\n        return \"hi\"\n",
            )
            .file(
                "derived.py",
                "from base import Base\n\n\nclass Derived(Base):\n    pass\n",
            )
            .file("pkgmod.py", "def helper():\n    return 1\n")
            .file(
                "consumer.py",
                "import pkgmod\nfrom derived import Derived\n\n\ndef plain():\n    return helper_local()\n\n\ndef helper_local():\n    return 0\n\n\ndef via_namespace():\n    return pkgmod.helper()\n\n\ndef via_inheritance():\n    return Derived().greet()\n\n\ndef via_missing():\n    return Derived().no_such_method()\n",
            )
            .build();

        let analyzer = PythonAnalyzer::from_project(project.project().clone());
        let callers: crate::hash::HashSet<String> = analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();
        analyzer.reset_definition_prefetch_batch_count_for_test();
        analyzer.reset_definition_candidates_query_count_for_test();

        let edges = build_rooted_python_usage_edges(&analyzer, &callers, |_| true)
            .expect("Python files are present, so a rooted scan must produce a graph");

        assert!(
            analyzer.definition_prefetch_batch_count_for_test() > 0,
            "the rooted scan must actually use batched definition prefetches"
        );
        assert_eq!(
            analyzer.definition_candidates_query_count_for_test(),
            0,
            "prefetched rooted-scan names must not fall back to point definition queries"
        );

        assert!(
            edges.edges.contains_key(&(
                "consumer.plain".to_string(),
                "consumer.helper_local".to_string()
            )),
            "a plain same-file call must resolve via the deferred Direct path: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
        assert!(
            edges.edges.contains_key(&(
                "consumer.via_namespace".to_string(),
                "pkgmod.helper".to_string()
            )),
            "a namespace-imported module call must resolve via the deferred namespace-fallback path: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
        assert!(
            edges.edges.contains_key(&(
                "consumer.via_inheritance".to_string(),
                "base.Base.greet".to_string()
            )),
            "a call to an inherited method must resolve via the deferred ancestor-fallback path: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
        assert!(
            !edges
                .edges
                .keys()
                .any(|(_, callee)| callee.ends_with(".no_such_method")),
            "a call to a method that does not exist anywhere in the hierarchy must record no edge \
             for it, even though the constructor call on the same line legitimately does: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }

    /// A bounded scan's namespace-fallback candidates must still be filtered by the
    /// caller's requested `targets`, not just by workspace membership. `facade.helper`
    /// does not resolve directly (it is a re-export), so it expands through
    /// `canonical_namespace_candidates` into `real.helper` -- which must only be
    /// recorded as an edge when the caller actually asked for it.
    #[test]
    fn bounded_scan_namespace_fallback_candidates_are_filtered_by_targets() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("real.py", "def helper():\n    return 1\n")
            .file("facade/__init__.py", "from real import helper\n")
            .file("other.py", "def helper():\n    return 2\n")
            .file(
                "consumer.py",
                "import facade\n\n\ndef run():\n    return facade.helper()\n",
            )
            .build();

        let analyzer = PythonAnalyzer::from_project(project.project().clone());
        let nodes: crate::hash::HashSet<String> = analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();
        // Shares `real.helper`/`facade.helper`'s terminal segment ("helper") so
        // `may_have_target_terminal` still lets the scan reach the fallback branch,
        // but is a different fqn than either -- the caller never asked for `real.helper`.
        let targets: crate::hash::HashSet<String> =
            std::iter::once("other.helper".to_string()).collect();

        let edges = build_cached_python_usage_edges_for_targets(&analyzer, &nodes, &targets)
            .expect("Python files are present, so a bounded scan must produce a graph");

        assert!(
            !edges
                .edges
                .keys()
                .any(|(_, callee)| callee == "real.helper"),
            "a namespace-fallback candidate outside the requested target set must not be \
             recorded as an edge in bounded mode: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }
}
