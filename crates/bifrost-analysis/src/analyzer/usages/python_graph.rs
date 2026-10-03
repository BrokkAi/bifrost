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

use crate::analyzer::store::StoreError;
use crate::analyzer::usages::common::{classify_recursive_hits, language_for_target};
use crate::analyzer::usages::inverted_edges::{
    EdgeNodeDomain, UsageEdgeBuildOutput, UsageEdgeBuildResult, UsageEdgeWeights, UsageEdges,
    build_edge_output_with_completeness, parse_and_collect_with_domain,
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
use brokk_bifrost_python::graph::extractor::{
    PythonScanTarget, build_python_graph, scan_file_for_seeds,
};
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
) -> Option<Output>
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
    let result = build_edge_output_with_completeness(&files, keep_file, |file| {
        let mut unavailable = false;
        let edges = parse_and_collect_with_domain(
            analyzer,
            file,
            domain,
            ParseSpec::whole(&language),
            |input| {
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
                        scan.scan_file(&graph, py, file, input)
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
                .unwrap_or_else(|_| {
                    unavailable = true;
                    Default::default()
                })
            },
        );
        (!unavailable).then_some(edges).flatten()
    });
    match result {
        UsageEdgeBuildResult::Complete(output) => Some(output),
        UsageEdgeBuildResult::Uncacheable { omitted_files, .. } => {
            analyzer.record_query_failure(StoreError::new(format!(
                "Python usage edge build omitted files: {omitted_files:?}"
            )));
            None
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
    build_python_edges(
        analyzer,
        resolver.py,
        EdgeNodeDomain::Rooted(callers),
        None,
        keep_file,
    )
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
    py.usage_edges_for_targets(nodes, targets, || {
        let resolver = PythonEdgeResolver::try_new(analyzer)
            .expect("resolved Python analyzer must construct a Python edge resolver");
        build_python_edges(
            analyzer,
            resolver.py,
            EdgeNodeDomain::Closed(nodes),
            Some(targets),
            |_| true,
        )
    })
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
    resolver.build_edge_weights(analyzer, nodes, keep_file)
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
            let graph = {
                let _scope = crate::profiling::scope("python_graph::build_syntax");
                build_python_graph(candidate_files, target.source(), scan_scope.cancellation())
            };
            if scan_scope.is_cancelled() {
                return Ok(CandidateUsageHits::default());
            }
            let seed_names = {
                let _scope = crate::profiling::scope("python_graph::infer_export_names");
                infer_export_names(py, target)
            };
            if seed_names.is_empty() {
                return Err(GraphFailureReason::NoGraphSeed("no export seed resolved")
                    .diagnostic(target.fq_name(), PYTHON_STRATEGY));
            }

            let seeds = {
                let _scope = crate::profiling::scope("python_graph::infer_usage_seeds");
                infer_usage_seeds(py, target, seed_names)
            };
            if seeds.is_empty() {
                return Err(
                    GraphFailureReason::NoGraphSeed("export graph produced no seeds")
                        .diagnostic(target.fq_name(), PYTHON_STRATEGY),
                );
            }

            let mut scan_files = graph.scan_files(candidate_files, target.source());
            scan_files.retain(|file| scan_scope.allows(file));

            let session = crate::analyzer::relational_frontier::RelationalFrontierSession::new(
                analyzer,
                cancellation,
            );
            let mut scan_files = scan_files.into_iter().collect::<Vec<_>>();
            scan_files.sort();
            let scan_target = PythonScanTarget::new(analyzer, target);
            let scan_result = match session.resolve_owned_items(
                "python_file_scan",
                &scan_files,
                |file, frontier| {
                    let source = PythonGraphSource {
                        token: scope.token(),
                        index: analyzer,
                        hierarchy: analyzer.type_hierarchy_provider(),
                        imports: analyzer.import_analysis_provider(),
                        definitions: frontier.as_ref(),
                    };
                    scan_file_for_seeds(
                        &source,
                        py,
                        &graph,
                        file,
                        &scan_target,
                        &seeds,
                        scan_scope.cancellation(),
                    )
                },
            ) {
                crate::analyzer::relational_frontier::RelationalItemFrontierOutcome::Complete(
                    results,
                ) => {
                    let mut result = brokk_bifrost_python::graph::extractor::ScanResult::default();
                    let mut missing_files = HashSet::default();
                    for file_result in results {
                        match file_result {
                            Ok(file_result) => {
                                result.hits.extend(file_result.hits);
                                result.unproven_hits.extend(file_result.unproven_hits);
                            }
                            Err(file) => {
                                missing_files.insert(file);
                            }
                        }
                    }
                    if !missing_files.is_empty() {
                        analyzer.record_query_failure(StoreError::new(format!(
                            "Python usage scan omitted files: {missing_files:?}"
                        )));
                        return Err(GraphFailureReason::UnsupportedTargetShape(
                            "canonical Python source facts were unavailable",
                        )
                        .diagnostic(target.fq_name(), PYTHON_STRATEGY));
                    }
                    result
                }
                crate::analyzer::relational_frontier::RelationalItemFrontierOutcome::Cancelled(
                    _,
                ) => return Ok(CandidateUsageHits::default()),
                crate::analyzer::relational_frontier::RelationalItemFrontierOutcome::Failed(_) => {
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
    ) -> Option<UsageEdgeWeights>
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
    use crate::analyzer::{CodeUnitIndex, ImportAnalysisProvider, Language, PythonAnalyzer};
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_python::graph::extractor::{
        collect_scope_facts_from_parsed_source, with_callable_return_type_lookup_counter_for_test,
    };
    use brokk_bifrost_python::graph_support::PythonSource;

    /// Imported annotations remain available from captured declaration metadata
    /// when the declaration's source file is no longer readable.
    #[test]
    fn imported_factory_return_walk_uses_canonical_declarations() {
        let consumer_source = "from models import User\n\n\ndef run():\n    user = User.guest()\n    return user.normalized_name\n";
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("models.py", "class User:\n    @property\n    def normalized_name(self) -> str:\n        return \"n\"\n\n    @classmethod\n    def guest(cls) -> \"User\":\n        return cls()\n")
            .file("consumer.py", consumer_source)
            .build();
        let analyzer = PythonAnalyzer::new(fixture.project_dyn());
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

        let (facts, counts) = with_callable_return_type_lookup_counter_for_test(|| {
            with_python_graph_source(&analyzer, |graph| {
                let models = fixture.file("models.py");
                let captured = analyzer
                    .prepared_syntax(graph.token, &models)
                    .expect("capture foreign declaration snapshot");
                assert!(captured.source().contains("def guest"));
                std::fs::remove_file(models.abs_path()).expect("remove declaration source");
                collect_scope_facts_from_parsed_source(
                    &graph,
                    &analyzer,
                    &consumer,
                    prepared.source(),
                    prepared.tree().root_node(),
                )
                .expect("captured Python scope facts")
            })
        });

        assert!(!facts.is_empty());
        assert!(
            counts.canonical > 0,
            "fixture must exercise the return-type walk: {counts:?}"
        );
        assert_eq!(
            counts.body, 0,
            "annotated returns must use captured metadata without body inference: {counts:?}"
        );
    }
    #[test]
    fn export_index_uses_captured_scope_and_order_after_source_removal() {
        use brokk_bifrost_core::analyzer::usages::model::ExportEntry;
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("source.py", "class Target:\n    pass\n")
            .file("exports.py", "from source import Target as early\nearly = 1\nlate = 2\nfrom source import Target as late\ndef hidden():\n    from source import Target as local\nmatch 1:\n    case 1:\n        from source import Target as matched\n")
            .build();
        let analyzer = PythonAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("exports.py");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let declarations = analyzer.top_level_declarations(&file);
        assert!(
            declarations.iter().any(|unit| unit.identifier() == "early"),
            "captured declarations: {declarations:?}"
        );
        let imports = analyzer.import_info_of(scope.token(), &file);
        assert_eq!(imports.len(), 4);
        std::fs::remove_file(file.abs_path()).expect("remove exported module source");
        let exports = analyzer.export_index_of(scope.token(), &file);
        assert!(matches!(
            exports.exports_by_name.get("early"),
            Some(ExportEntry::Local { .. })
        ));
        assert!(matches!(
            exports.exports_by_name.get("late"),
            Some(ExportEntry::ReexportedNamed { .. })
        ));
        assert!(matches!(
            exports.exports_by_name.get("matched"),
            Some(ExportEntry::ReexportedNamed { .. })
        ));
        assert!(!exports.exports_by_name.contains_key("local"));
    }

    #[test]
    fn module_replacement_uses_canonical_import_statement_order() {
        use brokk_bifrost_python::imports::module_replacement_of;
        for (source, expected) in [
            (
                "import sys as runtime, target as chosen\nruntime.modules[__name__] = chosen\n",
                Some("target"),
            ),
            (
                "import target as chosen\nruntime.modules[__name__] = chosen\nimport sys as runtime\n",
                None,
            ),
            (
                "import sys as runtime, target as chosen\nruntime = object()\nruntime.modules[__name__] = chosen\n",
                None,
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Python)
                .file("target.py", "class Target:\n    pass\n")
                .file("facade.py", source)
                .build();
            let analyzer = PythonAnalyzer::new(fixture.project_dyn());
            let file = fixture.file("facade.py");
            let scope = AnalyzerQueryScope::new(&analyzer);
            let imports = analyzer.import_info_of(scope.token(), &file);
            assert_eq!(imports.len(), 2);
            let replacement = module_replacement_of(&analyzer, &file, source, &imports);
            assert_eq!(
                replacement
                    .as_ref()
                    .map(|value| value.target_module.as_str()),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn export_index_uses_unsaved_import_scope_instead_of_disk() {
        use crate::analyzer::{OverlayProject, Project};
        use brokk_bifrost_core::analyzer::usages::model::ExportEntry;
        use std::sync::Arc;
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("source.py", "class Target:\n    pass\n")
            .file("exports.py", "from source import Target as disk\n")
            .build();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let file = fixture.file("exports.py");
        assert!(overlay.set(file.abs_path(), "from source import Target as unsaved\ndef hidden():\n    from source import Target as local\n".to_owned()));
        let analyzer = PythonAnalyzer::new(overlay as Arc<dyn Project>);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let exports = analyzer.export_index_of(scope.token(), &file);
        assert!(matches!(
            exports.exports_by_name.get("unsaved"),
            Some(ExportEntry::ReexportedNamed { .. })
        ));
        assert!(!exports.exports_by_name.contains_key("disk"));
        assert!(!exports.exports_by_name.contains_key("local"));
    }
    #[test]
    fn python_primary_facts_survive_reopen_and_unsaved_replacement() {
        use crate::analyzer::structural::provider::{
            StructuralFactsCacheOutcome, StructuralFactsLimitedOutcome,
        };
        use crate::analyzer::{AnalyzerConfig, OverlayProject, Project, WorkspaceAnalyzer};
        use crate::gitblob::test_repo::{commit_all, init_repo};
        use std::sync::Arc;
        let source_a = "from typing import Optional\nclass User:\n    pass\ndef create() -> Optional[User]:\n    return User()\n";
        let source_b = "from typing import Optional\nclass Other:\n    pass\ndef create() -> Optional[Other]:\n    return Other()\n";
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("models.py", source_a)
            .build();
        let repo = init_repo(fixture.root());
        commit_all(&repo, "Python canonical source fixture");
        let file = fixture.file("models.py");
        let first = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("publish Python source facts");
        assert!(first.persisted_store_path().is_some());
        drop(first);
        let reopened = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("reopen Python source facts");
        let provider = reopened
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("Python provider");
        let StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome,
        } = provider.structural_facts_limited(&file, source_a, usize::MAX, None)
        else {
            panic!("ready persisted Python facts");
        };
        assert_eq!(facts.source(), source_a);
        assert!(!facts.nodes().is_empty());
        assert_ne!(cache_outcome, StructuralFactsCacheOutcome::Extracted);
        assert_eq!(provider.structural_extraction_count(), 0);
        let create = reopened
            .analyzer()
            .definitions("models.create")
            .next()
            .expect("persisted callable");
        let metadata = reopened.analyzer().signature_metadata(&create);
        assert_eq!(
            metadata[0]
                .return_type_identity()
                .and_then(|identity| identity.nominal_name())
                .map(|name| name.path()),
            Some(["User".to_owned()].as_slice())
        );

        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), source_b.to_owned()));
        let dirty = reopened.clone_with_project(overlay as Arc<dyn Project>);
        let provider = dirty
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("dirty Python provider");
        let facts = provider
            .structural_facts(&file)
            .expect("dirty canonical Python facts");
        assert_eq!(facts.source(), source_b);
        let create = dirty
            .analyzer()
            .definitions("models.create")
            .next()
            .expect("dirty callable");
        let metadata = dirty.analyzer().signature_metadata(&create);
        assert_eq!(
            metadata[0]
                .return_type_identity()
                .and_then(|identity| identity.nominal_name())
                .map(|name| name.path()),
            Some(["Other".to_owned()].as_slice())
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

    /// An empty `pkg/__init__.py` is ordinary Python: it declares the package and
    /// contributes no edges. The whole-workspace inverted pass fails closed on any
    /// file whose scan produced no per-file result, so an empty file that the
    /// on-demand parse refuses to parse takes the entire graph down with it -- the
    /// build returns `None` and every caller of `usage_graph` on a package with an
    /// empty `__init__.py` gets "Python usage edge build omitted files".
    ///
    /// `build_rooted_python_usage_edges` returns `Some` only when the driver saw a
    /// result for every kept file: the other `None` is a workspace with no Python
    /// files at all, which the assertion below rules out.
    #[test]
    fn empty_package_init_is_scanned_rather_than_omitted() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("pkg/__init__.py", "")
            .file("pkg/models.py", "def load():\n    return 1\n")
            .file(
                "consumer.py",
                "from pkg.models import load\n\n\ndef run():\n    return load()\n",
            )
            .build();

        let analyzer = PythonAnalyzer::from_project(project.project().clone());
        let package_init = project.file("pkg/__init__.py");
        let analyzed = analyzer.get_analyzed_files();
        assert!(
            analyzed.contains(&package_init),
            "the empty package init must be part of the scanned workspace: {analyzed:?}"
        );
        let callers: crate::hash::HashSet<String> = analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();

        let edges = build_rooted_python_usage_edges(&analyzer, &callers, |_| true).expect(
            "an empty package init contributes no edges and must not be reported as omitted",
        );

        assert!(
            edges
                .edges
                .contains_key(&("consumer.run".to_string(), "pkg.models.load".to_string())),
            "the rest of the package must still resolve: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }
}
