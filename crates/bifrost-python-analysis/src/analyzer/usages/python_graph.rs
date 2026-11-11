//! The analysis-side wrappers over [`brokk_bifrost_python::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), and the inverted pass's fan-out -- `build_edge_output` and
//! `parse_and_collect` are the shared, language-agnostic driver.

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_analysis::analyzer::store::StoreError;

use brokk_bifrost_analysis::analyzer::usages::common::classify_recursive_hits;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

use brokk_bifrost_analysis::analyzer::usages::common::with_relational_frontier;

use brokk_bifrost_core::analyzer::usages::outcome::CandidateUsageHits;

use brokk_bifrost_core::analyzer::usages::outcome::GraphFailureReason;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_core::analyzer::usages::outcome::union_candidate_usages_with_limit;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageBatchQuery;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_analysis::analyzer::usages::traits::UsageQueryResolver;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use crate::analyzer::PythonAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_python::graph::PythonGraphSource;
use brokk_bifrost_python::graph::extractor::{
    PythonScanTarget, build_python_graph, scan_file_for_seed_batch,
};
use brokk_bifrost_python::graph::resolver::{infer_export_names, infer_usage_seeds};
use std::sync::Arc;

/// Run `visit` with the [`PythonGraphSource`] built from the *dispatching*
/// analyzer.
///
pub(crate) fn with_python_graph_source<R>(
    analyzer: &dyn IAnalyzer,
    mut visit: impl FnMut(PythonGraphSource<'_>) -> R,
) -> R {
    let scope = AnalyzerQueryScope::new(analyzer);
    with_relational_frontier(analyzer, "Python", |frontier| {
        visit(PythonGraphSource {
            token: scope.token(),
            index: analyzer,
            hierarchy: analyzer.type_hierarchy_provider(),
            imports: analyzer.import_analysis_provider(),
            definitions: frontier,
        })
    })
}

#[cfg(any(test, feature = "test-support"))]
static DEAD_CODE_REQUESTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn python_legacy_dead_code_requests_for_test() -> usize {
    DEAD_CODE_REQUESTS.load(std::sync::atomic::Ordering::Relaxed)
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
        self.find_usage_batch(
            analyzer,
            &[GraphUsageBatchQuery {
                overloads,
                scope: scan_scope.clone(),
                prepared: None,
            }],
            max_usages,
        )
        .pop()
        .expect("one query returns one result")
    }
}

/// Shared scope-fact construction must replay every target that consumed a
/// provisional common fact. Target-specific resolution uses its own recorder.
struct SharedScanFrontier<'a>(
    &'a [Arc<dyn brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionFrontier>],
);

impl brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionFrontier
    for SharedScanFrontier<'_>
{
    fn ask(
        &self,
        question: &brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuestion,
    ) -> brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionValue {
        let answer = self.0[0].ask(question);
        for frontier in &self.0[1..] {
            frontier.ask(question);
        }
        answer
    }
}

impl PythonQueryResolver<'_> {
    fn find_usage_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<GraphUsageOutcome> {
        let py = self.py;
        let scope = AnalyzerQueryScope::new(analyzer);
        let uncancelled = brokk_bifrost_core::cancellation::CancellationToken::new();
        let cancellation = queries
            .iter()
            .find_map(|query| query.scope.cancellation())
            .unwrap_or(&uncancelled);
        let mut files = HashSet::default();
        let mut targets = Vec::new();
        let mut seeds = Vec::new();
        let mut owners = Vec::new();
        let mut results = Vec::new();
        for (query_index, query) in queries.iter().enumerate() {
            for target in query.overloads {
                if query.scope.is_cancelled() {
                    targets.push(target);
                    seeds.push(None);
                    owners.push(query_index);
                    results.push(Ok(CandidateUsageHits::default()));
                    continue;
                }
                let names = infer_export_names(py, target);
                let seed = if names.is_empty() {
                    Err(GraphFailureReason::NoGraphSeed("no export seed resolved")
                        .diagnostic(target.fq_name(), PYTHON_STRATEGY))
                } else {
                    let seeds = infer_usage_seeds(py, target, names);
                    if seeds.is_empty() {
                        Err(
                            GraphFailureReason::NoGraphSeed("export graph produced no seeds")
                                .diagnostic(target.fq_name(), PYTHON_STRATEGY),
                        )
                    } else {
                        Ok(seeds)
                    }
                };
                if seed.is_ok() {
                    files.extend(query.scope.candidate_files().iter().cloned());
                    files.insert(target.source().clone());
                }
                results.push(
                    seed.as_ref()
                        .map(|_| CandidateUsageHits::default())
                        .map_err(Clone::clone),
                );
                targets.push(target);
                seeds.push(seed.ok());
                owners.push(query_index);
            }
        }
        if let Some(first) = targets.first() {
            let graph = {
                let _scope = brokk_bifrost_core::profiling::scope("python_graph::build_syntax");
                build_python_graph(&files, first.source(), Some(cancellation))
            };
            let scan_targets: Vec<_> = targets
                .iter()
                .map(|target| PythonScanTarget::new(analyzer, target))
                .collect();
            let mut files: Vec<_> = files.into_iter().collect();
            files.sort();
            let session = brokk_bifrost_analysis::analyzer::relational_frontier::RelationalFrontierSession::new(
                analyzer,
                cancellation,
            );
            let groups: Vec<Vec<_>> = files
                .iter()
                .map(|file| {
                    targets
                        .iter()
                        .enumerate()
                        .filter_map(|(index, _)| {
                            (seeds[index].is_some() && queries[owners[index]].scope.allows(file))
                                .then_some((index, file))
                        })
                        .collect()
                })
                .collect();
            let outcome = session.resolve_owned_item_groups("python_file_scan", &groups, |items| {
                let file = items[0].0.1;
                let frontiers: Vec<_> =
                    items.iter().map(|(_, frontier)| frontier.clone()).collect();
                let shared_frontier = SharedScanFrontier(&frontiers);
                let source = PythonGraphSource {
                    token: scope.token(),
                    index: analyzer,
                    hierarchy: analyzer.type_hierarchy_provider(),
                    imports: analyzer.import_analysis_provider(),
                    definitions: &shared_frontier,
                };
                let sources: Vec<_> = frontiers
                    .iter()
                    .map(|frontier| PythonGraphSource {
                        token: scope.token(),
                        index: analyzer,
                        hierarchy: analyzer.type_hierarchy_provider(),
                        imports: analyzer.import_analysis_provider(),
                        definitions: frontier.as_ref(),
                    })
                    .collect();
                let batch: Vec<_> = items
                    .iter()
                    .zip(&sources)
                    .map(|((item, _), source)| {
                        (
                            source,
                            &scan_targets[item.0],
                            seeds[item.0].as_ref().expect("admitted seed"),
                        )
                    })
                    .collect();
                let scanned =
                    scan_file_for_seed_batch(&source, py, &graph, file, &batch, Some(cancellation));
                items.iter().map(|(item, _)| item.0).zip(scanned).collect()
            });
            match outcome {
                brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Complete(
                    files,
                ) => {
                    for (index, scanned) in files {
                        match scanned {
                            Ok(scanned) => {
                                if let Ok(result) = &mut results[index] {
                                    result.hits.extend(scanned.hits);
                                    result.unproven_hits.extend(scanned.unproven_hits);
                                }
                            }
                            Err(file) => {
                                analyzer.record_query_failure(StoreError::new(format!(
                                    "Python usage scan omitted file: {file:?}"
                                )));
                                results[index] = Err(GraphFailureReason::UnsupportedTargetShape(
                                    "canonical Python source facts were unavailable",
                                )
                                .diagnostic(targets[index].fq_name(), PYTHON_STRATEGY));
                            }
                        }
                    }
                }
                brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Cancelled(
                    _,
                ) => {
                    for result in &mut results {
                        if result.is_ok() {
                            *result = Ok(CandidateUsageHits::default());
                        }
                    }
                }
                brokk_bifrost_analysis::analyzer::relational_frontier::RelationalItemFrontierOutcome::Failed(_) => {
                    for (target, result) in targets.iter().zip(&mut results) {
                        if result.is_ok() {
                            *result = Err(GraphFailureReason::UnsupportedTargetShape(
                                "the relational Python scan frontier failed",
                            )
                            .diagnostic(target.fq_name(), PYTHON_STRATEGY));
                        }
                    }
                }
            }
        }
        let mut results = results.into_iter();
        queries
            .iter()
            .map(|query| {
                let candidates: Vec<_> = query
                    .overloads
                    .iter()
                    .map(|target| {
                        results
                            .next()
                            .expect("one result per target")
                            .map(|result| CandidateUsageHits {
                                hits: classify_recursive_hits(analyzer, result.hits, target),
                                unproven_hits: result
                                    .unproven_hits
                                    .into_iter()
                                    .filter(|hit| &hit.enclosing != target)
                                    .collect(),
                            })
                    })
                    .collect();
                let mut candidates = candidates.into_iter();
                union_candidate_usages_with_limit(
                    query.overloads,
                    max_usages,
                    query.scope.max_unproven(),
                    |_| candidates.next().expect("one result per overload"),
                )
            })
            .collect()
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
    fn find_graph_usages_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<GraphUsageOutcome> {
        match PythonQueryResolver::try_new(analyzer) {
            Some(resolver) => resolver.find_usage_batch(analyzer, queries, max_usages),
            None => queries
                .iter()
                .map(|query| {
                    self.find_graph_usages(analyzer, query.overloads, &query.scope, max_usages)
                })
                .collect(),
        }
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            PythonQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Python,
                unsupported_target: "target is not Python",
                missing_analyzer: "analyzer does not expose PythonAnalyzer",
                strategy: PYTHON_STRATEGY,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_python::graph::extractor::collect_scope_facts_from_parsed_source;

    use crate::analyzer::usages::python_graph::with_python_graph_source;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

    use brokk_bifrost_core::analyzer::model::Language;

    use crate::analyzer::PythonAnalyzer;
    use crate::inline_project::InlineTestProject;

    use brokk_bifrost_python::graph::extractor::with_callable_return_type_lookup_counter_for_test;
    use brokk_bifrost_python::graph_support::PythonSource;

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
        use brokk_bifrost_core::analyzer::project::OverlayProject;

        use brokk_bifrost_core::analyzer::project::Project;
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
        use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsCacheOutcome;

        use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsLimitedOutcome;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_core::analyzer::project::OverlayProject;

        use brokk_bifrost_core::analyzer::project::Project;

        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        use brokk_bifrost_core::gitblob::test_repo::commit_all;

        use brokk_bifrost_core::gitblob::test_repo::init_repo;
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
}
