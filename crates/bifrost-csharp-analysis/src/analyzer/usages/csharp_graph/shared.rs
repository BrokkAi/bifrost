use crate::analyzer::usages::csharp_graph::build_csharp_edges;

use crate::analyzer::usages::csharp_graph::csharp_graph_source;

use brokk_bifrost_analysis::analyzer::usages::common::analyzed_files_for_language;

use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::usages::accumulator::UsageAccumulator;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::EdgeNodeDomain;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_core::analyzer::usages::outcome::GraphFailureReason;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_analysis::analyzer::usages::traits::UsageQueryResolver;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use crate::analyzer::CSharpAnalyzer;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_csharp::graph::extractor::{
    BatchScanState, PreparedCSharpFile, prepare_file, scan_prepared_file, scan_prepared_file_batch,
};
use brokk_bifrost_csharp::graph::resolver::TargetSpec;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct CSharpQueryResolver<'a> {
    csharp: &'a CSharpAnalyzer,
}

/// One authoritative C# inverse batch over a fixed union of caller roots.
///
/// Preparing a C# file reads and parses its source, builds its line table and
/// class-range index, and loads its using aliases. None of that state depends
/// on the target being queried, so the reference-differential campaign keeps
/// it once and shares it across target groups. Interactive and cancellable
/// usage queries continue to prepare only the files in their own request.
pub struct CSharpAuthoritativeUsageBatch<'a> {
    analyzer: &'a dyn IAnalyzer,
    resolver: CSharpQueryResolver<'a>,
    prepared_files: HashMap<ProjectFile, Arc<PreparedCSharpFile>>,
    token: QueryToken<'a>,
    #[cfg(any(test, feature = "test-support"))]
    batch_file_scans: AtomicUsize,
}

pub struct CSharpAuthoritativeUsageRequest<'a> {
    overloads: &'a [CodeUnit],
    candidate_files: &'a HashSet<ProjectFile>,
    max_usages: usize,
}

impl<'a> CSharpAuthoritativeUsageRequest<'a> {
    pub fn new(
        overloads: &'a [CodeUnit],
        candidate_files: &'a HashSet<ProjectFile>,
        max_usages: usize,
    ) -> Self {
        Self {
            overloads,
            candidate_files,
            max_usages,
        }
    }
}

fn csharp_target_specs(
    overloads: &[CodeUnit],
    mut spec_for: impl FnMut(&CodeUnit) -> Option<TargetSpec>,
) -> Result<Vec<TargetSpec>, Box<GraphUsageOutcome>> {
    overloads
        .iter()
        .map(|overload| {
            spec_for(overload).ok_or_else(|| {
                Box::new(GraphUsageOutcome::fallback_safe(
                    overload.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                    "CSharpUsageGraphStrategy",
                ))
            })
        })
        .collect()
}

impl<'a> CSharpAuthoritativeUsageBatch<'a> {
    pub fn new(
        analyzer: &'a dyn IAnalyzer,
        token: QueryToken<'a>,
        roots: &HashSet<ProjectFile>,
    ) -> Option<Self> {
        let resolver = CSharpQueryResolver::try_new(analyzer)?;
        let prepared_files = roots
            .iter()
            .filter_map(|file| {
                let source = analyzer.project().read_source(file).ok()?;
                prepare_file(resolver.csharp, file, source)
                    .map(|prepared| (file.clone(), Arc::new(prepared)))
            })
            .collect();
        Some(Self {
            analyzer,
            resolver,
            prepared_files,
            token,
            #[cfg(any(test, feature = "test-support"))]
            batch_file_scans: AtomicUsize::new(0),
        })
    }

    pub fn find_usages(
        &self,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        self.find_usages_batch(&[CSharpAuthoritativeUsageRequest::new(
            overloads,
            candidate_files,
            max_usages,
        )])
        .pop()
        .expect("one C# authoritative request produces one outcome")
    }

    pub fn find_usages_batch(
        &self,
        requests: &[CSharpAuthoritativeUsageRequest<'_>],
    ) -> Vec<GraphUsageOutcome> {
        struct SpecResult {
            spec: TargetSpec,
            usages: UsageAccumulator,
        }

        struct QueryPlan<'a> {
            target: CodeUnit,
            candidate_files: &'a HashSet<ProjectFile>,
            max_usages: usize,
            specs: Vec<SpecResult>,
        }

        let graph = csharp_graph_source(self.analyzer);
        let mut outcomes: Vec<Option<GraphUsageOutcome>> = std::iter::repeat_with(|| None)
            .take(requests.len())
            .collect();
        let mut plans: Vec<Option<QueryPlan<'_>>> = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            let Some(target) = request.overloads.first() else {
                outcomes[index] = Some(GraphUsageOutcome::Resolved(FuzzyResult::empty_success()));
                plans.push(None);
                continue;
            };
            let specs = match csharp_target_specs(request.overloads, |overload| {
                TargetSpec::from_target(&graph, overload)
            }) {
                Ok(specs) => specs
                    .into_iter()
                    .map(|spec| SpecResult {
                        spec,
                        usages: UsageAccumulator::bounded(request.max_usages),
                    })
                    .collect(),
                Err(outcome) => {
                    outcomes[index] = Some(*outcome);
                    plans.push(None);
                    continue;
                }
            };
            plans.push(Some(QueryPlan {
                target: target.clone(),
                candidate_files: request.candidate_files,
                max_usages: request.max_usages,
                specs,
            }));
        }

        // Path order, for the same reason as the single-query scan: each
        // spec stops at its cap, so file order decides the capped sample.
        let mut prepared_files: Vec<_> = self.prepared_files.iter().collect();
        prepared_files.sort_unstable_by_key(|(file, _)| *file);
        for (file, prepared) in prepared_files {
            let mut scans = Vec::new();
            for plan in plans.iter_mut().flatten() {
                if !plan.candidate_files.contains(file) {
                    continue;
                }
                for result in &mut plan.specs {
                    scans.push(BatchScanState {
                        spec: &result.spec,
                        usages: &mut result.usages,
                    });
                }
            }
            if !scans.is_empty() {
                #[cfg(any(test, feature = "test-support"))]
                self.batch_file_scans.fetch_add(1, Ordering::Relaxed);
                scan_prepared_file_batch(
                    self.resolver.csharp,
                    self.token,
                    &graph,
                    file,
                    prepared,
                    &mut scans,
                );
            }
        }

        for (index, plan) in plans.into_iter().enumerate() {
            let Some(plan) = plan else {
                continue;
            };
            let mut usages = UsageAccumulator::bounded(plan.max_usages);
            for result in plan.specs {
                usages.absorb(result.usages);
            }
            outcomes[index] = Some(GraphUsageOutcome::Resolved(
                usages.finish(&plan.target, FuzzyResult::MAX_UNPROVEN_HITS_PER_SYMBOL),
            ));
        }

        outcomes
            .into_iter()
            .map(|outcome| outcome.expect("every C# authoritative request has an outcome"))
            .collect()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn prepared_file_count_for_test(&self) -> usize {
        self.prepared_files.len()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn batch_file_scan_count_for_test(&self) -> usize {
        self.batch_file_scans.load(Ordering::Relaxed)
    }
}

impl<'a> UsageQueryResolver<'a> for CSharpQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            csharp: resolve_analyzer::<CSharpAnalyzer>(analyzer)?,
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
        self.find_usages_with_prepared_files(
            analyzer, token, overloads, scan_scope, max_usages, None,
        )
    }
}

impl CSharpQueryResolver<'_> {
    #[allow(clippy::too_many_arguments)]
    fn find_usages_with_prepared_files(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
        prepared_files: Option<&HashMap<ProjectFile, Arc<PreparedCSharpFile>>>,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let graph = csharp_graph_source(analyzer);
        let specs = match csharp_target_specs(overloads, |overload| {
            TargetSpec::from_target(&graph, overload)
        }) {
            Ok(specs) => specs,
            Err(outcome) => return *outcome,
        };

        // The scan stops at the `max_usages` cap, so the files it reached
        // decide the returned sample and total. Walk them in path order: hash
        // order depends on the workspace root and on how the candidate set was
        // built, and the same code on the same inputs must return the same
        // answer.
        let candidate_files = scan_scope.candidate_files();
        let mut files: Vec<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::CSharp)
            .cloned()
            .chain(
                overloads
                    .iter()
                    .map(CodeUnit::source)
                    .filter(|source| scan_scope.allows(source))
                    .cloned(),
            )
            .collect();
        files.sort();
        files.dedup();

        let mut usages = UsageAccumulator::bounded(max_usages);
        for file in files {
            if scan_scope.is_cancelled() || usages.limit_reached() {
                break;
            }
            let local_prepared = prepared_files
                .is_none()
                .then(|| {
                    analyzer
                        .project()
                        .read_source(&file)
                        .ok()
                        .and_then(|source| prepare_file(self.csharp, &file, source))
                })
                .flatten();
            let prepared = prepared_files
                .and_then(|files| files.get(&file).map(Arc::as_ref))
                .or(local_prepared.as_ref());
            let Some(prepared) = prepared else {
                continue;
            };
            for spec in &specs {
                scan_prepared_file(
                    self.csharp,
                    token,
                    &graph,
                    &file,
                    prepared,
                    spec,
                    &mut usages,
                );
                if usages.limit_reached() {
                    break;
                }
            }
        }

        GraphUsageOutcome::Resolved(usages.finish(target, scan_scope.max_unproven()))
    }
}

pub(crate) struct CSharpEdgeResolver<'a> {
    csharp: &'a CSharpAnalyzer,
    files: Vec<ProjectFile>,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> CSharpEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::CSharp);
        Some(Self { csharp, files })
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_csharp_edges(
            analyzer,
            token,
            self.csharp,
            &self.files,
            EdgeNodeDomain::Rooted(callers),
            keep_file,
        )
    }

    pub(crate) fn build_inbound_edges_with_completeness<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        callees: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeBuildResult<UsageEdges>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        crate::analyzer::usages::csharp_graph::build_csharp_edges_with_completeness(
            analyzer,
            token,
            self.csharp,
            &self.files,
            EdgeNodeDomain::Inbound(callees),
            keep_file,
        )
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        build_csharp_edges(
            analyzer,
            token,
            self.csharp,
            &self.files,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }
}
