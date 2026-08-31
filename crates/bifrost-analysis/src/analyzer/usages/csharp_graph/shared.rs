use super::{build_csharp_edges, csharp_graph_source};
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::{
    EdgeNodeDomain, UsageEdgeBuildResult, UsageEdgeWeights, UsageEdges,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    CSharpAnalyzer, CodeUnit, IAnalyzer, Language, ProjectFile, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_csharp::graph::extractor::{
    BatchScanState, PreparedCSharpFile, ScanState, prepare_file, scan_prepared_file,
    scan_prepared_file_batch,
};
use brokk_bifrost_csharp::graph::resolver::TargetSpec;
use std::collections::BTreeSet;
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
                prepare_file(resolver.csharp, file)
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
            hits: BTreeSet<UsageHit>,
            unproven_hits: BTreeSet<UsageHit>,
            limit_exceeded: bool,
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
            let mut specs = Vec::with_capacity(request.overloads.len());
            let mut unsupported = None;
            for overload in request.overloads {
                let Some(spec) = TargetSpec::from_target(&graph, overload) else {
                    unsupported = Some(GraphUsageOutcome::fallback_safe(
                        overload.fq_name(),
                        GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                        "CSharpUsageGraphStrategy",
                    ));
                    break;
                };
                specs.push(SpecResult {
                    spec,
                    hits: BTreeSet::new(),
                    unproven_hits: BTreeSet::new(),
                    limit_exceeded: false,
                });
            }
            if let Some(unsupported) = unsupported {
                outcomes[index] = Some(unsupported);
                plans.push(None);
            } else {
                plans.push(Some(QueryPlan {
                    target: target.clone(),
                    candidate_files: request.candidate_files,
                    max_usages: request.max_usages,
                    specs,
                }));
            }
        }

        for (file, prepared) in &self.prepared_files {
            let mut scans = Vec::new();
            for plan in plans.iter_mut().flatten() {
                if !plan.candidate_files.contains(file) {
                    continue;
                }
                for result in &mut plan.specs {
                    scans.push(BatchScanState {
                        spec: &result.spec,
                        max_usages: plan.max_usages,
                        hits: &mut result.hits,
                        unproven_hits: &mut result.unproven_hits,
                        limit_exceeded: &mut result.limit_exceeded,
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
            let mut hits = BTreeSet::new();
            let mut unproven_hits = BTreeSet::new();
            let mut limit_exceeded = false;
            for result in plan.specs {
                hits.extend(result.hits);
                unproven_hits.extend(result.unproven_hits);
                limit_exceeded |= result.limit_exceeded;
            }
            let external_callsites =
                crate::analyzer::usages::common::external_usage_hit_count(&hits);
            outcomes[index] = Some(GraphUsageOutcome::Resolved(
                if limit_exceeded || external_callsites > plan.max_usages {
                    FuzzyResult::TooManyCallsites {
                        short_name: plan.target.short_name().to_string(),
                        total_callsites: external_callsites,
                        limit: plan.max_usages,
                        sample_hits: hits,
                    }
                } else {
                    FuzzyResult::success_with_unproven(plan.target, hits, unproven_hits)
                },
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
        let mut specs = Vec::with_capacity(overloads.len());
        for overload in overloads {
            let Some(spec) = TargetSpec::from_target(&graph, overload) else {
                return GraphUsageOutcome::fallback_safe(
                    overload.fq_name(),
                    GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                    "CSharpUsageGraphStrategy",
                );
            };
            specs.push(spec);
        }

        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::CSharp)
            .cloned()
            .collect();
        for overload in overloads {
            if scan_scope.allows(overload.source()) {
                files.insert(overload.source().clone());
            }
        }

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            limit_exceeded: &mut limit_exceeded,
        };
        for file in files {
            if scan_scope.is_cancelled() || *state.limit_exceeded {
                break;
            }
            let local_prepared = prepared_files
                .is_none()
                .then(|| prepare_file(self.csharp, &file))
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
                    &mut state,
                );
                if *state.limit_exceeded {
                    break;
                }
            }
        }

        let external_callsites = crate::analyzer::usages::common::external_usage_hit_count(&hits);
        if limit_exceeded || external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_callsites,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
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
        super::build_csharp_edges_with_completeness(
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
