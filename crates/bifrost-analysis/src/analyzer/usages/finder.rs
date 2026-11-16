use crate::analyzer::languages::{CandidateCtx, candidate_augmentation, language_support_for_hook};
use crate::analyzer::usages::candidates::find_default_candidates_within;
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::model::{FuzzyResult, UsageProofAuthority};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{
    CandidateFileProvider, GraphUsageAnalyzer, GraphUsageBatchQuery, PreparedUsageQuery,
    UsageScanScope,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DescendantIndexScope, IAnalyzer, Language, ProjectFile,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use std::collections::BTreeSet;

struct PlannedUsageQuery {
    protected_candidates: HashSet<ProjectFile>,
    supplemental_candidates: HashSet<ProjectFile>,
}

fn augment_usage_candidates(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    base_candidates: &HashSet<ProjectFile>,
    cancellation: &CancellationToken,
) -> PlannedUsageQuery {
    let mut protected_candidates = base_candidates.clone();
    let mut supplemental_candidates = HashSet::default();
    for target in overloads {
        if let Some(augmentation) = candidate_augmentation(&CandidateCtx {
            analyzer,
            target,
            cancellation,
        }) {
            protected_candidates.extend(augmentation.protected);
            supplemental_candidates.extend(augmentation.supplemental);
        }
    }
    PlannedUsageQuery {
        protected_candidates,
        supplemental_candidates,
    }
}

pub(super) fn execute_graph_usage_query_in_scope(
    strategy: &dyn GraphUsageAnalyzer,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    candidate_files: &HashSet<ProjectFile>,
    max_usages: usize,
) -> FuzzyResult {
    let cancellation = CancellationToken::default();
    let scan_scope = UsageScanScope::with_cancellation(candidate_files, &cancellation);
    let outcome =
        graph_strategy_find_usages(strategy, analyzer, overloads, &scan_scope, None, max_usages);
    outcome.into_fuzzy_result()
}

/// A caller-supplied candidate-file predicate. Borrowing (`'a`) rather than
/// `'static`: `scan_usages`' filter classifies test files on demand against
/// the live analyzer, instead of pre-classifying the whole workspace into an
/// owned set before the query starts (see `searchtools::scan_usages`).
type FileFilter<'a> = Box<
    dyn Fn(&ProjectFile) -> Result<bool, crate::analyzer::QueryReadIncomplete> + Send + Sync + 'a,
>;

pub const DEFAULT_MAX_FILES: usize = 1000;
pub const DEFAULT_MAX_USAGES: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageQueryCompletion {
    Complete,
    Cancelled,
    CandidateFilesBudgetExhausted,
    SourceBytesBudgetExhausted,
}

pub struct QueryResult {
    /// Actual file-cap refusal, not the broader omitted-file flag.
    #[doc(hidden)]
    pub candidate_files_budget_exhausted: bool,
    pub completion: UsageQueryCompletion,
    pub candidate_files: HashSet<ProjectFile>,
    pub candidate_files_truncated: bool,
    pub source_bytes_truncated: bool,
    /// Request-local evidence from the source admission guard; never serialized.
    #[doc(hidden)]
    pub source_byte_refusal: Option<(usize, usize, usize)>,
    /// Sources whose indexed contents were unavailable, independently of caps.
    #[doc(hidden)]
    pub unavailable_sources: Vec<ProjectFile>,
    pub scanned_source_bytes: usize,
    pub candidate_files_sample: Option<CandidateFilesSample>,
    pub result: FuzzyResult,
    /// The authority of the strategy that produced `result`, so a consumer can
    /// read the proof tiers correctly without naming a language.
    pub proof_authority: UsageProofAuthority,
    pub graph_failure: Option<crate::analyzer::usages::model::UsageAnalysisDiagnostic>,
}

impl QueryResult {
    /// Convenience callers cannot carry execution coverage, so cancellation
    /// must remain a failure rather than exposing partial positives as Success.
    pub(crate) fn into_fuzzy_result(self, overloads: &[CodeUnit]) -> FuzzyResult {
        if self.completion == UsageQueryCompletion::Cancelled {
            return FuzzyResult::Failure {
                fq_name: overloads
                    .iter()
                    .map(|target| target.fq_name().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                reason_kind: "cancelled".into(),
                reason: "Usage query cancelled".into(),
            };
        }
        if self.has_complete_coverage() {
            return self.result;
        }
        let (hits_by_overload, unproven_by_overload, unproven_total_by_overload, mut diagnostics) =
            match self.result {
                FuzzyResult::Success {
                    hits_by_overload,
                    unproven_by_overload,
                    unproven_total_by_overload,
                } => (
                    hits_by_overload,
                    unproven_by_overload,
                    unproven_total_by_overload,
                    Vec::new(),
                ),
                FuzzyResult::Incomplete {
                    hits_by_overload,
                    unproven_by_overload,
                    unproven_total_by_overload,
                    diagnostics,
                } => (
                    hits_by_overload,
                    unproven_by_overload,
                    unproven_total_by_overload,
                    diagnostics,
                ),
                terminal => return terminal,
            };
        let causes = [
            (
                self.candidate_files_budget_exhausted
                    || self.completion == UsageQueryCompletion::CandidateFilesBudgetExhausted,
                "candidate_files_budget_exhausted",
            ),
            (
                self.source_bytes_truncated
                    || self.source_byte_refusal.is_some()
                    || self.completion == UsageQueryCompletion::SourceBytesBudgetExhausted,
                "source_bytes_budget_exhausted",
            ),
            (
                !self.unavailable_sources.is_empty(),
                "indexed_source_unavailable",
            ),
        ];
        let fq_name = overloads
            .iter()
            .map(|target| target.fq_name().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        for reason_kind in causes
            .iter()
            .filter_map(|(observed, kind)| observed.then_some(*kind))
            .chain(
                (diagnostics.is_empty() && !causes.iter().any(|(observed, _)| *observed))
                    .then_some("unavailable_canonical_facts"),
            )
        {
            if diagnostics.iter().any(|diagnostic| {
                diagnostic.strategy == "source_admission" && diagnostic.reason_kind == reason_kind
            }) {
                continue;
            }
            diagnostics.push(crate::analyzer::usages::model::UsageAnalysisDiagnostic {
                fq_name: fq_name.clone(),
                strategy: "source_admission".to_string(),
                reason_kind: reason_kind.to_string(),
                reason: format!(
                    "usage coverage is incomplete: completion={:?}, candidate_files_truncated={}, candidate_files_budget_exhausted={}, source_bytes_truncated={}, source_byte_refusal={:?}, unavailable_sources={:?}, graph_failure={:?}",
                    self.completion, self.candidate_files_truncated, self.candidate_files_budget_exhausted,
                    self.source_bytes_truncated, self.source_byte_refusal, self.unavailable_sources, self.graph_failure
                ),
            });
        }
        FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
            diagnostics,
        }
    }

    /// Whether candidate discovery and scanning finished without an execution gap.
    /// Semantic completeness and native proof tiers must also be checked before
    /// this inventory can certify absence.
    pub fn has_complete_coverage(&self) -> bool {
        self.completion == UsageQueryCompletion::Complete
            && !self.candidate_files_truncated
            && !self.source_bytes_truncated
            && !self.candidate_files_budget_exhausted
            && self.source_byte_refusal.is_none()
            && self.unavailable_sources.is_empty()
            && self.graph_failure.is_none()
    }
}

pub struct CandidateFilesSample {
    pub scanned: Vec<ProjectFile>,
    pub omitted: Vec<ProjectFile>,
    pub omitted_count: usize,
}

/// Scope and budget facts fixed before a graph scan and reported afterward.
#[doc(hidden)]
pub struct AdmittedUsageQuery {
    #[doc(hidden)]
    pub candidate_files: HashSet<ProjectFile>,
    #[doc(hidden)]
    pub candidate_files_truncated: bool,
    #[doc(hidden)]
    pub candidate_files_budget_exhausted: bool,
    #[doc(hidden)]
    pub source_bytes_truncated: bool,
    /// Request-local evidence from the source admission guard; never serialized.
    #[doc(hidden)]
    pub source_byte_refusal: Option<(usize, usize, usize)>,
    /// Sources whose indexed contents were unavailable, independently of caps.
    #[doc(hidden)]
    pub unavailable_sources: Vec<ProjectFile>,
    #[doc(hidden)]
    pub scanned_source_bytes: usize,
    #[doc(hidden)]
    pub candidate_files_sample: Option<CandidateFilesSample>,
}

type AdmittedUsagePlan = (
    AdmittedUsageQuery,
    Option<Box<dyn PreparedUsageQuery>>,
    Vec<crate::analyzer::QueryReadIncomplete>,
);

/// The common reference engine.
///
/// This type owns target-query planning, admission, cancellation, and language-plugin
/// dispatch. Its canonical-edge file-scan entry point is implemented beside the
/// canonical row model in `structural::reference_edges`. Languages provide semantic
/// resolution hooks; they do not own request traversal or budgets.
///
/// The strategy chosen depends on the target's language:
///
/// - JavaScript / TypeScript, Python, PHP, Rust, Java, Kotlin, C#, C++, Go, Ruby, and
///   Scala targets are routed to their graph strategy first.
/// - Graph strategies can explicitly mark an internal outcome as fallback-safe; those
///   diagnostics are surfaced as failures instead of being masked by text matches.
/// - Targets without a graph strategy surface a structured unsupported-language failure.
///
/// JDT-based Java analysis is intentionally omitted; bifrost is tree-sitter only.
pub struct ReferenceEngine<'a> {
    max_unproven: usize,
    file_filter: Option<FileFilter<'a>>,
    /// The request's test-file exclusion on its own, when it asked to drop
    /// test files.
    ///
    /// `file_filter` is that exclusion *and* the request's optional path
    /// filter, and the two cannot travel together into candidate discovery.
    /// A path filter is arbitrary per-request scoping, so it must never key a
    /// cross-request shared index; the test verdict is a pure function of the
    /// analyzer and the file, so it can. Pushing it down is what stops the
    /// type-hierarchy build from inverting classes the answer would throw
    /// away seconds later (#1748).
    excluded_test_files: Option<FileFilter<'a>>,
    cancellation: CancellationToken,
}

impl<'a> ReferenceEngine<'a> {
    pub fn new() -> Self {
        let cancellation = CancellationToken::default();
        Self {
            max_unproven: FuzzyResult::MAX_UNPROVEN_HITS_PER_SYMBOL,
            file_filter: None,
            excluded_test_files: None,
            cancellation,
        }
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    pub(crate) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub fn with_unproven_limit(mut self, limit: usize) -> Self {
        self.max_unproven = limit;
        self
    }

    pub fn with_file_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&ProjectFile) -> Result<bool, crate::analyzer::QueryReadIncomplete>
            + Send
            + Sync
            + 'a,
    {
        self.file_filter = Some(Box::new(filter));
        self
    }

    /// Declare which files the request already knows it will discard, so
    /// candidate discovery can skip building over them. `excludes` answers
    /// `true` for a file that is dropped; it must be a pure function of the
    /// analyzer and the file, because the index it prunes is shared across
    /// requests and keyed only by "was anything excluded".
    ///
    /// This does not replace [`Self::with_file_filter`], which stays the
    /// correctness backstop: several providers legitimately keep a
    /// whole-workspace index and let the retain do the work.
    pub fn with_test_file_exclusion<F>(mut self, excludes: F) -> Self
    where
        F: Fn(&ProjectFile) -> Result<bool, crate::analyzer::QueryReadIncomplete>
            + Send
            + Sync
            + 'a,
    {
        self.excluded_test_files = Some(Box::new(excludes));
        self
    }

    pub fn query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> QueryResult {
        self.query_with_provider_and_source_budget(
            analyzer, overloads, None, max_files, max_usages, None,
        )
    }

    pub fn query_with_source_budget(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
        max_source_bytes: usize,
    ) -> QueryResult {
        self.query_with_provider_and_source_budget(
            analyzer,
            overloads,
            None,
            max_files,
            max_usages,
            Some(max_source_bytes),
        )
    }

    pub fn query_with_provider(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        explicit_provider: Option<&dyn CandidateFileProvider>,
        max_files: usize,
        max_usages: usize,
    ) -> QueryResult {
        self.query_with_provider_and_source_budget(
            analyzer,
            overloads,
            explicit_provider,
            max_files,
            max_usages,
            None,
        )
    }

    #[doc(hidden)]
    pub fn query_with_provider_and_source_budget(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        explicit_provider: Option<&dyn CandidateFileProvider>,
        max_files: usize,
        max_usages: usize,
        max_source_bytes: Option<usize>,
    ) -> QueryResult {
        let _query_scope = AnalyzerQueryScope::with_cancellation(analyzer, &self.cancellation);
        let (admitted_query, prepared, classification_failures) = match self.admit_query(
            analyzer,
            overloads,
            explicit_provider,
            max_files,
            max_source_bytes,
        ) {
            Ok(admitted) => admitted,
            Err(result) => return *result,
        };
        let target = &overloads[0];
        let strategy = language_support_for_hook(language_for_target(target), "reference_plugin")
            .map(|support| support.reference_plugin().target_strategy());
        let explicit_candidates = explicit_provider
            .and_then(CandidateFileProvider::explicit_candidate_files)
            .map(|files| {
                files
                    .intersection(&admitted_query.candidate_files)
                    .cloned()
                    .collect::<HashSet<_>>()
            });
        let scan_scope =
            UsageScanScope::with_cancellation(&admitted_query.candidate_files, &self.cancellation)
                .with_explicit_candidates(explicit_candidates.as_ref())
                .with_test_inclusion(self.excluded_test_files.is_none())
                .with_unproven_limit(self.max_unproven);
        let _graph_scope = crate::profiling::scope("usages::graph_find_usages");
        let outcome = graph_find_usages(
            language_for_target(target),
            analyzer,
            overloads,
            &scan_scope,
            prepared.as_deref(),
            max_usages,
        );
        let mut query =
            finalize_graph_usage_query(outcome, &self.cancellation, admitted_query, strategy);
        record_classification_failures(&mut query, target, classification_failures);
        query
    }

    fn admit_query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        explicit_provider: Option<&dyn CandidateFileProvider>,
        max_files: usize,
        max_source_bytes: Option<usize>,
    ) -> Result<AdmittedUsagePlan, Box<QueryResult>> {
        // The scan's deadline, not just its loops: candidate discovery spends
        // most of its time inside single analyzer reads that take no token
        // (`definitions` for one import target is 1.14 s for a hot short name
        // on the rustc tree). Opening the request boundary with the token is
        // what lets those reads stop when this scan's budget does.
        let _query_scope = AnalyzerQueryScope::with_cancellation(analyzer, &self.cancellation);
        if overloads.is_empty() {
            return Err(Box::new(QueryResult {
                completion: UsageQueryCompletion::Complete,
                candidate_files: HashSet::default(),
                candidate_files_truncated: false,
                candidate_files_budget_exhausted: false,
                source_bytes_truncated: false,
                source_byte_refusal: None,
                unavailable_sources: Vec::new(),
                scanned_source_bytes: 0,
                candidate_files_sample: None,
                result: FuzzyResult::empty_success(),
                // No overloads means no target language and no strategy.
                proof_authority: UsageProofAuthority::Legacy,
                graph_failure: None,
            }));
        }
        if self.cancellation.is_cancelled() {
            return Err(Box::new(cancelled_query_result()));
        }

        let target = &overloads[0];
        let classification_failures = std::cell::RefCell::new(Vec::new());
        let excluded = |file: &ProjectFile| {
            self.excluded_test_files.as_ref().expect("exclusion filter")(file).map_err(|reason| {
                analyzer.record_query_incomplete(reason.clone());
                classification_failures.borrow_mut().push(reason);
                brokk_bifrost_core::analyzer::capabilities::SourceExclusionUnavailable
            })
        };
        let hierarchy_scope = match self.excluded_test_files.as_deref() {
            Some(_) => DescendantIndexScope::excluding_sources(&self.cancellation, &excluded),
            None => DescendantIndexScope::whole_workspace(&self.cancellation),
        };
        let _cand_scope = crate::profiling::scope("usages::candidate_discovery");
        let strategy = || {
            language_support_for_hook(language_for_target(target), "reference_plugin")
                .map(|support| support.reference_plugin().target_strategy())
        };
        // Complete target-directed preparation replaces generic discovery. In
        // particular, do not build a workspace hierarchy before the native
        // reverse operation has had a chance to nominate its own exact sites.
        let target_prepared = explicit_provider
            .is_none()
            .then(|| {
                strategy().and_then(|strategy| {
                    strategy.prepare_target_usage_query(analyzer, overloads, &self.cancellation)
                })
            })
            .flatten();
        let mut candidates = HashSet::default();
        let mut supplemental = HashSet::default();
        let prepared = if let Some(prepared) = target_prepared {
            Some(prepared)
        } else {
            for overload in overloads {
                match explicit_provider {
                    Some(provider) => {
                        candidates.extend(provider.find_candidates(overload, analyzer))
                    }
                    None => {
                        candidates.extend(find_default_candidates_within(
                            overload,
                            analyzer,
                            &hierarchy_scope,
                        ));
                    }
                }
                if self.cancellation.is_cancelled() {
                    return Err(Box::new(cancelled_query_result()));
                }
            }
            let provider_is_complete_scope =
                explicit_provider.is_some_and(CandidateFileProvider::is_complete_scope);
            if provider_is_complete_scope {
                None
            } else {
                let plan =
                    augment_usage_candidates(analyzer, overloads, &candidates, &self.cancellation);
                candidates = plan.protected_candidates;
                supplemental = plan.supplemental_candidates;
                strategy().and_then(|strategy| {
                    strategy.prepare_usage_query(
                        analyzer,
                        overloads,
                        &candidates,
                        &self.cancellation,
                    )
                })
            }
        };
        if let Some(prepared) = prepared.as_ref() {
            candidates.extend(prepared.candidate_files().iter().cloned());
        }
        if self.cancellation.is_cancelled() {
            return Err(Box::new(cancelled_query_result()));
        }
        // Protected files are everything discovered so far; the supplemental files join
        // only afterwards, so both budgets below drop them before touching anything here.
        let mut protected_candidates = candidates.clone();
        let supplemental_count = supplemental.len();
        candidates.extend(supplemental);

        if let Some(filter) = self.file_filter.as_ref() {
            candidates.retain(|file| {
                if self.cancellation.is_cancelled() {
                    return false;
                }
                match filter(file) {
                    Ok(admitted) => admitted,
                    Err(reason) => {
                        analyzer.record_query_incomplete(reason.clone());
                        classification_failures.borrow_mut().push(reason);
                        false
                    }
                }
            });
            protected_candidates.retain(|file| candidates.contains(file));
        }
        if self.cancellation.is_cancelled() {
            return Err(Box::new(cancelled_query_result()));
        }

        let all_candidates = candidates.clone();
        crate::profiling::note_with(|| {
            format!(
                "usages.candidates target={} total={} protected={} supplemental={}",
                target.fq_name(),
                all_candidates.len(),
                protected_candidates.len(),
                supplemental_count
            )
        });
        let candidate_files_budget_exhausted = candidates.len() > max_files;
        if candidate_files_budget_exhausted {
            candidates = truncate_candidates(candidates, &protected_candidates, max_files);
        }
        let admission = admit_candidates_by_source_bytes(
            analyzer,
            candidates,
            &protected_candidates,
            max_source_bytes,
            &self.cancellation,
        );
        if admission.cancelled {
            return Err(Box::new(cancelled_query_result()));
        }
        candidates = admission.files;
        let candidate_files_truncated = candidates.len() < all_candidates.len();
        let candidate_files_sample =
            candidate_files_truncated.then(|| candidate_files_sample(&all_candidates, &candidates));

        let admitted_query = AdmittedUsageQuery {
            candidate_files: candidates,
            candidate_files_truncated,
            candidate_files_budget_exhausted,
            source_bytes_truncated: admission.byte_refusal.is_some(),
            source_byte_refusal: admission.byte_refusal,
            unavailable_sources: admission.unavailable_sources,
            scanned_source_bytes: admission.scanned_source_bytes,
            candidate_files_sample,
        };

        Ok((
            admitted_query,
            prepared,
            classification_failures.into_inner(),
        ))
    }

    /// Independent target queries sharing a language's file walk when supported.
    pub(crate) fn query_batch_with_source_budget(
        &self,
        analyzer: &dyn IAnalyzer,
        targets: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
        max_source_bytes: usize,
    ) -> Vec<QueryResult> {
        let _scope = AnalyzerQueryScope::with_cancellation(analyzer, &self.cancellation);
        let mut answers: Vec<Option<QueryResult>> = (0..targets.len()).map(|_| None).collect();
        let mut groups: crate::hash::HashMap<Language, Vec<_>> = crate::hash::HashMap::default();
        for (index, target) in targets.iter().enumerate() {
            match self.admit_query(
                analyzer,
                std::slice::from_ref(target),
                None,
                max_files,
                Some(max_source_bytes),
            ) {
                Ok(query) => {
                    groups
                        .entry(language_for_target(target))
                        .or_default()
                        .push((index, query));
                }
                Err(result) => answers[index] = Some(*result),
            }
        }
        for (language, admitted) in groups {
            let queries: Vec<_> = admitted
                .iter()
                .map(
                    |(target_index, (query, prepared, _))| GraphUsageBatchQuery {
                        overloads: std::slice::from_ref(&targets[*target_index]),
                        scope: UsageScanScope::with_cancellation(
                            &query.candidate_files,
                            &self.cancellation,
                        )
                        .with_test_inclusion(self.excluded_test_files.is_none())
                        .with_unproven_limit(self.max_unproven),
                        prepared: prepared.as_deref(),
                    },
                )
                .collect();
            let outcomes = match language_support_for_hook(language, "reference_plugin") {
                Some(support) => support
                    .reference_plugin()
                    .target_strategy()
                    .find_graph_usages_batch(analyzer, &queries, max_usages),
                None => queries
                    .iter()
                    .map(|query| {
                        graph_find_usages(
                            language,
                            analyzer,
                            query.overloads,
                            &query.scope,
                            query.prepared,
                            max_usages,
                        )
                    })
                    .collect(),
            };
            assert_eq!(outcomes.len(), admitted.len());
            for ((target_index, (query, _, classification_failures)), outcome) in
                admitted.into_iter().zip(outcomes)
            {
                let strategy = language_support_for_hook(language, "reference_plugin")
                    .map(|support| support.reference_plugin().target_strategy());
                let mut result =
                    finalize_graph_usage_query(outcome, &self.cancellation, query, strategy);
                record_classification_failures(
                    &mut result,
                    &targets[target_index],
                    classification_failures,
                );
                answers[target_index] = Some(result);
            }
        }
        answers
            .into_iter()
            .map(|answer| answer.expect("every target has a query result"))
            .collect()
    }

    pub fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> FuzzyResult {
        self.query(analyzer, overloads, max_files, max_usages)
            .into_fuzzy_result(overloads)
    }

    pub fn find_usages_default(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
    ) -> FuzzyResult {
        self.find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
    }
}

fn record_classification_failures(
    query: &mut QueryResult,
    target: &CodeUnit,
    classification_failures: Vec<crate::analyzer::QueryReadIncomplete>,
) {
    for reason in classification_failures {
        let diagnostic = crate::analyzer::usages::model::UsageAnalysisDiagnostic {
            fq_name: target.fq_name().to_string(),
            strategy: "candidate_admission".to_string(),
            reason_kind: reason.label().to_string(),
            reason: format!("{reason:?}"),
        };
        query.result = match std::mem::replace(&mut query.result, FuzzyResult::empty_success()) {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            } => FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                diagnostics: vec![diagnostic],
            },
            FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                mut diagnostics,
            } => {
                diagnostics.push(diagnostic);
                FuzzyResult::Incomplete {
                    hits_by_overload,
                    unproven_by_overload,
                    unproven_total_by_overload,
                    diagnostics,
                }
            }
            result => result,
        };
    }
}

#[doc(hidden)]
pub fn finalize_graph_usage_query(
    outcome: GraphUsageOutcome,
    cancellation: &CancellationToken,
    admitted_query: AdmittedUsageQuery,
    strategy: Option<&dyn GraphUsageAnalyzer>,
) -> QueryResult {
    let mut graph_failure = None;
    let result = match outcome {
        GraphUsageOutcome::Resolved(result) => result,
        GraphUsageOutcome::FallbackSafe(diagnostic) => {
            graph_failure = Some(diagnostic.clone());
            FuzzyResult::Failure {
                fq_name: diagnostic.fq_name,
                reason_kind: diagnostic.reason_kind,
                reason: diagnostic.reason,
            }
        }
        GraphUsageOutcome::TerminalFailure(diagnostic) => {
            graph_failure = Some(diagnostic.clone());
            FuzzyResult::Failure {
                fq_name: diagnostic.fq_name,
                reason_kind: diagnostic.reason_kind,
                reason: diagnostic.reason,
            }
        }
    };
    let result = if admitted_query.unavailable_sources.is_empty() {
        result
    } else {
        let diagnostic =
            crate::analyzer::usages::model::UsageAnalysisDiagnostic::indexed_source_unavailable(
                &admitted_query.unavailable_sources,
            );
        match result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            } => FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                diagnostics: vec![diagnostic],
            },
            FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                mut diagnostics,
            } => {
                diagnostics.push(diagnostic);
                FuzzyResult::Incomplete {
                    hits_by_overload,
                    unproven_by_overload,
                    unproven_total_by_overload,
                    diagnostics,
                }
            }
            already_incomplete => already_incomplete,
        }
    };
    // A cancelled graph scan may still have established individual hits. Keep
    // those positives while marking the request's coverage incomplete.
    QueryResult {
        completion: if cancellation.is_cancelled() {
            UsageQueryCompletion::Cancelled
        } else if admitted_query.source_bytes_truncated {
            UsageQueryCompletion::SourceBytesBudgetExhausted
        } else if admitted_query.candidate_files_budget_exhausted {
            UsageQueryCompletion::CandidateFilesBudgetExhausted
        } else {
            UsageQueryCompletion::Complete
        },
        candidate_files_budget_exhausted: admitted_query.candidate_files_budget_exhausted,
        source_byte_refusal: admitted_query.source_byte_refusal,
        unavailable_sources: admitted_query.unavailable_sources,
        candidate_files: admitted_query.candidate_files,
        candidate_files_truncated: admitted_query.candidate_files_truncated,
        source_bytes_truncated: admitted_query.source_bytes_truncated,
        scanned_source_bytes: admitted_query.scanned_source_bytes,
        candidate_files_sample: admitted_query.candidate_files_sample,
        result,
        proof_authority: strategy.map_or(
            UsageProofAuthority::Legacy,
            GraphUsageAnalyzer::proof_authority,
        ),
        graph_failure,
    }
}

fn cancelled_query_result() -> QueryResult {
    QueryResult {
        completion: UsageQueryCompletion::Cancelled,
        candidate_files: HashSet::default(),
        candidate_files_truncated: false,
        candidate_files_budget_exhausted: false,
        source_bytes_truncated: false,
        source_byte_refusal: None,
        unavailable_sources: Vec::new(),
        scanned_source_bytes: 0,
        candidate_files_sample: None,
        result: FuzzyResult::empty_success(),
        // A cancelled scan ran no strategy, so nothing certified this answer.
        proof_authority: UsageProofAuthority::Legacy,
        graph_failure: None,
    }
}

#[derive(Default)]
struct SourceAdmission {
    files: HashSet<ProjectFile>,
    scanned_source_bytes: usize,
    cancelled: bool,
    byte_refusal: Option<(usize, usize, usize)>,
    unavailable_sources: Vec<ProjectFile>,
}

fn admit_candidates_by_source_bytes(
    analyzer: &dyn IAnalyzer,
    candidates: HashSet<ProjectFile>,
    protected_candidates: &HashSet<ProjectFile>,
    max_source_bytes: Option<usize>,
    cancellation: &CancellationToken,
) -> SourceAdmission {
    if cancellation.is_cancelled() {
        return SourceAdmission {
            cancelled: true,
            ..SourceAdmission::default()
        };
    }
    let mut ordered = candidates.iter().cloned().collect::<Vec<_>>();
    analyzer.prefetch_parse_variants(&ordered);
    let max_source_bytes = max_source_bytes.unwrap_or(usize::MAX);

    ordered.sort_by_key(|file| (!protected_candidates.contains(file), file.clone()));
    let mut admitted = HashSet::default();
    let mut scanned_source_bytes = 0usize;
    let mut source_byte_refusal = None;
    let mut unavailable_sources = Vec::new();
    for file in ordered {
        if cancellation.is_cancelled() {
            return SourceAdmission {
                cancelled: true,
                ..SourceAdmission::default()
            };
        }
        let Some(source_bytes) = analyzer.indexed_source(&file).map(|source| source.len()) else {
            unavailable_sources.push(file);
            continue;
        };
        if scanned_source_bytes.saturating_add(source_bytes) <= max_source_bytes {
            scanned_source_bytes += source_bytes;
            admitted.insert(file);
        } else {
            source_byte_refusal.get_or_insert((
                scanned_source_bytes,
                scanned_source_bytes.saturating_add(source_bytes),
                max_source_bytes,
            ));
        }
    }
    SourceAdmission {
        files: admitted,
        scanned_source_bytes,
        cancelled: false,
        byte_refusal: source_byte_refusal,
        unavailable_sources,
    }
}

impl Default for ReferenceEngine<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Compatibility name for callers that still consume the fuzzy usage result.
/// New reference-analysis code should name [`ReferenceEngine`].
pub type UsageFinder<'a> = ReferenceEngine<'a>;

fn truncate_candidates(
    candidates: HashSet<ProjectFile>,
    protected_candidates: &HashSet<ProjectFile>,
    max_files: usize,
) -> HashSet<ProjectFile> {
    if max_files == 0 {
        return HashSet::default();
    }

    let mut kept = HashSet::default();
    for file in sorted_files(protected_candidates)
        .into_iter()
        .take(max_files)
    {
        kept.insert(file);
    }

    if kept.len() >= max_files {
        return kept;
    }

    for file in sorted_files(&candidates) {
        if kept.len() >= max_files {
            break;
        }
        kept.insert(file);
    }
    kept
}

const CANDIDATE_FILE_SAMPLE_LIMIT: usize = 10;

fn candidate_files_sample(
    all_candidates: &HashSet<ProjectFile>,
    scanned_candidates: &HashSet<ProjectFile>,
) -> CandidateFilesSample {
    let scanned = sorted_files(scanned_candidates)
        .into_iter()
        .take(CANDIDATE_FILE_SAMPLE_LIMIT)
        .collect();
    let omitted_all: HashSet<ProjectFile> = all_candidates
        .iter()
        .filter(|file| !scanned_candidates.contains(*file))
        .cloned()
        .collect();
    let omitted_count = omitted_all.len();
    let omitted = sorted_files(&omitted_all)
        .into_iter()
        .take(CANDIDATE_FILE_SAMPLE_LIMIT)
        .collect();
    CandidateFilesSample {
        scanned,
        omitted,
        omitted_count,
    }
}

fn sorted_files(files: &HashSet<ProjectFile>) -> Vec<ProjectFile> {
    files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[doc(hidden)]
pub fn graph_strategy_find_usages(
    strategy: &dyn GraphUsageAnalyzer,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    scan_scope: &UsageScanScope<'_>,
    prepared: Option<&dyn PreparedUsageQuery>,
    max_usages: usize,
) -> GraphUsageOutcome {
    match prepared {
        Some(prepared) => prepared.find_graph_usages(analyzer, overloads, scan_scope, max_usages),
        None => strategy.find_graph_usages(analyzer, overloads, scan_scope, max_usages),
    }
}

fn graph_find_usages(
    language: Language,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    scan_scope: &UsageScanScope<'_>,
    prepared: Option<&dyn PreparedUsageQuery>,
    max_usages: usize,
) -> GraphUsageOutcome {
    match language_support_for_hook(language, "reference_plugin") {
        Some(support) => graph_strategy_find_usages(
            support.reference_plugin().target_strategy(),
            analyzer,
            overloads,
            scan_scope,
            prepared,
            max_usages,
        ),
        None => GraphUsageOutcome::terminal_failure(
            overloads[0].fq_name(),
            GraphFailureReason::UnsupportedTargetLanguage(
                "no graph usage strategy is available for this target language",
            ),
            "UsageFinder",
        ),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::analyzer::{CodeUnitType, EmptyAnalyzer, FileSetProject, Project, ProjectFile};

    use brokk_bifrost_test_macros::hardwon;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    #[hardwon("#11321: an unavailable indexed source was mislabeled as a source-byte budget cut")]
    fn source_admission_unavailable_is_not_a_budget_refusal() {
        let root = std::env::temp_dir();
        let file = ProjectFile::new(root.clone(), PathBuf::from("missing.java"));
        let project: Arc<dyn Project> =
            Arc::new(FileSetProject::new(root, std::iter::empty::<PathBuf>()));
        let analyzer = EmptyAnalyzer::new(project);
        let cancellation = CancellationToken::new();
        let admission = admit_candidates_by_source_bytes(
            &analyzer,
            [file.clone()].into_iter().collect(),
            &HashSet::default(),
            Some(100),
            &cancellation,
        );
        assert!(admission.files.is_empty());
        assert_eq!(admission.scanned_source_bytes, 0);
        assert!(!admission.cancelled);
        assert!(admission.byte_refusal.is_none());
        assert_eq!(admission.unavailable_sources, [file]);
        let query = finalize_graph_usage_query(
            GraphUsageOutcome::Resolved(FuzzyResult::empty_success()),
            &cancellation,
            AdmittedUsageQuery {
                candidate_files: admission.files,
                candidate_files_truncated: true,
                candidate_files_budget_exhausted: false,
                source_bytes_truncated: admission.byte_refusal.is_some(),
                source_byte_refusal: admission.byte_refusal,
                unavailable_sources: admission.unavailable_sources,
                scanned_source_bytes: admission.scanned_source_bytes,
                candidate_files_sample: None,
            },
            None,
        );
        assert_eq!(query.completion, UsageQueryCompletion::Complete);
        assert!(!query.candidate_files_budget_exhausted && !query.source_bytes_truncated);
        assert!(
            matches!(query.result, FuzzyResult::Incomplete { ref diagnostics, .. }
            if diagnostics.iter().any(|d| d.reason_kind == "indexed_source_unavailable"))
        );
    }

    #[test]
    #[hardwon("#11321: refused usage admission became a complete convenience answer")]
    fn admission_witnesses_never_publish_complete_usage_answers() {
        let root = std::env::temp_dir();
        let file = ProjectFile::new(root, PathBuf::from("missing.java"));
        let target = CodeUnit::new(file.clone(), CodeUnitType::Class, "Target", "Target");
        for (candidate_cut, byte_refusal, unavailable, complete_expected) in [
            (false, None, Vec::new(), true),
            (true, None, Vec::new(), false),
            (false, Some((0, 1, 2)), Vec::new(), false),
            (false, None, vec![file.clone()], false),
            (true, Some((0, 1, 2)), Vec::new(), false),
            (true, Some((0, 1, 2)), vec![file.clone()], false),
        ] {
            let mut expected_causes = BTreeSet::new();
            if candidate_cut {
                expected_causes.insert("candidate_files_budget_exhausted");
            }
            if byte_refusal.is_some() {
                expected_causes.insert("source_bytes_budget_exhausted");
            }
            if !unavailable.is_empty() {
                expected_causes.insert("indexed_source_unavailable");
            }
            let query = finalize_graph_usage_query(
                GraphUsageOutcome::Resolved(FuzzyResult::empty_success()),
                &CancellationToken::new(),
                AdmittedUsageQuery {
                    candidate_files: HashSet::default(),
                    candidate_files_truncated: !complete_expected,
                    candidate_files_budget_exhausted: candidate_cut,
                    source_bytes_truncated: byte_refusal.is_some(),
                    source_byte_refusal: byte_refusal,
                    unavailable_sources: unavailable,
                    scanned_source_bytes: 0,
                    candidate_files_sample: None,
                },
                None,
            );
            assert_eq!(query.has_complete_coverage(), complete_expected);
            assert_eq!(query.complete_answer(&target).is_some(), complete_expected);
            assert_eq!(
                super::super::reusable_usage_answer_digest(&query, &target).is_some(),
                complete_expected
            );
            let result = query.into_fuzzy_result(std::slice::from_ref(&target));
            assert_eq!(
                matches!(result, FuzzyResult::Success { .. }),
                complete_expected
            );
            if let FuzzyResult::Incomplete { diagnostics, .. } = result {
                let actual: BTreeSet<_> =
                    diagnostics.iter().map(|d| d.reason_kind.as_str()).collect();
                assert_eq!(actual, expected_causes);
                assert_eq!(diagnostics.len(), expected_causes.len());
            }
        }
    }

    struct PanicCandidateProvider;

    impl CandidateFileProvider for PanicCandidateProvider {
        fn find_candidates(
            &self,
            _target: &CodeUnit,
            _analyzer: &dyn IAnalyzer,
        ) -> HashSet<ProjectFile> {
            panic!("pre-cancelled query must not discover candidates");
        }
    }

    #[test]
    #[hardwon("22af2f573b4e: a cancelled usage query still invoked expensive candidate discovery")]
    fn issue_1228_pre_cancelled_query_skips_candidate_discovery() {
        let root = std::env::temp_dir();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root.clone(),
            std::iter::empty::<PathBuf>(),
        ));
        let analyzer = EmptyAnalyzer::new(project);
        let target = CodeUnit::new(
            ProjectFile::new(root, PathBuf::from("Target.java")),
            CodeUnitType::Class,
            "pkg",
            "Target",
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = UsageFinder::new()
            .with_cancellation(cancellation)
            .query_with_provider(
                &analyzer,
                &[target],
                Some(&PanicCandidateProvider),
                DEFAULT_MAX_FILES,
                DEFAULT_MAX_USAGES,
            );

        assert!(result.candidate_files.is_empty());
        assert!(result.result.all_hits_including_imports().is_empty());
        assert_eq!(result.completion, UsageQueryCompletion::Cancelled);
    }

    struct SingleCandidateProvider {
        candidate: ProjectFile,
    }

    impl CandidateFileProvider for SingleCandidateProvider {
        fn find_candidates(
            &self,
            _target: &CodeUnit,
            _analyzer: &dyn IAnalyzer,
        ) -> HashSet<ProjectFile> {
            HashSet::from_iter([self.candidate.clone()])
        }
    }

    #[test]
    #[hardwon(
        "22af2f573b4e: cancellation after discovery was incorrectly reported as empty success"
    )]
    fn issue_1228_cancellation_after_candidate_discovery_is_not_reported_as_empty_success() {
        let root = std::env::temp_dir();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root.clone(),
            std::iter::empty::<PathBuf>(),
        ));
        let analyzer = EmptyAnalyzer::new(project);
        let target_file = ProjectFile::new(root.clone(), PathBuf::from("Target.java"));
        let target = CodeUnit::new(target_file.clone(), CodeUnitType::Class, "pkg", "Target");
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let result = UsageFinder::new()
            .with_cancellation(cancellation)
            .query_with_provider(
                &analyzer,
                &[target],
                Some(&SingleCandidateProvider {
                    candidate: target_file,
                }),
                DEFAULT_MAX_FILES,
                DEFAULT_MAX_USAGES,
            );

        assert_eq!(result.completion, UsageQueryCompletion::Cancelled);
        assert!(result.candidate_files.is_empty());
        assert!(result.result.all_hits_including_imports().is_empty());
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
