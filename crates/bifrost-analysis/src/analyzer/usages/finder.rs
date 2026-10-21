use crate::analyzer::languages::{CandidateCtx, candidate_augmentation, language_support};
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
type FileFilter<'a> = Box<dyn Fn(&ProjectFile) -> bool + Send + Sync + 'a>;

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
    pub completion: UsageQueryCompletion,
    pub candidate_files: HashSet<ProjectFile>,
    pub candidate_files_truncated: bool,
    pub source_bytes_truncated: bool,
    pub scanned_source_bytes: usize,
    pub candidate_files_sample: Option<CandidateFilesSample>,
    pub result: FuzzyResult,
    /// The authority of the strategy that produced `result`, so a consumer can
    /// read the proof tiers correctly without naming a language.
    pub proof_authority: UsageProofAuthority,
    pub graph_failure: Option<crate::analyzer::usages::model::UsageAnalysisDiagnostic>,
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
    #[doc(hidden)]
    pub scanned_source_bytes: usize,
    #[doc(hidden)]
    pub candidate_files_sample: Option<CandidateFilesSample>,
}

type AdmittedUsagePlan = (AdmittedUsageQuery, Option<Box<dyn PreparedUsageQuery>>);

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
        F: Fn(&ProjectFile) -> bool + Send + Sync + 'a,
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
        F: Fn(&ProjectFile) -> bool + Send + Sync + 'a,
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
        let (admitted_query, prepared) = match self.admit_query(
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
        let strategy = language_support(language_for_target(target))
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
        finalize_graph_usage_query(outcome, &self.cancellation, admitted_query, strategy)
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
                source_bytes_truncated: false,
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
        let hierarchy_scope = match self.excluded_test_files.as_deref() {
            Some(excluded) => DescendantIndexScope::excluding_sources(&self.cancellation, excluded),
            None => DescendantIndexScope::whole_workspace(&self.cancellation),
        };
        let _cand_scope = crate::profiling::scope("usages::candidate_discovery");
        let mut candidates = HashSet::default();
        for overload in overloads {
            match explicit_provider {
                Some(provider) => candidates.extend(provider.find_candidates(overload, analyzer)),
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
        let strategy = language_support(language_for_target(target))
            .map(|support| support.reference_plugin().target_strategy());
        let provider_is_complete_scope =
            explicit_provider.is_some_and(CandidateFileProvider::is_complete_scope);
        let plan = if provider_is_complete_scope {
            PlannedUsageQuery {
                protected_candidates: candidates,
                supplemental_candidates: HashSet::default(),
            }
        } else {
            augment_usage_candidates(analyzer, overloads, &candidates, &self.cancellation)
        };
        candidates = plan.protected_candidates;
        let supplemental = plan.supplemental_candidates;
        let prepared = if provider_is_complete_scope {
            None
        } else {
            strategy.and_then(|strategy| {
                strategy.prepare_usage_query(analyzer, overloads, &candidates, &self.cancellation)
            })
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
            candidates.retain(|file| !self.cancellation.is_cancelled() && filter(file));
            protected_candidates.retain(|file| !self.cancellation.is_cancelled() && filter(file));
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
        let (admitted, scanned_source_bytes, source_bytes_truncated, source_admission_cancelled) =
            admit_candidates_by_source_bytes(
                analyzer,
                candidates,
                &protected_candidates,
                max_source_bytes,
                &self.cancellation,
            );
        if source_admission_cancelled {
            return Err(Box::new(cancelled_query_result()));
        }
        candidates = admitted;
        let candidate_files_truncated = candidates.len() < all_candidates.len();
        let candidate_files_sample =
            candidate_files_truncated.then(|| candidate_files_sample(&all_candidates, &candidates));

        let admitted_query = AdmittedUsageQuery {
            candidate_files: candidates,
            candidate_files_truncated,
            candidate_files_budget_exhausted,
            source_bytes_truncated,
            scanned_source_bytes,
            candidate_files_sample,
        };

        Ok((admitted_query, prepared))
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
                .map(|(target_index, (query, prepared))| GraphUsageBatchQuery {
                    overloads: std::slice::from_ref(&targets[*target_index]),
                    scope: UsageScanScope::with_cancellation(
                        &query.candidate_files,
                        &self.cancellation,
                    )
                    .with_test_inclusion(self.excluded_test_files.is_none())
                    .with_unproven_limit(self.max_unproven),
                    prepared: prepared.as_deref(),
                })
                .collect();
            let outcomes = match language_support(language) {
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
            for ((target_index, (query, _)), outcome) in admitted.into_iter().zip(outcomes) {
                let strategy = language_support(language)
                    .map(|support| support.reference_plugin().target_strategy());
                answers[target_index] = Some(finalize_graph_usage_query(
                    outcome,
                    &self.cancellation,
                    query,
                    strategy,
                ));
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
            .result
    }

    pub fn find_usages_default(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
    ) -> FuzzyResult {
        self.find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
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
        source_bytes_truncated: false,
        scanned_source_bytes: 0,
        candidate_files_sample: None,
        result: FuzzyResult::empty_success(),
        // A cancelled scan ran no strategy, so nothing certified this answer.
        proof_authority: UsageProofAuthority::Legacy,
        graph_failure: None,
    }
}

fn admit_candidates_by_source_bytes(
    analyzer: &dyn IAnalyzer,
    candidates: HashSet<ProjectFile>,
    protected_candidates: &HashSet<ProjectFile>,
    max_source_bytes: Option<usize>,
    cancellation: &CancellationToken,
) -> (HashSet<ProjectFile>, usize, bool, bool) {
    let Some(max_source_bytes) = max_source_bytes else {
        return (candidates, 0, false, false);
    };

    let mut ordered = candidates.iter().cloned().collect::<Vec<_>>();
    ordered.sort_by_key(|file| (!protected_candidates.contains(file), file.clone()));
    let mut admitted = HashSet::default();
    let mut scanned_source_bytes = 0usize;
    for file in ordered {
        if cancellation.is_cancelled() {
            return (HashSet::default(), 0, false, true);
        }
        let Some(source_bytes) = analyzer.indexed_source(&file).map(|source| source.len()) else {
            continue;
        };
        if scanned_source_bytes.saturating_add(source_bytes) <= max_source_bytes {
            scanned_source_bytes += source_bytes;
            admitted.insert(file);
        }
    }
    let truncated = admitted.len() < candidates.len();
    (admitted, scanned_source_bytes, truncated, false)
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
    match language_support(language) {
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
