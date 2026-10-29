// `UsageScanScope` -- the scan boundary plus its cancellation token -- names
// nothing analyzer-shaped, so it lives in `brokk-bifrost-core` where a language
// crate can accept one. Its co-residents below all name `IAnalyzer` and stay.
pub(crate) use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::model::{FuzzyResult, UsageProofAuthority};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;

/// Language-specific state prepared before the generic usage-query budgets run.
///
/// The plan owns its language-specific execution, so framework code never names
/// a language module or downcasts an untyped payload.
#[doc(hidden)]
pub trait PreparedUsageQuery: Send + Sync {
    fn candidate_files(&self) -> &HashSet<ProjectFile>;

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome;
}

/// Strategy for resolving usages of one or more overloads within a candidate file set.
pub trait UsageAnalyzer: Send + Sync {
    /// Independent queries with the same admission as `find_usages`.
    ///
    /// Memo hits replay publications but not read-ledger keys. Policy units must
    /// not route through this batch API until hits also replay their read keys
    /// (#7262). Dead-code reports are neither persisted nor policy units.
    fn find_usages_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<FuzzyResult> {
        queries
            .iter()
            .map(|query| {
                self.find_usages(
                    analyzer,
                    query.overloads,
                    query.scope.candidate_files(),
                    max_usages,
                )
            })
            .collect()
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult;
}

/// One independently admitted target group in a shared scan.
#[doc(hidden)]
pub struct GraphUsageBatchQuery<'a> {
    pub overloads: &'a [CodeUnit],
    pub scope: UsageScanScope<'a>,
    pub prepared: Option<&'a dyn PreparedUsageQuery>,
}

/// Graph-backed usage strategy that can distinguish fallback-safe gaps from terminal failures.
#[doc(hidden)]
pub trait GraphUsageAnalyzer: Send + Sync {
    /// Whether this strategy's proof tiers are authoritative. The engine stamps
    /// the answer with it so a consumer that may publish only proven evidence
    /// can tell a certified native inventory from a legacy language resolver's
    /// long-standing answer, without naming a language itself.
    ///
    /// The default is [`UsageProofAuthority::Legacy`]: a strategy that does not
    /// certify an inventory must not have its unproven candidates read as gaps
    /// in one.
    fn proof_authority(&self) -> UsageProofAuthority {
        UsageProofAuthority::Legacy
    }

    /// Prepare a complete target-directed inventory without generic candidate
    /// discovery. A returned plan owns every nomination, including unproven
    /// sites, so importer and hierarchy prepasses cannot add useful coverage.
    /// The framework still applies file and source-byte admission to its files.
    /// Explicit candidate providers bypass this hook; returning None preserves
    /// generic discovery and prepare_usage_query. Preparation must preserve the
    /// complete inventory and proof/completion evidence, not merely proven hits.
    ///
    /// PythonNativeUsageStrategy is the only current opt-in: its selected reverse
    /// operation owns all nominations independently of generic candidates. Java
    /// and Kotlin production strategies still consume generic discovery; explicit
    /// native JVM test queries already bypass it. Go uses canonical per-file
    /// hierarchy facts and Rust uses trait-directed hierarchy reads, neither the
    /// all-declaration hydration prepass removed for Python. They retain their
    /// existing preparation/scoping contracts rather than opt in implicitly.
    fn prepare_target_usage_query(
        &self,
        _analyzer: &dyn IAnalyzer,
        _overloads: &[CodeUnit],
        _cancellation: &CancellationToken,
    ) -> Option<Box<dyn PreparedUsageQuery>> {
        None
    }

    /// Prepare language-specific candidate and resolver state before generic
    /// file-count and source-byte admission. Most languages need no preparation.
    fn prepare_usage_query(
        &self,
        _analyzer: &dyn IAnalyzer,
        _overloads: &[CodeUnit],
        _candidate_files: &HashSet<ProjectFile>,
        _cancellation: &CancellationToken,
    ) -> Option<Box<dyn PreparedUsageQuery>> {
        None
    }

    fn find_graph_usages_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<GraphUsageOutcome> {
        queries
            .iter()
            .map(|query| match query.prepared {
                Some(prepared) => {
                    prepared.find_graph_usages(analyzer, query.overloads, &query.scope, max_usages)
                }
                None => self.find_graph_usages(analyzer, query.overloads, &query.scope, max_usages),
            })
            .collect()
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome;
}

impl<T> UsageAnalyzer for T
where
    T: GraphUsageAnalyzer,
{
    fn find_usages_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<FuzzyResult> {
        self.find_graph_usages_batch(analyzer, queries, max_usages)
            .into_iter()
            .map(GraphUsageOutcome::into_fuzzy_result)
            .collect()
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        super::finder::execute_graph_usage_query_in_scope(
            self,
            analyzer,
            overloads,
            candidate_files,
            max_usages,
        )
    }
}

/// Per-language resolver for the `scan_usages` (query) path. Borrows the concrete
/// analyzer out of `&dyn IAnalyzer` in [`try_new`](UsageQueryResolver::try_new) and
/// resolves one target's usages within a candidate file set. One impl per graph
/// language, so "both usage paths share one resolver" is a contract, not convention.
///
/// The `'a` borrow is load-bearing: impls hold `&'a ConcreteAnalyzer` from the analyzer
/// passed to `try_new`. Used only as a static bound, never as `dyn`.
#[doc(hidden)]
pub trait UsageQueryResolver<'a>: Sized {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self>;

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome;
}

#[doc(hidden)]
pub struct GraphUsageDispatchSpec {
    #[doc(hidden)]
    pub target_language: Language,
    #[doc(hidden)]
    pub unsupported_target: &'static str,
    #[doc(hidden)]
    pub missing_analyzer: &'static str,
    #[doc(hidden)]
    pub strategy: &'static str,
}

#[doc(hidden)]
pub fn dispatch_graph_usage_query<'a, Resolver>(
    analyzer: &'a dyn IAnalyzer,
    overloads: &[CodeUnit],
    scan_scope: &UsageScanScope<'_>,
    max_usages: usize,
    dispatch: GraphUsageDispatchSpec,
) -> GraphUsageOutcome
where
    Resolver: UsageQueryResolver<'a>,
{
    let Some(target) = overloads.first() else {
        return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
    };
    if language_for_target(target) != dispatch.target_language {
        return GraphUsageOutcome::fallback_safe(
            target.fq_name(),
            GraphFailureReason::UnsupportedTargetLanguage(dispatch.unsupported_target),
            dispatch.strategy,
        );
    }
    let Some(resolver) = Resolver::try_new(analyzer) else {
        return GraphUsageOutcome::fallback_safe(
            target.fq_name(),
            GraphFailureReason::MissingAnalyzerCapability(dispatch.missing_analyzer),
            dispatch.strategy,
        );
    };

    resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
}

/// Strategy for narrowing the file set fed into a [`UsageAnalyzer`].
///
/// Implementations should favor false positives over false negatives — over-reporting
/// candidates is fine; missing real call sites is not.
pub trait CandidateFileProvider: Send + Sync {
    /// Files named by the caller, whose publication is part of the request contract.
    /// Discovery providers leave this absent even when they bound the complete scope.
    fn explicit_candidate_files(&self) -> Option<&HashSet<ProjectFile>> {
        None
    }

    fn find_candidates(&self, target: &CodeUnit, analyzer: &dyn IAnalyzer) -> HashSet<ProjectFile>;

    /// Whether the returned files are the caller's complete execution scope.
    ///
    /// Discovery providers return false so language plugins can add structured
    /// candidates such as Ruby autoload consumers. A path-scoped provider returns
    /// true because scanning any file outside its result would violate the request.
    fn is_complete_scope(&self) -> bool {
        false
    }
}
