//! `why-not`: decide, by bounded prefix re-execution, which selector stage
//! dropped one explicit candidate.
//!
//! The selector of a match policy is one `CodeQuery`: a plan source followed by
//! at most `MAX_QUERY_STEPS` (16) typed steps. This adapter re-executes the
//! source alone, then the source plus `steps[0..1]`, then `steps[0..2]`, and so
//! on, testing each prefix in authored order even though it executes prefixes
//! deepest-first to acquire the deepest candidate-bearing lineage. When a
//! prefix retains the candidate, its
//! typed detailed provenance identifies the exact seed and intermediate rows;
//! this matters for relations that deliberately move the source anchor. When
//! no such lineage exists, the adapter falls back to source-span containment.
//! The first prefix that cannot retain or safely correlate the candidate names
//! the stage that dropped it or makes the answer unknown.
//!
//! Nothing here instruments the matcher, and nothing here changes ordinary
//! evaluation: prefix queries are built by cloning the resolved selector and
//! truncating its step list.

use std::collections::BTreeSet;
use std::ops::Range;

use brokk_bifrost_analysis::analyzer::ProjectFile;
use brokk_bifrost_analysis::analyzer::semantic::{
    WorkspaceRelativePath, WorkspaceRelativePathError,
};
use brokk_bifrost_rql::structural::search::{
    execute_code_query_detailed_eager_index, execute_code_query_detailed_eager_index_workspace,
};
use brokk_bifrost_rql::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryResultDetail, CodeQueryResultValue,
    DetailedCodeQueryEvidence, DetailedCodeQueryProvenanceEvidence,
};
use brokk_bifrost_rql::{CodeQueryPlanSource, SetOperator};

use crate::budget::PolicyBudget;
use crate::definition::{PolicyAnalysis, PolicyAnalysisType};
use crate::evaluator::{PolicyEvaluationContext, incomplete_reason_for_code, incomplete_reasons};
use crate::finding::{PolicyIncompleteReason, PolicySourceLocation};
use crate::resolved::LoadedPolicy;

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, PolicyExplanation, RawNode,
    build_explanation,
};

/// The selector path a match policy's one selector always occupies.
pub(super) const MATCH_SELECTOR_PATH: &str = "/analysis/selector";

/// Explain why one explicit candidate is not reported, choosing the adapter
/// from the loaded policy's analysis.
///
/// This is the entry point a host calls:
///
/// - a `match` policy answers through [`explain_match_candidate`];
/// - an `assertion` policy that carries a relational row plan answers through
///   the relational adapter, which decides per-binding row membership.
///
/// # Errors
///
/// - [`ExplainError::ExplanationAdapterUnavailable`] for a `taint`, `flow`, or
///   `typestate` policy. The error names the families that *are* supported.
/// - [`ExplainError::RelationalPlanUnavailable`] for an assertion policy whose
///   assertions are the capture-oriented families rather than a row plan.
/// - Everything the chosen adapter can return.
pub fn explain_candidate(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    candidate: &ExplanationCandidate,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    match &policy.definition().analysis {
        PolicyAnalysis::Match { .. } => {
            explain_match_candidate(policy, context, candidate, budget, limits)
        }
        PolicyAnalysis::Assertion { spec } => {
            let plan = spec
                .relational
                .as_ref()
                .ok_or(ExplainError::RelationalPlanUnavailable)?;
            super::why_not_relational::explain_relational_candidate(
                policy, plan, context, candidate, budget, limits,
            )
        }
        other => Err(ExplainError::adapter_unavailable(
            other.analysis_type(),
            ExplanationQuestion::WhyNot,
        )),
    }
}

/// One explicit position a caller believes should have matched.
///
/// A candidate is a workspace-relative path plus a byte range. A single offset
/// is spelled as an empty range at that offset ([`ExplanationCandidate::at_offset`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplanationCandidate {
    path: WorkspaceRelativePath,
    byte_start: u64,
    byte_end: u64,
}

impl ExplanationCandidate {
    /// A candidate at one byte offset.
    ///
    /// # Errors
    ///
    /// [`ExplainError::CandidateOutsideWorkspace`] when `path` is absolute,
    /// escapes the workspace with `..`, or is otherwise not a portable
    /// workspace-relative path.
    pub fn at_offset(path: &str, byte_offset: u64) -> Result<Self, ExplainError> {
        Self::in_range(path, byte_offset, byte_offset)
    }

    /// A candidate covering the half-open byte range `[byte_start, byte_end)`.
    ///
    /// # Errors
    ///
    /// [`ExplainError::CandidateOutsideWorkspace`] for a path that is not
    /// workspace-relative, and [`ExplainError::ReversedCandidateRange`] when
    /// the range ends before it starts.
    pub fn in_range(path: &str, byte_start: u64, byte_end: u64) -> Result<Self, ExplainError> {
        if byte_start > byte_end {
            return Err(ExplainError::ReversedCandidateRange {
                start: byte_start,
                end: byte_end,
            });
        }
        let parsed =
            WorkspaceRelativePath::new(path).map_err(|reason: WorkspaceRelativePathError| {
                ExplainError::CandidateOutsideWorkspace {
                    path: path.to_string(),
                    reason,
                }
            })?;
        Ok(Self {
            path: parsed,
            byte_start,
            byte_end,
        })
    }

    pub const fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }
    pub const fn byte_start(&self) -> u64 {
        self.byte_start
    }
    pub const fn byte_end(&self) -> u64 {
        self.byte_end
    }
    /// True when this candidate names one position rather than a region.
    pub const fn is_point(&self) -> bool {
        self.byte_start == self.byte_end
    }
}

/// Does one analyzer row cover this candidate?
///
/// The containment rule, stated exactly because a `why-not` verdict depends on
/// it:
///
/// - A row with **no byte span** is a whole-file row (the `file` domain). It
///   covers every candidate in the file it names.
/// - For a **range candidate** (`byte_end > byte_start`) a row `[rs, re)`
///   covers it when `rs <= byte_start && byte_end <= re`. The row must contain
///   the whole candidate; overlapping is not covering, because a selector that
///   returns only part of the region did not select the region.
/// - For a **point candidate** (`byte_end == byte_start`) a row `[rs, re)`
///   covers it when `rs <= offset < re`. The end is exclusive, so a point at a
///   row's exclusive end is outside it.
/// - A **degenerate empty row** `[p, p)` covers exactly the point candidate at
///   `p`, and no range candidate.
pub(super) fn row_covers_candidate(
    row_span: Option<&Range<usize>>,
    candidate: &ExplanationCandidate,
) -> bool {
    let Some(row_span) = row_span else {
        return true;
    };
    let start = u64::try_from(row_span.start).unwrap_or(u64::MAX);
    let end = u64::try_from(row_span.end).unwrap_or(u64::MAX);
    if candidate.is_point() {
        let offset = candidate.byte_start;
        if start == end {
            return start == offset;
        }
        return start <= offset && offset < end;
    }
    start <= candidate.byte_start && candidate.byte_end <= end
}

/// Explain why one explicit candidate is not reported by a match policy.
///
/// The tree is rooted at the candidate and renders one `selector_stage` node
/// per presented prefix, in authored order: the plan source first, then one
/// node per typed step. Prefix queries execute deepest-first so the adapter can
/// acquire the deepest candidate-bearing lineage and learn whether later
/// anchor-changing prefixes were exhaustive. Each rendered stage says whether
/// that lineage still passes through a returned row after the prefix ran.
///
/// # Failed versus unknown
///
/// A stage is `failed` only when its prefix query is `Complete`, no allowed
/// prefix was omitted, and the retained evidence rules out a later
/// anchor-changing introduction. The last condition comes either from an exact
/// candidate lineage or from an exhaustive strict suffix.
///
/// A stage is `unknown` when its prefix or a relevant later prefix reported
/// `ProvenSubset`, `Incomplete`, `Cancelled`, or `Invalid`; when the
/// prefix budget omitted part of the selector; or when retained provenance
/// cannot correlate a known candidate-bearing prefix. The `ProvenSubset` case
/// is deliberately conservative: a proven subset licenses every row it
/// returned but says nothing about what it left out, so an absence inside it is
/// undecided. The stage's `reasons` carry the mapped
/// [`PolicyIncompleteReason`]s, using the same diagnostic-code mapping the
/// evaluator uses for run completion.
///
/// A row that *is* returned is a positive fact regardless of completion, so a
/// covered candidate is `satisfied` under every completion.
///
/// Every prefix allowed by the execution limit runs before presentation. The
/// authored-order rendering stops at the first stage that is not `satisfied`;
/// results from deeper executions remain internal evidence for provenance and
/// suffix completeness because an anchor-changing step can introduce, move,
/// or lose the candidate.
///
/// # Locations
///
/// Stage nodes carry the candidate's file as an artifact-only location and put
/// the covering row's byte range in `actual`. Row-level display regions are
/// domain-specific and are not part of the detailed evidence this adapter
/// consumes, and inventing one would be worse than omitting it.
///
/// # Errors
///
/// - [`ExplainError::ExplanationAdapterUnavailable`] for a non-`match` policy.
/// - [`ExplainError::SelectorUnavailable`] when the loaded policy carries no
///   resolved `/analysis/selector`.
/// - [`ExplainError::BudgetExhausted`] when `limits` allow no prefix execution
///   or cannot hold a root node.
pub fn explain_match_candidate(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    candidate: &ExplanationCandidate,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let analysis_type = policy.definition().analysis.analysis_type();
    if !matches!(policy.definition().analysis, PolicyAnalysis::Match { .. }) {
        return Err(ExplainError::adapter_unavailable(
            analysis_type,
            ExplanationQuestion::WhyNot,
        ));
    }
    let selector = policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
        .ok_or(ExplainError::SelectorUnavailable)?;
    let Some((_, query)) = selector.as_query() else {
        return Err(ExplainError::PolicyUnavailable {
            message: "match explanations require a query selector; row selectors are endpoint-only"
                .to_owned(),
        });
    };
    if limits.max_prefix_executions() == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::PrefixExecutions,
        });
    }

    let stages = run_prefixes(
        query,
        context,
        candidate,
        budget,
        limits.max_prefix_executions(),
        PrefixExecution::AnalyzerOnly,
        budget.max_findings(),
    );
    let root = candidate_root(candidate, query, stages);
    build_explanation(
        ExplanationQuestion::WhyNot,
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        PolicyAnalysisType::Match,
        ExplanationSubject::Candidate {
            path: candidate.path.as_str().to_string(),
            byte_start: candidate.byte_start,
            byte_end: candidate.byte_end,
        },
        root,
        limits,
    )
}

/// Which execution path a prefix query takes.
///
/// A faithful re-execution must use the same path the evaluator that produced
/// the real verdict uses. The match evaluator reads the analyzer directly; the
/// relational driver prefers the generation-bound workspace oracles when the
/// evaluation context carries a workspace, because its row expansions need
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrefixExecution {
    /// Always execute against `context.analyzer`.
    AnalyzerOnly,
    /// Execute against `context.workspace` when there is one, and against
    /// `context.analyzer` otherwise.
    PreferWorkspace,
}

/// What one executed prefix concluded about the candidate.
#[derive(Debug)]
pub(super) struct StageOutcome {
    label: String,
    outcome: ExplanationOutcome,
    actual: String,
    reasons: Vec<PolicyIncompleteReason>,
    completion_label: Option<&'static str>,
}

impl StageOutcome {
    pub(super) const fn outcome(&self) -> ExplanationOutcome {
        self.outcome
    }
    pub(super) fn label(&self) -> &str {
        &self.label
    }
}

/// What the deepest executed prefix -- the complete selector, which is a row
/// binding's own relation -- returned for the candidate.
///
/// A caller that replays plan-level operators over the candidate's row needs
/// the row itself, not a second query for it, and needs to know whether the
/// query that produced it saw everything: a row absent from a non-exhaustive
/// row set is undecided, so a negative replayed over one is `unknown`.
#[derive(Debug, Default)]
pub(super) struct LocatedRows {
    rows: Vec<CodeQueryResultValue>,
    exhaustive: bool,
    reasons: Vec<PolicyIncompleteReason>,
}

impl LocatedRows {
    /// The rows the query returned for the candidate, judged against what that
    /// same query proved about its own row set.
    fn new(
        rows: Vec<CodeQueryResultValue>,
        completion: &CodeQueryCompletion,
        truncated: bool,
    ) -> Self {
        Self {
            rows,
            exhaustive: !truncated && matches!(completion, CodeQueryCompletion::Complete),
            reasons: absence_reasons(completion, truncated),
        }
    }

    pub(super) fn rows(&self) -> &[CodeQueryResultValue] {
        &self.rows
    }
    /// Whether the query returned every row it could, which is what licenses a
    /// `failed` verdict over the rows it did return.
    pub(super) const fn exhaustive(&self) -> bool {
        self.exhaustive
    }
    /// Why it did not, when it did not.
    pub(super) fn reasons(&self) -> &[PolicyIncompleteReason] {
        &self.reasons
    }
}

/// Rendered authored-order stages, actual executions, and prefix-budget
/// truncation for one walk.
#[derive(Debug)]
pub(super) struct StageWalk {
    stages: Vec<StageOutcome>,
    executed: usize,
    prefixes_truncated: bool,
    omitted_prefixes: u64,
    located: LocatedRows,
}

impl StageWalk {
    /// The rows the complete selector returned for the candidate, empty unless
    /// every presented stage retained it.
    pub(super) const fn located(&self) -> &LocatedRows {
        &self.located
    }
    pub(super) const fn prefixes_truncated(&self) -> bool {
        self.prefixes_truncated
    }
    pub(super) const fn omitted_prefixes(&self) -> u64 {
        self.omitted_prefixes
    }
    /// How many prefix queries this walk actually executed, which is what a
    /// caller charges against a shared execution budget.
    pub(super) const fn executed(&self) -> usize {
        self.executed
    }
    /// The first stage that did not retain the candidate, if any.
    pub(super) fn decided(&self) -> Option<&StageOutcome> {
        self.stages
            .iter()
            .find(|stage| stage.outcome != ExplanationOutcome::Satisfied)
    }
    pub(super) fn into_stages(self) -> Vec<StageOutcome> {
        self.stages
    }
}

pub(super) fn run_prefixes(
    selector: &CodeQuery,
    context: &PolicyEvaluationContext<'_>,
    candidate: &ExplanationCandidate,
    budget: &PolicyBudget,
    max_executions: usize,
    execution: PrefixExecution,
    row_limit: usize,
) -> StageWalk {
    let step_count = selector.plan.steps.len();
    let wanted = step_count.saturating_add(1);
    let executable = wanted.min(max_executions);
    let prefixes_omitted = executable < wanted;
    let mut stages = Vec::with_capacity(executable);
    let mut executed_count = 0usize;

    let execute_prefix = |prefix: usize| {
        let mut query = selector.clone();
        query.plan.steps.truncate(prefix);
        // Author-controlled presentation is not policy semantics: the
        // evaluator forces full detail and its own row bound, and a faithful
        // re-execution must do the same. The bound differs per family, so the
        // caller passes the one its evaluator uses.
        query.result_detail = CodeQueryResultDetail::Full;
        query.limit = row_limit;
        assert!(
            query.validate_steps().is_ok(),
            "every prefix of a resolved selector must remain executable"
        );

        match (execution, context.workspace) {
            (PrefixExecution::PreferWorkspace, Some(workspace)) => {
                execute_code_query_detailed_eager_index_workspace(
                    workspace,
                    &query,
                    budget.query_limits(),
                    context.cancellation,
                )
            }
            _ => execute_code_query_detailed_eager_index(
                context.analyzer,
                &query,
                budget.query_limits(),
                context.cancellation,
            ),
        }
    };

    // Run prefixes deepest-first. The deepest candidate-bearing result carries
    // the most complete identity-safe lineage available even when a later
    // relation moved away from, or dropped, the candidate anchor. Every result
    // is retained and reused by the authored-order presentation walk.
    let mut executed_prefixes = Vec::with_capacity(executable);
    for prefix in (0..executable).rev() {
        executed_count = executed_count.saturating_add(1);
        executed_prefixes.push((prefix, execute_prefix(prefix)));
    }
    let lineage = executed_prefixes
        .iter()
        .find_map(|(prefix, result)| {
            let lineage = CandidateLineage::from_result(
                *prefix,
                &result.result.results,
                &result.evidence,
                candidate,
            );
            lineage.target_retained.then_some(lineage)
        })
        .unwrap_or_default();
    executed_prefixes.reverse();

    // An absent source-span fallback is not conclusive when a later prefix was
    // non-exhaustive: an anchor-changing relation may have introduced the
    // candidate in rows that prefix omitted. Retain the completion state and
    // reasons of every strict suffix before consuming the results for
    // authored-order presentation.
    // The reasons accumulate as an ordered set so every per-prefix snapshot is
    // already sorted and deduplicated; the presentation order is part of the
    // explanation contract, which is what earns the ordered structure here.
    let mut suffix_exhaustive = true;
    let mut suffix_reasons: BTreeSet<PolicyIncompleteReason> = BTreeSet::new();
    let mut later_prefix_state = Vec::with_capacity(executable);
    for (_, executed) in executed_prefixes.iter().rev() {
        later_prefix_state.push((
            suffix_exhaustive,
            suffix_reasons.iter().copied().collect::<Vec<_>>(),
        ));
        let completion = executed.result.completion();
        if !matches!(completion, CodeQueryCompletion::Complete) {
            suffix_exhaustive = false;
            suffix_reasons.extend(absence_reasons(&completion, executed.result.truncated));
        }
    }
    later_prefix_state.reverse();

    let mut located = LocatedRows::default();
    for ((prefix, mut executed), (later_prefixes_exhaustive, later_prefix_reasons)) in
        executed_prefixes.into_iter().zip(later_prefix_state)
    {
        let label = match prefix.checked_sub(1) {
            None => plan_source_label(&selector.plan.source).to_string(),
            Some(index) => selector.plan.steps[index].op().label().to_string(),
        };
        let completion = executed.result.completion();
        let covering = if lineage.target_retained {
            lineage_covering(prefix, &executed.evidence, &lineage).map(describe_lineage_covering)
        } else {
            executed
                .evidence
                .iter()
                .find(|evidence| evidence_covers_candidate(evidence, candidate))
                .map(describe_span_covering)
        };

        let stage = match covering {
            Some(actual) => StageOutcome {
                label,
                outcome: ExplanationOutcome::Satisfied,
                actual,
                reasons: Vec::new(),
                completion_label: non_complete_label(&completion),
            },
            None => {
                // A candidate-bearing prefix proves the candidate exists, but
                // absence of a retained provenance prefix does not prove which
                // other stage lost it. Provenance may itself be bounded, or a
                // producer may lack an identity-preserving detailed reference.
                // Never turn that evidence gap into a false "seed dropped it"
                // verdict.
                let after_candidate_bearing_prefix = lineage
                    .source_prefix
                    .is_some_and(|source_prefix| prefix > source_prefix);
                let lineage_unresolved = lineage.target_retained && !after_candidate_bearing_prefix;
                let later_introduction_unresolved =
                    !lineage.target_retained && !later_prefixes_exhaustive;
                let trustworthy = !lineage_unresolved
                    && !later_introduction_unresolved
                    && !prefixes_omitted
                    && matches!(completion, CodeQueryCompletion::Complete);
                let outcome = if trustworthy {
                    ExplanationOutcome::Failed
                } else {
                    ExplanationOutcome::Unknown
                };
                let rows = executed.result.results.len();
                let mut reasons = absence_reasons(&completion, executed.result.truncated);
                if prefixes_omitted {
                    reasons.push(PolicyIncompleteReason::ReportRetentionBudget);
                }
                if lineage_unresolved {
                    reasons.push(if lineage.provenance_truncated {
                        PolicyIncompleteReason::ReportRetentionBudget
                    } else {
                        PolicyIncompleteReason::CapabilityIncomplete
                    });
                }
                if later_introduction_unresolved {
                    reasons.extend(later_prefix_reasons);
                }
                reasons.sort();
                reasons.dedup();
                StageOutcome {
                    label,
                    outcome,
                    actual: if trustworthy {
                        format!("{rows} rows, none covering the candidate")
                    } else if lineage_unresolved {
                        format!(
                            "an executed prefix retains the candidate, but none of these {rows} rows has a retained identity-preserving provenance path to it"
                        )
                    } else if prefixes_omitted {
                        format!(
                            "{rows} rows, none covering the candidate, but the prefix budget omitted later selector stages or results"
                        )
                    } else if later_introduction_unresolved {
                        format!(
                            "{rows} rows, none covering the candidate, but a later executed selector prefix was non-exhaustive and may still introduce it"
                        )
                    } else {
                        format!(
                            "{rows} rows, none covering the candidate, from a non-exhaustive query"
                        )
                    },
                    reasons,
                    completion_label: non_complete_label(&completion),
                }
            }
        };
        let decided = stage.outcome != ExplanationOutcome::Satisfied;
        if !decided && prefix == step_count {
            // The complete selector is the relation a row binding stands for,
            // so its rows -- and only its rows -- are the candidate's rows.
            debug_assert!(
                !prefixes_omitted,
                "the complete selector runs only when the budget omitted no prefix"
            );
            let covering = executed
                .evidence
                .iter()
                .filter(|evidence| evidence_covers_candidate(evidence, candidate))
                .map(|evidence| evidence.result_index)
                .collect::<Vec<_>>();
            let truncated = executed.result.truncated;
            let rows = std::mem::take(&mut executed.result.results)
                .into_iter()
                .enumerate()
                .filter(|(index, _)| covering.contains(index))
                .map(|(_, item)| item.value)
                .collect();
            located = LocatedRows::new(rows, &completion, truncated);
        }
        stages.push(stage);
        if decided {
            break;
        }
    }

    let presented_count = stages.len();
    let omitted_prefixes = if prefixes_omitted {
        u64::try_from(wanted.saturating_sub(presented_count)).unwrap_or(u64::MAX)
    } else {
        0
    };
    StageWalk {
        stages,
        executed: executed_count,
        prefixes_truncated: omitted_prefixes > 0,
        omitted_prefixes,
        located,
    }
}

#[derive(Default)]
struct CandidateLineage {
    target_retained: bool,
    source_prefix: Option<usize>,
    provenance_truncated: bool,
    targets: Vec<DetailedRowIdentity>,
    traces: Vec<DetailedCodeQueryProvenanceEvidence>,
}

#[derive(PartialEq, Eq)]
struct DetailedRowIdentity {
    domain: brokk_bifrost_rql::structural::DetailedCodeQueryDomain,
    key: brokk_bifrost_rql::structural::DetailedCodeQueryKey,
    file: ProjectFile,
    byte_span: Option<Range<usize>>,
    identities: brokk_bifrost_rql::structural::DetailedCodeQueryProvenanceIdentities,
    source_slice_sha256: Option<[u8; 32]>,
}

impl CandidateLineage {
    fn from_result(
        prefix: usize,
        results: &[brokk_bifrost_rql::structural::CodeQueryResultItem],
        evidence: &[DetailedCodeQueryEvidence],
        candidate: &ExplanationCandidate,
    ) -> Self {
        let mut lineage = Self::default();
        for evidence in evidence {
            if !evidence_covers_candidate(evidence, candidate) {
                continue;
            }
            lineage.target_retained = true;
            lineage.source_prefix = Some(prefix);
            let item = &results[evidence.result_index];
            lineage.provenance_truncated |= item.provenance_truncated;
            lineage.targets.push(DetailedRowIdentity {
                domain: evidence.domain,
                key: evidence.key.clone(),
                file: evidence.file.clone(),
                byte_span: evidence.byte_span.clone(),
                identities: evidence.identities.clone(),
                source_slice_sha256: evidence.source_slice_sha256,
            });
            lineage.traces.extend(evidence.provenance.iter().cloned());
        }
        lineage
    }
}

fn evidence_covers_candidate(
    evidence: &DetailedCodeQueryEvidence,
    candidate: &ExplanationCandidate,
) -> bool {
    evidence
        .file
        .rel_path()
        .to_str()
        .and_then(|path| WorkspaceRelativePath::new(path).ok())
        .is_some_and(|path| path == candidate.path)
        && row_covers_candidate(evidence.byte_span.as_ref(), candidate)
}

fn describe_span_covering(evidence: &DetailedCodeQueryEvidence) -> String {
    match evidence.byte_span.as_ref() {
        Some(span) => format!(
            "a {} row covering bytes [{}, {}) retains the candidate",
            evidence.domain.label(),
            span.start,
            span.end
        ),
        None => format!(
            "a whole-file {} row retains the candidate",
            evidence.domain.label()
        ),
    }
}

fn describe_lineage_covering(evidence: &DetailedCodeQueryEvidence) -> String {
    match evidence.byte_span.as_ref() {
        Some(span) => format!(
            "a {} row at bytes [{}, {}) on the candidate's identity-preserving provenance path retains it",
            evidence.domain.label(),
            span.start,
            span.end
        ),
        None => format!(
            "a whole-file {} row on the candidate's identity-preserving provenance path retains it",
            evidence.domain.label()
        ),
    }
}

fn lineage_covering<'a>(
    prefix: usize,
    evidence: &'a [DetailedCodeQueryEvidence],
    lineage: &CandidateLineage,
) -> Option<&'a DetailedCodeQueryEvidence> {
    if lineage
        .source_prefix
        .is_some_and(|source_prefix| prefix > source_prefix)
    {
        return None;
    }
    evidence.iter().find(|candidate| {
        lineage.targets.iter().any(|target| {
            candidate.domain == target.domain
                && candidate.key == target.key
                && candidate.file == target.file
                && candidate.byte_span == target.byte_span
                && candidate.identities == target.identities
                && candidate.source_slice_sha256 == target.source_slice_sha256
        }) || lineage.traces.iter().any(|terminal| {
            evidence_matches_ref(candidate, &terminal.seed)
                || candidate
                    .provenance
                    .iter()
                    .any(|prefix| provenance_is_prefix(prefix, terminal))
        })
    })
}

fn evidence_matches_ref(
    evidence: &DetailedCodeQueryEvidence,
    reference: &brokk_bifrost_rql::structural::DetailedCodeQueryProvenanceRefEvidence,
) -> bool {
    evidence.domain == reference.domain
        && evidence.key == reference.key
        && evidence.file == reference.file
        && evidence.byte_span == reference.byte_span
        && evidence.identities == reference.identities
        && evidence.source_slice_sha256 == reference.source_slice_sha256
}

fn provenance_is_prefix(
    prefix: &DetailedCodeQueryProvenanceEvidence,
    terminal: &DetailedCodeQueryProvenanceEvidence,
) -> bool {
    prefix.branch == terminal.branch
        && prefix.seed == terminal.seed
        && prefix.steps.len() <= terminal.steps.len()
        && prefix
            .steps
            .iter()
            .zip(&terminal.steps)
            .all(|(left, right)| left == right)
}

/// Map a non-exhaustive completion to the reasons an absence is undecided.
///
/// `Complete` never reaches here. Every other completion contributes its own
/// diagnostic codes through the evaluator's existing code-to-reason mapping,
/// so a `why-not` answer names incompleteness in the same vocabulary a run
/// does.
pub(super) fn absence_reasons(
    completion: &CodeQueryCompletion,
    truncated: bool,
) -> Vec<PolicyIncompleteReason> {
    let mut reasons = match completion {
        CodeQueryCompletion::Complete => Vec::new(),
        CodeQueryCompletion::ProvenSubset { codes } | CodeQueryCompletion::Invalid { codes } => {
            codes.iter().map(incomplete_reason_for_code).collect()
        }
        CodeQueryCompletion::Incomplete { .. } | CodeQueryCompletion::Cancelled => {
            incomplete_reasons(completion, truncated)
        }
    };
    if reasons.is_empty() && !matches!(completion, CodeQueryCompletion::Complete) {
        reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

const fn non_complete_label(completion: &CodeQueryCompletion) -> Option<&'static str> {
    match completion {
        CodeQueryCompletion::Complete => None,
        CodeQueryCompletion::ProvenSubset { .. } => Some("proven_subset"),
        CodeQueryCompletion::Incomplete { .. } => Some("incomplete"),
        CodeQueryCompletion::Cancelled => Some("cancelled"),
        CodeQueryCompletion::Invalid { .. } => Some("invalid"),
    }
}

/// One executed prefix as an explanation node, with its query-completion child
/// when the query was not exhaustive.
pub(super) fn stage_node(stage: StageOutcome, candidate: &ExplanationCandidate) -> RawNode {
    let completion_label = stage.completion_label;
    let reasons = stage.reasons.clone();
    let mut node = RawNode::new(
        ExplanationNodeKind::SelectorStage,
        stage.outcome,
        stage.label,
    )
    .with_expected("a returned row covers the candidate")
    .with_actual(stage.actual)
    .with_location(Some(PolicySourceLocation::artifact(candidate.path.clone())))
    .with_reasons(stage.reasons);
    if let Some(completion_label) = completion_label {
        node.push_child(
            RawNode::new(
                ExplanationNodeKind::CoverageObligation,
                ExplanationOutcome::Unknown,
                "query_completion",
            )
            .with_expected("an exhaustive query over the candidate's file")
            .with_actual(completion_label)
            .with_reasons(reasons),
        );
    }
    node
}

fn candidate_root(
    candidate: &ExplanationCandidate,
    selector: &CodeQuery,
    walk: StageWalk,
) -> RawNode {
    let decided = walk.decided();
    let root_outcome = match decided {
        Some(stage) => stage.outcome,
        None if walk.prefixes_truncated => ExplanationOutcome::Unknown,
        None => ExplanationOutcome::Satisfied,
    };
    let actual = match decided {
        Some(stage) => match stage.outcome {
            ExplanationOutcome::Failed => {
                format!("the candidate is dropped at selector stage {}", stage.label)
            }
            _ => format!(
                "the selector stage {} could not decide the candidate",
                stage.label
            ),
        },
        None if walk.prefixes_truncated => String::from(
            "the prefix-execution limit stopped the walk before the selector was exhausted",
        ),
        None => String::from("the selector retains the candidate at every stage"),
    };

    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        root_outcome,
        "match_candidate",
    )
    .with_expected(format!(
        "selector {MATCH_SELECTOR_PATH} retains the candidate through {} stage(s)",
        selector.plan.steps.len().saturating_add(1)
    ))
    .with_actual(actual)
    .with_location(Some(PolicySourceLocation::artifact(candidate.path.clone())))
    .with_source_truncation(walk.prefixes_truncated, walk.omitted_prefixes);

    for stage in walk.stages {
        root.push_child(stage_node(stage, candidate));
    }
    root
}

/// A short, stable label for the plan source a selector starts from.
const fn plan_source_label(source: &CodeQueryPlanSource) -> &'static str {
    match source {
        CodeQueryPlanSource::Seed(_) => "seed",
        CodeQueryPlanSource::Occurrences(_) => "occurrences",
        CodeQueryPlanSource::Scopes(_) => "scopes",
        CodeQueryPlanSource::Bindings(_) => "bindings",
        CodeQueryPlanSource::Paths(_) => "paths",
        CodeQueryPlanSource::GenerationSites(_) => "generation_sites",
        CodeQueryPlanSource::Exports(_) => "exports",
        CodeQueryPlanSource::Set { op, .. } => match op {
            SetOperator::Union => "union",
            SetOperator::Intersect => "intersect",
            SetOperator::Except => "except",
        },
    }
}
