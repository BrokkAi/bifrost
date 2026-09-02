//! `why`: project one retained match finding into an explanation tree.
//!
//! This adapter never re-executes anything. Every node it emits is a
//! projection of evidence the run already retained, so a `why` answer is
//! exactly as complete as the report it came from and cannot disagree with it.

use crate::definition::PolicyAnalysisType;
use crate::finding::{
    MatchFindingEvidence, PolicyFinding, PolicyFindingEvidence, PolicyIncompleteReason,
    PolicyQueryProvenance, PolicyQueryResultRef, PolicyRun, PolicyRunCompletion,
    PolicySourceLocation,
};
use crate::finding_identity::PolicyFindingId;

use super::model::{
    ExplainError, ExplanationLimits, ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion,
    ExplanationSubject, PolicyExplanation, RawNode, build_explanation,
};

/// The selector path a match policy's one selector always occupies. Re-derived
/// here rather than reaching into the evaluator so this module stays additive.
const MATCH_SELECTOR_PATH: &str = "/analysis/selector";

/// Explain why one retained finding exists, choosing the adapter from the
/// evidence the finding carries.
///
/// This is the entry point a host calls. It dispatches on the finding's own
/// evidence variant rather than on the run's analysis type, because the
/// evidence is what an adapter reads:
///
/// - `match` evidence projects through [`explain_match_finding`];
/// - `assertion` evidence -- including every relational assertion -- projects
///   through [`super::why_assertion::explain_assertion_finding`];
/// - `flow` and `taint` evidence project through the two entry points of
///   [`super::why_flow`], which read the witness paths, origins, certainty,
///   proof and completeness the run retained.
///
/// # Errors
///
/// - [`ExplainError::FindingNotFound`] when the run retains no finding with
///   this identity.
/// - [`ExplainError::ExplanationAdapterUnavailable`] for a `typestate`
///   finding. The error names the families that *are* supported.
/// - [`ExplainError::BudgetExhausted`] when `limits` cannot hold even a root.
pub fn explain_finding(
    run: &PolicyRun,
    finding_id: &PolicyFindingId,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let finding = find_finding(run, finding_id)?;
    match finding.evidence() {
        PolicyFindingEvidence::Match { .. } => explain_match_finding(run, finding_id, limits),
        PolicyFindingEvidence::Assertion { evidence } => {
            super::why_assertion::explain_assertion_finding(run, finding, evidence, limits)
        }
        PolicyFindingEvidence::Flow { evidence } => {
            super::why_flow::explain_flow_finding(run, finding, evidence, limits)
        }
        PolicyFindingEvidence::Taint { evidence } => {
            super::why_flow::explain_taint_finding(run, finding, evidence, limits)
        }
        other => Err(ExplainError::adapter_unavailable(
            other.analysis_type(),
            ExplanationQuestion::Why,
        )),
    }
}

fn find_finding<'a>(
    run: &'a PolicyRun,
    finding_id: &PolicyFindingId,
) -> Result<&'a PolicyFinding, ExplainError> {
    run.findings()
        .iter()
        .find(|finding| finding.id() == *finding_id)
        .ok_or(ExplainError::FindingNotFound {
            finding: *finding_id,
        })
}

/// Explain why one retained match finding exists.
///
/// The tree is rooted at the finding projection and carries, in order:
///
/// 1. the terminal row the finding anchors on;
/// 2. one branch node per retained query provenance record, each holding the
///    seed row and one node per pipeline step (with the step's `via` row as a
///    child where the analyzer recorded one);
/// 3. the run's coverage obligation, which is `satisfied` when the run's
///    completion is reliable and `unknown` otherwise, carrying the run's own
///    incomplete reasons.
///
/// Every node's outcome is `satisfied`: a retained finding is, by
/// construction, a chain of facts that held. What a `why` answer adds is the
/// chain itself, its exact locations, and where the retained evidence was cut
/// short (reported through the root's `children_truncated` pair).
///
/// # Errors
///
/// - [`ExplainError::ExplanationAdapterUnavailable`] when the run is not a
///   `match` run. Use [`explain_finding`] to dispatch on the finding instead.
/// - [`ExplainError::FindingNotFound`] when the run retains no finding with
///   this identity.
/// - [`ExplainError::BudgetExhausted`] when `limits` cannot hold even a root.
pub fn explain_match_finding(
    run: &PolicyRun,
    finding_id: &PolicyFindingId,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    if run.analysis_type() != PolicyAnalysisType::Match {
        return Err(ExplainError::adapter_unavailable(
            run.analysis_type(),
            ExplanationQuestion::Why,
        ));
    }
    let finding = find_finding(run, finding_id)?;
    let PolicyFindingEvidence::Match { evidence } = finding.evidence() else {
        return Err(ExplainError::adapter_unavailable(
            finding.evidence().analysis_type(),
            ExplanationQuestion::Why,
        ));
    };
    let root = finding_root(finding, evidence, run.completion());
    build_explanation(
        ExplanationQuestion::Why,
        run.policy_id().clone(),
        run.policy_hash(),
        run.analysis_type(),
        ExplanationSubject::Finding {
            finding_id: finding.id(),
            location: finding.primary().clone(),
        },
        root,
        limits,
    )
}

fn finding_root(
    finding: &PolicyFinding,
    evidence: &MatchFindingEvidence,
    completion: &PolicyRunCompletion,
) -> RawNode {
    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        ExplanationOutcome::Satisfied,
        "match_finding",
    )
    .with_expected(format!(
        "selector {MATCH_SELECTOR_PATH} selects a {} row",
        evidence.result_domain().as_str()
    ))
    .with_actual(finding.message())
    .with_location(Some(finding.primary().clone()))
    .with_source_truncation(
        evidence.provenance_truncated(),
        u64::from(evidence.provenance_truncated()),
    );

    root.push_child(
        RawNode::new(
            ExplanationNodeKind::SourceFact,
            ExplanationOutcome::Satisfied,
            "terminal_row",
        )
        .with_expected(format!(
            "a {} row at the finding anchor",
            evidence.result_domain().as_str()
        ))
        .with_actual(describe_ref(evidence.terminal()))
        .with_location(ref_location(evidence.terminal())),
    );

    for provenance in evidence.provenance() {
        root.push_child(provenance_node(provenance));
    }
    root.push_child(coverage_node(completion));
    root
}

fn provenance_node(provenance: &PolicyQueryProvenance) -> RawNode {
    let branch = provenance
        .branch()
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let mut node = RawNode::new(
        ExplanationNodeKind::SelectorStage,
        ExplanationOutcome::Satisfied,
        "provenance_branch",
    )
    .with_actual(if branch.is_empty() {
        String::from("root branch")
    } else {
        format!("set branch {branch}")
    });
    node.push_child(
        RawNode::new(
            ExplanationNodeKind::SourceFact,
            ExplanationOutcome::Satisfied,
            "seed_row",
        )
        .with_actual(describe_ref(provenance.seed()))
        .with_location(ref_location(provenance.seed())),
    );
    for step in provenance.steps() {
        let mut step_node = RawNode::new(
            ExplanationNodeKind::SelectorStage,
            ExplanationOutcome::Satisfied,
            step.operation(),
        )
        .with_actual(describe_ref(step.result()))
        .with_location(ref_location(step.result()));
        if let Some(via) = step.via() {
            step_node.push_child(
                RawNode::new(
                    ExplanationNodeKind::SourceFact,
                    ExplanationOutcome::Satisfied,
                    "via_row",
                )
                .with_actual(describe_ref(via))
                .with_location(ref_location(via)),
            );
        }
        node.push_child(step_node);
    }
    node
}

/// The run's coverage obligation as one node.
///
/// A reliable completion (`Complete`, `ProvenSubset`, `ProvenBySummary`)
/// licenses the finding, so the obligation is `satisfied`. Anything else is
/// `unknown` rather than `failed`: an inconclusive, unsupported, or failed run
/// did not disprove the coverage claim, it failed to establish it.
pub(super) fn coverage_node(completion: &PolicyRunCompletion) -> RawNode {
    let (outcome, reasons) = match completion {
        PolicyRunCompletion::Complete
        | PolicyRunCompletion::ProvenSubset { .. }
        | PolicyRunCompletion::ProvenBySummary => (ExplanationOutcome::Satisfied, Vec::new()),
        PolicyRunCompletion::Inconclusive { reasons } => {
            (ExplanationOutcome::Unknown, reasons.clone())
        }
        PolicyRunCompletion::Unsupported { .. } => (
            ExplanationOutcome::Unknown,
            vec![PolicyIncompleteReason::CapabilityIncomplete],
        ),
        PolicyRunCompletion::Failed { .. } => (ExplanationOutcome::Unknown, Vec::new()),
    };
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        outcome,
        "run_completion",
    )
    .with_expected("the run's selector coverage licenses this finding")
    .with_actual(completion_label(completion))
    .with_reasons(reasons)
}

fn completion_label(completion: &PolicyRunCompletion) -> &'static str {
    match completion {
        PolicyRunCompletion::Complete => "complete",
        PolicyRunCompletion::ProvenSubset { .. } => "proven_subset",
        PolicyRunCompletion::ProvenBySummary => "proven_by_summary",
        PolicyRunCompletion::Inconclusive { .. } => "inconclusive",
        PolicyRunCompletion::Unsupported { .. } => "unsupported",
        PolicyRunCompletion::Failed { .. } => "failed",
    }
}

/// The exact location a retained row reference carries.
///
/// A `file` reference has no span, so it projects to the artifact-only
/// location the crate already uses for whole-file findings.
pub(super) fn ref_location(value: &PolicyQueryResultRef) -> Option<PolicySourceLocation> {
    match value {
        PolicyQueryResultRef::File { path } => Some(PolicySourceLocation::artifact(path.clone())),
        other => other.location().cloned(),
    }
}

/// A short, deterministic rendering of one retained row reference.
pub(super) fn describe_ref(value: &PolicyQueryResultRef) -> String {
    match value {
        PolicyQueryResultRef::StructuralMatch { kind, .. } => format!("structural_match {kind}"),
        PolicyQueryResultRef::Declaration { kind, fq_name, .. } => {
            format!("declaration {kind} {fq_name}")
        }
        PolicyQueryResultRef::File { path } => format!("file {}", path.as_str()),
        PolicyQueryResultRef::ReferenceSite {
            target_fq_name,
            usage_kind,
            ..
        } => match usage_kind {
            Some(usage_kind) => format!("reference_site {usage_kind} -> {target_fq_name}"),
            None => format!("reference_site -> {target_fq_name}"),
        },
        PolicyQueryResultRef::CallSite {
            caller_fq_name,
            callee_fq_name,
            ..
        } => format!("call_site {caller_fq_name} -> {callee_fq_name}"),
        PolicyQueryResultRef::ExpressionSite {
            input_kind,
            parameter_index,
            parameter_name,
            ..
        } => match (parameter_index, parameter_name) {
            (_, Some(name)) => format!("expression_site {input_kind} {name}"),
            (Some(index), None) => format!("expression_site {input_kind} #{index}"),
            (None, None) => format!("expression_site {input_kind}"),
        },
        PolicyQueryResultRef::JsxAttributeValue {
            element_identity,
            coverage,
            ..
        } => format!("jsx_attribute_value {element_identity} {coverage}"),
        PolicyQueryResultRef::MemberTargetAnalysis {
            outcome, coverage, ..
        } => format!("member_target_analysis {outcome} {coverage}"),
        PolicyQueryResultRef::FieldWriteValue {
            member_target_id,
            coverage,
            ..
        } => format!("field_write_value -> {member_target_id} {coverage}"),
        PolicyQueryResultRef::ReceiverAnalysis {
            analysis_kind,
            outcome,
            ..
        } => format!("receiver_analysis {analysis_kind} {outcome}"),
        PolicyQueryResultRef::Unsupported {
            query_result_kind, ..
        } => format!("unsupported {query_result_kind}"),
    }
}
