//! `why`: project one retained assertion finding into an explanation tree.
//!
//! Like the match adapter, this one re-executes nothing. Every node is a
//! projection of what the run already retained -- the finding's evidence, its
//! primary and related locations, the run's completion, and the run's canonical
//! `obligations` list -- so a `why` answer is exactly as complete as the report
//! it came from and cannot disagree with it.
//!
//! # Relational assertions
//!
//! A relational assertion finding (`assert_kind == "relational"`) carries
//! everything the explanation needs without touching the plan:
//!
//! | explanation field | retained source |
//! | --- | --- |
//! | assertion id | the anchor's `assert_id` |
//! | group key | the anchor's `subject_ast_id`, which holds the rendered key |
//! | group | the evidence's `expected_class` |
//! | cardinality | the evidence's `expectation` |
//! | aggregate and observed value | the evidence's `observed` |
//! | representative rows | the finding's primary and related locations |
//!
//! The evaluator writes exactly those fields (`evaluate_relational_assertion_policy`
//! in `evaluator/assertion.rs`), which is why this adapter needs no read
//! accessor on the evaluator and no re-execution.
//!
//! # Outcomes
//!
//! The root is `satisfied`: the finding is established by retained evidence.
//! The assertion node under it is `failed`, because the finding exists exactly
//! when the authored expectation did not hold; its `expected` and `actual` are
//! the authored cardinality and the observed aggregate. That divergence from
//! the match adapter -- where every node is `satisfied` -- is deliberate: an
//! assertion finding *is* a failed comparison, and flattening it to `satisfied`
//! would throw away the one thing a reader wants.
//!
//! An obligation is never `failed`. An unmet obligation means the run could not
//! establish a coverage claim, so its node is `unknown` with the obligation's
//! own typed reasons.

use crate::finding::{
    AssertionFindingEvidence, PolicyFinding, PolicyLocationRelationship, PolicyObligation,
    PolicyRun,
};

use super::model::{
    ExplainError, ExplanationLimits, ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion,
    ExplanationSubject, PolicyExplanation, RawNode, build_explanation,
};
use super::why::coverage_node;

/// The `assert_kind` the relational driver stamps on every row-plan finding.
pub(super) const RELATIONAL_ASSERT_KIND: &str = "relational";

/// Explain why one retained assertion finding exists.
///
/// The tree is rooted at the finding projection and carries, in order:
///
/// 1. the assertion node, holding the authored expectation beside the observed
///    value, with one `source_fact` child per retained representative row (the
///    finding's primary location first, then its related locations in the
///    order the evaluator retained them);
/// 2. the run's completion as a coverage obligation, satisfied when the run is
///    reliable and unknown otherwise;
/// 3. one coverage-obligation node per unmet obligation the run retained *for
///    this same assertion*, in the run's own deterministic order.
///
/// Obligations belonging to another assertion are deliberately not attached:
/// they say nothing about this finding, and joining them would invite a reader
/// to blame an unrelated blocked verdict.
///
/// # Errors
///
/// [`ExplainError::BudgetExhausted`] when `limits` cannot hold even a root.
pub(super) fn explain_assertion_finding(
    run: &PolicyRun,
    finding: &PolicyFinding,
    evidence: &AssertionFindingEvidence,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let root = assertion_root(run, finding, evidence);
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

fn assertion_root(
    run: &PolicyRun,
    finding: &PolicyFinding,
    evidence: &AssertionFindingEvidence,
) -> RawNode {
    let assert_id = evidence.anchor().assert_id();
    let relational = evidence.assert_kind() == RELATIONAL_ASSERT_KIND;
    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        ExplanationOutcome::Satisfied,
        "assertion_finding",
    )
    .with_expected(if relational {
        format!(
            "assertion `{assert_id}` over group `{}` holds {}",
            evidence.expected_class(),
            evidence.expectation()
        )
    } else {
        format!(
            "assertion `{assert_id}` over `{}` holds {}",
            evidence.expected_class(),
            evidence.expectation()
        )
    })
    .with_actual(finding.message())
    .with_location(Some(finding.primary().clone()));

    root.push_child(assertion_node(finding, evidence));
    root.push_child(coverage_node(run.completion()));
    for obligation in run
        .obligations()
        .iter()
        .filter(|obligation| obligation.assertion() == assert_id)
    {
        root.push_child(obligation_node(obligation));
    }
    // The run's obligation list is itself bounded. Say so on the node that
    // carries the obligations rather than inventing a second truncation
    // channel: the run already counted what it dropped.
    root.with_source_truncation(
        run.obligations_truncated(),
        run.omitted_obligations_lower_bound(),
    )
}

/// The assertion itself: what was authored, what was observed, and which rows
/// the evaluator kept as the reason.
fn assertion_node(finding: &PolicyFinding, evidence: &AssertionFindingEvidence) -> RawNode {
    let assert_id = evidence.anchor().assert_id();
    let key = evidence.anchor().subject_ast_id();
    let relational = evidence.assert_kind() == RELATIONAL_ASSERT_KIND;
    let mut node = RawNode::new(
        ExplanationNodeKind::Assertion,
        ExplanationOutcome::Failed,
        assert_id,
    )
    .with_expected(if relational && !key.is_empty() {
        format!(
            "{} `{}` over group `{}` at key `{key}` requires {}",
            evidence.assert_kind(),
            evidence.asserted_role(),
            evidence.expected_class(),
            evidence.expectation()
        )
    } else {
        format!(
            "{} `{}` over `{}` requires {}",
            evidence.assert_kind(),
            evidence.asserted_role(),
            evidence.expected_class(),
            evidence.expectation()
        )
    })
    .with_actual(match evidence.observed() {
        Some(observed) => observed.to_string(),
        None => format!("{} contributing row(s)", evidence.actual_count()),
    })
    .with_location(Some(finding.primary().clone()));

    // The first representative row is the finding's own anchor; the evaluator
    // retains every other contributing row as a related location tagged
    // `Subject` (the first) or `Evidence`.
    node.push_child(
        RawNode::new(
            ExplanationNodeKind::SourceFact,
            ExplanationOutcome::Satisfied,
            "anchor_row",
        )
        .with_expected("a contributing row at the finding anchor")
        .with_actual(format!(
            "the group key `{}` is anchored here",
            evidence.anchor().subject_ast_id()
        ))
        .with_location(Some(finding.primary().clone())),
    );
    for related in finding.related() {
        node.push_child(
            RawNode::new(
                ExplanationNodeKind::SourceFact,
                ExplanationOutcome::Satisfied,
                relationship_label(related.relationship()),
            )
            .with_expected("a row that contributed to the asserted aggregate")
            .with_actual(format!(
                "{} row",
                relationship_label(related.relationship())
            ))
            .with_location(Some(related.location().clone())),
        );
    }
    node.with_source_truncation(
        finding.related_truncated(),
        finding.omitted_related_locations_lower_bound(),
    )
}

/// One unmet obligation for this assertion.
///
/// `unknown`, never `failed`: an unmet obligation states that the run could not
/// establish a coverage claim, which is not the same as establishing that the
/// claim is false.
fn obligation_node(obligation: &PolicyObligation) -> RawNode {
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        ExplanationOutcome::Unknown,
        obligation.kind().as_str(),
    )
    .with_expected(format!(
        "assertion `{}` can publish a verdict for group `{}`",
        obligation.assertion(),
        obligation.group()
    ))
    .with_actual(match obligation.group_key() {
        Some(key) => format!("no verdict was published at group key `{key}`"),
        None => String::from("no verdict was published for the group relation"),
    })
    .with_reasons(obligation.reasons().to_vec())
}

/// The stable snake_case node label for one related-location relationship.
///
/// The relational driver emits only `Subject` (the first representative row)
/// and `Evidence` (every other one), but the mapping is total so a future
/// assertion family cannot reach an unlabelled node.
const fn relationship_label(relationship: PolicyLocationRelationship) -> &'static str {
    match relationship {
        PolicyLocationRelationship::Subject => "subject_row",
        PolicyLocationRelationship::Evidence => "evidence_row",
        PolicyLocationRelationship::Source => "source_row",
        PolicyLocationRelationship::Sink => "sink_row",
        PolicyLocationRelationship::Origin => "origin_row",
        PolicyLocationRelationship::WitnessStep => "witness_step_row",
        PolicyLocationRelationship::Declaration => "declaration_row",
        PolicyLocationRelationship::CallTarget => "call_target_row",
        PolicyLocationRelationship::ExpectedOccurrence => "expected_occurrence_row",
        PolicyLocationRelationship::ActualOccurrence => "actual_occurrence_row",
        PolicyLocationRelationship::SelectedCandidate => "selected_candidate_row",
        PolicyLocationRelationship::ConsideredCandidate => "considered_candidate_row",
        PolicyLocationRelationship::BindingOf => "binding_of_row",
        PolicyLocationRelationship::DeclaringScope => "declaring_scope_row",
        PolicyLocationRelationship::GenerationSite => "generation_site_row",
        PolicyLocationRelationship::GeneratedDeclaration => "generated_declaration_row",
    }
}
