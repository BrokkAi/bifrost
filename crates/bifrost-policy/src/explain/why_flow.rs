//! `why`: project one retained flow or taint finding into an explanation tree.
//!
//! Like the match and assertion adapters, this one re-executes nothing. Every
//! node is a projection of evidence the run already retained -- the origin
//! endpoints and their exact sites, the bounded witness paths the solver
//! proved, the finding's certainty, proof and completeness, and the run's own
//! completion -- so a `why` answer is exactly as complete as the report it came
//! from and cannot disagree with it.
//!
//! # Two families, one retained shape
//!
//! A flow finding is a taint finding produced by the same interprocedural
//! solver over one synthetic internal label (#2436), so both families retain
//! the identical [`TaintFindingEvidence`]. What differs is what may be
//! published: `FlowFindingEvidence` deliberately hides the synthetic label,
//! categories and scenarios the flow lowering mints, because publishing them
//! would invite a reader to treat a correctness rule as a taint
//! classification. The two entry points below therefore build their own roots
//! and their own origin nodes, in their own vocabulary, and share every node
//! that projects a field the two families hold in common.
//!
//! | explanation node | retained source |
//! | --- | --- |
//! | root | the finding's message, primary location, and endpoint display names |
//! | `origin` / `taint_origin` | one `TaintOriginEvidence` (endpoint, site, and for taint its label and scenario) |
//! | `source_row` | one related location the origins did not already state |
//! | `witness_path` | one retained `BoundedWitness` |
//! | one step per path | one `WitnessStep`: its kind, label, exact site, and evidence references |
//! | `finding_certainty` | `FindingCertainty` and its typed reasons |
//! | `path_proof` | `ProofMetadata` |
//! | `retained_witnesses` | the finding's witness truncation pair |
//! | `finding_completeness` | `FindingCompleteness` and its typed reasons |
//! | `run_completion` | `PolicyRunCompletion` |
//!
//! # Outcomes
//!
//! Every node that projects retained evidence is `satisfied`: the finding is a
//! chain of facts that held, and the path nodes are the chain. Every node that
//! projects a limit of that evidence -- a possible certainty, an unproven
//! path, a truncated witness, a partial finding, an unreliable run -- is
//! `unknown`, never `failed`. None of them establishes that something is
//! absent; each states that the run did not establish that it is present.
//!
//! # Not projected
//!
//! The non-canonical display path (`TaintDisplayPathCache`) is a bounded
//! presentation projection of these same witnesses, chosen for a one-line
//! concise rendering. An explanation publishes the canonical steps instead, so
//! that a consumer comparing an explanation against the report's witnesses
//! compares like with like.

use crate::finding::{
    BoundedWitness, CertaintyReason, FindingIncompleteReason, PolicyFinding,
    PolicyLocationRelationship, PolicyRun, PolicySourceLocation, ProofMetadata, ProofReason,
    ProofState, RelatedPolicyLocation,
};
use crate::future_evidence::{FlowFindingEvidence, TaintFindingEvidence, TaintOriginEvidence};
use crate::resolved::ResolvedEndpointIdentity;

use super::model::{
    ExplainError, ExplanationLimits, ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion,
    ExplanationSubject, PolicyExplanation, RawNode, build_explanation,
};
use super::why::coverage_node;

/// Explain why one retained flow finding exists.
///
/// The tree is rooted at the finding projection, which sits on the observation
/// the tracked value reached, and carries, in order: one node per retained
/// origin, one node per related site the origins did not already state, one
/// node per retained witness path with its steps in path order, and the
/// finding's certainty, proof, witness retention, completeness and run
/// completion as coverage obligations.
///
/// # Errors
///
/// [`ExplainError::BudgetExhausted`] when `limits` cannot hold even a root.
pub(super) fn explain_flow_finding(
    run: &PolicyRun,
    finding: &PolicyFinding,
    evidence: &FlowFindingEvidence,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let taint_shaped = evidence.taint_shaped();
    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        ExplanationOutcome::Satisfied,
        "flow_finding",
    )
    .with_expected(format!(
        "a value from origin `{}` reaches observation `{}` at event `{}`",
        evidence.origin_display_name(),
        evidence.observation_display_name(),
        evidence.observation().as_str(),
    ))
    .with_actual(finding.message())
    .with_location(Some(finding.primary().clone()));

    for origin in evidence.origins() {
        root.push_child(
            RawNode::new(
                ExplanationNodeKind::SourceFact,
                ExplanationOutcome::Satisfied,
                "origin",
            )
            .with_expected(format!(
                "the tracked value originates at origin endpoint `{}`",
                endpoint_entry(origin.source_endpoint())
            ))
            .with_actual(with_evidence_refs(
                format!("origin {}", evidence.origin_display_name()),
                origin,
            ))
            .with_location(Some(origin.primary().clone())),
        );
    }
    push_shared_children(&mut root, run, finding, taint_shaped);
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

/// Explain why one retained taint finding exists.
///
/// The tree has the shape [`explain_flow_finding`] documents, in the security
/// vocabulary the taint family retains: each origin node names the label the
/// value entered with and the source scenario it belongs to, both of which a
/// flow finding does not publish.
///
/// # Errors
///
/// [`ExplainError::BudgetExhausted`] when `limits` cannot hold even a root.
pub(super) fn explain_taint_finding(
    run: &PolicyRun,
    finding: &PolicyFinding,
    evidence: &TaintFindingEvidence,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        ExplanationOutcome::Satisfied,
        "taint_finding",
    )
    .with_expected(format!(
        "a value from source `{}` reaches sink `{}` at event `{}`",
        evidence.source_display_name(),
        evidence.sink_display_name(),
        evidence.sink().as_str(),
    ))
    .with_actual(finding.message())
    .with_location(Some(finding.primary().clone()));

    for origin in evidence.origins() {
        root.push_child(
            RawNode::new(
                ExplanationNodeKind::SourceFact,
                ExplanationOutcome::Satisfied,
                "taint_origin",
            )
            .with_expected(format!(
                "a `{}` value enters at source endpoint `{}`",
                origin.source_label().as_str(),
                endpoint_entry(origin.source_endpoint())
            ))
            .with_actual(with_evidence_refs(
                format!(
                    "source {} in scenario {}",
                    evidence.source_display_name(),
                    origin.scenario_id().as_str()
                ),
                origin,
            ))
            .with_location(Some(origin.primary().clone())),
        );
    }
    push_shared_children(&mut root, run, finding, evidence);
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

/// Everything below the origin nodes, which the two families retain alike.
///
/// The root's own truncation pair is set here too, because the same two
/// retained counters -- the origins the projection dropped and the witnesses
/// the finding dropped -- are exactly what shortened this child list.
fn push_shared_children(
    root: &mut RawNode,
    run: &PolicyRun,
    finding: &PolicyFinding,
    evidence: &TaintFindingEvidence,
) {
    for related in unstated_related_locations(finding, evidence) {
        root.push_child(
            RawNode::new(
                ExplanationNodeKind::SourceFact,
                ExplanationOutcome::Satisfied,
                "source_row",
            )
            .with_expected("a retained site the tracked value passed through")
            .with_location(Some(related.clone())),
        );
    }
    for witness in finding.witnesses() {
        root.push_child(witness_node(witness));
    }
    root.push_child(certainty_node(finding));
    root.push_child(proof_node(finding.proof()));
    root.push_child(retained_witness_node(finding));
    root.push_child(completeness_node(finding));
    root.push_child(coverage_node(run.completion()));

    let dropped_root_children = u64::from(evidence.origins_truncated())
        .saturating_add(finding.omitted_witnesses_lower_bound());
    root.children_truncated |= evidence.origins_truncated() || finding.witnesses_truncated();
    root.omitted_children_lower_bound = root
        .omitted_children_lower_bound
        .saturating_add(dropped_root_children);
}

/// One retained witness path, with its steps in path order.
///
/// The path node itself carries no location: a path is a sequence of sites, and
/// naming one of them at the top would privilege it over the rest. Each step
/// carries the exact site the analyzer recorded for it, where it recorded one.
fn witness_node(witness: &BoundedWitness) -> RawNode {
    let mut node = RawNode::new(
        ExplanationNodeKind::Derivation,
        ExplanationOutcome::Satisfied,
        "witness_path",
    )
    .with_expected("a retained path from an origin to the observation")
    .with_actual(format!(
        "path {} with {} retained step(s)",
        witness.id().as_str(),
        witness.steps().len()
    ))
    .with_source_truncation(witness.truncated(), witness.omitted_steps_lower_bound());
    for step in witness.steps() {
        let mut actual = step.label().to_owned();
        if !step.evidence_refs().is_empty() {
            actual.push_str(" [evidence");
            for evidence_ref in step.evidence_refs() {
                actual.push(' ');
                actual.push_str(evidence_ref.as_str());
            }
            actual.push(']');
        }
        node.push_child(
            RawNode::new(
                ExplanationNodeKind::Derivation,
                ExplanationOutcome::Satisfied,
                step.kind().label(),
            )
            .with_actual(actual)
            .with_location(step.location().cloned()),
        );
    }
    node
}

/// The finding's certainty as one obligation.
///
/// A `possible` finding is may-evidence: the solver reported a path it could
/// not prove exactly. That is `unknown` and never `failed`, and the reasons it
/// carries are named rather than flattened into "possible".
fn certainty_node(finding: &PolicyFinding) -> RawNode {
    let reasons = finding.certainty().reasons();
    let outcome = if reasons.is_empty() {
        ExplanationOutcome::Satisfied
    } else {
        ExplanationOutcome::Unknown
    };
    let actual = if reasons.is_empty() {
        finding.certainty().label().to_owned()
    } else {
        format!(
            "{}: {}",
            finding.certainty().label(),
            join_labels(reasons.iter().map(CertaintyReason::label))
        )
    };
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        outcome,
        "finding_certainty",
    )
    .with_expected("the reported path is definite")
    .with_actual(actual)
}

/// The finding's proof state as one obligation.
fn proof_node(proof: &ProofMetadata) -> RawNode {
    let outcome = match proof.state() {
        ProofState::Proven => ExplanationOutcome::Satisfied,
        ProofState::Unproven | ProofState::Ambiguous => ExplanationOutcome::Unknown,
    };
    let mut actual = proof.state().label().to_owned();
    if !proof.reasons().is_empty() {
        actual.push_str(": ");
        actual.push_str(&join_labels(proof.reasons().iter().map(ProofReason::label)));
    }
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        outcome,
        "path_proof",
    )
    .with_expected("the retained witnesses prove the reported path")
    .with_actual(actual)
}

/// What the finding kept of the solver's witnesses, and what it did not.
///
/// A finding with no retained witness, a dropped witness, or a truncated one
/// says so here instead of letting a reader infer completeness from the number
/// of path nodes above.
///
/// The evidence's own `witness_refs_truncated` is not read: the projection
/// authority requires it to equal the finding's `witnesses_truncated`
/// (`validate_witness_references`), so reading both would report one fact
/// twice.
fn retained_witness_node(finding: &PolicyFinding) -> RawNode {
    let truncated_paths = finding
        .witnesses()
        .iter()
        .filter(|witness| witness.truncated())
        .count();
    let complete =
        !finding.witnesses().is_empty() && !finding.witnesses_truncated() && truncated_paths == 0;
    let mut actual = format!("{} retained path(s)", finding.witnesses().len());
    if finding.witnesses_truncated() {
        actual.push_str(&format!(
            "; at least {} path(s) omitted",
            finding.omitted_witnesses_lower_bound()
        ));
    }
    if truncated_paths > 0 {
        actual.push_str(&format!(
            "; {truncated_paths} retained path(s) omitted steps"
        ));
    }
    if finding.witnesses().is_empty() {
        actual.push_str("; no path is available to walk");
    }
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        if complete {
            ExplanationOutcome::Satisfied
        } else {
            ExplanationOutcome::Unknown
        },
        "retained_witnesses",
    )
    .with_expected("every path the solver proved is retained in full")
    .with_actual(actual)
}

/// The finding's own completeness as one obligation.
fn completeness_node(finding: &PolicyFinding) -> RawNode {
    let reasons = finding.completeness().reasons();
    let actual = if reasons.is_empty() {
        finding.completeness().label().to_owned()
    } else {
        format!(
            "{}: {}",
            finding.completeness().label(),
            join_labels(reasons.iter().copied().map(FindingIncompleteReason::label))
        )
    };
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        if reasons.is_empty() {
            ExplanationOutcome::Satisfied
        } else {
            ExplanationOutcome::Unknown
        },
        "finding_completeness",
    )
    .with_expected("the finding retains its evidence in full")
    .with_actual(actual)
}

/// The related sites the origin nodes did not already state.
///
/// The taint and flow projections retain one `Source` related location per
/// origin site, so an unfiltered pass would publish most sites twice. The
/// retained list can still hold a site no retained origin does -- the origins
/// are truncated independently -- so the remainder is published rather than
/// dropped.
fn unstated_related_locations<'a>(
    finding: &'a PolicyFinding,
    evidence: &'a TaintFindingEvidence,
) -> impl Iterator<Item = &'a PolicySourceLocation> {
    finding
        .related()
        .iter()
        .filter(|related| related.relationship() == PolicyLocationRelationship::Source)
        .map(RelatedPolicyLocation::location)
        .filter(move |location| {
            *location != finding.primary()
                && !evidence
                    .origins()
                    .iter()
                    .any(|origin| origin.primary() == *location)
        })
}

/// One origin's rendering, with the evidence references it carries.
fn with_evidence_refs(mut text: String, origin: &TaintOriginEvidence) -> String {
    if origin.evidence_refs().is_empty() {
        return text;
    }
    text.push_str(" [evidence");
    for evidence_ref in origin.evidence_refs() {
        text.push(' ');
        text.push_str(evidence_ref.as_str());
    }
    text.push(']');
    text
}

fn join_labels<'a>(labels: impl Iterator<Item = &'a str>) -> String {
    labels.collect::<Vec<_>>().join(", ")
}

/// The authored entry a resolved endpoint identity names.
///
/// Every identity spelling ends in one authored id -- a local or catalog entry,
/// or a match endpoint -- and that id is what an author recognizes.
fn endpoint_entry(identity: &ResolvedEndpointIdentity) -> &str {
    match identity {
        ResolvedEndpointIdentity::Local { entry_id, .. }
        | ResolvedEndpointIdentity::Catalog { entry_id, .. } => entry_id.as_str(),
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => endpoint_id.as_str(),
    }
}
