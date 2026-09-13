//! `why`: project one retained typestate finding into an explanation tree.
//!
//! Like the match, assertion and flow adapters, this one re-executes nothing.
//! Every node is a projection of evidence the run already retained -- the
//! protocol subject and the endpoint it entered the protocol at, the sites the
//! projection kept, the violating transition or unmet terminal expectation, the
//! solver's bounded witness paths, and the finding's certainty, proof, witness
//! retention, completeness and run completion -- so a `why` answer is exactly
//! as complete as the report it came from and cannot disagree with it.
//!
//! # A protocol witness is not a reachability witness
//!
//! A flow or taint finding is a meeting: a value leaves an origin and arrives
//! at an observation, and the witness is the path between them. A typestate
//! finding is an *automaton verdict*: a subject was tracked through state
//! events until one of them was not allowed. What a reader needs first is
//! therefore the transition itself -- the event, the state it left, and the
//! state it entered -- or, for the terminal family, the state the subject was
//! observed in against the states the expectation admitted.
//!
//! That is why the violating node here is an `assertion` node with a `failed`
//! outcome, exactly as the assertion adapter's is, rather than another
//! `derivation` node. The finding *is* a comparison that did not hold, and
//! flattening it to `satisfied` would discard the one thing a reader wants.
//!
//! | explanation node | retained source |
//! | --- | --- |
//! | root | the finding's message, primary location and subject reference |
//! | `protocol_subject` | `AnalysisSubjectRef` and the resolved source endpoint |
//! | `acquisition_site` / `subject_spelling` | one related location the root did not already state |
//! | `error_transition` / `terminal_expectation` | `TypestateViolationEvidence` |
//! | `witness_path` | one retained `BoundedWitness`, projected by the flow adapter's own node builder |
//! | `protocol_scenarios` | the evidence's scenario set and its truncation pair |
//! | `finding_certainty`, `path_proof`, `retained_witnesses`, `finding_completeness`, `run_completion` | the same retained fields every path-carrying family publishes |
//!
//! # Outcomes
//!
//! Every node projecting a retained fact is `satisfied`; the violating
//! transition is `failed`; every node projecting a *limit* of the evidence -- a
//! possible certainty, an unproven path, a truncated witness or scenario set,
//! a partial finding, an unreliable run -- is `unknown`, never `failed`.

use crate::definition::TypestateStateId;
use crate::finding::{PolicyFinding, PolicyRun, RelatedPolicyLocation};
use crate::future_evidence::{
    ResolvedTypestateTerminal, TypestateFindingEvidence, TypestateViolationEvidence,
};

use super::model::{
    ExplainError, ExplanationLimits, ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion,
    ExplanationSubject, PolicyExplanation, RawNode, build_explanation,
};
use super::why::coverage_node;
use super::why_assertion::relationship_label;
use super::why_flow::{
    certainty_node, completeness_node, endpoint_entry, proof_node, retained_witness_node,
    witness_node,
};

/// Explain why one retained typestate finding exists.
///
/// # Errors
///
/// [`ExplainError::BudgetExhausted`] when `limits` cannot hold even a root.
pub(super) fn explain_typestate_finding(
    run: &PolicyRun,
    finding: &PolicyFinding,
    evidence: &TypestateFindingEvidence,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        ExplanationOutcome::Satisfied,
        "typestate_finding",
    )
    .with_expected(format!(
        "subject `{}` obeys the protocol it enters at endpoint `{}`",
        evidence.subject().as_str(),
        endpoint_entry(evidence.source_endpoint())
    ))
    .with_actual(finding.message())
    .with_location(Some(finding.primary().clone()));

    root.push_child(
        RawNode::new(
            ExplanationNodeKind::SourceFact,
            ExplanationOutcome::Satisfied,
            "protocol_subject",
        )
        .with_expected("the tracked subject the automaton ran over")
        .with_actual(format!(
            "subject {} from endpoint {}",
            evidence.subject().as_str(),
            endpoint_entry(evidence.source_endpoint())
        ))
        .with_location(Some(finding.primary().clone())),
    );
    // The projection retains one `Source` location per acquisition and one
    // `Subject` location per spelling of the tracked value. They are the sites
    // a reader walks to see where the subject came from, so they are published
    // rather than folded into the root; the finding's own anchor is already
    // stated above and is filtered out here for the same reason the flow
    // adapter filters its origins.
    for related in finding
        .related()
        .iter()
        .filter(|related| related.location() != finding.primary())
    {
        root.push_child(related_node(related));
    }
    root.push_child(violation_node(finding, evidence.violation()));
    for witness in finding.witnesses() {
        root.push_child(witness_node(witness));
    }
    root.push_child(scenario_node(evidence));
    root.push_child(certainty_node(finding));
    root.push_child(proof_node(finding.proof()));
    root.push_child(retained_witness_node(finding));
    root.push_child(completeness_node(finding));
    root.push_child(coverage_node(run.completion()));

    // The two retained counters that shortened this child list: the related
    // locations the projection dropped and the witnesses the finding dropped.
    root.children_truncated |= finding.related_truncated() || finding.witnesses_truncated();
    root.omitted_children_lower_bound = root
        .omitted_children_lower_bound
        .saturating_add(finding.omitted_related_locations_lower_bound())
        .saturating_add(finding.omitted_witnesses_lower_bound());

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

/// One retained site the typestate projection kept beside the violation.
fn related_node(related: &RelatedPolicyLocation) -> RawNode {
    RawNode::new(
        ExplanationNodeKind::SourceFact,
        ExplanationOutcome::Satisfied,
        relationship_label(related.relationship()),
    )
    .with_expected("a retained site of the tracked protocol subject")
    .with_location(Some(related.location().clone()))
}

/// The event the automaton refused, stated as the comparison it is.
///
/// The node sits at the finding's own anchor because that anchor *is* the
/// violation site: the typestate projection mints the primary location from
/// `TypestateFinding::site`, which is the site the violating observation was
/// made at.
fn violation_node(finding: &PolicyFinding, violation: &TypestateViolationEvidence) -> RawNode {
    let node = match violation {
        TypestateViolationEvidence::ErrorTransition {
            event_id,
            endpoint,
            from,
            to,
        } => RawNode::new(
            ExplanationNodeKind::Assertion,
            ExplanationOutcome::Failed,
            "error_transition",
        )
        .with_expected(format!(
            "event `{}` does not move the subject out of state `{}` into an error state",
            event_id.as_str(),
            from.as_str()
        ))
        .with_actual(match endpoint {
            Some(endpoint) => format!(
                "event `{}` at endpoint `{}` moved the subject from `{}` to `{}`",
                event_id.as_str(),
                endpoint_entry(endpoint),
                from.as_str(),
                to.as_str()
            ),
            None => format!(
                "event `{}` moved the subject from `{}` to `{}`",
                event_id.as_str(),
                from.as_str(),
                to.as_str()
            ),
        }),
        TypestateViolationEvidence::TerminalExpectation {
            expectation_id,
            terminal,
            observed_state,
            expected_states,
        } => RawNode::new(
            ExplanationNodeKind::Assertion,
            ExplanationOutcome::Failed,
            "terminal_expectation",
        )
        .with_expected(format!(
            "expectation `{}` requires state {} at {}",
            expectation_id.as_str(),
            join_states(expected_states),
            terminal_label(terminal)
        ))
        .with_actual(format!(
            "the subject was observed in state `{}`",
            observed_state.as_str()
        )),
    };
    node.with_location(Some(finding.primary().clone()))
}

/// The scenario set the violation was established over.
///
/// A truncated set is `unknown`: the finding stands, but the explanation cannot
/// name every scenario that produced it, and a reader must not infer the set
/// from the ids that survived.
fn scenario_node(evidence: &TypestateFindingEvidence) -> RawNode {
    let mut actual = format!(
        "{} retained scenario(s): {}",
        evidence.scenario_ids().len(),
        evidence
            .scenario_ids()
            .iter()
            .map(|scenario| scenario.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if evidence.scenarios_truncated() {
        actual.push_str(&format!(
            "; at least {} scenario(s) omitted",
            evidence.omitted_scenarios_lower_bound()
        ));
    }
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        if evidence.scenarios_truncated() {
            ExplanationOutcome::Unknown
        } else {
            ExplanationOutcome::Satisfied
        },
        "protocol_scenarios",
    )
    .with_expected("every scenario the violation was established over is retained")
    .with_actual(actual)
}

/// Where the terminal expectation was evaluated, in the authored vocabulary.
fn terminal_label(terminal: &ResolvedTypestateTerminal) -> String {
    match terminal {
        ResolvedTypestateTerminal::Endpoint { endpoint, phase } => format!(
            "endpoint `{}` ({})",
            endpoint_entry(endpoint),
            phase.label()
        ),
        ResolvedTypestateTerminal::SemanticEvent { event } => format!(
            "semantic event `{}/{}`",
            event.label(),
            event.scope().label()
        ),
    }
}

fn join_states(states: &[TypestateStateId]) -> String {
    let rendered = states
        .iter()
        .map(|state| format!("`{}`", state.as_str()))
        .collect::<Vec<_>>();
    match rendered.len() {
        1 => rendered.join(""),
        _ => format!("one of [{}]", rendered.join(", ")),
    }
}
