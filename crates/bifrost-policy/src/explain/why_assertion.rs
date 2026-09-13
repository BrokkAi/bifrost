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
//! # Declared effects
//!
//! An effect policy asserts over the `procedure_effect` relation, so the rows
//! behind its verdict are derivations rather than positions. The evaluator
//! retains their chains on the finding
//! ([`crate::finding::EffectDerivationEvidence`]), and this adapter publishes
//! one `effect_derivation` node per chain under the assertion node, with the
//! reviewed declaration, the propagation, and the timing classification as its
//! children (issue 3207).
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
    AssertionFindingEvidence, EffectDerivationEvidence, PolicyFinding, PolicyLocationRelationship,
    PolicyObligation, PolicyRun,
};

use super::model::{
    ExplainError, ExplanationLimits, ExplanationNodeKind, ExplanationOutcome, ExplanationQuestion,
    ExplanationSubject, PolicyExplanation, RawNode, build_explanation,
};
use super::why::coverage_node;

/// The `assert_kind` the relational driver stamps on every row-plan finding.
pub(super) const RELATIONAL_ASSERT_KIND: &str = "relational";

/// The one `coverage` value of the effect relation that licenses an absence
/// claim. Spelled once here rather than compared inline in two places.
const EXHAUSTIVE_EFFECT_COVERAGE: &str = "exhaustive";

/// Explain why one retained assertion finding exists.
///
/// The tree is rooted at the finding projection and carries, in order:
///
/// 1. the assertion node, holding the authored expectation beside the observed
///    value, with one `source_fact` child per retained representative row (the
///    finding's primary location first, then its related locations in the
///    order the evaluator retained them), followed by one `effect_derivation`
///    child per retained declared-effect chain;
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
    for derivation in evidence.effect_derivations() {
        node.push_child(effect_derivation_node(derivation));
    }
    node.with_source_truncation(
        finding.related_truncated() || evidence.effect_derivations_truncated(),
        finding
            .omitted_related_locations_lower_bound()
            .saturating_add(evidence.omitted_effect_derivations_lower_bound()),
    )
}

/// One declared-effect chain behind the asserted aggregate.
///
/// The three links the effect contract names are three children rather than
/// three sentences in one string: the reviewed declaration the effect came
/// from, the propagation the analyzer walked to reach it, and the timing that
/// classification was composed under. A consumer branches on the labels; it
/// never parses the prose.
///
/// The propagation child is one node and not one node per hop, because one
/// bounded rendered chain is what the effect relation retains. Splitting that
/// rendering into hops would mean reading a string the analyzer publishes as a
/// whole, and a `why` answer is a projection of retained evidence rather than a
/// second parse of it.
///
/// The chain node is `satisfied` -- the effect is attributed, which is why the
/// finding exists -- while its coverage child is `unknown` whenever the effect
/// relation did not declare the reachable call graph exhaustive or the chain
/// complete. An open effect set never disproves anything; it states that the
/// walk did not finish.
fn effect_derivation_node(derivation: &EffectDerivationEvidence) -> RawNode {
    let mut node = RawNode::new(
        ExplanationNodeKind::EffectDerivation,
        ExplanationOutcome::Satisfied,
        "effect",
    )
    .with_expected(format!(
        "the asserted aggregate counts the `{}` effect",
        derivation.effect_id()
    ))
    .with_actual(match derivation.certainty() {
        Some(certainty) => format!(
            "{} effect `{}` ({}), {}",
            derivation.classification(),
            derivation.effect_id(),
            certainty,
            derivation.derivation()
        ),
        None => format!(
            "{} effect `{}`, {}",
            derivation.classification(),
            derivation.effect_id(),
            derivation.derivation()
        ),
    });

    node.push_child(
        RawNode::new(
            ExplanationNodeKind::EffectDerivation,
            ExplanationOutcome::Satisfied,
            "effect_declaration",
        )
        .with_expected("a reviewed semantic model declares this effect on an exact procedure")
        .with_actual(format!(
            "derivation {} at depth {}",
            derivation.derivation(),
            derivation
                .depth()
                .map_or_else(|| String::from("unknown"), |depth| depth.to_string())
        )),
    );
    node.push_child(
        RawNode::new(
            ExplanationNodeKind::EffectDerivation,
            ExplanationOutcome::Satisfied,
            "propagation_hop",
        )
        .with_expected("the call chain from the asserted procedure to the declaring one")
        // The hop truncation is stated on the coverage obligation below rather
        // than through this node's child-truncation pair: the pair means
        // "children were dropped", and a chain node has no children to drop.
        .with_actual(match derivation.witness_chain() {
            Some(chain) => format!("{chain} [{} retained hop(s)]", derivation.witness_steps()),
            None => format!(
                "no chain is retained [{} retained hop(s)]",
                derivation.witness_steps()
            ),
        }),
    );
    node.push_child(
        RawNode::new(
            ExplanationNodeKind::EffectDerivation,
            ExplanationOutcome::Satisfied,
            "timing_classification",
        )
        .with_expected("when the effect runs relative to the call that declares it")
        .with_actual(format!(
            "timing {}, execution timing {}",
            derivation.timing().unwrap_or("unknown"),
            derivation.execution_timing().unwrap_or("unknown")
        )),
    );
    node.push_child(
        RawNode::new(
            ExplanationNodeKind::CoverageObligation,
            if derivation.coverage() == EXHAUSTIVE_EFFECT_COVERAGE
                && !derivation.witness_truncated()
            {
                ExplanationOutcome::Satisfied
            } else {
                ExplanationOutcome::Unknown
            },
            "effect_coverage",
        )
        .with_expected("the reachable call graph behind this effect was walked in full")
        .with_actual(if derivation.witness_truncated() {
            format!("{}; the retained chain omitted hops", derivation.coverage())
        } else {
            derivation.coverage().to_owned()
        }),
    );
    node
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
/// assertion family cannot reach an unlabelled node. Shared with the typestate
/// adapter, whose projection tags `Source` and `Subject`, so one relationship
/// reads the same in both answers.
pub(super) const fn relationship_label(relationship: PolicyLocationRelationship) -> &'static str {
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
