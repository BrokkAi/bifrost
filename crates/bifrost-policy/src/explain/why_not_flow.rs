//! `why-not` for a flow or taint policy: one explicit origin and observation
//! pair, answered by the production solver (issue 3686).
//!
//! # The candidate contract
//!
//! A flow or taint finding is a value that enters at one site and is observed
//! at another, so a candidate names both: the **source** position (a flow
//! origin or a taint source) and the **observation** position (a flow
//! observation or a taint sink). Each position is an [`ExplanationCandidate`]
//! (a workspace-relative path and a byte range) and resolves, under the same
//! containment rule a `match` candidate uses, to the innermost site a compiled
//! endpoint of that role binds. The policy, the workspace generation the host
//! pins, and the one semantic-model snapshot frozen for the question complete
//! the identity.
//!
//! # One production route
//!
//! The answer comes from the ordinary taint compiler and solver, narrowed to
//! the analysis regions that bind both sites
//! (`crate::taint_policy::solve_flow_candidate`). A reached candidate is then
//! projected by the ordinary evaluator, so the finding it names is the finding
//! an ordinary run reports, with the same identity and retained witnesses.
//!
//! When the solve is exhaustive and the candidate is not reached, and the
//! candidate regions bind kills, one more pass runs the same route over the
//! policy with its kills removed. A counterfactual path that reaches the
//! observation there, matched to the kills of the first pass by program-point
//! identity, is what names the kill that blocked the candidate. Each pass is
//! bounded by the policy's own budget, and the explanation's execution limit
//! caps the passes at two.
//!
//! # Outcomes
//!
//! The stages render in order: the origin binding, the observation binding,
//! the analysis region, the propagation, and the kill attribution. A stage is
//! `failed` only on exhaustive evidence: every endpoint selector finished, no
//! region was skipped or refused, and the candidate regions' solve reached a
//! fixed point with complete coverage. Anything less is `unknown`, and every
//! limit is published as a typed `boundary:<kind>` child carrying the run's own
//! incomplete reasons: unknown dispatch, a missing or incompatible model, an
//! unsupported flow, cancellation, and an exhausted budget all land there
//! rather than in `failed`.

use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;

use crate::budget::PolicyBudget;
use crate::definition::PolicyAnalysis;
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::finding::{
    PolicyFinding, PolicyFindingEvidence, PolicyIncompleteReason, PolicyRunCompletion,
    PolicySourceLocation,
};
use crate::resolved::{LoadedPolicy, ResolvedEndpointIdentity, ResolvedTaintPolicySpec};
use crate::taint_policy::{
    CandidateBinding, CandidateBoundary, CandidatePass, CandidateSite, CandidateSolve,
    project_candidate_witness, solve_flow_candidate,
};

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationPosition, ExplanationQuestion, ExplanationSubject,
    PolicyExplanation, RawNode, build_explanation,
};
use super::why_flow::{
    certainty_node, completeness_node, endpoint_entry, proof_node, retained_witness_node,
    witness_node,
};
use super::why_not::ExplanationCandidate;

/// One explicit flow or taint candidate: where the tracked value should enter
/// and where it should be observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowExplanationCandidate {
    source: ExplanationCandidate,
    observation: ExplanationCandidate,
}

impl FlowExplanationCandidate {
    /// `source` is the origin (flow) or source (taint) position, and
    /// `observation` the observation (flow) or sink (taint) position.
    pub const fn new(source: ExplanationCandidate, observation: ExplanationCandidate) -> Self {
        Self {
            source,
            observation,
        }
    }
    pub const fn source(&self) -> &ExplanationCandidate {
        &self.source
    }
    pub const fn observation(&self) -> &ExplanationCandidate {
        &self.observation
    }
}

/// The two families' own words for the same stages.
struct Vocabulary {
    root: &'static str,
    source: &'static str,
    observation: &'static str,
    kill: &'static str,
    source_stage: &'static str,
    observation_stage: &'static str,
    attribution_stage: &'static str,
}

const FLOW_VOCABULARY: Vocabulary = Vocabulary {
    root: "flow_candidate",
    source: "origin",
    observation: "observation",
    kill: "kill",
    source_stage: "origin_endpoint",
    observation_stage: "observation_endpoint",
    attribution_stage: "kill_attribution",
};

const TAINT_VOCABULARY: Vocabulary = Vocabulary {
    root: "taint_candidate",
    source: "source",
    observation: "sink",
    kill: "sanitizer",
    source_stage: "source_endpoint",
    observation_stage: "sink_endpoint",
    attribution_stage: "sanitizer_attribution",
};

/// Explain why one explicit flow or taint candidate is, or is not, reported.
///
/// # Errors
///
/// - [`ExplainError::CandidateSourceUnsupported`] for a `match` or
///   `assertion` policy, whose candidate is one position.
/// - [`ExplainError::ExplanationAdapterUnavailable`] for a `typestate` policy.
/// - [`ExplainError::PolicyUnavailable`] when the context carries no
///   workspace analyzer, which the production solver needs, or when the
///   ordinary evaluator cannot project a reached candidate.
/// - [`ExplainError::BudgetExhausted`] when `limits` allow no production pass
///   or cannot hold a root node.
pub fn explain_flow_candidate(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    candidate: &FlowExplanationCandidate,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let analysis_type = policy.definition().analysis.analysis_type();
    let vocabulary = match &policy.definition().analysis {
        PolicyAnalysis::Flow { .. } => &FLOW_VOCABULARY,
        PolicyAnalysis::Taint { .. } => &TAINT_VOCABULARY,
        PolicyAnalysis::Match { .. } | PolicyAnalysis::Assertion { .. } => {
            return Err(ExplainError::CandidateSourceUnsupported { analysis_type });
        }
        PolicyAnalysis::Typestate { .. } => {
            return Err(ExplainError::adapter_unavailable(
                analysis_type,
                ExplanationQuestion::WhyNot,
            ));
        }
    };
    let spec = policy
        .resolved_taint()
        .ok_or_else(|| ExplainError::PolicyUnavailable {
            message: "the loaded policy is missing its resolved taint-shaped specification"
                .to_owned(),
        })?;
    let workspace = context
        .workspace
        .ok_or_else(|| ExplainError::PolicyUnavailable {
            message: "a flow or taint candidate is answered by the production solver, which \
                      needs a workspace analyzer"
                .to_owned(),
        })?;
    if limits.max_prefix_executions() == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::PrefixExecutions,
        });
    }
    // One model publication for the whole question: both passes, and the
    // projection of a reached candidate, read this exact snapshot.
    let snapshot = context.analyzer.active_semantic_model_snapshot();
    let authored = solve_flow_candidate(
        policy,
        spec,
        workspace,
        snapshot.clone(),
        context.cancellation,
        budget,
        candidate,
    );

    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        ExplanationOutcome::Unknown,
        vocabulary.root,
    )
    .with_expected(format!(
        "a value entering at the {} position reaches the {} position without passing a {}, \
         and the policy reports it",
        vocabulary.source, vocabulary.observation, vocabulary.kill
    ))
    .with_location(Some(match &authored.observation {
        CandidateBinding::Bound(sites) => sites[0].location.clone(),
        CandidateBinding::Unbound | CandidateBinding::Unevaluated => {
            PolicySourceLocation::artifact(candidate.observation().path().clone())
        }
    }));

    let (outcome, actual) = if let (CandidateBinding::Unevaluated, CandidateBinding::Unevaluated) =
        (&authored.origin, &authored.observation)
    {
        assert!(
            !authored.selection_gaps.is_empty(),
            "a pass that never reached the candidate's sites states why"
        );
        for gap in &authored.selection_gaps {
            root.push_child(boundary_node(gap));
        }
        (
            ExplanationOutcome::Unknown,
            String::from("the policy could not be compiled into a plan for this candidate"),
        )
    } else {
        let mut stages = Vec::new();
        let source_stage = binding_stage(
            vocabulary.source_stage,
            vocabulary.source,
            &authored.origin,
            &authored.selection_gaps,
            candidate.source(),
        );
        let observation_stage = binding_stage(
            vocabulary.observation_stage,
            vocabulary.observation,
            &authored.observation,
            &authored.selection_gaps,
            candidate.observation(),
        );
        stages.extend(source_stage);
        stages.extend(observation_stage);
        let bound = matches!(authored.origin, CandidateBinding::Bound(_))
            && matches!(authored.observation, CandidateBinding::Bound(_));
        if bound {
            stages.push(region_stage(&authored));
        }
        let mut decided = decided_by(&stages);
        if decided.is_none()
            && let Some(solve) = &authored.solve
        {
            let propagation = propagation_stage(
                policy,
                context,
                &authored,
                solve,
                vocabulary,
                budget,
                snapshot.clone(),
            )?;
            let negative = propagation.outcome == ExplanationOutcome::Failed;
            stages.push(propagation);
            if negative && solve.kill_sites().next().is_some() {
                stages.push(attribution_stage(
                    policy, spec, context, workspace, solve, candidate, vocabulary, budget, limits,
                    snapshot,
                )?);
            }
            decided = decided_by(&stages);
        }
        let outcome = match decided {
            Some(stage) => stage.outcome,
            None => ExplanationOutcome::Satisfied,
        };
        let actual = match decided {
            Some(stage) if stage.outcome == ExplanationOutcome::Failed => {
                format!(
                    "the candidate is not reported: stage {} failed",
                    stage.label
                )
            }
            Some(stage) => format!("the stage {} could not decide the candidate", stage.label),
            None => String::from("the candidate is reported"),
        };
        for stage in stages {
            root.push_child(stage);
        }
        (outcome, actual)
    };
    root.outcome = outcome;
    root.actual = Some(actual);
    build_explanation(
        ExplanationQuestion::WhyNot,
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        analysis_type,
        ExplanationSubject::FlowCandidate {
            source: position(candidate.source()),
            observation: position(candidate.observation()),
        },
        root,
        limits,
    )
}

/// The first stage that is not `satisfied`, in rendering order.
fn decided_by(stages: &[RawNode]) -> Option<&RawNode> {
    // A proven failure anywhere decides the candidate even when an earlier
    // stage is undecided: an origin that is provably unbound cannot be
    // reported whatever the observation's selection says.
    stages
        .iter()
        .find(|stage| stage.outcome == ExplanationOutcome::Failed)
        .or_else(|| {
            stages
                .iter()
                .find(|stage| stage.outcome != ExplanationOutcome::Satisfied)
        })
}

fn position(candidate: &ExplanationCandidate) -> ExplanationPosition {
    ExplanationPosition {
        path: candidate.path().as_str().to_owned(),
        byte_start: candidate.byte_start(),
        byte_end: candidate.byte_end(),
    }
}

/// One typed limit as an `unknown` coverage obligation.
fn boundary_node(boundary: &CandidateBoundary) -> RawNode {
    RawNode::new(
        ExplanationNodeKind::CoverageObligation,
        ExplanationOutcome::Unknown,
        format!("boundary:{}", boundary.kind.label()),
    )
    .with_expected("the analysis covers this stage exhaustively")
    .with_actual(boundary.detail.clone())
    .with_location(boundary.location.clone())
    .with_reasons(boundary.reasons.clone())
}

fn boundary_reasons<'a>(
    boundaries: impl IntoIterator<Item = &'a CandidateBoundary>,
) -> Vec<PolicyIncompleteReason> {
    boundaries
        .into_iter()
        .flat_map(|boundary| boundary.reasons.iter().copied())
        .collect()
}

fn describe_sites(role: &str, sites: &[CandidateSite]) -> String {
    let entries = sites
        .iter()
        .map(|site| format!("`{}`", endpoint_entry(&site.endpoint)))
        .collect::<Vec<_>>()
        .join(", ");
    match sites[0].location.byte_span() {
        Some(span) => format!(
            "{role} endpoint {entries} binds the site at bytes [{}, {})",
            span.start(),
            span.end()
        ),
        None => format!("{role} endpoint {entries} binds a whole-file site"),
    }
}

/// Whether a compiled endpoint of one role binds the candidate's position.
/// `None` when the compile stopped before that role's sites were known and
/// another stage decides the candidate.
fn binding_stage(
    label: &str,
    role: &str,
    binding: &CandidateBinding,
    gaps: &[CandidateBoundary],
    position: &ExplanationCandidate,
) -> Option<RawNode> {
    let expected = format!("a compiled {role} endpoint binds a site covering this position");
    let node = match binding {
        CandidateBinding::Unevaluated => return None,
        CandidateBinding::Bound(sites) => RawNode::new(
            ExplanationNodeKind::SelectorStage,
            ExplanationOutcome::Satisfied,
            label,
        )
        .with_expected(expected)
        .with_actual(describe_sites(role, sites))
        .with_location(Some(sites[0].location.clone())),
        CandidateBinding::Unbound if gaps.is_empty() => RawNode::new(
            ExplanationNodeKind::SelectorStage,
            ExplanationOutcome::Failed,
            label,
        )
        .with_expected(expected)
        .with_actual(format!(
            "no {role} endpoint binds a site covering this position, and every endpoint \
                     selector finished exhaustively"
        ))
        .with_location(Some(PolicySourceLocation::artifact(
            position.path().clone(),
        ))),
        CandidateBinding::Unbound => {
            let mut node = RawNode::new(
                ExplanationNodeKind::SelectorStage,
                ExplanationOutcome::Unknown,
                label,
            )
            .with_expected(expected)
            .with_actual(format!(
                "no {role} endpoint binds a site covering this position, but the \
                         endpoint selection was not exhaustive"
            ))
            .with_location(Some(PolicySourceLocation::artifact(
                position.path().clone(),
            )))
            .with_reasons(boundary_reasons(gaps));
            for gap in gaps {
                node.push_child(boundary_node(gap));
            }
            node
        }
    };
    Some(node)
}

/// Whether a compiled analysis region binds both sites, which is where a flow
/// between them can exist at all.
fn region_stage(pass: &CandidatePass) -> RawNode {
    let expected = "a compiled analysis region contains both endpoint sites";
    if pass.candidate_regions > 0 {
        return RawNode::new(
            ExplanationNodeKind::Derivation,
            ExplanationOutcome::Satisfied,
            "analysis_region",
        )
        .with_expected(expected)
        .with_actual(format!(
            "{} of {} compiled analysis region(s) bind both sites; only those were solved",
            pass.candidate_regions, pass.compiled_regions
        ));
    }
    if pass.selection_gaps.is_empty() {
        return RawNode::new(
            ExplanationNodeKind::Derivation,
            ExplanationOutcome::Failed,
            "analysis_region",
        )
        .with_expected(expected)
        .with_actual(format!(
            "none of {} compiled analysis region(s) binds both sites, and no region was skipped \
             or refused, so no call path connects them",
            pass.compiled_regions
        ));
    }
    let mut node = RawNode::new(
        ExplanationNodeKind::Derivation,
        ExplanationOutcome::Unknown,
        "analysis_region",
    )
    .with_expected(expected)
    .with_actual(format!(
        "none of {} compiled analysis region(s) binds both sites, but the region selection was \
         not exhaustive",
        pass.compiled_regions
    ))
    .with_reasons(boundary_reasons(&pass.selection_gaps));
    for gap in &pass.selection_gaps {
        node.push_child(boundary_node(gap));
    }
    node
}

/// What the solve of the candidate regions established, and whether the
/// candidate was reached.
///
/// A reached candidate is projected by the ordinary evaluator over exactly the
/// candidate regions' payload, and the stage names the finding that
/// projection reports with its retained witnesses: the same finding an
/// ordinary run reports.
fn propagation_stage(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    pass: &CandidatePass,
    solve: &CandidateSolve,
    vocabulary: &Vocabulary,
    budget: &PolicyBudget,
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
) -> Result<RawNode, ExplainError> {
    let expected = format!(
        "the solver reaches the {} from the {} without passing a {}",
        vocabulary.observation, vocabulary.source, vocabulary.kill
    );
    if solve.reached {
        let mut run_budget = *budget;
        let run = DefaultPolicyEvaluator::new()
            .with_taint(&pass.evaluator)
            .with_active_semantic_model_snapshot(snapshot)
            .evaluate(policy, context, &mut run_budget)
            .map_err(|error| ExplainError::PolicyUnavailable {
                message: format!("the reached candidate could not be projected: {error:?}"),
            })?;
        let (CandidateBinding::Bound(origin_sites), CandidateBinding::Bound(observation_sites)) =
            (&pass.origin, &pass.observation)
        else {
            unreachable!("a solved candidate has both sites bound");
        };
        let finding = run.findings().iter().find(|finding| {
            finding.primary() == &observation_sites[0].location
                && reported_origin(finding).is_some_and(|endpoint| {
                    origin_sites.iter().any(|site| &site.endpoint == endpoint)
                })
        });
        let Some(finding) = finding else {
            let complete = matches!(run.completion(), PolicyRunCompletion::Complete);
            let mut node = RawNode::new(
                ExplanationNodeKind::Derivation,
                if complete {
                    ExplanationOutcome::Failed
                } else {
                    ExplanationOutcome::Unknown
                },
                "propagation",
            )
            .with_expected(expected)
            .with_actual(format!(
                "the solver reached the {} from the {}, but the policy's projection reports no \
                 finding for this pair: no label the value carries there is one the {} endpoint \
                 mints and the {} endpoint accepts",
                vocabulary.observation,
                vocabulary.source,
                vocabulary.source,
                vocabulary.observation
            ));
            if let PolicyRunCompletion::Inconclusive { reasons, .. } = run.completion() {
                node = node.with_reasons(reasons.clone());
            }
            return Ok(node);
        };
        let mut node = RawNode::new(
            ExplanationNodeKind::Derivation,
            ExplanationOutcome::Satisfied,
            "propagation",
        )
        .with_expected(expected)
        .with_actual(format!(
            "the solver reaches the {} from the {}; the policy reports finding {}",
            vocabulary.observation,
            vocabulary.source,
            finding.id()
        ))
        .with_source_truncation(
            finding.witnesses_truncated(),
            finding.omitted_witnesses_lower_bound(),
        );
        node.push_child(
            RawNode::new(
                ExplanationNodeKind::SourceFact,
                ExplanationOutcome::Satisfied,
                "reported_finding",
            )
            .with_expected("the finding an ordinary run reports for this candidate")
            .with_actual(format!("finding {}: {}", finding.id(), finding.message()))
            .with_location(Some(finding.primary().clone())),
        );
        for witness in finding.witnesses() {
            node.push_child(witness_node(witness));
        }
        node.push_child(certainty_node(finding));
        node.push_child(proof_node(finding.proof()));
        node.push_child(retained_witness_node(finding));
        node.push_child(completeness_node(finding));
        return Ok(node);
    }
    // The negative needs both halves of the coverage: the candidate regions'
    // solve, and the compile that built them. A selector that did not finish
    // can miss a declared transform or model inside these very regions, and
    // under optimistic call modeling that hides a flow.
    let gaps = pass
        .selection_gaps
        .iter()
        .chain(&solve.boundaries)
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        let mut node = RawNode::new(
            ExplanationNodeKind::Derivation,
            ExplanationOutcome::Failed,
            "propagation",
        )
        .with_expected(expected)
        .with_actual(format!(
            "no path from the {} reaches the {} in {} solved analysis region(s)",
            vocabulary.source, vocabulary.observation, pass.candidate_regions
        ));
        node.push_child(
            RawNode::new(
                ExplanationNodeKind::CoverageObligation,
                ExplanationOutcome::Satisfied,
                "region_coverage",
            )
            .with_expected("the compile and the candidate regions' solve are exhaustive")
            .with_actual(if solve.proven_by_summary {
                "every endpoint selector finished, no region was skipped or refused, and the \
                 solve reached a fixed point whose open boundaries are closed by \
                 authored-complete external summaries"
            } else {
                "every endpoint selector finished, no region was skipped or refused, and the \
                 solve reached a fixed point with complete coverage"
            }),
        );
        return Ok(node);
    }
    let mut node = RawNode::new(
        ExplanationNodeKind::Derivation,
        ExplanationOutcome::Unknown,
        "propagation",
    )
    .with_expected(expected)
    .with_actual(format!(
        "no retained path from the {} reaches the {}, but the compile or the solve of the \
         candidate regions was not exhaustive",
        vocabulary.source, vocabulary.observation
    ))
    .with_reasons(boundary_reasons(gaps.iter().copied()));
    for boundary in gaps {
        node.push_child(boundary_node(boundary));
    }
    Ok(node)
}

/// The origin endpoint a projected flow or taint finding reports.
fn reported_origin(finding: &PolicyFinding) -> Option<&ResolvedEndpointIdentity> {
    match finding.evidence() {
        PolicyFindingEvidence::Flow { evidence } => Some(evidence.origin_endpoint()),
        PolicyFindingEvidence::Taint { evidence } => Some(evidence.source_endpoint()),
        _ => None,
    }
}

/// Which declared kill blocks the candidate, decided by the same production
/// route over the policy with its kills removed.
#[allow(clippy::too_many_arguments)]
fn attribution_stage(
    policy: &LoadedPolicy,
    spec: &ResolvedTaintPolicySpec,
    context: &PolicyEvaluationContext<'_>,
    workspace: &WorkspaceAnalyzer,
    authored_solve: &CandidateSolve,
    candidate: &FlowExplanationCandidate,
    vocabulary: &Vocabulary,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
) -> Result<RawNode, ExplainError> {
    let label = vocabulary.attribution_stage;
    let expected = format!(
        "with the policy's {}s removed, the same route reaches the {}, and every such path \
         passes a declared {}",
        vocabulary.kill, vocabulary.observation, vocabulary.kill
    );
    if limits.max_prefix_executions() < 2 {
        return Ok(RawNode::new(
            ExplanationNodeKind::Derivation,
            ExplanationOutcome::Unknown,
            label,
        )
        .with_expected(expected)
        .with_actual(
            "the explanation's execution limit allowed one production pass, so the \
                     counterfactual pass did not run",
        )
        .with_reasons(vec![PolicyIncompleteReason::ReportRetentionBudget]));
    }
    let mut relaxed_spec = spec.clone();
    relaxed_spec.sanitizers.clear();
    let relaxed = solve_flow_candidate(
        policy,
        &relaxed_spec,
        workspace,
        snapshot,
        context.cancellation,
        budget,
        candidate,
    );
    let Some(relaxed_solve) = relaxed.solve.as_ref().filter(|solve| solve.reached) else {
        let boundaries = relaxed
            .selection_gaps
            .iter()
            .chain(
                relaxed
                    .solve
                    .iter()
                    .flat_map(|solve| solve.boundaries.iter()),
            )
            .collect::<Vec<_>>();
        let unreached_exhaustively = relaxed.solve.is_some() && boundaries.is_empty();
        let mut node = RawNode::new(
            ExplanationNodeKind::Derivation,
            if unreached_exhaustively {
                ExplanationOutcome::Failed
            } else {
                ExplanationOutcome::Unknown
            },
            label,
        )
        .with_expected(expected)
        .with_actual(if unreached_exhaustively {
            format!(
                "with the {}s removed the {} is still unreached, so the absence does not depend \
                 on a declared {}",
                vocabulary.kill, vocabulary.observation, vocabulary.kill
            )
        } else {
            String::from("the counterfactual pass did not decide the candidate")
        })
        .with_reasons(boundary_reasons(boundaries.iter().copied()));
        for boundary in boundaries {
            node.push_child(boundary_node(boundary));
        }
        return Ok(node);
    };

    let mut kills = Vec::<&CandidateSite>::new();
    let mut unattributed = 0usize;
    let mut paths = Vec::new();
    for (index, witness) in relaxed_solve
        .witnesses
        .iter()
        .take(budget.max_witnesses_per_finding())
        .enumerate()
    {
        let on_path = authored_solve.kills_on(witness);
        if on_path.is_empty() {
            unattributed += 1;
        }
        for kill in on_path {
            if !kills.contains(&kill) {
                kills.push(kill);
            }
        }
        // Several solver findings at one observation can retain the same
        // path; it is published once.
        if let Some(projected) = project_candidate_witness(workspace, witness, index, budget)
            .map_err(|message| ExplainError::PolicyUnavailable { message })?
            && !paths
                .iter()
                .any(|path: &crate::finding::BoundedWitness| path.steps() == projected.steps())
        {
            paths.push(projected);
        }
    }
    let omitted_paths = relaxed_solve
        .witnesses
        .len()
        .saturating_sub(budget.max_witnesses_per_finding());
    let attributed = unattributed == 0 && !kills.is_empty();
    let mut node = RawNode::new(
        ExplanationNodeKind::Derivation,
        if attributed {
            ExplanationOutcome::Satisfied
        } else {
            ExplanationOutcome::Unknown
        },
        label,
    )
    .with_expected(expected)
    .with_actual(if attributed {
        format!(
            "with the {}s removed the same route reaches the {}; each of {} retained path(s) \
             passes a {} the policy declares",
            vocabulary.kill,
            vocabulary.observation,
            relaxed_solve
                .witnesses
                .len()
                .min(budget.max_witnesses_per_finding()),
            vocabulary.kill
        )
    } else {
        format!(
            "with the {}s removed the same route reaches the {}, but {unattributed} retained \
             path(s) pass no bound {} site",
            vocabulary.kill, vocabulary.observation, vocabulary.kill
        )
    })
    .with_source_truncation(
        omitted_paths > 0,
        u64::try_from(omitted_paths).unwrap_or(u64::MAX),
    );
    if !attributed {
        node = node.with_reasons(vec![PolicyIncompleteReason::CapabilityIncomplete]);
    }
    for kill in kills {
        node.push_child(
            RawNode::new(
                ExplanationNodeKind::SourceFact,
                ExplanationOutcome::Satisfied,
                vocabulary.kill,
            )
            .with_expected(format!(
                "a declared {} clears the tracked value on the path",
                vocabulary.kill
            ))
            .with_actual(format!(
                "{} `{}` is bound at this program point, which the counterfactual path passes",
                vocabulary.kill,
                endpoint_entry(&kill.endpoint)
            ))
            .with_location(Some(kill.location.clone())),
        );
    }
    for path in &paths {
        let mut path_node = witness_node(path);
        path_node.label = String::from("counterfactual_path");
        node.push_child(path_node);
    }
    Ok(node)
}
