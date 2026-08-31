//! The host-facing entry point: load one policy, then answer `why` or
//! `why-not` about it.
//!
//! MCP and the CLI both need the same three steps -- resolve a workspace root,
//! register exactly one policy, and either evaluate it (for `why`) or hold it
//! loaded (for `why-not`) -- so they live here rather than being written twice.
//!
//! # One policy, by construction
//!
//! An explanation is about one policy: a finding identity belongs to one run,
//! and a candidate is tested against one plan. A selection that resolves to
//! more than one policy is refused with
//! [`ExplainError::AmbiguousPolicySelection`] rather than silently explained
//! against whichever policy sorted first.
//!
//! # Not a gate
//!
//! Nothing here loads suppressions, scopes, baselines, or a diff base, and
//! nothing here computes an exit status. An explanation is a query about a
//! policy, not a verdict about a workspace; the gating surfaces stay in the
//! coordinator.

use std::path::Path;
use std::sync::Arc;

#[cfg(test)]
use std::cell::Cell;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::packs_document::load_workspace_packs_config_at;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerQueryScope, FilesystemProject, Project, WorkspaceAnalyzer,
};

use crate::budget::{PolicyBatchBudget, PolicyBudget};
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::coordinator::{
    PolicyEvaluationInput, activate_owned_policy_workspace, owned_policy_analyzer_config,
    policy_budget_for_workspace, ready_policy_semantic_model_snapshot,
};
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::finding_identity::PolicyFindingId;
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::resolved::LoadedPolicy;
use crate::taint_policy::ProductionTaintPolicyEvaluator;
use crate::typestate_policy::ProductionTypestatePolicyEvaluator;

use super::model::{ExplainError, ExplanationLimits, PolicyExplanation};
use super::near_miss::{NearMissCandidates, PolicyNearMissRanking, rank_near_misses};
use super::why::explain_finding;
use super::why_not::{ExplanationCandidate, explain_candidate};

#[cfg(test)]
thread_local! {
    static OWNED_WORKSPACE_BUILD_COUNT: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn owned_workspace_build_count_for_test() -> u64 {
    OWNED_WORKSPACE_BUILD_COUNT.with(Cell::get)
}

/// Which question a host is asking about one policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplanationTarget {
    /// Why does this retained finding exist? The policy is evaluated once and
    /// the finding is looked up in the resulting run.
    Finding(PolicyFindingId),
    /// Why is this candidate not reported? The policy is loaded but not
    /// evaluated; only the bounded candidate-specific plan runs.
    Candidate(ExplanationCandidate),
}

/// Explain one policy against one workspace.
///
/// `workspace` is the caller's immutable analyzer snapshot when it owns one
/// (MCP, LSP). When it is `None` -- the CLI's case -- a snapshot is built over
/// `root` for the duration of the call, exactly as the coordinator does for a
/// CLI policy run.
///
/// # Errors
///
/// - [`ExplainError::PolicyUnavailable`] when the root cannot be opened, the
///   policy cannot be registered, or the policy could not be evaluated. The
///   message is diagnostic text and is never parsed.
/// - [`ExplainError::AmbiguousPolicySelection`] when `policy_inputs` resolves
///   to more or fewer than one policy.
/// - Everything the chosen adapter can return, including
///   [`ExplainError::ExplanationAdapterUnavailable`] and
///   [`ExplainError::FindingNotFound`].
pub fn explain_policy_inputs(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    target: &ExplanationTarget,
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        workspace,
        flow_state,
        cancellation,
        |policy, context, budget| explain_loaded_policy(policy, context, target, budget, limits),
    )
}

/// Rank the subjects that came closest to satisfying one policy.
///
/// The workspace, registry, and budget handling are exactly
/// [`explain_policy_inputs`]'s. Only the question differs: a ranking is over a
/// bounded candidate *set*, so it returns the sibling
/// [`PolicyNearMissRanking`] document rather than a node tree.
///
/// # Errors
///
/// [`ExplainError::PolicyUnavailable`] and
/// [`ExplainError::AmbiguousPolicySelection`] exactly as
/// [`explain_policy_inputs`] reports them, plus everything
/// [`rank_near_misses`] can return.
pub fn rank_policy_near_misses(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    candidates: &NearMissCandidates,
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
) -> Result<PolicyNearMissRanking, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        workspace,
        flow_state,
        cancellation,
        |policy, context, budget| rank_near_misses(policy, context, candidates, budget, limits),
    )
}

/// Resolve a root, register exactly one policy, obtain a workspace snapshot,
/// and hand the loaded policy plus its evaluation context to one question.
///
/// Shared because every host-facing question needs the same three steps and
/// the same refusal of an ambiguous selection.
fn with_one_policy<T>(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    answer: impl FnOnce(
        &LoadedPolicy,
        &PolicyEvaluationContext<'_>,
        &mut PolicyBudget,
    ) -> Result<T, ExplainError>,
) -> Result<T, ExplainError> {
    let root = root.canonicalize().map_err(|error| {
        unavailable(format!(
            "failed to resolve the policy workspace root {}: {error}",
            root.display()
        ))
    })?;
    check_explanation_cancellation(cancellation)?;
    if policy_inputs.is_empty() {
        return Err(ExplainError::AmbiguousPolicySelection { selected: 0 });
    }
    let owned = match workspace {
        Some(_) => None,
        None => {
            #[cfg(test)]
            OWNED_WORKSPACE_BUILD_COUNT.with(|count| count.set(count.get() + 1));
            let project = FilesystemProject::new(&root).map_err(|error| {
                unavailable(format!(
                    "failed to construct the analyzer project {}: {error}",
                    root.display()
                ))
            })?;
            let project: Arc<dyn Project> = Arc::new(project);
            // Persisted for the same reason the coordinator's fallback is: an
            // explanation over a live root should read the cache the ordinary
            // run already warmed rather than re-parse the workspace.
            Some(
                WorkspaceAnalyzer::build_persisted(project, owned_policy_analyzer_config())
                    .map_err(|error| {
                        unavailable(format!(
                            "failed to build the analyzer workspace at {}: {error}",
                            root.display()
                        ))
                    })?,
            )
        }
    };
    let workspace = workspace
        .or(owned.as_ref())
        .expect("either the caller supplied a workspace or one was built");
    let uncancelled = CancellationToken::default();
    let semantic_cancellation = cancellation.unwrap_or(&uncancelled);
    let workspace_activation = match owned.as_ref() {
        Some(owned_workspace) => {
            match load_workspace_packs_config_at(&root) {
                // Ordinary evaluation diagnoses a malformed document and then
                // evaluates without any semantic publication. An explanation
                // must still be able to recover a finding retained by that
                // unreliable run.
                Err(_) => None,
                Ok(config) => {
                    // Activation-construction failures have the same normal-run
                    // recovery: diagnose there, and explain here under a pinned
                    // absence rather than changing which findings are reachable.
                    activate_owned_policy_workspace(
                        &root,
                        owned_workspace,
                        config.as_ref(),
                        semantic_cancellation,
                    )
                    .unwrap_or_default()
                }
            }
        }
        None => None,
    };
    check_explanation_cancellation(cancellation)?;
    let active_semantic_model_snapshot = match owned.as_ref() {
        Some(_) => ready_policy_semantic_model_snapshot(workspace_activation.as_ref()),
        None => workspace.analyzer().active_semantic_model_snapshot(),
    };
    // Pin both a successful activation and a deliberate absence for the whole
    // question. A host publication that races an explanation must not change
    // the model set between its prefix executions or finding re-evaluation.
    let _semantic_model_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        workspace.analyzer(),
        active_semantic_model_snapshot,
    );
    // Normal evaluation resolves qualified policy locators only after the
    // analyzer and semantic publication are ready. Explanation must cross the
    // same loaded-policy boundary or an otherwise runnable policy can fail here
    // solely because the host omitted its analyzer.
    let mut registry = open_registry(&root)?;
    register_inputs(
        &mut registry,
        policy_inputs,
        workspace.analyzer(),
        cancellation,
    )?;
    check_explanation_cancellation(cancellation)?;
    let selected = registry.policies().len();
    if selected != 1 {
        return Err(ExplainError::AmbiguousPolicySelection { selected });
    }
    let policy = registry
        .policies()
        .next()
        .expect("a registry holding one policy yields it");
    let owned_flow_state = flow_state
        .is_none()
        .then(brokk_bifrost_flow::FlowWorkspaceState::new);
    let flow_state = flow_state
        .or(owned_flow_state.as_ref())
        .expect("every explanation owns reusable flow state");
    let context = PolicyEvaluationContext {
        analyzer: workspace.analyzer(),
        workspace: Some(workspace),
        flow_state,
        cancellation,
        cvss_overlays: &[],
        organizational_risk: &[],
    };
    // The same per-policy budget an ordinary run would use, scaled the same
    // way, so a re-executed prefix is bounded exactly as the original was.
    let mut budget =
        policy_budget_for_workspace(*PolicyBatchBudget::default().per_policy(), Some(workspace));
    check_explanation_cancellation(cancellation)?;
    answer(policy, &context, &mut budget)
}

/// Answer one explanation question about an already-loaded policy.
///
/// Split out so a host that already owns a registry and an evaluation context
/// -- and a test -- can reuse the dispatch without re-opening a workspace.
///
/// # The `why` evaluation is the ordinary one
///
/// A `why` question needs the run its finding came from, so it evaluates the
/// policy with the same evaluator an ordinary run uses, production taint and
/// typestate adapters installed. Without them a taint, flow or typestate
/// policy would report `unsupported` here and every one of its findings would
/// be unfindable -- an explanation surface that silently disagreed with the
/// report it exists to explain.
///
/// The host entry point activates every semantic source for an analyzer it
/// owns, or pins the active snapshot of a caller-owned analyzer. This public
/// dispatch boundary also freezes that selected publication for both targets.
/// The snapshot reaches selector queries and every production evaluator adapter,
/// so a model-backed finding is re-evaluated under the same model authority as
/// an ordinary policy run.
///
/// # Errors
///
/// [`ExplainError::PolicyUnavailable`] when a `why` question could not evaluate
/// the policy, plus everything the chosen adapter can return.
pub fn explain_loaded_policy(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    target: &ExplanationTarget,
    budget: &mut PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    let active_semantic_model_snapshot = context.analyzer.active_semantic_model_snapshot();
    // This public reuse boundary may be called without `with_one_policy`'s
    // host scope. Freeze one publication for every target so candidate prefix
    // executions and finding adapters cannot observe different model sets.
    let _semantic_model_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        context.analyzer,
        active_semantic_model_snapshot.clone(),
    );
    match target {
        ExplanationTarget::Finding(finding_id) => {
            let taint = context.workspace.map_or_else(
                ProductionTaintPolicyEvaluator::default,
                |workspace| {
                    ProductionTaintPolicyEvaluator::prepare(
                        std::iter::once(policy),
                        workspace,
                        Ok(active_semantic_model_snapshot.clone()),
                        context.cancellation,
                        budget,
                    )
                },
            );
            let typestate = ProductionTypestatePolicyEvaluator::with_active_semantic_model_snapshot(
                active_semantic_model_snapshot.clone(),
            );
            let run = DefaultPolicyEvaluator::new()
                .with_taint(&taint)
                .with_typestate(&typestate)
                .with_active_semantic_model_snapshot(active_semantic_model_snapshot)
                .evaluate(policy, context, budget)
                .map_err(|error| {
                    unavailable(format!("the policy could not be evaluated: {error:?}"))
                })?;
            explain_finding(&run, finding_id, limits)
        }
        ExplanationTarget::Candidate(candidate) => {
            explain_candidate(policy, context, candidate, budget, limits)
        }
    }
}

fn open_registry(root: &Path) -> Result<PolicyRegistry, ExplainError> {
    let catalogs = Arc::new(
        TaintCatalogRegistry::new_for_workspace(
            root.to_path_buf(),
            CatalogRegistryLimits::default(),
        )
        .map_err(|error| {
            unavailable(format!(
                "failed to initialize the policy catalog registry: {error}"
            ))
        })?,
    );
    PolicyRegistry::new_for_workspace(
        root.to_path_buf(),
        catalogs,
        PolicyRegistryLimits::default(),
    )
    .map_err(|error| unavailable(format!("failed to initialize the policy registry: {error}")))
}

fn register_inputs(
    registry: &mut PolicyRegistry,
    policy_inputs: &[PolicyEvaluationInput],
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> Result<(), ExplainError> {
    for input in policy_inputs {
        check_explanation_cancellation(cancellation)?;
        match input {
            PolicyEvaluationInput::WorkspaceFile(path) => {
                registry
                    .load_policy_path_with_analyzer(path, analyzer)
                    .map_err(|error| {
                        unavailable(format!(
                            "failed to load the policy file {}: {error}",
                            path.display()
                        ))
                    })?;
            }
            PolicyEvaluationInput::Embedded { identity, source } => {
                registry
                    .register_policy_bytes_with_analyzer(
                        identity.clone(),
                        source.as_bytes(),
                        analyzer,
                    )
                    .map_err(|error| {
                        unavailable(format!("failed to register a policy source: {error}"))
                    })?;
            }
        }
    }
    Ok(())
}

/// Match the coordinator's front-door treatment of explicit cancellation.
///
/// A timeout is not an ordinary cancellation: normal evaluation preserves it
/// as a structured incomplete outcome, so the explanation adapters retain
/// their existing bounded-query handling for that case.
fn check_explanation_cancellation(
    cancellation: Option<&CancellationToken>,
) -> Result<(), ExplainError> {
    let Some(cancellation) = cancellation else {
        return Ok(());
    };
    if !cancellation.is_cancelled() || cancellation.is_timed_out() {
        return Ok(());
    }
    Err(unavailable("policy explanation cancelled".to_string()))
}

fn unavailable(message: String) -> ExplainError {
    ExplainError::PolicyUnavailable { message }
}
