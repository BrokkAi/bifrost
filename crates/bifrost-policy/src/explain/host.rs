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

use brokk_bifrost_rql::structural::identifier_typos::IdentifierTypoTable;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::packs_document::load_workspace_packs_config_at;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    SemanticModelActivationInput, SemanticModelActivationRead, SemanticModelSetupFailure,
};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, AnalyzerQueryScope, FilesystemProject, Project, WorkspaceAnalyzer,
};

use crate::budget::{PolicyBatchBudget, PolicyBudget};
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::coordinator::{
    PolicyEvaluationInput, activate_owned_policy_workspace, policy_budget_for_workspace,
};
use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use crate::finding_identity::PolicyFindingId;
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::resolved::LoadedPolicy;
use crate::taint_policy::ProductionTaintPolicyEvaluator;
use crate::typestate_policy::ProductionTypestatePolicyEvaluator;

use super::model::{ExplainError, ExplanationGeneration, ExplanationLimits, PolicyExplanation};
use super::near_miss::{NearMissCandidates, PolicyNearMissRanking, rank_near_misses};
use super::why::explain_finding;
use super::why_not::{ExplanationCandidate, explain_candidate};
use super::why_not_flow::{FlowExplanationCandidate, explain_flow_candidate};

/// Which question a host is asking about one policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplanationTarget {
    /// Why does this retained finding exist? The policy is evaluated once and
    /// the finding is looked up in the resulting run.
    Finding(PolicyFindingId),
    /// Why is this candidate not reported? The policy is loaded but not
    /// evaluated; only the bounded candidate-specific plan runs.
    Candidate(ExplanationCandidate),
    /// Why is this flow or taint candidate -- a source position and an
    /// observation position -- not reported? Only the analysis regions that
    /// bind both sites are compiled into a solve (issue 3686).
    FlowCandidate(FlowExplanationCandidate),
}

/// Explain one policy against one workspace.
///
/// `workspace` is the caller's immutable analyzer snapshot when it owns one
/// (MCP, LSP). When it is `None` -- the CLI's case -- a snapshot is built over
/// `root` for the duration of the call, exactly as the coordinator does for a
/// CLI policy run.
///
/// `generation` pins the workspace the answer must be about. `None` answers
/// about whatever the analyzer holds, which is what a caller that has not yet
/// read a generation asks for; the produced document states the generation it
/// was answered under so the next question can pin it.
///
/// # Errors
///
/// - [`ExplainError::PolicyUnavailable`] when the root cannot be opened, the
///   policy cannot be registered, or the policy could not be evaluated. The
///   message is diagnostic text and is never parsed.
/// - [`ExplainError::StaleWorkspaceGeneration`] when `generation` is not the
///   generation the analyzer is serving.
/// - [`ExplainError::AmbiguousPolicySelection`] when `policy_inputs` resolves
///   to more or fewer than one policy.
/// - Everything the chosen adapter can return, including
///   [`ExplainError::ExplanationAdapterUnavailable`] and
///   [`ExplainError::FindingNotFound`].
// Eight necessary inputs, none of them removable: a root, the policy selection,
// the question, the workspace pin, the caller's analyzer and flow state, the
// cancellation token, and the bounds. Folding any of them into a struct would
// only move the list.
#[allow(clippy::too_many_arguments)]
pub fn explain_policy_inputs(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    target: &ExplanationTarget,
    generation: Option<ExplanationGeneration>,
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
) -> Result<PolicyExplanation, ExplainError> {
    explain_policy_inputs_with_semantic_models(
        root,
        policy_inputs,
        target,
        generation,
        workspace,
        None,
        flow_state,
        cancellation,
        limits,
        retention_budget,
    )
}

/// [`explain_policy_inputs`] for a caller that captured the semantic-model
/// activation of its own `workspace` snapshot (the MCP session). `None` makes
/// the host capture it: an owned analyzer is activated, a borrowed one is read.
///
/// # Errors
///
/// Exactly [`explain_policy_inputs`]'s.
#[allow(clippy::too_many_arguments)]
pub fn explain_policy_inputs_with_semantic_models(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    target: &ExplanationTarget,
    generation: Option<ExplanationGeneration>,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic_models: Option<SemanticModelActivationRead>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
) -> Result<PolicyExplanation, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        generation,
        workspace,
        semantic_models,
        flow_state,
        cancellation,
        |policy, context, budget, activation| {
            explain_loaded_policy_under(
                policy, context, target, generation, budget, limits, activation,
            )
        },
        retention_budget,
        None,
    )
}

/// Explain through the same kernel with launch-owned approval, not repo options.
#[allow(clippy::too_many_arguments)]
pub fn explain_policy_inputs_with_host_activation_context(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    target: &ExplanationTarget,
    generation: Option<ExplanationGeneration>,
    limits: &ExplanationLimits,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
    host: &Arc<brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext>,
) -> Result<PolicyExplanation, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        generation,
        None,
        None,
        None,
        None,
        |policy, context, budget, activation| {
            explain_loaded_policy_under(
                policy, context, target, generation, budget, limits, activation,
            )
        },
        retention_budget,
        Some(host),
    )
}

/// Near-miss questions use the same passed approval as evaluation/explanation.
#[allow(clippy::too_many_arguments)]
pub fn rank_policy_near_misses_with_host_activation_context(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    candidates: &NearMissCandidates,
    generation: Option<ExplanationGeneration>,
    limits: &ExplanationLimits,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
    host: &Arc<brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext>,
) -> Result<PolicyNearMissRanking, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        generation,
        None,
        None,
        None,
        None,
        |policy, context, budget, activation| {
            let limits = limits.under_semantic_models(activation.status());
            Ok(
                rank_near_misses(policy, context, candidates, budget, &limits)?
                    .answered_under(ExplanationGeneration::of(context.analyzer)),
            )
        },
        retention_budget,
        Some(host),
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
/// [`ExplainError::PolicyUnavailable`],
/// [`ExplainError::StaleWorkspaceGeneration`] and
/// [`ExplainError::AmbiguousPolicySelection`] exactly as
/// [`explain_policy_inputs`] reports them, plus everything
/// [`rank_near_misses`] can return.
#[allow(clippy::too_many_arguments)]
pub fn rank_policy_near_misses(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    candidates: &NearMissCandidates,
    generation: Option<ExplanationGeneration>,
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
) -> Result<PolicyNearMissRanking, ExplainError> {
    rank_policy_near_misses_with_semantic_models(
        root,
        policy_inputs,
        candidates,
        generation,
        workspace,
        None,
        flow_state,
        cancellation,
        limits,
        retention_budget,
    )
}

/// [`rank_policy_near_misses`] for a caller that captured the semantic-model
/// activation of its own `workspace` snapshot. See
/// [`explain_policy_inputs_with_semantic_models`].
///
/// # Errors
///
/// Exactly [`rank_policy_near_misses`]'s.
#[allow(clippy::too_many_arguments)]
pub fn rank_policy_near_misses_with_semantic_models(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    candidates: &NearMissCandidates,
    generation: Option<ExplanationGeneration>,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic_models: Option<SemanticModelActivationRead>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
) -> Result<PolicyNearMissRanking, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        generation,
        workspace,
        semantic_models,
        flow_state,
        cancellation,
        |policy, context, budget, activation| {
            let limits = limits.under_semantic_models(activation.status());
            Ok(
                rank_near_misses(policy, context, candidates, budget, &limits)?
                    .answered_under(ExplanationGeneration::of(context.analyzer)),
            )
        },
        retention_budget,
        None,
    )
}

/// Resolve a root, register exactly one policy, obtain a workspace snapshot,
/// and hand the loaded policy plus its evaluation context to one question.
///
/// Shared because every host-facing question needs the same three steps and
/// the same refusal of an ambiguous selection.
#[allow(clippy::too_many_arguments)]
fn with_one_policy<T>(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    generation: Option<ExplanationGeneration>,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic_models: Option<SemanticModelActivationRead>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    cancellation: Option<&CancellationToken>,
    answer: impl FnOnce(
        &LoadedPolicy,
        &PolicyEvaluationContext<'_>,
        &mut PolicyBudget,
        &SemanticModelActivationRead,
    ) -> Result<T, ExplainError>,
    retention_budget: &brokk_bifrost_analysis::retention_budget::RetentionBudget,
    approval: Option<&Arc<brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext>>,
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
                WorkspaceAnalyzer::build_persisted_with_budget(
                    project,
                    AnalyzerConfig::default(),
                    retention_budget,
                )
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
    if let Some(host) = approval {
        workspace
            .bind_host_activation_context(Arc::clone(host))
            .map_err(unavailable)?;
    }
    // This owner boundary covers explanations and near-miss questions. The
    // guard drops before `owned`, including on activation/selection errors.
    let _retention = brokk_bifrost_analysis::profiling::retention_scope(
        workspace.retention_budget(),
        "policy_explanation",
        "explain",
    );
    // The earliest point a pinned generation can be checked: the analyzer
    // exists, and nothing after this -- pack activation, registry loading,
    // policy registration, evaluation -- is worth doing for a question about a
    // workspace this one is not.
    ExplanationGeneration::require_current(generation, workspace.analyzer())?;
    let uncancelled = CancellationToken::default();
    let semantic_cancellation = cancellation.unwrap_or(&uncancelled);
    assert!(
        semantic_models.is_none() || owned.is_none(),
        "a caller-supplied activation read describes a caller-supplied workspace"
    );
    // One capture serves both the pin and the status the answer states. A
    // failed activation is reported, never turned into an absent snapshot.
    let activation = match (semantic_models, owned.as_ref()) {
        (Some(read), _) => read,
        (None, Some(owned_workspace)) => {
            owned_activation_read(&root, owned_workspace, semantic_cancellation)
        }
        (None, None) => SemanticModelActivationRead::capture(workspace.analyzer()),
    };
    check_explanation_cancellation(cancellation)?;
    // Pin the captured publication for the whole question. A host publication
    // that races an explanation must not change the model set between its
    // prefix executions or finding re-evaluation.
    let _question_scope =
        super::value_flow_question_scope(workspace.analyzer(), activation.snapshot().cloned())?;
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
        acceptance_hint: None,
        analyzer: workspace.analyzer(),
        workspace: Some(workspace),
        flow_state,
        root_memo: None,
        cancellation,
        cvss_overlays: &[],
        organizational_risk: &[],
        // An explanation re-executes one policy to describe what it did, so
        // it has nothing to reuse and nothing to publish.
        incremental: None,
        // Reproduce an ordinary pack-driven run's typo table, so a
        // misspelled-identifier finding remains explainable (#10386).
        identifier_typos: explanation_identifier_typos(policy)?,
    };
    // The same per-policy budget an ordinary run would use, scaled the same
    // way, so a re-executed prefix is bounded exactly as the original was.
    let mut budget =
        policy_budget_for_workspace(*PolicyBatchBudget::default().per_policy(), Some(workspace));
    check_explanation_cancellation(cancellation)?;
    answer(policy, &context, &mut budget, &activation)
}

/// Activate every semantic source of an analyzer this host owns and reduce the
/// outcome, including setup failures, to one read.
fn owned_activation_read(
    root: &Path,
    owned_workspace: &WorkspaceAnalyzer,
    cancellation: &CancellationToken,
) -> SemanticModelActivationRead {
    let config = match load_workspace_packs_config_at(root) {
        Ok(config) => config,
        Err(error) => {
            return SemanticModelActivationRead::reduce(SemanticModelActivationInput::SetupFailed(
                SemanticModelSetupFailure::PacksDocument(&error),
            ));
        }
    };
    match activate_owned_policy_workspace(root, owned_workspace, config.as_ref(), cancellation) {
        Err(error) => {
            SemanticModelActivationRead::reduce(SemanticModelActivationInput::SetupFailed(
                SemanticModelSetupFailure::Activation(&error),
            ))
        }
        Ok(None) => SemanticModelActivationRead::reduce(SemanticModelActivationInput::Runtime {
            ecosystems: &[],
            runtime: None,
        }),
        Ok(Some(activation)) => {
            SemanticModelActivationRead::reduce(SemanticModelActivationInput::Runtime {
                ecosystems: &activation.outcome.ecosystems,
                runtime: activation.outcome.runtime.as_ref(),
            })
        }
    }
}

/// The catalog typo table an explanation reproduces. A policy that reads it,
/// or that reads every registered catalog, cannot be explained faithfully
/// while what the rules packs supply may be incomplete (#10941).
fn explanation_identifier_typos(
    policy: &LoadedPolicy,
) -> Result<Option<&'static Arc<IdentifierTypoTable>>, ExplainError> {
    if crate::builtin::policy_reads_identifier_typos(policy)
        && let Some(gap) = crate::builtin::catalog_identifier_typos_gap()
    {
        return Err(ExplainError::PolicyUnavailable {
            message: format!(
                "policy `{}` reads identifier typos, but {gap}",
                policy.definition().metadata.id
            ),
        });
    }
    if crate::builtin::policy_reads_any_registered_catalog(policy)
        && let Some(gap) = crate::builtin::catalog_registry_gap()
    {
        return Err(ExplainError::PolicyUnavailable {
            message: format!(
                "policy `{}` reads every registered catalog, but {gap}",
                policy.definition().metadata.id
            ),
        });
    }
    // A catalog that failed to load supplies nothing here, and this policy
    // does not read the table.
    Ok(crate::builtin::catalog_identifier_typos().ok().flatten())
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
/// # The generation is enforced here too
///
/// This is a public boundary in its own right, so it refuses a stale pin on
/// its own evidence rather than trusting a caller to have gone through
/// [`explain_policy_inputs`]. The check is one comparison of a memoized
/// content identity, so the host path paying for it twice costs nothing.
///
/// # Errors
///
/// [`ExplainError::PolicyUnavailable`] when a `why` question could not evaluate
/// the policy, [`ExplainError::StaleWorkspaceGeneration`] when `generation` is
/// not the analyzer's, plus everything the chosen adapter can return.
pub fn explain_loaded_policy(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    target: &ExplanationTarget,
    generation: Option<ExplanationGeneration>,
    budget: &mut PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    explain_loaded_policy_under(
        policy,
        context,
        target,
        generation,
        budget,
        limits,
        &SemanticModelActivationRead::capture(context.analyzer),
    )
}

/// [`explain_loaded_policy`] under one already captured activation, so the
/// host entry point pins and states the same publication.
fn explain_loaded_policy_under(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    target: &ExplanationTarget,
    generation: Option<ExplanationGeneration>,
    budget: &mut PolicyBudget,
    limits: &ExplanationLimits,
    activation: &SemanticModelActivationRead,
) -> Result<PolicyExplanation, ExplainError> {
    ExplanationGeneration::require_current(generation, context.analyzer)?;
    let answered_under = ExplanationGeneration::of(context.analyzer);
    let active_semantic_model_snapshot = activation.snapshot().cloned();
    let limits = limits.under_semantic_models(activation.status());
    let limits = &limits;
    // This public reuse boundary may be called without `with_one_policy`'s
    // host scope. Freeze one publication for every target so candidate prefix
    // executions and finding adapters cannot observe different model sets.
    let _question_scope = if context.workspace.is_some() {
        super::value_flow_question_scope(context.analyzer, active_semantic_model_snapshot.clone())?
    } else {
        AnalyzerQueryScope::with_active_semantic_model_snapshot(
            context.analyzer,
            active_semantic_model_snapshot.clone(),
        )
    };
    match target {
        ExplanationTarget::Finding(finding_id) => {
            let taint = context.workspace.map_or_else(
                ProductionTaintPolicyEvaluator::default,
                |workspace| {
                    ProductionTaintPolicyEvaluator::prepare(
                        context.flow_resources(),
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
            let status = activation.status();
            explain_finding(&run, finding_id, status, limits).map_err(|error| {
                match (error, status.cause()) {
                    // Without models the finding may be absent only because
                    // they did not activate; name that instead of a bare
                    // not-found.
                    (ExplainError::FindingNotFound { finding }, Some(cause)) => {
                        unavailable(format!(
                            "finding {finding} was not found, and semantic models were not \
                             active, so it may exist only with them: {cause}"
                        ))
                    }
                    (error, _) => error,
                }
            })
        }
        ExplanationTarget::Candidate(candidate) => {
            explain_candidate(policy, context, candidate, budget, limits)
        }
        ExplanationTarget::FlowCandidate(candidate) => {
            explain_flow_candidate(policy, context, candidate, budget, limits)
        }
    }
    .map(|explanation| explanation.answered_under(answered_under))
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
            PolicyEvaluationInput::Embedded {
                identity, source, ..
            } => {
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
