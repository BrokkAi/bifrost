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

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
};

use crate::budget::{PolicyBatchBudget, PolicyBudget};
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::coordinator::PolicyEvaluationInput;
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
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        workspace,
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
    cancellation: Option<&CancellationToken>,
    limits: &ExplanationLimits,
) -> Result<PolicyNearMissRanking, ExplainError> {
    with_one_policy(
        root,
        policy_inputs,
        workspace,
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
    let mut registry = open_registry(&root)?;
    register_inputs(&mut registry, policy_inputs)?;
    let selected = registry.policies().len();
    if selected != 1 {
        return Err(ExplainError::AmbiguousPolicySelection { selected });
    }
    let policy = registry
        .policies()
        .next()
        .expect("a registry holding one policy yields it");

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
            Some(
                WorkspaceAnalyzer::build_ephemeral(project, AnalyzerConfig::default())
                    .expect("ephemeral workspace should build"),
            )
        }
    };
    let workspace = workspace
        .or(owned.as_ref())
        .expect("either the caller supplied a workspace or one was built");
    let context = PolicyEvaluationContext {
        analyzer: workspace.analyzer(),
        workspace: Some(workspace),
        cancellation,
        cvss_overlays: &[],
        organizational_risk: &[],
    };
    // The same per-policy budget an ordinary run would use, scaled the same
    // way, so a re-executed prefix is bounded exactly as the original was.
    let mut budget = PolicyBatchBudget::default().per_policy().to_owned();
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
/// What it does not do is activate semantic-model packs: activation belongs to
/// the host that owns the analyzer's lifecycle, and re-activating here would
/// race it. A finding that exists only because an activated pack modeled a
/// call is therefore reported as [`ExplainError::FindingNotFound`] rather than
/// explained from a differently-modeled run.
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
    match target {
        ExplanationTarget::Finding(finding_id) => {
            let taint = context.workspace.map_or_else(
                ProductionTaintPolicyEvaluator::default,
                |workspace| {
                    ProductionTaintPolicyEvaluator::prepare(
                        std::iter::once(policy),
                        workspace,
                        Ok(None),
                        context.cancellation,
                        budget,
                    )
                },
            );
            let typestate = ProductionTypestatePolicyEvaluator::default();
            let run = DefaultPolicyEvaluator::new()
                .with_taint(&taint)
                .with_typestate(&typestate)
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
) -> Result<(), ExplainError> {
    for input in policy_inputs {
        match input {
            PolicyEvaluationInput::WorkspaceFile(path) => {
                registry.load_policy_path(path).map_err(|error| {
                    unavailable(format!(
                        "failed to load the policy file {}: {error}",
                        path.display()
                    ))
                })?;
            }
            PolicyEvaluationInput::Embedded { identity, source } => {
                registry
                    .register_policy_bytes(identity.clone(), source.as_bytes())
                    .map_err(|error| {
                        unavailable(format!("failed to register a policy source: {error}"))
                    })?;
            }
        }
    }
    Ok(())
}

fn unavailable(message: String) -> ExplainError {
    ExplainError::PolicyUnavailable { message }
}
