//! Shared, protocol-neutral execution for code-intelligence requests.
//!
//! MCP and LSP own different transport and workspace-lifecycle concerns: MCP
//! owns watcher-backed snapshots and response rendering, while LSP owns editor
//! overlays, request workers, and progress reporting. Both hosts execute the
//! same structural queries and RQL policies against a caller-owned workspace.
//! This module is the typed boundary for that common work. It deliberately
//! knows nothing about JSON-RPC, LSP types, MCP renderers, or host state.

use crate::CancellationToken;
use crate::analyzer::WorkspaceAnalyzer;
use crate::policy::{
    PolicyBatchOutcome, PolicyCoordinatorError, PolicyEvaluationInput, PolicyEvaluationOptions,
    PolicyHostActivationContext, PolicySourceIdentity, PolicySuppressionPreflight,
    evaluate_policy_inputs_with_analyzer, evaluate_policy_inputs_with_analyzer_and_host_activation,
    evaluate_policy_inputs_with_analyzer_and_suppression_preflight,
    evaluate_policy_inputs_with_analyzer_and_suppression_preflight_and_host_activation,
    evaluate_policy_source, evaluate_policy_source_with_host_activation,
};
use brokk_bifrost_flow::FlowWorkspaceState;
use brokk_bifrost_rql::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryResponse, ProtocolRegistrationSet,
    TaintResultRegistrationSet, ValueFlowPlanRegistrationSet,
    execute_workspace_request_with_all_analysis_registrations,
    execute_workspace_request_with_analysis_registrations,
    execute_workspace_request_with_cancellation, execute_workspace_request_with_limits,
    execute_workspace_request_with_registrations_and_limits,
};
use std::path::Path;

/// Executes typed code-intelligence requests against one caller-owned workspace.
///
/// Construction borrows rather than owns the workspace so hosts retain their
/// lifecycle semantics. In particular, an LSP runtime continues to observe its
/// overlay project, and an MCP runtime continues to use its watcher-refreshed
/// snapshot.
pub struct CodeIntelligenceRuntime<'a> {
    workspace: &'a WorkspaceAnalyzer,
    flow_state: &'a FlowWorkspaceState,
    cancellation: Option<&'a CancellationToken>,
    host_activation: Option<PolicyHostActivationContext<'a>>,
}

impl<'a> CodeIntelligenceRuntime<'a> {
    pub const fn new(
        workspace: &'a WorkspaceAnalyzer,
        flow_state: &'a FlowWorkspaceState,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            workspace,
            flow_state,
            cancellation,
            host_activation: None,
        }
    }

    /// Borrow activation state completed by the host for this workspace
    /// snapshot. Policy evaluation attaches its review without activating
    /// semantic packs again.
    pub fn with_host_activation_context(
        mut self,
        host_activation: PolicyHostActivationContext<'a>,
    ) -> Self {
        self.host_activation = Some(host_activation);
        self
    }

    /// Execute a structural query without host-specific protocol registrations.
    pub fn execute_query(
        &self,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
    ) -> CodeQueryResponse {
        match self.cancellation {
            Some(cancellation) => execute_workspace_request_with_cancellation(
                self.workspace,
                self.flow_state,
                query,
                limits,
                cancellation,
            ),
            None => execute_workspace_request_with_limits(
                self.workspace,
                self.flow_state,
                query,
                limits,
            ),
        }
    }

    /// Execute a query with caller-owned typestate registrations and summaries.
    ///
    /// Long-lived hosts that cache production typestate summaries pass the
    /// workspace's shared repository handle here. That handle is semantic
    /// execution context, not an MCP concern, so it belongs at this boundary.
    pub fn execute_query_with_registrations(
        &self,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
    ) -> CodeQueryResponse {
        execute_workspace_request_with_registrations_and_limits(
            self.workspace,
            self.flow_state,
            workspace_generation,
            registrations,
            query,
            limits,
            self.cancellation,
        )
    }

    /// Execute a query with caller-owned typestate and value-flow registrations.
    pub fn execute_query_with_analysis_registrations(
        &self,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        value_flow_registrations: &ValueFlowPlanRegistrationSet,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
    ) -> CodeQueryResponse {
        execute_workspace_request_with_analysis_registrations(
            self.workspace,
            self.flow_state,
            workspace_generation,
            registrations,
            value_flow_registrations,
            query,
            limits,
            self.cancellation,
        )
    }

    /// Execute a query with every caller-owned immutable analysis registration.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_query_with_all_analysis_registrations(
        &self,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        value_flow_registrations: &ValueFlowPlanRegistrationSet,
        taint_registrations: &TaintResultRegistrationSet,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
    ) -> CodeQueryResponse {
        execute_workspace_request_with_all_analysis_registrations(
            self.workspace,
            self.flow_state,
            workspace_generation,
            registrations,
            value_flow_registrations,
            taint_registrations,
            query,
            limits,
            self.cancellation,
        )
    }

    /// Evaluate a mixed set of workspace-backed and embedded RQL policies.
    pub fn evaluate_policy_inputs(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
        match self.host_activation {
            Some(host_activation) => evaluate_policy_inputs_with_analyzer_and_host_activation(
                root,
                policy_inputs,
                self.workspace,
                self.flow_state,
                options,
                host_activation,
                self.cancellation,
            ),
            None => evaluate_policy_inputs_with_analyzer(
                root,
                policy_inputs,
                self.workspace,
                self.flow_state,
                options,
                self.cancellation,
            ),
        }
    }

    /// Evaluate policies using suppression configuration already validated by
    /// the host before it waited for workspace readiness.
    pub fn evaluate_policy_inputs_with_suppression_preflight(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
        suppression_preflight: PolicySuppressionPreflight,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
        match self.host_activation {
            Some(host_activation) => {
                evaluate_policy_inputs_with_analyzer_and_suppression_preflight_and_host_activation(
                    root,
                    policy_inputs,
                    self.workspace,
                    self.flow_state,
                    options,
                    suppression_preflight,
                    host_activation,
                    self.cancellation,
                )
            }
            None => evaluate_policy_inputs_with_analyzer_and_suppression_preflight(
                root,
                policy_inputs,
                self.workspace,
                self.flow_state,
                options,
                suppression_preflight,
                self.cancellation,
            ),
        }
    }

    /// Evaluate an editor-provided RQL policy source against this workspace.
    pub fn evaluate_policy_source(
        &self,
        root: &Path,
        source_identity: PolicySourceIdentity,
        source: &str,
        options: &PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
        match self.host_activation {
            Some(host_activation) => evaluate_policy_source_with_host_activation(
                root,
                source_identity,
                source,
                self.workspace,
                self.flow_state,
                options,
                host_activation,
                self.cancellation,
            ),
            None => evaluate_policy_source(
                root,
                source_identity,
                source,
                self.workspace,
                self.flow_state,
                options,
                self.cancellation,
            ),
        }
    }
}
