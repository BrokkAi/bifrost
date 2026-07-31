//! Shared, protocol-neutral execution for code-intelligence requests.
//!
//! MCP and LSP own different transport and workspace-lifecycle concerns: MCP
//! owns watcher-backed snapshots and response rendering, while LSP owns editor
//! overlays, request workers, and progress reporting. Both hosts execute the
//! same structural queries and RQL policies against a caller-owned workspace.
//! This module is the typed boundary for that common work. It deliberately
//! knows nothing about JSON-RPC, LSP types, MCP renderers, or host state.

use std::path::Path;

use crate::CancellationToken;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::policy::{
    PolicyBatchOutcome, PolicyCoordinatorError, PolicyEvaluationInput, PolicyEvaluationOptions,
    PolicySourceIdentity, evaluate_policy_inputs_with_analyzer, evaluate_policy_source,
};
use crate::analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryResponse, ProtocolRegistrationSet,
    TaintResultRegistrationSet, ValueFlowPlanRegistrationSet,
    execute_workspace_request_with_all_analysis_registration_lease,
    execute_workspace_request_with_analysis_registration_lease,
    execute_workspace_request_with_cancellation, execute_workspace_request_with_limits,
    execute_workspace_request_with_registration_lease,
};
use crate::analyzer::typestate::ProductionTypestateSummaryLease;

/// Executes typed code-intelligence requests against one caller-owned workspace.
///
/// Construction borrows rather than owns the workspace so hosts retain their
/// lifecycle semantics. In particular, an LSP runtime continues to observe its
/// overlay project, and an MCP runtime continues to use its watcher-refreshed
/// snapshot.
pub struct CodeIntelligenceRuntime<'a> {
    workspace: &'a WorkspaceAnalyzer,
    cancellation: Option<&'a CancellationToken>,
}

impl<'a> CodeIntelligenceRuntime<'a> {
    pub const fn new(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            workspace,
            cancellation,
        }
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
                query,
                limits,
                cancellation,
            ),
            None => execute_workspace_request_with_limits(self.workspace, query, limits),
        }
    }

    /// Execute a query with caller-owned typestate registrations and summaries.
    ///
    /// Long-lived hosts that cache production typestate summaries provide a
    /// generation-bound lease here. The lease is semantic execution context,
    /// not an MCP concern, so it belongs at this boundary.
    pub fn execute_query_with_registration_lease(
        &self,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
        summary_lease: ProductionTypestateSummaryLease,
    ) -> CodeQueryResponse {
        execute_workspace_request_with_registration_lease(
            self.workspace,
            workspace_generation,
            registrations,
            query,
            limits,
            self.cancellation,
            summary_lease,
        )
    }

    /// Execute a query with caller-owned typestate and value-flow registrations.
    pub fn execute_query_with_analysis_registration_lease(
        &self,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        value_flow_registrations: &ValueFlowPlanRegistrationSet,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
        summary_lease: ProductionTypestateSummaryLease,
    ) -> CodeQueryResponse {
        execute_workspace_request_with_analysis_registration_lease(
            self.workspace,
            workspace_generation,
            registrations,
            value_flow_registrations,
            query,
            limits,
            self.cancellation,
            summary_lease,
        )
    }

    /// Execute a query with every caller-owned immutable analysis registration.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_query_with_all_analysis_registration_lease(
        &self,
        workspace_generation: u64,
        registrations: &ProtocolRegistrationSet,
        value_flow_registrations: &ValueFlowPlanRegistrationSet,
        taint_registrations: &TaintResultRegistrationSet,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
        summary_lease: ProductionTypestateSummaryLease,
    ) -> CodeQueryResponse {
        execute_workspace_request_with_all_analysis_registration_lease(
            self.workspace,
            workspace_generation,
            registrations,
            value_flow_registrations,
            taint_registrations,
            query,
            limits,
            self.cancellation,
            summary_lease,
        )
    }

    /// Evaluate a mixed set of workspace-backed and embedded RQL policies.
    pub fn evaluate_policy_inputs(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
        evaluate_policy_inputs_with_analyzer(
            root,
            policy_inputs,
            self.workspace,
            options,
            self.cancellation,
        )
    }

    /// Evaluate an editor-provided RQL policy source against this workspace.
    pub fn evaluate_policy_source(
        &self,
        root: &Path,
        source_identity: PolicySourceIdentity,
        source: &str,
        options: &PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
        evaluate_policy_source(
            root,
            source_identity,
            source,
            self.workspace,
            options,
            self.cancellation,
        )
    }
}
