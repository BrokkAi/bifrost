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
    PolicySourceIdentity, PolicySuppressionPreflight, evaluate_policy_inputs_for_host_session,
    evaluate_policy_inputs_for_host_session_with_suppression_preflight,
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
    ///
    /// Policy evaluation answers one question whatever the host: the
    /// coordinator analyzes this workspace's project under the policy
    /// configuration and activates the policy's own semantic sources, exactly
    /// as the CLI does, so a session's findings and published evidence agree
    /// with every other entry point's (#3735).
    pub fn evaluate_policy_inputs(
        &self,
        root: &Path,
        policy_inputs: &[PolicyEvaluationInput],
        options: &PolicyEvaluationOptions,
    ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
        evaluate_policy_inputs_for_host_session(
            root,
            policy_inputs,
            self.workspace,
            options,
            self.cancellation,
        )
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
        evaluate_policy_inputs_for_host_session_with_suppression_preflight(
            root,
            policy_inputs,
            self.workspace,
            options,
            suppression_preflight,
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
        self.evaluate_policy_inputs(
            root,
            &[PolicyEvaluationInput::embedded(source_identity, source)],
            options,
        )
    }
}

#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod tests {
    use super::CodeIntelligenceRuntime;
    use super::inline_project::InlineTestProject;
    use crate::CancellationToken;
    use crate::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
        acquire_active_semantic_models, compile_source,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::flow::FlowWorkspaceState;
    use crate::rql::{CodeQuery, CodeQueryCompletion, CodeQueryResultValue};
    use serde_json::json;

    #[test]
    fn runtime_executes_public_java_effect_operations_with_structural_joins_and_uncertainty() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "App.java",
                r#"import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

class Service {
  static URLConnection run(URL url) throws IOException {
    return url.openConnection();
  }
}

class Other {
  URLConnection openConnection() { return null; }
}

class Caller {
  static URLConnection positive(URL url) throws IOException {
    return Service.run(url);
  }

  static URLConnection near(Other other) {
    return other.openConnection();
  }

  static URLConnection unknown(URL url) {
    return MissingGateway.dispatch(url);
  }
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());

        let pack = compile_source(
            SourceFormat::Json,
            include_str!("../../../semantic-packs/web-network/jvm/bifrost.web-network-jvm.json")
                .as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| {
            panic!("public JVM web-network pack compiles: {diagnostics:#?}")
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:public-java-network-effects".to_owned(),
                },
            )
            .expect("register public JVM web-network pack");

        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().expect("crate version"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".to_owned(),
                    ecosystem: "jdk".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        let snapshot = match activation {
            SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
            other => panic!("public JVM web-network pack activates: {other:#?}"),
        };
        let _semantic_model_scope =
            crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );

        let flow_state = FlowWorkspaceState::new();
        let runtime = CodeIntelligenceRuntime::new(&workspace, &flow_state, None);
        let execute = |query| {
            let query = CodeQuery::from_json(&query).expect("query should parse");
            runtime.execute_query(&query, Default::default())
        };

        let positive_dispatch = execute(json!({
            "languages": ["java"],
            "match": { "kind": "call", "callee": { "name": "openConnection" } },
            "inside": { "kind": "method", "name": "run" },
            "steps": [{ "op": "dispatch_targets" }],
            "result_detail": "full"
        }));
        let positive_dispatch_result = positive_dispatch.result().expect("query result");
        assert_eq!(
            positive_dispatch_result.completion(),
            CodeQueryCompletion::Complete
        );
        let [positive_dispatch_item] = positive_dispatch_result.results.as_slice() else {
            panic!("one modeled URL.openConnection target: {positive_dispatch_result:#?}");
        };
        let CodeQueryResultValue::DispatchTarget {
            value: positive_target,
        } = &positive_dispatch_item.value
        else {
            panic!("dispatch-target query returns a target row: {positive_dispatch_item:#?}");
        };
        assert_eq!(positive_target.proof, "proven");
        assert_eq!(positive_target.completeness, "partial");
        assert_eq!(positive_target.coverage, "open");
        let positive_target_id = positive_target.target_id.as_str();
        let positive_target_ast_id = positive_target
            .site_ast_id
            .clone()
            .expect("modeled target AST identity");

        let positive_effects = execute(json!({
            "languages": ["java"],
            "match": { "kind": "call", "callee": { "name": "openConnection" } },
            "inside": { "kind": "method", "name": "run" },
            "steps": [{ "op": "call_shape" }, { "op": "call_effects" }],
            "result_detail": "full"
        }));
        let positive_effects_result = positive_effects.result().expect("query result");
        assert_eq!(
            positive_effects_result.completion(),
            CodeQueryCompletion::Complete
        );
        let positive_effect = positive_effects_result
            .results
            .iter()
            .find_map(|item| match &item.value {
                CodeQueryResultValue::CallEffect { value }
                    if value.effect_id.as_deref() == Some("bifrost.network_io") =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!("declared URL.openConnection effect: {positive_effects_result:#?}")
            });
        assert_eq!(positive_effect.site_ast_id, positive_target_ast_id);
        assert_eq!(
            positive_effect.target_id.as_deref(),
            Some(positive_target_id)
        );
        assert_eq!(positive_effect.derivation, "declared");
        assert_eq!(positive_effect.coverage, "exhaustive");
        assert_eq!(positive_effect.proof, Some("proven"));
        assert_eq!(
            positive_effect.pack_id.as_deref(),
            Some("bifrost.web-network-jvm")
        );
        assert_eq!(
            positive_effect.model_id.as_deref(),
            Some("bifrost.web-network-jvm#summary.web-network.jvm.java-net-url.openconnection")
        );
        assert_eq!(
            positive_effect.summary_id.as_deref(),
            Some("summary.web-network.jvm.java-net-url.openconnection")
        );
        assert!(!positive_effect.terminal);
        let positive_effect_site_id = positive_effect.site_id.clone();

        let service_call_shape = execute(json!({
            "languages": ["java"],
            "match": { "kind": "call", "callee": { "name": "run" } },
            "inside": { "kind": "method", "name": "positive" },
            "steps": [{ "op": "call_shape" }],
            "result_detail": "full"
        }));
        let service_call_shape_result = service_call_shape.result().expect("query result");
        assert_eq!(
            service_call_shape_result.completion(),
            CodeQueryCompletion::Complete
        );
        let [service_call_shape_item] = service_call_shape_result.results.as_slice() else {
            panic!("one Service.run call-shape row: {service_call_shape_result:#?}");
        };
        let CodeQueryResultValue::CallShape {
            value: service_call_shape,
        } = &service_call_shape_item.value
        else {
            panic!("call-shape query returns a call-shape row: {service_call_shape_item:#?}");
        };
        let service_call_shape_site_id = service_call_shape.site_id.clone();

        let positive_procedure = execute(json!({
            "languages": ["java"],
            "match": { "kind": "method", "name": "positive" },
            "inside_decl": { "kind": "class", "name": "Caller" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "procedure_effects" }],
            "result_detail": "full"
        }));
        let positive_procedure_result = positive_procedure.result().expect("query result");
        assert_eq!(
            positive_procedure_result.completion(),
            CodeQueryCompletion::Complete
        );
        let positive_procedure_effect = positive_procedure_result
            .results
            .iter()
            .find_map(|item| match &item.value {
                CodeQueryResultValue::ProcedureEffect { value }
                    if value.effect_id.as_deref() == Some("bifrost.network_io") =>
                {
                    Some(value.as_ref())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("transitive network effect: {positive_procedure_result:#?}"));
        assert_eq!(positive_procedure_effect.classification, Some("transitive"));
        assert_eq!(positive_procedure_effect.derivation, "declared");
        assert_eq!(positive_procedure_effect.coverage, "exhaustive");
        assert!(positive_procedure_effect.witness_available);
        assert_eq!(
            positive_procedure_effect.witness_site_id.as_deref(),
            Some(service_call_shape_site_id.as_str())
        );
        assert_eq!(
            positive_procedure_effect.witness_effect_site_id.as_deref(),
            Some(positive_effect_site_id.as_str())
        );
        assert_eq!(
            positive_procedure_effect.pack_id.as_deref(),
            Some("bifrost.web-network-jvm")
        );
        assert_eq!(
            positive_procedure_effect.model_id.as_deref(),
            Some("bifrost.web-network-jvm#summary.web-network.jvm.java-net-url.openconnection")
        );
        assert_eq!(
            positive_procedure_effect.summary_id.as_deref(),
            Some("summary.web-network.jvm.java-net-url.openconnection")
        );

        let near_dispatch = execute(json!({
            "languages": ["java"],
            "match": { "kind": "call", "callee": { "name": "openConnection" } },
            "inside": { "kind": "method", "name": "near" },
            "steps": [{ "op": "dispatch_targets" }],
            "result_detail": "full"
        }));
        let near_dispatch_result = near_dispatch.result().expect("query result");
        assert_eq!(
            near_dispatch_result.completion(),
            CodeQueryCompletion::Complete
        );
        let [near_dispatch_item] = near_dispatch_result.results.as_slice() else {
            panic!("one same-name near-miss target: {near_dispatch_result:#?}");
        };
        let CodeQueryResultValue::DispatchTarget { value: near_target } = &near_dispatch_item.value
        else {
            panic!("near-miss dispatch returns a target row: {near_dispatch_item:#?}");
        };
        assert_eq!(near_target.proof, "proven");
        assert_eq!(near_target.completeness, "complete");
        assert_eq!(near_target.coverage, "exhaustive");
        assert_ne!(near_target.target_id.as_str(), positive_target_id);
        let near_dispatch_site_ast_id = near_target
            .site_ast_id
            .clone()
            .expect("near-miss dispatch AST identity");

        let near_effects = execute(json!({
            "languages": ["java"],
            "match": { "kind": "call", "callee": { "name": "openConnection" } },
            "inside": { "kind": "method", "name": "near" },
            "steps": [{ "op": "call_shape" }, { "op": "call_effects" }],
            "result_detail": "full"
        }));
        let near_effects_result = near_effects.result().expect("query result");
        assert_eq!(
            near_effects_result.completion(),
            CodeQueryCompletion::Complete
        );
        let [near_effect_item] = near_effects_result.results.as_slice() else {
            panic!("one terminal same-name near-miss effect: {near_effects_result:#?}");
        };
        let CodeQueryResultValue::CallEffect { value: near_effect } = &near_effect_item.value
        else {
            panic!("near-miss query returns a call-effect row: {near_effect_item:#?}");
        };
        assert_eq!(near_effect.site_ast_id, near_dispatch_site_ast_id);
        assert!(near_effect.terminal);
        assert_eq!(near_effect.effect_id, None);
        assert_eq!(near_effect.derivation, "none");
        assert_eq!(near_effect.coverage, "exhaustive");
        assert_eq!(near_effect.pack_id, None);
        assert_eq!(near_effect.model_id, None);
        assert_eq!(near_effect.summary_id, None);

        let unknown_procedure = execute(json!({
            "languages": ["java"],
            "match": { "kind": "method", "name": "unknown" },
            "inside_decl": { "kind": "class", "name": "Caller" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "procedure_effects" }],
            "result_detail": "full"
        }));
        let unknown_procedure_result = unknown_procedure.result().expect("query result");
        assert!(
            matches!(
                unknown_procedure_result.completion(),
                CodeQueryCompletion::Incomplete { .. }
            ),
            "unresolved callee keeps the public runtime query incomplete: {unknown_procedure_result:#?}"
        );
        let [unknown_item] = unknown_procedure_result.results.as_slice() else {
            panic!("one terminal typed uncertainty row: {unknown_procedure_result:#?}");
        };
        let CodeQueryResultValue::ProcedureEffect {
            value: unknown_effect,
        } = &unknown_item.value
        else {
            panic!("uncertainty query returns a procedure-effect row: {unknown_item:#?}");
        };
        assert!(unknown_effect.terminal);
        assert_eq!(unknown_effect.effect_id, None);
        assert_eq!(unknown_effect.derivation, "incomplete");
        assert_eq!(unknown_effect.reason, Some("dispatch_unresolved"));
        assert_eq!(unknown_effect.coverage, "open");
        assert_eq!(unknown_effect.pack_id, None);
        assert_eq!(unknown_effect.model_id, None);
        assert_eq!(unknown_effect.summary_id, None);
    }
}
