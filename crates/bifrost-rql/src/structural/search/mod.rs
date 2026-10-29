//! Workspace-level execution of a structural query (`query_code`): scope by
//! path globs and languages, derive the planner's positive anchors and query
//! requirements, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::derived_cache::{
    DerivedLayer, DerivedLayerAcquisition, DerivedLayerBuildMetrics, DerivedLayerLifecycle,
    DerivedLayerRequest, DirectImportTopology, DirectImportTopologyLimits,
    RequestLocalDirectImportGraph, build_direct_import_topology,
};
use super::execution::plan::{
    CodeQueryExplain, LogicalQueryOperator, LogicalQueryPlan, PhysicalQueryNodeId,
    PhysicalQueryOperator, PhysicalQueryPlan,
};
use super::execution::profile::{
    CodeQueryProfile, QueryAccessPathProfile, QueryAccessPathTermProfile, QueryCacheProfile,
    QueryExecutionProfile, QueryOperatorDisposition, QueryOperatorProfile,
    QueryOperatorTermination, QueryOperatorWorkProfile, QueryRetainedValueCensus,
    QueryRetainedValueKind,
};
use super::execution::scheduler::BoundedReadyScheduler;
use super::facts::{FileFacts, Span};
use super::index::{
    QueryStructuralIndexSession, STRUCTURAL_INDEX_REPRESENTATION_VERSION, SnapshotStructuralIndex,
    StructuralCandidateSet, StructuralIndexAcquisition, StructuralIndexBuildMetrics,
    StructuralIndexLifecycle,
};
use super::index_query::SourceAnchorGroup;
use super::kinds::{NormalizedKind, Role};
use super::matcher::FactMatch;
use super::planner::QueryPlan;
use super::provider::{
    StructuralFactProvider, StructuralFactsCacheOutcome, StructuralFactsLimitedOutcome,
    StructuralSourceLimitedOutcome,
};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::reference_candidates::{
    ReferenceCandidateRanges, reference_candidate_ranges, reference_candidate_ranges_cancellable,
};
#[cfg(test)]
use crate::analyzer::usages::CallArgument;
#[cfg(test)]
use crate::analyzer::usages::UsageHit;
use crate::analyzer::usages::get_definition::{
    CallSyntaxKind, DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    parse_tree_for_language, resolve_definition_batch_with_source,
    resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverIdentityProof, ReceiverValue,
};
use crate::analyzer::usages::receiver_query::{
    ReceiverMemberTarget, ReceiverQueryAnalysis, ReceiverQueryError, ReceiverQueryInput,
    ReceiverQueryOperation, ReceiverQueryReport, ReceiverQueryService,
};
use crate::analyzer::usages::{
    CallBindingCache, CallBindingStatus, CallRelationDiagnostic, CallRelationDiagnosticCode,
    CallRelationLimits, CallRelationResult, CallRelationService, CallSite, DEFAULT_MAX_FILES,
    ExplicitCandidateProvider, FuzzyResult, ReferenceHit, ReferenceKind, UsageFinder, UsageHitKind,
    UsageProof, bind_call_site_arguments,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, PersistedImportAdjacency, PersistedImportDirection, ProjectFile,
    Range, SubsetCoverage, WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::query::JsxElementIdentity;
use crate::structural::analysis_context::{
    ProtocolRef, ProtocolRegistrationSet, QueryAnalysisContext, QueryAnalysisContextError,
    QueryAnalysisValidationLimits, TaintResultRef, TaintResultRegistrationSet, ValueFlowPlanRef,
    ValueFlowPlanRegistrationSet,
};
use crate::structural::capabilities::QueryFeature;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
#[cfg(test)]
use brokk_bifrost_analysis::native_resolution_test_support::SelectedReferenceInverseIndex;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::native_resolution_test_support::{
    FactReferenceEdgeCatalog, FactResolutionSource, SelectedFactResolutionSnapshot,
    SelectedReferenceInverseIndexBuildOutcome, build_selected_reference_inverse_index,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::materialization::SourceExportLocalDefinition;
use brokk_bifrost_core::util::elapsed_ns;
use brokk_bifrost_rql::schema::{reference_kind_label, usage_proof_label};
use brokk_bifrost_rql::{
    CallArgumentSelector, CallIdentity, CallInputSelector, CallSiteTraversalFilter,
    CallTraversalFilter, CodeQuery, CodeQueryExecutionMode, CodeQueryPlan, CodeQueryPlanSource,
    CodeQueryResultDetail, CodeQuerySeed, CrossDomainRelation, FieldWriteValueTraversal,
    HierarchyTraversal, PathFilter, Pattern, QueryError, QueryRowProjectionColumn, QueryStep,
    ReferenceTraversalFilter, ResolvedCallFilter, ResolvedCallIdentityKind, ResolvedCallProof,
    SetOperator,
};
use brokk_bifrost_tools::searchtools::session_subset;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

mod applicability;
mod assignment_relations;
mod body_relations;
mod branch_relations;
mod call_binding;
mod call_shape;
mod callable_signature;
mod configuration;
mod configuration_absence;
mod configuration_join;
mod cpp_class_facts;
mod cpp_expressions;
mod cpp_format;
mod dependency_evidence;
mod python_special_method_signature;
mod statement_facts;
use dependency_evidence::{DependencyEvidenceValue, execute_dependency_evidence_seed};
mod control_relations;
mod cpp_range_relations;
mod cpp_language_rules {
    include!(concat!("cpp", "_rules.rs"));
}
mod cross_domain;
mod csharp_language_rules {
    include!(concat!("csharp", "_rules.rs"));
}
mod java_language_rules {
    include!(concat!("java", "_rules.rs"));
}
mod js_language_rules {
    include!(concat!("js", "_rules.rs"));
}
mod callable_metrics;
mod decorator_binding;
mod dependency_configuration;
mod dispatch;
mod edges;
mod effects;
mod environment;
mod execution;
pub(crate) mod expansions;
mod failure_handler_state;
mod field_metadata;
mod field_write;
mod flow_state;
mod guards;
mod imports;
mod initializer_relations;
mod jsx;
mod language_rules;
mod literal_occurrences;
mod loop_relations;
mod materialization;
mod member_family;
mod occurrences;
mod pending_cleanup_flow;
mod python_attribute_shadow;
mod python_call_relations;
mod python_class_hierarchy;
mod python_commented_out_code;
mod python_format_issues;
mod python_method_receiver;
mod python_mutable_default;
mod python_rule_facts;
mod python_url_construction;
mod python_variables;
mod rust_marker_impls;
mod rust_pointer_safety;
mod statement_reachability;
use edges::{EdgeKey, EdgeTraversalCache, EdgeValue};
#[cfg(any(test, feature = "test-support"))]
pub use edges::{SelectedEdgesOfTelemetry, SelectedEdgesOfTelemetrySnapshot};
mod paths;
mod pipeline;
mod provenance;
mod python_comparisons;
mod python_import_cycles;
mod python_imports;
mod python_unsafe_import_cycles;
mod receiver;
mod relation_capabilities;
mod relations;
mod render;
mod resolved_value;
mod scalar_conditions;
use super::occurrence_rows::OccurrenceDerivationOptions;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use applicability::{CallableApplicabilityValue, OverloadSelectionValue};
use branch_relations::{BranchRelationTraversalCache, BranchRelationValue};
use call_binding::CallBindingValue;
use callable_metrics::CallableMetricsValue;
use callable_signature::{CallableSignatureValue, SignatureParameterValue};
use configuration::{
    ConfigurationFactKey, ConfigurationFactValue, ConfigurationFactsTraversalCache,
    execute_configuration_facts_seed,
};
use control_relations::{ControlRelationKey, ControlRelationTraversalCache, ControlRelationValue};
use cpp_expressions::CppExpressionValue;
use cross_domain::{
    CrossDomainKey, CrossDomainValue, execute_correlate_configuration_key, execute_require_both,
};
use decorator_binding::DecoratedParameterValue;
use dependency_configuration::execute_dependency_configuration;
use dispatch::{DispatchSiteValue, DispatchTargetValue};
use effects::{
    AssignmentRelationValue, CallEffectValue, CallResultContractValue, CallResultObligationValue,
    DetachedTaskTransferValue, EffectTraversalCache, NilnessOperationValue, ProcedureEffectValue,
    ResultContractFailureUseValue, ResultContractUseValue, SwitchCoverageValue,
};
use environment::{
    BindingKey, BindingValue, CandidateHopKey, CandidateHopValue, CandidateKey, CandidateValue,
    EnvironmentTraversalCache, ScopeKey, ScopeValue,
};
use failure_handler_state::{FailureHandlerStateCache, FailureHandlerStateValue};
use flow_state::{
    BindingInitializerCallValue, FlowRelationKey, FlowRelationValue, FlowStateTraversalCache,
    StateEventKey, StateEventValue,
};
use guards::{GuardKey, GuardValue};
use literal_occurrences::LiteralOccurrenceValue;
use loop_relations::LoopRelationValue;
use member_family::{MemberFamilyEdgeValue, MemberFamilyValue};
use occurrences::{OccurrenceKey, OccurrenceTraversalCache, OccurrenceValue};
use paths::{
    PATH_QUERY_AXES, PathKey, PathTraversalCache, PathValue, RESOLVED_PATH_QUERY_AXES, SegmentKey,
    SegmentValue, public_path, public_segment,
};
use pending_cleanup_flow::PendingCleanupFlowValue;
use python_class_hierarchy::PythonHierarchyFactValue;
use python_rule_facts::PythonRuleFactValue;
use rewrite_paths::{RewritePathKey, RewritePathTraversalCache, RewritePathValue};
use rust_marker_impls::RustMarkerImplValue;
use rust_pointer_safety::RustPointerFindingValue;
use statement_reachability::StatementReachabilityValue;
use topology_rows::{
    TopologyEdgeKey, TopologyEdgeValue, TopologyEntityKey, TopologyEntityValue,
    TopologyTraversalCache,
};
mod results;
mod rewrite_paths;
mod row_relations;
mod seeds;
mod semantic;
mod taint;
#[cfg(test)]
mod tests;
mod topology_rows;
mod type_flow;
mod typestate;
mod units;
mod value_flow;
mod witness_projection;
mod xml_relations;

#[cfg(test)]
pub(crate) mod test_support {
    use super::{CodeQueryDiagnostic, CodeQueryDiagnosticImpact};

    pub(crate) fn assert_incomplete_diagnostics(
        diagnostics: &[CodeQueryDiagnostic],
        expected_count: usize,
    ) {
        assert_eq!(diagnostics.len(), expected_count, "{diagnostics:?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete),
            "{diagnostics:?}"
        );
    }
}

impl QueryExecutionState<'_> {
    fn diagnostic(
        analyzer: &dyn IAnalyzer,
        diagnostic: CodeQueryDiagnostic,
        cause: Option<DerivationExecutionCause>,
    ) -> CodeQueryDiagnostic {
        if cause.is_some() || diagnostic.code.is_execution_state() {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause={} execution_cause={cause:?}",
                    file!(),
                    line!(),
                    diagnostic.code.as_str()
                )
            });
            analyzer.mark_execution_dependent();
        }
        diagnostic
    }
}

/// Keep the first exact diagnostic value. Source, branch and related evidence
/// are part of its identity, even when code and message are the same.
fn normalize_query_diagnostics(diagnostics: Vec<CodeQueryDiagnostic>) -> Vec<CodeQueryDiagnostic> {
    let mut seen = HashSet::default();
    diagnostics
        .into_iter()
        .filter(|diagnostic| seen.insert(diagnostic.clone()))
        .collect()
}

fn incomplete_diagnostic(
    code: CodeQueryDiagnosticCode,
    language: &'static str,
    message: String,
    exhausted_roots: Vec<CodeQueryExhaustedRoot>,
) -> CodeQueryDiagnostic {
    CodeQueryDiagnostic {
        related: Vec::new(),
        source: None,
        code,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language,
        message,
        exhausted_roots,
        withheld_rows_path: None,
    }
}

fn push_deduplicated_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    code: CodeQueryDiagnosticCode,
    message: String,
) {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code && diagnostic.message == message)
    {
        return;
    }
    diagnostics.push(incomplete_diagnostic(
        code,
        "workspace",
        message,
        Vec::new(),
    ));
}

fn same_range(left: &Range, right: &Range) -> bool {
    left.start_byte == right.start_byte && left.end_byte == right.end_byte
}

/// Flow reuse resources for a query, optionally including one policy run's root memo.
/// Converting a workspace state alone deliberately supplies no run memo.
#[derive(Clone)]
pub struct SemanticFlowResources {
    state: brokk_bifrost_flow::FlowWorkspaceState,
    root_memo: Option<TypeFlowRootMemo>,
}

impl SemanticFlowResources {
    pub fn from_workspace_state(state: &brokk_bifrost_flow::FlowWorkspaceState) -> Self {
        Self {
            state: state.clone(),
            root_memo: None,
        }
    }
    pub fn with_root_memo(mut self, memo: Option<TypeFlowRootMemo>) -> Self {
        self.root_memo = memo;
        self
    }
}
impl From<&brokk_bifrost_flow::FlowWorkspaceState> for SemanticFlowResources {
    fn from(state: &brokk_bifrost_flow::FlowWorkspaceState) -> Self {
        Self::from_workspace_state(state)
    }
}
impl From<&SemanticFlowResources> for SemanticFlowResources {
    fn from(resources: &SemanticFlowResources) -> Self {
        resources.clone()
    }
}
impl std::ops::Deref for SemanticFlowResources {
    type Target = brokk_bifrost_flow::FlowWorkspaceState;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

/// Deterministic work counters for one reusable row-family session.
///
/// These counters describe producer construction and reuse, not query budget
/// charges. Each query keeps its independent scan and row budgets even when a
/// complete immutable producer result can be replayed.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeQueryRowFamilySessionStats {
    pub occurrence_derivations: usize,
    pub occurrence_reuses: usize,
    pub environment_derivations: usize,
    pub environment_reuses: usize,
    pub traced_occurrence_derivations: usize,
    pub traced_occurrence_reuses: usize,
}

#[derive(Clone)]
struct SharedRowFamilyStores {
    occurrence: Option<Arc<Mutex<occurrences::OccurrenceTraversalStore>>>,
    environment: Option<Arc<Mutex<environment::EnvironmentTraversalStore>>>,
    selected_ast_ids: Option<Arc<std::collections::HashSet<String>>>,
    active_semantic_model_snapshot:
        Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
}

/// Complete occurrence and lexical-environment products shared by a caller's
/// explicitly bounded batch of structural queries.
///
/// Reuse is fail-closed: it requires an exact workspace content identity,
/// semantic-model snapshot, and matching occurrence derivation options.
/// Incomplete and cancelled products remain query-local, as do diagnostic
/// suppression, budgets and completion.
/// A session created with [`CodeQueryRowFamilySession::for_ast_ids`] is a
/// correlated batch: execute its `binding_of` query before its scope query so
/// the latter can project the declaring scopes the former reached.
#[doc(hidden)]
pub struct CodeQueryRowFamilySession {
    content: Option<WorkspaceContentIdentity>,
    active_semantic_model_snapshot:
        Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
    occurrence_options: Option<OccurrenceDerivationOptions>,
    occurrence: Arc<Mutex<occurrences::OccurrenceTraversalStore>>,
    environment: Arc<Mutex<environment::EnvironmentTraversalStore>>,
    selected_ast_ids: Option<Arc<std::collections::HashSet<String>>>,
}

impl Default for CodeQueryRowFamilySession {
    fn default() -> Self {
        Self {
            content: None,
            active_semantic_model_snapshot: None,
            occurrence_options: None,
            occurrence: Arc::new(Mutex::new(occurrences::OccurrenceTraversalStore::default())),
            environment: Arc::new(Mutex::new(environment::EnvironmentTraversalStore::default())),
            selected_ast_ids: None,
        }
    }
}

impl CodeQueryRowFamilySession {
    /// Create a session whose occurrence seeds can observe only the AST
    /// identities a correlated caller will join. A scope seed in this session
    /// projects declaring scopes recorded by preceding `binding_of` queries.
    #[doc(hidden)]
    pub fn for_ast_ids(ast_ids: Vec<String>) -> Self {
        Self {
            selected_ast_ids: Some(Arc::new(ast_ids.into_iter().collect())),
            ..Self::default()
        }
    }

    fn clear_products(&mut self) {
        self.occurrence = Arc::new(Mutex::new(occurrences::OccurrenceTraversalStore::default()));
        self.environment = Arc::new(Mutex::new(environment::EnvironmentTraversalStore::default()));
        self.occurrence_options = None;
    }

    fn stores(
        &mut self,
        analyzer: &dyn IAnalyzer,
        occurrence_options: OccurrenceDerivationOptions,
    ) -> SharedRowFamilyStores {
        let active_semantic_model_snapshot = analyzer.active_semantic_model_snapshot();
        let same_semantic_snapshot = match (
            self.active_semantic_model_snapshot.as_ref(),
            active_semantic_model_snapshot.as_ref(),
        ) {
            (None, None) => true,
            (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
            _ => false,
        };
        if !same_semantic_snapshot {
            self.clear_products();
            self.active_semantic_model_snapshot = active_semantic_model_snapshot.clone();
        }
        let Some(content) = analyzer.workspace_content_identity() else {
            self.content = None;
            self.clear_products();
            return SharedRowFamilyStores {
                occurrence: None,
                environment: None,
                selected_ast_ids: self.selected_ast_ids.clone(),
                active_semantic_model_snapshot,
            };
        };
        if self.content != Some(content) {
            self.clear_products();
            self.content = Some(content);
        }
        if self.occurrence_options != Some(occurrence_options) {
            self.occurrence =
                Arc::new(Mutex::new(occurrences::OccurrenceTraversalStore::default()));
            self.occurrence_options = Some(occurrence_options);
        }
        SharedRowFamilyStores {
            occurrence: Some(Arc::clone(&self.occurrence)),
            environment: Some(Arc::clone(&self.environment)),
            selected_ast_ids: self.selected_ast_ids.clone(),
            active_semantic_model_snapshot,
        }
    }

    #[doc(hidden)]
    pub fn stats(&self) -> CodeQueryRowFamilySessionStats {
        let (occurrence_derivations, occurrence_reuses) = self
            .occurrence
            .lock()
            .expect("a row-family occurrence cache lock is not poisoned")
            .stats();
        let (
            environment_derivations,
            environment_reuses,
            traced_occurrence_derivations,
            traced_occurrence_reuses,
        ) = self
            .environment
            .lock()
            .expect("a row-family environment cache lock is not poisoned")
            .stats();
        CodeQueryRowFamilySessionStats {
            occurrence_derivations,
            occurrence_reuses,
            environment_derivations,
            environment_reuses,
            traced_occurrence_derivations,
            traced_occurrence_reuses,
        }
    }
}

// `apply_pipeline_step` below (this engine's own per-step dispatch) reaches
// into `expansions` for its three graph-traversal entry points.
#[cfg(any(test, feature = "test-support"))]
pub use effects::cancelled_modeled_call_coverages_for_test;

use execution::*;
use expansions::{
    call_declaration_expansions, inbound_reference_expansions, scan_outbound_reference_hits,
};
use imports::*;
use pipeline::*;
use receiver::*;
use relations::*;
use render::*;
use row_relations::*;
use seeds::*;
use semantic::{
    SemanticCallResultValue, SemanticControlEdgeValue, SemanticProcedureValue,
    SemanticProgramPointValue, SemanticQueryContext,
};
use taint::SemanticTaintFindingValue;
use type_flow::{AbsentMemberFindingValue, AbsentMemberWitnessValue, ClassSetRowValue};
use typestate::{SemanticTypestateFindingValue, SemanticTypestateWitnessValue};
use units::unit_row_key;
pub use units::{
    CodeQueryExecutionScope, MergedLimit, MergedUnitRows, SelectorUnitExecution,
    UnitExecutionResult, UnitRow, UnitRowCapture, UnitRowDependencyMitigation, UnitRowEvidence,
    UnitRowField, UnitRowIdentities, UnitRowIdentityCandidate, UnitRowItem, UnitRowItemProvenance,
    UnitRowItemProvenanceStep, UnitRowItemRef, UnitRowItemRefValue, UnitRowItemTerminal,
    UnitRowKey, UnitRowProvenance, UnitRowProvenanceRef, UnitRowProvenanceStep, UnitRowScalar,
    UnitRowUnknownField, execute_code_query_selector_unit, execute_code_query_unit,
    merge_unit_rows, plan_seed_files, seed_file_order, structural_seed_file_order,
};
pub(crate) use value_flow::public_witness_step;
use value_flow::{SemanticFlowEndpointValue, SemanticFlowWitnessValue};
pub(crate) use witness_projection::project_taint_finding_report_bounded;
pub use witness_projection::{project_production_taint_findings, project_taint_finding_report};

// Internal wiring: hoist the handful of `expansions`-child items the moved
// test module (tests.rs) still reaches via a bare `super::name` path, exactly
// as it did when this was one flat file. This is private (not part of the
// external crate/pub surface below) and only referenced under `#[cfg(test)]`.
#[cfg(test)]
use expansions::{
    append_outbound_lookup_diagnostics, group_outbound_lookup_candidates, reference_hits_for_target,
};

// Re-export the exact previous public/pub(crate) surface of `search.rs` so
// that `crate::structural::search::X` keeps resolving for every
// existing consumer path unchanged.
use super::lexical_environment::BindingOfOutcome;
use super::occurrence_rows::{OccurrenceRow, OccurrenceTarget};
use super::occurrences::{OccurrenceClass, OccurrenceRole};
use crate::analyzer::semantic::{
    ContentIdentity, LengthDelimitedDigest, SemanticArtifactLeaseSnapshot, SemanticBudget,
    SemanticBudgetCharge, SemanticBudgetScopeSnapshot, SemanticExecutionBudget,
    SemanticExecutionBudgetCharge, SemanticExecutionBudgetSnapshot,
};
use crate::analyzer::usages::get_definition::TraceCandidateRef;
use brokk_bifrost_rql::{
    BindingFilter, CandidateFilter, ControlRelationFilter, EdgeFilter, FlowRelationFilter,
    OccurrenceFilter, OccurrenceSeed, RewritePathFilter, ScopeFilter, StateEventFilter,
};
pub use results::ALL_DETAILED_CODE_QUERY_DOMAINS;
pub use results::CodeQueryAbsentMemberFinding;
pub use results::CodeQueryAbsentMemberWitness;
pub use results::CodeQueryAbsentMemberWitnessStatus;
pub use results::CodeQueryAssignmentRelation;
pub use results::CodeQueryBinding;
pub use results::CodeQueryBudgetedWork;
pub use results::CodeQueryCallArgument;
pub use results::CodeQueryCallArgumentGroup;
pub use results::CodeQueryCallBinding;
pub use results::CodeQueryCallEffect;
pub use results::CodeQueryCallResult;
pub use results::CodeQueryCallResultContract;
pub use results::CodeQueryCallResultObligation;
pub use results::CodeQueryCallShape;
pub use results::CodeQueryCallShapeArgument;
pub use results::CodeQueryCallSite;
pub use results::CodeQueryCallableApplicability;
pub use results::CodeQueryCallableMetrics;
pub use results::CodeQueryCallableSignature;
pub use results::CodeQueryCandidateHop;
pub use results::CodeQueryCandidateRef;
pub use results::CodeQueryCapture;
pub use results::CodeQueryClassSetRow;
pub use results::CodeQueryCompletion;
pub use results::CodeQueryControlEdge;
pub use results::CodeQueryCppExpression;
pub use results::CodeQueryDeclaration;
pub use results::CodeQueryDeclarationState;
pub use results::CodeQueryDecoratedParameter;
pub use results::CodeQueryDetachedTaskTransfer;
pub use results::CodeQueryDiagnostic;
pub use results::CodeQueryDiagnosticCode;
pub use results::CodeQueryDiagnosticImpact;
pub use results::CodeQueryDispatchOutcome;
pub use results::CodeQueryDispatchTarget;
pub use results::CodeQueryEnumDomain;
pub use results::CodeQueryExecutionLimits;
pub use results::CodeQueryExecutionWork;
pub use results::CodeQueryExhaustedCharge;
pub use results::CodeQueryExhaustedRoot;
pub use results::CodeQueryExport;
pub use results::CodeQueryExportBinding;
pub use results::CodeQueryExportLocalDefinition;
pub use results::CodeQueryExpressionSite;
pub use results::CodeQueryFieldWriteValue;
pub use results::CodeQueryFile;
pub use results::CodeQueryFlowCarrierSymbol;
pub use results::CodeQueryFlowCertainty;
pub use results::CodeQueryFlowDeclarationSegment;
pub use results::CodeQueryFlowEndpoint;
pub use results::CodeQueryFlowEvent;
pub use results::CodeQueryFlowFactSymbol;
pub use results::CodeQueryFlowPortSymbol;
pub use results::CodeQueryFlowReachability;
pub use results::CodeQueryFlowSelectorSymbol;
pub use results::CodeQueryFlowStatus;
pub use results::CodeQueryFlowSymbolSite;
pub use results::CodeQueryFlowWitness;
pub use results::CodeQueryFlowWitnessStep;
pub use results::CodeQueryFlowWitnessStepKind;
pub use results::CodeQueryGenerationSite;
pub use results::CodeQueryImportBinder;
pub use results::CodeQueryJsxAttributeValue;
pub use results::CodeQueryLexicalScope;
pub use results::CodeQueryLiteralOccurrence;
pub use results::CodeQueryLoopReason;
pub use results::CodeQueryLoopRelation;
pub use results::CodeQueryMatch;
pub use results::CodeQueryMemberFamily;
pub use results::CodeQueryMemberFamilyEdge;
pub use results::CodeQueryMemberSelection;
pub use results::CodeQueryMemberTarget;
pub use results::CodeQueryMemberTargetAnalysis;
pub use results::CodeQueryNilnessOperation;
pub use results::CodeQueryOccurrence;
pub use results::CodeQueryOccurrenceTarget;
pub use results::CodeQueryOverloadSelection;
pub use results::CodeQueryPathSegment;
pub use results::CodeQueryPendingCleanupFlow;
pub use results::CodeQueryPointsToCandidate;
pub use results::CodeQueryProcedure;
pub use results::CodeQueryProcedureEffect;
pub use results::CodeQueryProgramPoint;
pub use results::CodeQueryProgramPointBoundary;
pub use results::CodeQueryProgramPointRef;
pub use results::CodeQueryProvenance;
pub use results::CodeQueryProvenanceStep;
pub use results::CodeQueryPythonHierarchyEndpoint;
pub use results::CodeQueryPythonHierarchyFact;
pub use results::CodeQueryPythonImportLeaf;
pub use results::CodeQueryPythonImportSite;
pub use results::CodeQueryPythonRuleFact;
pub use results::CodeQueryQualifiedPath;
pub use results::CodeQueryRange;
pub use results::CodeQueryReceiverAnalysis;
pub use results::CodeQueryReceiverEvidence;
pub use results::CodeQueryReceiverOutcome;
pub use results::CodeQueryReceiverValue;
pub use results::CodeQueryReferenceEdge;
pub use results::CodeQueryReferenceSite;
pub use results::CodeQueryResolutionCandidate;
pub use results::CodeQueryResponse;
pub use results::CodeQueryResult;
pub use results::CodeQueryResultContractFailureUse;
pub use results::CodeQueryResultContractUse;
pub use results::CodeQueryResultItem;
pub use results::CodeQueryResultRef;
pub use results::CodeQueryResultSubjectAssignment;
pub use results::CodeQueryResultSubjectOutcome;
pub use results::CodeQueryResultSubjectUse;
pub use results::CodeQueryResultValue;
pub use results::CodeQueryRowCoverage;
pub use results::CodeQueryRowCoverageExtent;
pub use results::CodeQueryRowField;
pub use results::CodeQueryRowFieldError;
pub use results::CodeQueryRowFieldUnknownReason;
pub use results::CodeQueryRowRef;
pub use results::CodeQueryRowScalarRef;
pub use results::CodeQueryRowScalarType;
pub use results::CodeQueryRustPointerFinding;
pub use results::CodeQuerySemanticCompleteness;
pub use results::CodeQuerySemanticEvidence;
pub use results::CodeQuerySemanticLimits;
pub use results::CodeQuerySemanticProof;
pub use results::CodeQuerySemanticReceipt;
pub use results::CodeQuerySemanticRowLimits;
pub use results::CodeQuerySemanticWork;
pub use results::CodeQuerySignatureParameter;
pub use results::CodeQuerySourceSite;
pub use results::CodeQueryStableOwnerCandidate;
pub use results::CodeQueryStableOwnerDerivation;
pub use results::CodeQueryStatementReachability;
pub use results::CodeQuerySwitchCoverage;
pub use results::CodeQueryTaintFinding;
pub use results::CodeQueryTaintFindingKey;
pub use results::CodeQueryTaintLimits;
pub use results::CodeQueryTaintOrigin;
pub use results::CodeQueryTaintProjectionLimits;
pub use results::CodeQueryTaintWitness;
pub use results::CodeQueryTypeFlowWork;
pub use results::CodeQueryTypestateCertainty;
pub use results::CodeQueryTypestateFinding;
pub use results::CodeQueryTypestateFindingKind;
pub use results::CodeQueryTypestateLimits;
pub use results::CodeQueryTypestateSubject;
pub use results::CodeQueryTypestateUncertainty;
pub use results::CodeQueryTypestateWitness;
pub use results::CodeQueryTypestateWitnessStep;
pub use results::CodeQueryTypestateWitnessStepKind;
pub use results::CodeQueryTypestateWork;
pub use results::CodeQueryValueFlowLimits;
pub use results::CodeQueryValueFlowWork;
pub use results::DetailedCodeQueryDecoratedParameterEvidence;
pub use results::DetailedCodeQueryDomain;
pub use results::DetailedCodeQueryEvidence;
pub use results::DetailedCodeQueryExportLocalDefinition;
pub use results::DetailedCodeQueryIdentityCandidate;
pub use results::DetailedCodeQueryKey;
pub use results::DetailedCodeQueryProvenanceEvidence;
pub use results::DetailedCodeQueryProvenanceIdentities;
pub use results::DetailedCodeQueryProvenanceRefEvidence;
pub(crate) use results::DetailedCodeQueryProvenanceStepEvidence;
pub use results::DetailedCodeQueryResult;
pub use results::SUPPRESSED_ROW_SET_CAPABILITY;
pub(crate) use results::UnionExecutionStrategy;
pub use results::VALUE_FLOW_CAPABILITY;
pub use results::code_query_completion;
#[cfg(feature = "query-result-fixtures")]
pub use results::code_query_result_fixtures_json;
pub use results::code_query_result_json_schema;
pub use results::{CodeQueryFlowRelation, CodeQueryStateEvent, CodeQueryStateEventRef};
pub use results::{CodeQueryRelatedSource, CodeQuerySourceSpan};
pub use results::{CodeQueryRewritePath, CodeQueryRewriteStep};
pub use results::{CodeQueryRustMarkerImpl, CodeQueryRustMarkerUse};
pub use results::{MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES, render_exhausted_roots};
pub use type_flow::{CodeQueryRootAllotment, TypeFlowRootMemo};

/// Longest match/capture snippet reported inline; full content is always
/// reachable via the returned line range.
const SNIPPET_MAX_CHARS: usize = 160;
const MAX_SCANNED_FILES: usize = 20_000;
const MAX_SCANNED_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FACT_NODES: usize = 2_000_000;
const MAX_PIPELINE_ROWS: usize = 50_000;
const MAX_SEMANTIC_MATERIALIZED_FILES: usize = 256;
const MAX_SEMANTIC_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEMANTIC_ROWS_PER_DIMENSION: usize = 1_000_000;
// 256 MiB, raised from 64 MiB with owner approval on issue #2523
// (2026-08-23). The floor only governs workspaces whose scaled budget
// (25 bytes per source byte) falls below it, roughly under 10 MiB of
// source. Measured basis: the gson relational effect walk retains just
// over 64 MiB at full 98/98 subject coverage (206 MiB process peak RSS),
// and a 1 GiB probe retains no more than the 256 MiB run, so the walk
// does not expand to fill the allowance.
const MAX_SEMANTIC_RETAINED_BYTES: usize = 256 * 1024 * 1024;
const MAX_PROVENANCE_TRACES: usize = 16;
const BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD: usize = 100;
const CODE_QUERY_SCHEDULER_WORKERS: usize = 2;
const MIN_AUTO_STRUCTURAL_INDEX_FILES: usize = 8;
const BENCHMARK_ACCESS_MODE_ENV: &str = "BIFROST_QUERY_CODE_ACCESS_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuralAccessMode {
    Auto,
    /// Auto's viability rules without its first-build deferral. For callers
    /// that will run a whole batch of queries against one snapshot (policy
    /// packs), reuse is guaranteed, so waiting for a second request before
    /// building the snapshot index only converts the first batch into a
    /// full-workspace scan.
    EagerAuto,
    ScanOnly,
    IndexedRequired,
    #[cfg(test)]
    DerivedAutoForTest,
}

impl StructuralAccessMode {
    const fn uses_auto_index_admission(self) -> bool {
        match self {
            Self::Auto | Self::EagerAuto => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::ScanOnly | Self::IndexedRequired => false,
        }
    }

    /// Whether the first viable request for a snapshot scans and merely
    /// records reuse interest instead of building the index.
    const fn defers_first_snapshot_build(self) -> bool {
        match self {
            Self::Auto => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::EagerAuto | Self::ScanOnly | Self::IndexedRequired => false,
        }
    }

    const fn permits_snapshot_import_topology(self) -> bool {
        match self {
            Self::IndexedRequired => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::Auto | Self::EagerAuto | Self::ScanOnly => false,
        }
    }

    const fn permits_persisted_import_graph(self) -> bool {
        match self {
            Self::Auto | Self::EagerAuto | Self::IndexedRequired => true,
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::ScanOnly => false,
        }
    }

    const fn uses_snapshot_import_auto_admission(self) -> bool {
        match self {
            #[cfg(test)]
            Self::DerivedAutoForTest => true,
            Self::Auto | Self::EagerAuto | Self::ScanOnly | Self::IndexedRequired => false,
        }
    }
}

/// A match found before rendering, held until the rendering pass (which
/// truncates at `limit` and does enclosing-symbol lookups).
type PendingMatch = (Language, ProjectFile, Arc<FileFacts>, FactMatch);

#[derive(Debug, Clone)]
struct SeedMatch {
    language: Language,
    file: ProjectFile,
    facts: Arc<FileFacts>,
    fact_match: FactMatch,
    python_import: Option<CodeQueryPythonImportSite>,
}

#[derive(Debug, Clone)]
struct DeclarationValue {
    unit: CodeUnit,
    range: Range,
    // `CodeUnitType` deliberately coarsens every callable to `Function`.
    // An exact structural projection retains the normalized leaf kind so the
    // public declaration does not erase method/constructor distinctions
    // already proved by the seed facts.
    //
    // The leaf kind is presentation evidence about the declaration, never part
    // of its identity: one declaration reached by a member list and by an
    // enclosing-declaration selection must key, intersect and deduplicate as
    // one row even though only the structural projection proved a leaf kind.
    // `merge_structural_kind` folds the evidence together when an intersection
    // combines two spellings of one row; unions and renders keep the first
    // writer's value.
    structural_kind: Option<NormalizedKind>,
}

/// A declaration row is identified by the declaration it names -- the
/// `CodeUnit` and the exact range that code unit covers -- and by nothing
/// else. See the `structural_kind` field for why the optional leaf kind cannot
/// participate.
impl PartialEq for DeclarationValue {
    fn eq(&self, other: &Self) -> bool {
        self.unit == other.unit && self.range == other.range
    }
}

impl Eq for DeclarationValue {}

impl std::hash::Hash for DeclarationValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.unit.hash(state);
        self.range.hash(state);
    }
}

impl DeclarationValue {
    fn new(unit: CodeUnit, range: Range) -> Self {
        Self {
            unit,
            range,
            structural_kind: None,
        }
    }

    fn with_structural_kind(mut self, kind: NormalizedKind) -> Self {
        debug_assert!(kind.satisfies(NormalizedKind::Declaration));
        self.structural_kind = Some(kind);
        self
    }

    /// Fold the exact structural leaf kind another projection of this same
    /// declaration proved into this value. Identity matched before the merge,
    /// so the only thing two spellings of one row can disagree about is this
    /// presentation metadata; keep whichever spelling carries it.
    fn merge_structural_kind(&mut self, other: Self) {
        debug_assert_eq!(self, &other, "declaration evidence merges by identity");
        if self.structural_kind.is_none() {
            self.structural_kind = other.structural_kind;
        }
    }

    /// The label the rendered declaration's visible `kind` field carries: the
    /// exact structural leaf kind when an exact projection proved one, and the
    /// analyzer's coarser unit kind otherwise.
    fn kind_label(&self) -> &'static str {
        self.structural_kind
            .map(NormalizedKind::label)
            .unwrap_or_else(|| self.unit.kind().display_lowercase())
    }

    fn declaration_id(&self) -> String {
        self.unit.declaration_id().to_string()
    }

    fn site_id(&self) -> String {
        self.unit
            .declaration_site_id(self.range.start_byte, self.range.end_byte)
            .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReferenceSiteValue {
    file: ProjectFile,
    range: Range,
    target: DeclarationValue,
    enclosing: Option<DeclarationValue>,
    usage_kind: UsageHitKind,
    proof: UsageProof,
    reference_kind: Option<ReferenceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallSiteIdentityFacts {
    /// The receiver shape selected from the call AST. This is deliberately a
    /// syntax fact: an explicit receiver is not assumed to be `this`.
    receiver_kind: &'static str,
    /// Resolver-owned lexical identities for written actuals, in source
    /// argument order. `None` means the actual is not a lexical binding or its
    /// binding could not be resolved.
    argument_identities: Vec<Option<String>>,
    /// Stable identities of the enclosing caller's formal parameters aligned
    /// with the written actuals. A policy can compare the first two fields to
    /// prove that an actual is the caller's own parameter rather than merely a
    /// same-spelled or differently typed value.
    caller_parameter_identities: Vec<Option<String>>,
}

impl Default for CallSiteIdentityFacts {
    fn default() -> Self {
        Self {
            receiver_kind: "unknown",
            argument_identities: Vec::new(),
            caller_parameter_identities: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallSiteValue(
    CallSite,
    CallBindingStatus,
    String,
    Option<String>,
    Option<String>,
    CallSiteIdentityFacts,
);

impl CallSiteValue {
    fn new(
        site: CallSite,
        binding: CallBindingStatus,
        semantic_identity: Option<(String, String)>,
        identity_facts: CallSiteIdentityFacts,
    ) -> Self {
        let (identity_id, program_point_id, site_id) = semantic_identity.map_or_else(
            || {
                let mut digest =
                    LengthDelimitedDigest::new(b"bifrost.code_query.source_call_site.v1");
                digest.push(rel_path_string(&site.file).as_bytes());
                digest.push(&site.range.start_byte.to_le_bytes());
                digest.push(&site.range.end_byte.to_le_bytes());
                (digest.finish().to_string(), None, None)
            },
            |(site_id, program_point_id)| (site_id.clone(), Some(program_point_id), Some(site_id)),
        );
        Self(
            site,
            binding,
            identity_id,
            program_point_id,
            site_id,
            identity_facts,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExpressionInput {
    Receiver,
    Parameter { index: usize, name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpressionSiteValue {
    call_site: CallSiteValue,
    range: Range,
    input: ExpressionInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum JsxValueCoverage {
    Complete,
    Incomplete,
}

impl JsxValueCoverage {
    const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Debug, Clone)]
struct JsxAttributeValue {
    seed: Arc<SeedMatch>,
    value_node: u32,
    attribute_node: u32,
    element_identity: JsxElementIdentity,
    element_name: Option<String>,
    attribute_name: Option<String>,
    property_name: Option<String>,
    coverage: JsxValueCoverage,
    reason: Option<&'static str>,
    component: Option<CodeUnit>,
    attribute_target: Option<CodeUnit>,
}

impl JsxAttributeValue {
    fn ast_id(&self) -> String {
        crate::analyzer::structural::occurrence_rows::ast_id(
            self.seed.facts.source_identity(),
            self.value_node,
        )
    }

    fn id(&self) -> String {
        format!(
            "jsx_attribute_value:{}:{}",
            self.ast_id(),
            self.attribute_node
        )
    }
}

#[derive(Debug, Clone)]
struct ReceiverAnalysisValue {
    report: ReceiverQueryReport,
    capture: Option<String>,
    site_id: String,
    site_ast_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ReceiverEvidenceValue {
    receiver: ReceiverAnalysisValue,
    id: String,
    parent_evidence_id: Option<String>,
    ordinal: usize,
    chain_hop: usize,
    value: ReceiverValue,
    factory: Option<CodeUnit>,
}

#[derive(Debug, Clone)]
struct PointsToCandidateValue {
    file: ProjectFile,
    language: Language,
    range: Range,
    id: String,
    site_id: String,
    program_point_id: Option<String>,
    candidate_index: usize,
    object_id: Option<String>,
    object_cardinality: Option<&'static str>,
    proof: &'static str,
    completeness: &'static str,
    coverage: &'static str,
}

/// Exact right-hand operand of one proven static member assignment.
#[derive(Debug, Clone)]
struct FieldWriteValue {
    seed: Arc<SeedMatch>,
    analysis: ReceiverAnalysisValue,
    target: ReceiverMemberTarget,
    assignment_node: u32,
    left_node: u32,
    receiver_node: u32,
    member_node: u32,
    rhs_node: u32,
}

impl FieldWriteValue {
    fn ast_id(&self, node: u32) -> String {
        crate::analyzer::structural::occurrence_rows::ast_id(
            self.seed.facts.source_identity(),
            node,
        )
    }

    fn assignment_ast_id(&self) -> String {
        self.ast_id(self.assignment_node)
    }

    fn rhs_ast_id(&self) -> String {
        self.ast_id(self.rhs_node)
    }

    fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"bifrost.field_write_value.v1");
        hasher.update(self.assignment_ast_id().as_bytes());
        hasher.update(self.rhs_ast_id().as_bytes());
        hasher.update(
            self.target
                .receiver_identity_id()
                .expect("field-write targets retain an exact receiver identity")
                .as_bytes(),
        );
        hasher.update(self.target.member_identity_id().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// One derived call-shape report shared by its outcome, group, and argument
/// pipeline rows. Group and argument values index into the shared report
/// instead of cloning row data per pipeline expansion.
#[derive(Debug, Clone)]
struct CallShapeValue {
    report: Arc<crate::analyzer::usages::call_shape::CallShapeReport>,
    /// The source-backed structural seed that owns this call shape, when the
    /// shape came through the ordinary query pipeline. Match-only relations
    /// can project a proven semantic filter back to this source row.
    seed: Option<Arc<SeedMatch>>,
    /// The normalized facts that produced `report`, retained so relations can
    /// inspect selected literal/type facts without reparsing source text.
    facts: Option<Arc<FileFacts>>,
    /// Exact external identity from the language resolver, independent of
    /// call-binding or semantic-model coverage.
    resolved_external_callee: Option<String>,
}

impl CallShapeValue {
    /// The exact source snapshot that produced the report, when retained.
    fn source(&self) -> Option<&str> {
        self.facts.as_deref().map(FileFacts::source)
    }
}

#[derive(Debug, Clone)]
struct CallArgumentGroupValue {
    shape: CallShapeValue,
    group_index: usize,
}

#[derive(Debug, Clone)]
struct CallArgumentValue {
    shape: CallShapeValue,
    argument_index: usize,
}

#[derive(Default)]
struct IndexedDeclarations {
    by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    by_unit: HashMap<CodeUnit, Option<DeclarationValue>>,
    owner_by_member: HashMap<CodeUnit, CodeUnit>,
}

impl IndexedDeclarations {
    fn get(&mut self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<DeclarationValue> {
        if let Some(value) = self.by_unit.get(unit) {
            return value.clone();
        }

        let value = if unit.is_synthetic() || unit.is_file_scope() {
            None
        } else {
            let declarations = self
                .by_file
                .entry(unit.source().clone())
                .or_insert_with(|| analyzer.declarations(unit.source()));
            declarations.contains(unit).then(|| {
                analyzer
                    .ranges_of(unit)
                    .into_iter()
                    .min_by_key(primary_range_key)
                    .map(|range| DeclarationValue::new(unit.clone(), range))
            })?
        };
        self.by_unit.insert(unit.clone(), value.clone());
        value
    }

    fn record_owner(&mut self, member: &CodeUnit, owner: &CodeUnit) {
        self.owner_by_member
            .entry(member.clone())
            .or_insert_with(|| owner.clone());
    }

    fn owner_of(
        &mut self,
        analyzer: &dyn IAnalyzer,
        member: &CodeUnit,
        work: &mut usize,
        max_work: usize,
    ) -> (Option<DeclarationValue>, bool) {
        if let Some(owner) = self.owner_by_member.get(member).cloned() {
            if *work >= max_work {
                return (None, true);
            }
            *work += 1;
            return (self.get(analyzer, &owner), false);
        }

        let owner = {
            let declarations = self
                .by_file
                .entry(member.source().clone())
                .or_insert_with(|| analyzer.declarations(member.source()));
            let mut found = None;
            'owners: for candidate in declarations.iter() {
                if *work >= max_work {
                    return (None, true);
                }
                *work += 1;
                if !is_type_declaration(analyzer, candidate) {
                    continue;
                }
                for child in analyzer.direct_children(candidate) {
                    if *work >= max_work {
                        return (None, true);
                    }
                    *work += 1;
                    if &child == member {
                        found = Some(candidate.clone());
                        break 'owners;
                    }
                }
            }
            found
        };
        if let Some(owner) = owner {
            self.record_owner(member, &owner);
            return (self.get(analyzer, &owner), false);
        }
        (None, false)
    }
}

fn primary_range_key(range: &Range) -> (usize, usize, usize, usize) {
    (
        range.start_line,
        range.start_byte,
        range.end_line,
        range.end_byte,
    )
}

struct PipelineExpansion {
    value: PipelineValue,
    trace: Vec<(PipelineTraceValue, Option<PipelineVia>)>,
    budgeted: bool,
}

#[derive(Debug, Clone)]
struct ResultSubjectUseValue {
    row: CodeQueryResultSubjectUse,
    assignment_conversions: Vec<crate::analyzer::JavaLocalAssignmentEvidence>,
    file: ProjectFile,
}

#[derive(Debug, Clone)]
enum PipelineValue {
    StructuralMatch(Arc<SeedMatch>),
    Declaration(DeclarationValue),
    Semantic(SemanticPipelineValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    JsxAttributeValue(Box<JsxAttributeValue>),
    ReceiverAnalysis(ReceiverAnalysisValue),
    MemberTargetAnalysis(ReceiverAnalysisValue),
    ReceiverOutcome(ReceiverAnalysisValue),
    ReceiverEvidence(ReceiverEvidenceValue),
    PointsToCandidate(Box<PointsToCandidateValue>),
    FieldWriteValue(Box<FieldWriteValue>),
    RuntimeKeyedReadValue(Box<RuntimeKeyedReadValue>),
    CallShape(CallShapeValue),
    CallArgumentGroup(CallArgumentGroupValue),
    CallArgument(CallArgumentValue),
    CallBinding(Box<CallBindingValue>),
    CallEffect(Box<CallEffectValue>),
    CallResultContract(Box<CallResultContractValue>),
    CallResultObligation(Box<CallResultObligationValue>),
    ResultSubjectUse(Box<ResultSubjectUseValue>),
    ResultContractUse(Box<ResultContractUseValue>),
    ResultContractFailureUse(Box<ResultContractFailureUseValue>),
    NilnessOperation(Box<NilnessOperationValue>),
    SwitchCoverage(Box<SwitchCoverageValue>),
    AssignmentRelation(Box<AssignmentRelationValue>),
    ClassSetRow(Box<ClassSetRowValue>),
    AbsentMemberFinding(Box<AbsentMemberFindingValue>),
    DetachedTaskTransfer(Box<DetachedTaskTransferValue>),
    ProcedureEffect(Box<ProcedureEffectValue>),
    CallableSignature(Box<CallableSignatureValue>),
    LiteralOccurrence(LiteralOccurrenceValue),
    CallableMetrics(Box<CallableMetricsValue>),
    SignatureParameter(Box<SignatureParameterValue>),
    DecoratedParameter(DecoratedParameterValue),
    CallableApplicability(Box<CallableApplicabilityValue>),
    OverloadSelection(Box<OverloadSelectionValue>),
    MemberSelection(MemberSelectionValue),
    DispatchOutcome(Box<DispatchSiteValue>),
    DispatchTarget(Box<DispatchTargetValue>),
    MemberFamily(Box<MemberFamilyValue>),
    MemberFamilyEdge(Box<MemberFamilyEdgeValue>),
    PythonHierarchyFact(Box<PythonHierarchyFactValue>),
    Occurrence(OccurrenceValue),
    LexicalScope(ScopeValue),
    Binding(BindingValue),
    ResolutionCandidate(Box<CandidateValue>),
    CandidateHop(Box<CandidateHopValue>),
    GenerationSite(materialization::GenerationSiteValue),
    Export(materialization::ExportValue),
    DeclarationState(materialization::DeclarationStateValue),
    ReferenceEdge(Box<EdgeValue>),
    StateEvent(Box<StateEventValue>),
    BindingInitializerCall(Box<BindingInitializerCallValue>),
    FlowRelation(Box<FlowRelationValue>),
    ControlRelation(Box<ControlRelationValue>),
    BranchRelation(Box<BranchRelationValue>),
    LoopRelation(Box<LoopRelationValue>),
    CppExpression(Box<CppExpressionValue>),
    FailureHandlerState(Box<FailureHandlerStateValue>),
    StatementReachability(Box<StatementReachabilityValue>),
    PendingCleanupFlow(Box<PendingCleanupFlowValue>),
    PythonRuleFact(Box<PythonRuleFactValue>),
    Guard(Box<GuardValue>),
    SourceSet(Box<TopologyEntityValue>),
    BuildTarget(Box<TopologyEntityValue>),
    TopologyEdge(Box<TopologyEdgeValue>),
    RewritePath(Box<RewritePathValue>),
    QualifiedPath(PathValue),
    PathSegment(SegmentValue),
    ConfigurationFact(ConfigurationFactValue),
    CrossDomain(Box<CrossDomainValue>),
    DependencyEvidence(DependencyEvidenceValue),
}

/// One member-selection summary computed from the production resolver's own
/// candidate trace for one reference occurrence. `completeness` is `None`
/// exactly when the traced file recorded no candidate trace for the row.
#[derive(Debug, Clone)]
struct MemberSelectionValue {
    occurrence: Arc<OccurrenceRow>,
    selected: usize,
    candidates: usize,
    completeness: Option<crate::analyzer::usages::get_definition::trace::TraceCompleteness>,
}

/// One runtime keyed-read endpoint or terminal typed limitation row.
#[derive(Debug, Clone)]
struct RuntimeKeyedReadValue {
    file: ProjectFile,
    range: Range,
    endpoint: Option<crate::analyzer::semantic::RuntimeKeyedReadEndpoint>,
    limitations: Vec<crate::analyzer::semantic::RuntimeReadLimitation>,
    conclusive_exclusion: bool,
    ordinal: usize,
}

impl RuntimeKeyedReadValue {
    fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.runtime_keyed_read.v1");
        digest.push(rel_path_string(&self.file).as_bytes());
        digest.push(&self.range.start_byte.to_le_bytes());
        digest.push(&self.range.end_byte.to_le_bytes());
        digest.push(&self.ordinal.to_le_bytes());
        if let Some(endpoint) = &self.endpoint {
            digest.push(endpoint.runtime.as_bytes());
            digest.push(endpoint.global.as_bytes());
            digest.push(endpoint.container.as_bytes());
            digest.push(endpoint.exposure_id.as_bytes());
            digest.push(endpoint.behavior_id.as_bytes());
            digest.push(endpoint.refinement_identity.to_string().as_bytes());
        }
        digest.finish().to_string()
    }

    fn key_kind(&self) -> &'static str {
        match self.endpoint.as_ref().map(|endpoint| &endpoint.key) {
            Some(crate::analyzer::semantic::RuntimeAccessKey::Property(_)) => "property",
            Some(crate::analyzer::semantic::RuntimeAccessKey::Index(_)) => "index",
            None => "unknown",
        }
    }

    fn source_origin(&self) -> &'static str {
        match self
            .endpoint
            .as_ref()
            .map(|endpoint| endpoint.source_origin)
        {
            Some(crate::analyzer::semantic::RuntimeReadSourceOrigin::PristineRuntimeInput) => {
                "pristine_runtime_input"
            }
            Some(crate::analyzer::semantic::RuntimeReadSourceOrigin::Mutated) => "mutated",
            Some(crate::analyzer::semantic::RuntimeReadSourceOrigin::Indeterminate) | None => {
                "indeterminate"
            }
        }
    }

    fn outcome(&self) -> &'static str {
        if self.endpoint.is_some() {
            "endpoint"
        } else if self.conclusive_exclusion {
            "conclusive_exclusion"
        } else {
            "incomplete"
        }
    }
}

impl MemberSelectionValue {
    fn stable_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"bifrost.member_selection.v1");
        hasher.update(self.occurrence.ast_id().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone)]
enum SemanticPipelineValue {
    Procedure(SemanticProcedureValue),
    ProcedureReference(Box<semantic::SemanticProcedureReferenceValue>),
    ProgramPoint(SemanticProgramPointValue),
    ProgramPointReference(Box<semantic::SemanticProgramPointReferenceValue>),
    ControlEdge(SemanticControlEdgeValue),
    ControlEdgeReference(Box<semantic::SemanticControlEdgeReferenceValue>),
    CallResult(SemanticCallResultValue),
    TypestateFinding(SemanticTypestateFindingValue),
    TypestateWitness(SemanticTypestateWitnessValue),
    FlowEndpoint(Box<SemanticFlowEndpointValue>),
    FlowWitness(SemanticFlowWitnessValue),
    AbsentMemberWitness(AbsentMemberWitnessValue),
    TaintFinding(Box<SemanticTaintFindingValue>),
    RustMarkerImpl(Box<RustMarkerImplValue>),
    RustPointerFinding(Box<RustPointerFindingValue>),
}

struct DetailedSemanticProjection<'a> {
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &'a ProjectFile,
    byte_span: std::ops::Range<usize>,
    display_range: CodeQueryRange,
    language: &'static str,
    stable_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PipelineKey {
    StructuralMatch(ProjectFile, u32, Option<Range>),
    Declaration(DeclarationValue),
    Semantic(SemanticPipelineKey),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    JsxAttributeValue(String),
    ReceiverAnalysis(ReceiverQueryOperation, ProjectFile, Range),
    MemberTargetAnalysis(ReceiverQueryOperation, ProjectFile, Range),
    ReceiverOutcome(String),
    ReceiverEvidence(String),
    PointsToCandidate(String),
    FieldWriteValue(String),
    RuntimeKeyedReadValue(String),
    CallShape(String),
    CallArgumentGroup(String),
    CallArgument(String),
    CallBinding(String),
    CallEffect(String),
    CallResultContract(String),
    CallResultObligation(String),
    ResultSubjectUse(String),
    ResultContractUse(String),
    ResultContractFailureUse(String),
    NilnessOperation(String),
    SwitchCoverage(String),
    AssignmentRelation(String),
    ClassSetRow(String),
    AbsentMemberFinding(String),
    DetachedTaskTransfer(String),
    ProcedureEffect(String),
    CallableSignature(String),
    LiteralOccurrence(String),
    CallableMetrics(String),
    SignatureParameter(String),
    DecoratedParameter(String),
    CallableApplicability(String),
    OverloadSelection(String),
    MemberSelection(String),
    DispatchOutcome(String),
    DispatchTarget(String),
    MemberFamily(String),
    MemberFamilyEdge(String),
    PythonHierarchyFact(String),
    Occurrence(OccurrenceKey),
    LexicalScope(ScopeKey),
    Binding(BindingKey),
    ResolutionCandidate(CandidateKey),
    CandidateHop(CandidateHopKey),
    GenerationSite(materialization::GenerationSiteKey),
    Export(materialization::ExportKey),
    DeclarationState(materialization::DeclarationStateKey),
    ReferenceEdge(EdgeKey),
    StateEvent(StateEventKey),
    BindingInitializerCall(String),
    FlowRelation(FlowRelationKey),
    ControlRelation(ControlRelationKey),
    BranchRelation(String),
    LoopRelation(String),
    CppExpression(String),
    FailureHandlerState(String),
    StatementReachability(String),
    PendingCleanupFlow(String),
    PythonRuleFact(String),
    Guard(GuardKey),
    SourceSet(TopologyEntityKey),
    BuildTarget(TopologyEntityKey),
    TopologyEdge(TopologyEdgeKey),
    RewritePath(RewritePathKey),
    QualifiedPath(PathKey),
    PathSegment(SegmentKey),
    ConfigurationFact(ConfigurationFactKey),
    CrossDomain(Box<CrossDomainKey>),
    DependencyEvidence(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SemanticPipelineKey {
    ProgramPointReference(String),
    ControlEdgeReference(String),
    ProcedureReference(Box<crate::analyzer::semantic::SemanticProcedureReference>),
    Procedure(crate::analyzer::semantic::ProcedureHandle),
    ProgramPoint(crate::analyzer::semantic::ProgramPointHandle),
    ControlEdge(crate::analyzer::semantic::ControlEdgeHandle),
    CallResult(String),
    TypestateFinding(String),
    TypestateWitness(String),
    FlowEndpoint(String),
    FlowWitness(String),
    AbsentMemberWitness(String),
    TaintFinding(String),
    RustMarkerImpl(String),
    RustPointerFinding(String),
}

impl PipelineValue {
    /// Absent-member rows with the same identity can carry different root
    /// evidence. A union or deduplicating render keeps the first row, so merge
    /// the evidence here to keep whole and sliced queries consistent.
    fn merge_evidence(&mut self, other: Self) {
        if let (Self::AbsentMemberFinding(value), Self::AbsentMemberFinding(other)) = (self, other)
        {
            value.merge_evidence(*other);
        }
    }

    /// Merge one contribution into an intersection survivor. Intersections and
    /// differences are never sliced, so a declaration survivor may adopt the
    /// exact structural leaf kind the other spelling proved, including for
    /// declarations embedded in a reference site, without diverging from a
    /// per-seed-file merge; every other value family then
    /// falls back to the ordinary set merge.
    fn merge_intersect_evidence(&mut self, other: Self) {
        let other = match (&mut *self, other) {
            (Self::Declaration(value), Self::Declaration(other)) => {
                value.merge_structural_kind(other);
                return;
            }
            (Self::ReferenceSite(value), Self::ReferenceSite(other)) => {
                debug_assert_eq!(value, &other, "reference evidence merges by identity");
                value.target.merge_structural_kind(other.target);
                match (&mut value.enclosing, other.enclosing) {
                    (Some(value), Some(other)) => value.merge_structural_kind(other),
                    (None, None) => {}
                    _ => unreachable!("equal reference sites have equal enclosing presence"),
                }
                return;
            }
            (_, other) => other,
        };
        self.merge_evidence(other);
    }

    fn key(&self) -> PipelineKey {
        match self {
            Self::StructuralMatch(seed) => PipelineKey::StructuralMatch(
                seed.file.clone(),
                seed.fact_match.node,
                seed.fact_match.reported_range,
            ),
            Self::Declaration(declaration) => PipelineKey::Declaration(declaration.clone()),
            Self::Semantic(value) => PipelineKey::Semantic(value.key()),
            Self::File(file) => PipelineKey::File(file.clone()),
            Self::ReferenceSite(site) => PipelineKey::ReferenceSite(site.clone()),
            Self::CallSite(site) => PipelineKey::CallSite(site.clone()),
            Self::ExpressionSite(site) => PipelineKey::ExpressionSite(site.clone()),
            Self::JsxAttributeValue(value) => PipelineKey::JsxAttributeValue(value.id()),
            Self::ReceiverAnalysis(value) => PipelineKey::ReceiverAnalysis(
                value.report.operation,
                value.report.site.file.clone(),
                value.report.site.range,
            ),
            Self::MemberTargetAnalysis(value) => PipelineKey::MemberTargetAnalysis(
                value.report.operation,
                value.report.site.file.clone(),
                value.report.site.range,
            ),
            Self::ReceiverOutcome(value) => PipelineKey::ReceiverOutcome(value.site_id.clone()),
            Self::ReceiverEvidence(value) => PipelineKey::ReceiverEvidence(value.id.clone()),
            Self::PointsToCandidate(value) => PipelineKey::PointsToCandidate(value.id.clone()),
            Self::FieldWriteValue(value) => PipelineKey::FieldWriteValue(value.id()),
            Self::RuntimeKeyedReadValue(value) => PipelineKey::RuntimeKeyedReadValue(value.id()),
            Self::CallShape(value) => PipelineKey::CallShape(value.report.outcome.site_id.clone()),
            Self::CallArgumentGroup(value) => PipelineKey::CallArgumentGroup(
                value.shape.report.groups[value.group_index].id.clone(),
            ),
            Self::CallArgument(value) => PipelineKey::CallArgument(
                value.shape.report.arguments[value.argument_index]
                    .id
                    .clone(),
            ),
            Self::CallBinding(value) => PipelineKey::CallBinding(value.row().id.clone()),
            Self::CallEffect(value) => PipelineKey::CallEffect(value.row().id.clone()),
            Self::CallResultContract(value) => PipelineKey::CallResultContract(value.id.clone()),
            Self::CallResultObligation(value) => {
                PipelineKey::CallResultObligation(value.id.clone())
            }
            Self::ResultSubjectUse(value) => PipelineKey::ResultSubjectUse(value.row.id.clone()),
            Self::ResultContractUse(value) => PipelineKey::ResultContractUse(value.id.clone()),
            Self::ResultContractFailureUse(value) => {
                PipelineKey::ResultContractFailureUse(value.id.clone())
            }
            Self::NilnessOperation(value) => PipelineKey::NilnessOperation(value.id.clone()),
            Self::SwitchCoverage(value) => PipelineKey::SwitchCoverage(value.id.clone()),
            Self::AssignmentRelation(value) => PipelineKey::AssignmentRelation(value.id.clone()),
            Self::ClassSetRow(value) => PipelineKey::ClassSetRow(value.id.clone()),
            Self::AbsentMemberFinding(value) => PipelineKey::AbsentMemberFinding(value.id.clone()),
            Self::DetachedTaskTransfer(value) => {
                PipelineKey::DetachedTaskTransfer(value.id.clone())
            }
            Self::ProcedureEffect(value) => PipelineKey::ProcedureEffect(value.row().id.clone()),
            Self::CallableSignature(value) => {
                PipelineKey::CallableSignature(value.report.signature.id.clone())
            }
            Self::LiteralOccurrence(value) => PipelineKey::LiteralOccurrence(value.row.id.clone()),
            Self::CallableMetrics(value) => {
                PipelineKey::CallableMetrics(value.declaration.site_id())
            }
            Self::SignatureParameter(value) => {
                PipelineKey::SignatureParameter(value.row().id.clone())
            }
            Self::DecoratedParameter(value) => {
                PipelineKey::DecoratedParameter(value.id().to_string())
            }
            Self::CallableApplicability(value) => {
                PipelineKey::CallableApplicability(value.row().id.clone())
            }
            Self::OverloadSelection(value) => {
                PipelineKey::OverloadSelection(value.row().id.clone())
            }
            Self::MemberSelection(value) => PipelineKey::MemberSelection(value.occurrence.ast_id()),
            Self::DispatchOutcome(value) => PipelineKey::DispatchOutcome(value.site_id.clone()),
            Self::DispatchTarget(value) => PipelineKey::DispatchTarget(value.id()),
            Self::MemberFamily(value) => PipelineKey::MemberFamily(value.id()),
            Self::MemberFamilyEdge(value) => PipelineKey::MemberFamilyEdge(value.id()),
            Self::PythonHierarchyFact(value) => PipelineKey::PythonHierarchyFact(value.id()),
            Self::Occurrence(value) => PipelineKey::Occurrence(value.key()),
            Self::LexicalScope(value) => PipelineKey::LexicalScope(value.key()),
            Self::GenerationSite(value) => PipelineKey::GenerationSite(value.key()),
            Self::Export(value) => PipelineKey::Export(value.key()),
            Self::DeclarationState(value) => PipelineKey::DeclarationState(value.key()),
            Self::Binding(value) => PipelineKey::Binding(value.key()),
            Self::ResolutionCandidate(value) => PipelineKey::ResolutionCandidate(value.key()),
            Self::CandidateHop(value) => PipelineKey::CandidateHop(value.key()),
            Self::ReferenceEdge(value) => PipelineKey::ReferenceEdge(value.key()),
            Self::StateEvent(value) => PipelineKey::StateEvent(value.key()),
            Self::BindingInitializerCall(value) => {
                PipelineKey::BindingInitializerCall(value.row.id.clone())
            }
            Self::FlowRelation(value) => PipelineKey::FlowRelation(value.key()),
            Self::ControlRelation(value) => PipelineKey::ControlRelation(value.key()),
            Self::BranchRelation(value) => PipelineKey::BranchRelation(value.key()),
            Self::LoopRelation(value) => PipelineKey::LoopRelation(value.row.id.clone()),
            Self::CppExpression(value) => PipelineKey::CppExpression(value.row.id.clone()),
            Self::FailureHandlerState(value) => PipelineKey::FailureHandlerState(value.key()),
            Self::StatementReachability(value) => {
                PipelineKey::StatementReachability(value.row.id.clone())
            }
            Self::PendingCleanupFlow(value) => {
                PipelineKey::PendingCleanupFlow(value.row.id.clone())
            }
            Self::PythonRuleFact(value) => PipelineKey::PythonRuleFact(value.row.id.clone()),
            Self::Guard(value) => PipelineKey::Guard(value.key()),
            Self::SourceSet(value) => PipelineKey::SourceSet(value.key()),
            Self::BuildTarget(value) => PipelineKey::BuildTarget(value.key()),
            Self::TopologyEdge(value) => PipelineKey::TopologyEdge(value.key()),
            Self::RewritePath(value) => PipelineKey::RewritePath(value.key()),
            Self::QualifiedPath(value) => PipelineKey::QualifiedPath(value.key()),
            Self::PathSegment(value) => PipelineKey::PathSegment(value.key()),
            Self::DependencyEvidence(value) => PipelineKey::DependencyEvidence(value.row.id()),
            Self::ConfigurationFact(value) => PipelineKey::ConfigurationFact(value.key()),
            Self::CrossDomain(value) => PipelineKey::CrossDomain(Box::new(value.key())),
        }
    }

    fn set_difference_key(&self) -> PipelineKey {
        match self {
            Self::Binding(value) => PipelineKey::Binding(value.set_difference_key()),
            _ => self.key(),
        }
    }
}

impl SemanticPipelineValue {
    fn key(&self) -> SemanticPipelineKey {
        match self {
            Self::Procedure(procedure) => SemanticPipelineKey::Procedure(procedure.handle.clone()),
            Self::ProcedureReference(value) => SemanticPipelineKey::ProcedureReference(Box::new(
                crate::analyzer::semantic::SemanticProcedureReference {
                    key: value.key.clone(),
                    locator: value.locator.clone(),
                },
            )),
            Self::ProgramPoint(point) => SemanticPipelineKey::ProgramPoint(point.handle.clone()),
            Self::ProgramPointReference(value) => {
                SemanticPipelineKey::ProgramPointReference(value.public.id.clone())
            }
            Self::ControlEdge(edge) => SemanticPipelineKey::ControlEdge(edge.handle.clone()),
            Self::ControlEdgeReference(value) => {
                SemanticPipelineKey::ControlEdgeReference(value.public.id.clone())
            }
            Self::CallResult(result) => SemanticPipelineKey::CallResult(result.public().id),
            Self::TypestateFinding(finding) => {
                SemanticPipelineKey::TypestateFinding(finding.key().to_string())
            }
            Self::TypestateWitness(witness) => {
                SemanticPipelineKey::TypestateWitness(witness.key().to_string())
            }
            Self::FlowEndpoint(endpoint) => {
                SemanticPipelineKey::FlowEndpoint(endpoint.key().to_string())
            }
            Self::FlowWitness(witness) => {
                SemanticPipelineKey::FlowWitness(witness.key().to_string())
            }
            Self::AbsentMemberWitness(witness) => {
                SemanticPipelineKey::AbsentMemberWitness(witness.key().to_string())
            }
            Self::TaintFinding(finding) => {
                SemanticPipelineKey::TaintFinding(finding.key().to_string())
            }
            Self::RustMarkerImpl(finding) => {
                SemanticPipelineKey::RustMarkerImpl(finding.row.id.clone())
            }
            Self::RustPointerFinding(finding) => {
                SemanticPipelineKey::RustPointerFinding(finding.row.id.clone())
            }
        }
    }

    fn file(&self) -> &ProjectFile {
        match self {
            Self::Procedure(value) => value.file(),
            Self::ProcedureReference(value) => &value.file,
            Self::ProgramPoint(value) => value.file(),
            Self::ProgramPointReference(value) => &value.procedure.file,
            Self::ControlEdge(value) => value.file(),
            Self::ControlEdgeReference(value) => &value.procedure.file,
            Self::CallResult(value) => value.file(),
            Self::TypestateFinding(value) => value.file(),
            Self::TypestateWitness(value) => value.file(),
            Self::FlowEndpoint(value) => value.file(),
            Self::FlowWitness(value) => value.file(),
            Self::AbsentMemberWitness(value) => value.file(),
            Self::TaintFinding(value) => value.file(),
            Self::RustMarkerImpl(value) => &value.file,
            Self::RustPointerFinding(value) => &value.file,
        }
    }

    fn public_result(self) -> CodeQueryResultValue {
        match self {
            Self::ProcedureReference(value) => CodeQueryResultValue::Procedure {
                value: value.public,
            },
            Self::Procedure(value) => CodeQueryResultValue::Procedure {
                value: value.public(),
            },
            Self::ProgramPointReference(value) => CodeQueryResultValue::ProgramPoint {
                value: value.public,
            },
            Self::ProgramPoint(value) => CodeQueryResultValue::ProgramPoint {
                value: value.public(),
            },
            Self::ControlEdgeReference(value) => CodeQueryResultValue::ControlEdge {
                value: Box::new(value.public),
            },
            Self::ControlEdge(value) => CodeQueryResultValue::ControlEdge {
                value: Box::new(value.public()),
            },
            Self::CallResult(value) => CodeQueryResultValue::CallResult {
                value: Box::new(value.public()),
            },
            Self::TypestateFinding(value) => CodeQueryResultValue::TypestateFinding {
                value: Box::new(value.public),
            },
            Self::TypestateWitness(value) => CodeQueryResultValue::TypestateWitness {
                value: Box::new(value.public),
            },
            Self::FlowEndpoint(value) => CodeQueryResultValue::FlowEndpoint {
                value: Box::new(value.public),
            },
            Self::FlowWitness(value) => CodeQueryResultValue::FlowWitness {
                value: Box::new(value.public),
            },
            Self::AbsentMemberWitness(value) => CodeQueryResultValue::AbsentMemberWitness {
                value: Box::new(value.public),
            },
            Self::TaintFinding(value) => CodeQueryResultValue::TaintFinding {
                value: Box::new(value.public),
            },
            Self::RustMarkerImpl(value) => CodeQueryResultValue::RustMarkerImpl {
                value: Box::new(value.row.clone()),
            },
            Self::RustPointerFinding(value) => CodeQueryResultValue::RustPointerFinding {
                value: Box::new(value.row.clone()),
            },
        }
    }

    fn public_ref(&self) -> CodeQueryResultRef {
        match self {
            Self::Procedure(value) => value.public_ref(),
            Self::ProcedureReference(value) => value.public_ref(),
            Self::ProgramPointReference(value) => CodeQueryResultRef::ProgramPoint {
                id: value.public.id.clone(),
                path: value.public.path.clone(),
                range: value.public.range,
                procedure_id: value.public.procedure_id.clone(),
                boundary: value.public.boundary,
            },
            Self::ProgramPoint(value) => value.public_ref(),
            Self::ControlEdgeReference(value) => CodeQueryResultRef::ControlEdge {
                id: value.public.id.clone(),
                path: value.public.path.clone(),
                range: value.public.range,
                edge_kind: value.public.edge_kind,
                procedure_id: value.public.procedure_id.clone(),
                source_id: value.public.source.id.clone(),
                target_id: value.public.target.id.clone(),
            },
            Self::ControlEdge(value) => value.public_ref(),
            Self::CallResult(value) => value.public_ref(),
            Self::TypestateFinding(value) => value.public_ref(),
            Self::TypestateWitness(value) => value.public_ref(),
            Self::FlowEndpoint(value) => value.public_ref(),
            Self::FlowWitness(value) => value.public_ref(),
            Self::AbsentMemberWitness(value) => value.public_ref(),
            Self::TaintFinding(value) => value.public_ref(),
            Self::RustMarkerImpl(value) => CodeQueryResultRef::RustMarkerImpl {
                id: value.row.id.clone(),
                path: value.row.path.clone(),
                range: value.row.range,
                relation: value.row.trait_kind,
            },
            Self::RustPointerFinding(value) => CodeQueryResultRef::RustPointerFinding {
                id: value.row.id.clone(),
                path: value.row.path.clone(),
                range: value.row.range,
                relation: value.row.relation,
            },
        }
    }

    fn detailed_projection(&self) -> DetailedSemanticProjection<'_> {
        match self {
            Self::ProcedureReference(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::Procedure,
                key: DetailedCodeQueryKey::Procedure {
                    id: value.public.id.clone(),
                },
                file: &value.file,
                byte_span: value.byte_span.clone(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::Procedure(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::Procedure,
                    key: DetailedCodeQueryKey::Procedure {
                        id: public.id.clone(),
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::ProgramPointReference(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::ProgramPoint,
                key: DetailedCodeQueryKey::ProgramPoint {
                    id: value.public.id.clone(),
                    procedure_id: value.public.procedure_id.clone(),
                },
                file: &value.procedure.file,
                byte_span: value.byte_span.clone(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::ProgramPoint(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::ProgramPoint,
                    key: DetailedCodeQueryKey::ProgramPoint {
                        id: public.id.clone(),
                        procedure_id: public.procedure_id,
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::ControlEdgeReference(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::ControlEdge,
                key: DetailedCodeQueryKey::ControlEdge {
                    id: value.public.id.clone(),
                    procedure_id: value.public.procedure_id.clone(),
                },
                file: &value.procedure.file,
                byte_span: value.byte_span.clone(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::ControlEdge(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::ControlEdge,
                    key: DetailedCodeQueryKey::ControlEdge {
                        id: public.id.clone(),
                        procedure_id: public.procedure_id,
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::CallResult(value) => {
                let public = value.public();
                DetailedSemanticProjection {
                    domain: DetailedCodeQueryDomain::CallResult,
                    key: DetailedCodeQueryKey::CallResult {
                        id: public.id.clone(),
                        site_id: public.site_id,
                    },
                    file: value.file(),
                    byte_span: value.byte_span(),
                    display_range: public.range,
                    language: public.language,
                    stable_id: public.id,
                }
            }
            Self::TypestateFinding(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::TypestateFinding,
                key: DetailedCodeQueryKey::TypestateFinding {
                    id: value.public.id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::TypestateWitness(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::TypestateWitness,
                key: DetailedCodeQueryKey::TypestateWitness {
                    id: value.public.id.clone(),
                    finding_id: value.public.finding_id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::FlowEndpoint(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::FlowEndpoint,
                key: DetailedCodeQueryKey::FlowEndpoint {
                    id: value.public.id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::FlowWitness(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::FlowWitness,
                key: DetailedCodeQueryKey::FlowWitness {
                    id: value.public.id.clone(),
                    endpoint_id: value.public.endpoint_id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::AbsentMemberWitness(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::AbsentMemberWitness,
                key: DetailedCodeQueryKey::AbsentMemberWitness {
                    id: value.public.id.clone(),
                    finding_id: value.public.finding_id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::TaintFinding(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::TaintFinding,
                key: DetailedCodeQueryKey::TaintFinding {
                    id: value.public.id.clone(),
                },
                file: value.file(),
                byte_span: value.byte_span(),
                display_range: value.public.range,
                language: value.public.language,
                stable_id: value.public.id.clone(),
            },
            Self::RustMarkerImpl(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::RustMarkerImpl,
                key: DetailedCodeQueryKey::RustMarkerImpl {
                    id: value.row.id.clone(),
                },
                file: &value.file,
                byte_span: value.byte_span.clone(),
                display_range: value.row.range,
                language: value.row.language,
                stable_id: value.row.id.clone(),
            },
            Self::RustPointerFinding(value) => DetailedSemanticProjection {
                domain: DetailedCodeQueryDomain::RustPointerFinding,
                key: DetailedCodeQueryKey::RustPointerFinding {
                    id: value.row.id.clone(),
                },
                file: &value.file,
                byte_span: value.byte_span.clone(),
                display_range: value.row.range,
                language: value.row.language,
                stable_id: value.row.id.clone(),
            },
        }
    }
}

#[derive(Debug, Clone)]
struct PipelineTrace {
    // Temporary ordering inside a grouped file-window step; cleared on return.
    window_order: Option<(usize, usize, usize)>,
    branch: Vec<usize>,
    seed: Arc<SeedMatch>,
    steps: Vec<PipelineTraceStep>,
}

#[derive(Debug, Clone)]
struct PipelineTraceStep {
    op: QueryStep,
    value: PipelineTraceValue,
    via: Option<PipelineVia>,
}

#[derive(Debug, Clone)]
struct SemanticTraceSnapshot {
    public: CodeQueryResultRef,
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: ProjectFile,
    byte_span: std::ops::Range<usize>,
    display_range: CodeQueryRange,
    language: &'static str,
    stable_id: String,
}

impl SemanticTraceSnapshot {
    fn of(value: &SemanticPipelineValue) -> Self {
        let projection = value.detailed_projection();
        Self {
            public: value.public_ref(),
            domain: projection.domain,
            key: projection.key,
            file: projection.file.clone(),
            byte_span: projection.byte_span,
            display_range: projection.display_range,
            language: projection.language,
            stable_id: projection.stable_id,
        }
    }
    fn file(&self) -> &ProjectFile {
        &self.file
    }
    fn public_ref(&self) -> CodeQueryResultRef {
        self.public.clone()
    }
    fn detailed_projection(&self) -> DetailedSemanticProjection<'_> {
        DetailedSemanticProjection {
            domain: self.domain,
            key: self.key.clone(),
            file: &self.file,
            byte_span: self.byte_span.clone(),
            display_range: self.display_range,
            language: self.language,
            stable_id: self.stable_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
enum PipelineTraceValue {
    StructuralMatch(Arc<SeedMatch>),
    Declaration(DeclarationValue),
    Semantic(Box<SemanticTraceSnapshot>),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    JsxAttributeValue(Box<JsxAttributeValue>),
    ReceiverAnalysis(ReceiverAnalysisValue),
    MemberTargetAnalysis(ReceiverAnalysisValue),
    ReceiverOutcome(ReceiverAnalysisValue),
    ReceiverEvidence(ReceiverEvidenceValue),
    PointsToCandidate(Box<PointsToCandidateValue>),
    FieldWriteValue(Box<FieldWriteValue>),
    RuntimeKeyedReadValue(Box<RuntimeKeyedReadValue>),
    CallShape(CallShapeValue),
    CallArgumentGroup(CallArgumentGroupValue),
    CallArgument(CallArgumentValue),
    CallBinding(Box<CallBindingValue>),
    CallEffect(Box<CallEffectValue>),
    CallResultContract(Box<CallResultContractValue>),
    CallResultObligation(Box<CallResultObligationValue>),
    ResultSubjectUse(Box<ResultSubjectUseValue>),
    ResultContractUse(Box<ResultContractUseValue>),
    ResultContractFailureUse(Box<ResultContractFailureUseValue>),
    NilnessOperation(Box<NilnessOperationValue>),
    SwitchCoverage(Box<SwitchCoverageValue>),
    AssignmentRelation(Box<AssignmentRelationValue>),
    ClassSetRow(Box<ClassSetRowValue>),
    AbsentMemberFinding(Box<AbsentMemberFindingValue>),
    DetachedTaskTransfer(Box<DetachedTaskTransferValue>),
    ProcedureEffect(Box<ProcedureEffectValue>),
    CallableSignature(Box<CallableSignatureValue>),
    LiteralOccurrence(LiteralOccurrenceValue),
    CallableMetrics(Box<CallableMetricsValue>),
    SignatureParameter(Box<SignatureParameterValue>),
    DecoratedParameter(DecoratedParameterValue),
    CallableApplicability(Box<CallableApplicabilityValue>),
    OverloadSelection(Box<OverloadSelectionValue>),
    MemberSelection(MemberSelectionValue),
    DispatchOutcome(Box<DispatchSiteValue>),
    DispatchTarget(Box<DispatchTargetValue>),
    MemberFamily(Box<MemberFamilyValue>),
    MemberFamilyEdge(Box<MemberFamilyEdgeValue>),
    PythonHierarchyFact(Box<PythonHierarchyFactValue>),
    Occurrence(OccurrenceValue),
    LexicalScope(ScopeValue),
    Binding(BindingValue),
    ResolutionCandidate(Box<CandidateValue>),
    CandidateHop(Box<CandidateHopValue>),
    GenerationSite(materialization::GenerationSiteValue),
    Export(materialization::ExportValue),
    DeclarationState(materialization::DeclarationStateValue),
    ReferenceEdge(Box<EdgeValue>),
    StateEvent(Box<StateEventValue>),
    BindingInitializerCall(Box<BindingInitializerCallValue>),
    FlowRelation(Box<FlowRelationValue>),
    ControlRelation(Box<ControlRelationValue>),
    BranchRelation(Box<BranchRelationValue>),
    LoopRelation(Box<LoopRelationValue>),
    CppExpression(Box<CppExpressionValue>),
    FailureHandlerState(Box<FailureHandlerStateValue>),
    StatementReachability(Box<StatementReachabilityValue>),
    PendingCleanupFlow(Box<PendingCleanupFlowValue>),
    PythonRuleFact(Box<PythonRuleFactValue>),
    Guard(Box<GuardValue>),
    SourceSet(Box<TopologyEntityValue>),
    BuildTarget(Box<TopologyEntityValue>),
    TopologyEdge(Box<TopologyEdgeValue>),
    RewritePath(Box<RewritePathValue>),
    QualifiedPath(PathValue),
    PathSegment(SegmentValue),
    ConfigurationFact(ConfigurationFactValue),
    CrossDomain(Box<CrossDomainValue>),
    DependencyEvidence(DependencyEvidenceValue),
}

#[derive(Debug, Clone)]
enum PipelineVia {
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
}

#[derive(Default)]
struct ReferenceTraversalCache {
    inbound: HashMap<CodeUnit, Vec<ReferenceHit>>,
    outbound: HashMap<ProjectFile, Vec<ReferenceHit>>,
    inbound_incomplete: HashSet<CodeUnit>,
    outbound_incomplete: HashSet<ProjectFile>,
    inbound_exhausted: HashSet<CodeUnit>,
    outbound_exhausted: HashSet<ProjectFile>,
    reported_inbound: HashSet<CodeUnit>,
}

#[derive(Default)]
struct CallTraversalCache {
    incoming: HashMap<CodeUnit, CallRelationResult>,
    outgoing: HashMap<CodeUnit, CallRelationResult>,
    reported_incoming: HashSet<CodeUnit>,
    reported_outgoing: HashSet<CodeUnit>,
    bindings: CallBindingCache,
    effects: EffectTraversalCache,
    /// Call sites whose suppressed-shape incompleteness has already been
    /// reported, keyed by `site_ast_id`. One site reached by many pipeline
    /// rows states its gap once (#1949).
    reported_suppressed_shapes: HashSet<String>,
}

impl CallTraversalCache {
    fn with_active_semantic_models(
        active_models: Option<Arc<crate::analyzer::semantic_model::ResolvedActiveSemanticModels>>,
        shared_call_target_outcomes: Option<
            crate::analyzer::usages::call_relations::CallTargetOutcomeCache,
        >,
    ) -> Self {
        Self {
            bindings: CallBindingCache::default()
                .with_shared_call_target_outcomes(shared_call_target_outcomes),
            effects: EffectTraversalCache::with_active_semantic_models(active_models),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
struct PipelineRow {
    value: PipelineValue,
    traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
    /// The visible-to-source field mapping established by terminal row
    /// projection steps. Empty means the row publishes its native schema.
    row_projection: Vec<QueryRowProjectionColumn>,
}

struct CachedSourceCoordinates {
    source: String,
    line_starts: Vec<usize>,
}

#[derive(Default)]
struct PipelineRenderCache {
    sources: HashMap<ProjectFile, Option<CachedSourceCoordinates>>,
    conflicting_sources: HashSet<ProjectFile>,
    declaration_ranges: HashMap<DeclarationValue, Option<CodeQueryRange>>,
    enclosing_units: HashMap<(ProjectFile, usize, usize), Option<CodeUnit>>,
    file_declarations: HashMap<ProjectFile, Vec<(CodeUnit, Vec<Range>)>>,
    source_loads_sealed: bool,
}

impl PipelineRenderCache {
    fn retain_source_snapshot(&mut self, file: &ProjectFile, source: &str) -> bool {
        if self.conflicting_sources.contains(file) {
            return false;
        }
        if let Some(existing) = self.sources.get(file) {
            match existing {
                Some(coordinates) if coordinates.source == source => return true,
                Some(_) => {
                    // Conflicting snapshots cannot support exact evidence or
                    // rendering. Retain the negative cache entry so a later
                    // renderer cannot silently hydrate a third source version.
                    self.sources.insert(file.clone(), None);
                    self.conflicting_sources.insert(file.clone());
                    return false;
                }
                None => {
                    // A held fact snapshot has already been charged by seed
                    // execution and may safely replace an earlier negative
                    // hydration entry.
                    self.sources.remove(file);
                }
            }
        }
        self.sources.insert(
            file.clone(),
            Some(CachedSourceCoordinates {
                line_starts: compute_line_starts(source),
                source: source.to_string(),
            }),
        );
        true
    }

    fn coordinates_for<F>(
        &mut self,
        file: &ProjectFile,
        load: F,
    ) -> Option<&CachedSourceCoordinates>
    where
        F: FnOnce() -> Option<String>,
    {
        if self.source_loads_sealed && !self.sources.contains_key(file) {
            // Sealed means "load no new source for this row", not "this file
            // has no source". Recording the refusal as a negative entry made
            // the budgeted retention of that same file later in the render
            // pass a no-op -- `retain_budgeted_source_snapshot` returns early
            // for any file the cache already holds an entry for -- so every
            // row of a file some earlier row's nested rendering happened to
            // probe rendered the fallback coordinates (column 1) instead of
            // its own. The refusal is about this probe, so it stays local to
            // it.
            return None;
        }
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                load().map(|source| CachedSourceCoordinates {
                    line_starts: compute_line_starts(&source),
                    source,
                })
            })
            .as_ref()
    }

    fn retain_loaded_source(&mut self, file: &ProjectFile, source: Option<String>) {
        self.sources.entry(file.clone()).or_insert_with(|| {
            source.map(|source| CachedSourceCoordinates {
                line_starts: compute_line_starts(&source),
                source,
            })
        });
    }

    fn seal_source_loads(&mut self) {
        self.source_loads_sealed = true;
    }

    fn source_snapshot(&self, file: &ProjectFile) -> Option<&str> {
        self.sources
            .get(file)
            .and_then(Option::as_ref)
            .map(|coordinates| coordinates.source.as_str())
    }

    fn range_for_declaration(
        &mut self,
        analyzer: &dyn IAnalyzer,
        declaration: &DeclarationValue,
    ) -> Option<CodeQueryRange> {
        if let Some(range) = self.declaration_ranges.get(declaration) {
            return *range;
        }

        let file = declaration.unit.source();
        let range = {
            self.coordinates_for(file, || analyzer.indexed_source(file))
                .map(|coordinates| {
                    range_for_offsets(
                        &coordinates.source,
                        &coordinates.line_starts,
                        declaration.range.start_byte,
                        declaration.range.end_byte,
                    )
                })
        };
        self.declaration_ranges.insert(declaration.clone(), range);
        range
    }

    fn enclosing_unit_for_lines(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        let cache_key = (file.clone(), start_line, end_line);
        if let Some(enclosing) = self.enclosing_units.get(&cache_key) {
            return enclosing.clone();
        }

        // A structural query commonly renders many matches from one source
        // file. Calling `enclosing_code_unit_for_lines` for every match
        // repeatedly clones and scans the full declaration set. Retain the
        // declaration ranges once for this render pass instead.
        let declarations = self
            .file_declarations
            .entry(file.clone())
            .or_insert_with(|| {
                analyzer
                    .declarations(file)
                    .into_iter()
                    .map(|code_unit| {
                        let ranges = analyzer.ranges(&code_unit);
                        (code_unit, ranges)
                    })
                    .collect()
            });
        let enclosing =
            brokk_bifrost_core::analyzer::code_unit_index::narrowest_enclosing_by_lines(
                declarations
                    .iter()
                    .map(|(code_unit, ranges)| (code_unit, ranges.iter().copied())),
                start_line,
                end_line,
            )
            .cloned();
        self.enclosing_units.insert(cache_key, enclosing.clone());
        enclosing
    }
}

/// Run `query` across every language provider the analyzer exposes.
pub fn execute(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResult {
    execute_with_limits(analyzer, query, CodeQueryExecutionLimits::default())
}

/// Run `query` with access to the generation-bound semantic-oracle facade.
/// Receiver traversal uses this entrypoint in product code; the analyzer-only
/// entrypoint remains available for callers that do not own a workspace.
pub fn execute_workspace(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    query: &CodeQuery,
) -> CodeQueryResult {
    execute_workspace_with_limits(
        workspace,
        flow_state,
        query,
        CodeQueryExecutionLimits::default(),
    )
}

/// Honor the query's root execution mode through the public Rust surface.
/// Ordinary callers that always want rows may continue to use [`execute`].
pub fn execute_request(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResponse {
    execute_request_with_limits(analyzer, query, CodeQueryExecutionLimits::default())
}

pub fn execute_request_with_limits(
    analyzer: &dyn IAnalyzer,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResponse {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    execute_request_internal(analyzer, token, None, None, query, limits, None, None)
}

/// Honor the query's root execution mode with access to generation-bound
/// semantic oracles for receiver traversal.
pub fn execute_workspace_request(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    query: &CodeQuery,
) -> CodeQueryResponse {
    execute_workspace_request_with_limits(
        workspace,
        flow_state,
        query,
        CodeQueryExecutionLimits::default(),
    )
}

pub fn execute_workspace_request_with_limits(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResponse {
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let token = scope.token();
    execute_request_internal(
        workspace.analyzer(),
        token,
        Some(workspace),
        Some(flow_state),
        query,
        limits,
        None,
        None,
    )
}

/// Execute against an immutable host registration snapshot.
///
/// The generation must be the same value captured in each registration. A
/// query-local capability context is created only for results/profile modes;
/// explain remains planning-only.
pub fn execute_workspace_request_with_registrations(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
) -> CodeQueryResponse {
    execute_workspace_request_with_registration_limits(
        workspace,
        flow_state,
        workspace_generation,
        registrations,
        query,
        CodeQueryExecutionLimits::default(),
    )
}

pub fn execute_workspace_request_with_registration_limits(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResponse {
    let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
    let taint_registrations = TaintResultRegistrationSet::default();
    execute_workspace_request_with_all_analysis_registrations(
        workspace,
        flow_state,
        workspace_generation,
        registrations,
        &value_flow_registrations,
        &taint_registrations,
        query,
        limits,
        None,
    )
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CodeQueryExecutionBudget {
    scanned_files: usize,
    scanned_source_bytes: usize,
    fact_nodes: usize,
    examined_references: usize,
    pipeline_rows: usize,
    provenance_steps: usize,
    retained_evidence_bytes: usize,
    import_files_resolved: usize,
    import_edges_resolved: usize,
}

impl CodeQueryExecutionBudget {
    fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_sub(earlier.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_sub(earlier.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_sub(earlier.fact_nodes),
            examined_references: self
                .examined_references
                .saturating_sub(earlier.examined_references),
            pipeline_rows: self.pipeline_rows.saturating_sub(earlier.pipeline_rows),
            provenance_steps: self
                .provenance_steps
                .saturating_sub(earlier.provenance_steps),
            retained_evidence_bytes: self
                .retained_evidence_bytes
                .saturating_sub(earlier.retained_evidence_bytes),
            import_files_resolved: self
                .import_files_resolved
                .saturating_sub(earlier.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_sub(earlier.import_edges_resolved),
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_add(other.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_add(other.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_add(other.fact_nodes),
            examined_references: self
                .examined_references
                .saturating_add(other.examined_references),
            pipeline_rows: self.pipeline_rows.saturating_add(other.pipeline_rows),
            provenance_steps: self.provenance_steps.saturating_add(other.provenance_steps),
            retained_evidence_bytes: self
                .retained_evidence_bytes
                .saturating_add(other.retained_evidence_bytes),
            import_files_resolved: self
                .import_files_resolved
                .saturating_add(other.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_add(other.import_edges_resolved),
        }
    }

    fn fair_lanes(self) -> [usize; 5] {
        [
            self.scanned_files,
            self.scanned_source_bytes,
            self.fact_nodes.saturating_add(self.examined_references),
            self.pipeline_rows.max(self.provenance_steps),
            self.retained_evidence_bytes,
        ]
    }
}

#[derive(Debug)]
struct FairSeedBudgetState {
    usage: Vec<CodeQueryExecutionBudget>,
    finished: Vec<bool>,
    failed: bool,
    ledger: SeedScanLedger,
}

/// Per-file charges already admitted against one query execution's budget.
///
/// Compatible union branches (same language and file scope, different match
/// predicates) revisit the same files; the source bytes are read and the
/// normalized facts extracted once, with every later visit served from the
/// provider memory cache. This ledger lets those later visits skip the
/// already-admitted per-file charges so one execution meters each file's
/// extraction once, while files a branch alone visits still pay full price.
/// Sequential execution keeps one ledger on `QueryExecutionState`; parallel
/// union branches share the one inside `FairSeedBudgetState`, where
/// check-admit-mark is atomic under the coordinator mutex.
#[derive(Debug, Default)]
struct SeedScanLedger {
    /// The file's `scanned_files` / `scanned_source_bytes` charge was
    /// admitted (either access mode).
    scanned: HashSet<(Language, ProjectFile)>,
    /// The file's complete fact-node count was admitted by a Scan-access
    /// seed. Indexed access never marks this: its candidate charges are
    /// branch-specific and stay per-branch.
    fully_charged: HashSet<(Language, ProjectFile)>,
}

#[derive(Debug)]
struct FairSeedBudgetCoordinator {
    base: CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    branch_count: usize,
    cancellation: Option<CancellationToken>,
    state: Mutex<FairSeedBudgetState>,
    changed: Condvar,
    wait_ns: AtomicU64,
    waiters: AtomicUsize,
}

#[derive(Debug, Clone)]
struct FairSeedBudgetLease {
    coordinator: Arc<FairSeedBudgetCoordinator>,
    branch: usize,
}

enum FairSeedBudgetAdmission {
    Admitted,
    Rejected(CodeQueryExecutionBudget),
    Cancelled,
}

/// Which per-file charge a shared admission covers in the [`SeedScanLedger`].
#[derive(Clone, Copy)]
enum SeedChargeLane {
    /// `scanned_files` / `scanned_source_bytes` for one file.
    Scanned,
    /// The complete fact-node count of one Scan-access file.
    FullFacts,
}

impl SeedChargeLane {
    fn set(self, ledger: &SeedScanLedger) -> &HashSet<(Language, ProjectFile)> {
        match self {
            Self::Scanned => &ledger.scanned,
            Self::FullFacts => &ledger.fully_charged,
        }
    }

    fn set_mut(self, ledger: &mut SeedScanLedger) -> &mut HashSet<(Language, ProjectFile)> {
        match self {
            Self::Scanned => &mut ledger.scanned,
            Self::FullFacts => &mut ledger.fully_charged,
        }
    }
}

enum FairSeedBudgetSharedAdmission {
    /// An earlier seed scan in this execution already admitted this file's
    /// charge; the caller must not raise its local budget.
    AlreadyCharged,
    Admitted,
    Rejected(CodeQueryExecutionBudget),
    Cancelled,
}

fn accumulated_seed_budget(
    base: CodeQueryExecutionBudget,
    usage: &[CodeQueryExecutionBudget],
) -> CodeQueryExecutionBudget {
    usage
        .iter()
        .copied()
        .fold(base, CodeQueryExecutionBudget::saturating_add)
}

impl FairSeedBudgetCoordinator {
    fn new(
        base: CodeQueryExecutionBudget,
        limits: CodeQueryExecutionLimits,
        branch_count: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<Self> {
        debug_assert!(branch_count >= 2);
        Arc::new(Self {
            base,
            limits,
            branch_count,
            cancellation: cancellation.cloned(),
            state: Mutex::new(FairSeedBudgetState {
                usage: vec![CodeQueryExecutionBudget::default(); branch_count],
                finished: vec![false; branch_count],
                failed: false,
                ledger: SeedScanLedger::default(),
            }),
            changed: Condvar::new(),
            wait_ns: AtomicU64::new(0),
            waiters: AtomicUsize::new(0),
        })
    }

    fn lease(self: &Arc<Self>, branch: usize) -> FairSeedBudgetLease {
        debug_assert!(branch < self.branch_count);
        FairSeedBudgetLease {
            coordinator: Arc::clone(self),
            branch,
        }
    }

    fn maximum_pipeline_rows(&self) -> usize {
        self.limits.max_pipeline_rows
    }

    fn limits_lanes(&self) -> [usize; 5] {
        [
            self.limits.max_scanned_files,
            self.limits.max_scanned_source_bytes,
            self.limits.max_fact_nodes,
            self.limits.max_pipeline_rows,
            self.limits.semantic.max_retained_bytes.min(8 * 1024 * 1024),
        ]
    }

    fn branch_allowance(&self, state: &FairSeedBudgetState, branch: usize) -> [usize; 5] {
        let base = self.base.fair_lanes();
        let limits = self.limits_lanes();
        let mut used = base;
        for earlier in 0..branch {
            let remaining = self.branch_count.saturating_sub(earlier).max(1);
            let earlier_allowance: [usize; 5] = std::array::from_fn(|lane| {
                limits[lane].saturating_sub(used[lane]).div_ceil(remaining)
            });
            let actual = state.usage[earlier].fair_lanes();
            for lane in 0..used.len() {
                used[lane] = used[lane].saturating_add(if state.finished[earlier] {
                    actual[lane]
                } else {
                    earlier_allowance[lane]
                });
            }
        }
        let remaining = self.branch_count.saturating_sub(branch).max(1);
        std::array::from_fn(|lane| limits[lane].saturating_sub(used[lane]).div_ceil(remaining))
    }

    fn global_projected(
        &self,
        state: &FairSeedBudgetState,
        branch: usize,
        local_delta: CodeQueryExecutionBudget,
    ) -> CodeQueryExecutionBudget {
        accumulated_seed_budget(self.base, &state.usage[..branch]).saturating_add(local_delta)
    }

    fn committed_budget(&self) -> CodeQueryExecutionBudget {
        let state = self.state.lock().expect("fair seed budget lock poisoned");
        accumulated_seed_budget(self.base, &state.usage)
    }

    fn wait_ns(&self) -> u64 {
        self.wait_ns.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn waiting_branches(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    fn fail(&self) {
        let mut state = self.state.lock().expect("fair seed budget lock poisoned");
        state.failed = true;
        self.changed.notify_all();
    }
}

impl FairSeedBudgetLease {
    fn budget_before_branch(&self) -> CodeQueryExecutionBudget {
        let state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        accumulated_seed_budget(self.coordinator.base, &state.usage[..self.branch])
    }

    fn admit(&self, projected_local: CodeQueryExecutionBudget) -> FairSeedBudgetAdmission {
        let local_delta = projected_local.saturating_sub(self.coordinator.base);
        let requested = local_delta.fair_lanes();
        let mut state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        loop {
            if state.failed {
                return FairSeedBudgetAdmission::Cancelled;
            }
            if self
                .coordinator
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                return FairSeedBudgetAdmission::Cancelled;
            }
            let allowance = self.coordinator.branch_allowance(&state, self.branch);
            if requested
                .iter()
                .zip(allowance)
                .all(|(requested, allowance)| *requested <= allowance)
            {
                state.usage[self.branch] = local_delta;
                return FairSeedBudgetAdmission::Admitted;
            }
            if state.finished[..self.branch]
                .iter()
                .all(|finished| *finished)
            {
                return FairSeedBudgetAdmission::Rejected(self.coordinator.global_projected(
                    &state,
                    self.branch,
                    local_delta,
                ));
            }
            let wait_started = Instant::now();
            self.coordinator.waiters.fetch_add(1, Ordering::AcqRel);
            let (next_state, _) = self
                .coordinator
                .changed
                .wait_timeout(state, Duration::from_millis(2))
                .expect("fair seed budget lock poisoned while waiting");
            self.coordinator.waiters.fetch_sub(1, Ordering::AcqRel);
            self.coordinator
                .wait_ns
                .fetch_add(elapsed_ns(wait_started), Ordering::Relaxed);
            state = next_state;
        }
    }

    /// [`Self::admit`] for a per-file charge shared across branches: checks
    /// the coordinator ledger, admits, and marks atomically under the
    /// coordinator mutex so concurrent branches cannot both charge one file.
    fn admit_shared(
        &self,
        lane: SeedChargeLane,
        key: &(Language, ProjectFile),
        projected_local: CodeQueryExecutionBudget,
    ) -> FairSeedBudgetSharedAdmission {
        let local_delta = projected_local.saturating_sub(self.coordinator.base);
        let requested = local_delta.fair_lanes();
        let mut state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        loop {
            // Re-check on every wake: another branch may have charged this
            // file while this one waited for allowance.
            if lane.set(&state.ledger).contains(key) {
                return FairSeedBudgetSharedAdmission::AlreadyCharged;
            }
            if state.failed {
                return FairSeedBudgetSharedAdmission::Cancelled;
            }
            if self
                .coordinator
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                return FairSeedBudgetSharedAdmission::Cancelled;
            }
            let allowance = self.coordinator.branch_allowance(&state, self.branch);
            if requested
                .iter()
                .zip(allowance)
                .all(|(requested, allowance)| *requested <= allowance)
            {
                state.usage[self.branch] = local_delta;
                lane.set_mut(&mut state.ledger).insert(key.clone());
                return FairSeedBudgetSharedAdmission::Admitted;
            }
            if state.finished[..self.branch]
                .iter()
                .all(|finished| *finished)
            {
                return FairSeedBudgetSharedAdmission::Rejected(self.coordinator.global_projected(
                    &state,
                    self.branch,
                    local_delta,
                ));
            }
            let wait_started = Instant::now();
            self.coordinator.waiters.fetch_add(1, Ordering::AcqRel);
            let (next_state, _) = self
                .coordinator
                .changed
                .wait_timeout(state, Duration::from_millis(2))
                .expect("fair seed budget lock poisoned while waiting");
            self.coordinator.waiters.fetch_sub(1, Ordering::AcqRel);
            self.coordinator
                .wait_ns
                .fetch_add(elapsed_ns(wait_started), Ordering::Relaxed);
            state = next_state;
        }
    }

    fn finish(&self, local_budget: CodeQueryExecutionBudget) {
        let mut state = self
            .coordinator
            .state
            .lock()
            .expect("fair seed budget lock poisoned");
        state.usage[self.branch] = local_budget.saturating_sub(self.coordinator.base);
        state.finished[self.branch] = true;
        self.coordinator.changed.notify_all();
    }
}

#[derive(Clone)]
struct CachedSeedExecution {
    rows: Vec<PipelineRow>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    truncated: bool,
    /// Whether the cached rows exhaust the seed relation, independently of
    /// whether an enclosing limit can still return a semantically complete
    /// response from a terminal-cap probe.
    complete: Option<bool>,
}

struct QueryExecutionState<'a> {
    analyzer: &'a dyn IAnalyzer,
    workspace: Option<&'a WorkspaceAnalyzer>,
    cancellation: Option<&'a CancellationToken>,
    /// Which files the seed scanners enumerate. Narrowed only by a unit
    /// execution; every derived-value expansion still sees the workspace.
    scope: CodeQueryExecutionScope<'a>,
    /// Languages in this run's seed-file inventory, independent of provider
    /// registration and of any branch's language or path filters.
    scanned_languages: HashSet<Language>,
    /// Physical node at which an opt-in expansion execution retains its exact
    /// source rows. `None` preserves all existing execution behavior.
    source_row_boundary: Option<PhysicalQueryNodeId>,
    /// Rows each plan operator emitted, indexed by its physical plan node.
    /// `max_step_outputs` is enforced per step and has no other counter.
    step_outputs: Vec<u64>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    budget: CodeQueryExecutionBudget,
    seed_cache: HashMap<String, CachedSeedExecution>,
    /// Per-file charges already admitted in this execution; parallel union
    /// branches use the coordinator's ledger through their lease instead.
    seed_scan_ledger: SeedScanLedger,
    indexed_declarations: IndexedDeclarations,
    reference_cache: ReferenceTraversalCache,
    call_cache: CallTraversalCache,
    call_binding_identity_request: call_binding::CallBindingIdentityRequest,
    occurrence_cache: OccurrenceTraversalCache,
    environment_cache: EnvironmentTraversalCache,
    materialization_cache: materialization::MaterializationTraversalCache,
    edge_cache: EdgeTraversalCache,
    flow_state_cache: FlowStateTraversalCache,
    control_relation_cache: ControlRelationTraversalCache,
    branch_relation_cache: BranchRelationTraversalCache,
    cpp_expression_cache: HashMap<
        ProjectFile,
        Arc<brokk_bifrost_core::analyzer::cpp_facts::CppExpressionSourceFacts>,
    >,
    cpp_class_fact_cache:
        HashMap<ProjectFile, Arc<brokk_bifrost_core::analyzer::cpp_facts::CppClassFactRows>>,
    cpp_class_declaration_cache: HashMap<
        ProjectFile,
        Arc<Vec<brokk_bifrost_core::analyzer::cpp_facts::CppDeclarationSourceFact>>,
    >,
    rust_marker_impls_cache: rust_marker_impls::RustMarkerImplsCache,
    /// Query-local callable metrics expansion results; never retained by the workspace.
    callable_metrics_cache: HashMap<
        ProjectFile,
        Option<
            Vec<(
                CodeUnit,
                brokk_bifrost_core::analyzer::cognitive_complexity::CallableMetrics,
            )>,
        >,
    >,
    failure_handler_state_cache: FailureHandlerStateCache,
    topology_cache: TopologyTraversalCache,
    rewrite_path_cache: RewritePathTraversalCache,
    path_cache: PathTraversalCache,
    configuration_cache: ConfigurationFactsTraversalCache,
    // Parallel seed branches retain separate domains and account for their own
    // work. A shared blocking initializer could cycle through fair budget waits.
    comparison_chain_operators: HashMap<ProjectFile, Arc<seeds::ComparisonChainOperators>>,
    receiver_facts: HashMap<ProjectFile, Arc<FileFacts>>,
    /// Reused for the full lifetime of this CodeQuery, including later
    /// receiver steps that resolve additional selected native sites.
    receiver_service: Option<ReceiverQueryService<'a>>,
    semantic: Option<SemanticQueryContext<'a>>,
    import_graph: Option<RequestLocalDirectImportGraph>,
    import_graph_content: Option<WorkspaceContentIdentity>,
    direct_import_layer: Option<Arc<DerivedLayer>>,
    direct_import_layer_content: Option<WorkspaceContentIdentity>,
    deferred_derived_builds: HashSet<DerivedLayerRequest>,
    cache_profile: Option<QueryCacheProfile>,
    profile: Option<QueryExecutionProfile>,
    retained_value_census: Option<QueryRetainedValueCensus>,
    structural_index_session: QueryStructuralIndexSession,
    access_mode: StructuralAccessMode,
    access_failure: Option<String>,
    parallel_seed_budget: Option<FairSeedBudgetLease>,
    scheduler_workers: usize,
}

#[derive(Clone, Copy)]
enum DirectImportAccess<'a> {
    RequestLocal(&'a RequestLocalDirectImportGraph),
    Snapshot(&'a DirectImportTopology),
    Persisted(&'a PersistedImportAdjacency),
}

impl DirectImportAccess<'_> {
    fn imports_of(&self, file: &ProjectFile) -> Option<Vec<ProjectFile>> {
        match self {
            Self::RequestLocal(graph) => {
                graph.supports_source(file).then(|| graph.imports_of(file))
            }
            Self::Snapshot(topology) => topology.imports_of(file),
            Self::Persisted(adjacency) => adjacency.by_file.get(file).cloned(),
        }
    }

    fn importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        match self {
            Self::RequestLocal(graph) => graph.importers_of(file),
            Self::Snapshot(topology) => topology.known_importers_of(file),
            Self::Persisted(adjacency) => adjacency.by_file.get(file).cloned().unwrap_or_default(),
        }
    }

    fn unsupported_languages(&self) -> Vec<Language> {
        match self {
            Self::RequestLocal(graph) => graph.unsupported_languages(),
            Self::Snapshot(topology) => topology.unsupported_languages(),
            Self::Persisted(_) => Vec::new(),
        }
    }
}

struct PlanExecution {
    rows: Vec<PipelineRow>,
    truncated: bool,
    cancelled: bool,
    /// An intermediate authored pipeline step exhausted its budget, so the
    /// remaining steps in that same suffix must not run.
    pipeline_halted: bool,
}

struct ParallelSeedBranchResult {
    execution: PlanExecution,
    diagnostics: Vec<CodeQueryDiagnostic>,
    seed_cache: HashMap<String, CachedSeedExecution>,
    cache_profile: Option<QueryCacheProfile>,
    operators: Vec<QueryOperatorProfile>,
    access_path: QueryAccessPathProfile,
    access_failure: Option<String>,
}

struct ParallelUnionExecution {
    execution: PlanExecution,
    input_rows: usize,
    rows_visited: usize,
    rows_discarded: Option<usize>,
    temporary_capacity_bytes_lower_bound: u64,
    operator_truncated: bool,
    dependency_wait_ns: u64,
    scheduling_overhead_ns: u64,
    merge_ns: u64,
}

#[doc(hidden)]
pub fn execute_with_limits(
    analyzer: &dyn IAnalyzer,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    execute_with_semantic_overlay(analyzer, query, |_| {
        execute_code_query_detailed(analyzer, query, limits, None).result
    })
}

#[doc(hidden)]
pub fn execute_workspace_with_limits(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    execute_with_semantic_overlay(workspace.analyzer(), query, |scope| {
        let token = scope.token();
        execute_internal_with_analysis(
            workspace.analyzer(),
            token,
            Some(workspace),
            Some(SemanticFlowResources::from_workspace_state(flow_state)),
            None,
            0,
            query,
            limits,
            None,
            None,
            false,
        )
        .result
    })
}

fn execute_with_semantic_overlay(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    execute: impl FnOnce(&AnalyzerQueryScope) -> CodeQueryResult,
) -> CodeQueryResult {
    let snapshot = analyzer.active_semantic_model_snapshot();
    let _semantic_model_scope =
        AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, snapshot);
    let mut result = execute(&_semantic_model_scope);
    augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
    result
}

/// Atomic result of the comparable selected-Java `edges_of` execution path.
///
/// Cancellation and generation drift deliberately carry no query result: the
/// selected inverse index and the rendered rows are one generation-bound
/// operation, so neither condition may expose a prefix.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub enum SelectedEdgesOfExecutionOutcome {
    Executed(CodeQueryResult),
    Cancelled,
    Stale,
}

/// Execute one explicitly Java-only query with `edges_of` acquisition backed
/// by the canonical selected-Java inverse index.
///
/// Parsing, planning, filtering, edge values, rendering, limits, and result
/// assembly are the ordinary RQL pipeline. Only the request-local inverse
/// provider injected into [`EdgeTraversalCache`] differs. A set composition
/// may feed a shared `edges_of` suffix, but `edges_of` inside a set branch is
/// rejected because the ordinary sequential-union retry does not transactionally
/// publish branch-local diagnostic deduplication state.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub fn execute_workspace_with_selected_edges_of<S>(
    workspace: &WorkspaceAnalyzer,
    _flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    query: &CodeQuery,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    catalog: &FactReferenceEdgeCatalog<'_>,
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    telemetry: &SelectedEdgesOfTelemetry,
) -> Result<SelectedEdgesOfExecutionOutcome, String>
where
    S: FactResolutionSource,
{
    if let Some(outcome) = selected_edges_of_entry_gate(query, cancellation)? {
        return Ok(outcome);
    }

    let analyzer = workspace.analyzer();
    let snapshot = analyzer.active_semantic_model_snapshot();
    let scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, snapshot);
    let token = scope.token();
    let expected_generation = catalog.generation();
    telemetry.record_build_attempt();
    let build_result = build_selected_reference_inverse_index(
        analyzer,
        selected,
        catalog,
        maximum_batch_size,
        cancellation,
    );
    if cancellation.is_cancelled() {
        telemetry.record_cancelled_build();
        return Ok(SelectedEdgesOfExecutionOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != expected_generation {
        telemetry.record_stale_build();
        return Ok(SelectedEdgesOfExecutionOutcome::Stale);
    }
    let build_outcome = match build_result {
        Ok(outcome) => outcome,
        Err(error) => {
            telemetry.record_failed_build();
            return Err(error.to_string());
        }
    };
    let index = match build_outcome {
        SelectedReferenceInverseIndexBuildOutcome::Complete(index) => {
            telemetry.record_complete_build(&index);
            index
        }
        SelectedReferenceInverseIndexBuildOutcome::Incomplete(index) => {
            telemetry.record_incomplete_build(&index);
            index
        }
        SelectedReferenceInverseIndexBuildOutcome::Cancelled => {
            telemetry.record_cancelled_build();
            return Ok(SelectedEdgesOfExecutionOutcome::Cancelled);
        }
        SelectedReferenceInverseIndexBuildOutcome::Stale => {
            telemetry.record_stale_build();
            return Ok(SelectedEdgesOfExecutionOutcome::Stale);
        }
    };
    let generation = index.generation();
    debug_assert_eq!(generation, expected_generation);
    if cancellation.is_cancelled() {
        return Ok(SelectedEdgesOfExecutionOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedEdgesOfExecutionOutcome::Stale);
    }

    let edge_cache = EdgeTraversalCache::with_selected_inverse(index, telemetry.clone());
    let mut result = execute_internal_with_analysis_strategy_and_edge_cache(
        analyzer,
        token,
        Some(workspace),
        None,
        0,
        query,
        CodeQueryExecutionLimits::default(),
        Some(cancellation),
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        benchmark_structural_access_mode(),
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        edge_cache,
    )
    .result;
    augment_public_result_with_semantic_overlay(analyzer, query, &mut result);

    Ok(selected_edges_of_publication_gate(
        analyzer,
        generation,
        cancellation,
        result,
    ))
}

#[cfg(any(test, feature = "test-support"))]
fn selected_edges_of_entry_gate(
    query: &CodeQuery,
    cancellation: &CancellationToken,
) -> Result<Option<SelectedEdgesOfExecutionOutcome>, String> {
    if cancellation.is_cancelled() {
        return Ok(Some(SelectedEdgesOfExecutionOutcome::Cancelled));
    }
    if !query_plan_has_explicit_java_only_seeds(&query.plan) {
        return Err(
            "selected-Java edges_of execution requires every query seed to name only the Java language explicitly"
                .to_string(),
        );
    }
    if query_plan_has_retryable_branch_local_edges_of(&query.plan) {
        return Err(
            "selected-Java edges_of execution requires set branches to feed a shared edges_of suffix; edges_of inside a set branch is unsupported"
                .to_string(),
        );
    }
    Ok(None)
}

#[cfg(any(test, feature = "test-support"))]
fn selected_edges_of_publication_gate(
    analyzer: &dyn IAnalyzer,
    generation: u64,
    cancellation: &CancellationToken,
    result: CodeQueryResult,
) -> SelectedEdgesOfExecutionOutcome {
    if cancellation.is_cancelled() || matches!(result.completion(), CodeQueryCompletion::Cancelled)
    {
        return SelectedEdgesOfExecutionOutcome::Cancelled;
    }
    if analyzer.project().analysis_generation() != generation {
        return SelectedEdgesOfExecutionOutcome::Stale;
    }
    SelectedEdgesOfExecutionOutcome::Executed(result)
}

#[cfg(any(test, feature = "test-support"))]
fn query_plan_has_explicit_java_only_seeds(plan: &CodeQueryPlan) -> bool {
    fn explicit_java_only(languages: &[Language]) -> bool {
        !languages.is_empty() && languages.iter().all(|language| *language == Language::Java)
    }

    match &plan.source {
        CodeQueryPlanSource::Seed(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::Occurrences(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::Scopes(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::Bindings(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::Paths(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::GenerationSites(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::Exports(seed) => explicit_java_only(&seed.languages),
        CodeQueryPlanSource::DependencyEvidence(_)
        | CodeQueryPlanSource::ConfigurationFacts(_)
        | CodeQueryPlanSource::Correlate(_)
        | CodeQueryPlanSource::RequireBoth(_) => false,
        CodeQueryPlanSource::Set { branches, .. } => {
            !branches.is_empty() && branches.iter().all(query_plan_has_explicit_java_only_seeds)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn query_plan_has_retryable_branch_local_edges_of(plan: &CodeQueryPlan) -> bool {
    fn subtree_has_edges_of(plan: &CodeQueryPlan) -> bool {
        plan.steps
            .iter()
            .any(|step| matches!(step, QueryStep::EdgesOf(_)))
            || match &plan.source {
                CodeQueryPlanSource::Set { branches, .. } => {
                    branches.iter().any(subtree_has_edges_of)
                }
                CodeQueryPlanSource::Seed(_)
                | CodeQueryPlanSource::Occurrences(_)
                | CodeQueryPlanSource::Scopes(_)
                | CodeQueryPlanSource::Bindings(_)
                | CodeQueryPlanSource::Paths(_)
                | CodeQueryPlanSource::GenerationSites(_)
                | CodeQueryPlanSource::Exports(_)
                | CodeQueryPlanSource::DependencyEvidence(_)
                | CodeQueryPlanSource::ConfigurationFacts(_)
                | CodeQueryPlanSource::Correlate(_)
                | CodeQueryPlanSource::RequireBoth(_) => false,
            }
    }

    match &plan.source {
        CodeQueryPlanSource::Set { branches, .. } => branches.iter().any(subtree_has_edges_of),
        CodeQueryPlanSource::Seed(_)
        | CodeQueryPlanSource::Occurrences(_)
        | CodeQueryPlanSource::Scopes(_)
        | CodeQueryPlanSource::Bindings(_)
        | CodeQueryPlanSource::Paths(_)
        | CodeQueryPlanSource::GenerationSites(_)
        | CodeQueryPlanSource::Exports(_)
        | CodeQueryPlanSource::DependencyEvidence(_)
        | CodeQueryPlanSource::ConfigurationFacts(_)
        | CodeQueryPlanSource::Correlate(_)
        | CodeQueryPlanSource::RequireBoth(_) => false,
    }
}

#[cfg(test)]
fn execute_workspace_with_selected_inverse_index_for_test(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    index: SelectedReferenceInverseIndex,
    telemetry: &SelectedEdgesOfTelemetry,
) -> CodeQueryResult {
    let analyzer = workspace.analyzer();
    let snapshot = analyzer.active_semantic_model_snapshot();
    let scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, snapshot);
    let token = scope.token();
    let edge_cache = EdgeTraversalCache::with_selected_inverse(index, telemetry.clone());
    let mut result = execute_internal_with_analysis_strategy_and_edge_cache(
        analyzer,
        token,
        Some(workspace),
        None,
        0,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        benchmark_structural_access_mode(),
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        edge_cache,
    )
    .result;
    augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
    result
}

/// Execute a mode-aware query with explicit limits and cooperative cancellation.
///
/// Unlike protocol surfaces that translate cancellation into their own error
/// response, a profiled Rust request returns its cancellation observations and
/// cancellation-safe partial result to the caller.
pub fn execute_request_with_cancellation(
    analyzer: &dyn IAnalyzer,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResponse {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    execute_request_internal(
        analyzer,
        token,
        None,
        None,
        query,
        limits,
        Some(cancellation),
        None,
    )
}

/// Execute a mode-aware workspace query with explicit limits and cooperative
/// cancellation. Explain mode remains planning-only and does not inspect the
/// workspace.
pub fn execute_workspace_request_with_cancellation(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResponse {
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let token = scope.token();
    execute_request_internal(
        workspace.analyzer(),
        token,
        Some(workspace),
        Some(flow_state),
        query,
        limits,
        Some(cancellation),
        None,
    )
}

pub fn execute_workspace_request_with_registration_cancellation(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResponse {
    let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
    let taint_registrations = TaintResultRegistrationSet::default();
    execute_workspace_request_with_all_analysis_registrations(
        workspace,
        flow_state,
        workspace_generation,
        registrations,
        &value_flow_registrations,
        &taint_registrations,
        query,
        limits,
        Some(cancellation),
    )
}

/// Execute with caller-owned reusable flow state and typestate registrations.
pub fn execute_workspace_request_with_registrations_and_limits(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> CodeQueryResponse {
    let value_flow_registrations = ValueFlowPlanRegistrationSet::default();
    execute_workspace_request_with_analysis_registrations(
        workspace,
        flow_state,
        workspace_generation,
        registrations,
        &value_flow_registrations,
        query,
        limits,
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_workspace_request_with_analysis_registrations(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    value_flow_registrations: &ValueFlowPlanRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> CodeQueryResponse {
    let taint_registrations = TaintResultRegistrationSet::default();
    execute_workspace_request_with_all_analysis_registrations(
        workspace,
        flow_state,
        workspace_generation,
        registrations,
        value_flow_registrations,
        &taint_registrations,
        query,
        limits,
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_workspace_request_with_all_analysis_registrations(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    workspace_generation: u64,
    registrations: &ProtocolRegistrationSet,
    value_flow_registrations: &ValueFlowPlanRegistrationSet,
    taint_registrations: &TaintResultRegistrationSet,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> CodeQueryResponse {
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let token = scope.token();
    execute_request_internal(
        workspace.analyzer(),
        token,
        Some(workspace),
        Some(flow_state),
        query,
        limits,
        cancellation,
        Some((
            workspace_generation,
            registrations,
            value_flow_registrations,
            taint_registrations,
        )),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_request_internal(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    registrations: Option<(
        u64,
        &ProtocolRegistrationSet,
        &ValueFlowPlanRegistrationSet,
        &TaintResultRegistrationSet,
    )>,
) -> CodeQueryResponse {
    let active_semantic_model_snapshot = analyzer.active_semantic_model_snapshot();
    let _semantic_model_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        analyzer,
        active_semantic_model_snapshot,
    );
    if query_plan_requires_typestate(&query.plan) && !limits.typestate.is_valid() {
        return CodeQueryResponse::Results(invalid_plan_result(
            session_subset(analyzer),
            "typestate execution limits must be positive and no greater than their hard maxima",
        ));
    }
    if query_plan_requires_value_flow(&query.plan) && !limits.value_flow.is_valid() {
        return CodeQueryResponse::Results(invalid_plan_result(
            session_subset(analyzer),
            "value-flow execution limits must be positive and no greater than their hard maxima",
        ));
    }
    if query_plan_requires_taint(&query.plan) && !limits.taint.is_valid() {
        return CodeQueryResponse::Results(invalid_plan_result(
            session_subset(analyzer),
            "taint projection limits must be positive and no greater than their hard maxima",
        ));
    }
    let analysis_context = if query.execution_mode == CodeQueryExecutionMode::Explain {
        None
    } else if let (
        Some(workspace),
        Some((workspace_generation, registrations, value_flow_registrations, taint_registrations)),
    ) = (workspace, registrations)
    {
        let requested = requested_protocol_refs(&query.plan);
        let requested_value_flows = requested_value_flow_refs(&query.plan);
        let requested_taint_results = requested_taint_result_refs(&query.plan);
        let summaries = flow_state
            .expect("workspace query execution requires host-owned flow state")
            .typestate_summaries();
        match QueryAnalysisContext::new_with_all_registrations_and_summaries(
            workspace,
            workspace_generation,
            registrations,
            &requested,
            value_flow_registrations,
            &requested_value_flows,
            taint_registrations,
            &requested_taint_results,
            QueryAnalysisValidationLimits::new(
                limits.semantic.max_materialized_files,
                limits.semantic.max_source_bytes,
            ),
            cancellation,
            summaries,
        ) {
            Ok(context) => Some(context),
            Err(error) => {
                return CodeQueryResponse::Results(query_analysis_context_error_result(
                    session_subset(analyzer),
                    error,
                ));
            }
        }
    } else {
        None
    };
    let semantic_flow_resources = flow_state.map(SemanticFlowResources::from_workspace_state);
    let workspace_generation = registrations.map_or(0, |(generation, _, _, _)| generation);
    match query.execution_mode {
        CodeQueryExecutionMode::Results => {
            let mut result = execute_internal_with_analysis(
                analyzer,
                token,
                workspace,
                semantic_flow_resources.clone(),
                analysis_context.as_ref(),
                workspace_generation,
                query,
                limits,
                cancellation,
                None,
                false,
            )
            .result;
            augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
            CodeQueryResponse::Results(result)
        }
        CodeQueryExecutionMode::Explain => match select_physical_plan(
            query,
            UnionExecutionStrategy::Auto,
            CODE_QUERY_SCHEDULER_WORKERS,
            0,
        ) {
            Ok(physical_plan) => {
                // The measured production Auto policy is sequential. Explain
                // performs only lowering and physical selection: it does not
                // construct an analyzer query scope or touch workspace data.
                CodeQueryResponse::Explain(
                    physical_plan.public_explain(query, CODE_QUERY_SCHEDULER_WORKERS),
                )
            }
            Err(error) => {
                CodeQueryResponse::Results(invalid_plan_result(session_subset(analyzer), error))
            }
        },
        CodeQueryExecutionMode::Profile => {
            let detailed = execute_internal_with_analysis(
                analyzer,
                token,
                workspace,
                semantic_flow_resources,
                analysis_context.as_ref(),
                workspace_generation,
                query,
                limits,
                cancellation,
                None,
                true,
            );
            let DetailedCodeQueryResult {
                mut result,
                profile,
                ..
            } = detailed;
            augment_public_result_with_semantic_overlay(analyzer, query, &mut result);
            match profile {
                Some(profile) => CodeQueryResponse::Profile(Box::new(
                    CodeQueryProfile::from_internal(query, result, profile),
                )),
                // Programmatically constructed invalid plans retain the
                // existing typed diagnostic instead of panicking while a
                // decoded request always reaches the profiled branch above.
                None => CodeQueryResponse::Results(result),
            }
        }
    }
}

pub fn execute_code_query_detailed(
    analyzer: &dyn IAnalyzer,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    execute_internal(analyzer, None, query, limits, cancellation, None, false)
}

/// `execute_code_query_detailed` for callers that will run a batch of queries
/// against the same snapshot: builds the snapshot structural index on first
/// use instead of deferring it to a later request.
pub fn execute_code_query_detailed_eager_index(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index_in_scope(
        analyzer,
        flow_state,
        query,
        limits,
        cancellation,
        CodeQueryExecutionScope::whole_workspace(),
    )
}

/// Eager structural execution over an explicit query execution scope.
///
/// `CodeQueryExecutionScope::whole_workspace()` preserves the behavior of the
/// historical whole-workspace entry point. A narrowed scope restricts seed
/// enumeration while retaining the scope's full workspace file set for
/// dependency and provider lookups.
pub fn execute_code_query_detailed_eager_index_in_scope(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    execution_scope: CodeQueryExecutionScope<'_>,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        None,
        Some(flow_state.into()),
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        execution_scope,
        None,
    )
}

/// Eager structural execution that reuses complete row-family products across
/// an explicitly bounded caller batch.
#[doc(hidden)]
pub fn execute_code_query_detailed_eager_index_with_row_family_session(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    row_family_session: &mut CodeQueryRowFamilySession,
) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index_with_row_family_session_in_scope(
        analyzer,
        flow_state,
        query,
        limits,
        cancellation,
        row_family_session,
        CodeQueryExecutionScope::whole_workspace(),
    )
}

/// Eager structural execution with shared row-family products over an exact
/// seed-file scope.
#[doc(hidden)]
pub fn execute_code_query_detailed_eager_index_with_row_family_session_in_scope(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    row_family_session: &mut CodeQueryRowFamilySession,
    execution_scope: CodeQueryExecutionScope<'_>,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    let stores = row_family_session.stores(analyzer, OccurrenceDerivationOptions::IDENTITY_ONLY);
    execute_internal_with_analysis_strategy_and_row_family_session(
        analyzer,
        token,
        None,
        Some(flow_state.into()),
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        Some(stores),
        None,
        None,
        execution_scope,
        None,
        EdgeTraversalCache::default(),
    )
}

/// `execute_code_query_detailed_eager_index` for a caller that reads each
/// occurrence row's identity, role and position but never its resolved target.
///
/// The definition batch is one resolution per reference-class row and is the
/// dominant cost of deriving a large file's occurrences. A consumer that joins
/// captures to rows by AST identity -- an assertion policy's row families --
/// needs none of it, and rows come back carrying
/// `CodeQueryOccurrenceTarget::NotDerived` so the omission is stated rather
/// than mistaken for an unresolved reference.
pub fn execute_code_query_detailed_eager_index_without_targets(
    analyzer: &dyn IAnalyzer,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        None,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        CodeQueryExecutionScope::whole_workspace(),
        None,
    )
}

/// Identity-only eager structural execution that reuses complete row-family
/// products across an explicitly bounded caller batch.
#[doc(hidden)]
pub fn execute_code_query_detailed_eager_index_without_targets_with_row_family_session(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    row_family_session: &mut CodeQueryRowFamilySession,
) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index_without_targets_with_row_family_session_in_scope(
        analyzer,
        query,
        limits,
        cancellation,
        row_family_session,
        CodeQueryExecutionScope::whole_workspace(),
    )
}

/// Identity-only eager structural execution with shared row-family products
/// over an exact seed-file scope.
#[doc(hidden)]
pub fn execute_code_query_detailed_eager_index_without_targets_with_row_family_session_in_scope(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    row_family_session: &mut CodeQueryRowFamilySession,
    execution_scope: CodeQueryExecutionScope<'_>,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    let stores = row_family_session.stores(analyzer, OccurrenceDerivationOptions::IDENTITY_ONLY);
    execute_internal_with_analysis_strategy_and_row_family_session(
        analyzer,
        token,
        None,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        Some(stores),
        None,
        None,
        execution_scope,
        None,
        EdgeTraversalCache::default(),
    )
}

/// `execute_code_query_detailed_eager_index` with the generation-bound
/// workspace semantic services attached.
///
/// A relational assertion binding that expands into a semantic row family
/// (the #1477 dispatch rows) needs the workspace oracles; without them the
/// step reports `SemanticWorkspaceRequired` and the plan is invalid.
pub fn execute_code_query_detailed_eager_index_workspace(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,

    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index_workspace_in_scope(
        workspace,
        flow_state,
        query,
        limits,
        cancellation,
        CodeQueryExecutionScope::whole_workspace(),
    )
}

/// Eager workspace-backed structural execution over an explicit query
/// execution scope.
pub fn execute_code_query_detailed_eager_index_workspace_in_scope(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    execution_scope: CodeQueryExecutionScope<'_>,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    execute_internal_with_analysis_strategy(
        workspace.analyzer(),
        token,
        Some(workspace),
        Some(flow_state.into()),
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        execution_scope,
        None,
    )
}

/// Execute a full source query plus an appended expansion suffix against an
/// exact set of source rows produced by the source query.
///
/// This is a query-specific policy seam. The source rows are matched at the
/// physical source-prefix boundary using structured detailed evidence, then
/// the suffix continues through the ordinary eager executor. Existing callers
/// leave this selection unset and retain their whole-workspace behavior.
#[doc(hidden)]
pub fn execute_code_query_expansion(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    source_steps: usize,
    source_rows: &[DetailedCodeQueryEvidence],
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    assert!(
        source_steps <= query.plan.steps.len(),
        "source step count must be a prefix of the full query plan"
    );
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        workspace,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        CodeQueryExecutionScope::for_source_rows(
            query.plan.steps.len() - source_steps,
            source_rows,
        ),
        None,
    )
}

/// Workspace-backed detailed execution for a coordinator that continues
/// semantic analysis after consuming the query rows.
///
/// The ordinary detailed entry point intentionally releases windowed
/// artifacts. This opt-in form snapshots the parent semantic and execution
/// ledgers, then runs independently bounded children in the same logical
/// scope. The semantic child's exact additive limits come from the
/// coordinator's parent ledger; `limits.semantic.max_retained_bytes` remains
/// the separate physical cap over the deduplicated union of parent leases,
/// active source windows, and successful result-contract dependencies. A
/// nested query can therefore charge only repeat lookup work for an artifact
/// or file the parent already paid, and returns a one-shot charge plus the
/// exact complete allocations behind policy-relevant rows. The coordinator
/// must import performed work before atomically promoting or dropping those
/// allocations.
///
/// `execution_scope` narrows the seed enumeration exactly as it does for
/// [`execute_code_query_unit`]: a policy compiling one selector per seed file
/// passes that file, and every whole-workspace caller passes
/// [`CodeQueryExecutionScope::whole_workspace`] and executes byte for byte as
/// it always has.
#[allow(clippy::too_many_arguments)]
pub fn execute_code_query_detailed_eager_index_workspace_with_semantic_receipt(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    root_allotment: CodeQueryRootAllotment,
    cancellation: Option<&CancellationToken>,
    parent_semantic: &SemanticBudget,
    parent_execution: &SemanticExecutionBudget,
    artifact_leases: SemanticArtifactLeaseSnapshot,
    execution_scope: CodeQueryExecutionScope<'_>,
) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_core(
        workspace,
        flow_state,
        query,
        limits,
        root_allotment,
        cancellation,
        parent_semantic,
        parent_execution,
        artifact_leases,
        execution_scope,
        None,
    )
}

/// Eager workspace query execution that also reuses complete occurrence and
/// lexical-environment row families across one explicitly bounded selector
/// compilation.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_and_row_family_session(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    root_allotment: CodeQueryRootAllotment,
    cancellation: Option<&CancellationToken>,
    parent_semantic: &SemanticBudget,
    parent_execution: &SemanticExecutionBudget,
    artifact_leases: SemanticArtifactLeaseSnapshot,
    execution_scope: CodeQueryExecutionScope<'_>,
    row_family_session: &mut CodeQueryRowFamilySession,
) -> DetailedCodeQueryResult {
    execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_core(
        workspace,
        flow_state,
        query,
        limits,
        root_allotment,
        cancellation,
        parent_semantic,
        parent_execution,
        artifact_leases,
        execution_scope,
        Some(row_family_session),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_core(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    root_allotment: CodeQueryRootAllotment,
    cancellation: Option<&CancellationToken>,
    parent_semantic: &SemanticBudget,
    parent_execution: &SemanticExecutionBudget,
    artifact_leases: SemanticArtifactLeaseSnapshot,
    execution_scope: CodeQueryExecutionScope<'_>,
    row_family_session: Option<&mut CodeQueryRowFamilySession>,
) -> DetailedCodeQueryResult {
    let parent_scope = parent_semantic.scope_snapshot();
    let (execution_before, execution_child) =
        parent_execution.fork_with_materialized_file_limit(limits.semantic.max_materialized_files);
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let token = scope.token();
    let access_mode = eager_structural_access_mode();
    let row_family_stores = row_family_session.map(|session| {
        session.stores(
            workspace.analyzer(),
            OccurrenceDerivationOptions::IDENTITY_ONLY,
        )
    });
    execute_internal_with_analysis_strategy_and_row_family_session(
        workspace.analyzer(),
        token,
        Some(workspace),
        Some(flow_state.into()),
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        row_family_stores,
        Some(SemanticQueryContinuation {
            parent_scope,
            child_semantic_limits: parent_semantic.remaining(),
            root_allotment,
            execution_before,
            execution_child,
            artifact_leases,
        }),
        None,
        execution_scope,
        None,
        EdgeTraversalCache::default(),
    )
}

struct SemanticQueryContinuation {
    parent_scope: SemanticBudgetScopeSnapshot,
    child_semantic_limits: crate::analyzer::semantic::SemanticWork,
    root_allotment: type_flow::CodeQueryRootAllotment,
    execution_before: SemanticExecutionBudgetSnapshot,
    execution_child: SemanticExecutionBudget,
    artifact_leases: SemanticArtifactLeaseSnapshot,
}

/// Internal opt-in profile entry point used by the M2 measurement harness.
/// Public query surfaces remain unchanged until the explicit M5 rollout.
#[cfg(test)]
pub(crate) fn execute_code_query_profiled(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> DetailedCodeQueryResult {
    execute_internal(analyzer, None, query, limits, None, None, true)
}

/// M4 benchmark/test entry point. A forced strategy still passes through the
/// same semantic eligibility gate as production; unsafe shapes stay serial.
#[cfg(test)]
pub(crate) fn execute_code_query_with_union_strategy(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    strategy: UnionExecutionStrategy,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        None,
        None,
        None,
        0,
        query,
        limits,
        None,
        None,
        capture_profile,
        strategy,
        CODE_QUERY_SCHEDULER_WORKERS,
        StructuralAccessMode::Auto,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        CodeQueryExecutionScope::whole_workspace(),
        None,
    )
}

#[cfg(test)]
pub(crate) fn execute_code_query_with_access_mode(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    mode: StructuralAccessMode,
    capture_profile: bool,
) -> Result<DetailedCodeQueryResult, String> {
    let mut failure = None;
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let detailed = execute_internal_with_analysis_strategy(
        analyzer,
        token,
        None,
        None,
        None,
        0,
        query,
        limits,
        None,
        None,
        capture_profile,
        UnionExecutionStrategy::Sequential,
        CODE_QUERY_SCHEDULER_WORKERS,
        mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        Some(&mut failure),
        CodeQueryExecutionScope::whole_workspace(),
        None,
    );
    match failure {
        Some(failure) => Err(failure),
        None => Ok(detailed),
    }
}

#[cfg(test)]
pub(crate) fn execute_with_cancellation(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResult {
    execute_code_query_detailed(analyzer, query, limits, Some(cancellation)).result
}

#[cfg(test)]
fn execute_with_receiver_budget_for_test(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    receiver_budget: ReceiverAnalysisBudget,
) -> CodeQueryResult {
    execute_internal(
        analyzer,
        None,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        Some(receiver_budget),
        false,
    )
    .result
}

fn execute_internal(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    execute_internal_with_analysis(
        analyzer,
        token,
        workspace,
        None,
        None,
        0,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_internal_with_analysis(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic_flow_resources: Option<SemanticFlowResources>,
    analysis_context: Option<&QueryAnalysisContext>,
    workspace_generation: u64,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        workspace,
        semantic_flow_resources,
        analysis_context,
        workspace_generation,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        benchmark_structural_access_mode(),
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        CodeQueryExecutionScope::whole_workspace(),
        None,
    )
}

fn benchmark_structural_access_mode() -> StructuralAccessMode {
    match std::env::var(BENCHMARK_ACCESS_MODE_ENV).as_deref() {
        Ok("scan_only") => StructuralAccessMode::ScanOnly,
        _ => StructuralAccessMode::Auto,
    }
}

fn eager_structural_access_mode() -> StructuralAccessMode {
    match benchmark_structural_access_mode() {
        StructuralAccessMode::ScanOnly => StructuralAccessMode::ScanOnly,
        _ => StructuralAccessMode::EagerAuto,
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn execute_internal_with_strategy(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
    union_strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    access_mode: StructuralAccessMode,
    access_failure_out: Option<&mut Option<String>>,
) -> DetailedCodeQueryResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    execute_internal_with_analysis_strategy_and_edge_cache(
        analyzer,
        token,
        workspace,
        None,
        0,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
        union_strategy,
        scheduler_workers,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        access_failure_out,
        EdgeTraversalCache::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_internal_with_analysis_strategy(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic_flow_resources: Option<SemanticFlowResources>,
    analysis_context: Option<&QueryAnalysisContext>,
    workspace_generation: u64,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
    union_strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    access_mode: StructuralAccessMode,
    occurrence_options: OccurrenceDerivationOptions,
    semantic_continuation: Option<SemanticQueryContinuation>,
    access_failure_out: Option<&mut Option<String>>,
    scope: CodeQueryExecutionScope<'_>,
    row_keys_out: Option<&mut Vec<UnitRowKey>>,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis_strategy_and_row_family_session(
        analyzer,
        token,
        workspace,
        semantic_flow_resources,
        analysis_context,
        workspace_generation,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
        union_strategy,
        scheduler_workers,
        access_mode,
        occurrence_options,
        None,
        semantic_continuation,
        access_failure_out,
        scope,
        row_keys_out,
        EdgeTraversalCache::default(),
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-support"))]
fn execute_internal_with_analysis_strategy_and_edge_cache(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    workspace: Option<&WorkspaceAnalyzer>,
    analysis_context: Option<&QueryAnalysisContext>,
    workspace_generation: u64,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
    union_strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    access_mode: StructuralAccessMode,
    occurrence_options: OccurrenceDerivationOptions,
    semantic_continuation: Option<SemanticQueryContinuation>,
    access_failure_out: Option<&mut Option<String>>,
    edge_cache: EdgeTraversalCache,
) -> DetailedCodeQueryResult {
    execute_internal_with_analysis_strategy_and_row_family_session(
        analyzer,
        token,
        workspace,
        None,
        analysis_context,
        workspace_generation,
        query,
        limits,
        cancellation,
        receiver_budget_override,
        capture_profile,
        union_strategy,
        scheduler_workers,
        access_mode,
        occurrence_options,
        None,
        semantic_continuation,
        access_failure_out,
        CodeQueryExecutionScope::whole_workspace(),
        None,
        edge_cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_internal_with_analysis_strategy_and_row_family_session(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    workspace: Option<&WorkspaceAnalyzer>,
    semantic_flow_resources: Option<SemanticFlowResources>,
    analysis_context: Option<&QueryAnalysisContext>,
    workspace_generation: u64,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
    union_strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    access_mode: StructuralAccessMode,
    occurrence_options: OccurrenceDerivationOptions,
    row_family_stores: Option<SharedRowFamilyStores>,
    semantic_continuation: Option<SemanticQueryContinuation>,
    access_failure_out: Option<&mut Option<String>>,
    scope: CodeQueryExecutionScope<'_>,
    mut row_keys_out: Option<&mut Vec<UnitRowKey>>,
    edge_cache: EdgeTraversalCache,
) -> DetailedCodeQueryResult {
    let value_flow_cache = semantic_flow_resources
        .as_ref()
        .map(|resources| resources.value_flow_cache());
    let type_flow_summaries = semantic_flow_resources
        .as_ref()
        .map(|resources| resources.type_flow_summaries());
    let active_semantic_model_snapshot = match row_family_stores.as_ref() {
        Some(stores) => stores.active_semantic_model_snapshot.clone(),
        None => analyzer.active_semantic_model_snapshot(),
    };
    // Keep every resolver read in this query on the same semantic-model
    // publication. Passing `None` deliberately freezes the absence so a pack
    // activated midway through the query cannot change later row families.
    let _query_scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
        analyzer,
        active_semantic_model_snapshot.clone(),
    );
    let request_started = capture_profile.then(Instant::now);
    let planning_started = capture_profile.then(Instant::now);
    if !capture_profile && cancellation.is_some_and(CancellationToken::is_cancelled) {
        return detailed_result_without_evidence(
            cancelled_query_result(session_subset(analyzer)),
            CodeQueryExecutionBudget::default(),
        );
    }
    let physical_plan = match select_physical_plan(
        query,
        union_strategy,
        scheduler_workers,
        scope.inherited_suffix_steps(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return detailed_result_without_evidence(
                invalid_plan_result(session_subset(analyzer), error),
                CodeQueryExecutionBudget::default(),
            );
        }
    };
    let source_row_boundary = source_row_boundary(&physical_plan, &scope);
    let requires_semantic = query_plan_requires_semantic(&query.plan);
    let call_binding_identity_request = query_plan_requires_call_binding_identity(&query.plan);
    let optional_call_site_identity =
        workspace.is_some() && query_plan_has_call_site_rows(&query.plan);
    if requires_semantic && semantic_continuation.is_none() && !limits.semantic.all_positive() {
        return detailed_result_without_evidence(
            invalid_plan_result(
                session_subset(analyzer),
                "semantic execution limits must all be positive for a semantic query",
            ),
            CodeQueryExecutionBudget::default(),
        );
    }
    if query_plan_requires_typestate(&query.plan) && !limits.typestate.is_valid() {
        return detailed_result_without_evidence(
            invalid_plan_result(
                session_subset(analyzer),
                "typestate execution limits must be positive and no greater than their hard maxima",
            ),
            CodeQueryExecutionBudget::default(),
        );
    }
    if query_plan_requires_value_flow(&query.plan) && !limits.value_flow.is_valid() {
        return detailed_result_without_evidence(
            invalid_plan_result(
                session_subset(analyzer),
                "value-flow execution limits must be positive and no greater than their hard maxima",
            ),
            CodeQueryExecutionBudget::default(),
        );
    }
    let planning_ns = planning_started.map(elapsed_ns).unwrap_or(0);
    let active_models = active_semantic_model_snapshot
        .as_ref()
        .map(|snapshot| Arc::clone(snapshot.active_models()));
    let shared_call_target_outcomes = scope
        .shared_call_target_outcomes()
        .filter(|cache| cache.matches_current(analyzer, active_models.as_deref()))
        .cloned();
    let (occurrence_cache, environment_cache) = row_family_stores.map_or_else(
        || {
            (
                OccurrenceTraversalCache::with_options(occurrence_options),
                EnvironmentTraversalCache::default(),
            )
        },
        |stores| {
            let select_joined_scopes = stores.selected_ast_ids.is_some();
            let occurrence = match (stores.occurrence, stores.selected_ast_ids) {
                (Some(shared), selected_ast_ids) => OccurrenceTraversalCache::with_shared_store(
                    occurrence_options,
                    shared,
                    selected_ast_ids,
                ),
                (None, Some(selected_ast_ids)) => OccurrenceTraversalCache::with_selected_ast_ids(
                    occurrence_options,
                    selected_ast_ids,
                ),
                (None, None) => OccurrenceTraversalCache::with_options(occurrence_options),
            };
            let environment = stores
                .environment
                .map_or_else(EnvironmentTraversalCache::default, |shared| {
                    EnvironmentTraversalCache::with_shared_store(shared, select_joined_scopes)
                });
            (occurrence, environment)
        },
    );
    let mut diagnostics = Vec::new();
    let preflight_files = scope
        .workspace_files()
        .map_or_else(|| analyzer.analyzed_files(), |files| files.to_vec());
    relation_capabilities::preflight(&query.plan, &preflight_files, workspace, &mut diagnostics);
    let mut state = QueryExecutionState {
        analyzer,
        workspace,
        cancellation,
        scope: scope.clone(),
        scanned_languages: scope
            .seed_files()
            .unwrap_or(&preflight_files)
            .iter()
            .map(crate::analyzer::common::language_for_file)
            .collect(),
        source_row_boundary,
        step_outputs: vec![0; physical_plan.node_count()],
        receiver_budget_override,
        budget: CodeQueryExecutionBudget::default(),
        seed_cache: HashMap::default(),
        seed_scan_ledger: SeedScanLedger::default(),
        indexed_declarations: IndexedDeclarations::default(),
        reference_cache: ReferenceTraversalCache::default(),
        occurrence_cache,
        environment_cache,
        configuration_cache: ConfigurationFactsTraversalCache::default(),
        materialization_cache: materialization::MaterializationTraversalCache::default(),
        edge_cache,
        flow_state_cache: FlowStateTraversalCache::new(active_semantic_model_snapshot.clone()),
        control_relation_cache: ControlRelationTraversalCache::default(),
        branch_relation_cache: BranchRelationTraversalCache::default(),
        cpp_expression_cache: HashMap::default(),
        cpp_class_fact_cache: HashMap::default(),
        cpp_class_declaration_cache: HashMap::default(),
        rust_marker_impls_cache: rust_marker_impls::RustMarkerImplsCache::default(),
        callable_metrics_cache: HashMap::default(),
        failure_handler_state_cache: FailureHandlerStateCache::default(),
        topology_cache: TopologyTraversalCache::default(),
        rewrite_path_cache: RewritePathTraversalCache::default(),
        path_cache: PathTraversalCache::default(),
        call_cache: CallTraversalCache::with_active_semantic_models(
            active_models.clone(),
            shared_call_target_outcomes,
        ),
        call_binding_identity_request,
        comparison_chain_operators: HashMap::default(),
        receiver_facts: HashMap::default(),
        receiver_service: None,
        semantic: workspace
            .filter(|_| requires_semantic || optional_call_site_identity)
            .map(|workspace| match semantic_continuation {
                Some(continuation) => SemanticQueryContext::new_with_parent_scope(
                    workspace,
                    cancellation,
                    limits.semantic,
                    limits.typestate,
                    limits.value_flow,
                    limits.taint,
                    workspace_generation,
                    analysis_context,
                    active_semantic_model_snapshot,
                    value_flow_cache.clone(),
                    type_flow_summaries.clone(),
                    &continuation.parent_scope,
                    continuation.child_semantic_limits,
                    continuation.root_allotment,
                    continuation.execution_before,
                    continuation.execution_child,
                    continuation.artifact_leases,
                ),
                None => SemanticQueryContext::new_with_analysis(
                    workspace,
                    cancellation,
                    limits.semantic,
                    limits.typestate,
                    limits.value_flow,
                    limits.taint,
                    workspace_generation,
                    analysis_context,
                    active_semantic_model_snapshot,
                    value_flow_cache,
                    type_flow_summaries,
                    CodeQueryRootAllotment::from_execution_limits(&limits),
                ),
            }),
        import_graph: None,
        import_graph_content: None,
        direct_import_layer: None,
        direct_import_layer_content: None,
        deferred_derived_builds: HashSet::default(),
        cache_profile: capture_profile.then(QueryCacheProfile::default),
        profile: capture_profile
            .then(|| QueryExecutionProfile::new(&physical_plan, planning_ns, scheduler_workers)),
        retained_value_census: capture_profile.then(QueryRetainedValueCensus::default),
        structural_index_session: QueryStructuralIndexSession::default(),
        access_mode,
        access_failure: None,
        parallel_seed_budget: None,
        scheduler_workers,
    };
    if let Some(semantic) = state.semantic.as_mut() {
        semantic.set_root_memo(semantic_flow_resources.and_then(|resources| resources.root_memo));
    }
    let python_gate_file = {
        let files = state
            .scope
            .seed_files()
            .map_or_else(|| analyzer.analyzed_files(), |files| files.to_vec());
        python_absent_member_file(&query.plan, &files)
    };
    if let (Some(file), Some(semantic)) = (python_gate_file.as_ref(), state.semantic.as_mut()) {
        semantic.require_python_absent_member_declaration_surface(file);
    }
    let mut profile_branch = state.profile.as_ref().map(|_| Vec::new());
    let execution_started = capture_profile.then(Instant::now);
    let mut execution = execute_plan(
        &physical_plan,
        token,
        physical_plan.root(),
        &mut state,
        limits,
        None,
        &mut diagnostics,
        &mut profile_branch,
    );
    // The root `Limit` operator (query.limit, e.g. a policy's
    // `budget.max_findings()` override) is the only node in the plan that is
    // ever handed a terminal row cap: it names its own truncation via
    // `push_truncation_diagnostic` whenever it cuts its child's rows down to
    // `count`. Nothing else in the plan is guaranteed to explain a cap it did
    // not itself enforce -- issue #2779 is exactly that gap, discovered as a
    // policy selector that truncated with `truncated=true` and zero
    // diagnostics, which downstream collapsed to a bare, unexplained
    // `PartialDiscovery`. This is a defense-in-depth backstop, not the
    // primary reporting path: see `needs_root_terminal_cap_diagnostic`.
    if needs_root_terminal_cap_diagnostic(
        execution.truncated,
        execution.cancelled,
        execution.rows.len(),
        query.limit,
        &diagnostics,
    ) {
        push_truncation_diagnostic(&mut diagnostics, &state.budget, query.limit);
    }
    if !state
        .structural_index_session
        .selections_are_current(|content| state.analyzer.workspace_content_matches(content))
    {
        execution.rows.clear();
        execution.truncated = true;
        state
            .access_failure
            .get_or_insert_with(|| "workspace content changed before result rendering".to_string());
        diagnostics.push(QueryExecutionState::diagnostic(analyzer, CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "workspace content changed after structural posting selection; retry the query for a coherent snapshot".to_string(),
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }, Some(DerivationExecutionCause::Snapshot)));
    }
    if let (Some(profile), Some(started)) = (&mut state.profile, execution_started) {
        profile.execution_ns = elapsed_ns(started);
    }
    let semantic_work = state
        .semantic
        .as_ref()
        .map_or_else(CodeQuerySemanticWork::default, SemanticQueryContext::work);
    // Observe sticky query-local execution state before dropping its ledgers.
    if execution.cancelled
        || execution.truncated
        || state.access_failure.is_some()
        || semantic_work.budget_exhausted
        || state.call_cache.effects.truncated
        || state.control_relation_cache.refusal_count() > 0
    {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=query_boundary cancelled={} truncated={} provider={} semantic={} effect_coverage={} cfg={}",
                file!(),
                line!(),
                execution.cancelled,
                execution.truncated,
                state.access_failure.is_some(),
                semantic_work.budget_exhausted,
                state.call_cache.effects.truncated,
                state.control_relation_cache.refusal_count() > 0
            )
        });
        state.analyzer.mark_execution_dependent();
    }
    let execution_work_profile =
        capture_profile.then(|| execution_work_snapshot(state.budget, semantic_work));
    let rendering_started = capture_profile.then(Instant::now);
    let mut cancelled = execution.cancelled;
    let mut truncated = execution.truncated;
    // A narrowed union leaf keeps the executor's actual traces and carries
    // the authored path through every projection. The ordinary root query
    // retains its historical plain-structural response shape, which omits
    // seed-only traces.
    if !scope.branch_path().is_empty() {
        let branch_path = scope.branch_path();
        for row in &mut execution.rows {
            for trace in &mut row.traces {
                assert!(
                    trace.branch.is_empty(),
                    "a union leaf trace must not already carry a set branch"
                );
                trace.branch.extend_from_slice(branch_path);
            }
        }
    } else if query.seed().is_some() && query.plan.steps.is_empty() {
        for row in &mut execution.rows {
            row.traces.clear();
            row.provenance_truncated = false;
        }
    }
    if scope.branch_path().is_empty()
        && let Some(seed) = query.seed()
    {
        let plan = QueryPlan::for_query(seed);
        if should_report_broad_query(&plan, seed, &state.budget, truncated) {
            push_broad_query_diagnostic(&mut diagnostics, &state.budget);
        }
    }
    let mut render_cache = PipelineRenderCache::default();
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        cancelled = true;
        push_cancelled_diagnostic(&mut diagnostics);
    }
    let mut results = Vec::with_capacity(execution.rows.len());
    let mut evidence = Vec::with_capacity(execution.rows.len());
    for (result_index, row) in execution.rows.into_iter().enumerate() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            truncated = true;
            push_cancelled_diagnostic(&mut diagnostics);
            break;
        }
        if retain_budgeted_pipeline_sources(
            analyzer,
            &row,
            &mut render_cache,
            &mut state.budget,
            limits,
            &mut diagnostics,
        ) {
            truncated = true;
        }
        render_cache.seal_source_loads();
        if let Some(row_keys) = row_keys_out.as_deref_mut() {
            row_keys.push(unit_row_key(&row.value.key()));
        }
        let terminal_source_file = terminal_source_file(&row.value);
        let retained_source =
            terminal_source_file.and_then(|file| render_cache.source_snapshot(file));
        let binding_range = pipeline_export_binding_range(&row.value, &render_cache);
        let mut row_evidence = detailed_evidence_for_pipeline_value(
            result_index,
            &row.value,
            retained_source,
            binding_range,
        );
        row_evidence.provenance = detailed_provenance_for_row(&row, &render_cache);
        evidence.push(row_evidence);
        results.push(render_pipeline_item(
            analyzer,
            row,
            query.result_detail,
            &mut render_cache,
        ));
    }
    let structural_index_stale = !state
        .structural_index_session
        .selections_are_current(|content| state.analyzer.workspace_content_matches(content));
    if structural_index_stale {
        results.clear();
        evidence.clear();
        truncated = true;
        state
            .access_failure
            .get_or_insert_with(|| "workspace content changed during result rendering".to_string());
        if !diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                && diagnostic.message.contains("structural posting")
        }) {
            diagnostics.push(QueryExecutionState::diagnostic(analyzer, CodeQueryDiagnostic {
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: "source generation changed during structural posting replay; retry the query for a coherent snapshot".to_string(),
            exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }, Some(DerivationExecutionCause::Snapshot)));
        }
    }
    if !cancelled && !structural_index_stale {
        state.structural_index_session.publish_auto_observations();
    }
    if !scope.branch_path().is_empty() {
        let branch_path = scope.branch_path();
        for diagnostic in &mut diagnostics {
            if diagnostic.branch.is_empty() {
                diagnostic.branch.extend_from_slice(branch_path);
            } else {
                assert!(
                    diagnostic.branch.starts_with(branch_path),
                    "a union leaf diagnostic must carry its full branch path"
                );
            }
        }
    }
    // Rendering can itself exhaust provenance/output limits or observe a
    // stale source after the plan has finished.
    if cancelled || truncated || state.access_failure.is_some() {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=render_boundary cancelled={} truncated={} provider={}",
                file!(),
                line!(),
                cancelled,
                truncated,
                state.access_failure.is_some()
            )
        });
        state.analyzer.mark_execution_dependent();
    }
    let total_work = execution_work_snapshot(state.budget, semantic_work);
    let work = public_execution_work(total_work);
    let budgeted_work =
        budgeted_execution_work(state.budget, std::mem::take(&mut state.step_outputs));
    if let Some(profile) = &mut state.profile {
        let execution_work = execution_work_profile.unwrap_or_default();
        profile.rendering_ns = rendering_started.map(elapsed_ns).unwrap_or(0);
        profile.total_elapsed_ns = request_started.map(elapsed_ns).unwrap_or(0);
        profile.execution_work = execution_work;
        profile.rendering_work = total_work.saturating_sub(execution_work);
        profile.work = total_work;
        profile.cache = state.cache_profile.unwrap_or_default();
    }
    let profile = state.profile;
    if let Some(out) = access_failure_out {
        *out = state.access_failure.take();
    }
    let semantic_receipt = state
        .semantic
        .take()
        .and_then(SemanticQueryContext::into_receipt);
    let mut result = CodeQueryResult {
        results,
        truncated: truncated || cancelled,
        session_subset: session_subset(analyzer),
        diagnostics: normalize_query_diagnostics(
            diagnostics
                .into_iter()
                .map(|diagnostic| QueryExecutionState::diagnostic(analyzer, diagnostic, None))
                .collect(),
        ),
    };
    result.cap_flow_status_by_run();
    let detailed = DetailedCodeQueryResult {
        result,
        work,
        budgeted_work,
        evidence,
        profile,
        semantic_receipt,
    };
    detailed.assert_invariants();
    detailed
}

/// Whether the root terminal-cap backstop (issue #2779) must push its own
/// truncation diagnostic for one `execute_plan` result.
///
/// The outermost `Limit` operator is the only node ever handed a terminal row
/// cap, and it already names its own truncation via
/// `push_truncation_diagnostic` whenever it enforces `query.limit`. This
/// check only fires when nothing already explains the truncation:
///
/// - `truncated` must be set (nothing to explain otherwise).
/// - `cancelled` must be clear: a cancellation names itself with its own
///   `Cancelled` diagnostic and can leave any row count, so it must never be
///   relabeled as a cap truncation.
/// - `query_limit` must be positive: a zero limit makes `row_count == 0` a
///   trivial match for "no results" rather than evidence of a cut.
/// - `row_count` must equal `query_limit` exactly: that is the fingerprint a
///   correctly-truncating `Limit` leaves behind (it truncates its child's
///   rows down to exactly `count`). A row count below the limit means some
///   other, unrelated mechanism (a budget lane, a stale-content retry, ...)
///   stopped the query short, and that mechanism must name itself instead.
/// - No diagnostic already carries `Incomplete` impact: if one does, it
///   already explains the truncation (whether or not it is literally
///   `ResultLimitReached`), and adding this one would double- or
///   mis-attribute the cause.
fn needs_root_terminal_cap_diagnostic(
    truncated: bool,
    cancelled: bool,
    row_count: usize,
    query_limit: usize,
    diagnostics: &[CodeQueryDiagnostic],
) -> bool {
    truncated
        && !cancelled
        && query_limit > 0
        && row_count == query_limit
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
}

fn select_physical_plan(
    query: &CodeQuery,
    strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
    inherited_suffix_steps: usize,
) -> Result<PhysicalQueryPlan, QueryError> {
    let logical_plan = LogicalQueryPlan::lower(query)?;
    let parallel_union = select_parallel_union(&logical_plan, strategy, scheduler_workers);
    Ok(PhysicalQueryPlan::select_with_parallel_union(
        logical_plan,
        parallel_union,
        inherited_suffix_steps,
    ))
}

/// Locate the source prefix in the validated plan. The logical builder adds
/// one unary node per authored suffix step and one root limit; physical
/// lowering preserves those dependencies. Walking only the outer suffix also
/// keeps selection above any set branches in the source query.
fn source_row_boundary(
    plan: &PhysicalQueryPlan,
    scope: &CodeQueryExecutionScope<'_>,
) -> Option<PhysicalQueryNodeId> {
    scope
        .source_selection()
        .map(|selection| plan.suffix_input(selection.suffix_steps()))
}

fn select_parallel_union(
    logical_plan: &LogicalQueryPlan,
    strategy: UnionExecutionStrategy,
    scheduler_workers: usize,
) -> Option<super::execution::plan::LogicalQueryNodeId> {
    if strategy == UnionExecutionStrategy::Sequential || scheduler_workers < 2 {
        return None;
    }
    let LogicalQueryOperator::Limit { input, .. } =
        logical_plan.node(logical_plan.root()).operator()
    else {
        return None;
    };
    let union = *input;
    let LogicalQueryOperator::Set {
        op: SetOperator::Union,
        inputs,
    } = logical_plan.node(union).operator()
    else {
        return None;
    };
    if inputs.len() != 2 || inputs[0] == inputs[1] {
        return None;
    }
    inputs
        .iter()
        .all(|&input| {
            matches!(
                logical_plan.node(input).operator(),
                LogicalQueryOperator::Seed(_)
            )
        })
        .then_some(())?;

    // The corrected M4 request-scoped, persistence-isolated A/B found no
    // stable cold-and-warm crossover, even at 1,001 analyzed files. Retain the
    // independently testable physical alternative, but keep production Auto
    // on the conservative sequential implementation until a later workload
    // supplies a measured selector with positive evidence.
    (strategy == UnionExecutionStrategy::Parallel).then_some(union)
}

fn detailed_result_without_evidence(
    result: CodeQueryResult,
    budget: CodeQueryExecutionBudget,
) -> DetailedCodeQueryResult {
    let detailed = DetailedCodeQueryResult {
        result,
        work: public_execution_work(execution_work_snapshot(
            budget,
            CodeQuerySemanticWork::default(),
        )),
        budgeted_work: budgeted_execution_work(budget, Vec::new()),
        evidence: Vec::new(),
        profile: None,
        semantic_receipt: None,
    };
    detailed.assert_invariants();
    detailed
}

/// The budgeted lanes `CodeQueryExecutionWork` drops, plus the per-step output
/// counts, for a caller that merges several executions of one query.
fn budgeted_execution_work(
    budget: CodeQueryExecutionBudget,
    step_outputs: Vec<u64>,
) -> CodeQueryBudgetedWork {
    let as_u64 = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    CodeQueryBudgetedWork {
        provenance_steps: as_u64(budget.provenance_steps),
        import_files_resolved: as_u64(budget.import_files_resolved),
        import_edges_resolved: as_u64(budget.import_edges_resolved),
        step_outputs,
    }
}

fn public_execution_work(work: QueryOperatorWorkProfile) -> CodeQueryExecutionWork {
    CodeQueryExecutionWork {
        scanned_files: work.scanned_files,
        scanned_source_bytes: work.scanned_source_bytes,
        fact_nodes: work.fact_nodes,
        pipeline_rows: work.pipeline_rows,
        examined_references: work.examined_references,
        semantic: work.semantic,
    }
}

fn execution_work_snapshot(
    budget: CodeQueryExecutionBudget,
    semantic: CodeQuerySemanticWork,
) -> QueryOperatorWorkProfile {
    let as_u64 = |value| u64::try_from(value).unwrap_or(u64::MAX);
    QueryOperatorWorkProfile {
        scanned_files: as_u64(budget.scanned_files),
        scanned_source_bytes: as_u64(budget.scanned_source_bytes),
        fact_nodes: as_u64(budget.fact_nodes),
        pipeline_rows: as_u64(budget.pipeline_rows),
        examined_references: as_u64(budget.examined_references),
        provenance_steps: as_u64(budget.provenance_steps),
        import_files_resolved: as_u64(budget.import_files_resolved),
        import_edges_resolved: as_u64(budget.import_edges_resolved),
        semantic,
    }
}

fn state_execution_work_snapshot(state: &QueryExecutionState<'_>) -> QueryOperatorWorkProfile {
    execution_work_snapshot(
        state.budget,
        state
            .semantic
            .as_ref()
            .map_or_else(CodeQuerySemanticWork::default, SemanticQueryContext::work),
    )
}

fn detailed_export_binding_range(
    file: &ProjectFile,
    definition: Option<&SourceExportLocalDefinition>,
    cache: &PipelineRenderCache,
) -> Option<CodeQueryRange> {
    let Some(SourceExportLocalDefinition::Defined { binding }) = definition else {
        return None;
    };
    let coordinates = cache.sources.get(file)?.as_ref()?;
    Some(render::range_for_offsets(
        &coordinates.source,
        &coordinates.line_starts,
        binding.range.start_byte,
        binding.range.end_byte,
    ))
}

fn pipeline_export_binding_range(
    value: &PipelineValue,
    cache: &PipelineRenderCache,
) -> Option<CodeQueryRange> {
    match value {
        PipelineValue::Export(value) => {
            let row = value.row();
            detailed_export_binding_range(&row.file, row.local_definition.as_ref(), cache)
        }
        PipelineValue::CrossDomain(value) => value
            .code()
            .and_then(|code| pipeline_export_binding_range(code, cache)),
        _ => None,
    }
}

fn detailed_export_local_definition(
    definition: Option<&SourceExportLocalDefinition>,
    binding_range: Option<CodeQueryRange>,
) -> Option<DetailedCodeQueryExportLocalDefinition> {
    definition.map(|definition| match definition {
        SourceExportLocalDefinition::Defined { binding } => {
            DetailedCodeQueryExportLocalDefinition::Defined {
                binding_name: binding.name.clone(),
                binding_kind: binding.kind.label().to_owned(),
                start_byte: binding.range.start_byte,
                end_byte: binding.range.end_byte,
                range: binding_range.unwrap_or(CodeQueryRange {
                    start_line: binding.range.start_line,
                    start_column: 1,
                    end_line: binding.range.end_line,
                    end_column: 1,
                }),
            }
        }
        SourceExportLocalDefinition::Undefined => DetailedCodeQueryExportLocalDefinition::Undefined,
        SourceExportLocalDefinition::Unknown => DetailedCodeQueryExportLocalDefinition::Unknown,
    })
}

fn detailed_evidence_for_pipeline_value(
    result_index: usize,
    value: &PipelineValue,
    retained_source: Option<&str>,
    binding_range: Option<CodeQueryRange>,
) -> DetailedCodeQueryEvidence {
    match value {
        PipelineValue::StructuralMatch(seed) => {
            let fact = seed.facts.node(seed.fact_match.node);
            let span = seed.fact_match.display_span(&seed.facts);
            let byte_span = span.start_byte..span.end_byte;
            let path = rel_path_string(&seed.file);
            let stable_owner_candidate = canonical_ast_candidate(seed);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::StructuralMatch,
                key: DetailedCodeQueryKey::StructuralMatch {
                    kind: fact.kind.label().to_string(),
                    analyzer_id: Some(match_id(&path, fact.kind.label(), span)),
                },
                file: seed.file.clone(),
                source_slice_sha256: source_slice_sha256(seed.facts.source(), &byte_span),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(
                    stable_owner_candidate.clone().map(|candidate| {
                        DetailedCodeQueryIdentityCandidate {
                            file: seed.file.clone(),
                            candidate,
                        }
                    }),
                ),
                stable_owner_candidate,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::Declaration(declaration) => {
            let file = declaration.unit.source().clone();
            let kind = declaration.kind_label();
            let fq_name = declaration.unit.fq_name();
            let byte_span = range_byte_span(declaration.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Declaration,
                key: DetailedCodeQueryKey::Declaration {
                    kind: kind.to_string(),
                    fq_name: fq_name.clone(),
                    analyzer_id: Some(declaration.declaration_id()),
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(
                    detailed_identity_candidate_for_unit(&declaration.unit),
                ),
                stable_owner_candidate: stable_owner_candidate_for_unit(&file, &declaration.unit),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::Semantic(value) => {
            let projection = value.detailed_projection();
            detailed_semantic_evidence(
                result_index,
                projection.domain,
                projection.key,
                projection.file,
                projection.byte_span,
                projection.language,
                projection.stable_id,
                retained_source,
            )
        }
        PipelineValue::File(file) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ReferenceSite(site) => {
            let target_fq_name = site.target.unit.fq_name();
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReferenceSite,
                key: DetailedCodeQueryKey::ReferenceSite {
                    target_id: Some(site.target.declaration_id()),
                    target_fq_name,
                },
                file: site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::ReferenceTarget(
                    detailed_identity_candidate_for_unit(&site.target.unit),
                ),
                stable_owner_candidate: site.enclosing.as_ref().and_then(|declaration| {
                    stable_owner_candidate_for_unit(&site.file, &declaration.unit)
                }),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallSite(site) => {
            let file = &site.0.file;
            let byte_span = range_byte_span(site.0.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallSite,
                key: DetailedCodeQueryKey::CallSite {
                    site_id: site.4.clone(),
                    caller_fq_name: site.0.caller.fq_name(),
                    callee_fq_name: site.0.callee.fq_name(),
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Call {
                    caller: detailed_identity_candidate_for_unit(&site.0.caller),
                    callee: detailed_identity_candidate_for_unit(&site.0.callee),
                },
                // A call-site wire ID identifies this row; it is not a stable
                // semantic owner accepted by policy finding anchors. Keep the
                // enclosing caller declaration as the owner, as before the
                // call-site identity projection was added.
                stable_owner_candidate: stable_owner_candidate_for_unit(file, &site.0.caller),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CrossDomain(value) => {
            // The evidence anchor is the carried code row, or the
            // configuration fact of a configuration witness. Both nested rows
            // remain whole in the rendered row itself.
            let anchor = match value.code() {
                Some(code) => detailed_evidence_for_pipeline_value(
                    result_index,
                    code,
                    retained_source,
                    binding_range,
                ),
                None => detailed_evidence_for_pipeline_value(
                    result_index,
                    &PipelineValue::ConfigurationFact(
                        value
                            .configuration()
                            .expect("a witness without code carries a configuration fact")
                            .clone(),
                    ),
                    retained_source,
                    binding_range,
                ),
            };
            DetailedCodeQueryEvidence {
                domain: DetailedCodeQueryDomain::CrossDomain,
                key: DetailedCodeQueryKey::CrossDomain {
                    id: value.id(),
                    code_id: value.code_id(),
                    configuration_id: value.configuration_id(),
                },
                identities: DetailedCodeQueryProvenanceIdentities::None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
                ..anchor
            }
        }
        PipelineValue::ExpressionSite(site) => {
            let file = &site.call_site.0.file;
            let byte_span = range_byte_span(site.range);
            let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ExpressionSite,
                key: DetailedCodeQueryKey::ExpressionSite {
                    input_kind: input_kind.to_string(),
                    parameter_index: parameter_index.map(|index| {
                        u32::try_from(index).expect("query parameter indexes fit in u32")
                    }),
                    parameter_name,
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: stable_owner_candidate_for_unit(
                    file,
                    &site.call_site.0.caller,
                ),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::JsxAttributeValue(value) => {
            let node = value.seed.facts.node(value.value_node);
            let byte_span = node.range.start_byte..node.range.end_byte;
            let ast_id = value.ast_id();
            let candidate = canonical_ast_candidate_for_node(&value.seed, value.value_node);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::JsxAttributeValue,
                key: DetailedCodeQueryKey::JsxAttributeValue {
                    id: value.id(),
                    ast_id,
                },
                file: value.seed.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(candidate.as_ref().map(
                    |candidate| DetailedCodeQueryIdentityCandidate {
                        file: value.seed.file.clone(),
                        candidate: candidate.clone(),
                    },
                )),
                stable_owner_candidate: candidate,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::ReceiverAnalysis(value) => {
            let site = &value.report.site;
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverAnalysis,
                key: DetailedCodeQueryKey::ReceiverAnalysis {
                    analysis_kind: value.report.operation.as_str().to_string(),
                    outcome: receiver_query_outcome_label(&value.report.analysis).to_string(),
                    capture: value.capture.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::MemberTargetAnalysis(value) => {
            let site = &value.report.site;
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::MemberTargetAnalysis,
                key: DetailedCodeQueryKey::MemberTargetAnalysis {
                    site_id: value.site_id.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::ReceiverOutcome(value) => {
            let site = &value.report.site;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverOutcome,
                key: DetailedCodeQueryKey::ReceiverOutcome {
                    id: value.site_id.clone(),
                    site_id: value.site_id.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(site.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::ReceiverEvidence(value) => {
            let site = &value.receiver.report.site;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverEvidence,
                key: DetailedCodeQueryKey::ReceiverEvidence {
                    id: value.id.clone(),
                    site_id: value.receiver.site_id.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(site.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::PointsToCandidate(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::PointsToCandidate,
            key: DetailedCodeQueryKey::PointsToCandidate {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::FieldWriteValue(value) => {
            let node = value.seed.facts.node(value.rhs_node);
            let byte_span = range_byte_span(node.range);
            let rhs_ast_id = value.rhs_ast_id();
            let candidate = canonical_ast_candidate_for_node(&value.seed, value.rhs_node);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::FieldWriteValue,
                key: DetailedCodeQueryKey::FieldWriteValue {
                    id: value.id(),
                    assignment_ast_id: value.assignment_ast_id(),
                    rhs_ast_id,
                    receiver_identity_id: value
                        .target
                        .receiver_identity_id()
                        .expect("field-write targets retain an exact receiver identity"),
                    member_target_id: value.target.member_identity_id(),
                },
                file: value.seed.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(candidate.as_ref().map(
                    |candidate| DetailedCodeQueryIdentityCandidate {
                        file: value.seed.file.clone(),
                        candidate: candidate.clone(),
                    },
                )),
                stable_owner_candidate: candidate,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::RuntimeKeyedReadValue(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::RuntimeKeyedReadValue,
            key: DetailedCodeQueryKey::RuntimeKeyedReadValue { id: value.id() },
            file: value.file.clone(),
            source_slice_sha256: retained_source
                .and_then(|source| source_slice_sha256(source, &range_byte_span(value.range))),
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: value.endpoint.clone(),
        },
        PipelineValue::CallShape(value) => {
            let outcome = &value.report.outcome;
            let byte_span = range_byte_span(outcome.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallShape,
                key: DetailedCodeQueryKey::CallShape {
                    id: outcome.id.clone(),
                    site_id: outcome.site_id.clone(),
                },
                file: outcome.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallArgumentGroup(value) => {
            let outcome = &value.shape.report.outcome;
            let group = &value.shape.report.groups[value.group_index];
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallArgumentGroup,
                key: DetailedCodeQueryKey::CallArgumentGroup {
                    id: group.id.clone(),
                    site_id: group.site_id.clone(),
                },
                file: outcome.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(outcome.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallArgument(value) => {
            let outcome = &value.shape.report.outcome;
            let argument = &value.shape.report.arguments[value.argument_index];
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallArgument,
                key: DetailedCodeQueryKey::CallArgument {
                    id: argument.id.clone(),
                    group_id: argument.group_id.clone(),
                },
                file: outcome.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(argument.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallBinding(value) => {
            let row = value.row();
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallBinding,
                key: DetailedCodeQueryKey::CallBinding {
                    id: row.id.clone(),
                    site_id: row.site_id.clone(),
                },
                file: value.file().clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(row.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallEffect(value) => {
            let row = value.row();
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallEffect,
                key: DetailedCodeQueryKey::CallEffect {
                    id: row.id.clone(),
                    site_id: row.site_id.clone(),
                },
                file: value.file().clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(row.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallResultContract(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::CallResultContract,
            key: DetailedCodeQueryKey::CallResultContract {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::CallResultObligation(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::CallResultObligation,
            key: DetailedCodeQueryKey::CallResultObligation {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ResultSubjectUse(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::ResultSubjectUse,
            key: DetailedCodeQueryKey::ResultSubjectUse {
                id: value.row.id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: Some(CodeQueryStableOwnerCandidate::Derived {
                namespace: value.row.language.to_string(),
                derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
                semantic_key: value.row.id.clone(),
            }),
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ResultContractUse(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::ResultContractUse,
            key: DetailedCodeQueryKey::ResultContractUse {
                id: value.id.clone(),
                acquisition_id: value.acquisition_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ResultContractFailureUse(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::ResultContractFailureUse,
            key: DetailedCodeQueryKey::ResultContractFailureUse {
                id: value.id.clone(),
                acquisition_id: value.acquisition_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::NilnessOperation(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::NilnessOperation,
            key: DetailedCodeQueryKey::NilnessOperation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::SwitchCoverage(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::SwitchCoverage,
            key: DetailedCodeQueryKey::SwitchCoverage {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::AssignmentRelation(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::AssignmentRelation,
            key: DetailedCodeQueryKey::AssignmentRelation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ClassSetRow(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::ClassSetRow,
            key: DetailedCodeQueryKey::ClassSetRow {
                id: value.id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::AbsentMemberFinding(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::AbsentMemberFinding,
            key: DetailedCodeQueryKey::AbsentMemberFinding {
                id: value.id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::DetachedTaskTransfer(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::DetachedTaskTransfer,
            key: DetailedCodeQueryKey::DetachedTaskTransfer {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ProcedureEffect(value) => {
            let row = value.row();
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ProcedureEffect,
                key: DetailedCodeQueryKey::ProcedureEffect {
                    id: row.id.clone(),
                    procedure_id: row.procedure_declaration_id.clone(),
                    site_id: value.subject.site_id.clone(),
                },
                file: value.file().clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(value.subject.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallableSignature(value) => {
            let byte_span = range_byte_span(value.declaration.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallableSignature,
                key: DetailedCodeQueryKey::CallableSignature {
                    id: value.report.signature.id.clone(),
                    declaration_id: value.declaration.declaration_id(),
                    site_id: value.declaration.site_id(),
                },
                file: value.file().clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::LiteralOccurrence(value) => {
            let byte_span = range_byte_span(value.source_range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::LiteralOccurrence,
                key: DetailedCodeQueryKey::LiteralOccurrence {
                    id: value.row.id.clone(),
                },
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CallableMetrics(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::CallableMetrics,
            key: DetailedCodeQueryKey::CallableMetrics {
                id: value.declaration.site_id(),
                callable_id: Some(value.declaration.unit.declaration_id().to_string()),
                site_id: value.declaration.site_id(),
            },
            file: value.file().clone(),
            source_slice_sha256: retained_source.and_then(|source| {
                source_slice_sha256(source, &range_byte_span(value.declaration.range))
            }),
            byte_span: Some(range_byte_span(value.declaration.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::SignatureParameter(value) => {
            let byte_span = range_byte_span(value.signature.declaration.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::SignatureParameter,
                key: DetailedCodeQueryKey::SignatureParameter {
                    id: value.row().id.clone(),
                    signature_id: value.row().signature_id.clone(),
                },
                file: value.file().clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::DecoratedParameter(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::DecoratedParameter,
            key: DetailedCodeQueryKey::DecoratedParameter {
                id: value.row.id.clone(),
                parameter_id: value.row.parameter_id.clone(),
            },
            file: value.file.clone(),
            source_slice_sha256: retained_source
                .and_then(|source| source_slice_sha256(source, &range_byte_span(value.range))),
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: value.semantic.as_deref().cloned(),
            runtime_keyed_read: None,
        },
        PipelineValue::CallableApplicability(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::CallableApplicability,
            key: DetailedCodeQueryKey::CallableApplicability {
                id: value.row().id.clone(),
                site_ast_id: value.row().site_ast_id.clone(),
            },
            file: value.occurrence.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.occurrence.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::OverloadSelection(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::OverloadSelection,
            key: DetailedCodeQueryKey::OverloadSelection {
                id: value.row().id.clone(),
                site_ast_id: value.row().site_ast_id.clone(),
            },
            file: value.occurrence.file.clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.occurrence.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::MemberSelection(value) => {
            let row = &value.occurrence;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::MemberSelection,
                key: DetailedCodeQueryKey::MemberSelection {
                    id: value.stable_id(),
                    site_ast_id: row.ast_id(),
                },
                file: row.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(range_byte_span(row.range)),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::Occurrence(value) => {
            let row = &value.row;
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Occurrence,
                key: DetailedCodeQueryKey::Occurrence {
                    id: row.id(),
                    ast_id: row.ast_id(),
                    role: row.role.label().to_string(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.file, unit)),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::LexicalScope(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::LexicalScope,
                key: DetailedCodeQueryKey::LexicalScope {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    index: row.index,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::Binding(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Binding,
                key: DetailedCodeQueryKey::Binding {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    name: row.name.clone(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::GenerationSite(value) => {
            let row = value.row();
            let byte_span = row.site.start_byte..row.site.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::GenerationSite,
                key: DetailedCodeQueryKey::GenerationSite {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    kind: row.kind.label().to_string(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::Export(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Export,
                key: DetailedCodeQueryKey::Export {
                    id: value.id(),
                    form: row.form.label().to_string(),
                    exported_name: row.exported_name.clone(),
                    local_definition: detailed_export_local_definition(
                        row.local_definition.as_ref(),
                        binding_range,
                    ),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::DeclarationState(value) => {
            let row = value.row();
            let byte_span = row
                .declaration
                .map(|declaration| declaration.start_byte..declaration.end_byte);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::DeclarationState,
                key: DetailedCodeQueryKey::DeclarationState {
                    id: value.id(),
                    fq_name: row.unit.fq_name().to_string(),
                    origin: row.origin.label().to_string(),
                },
                file: row.file.clone(),
                source_slice_sha256: byte_span.as_ref().and_then(|span| {
                    retained_source.and_then(|source| source_slice_sha256(source, span))
                }),
                byte_span,
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::StateEvent(value) => {
            let row = value.row();
            let byte_span = row.site.range.start_byte..row.site.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::StateEvent,
                key: DetailedCodeQueryKey::StateEvent {
                    id: value.id(),
                    ast_id: row.site.ast_id.clone(),
                    procedure_id: value.procedure_id.to_string(),
                    event_class: row.event_class.label().to_string(),
                },
                file: row.site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::BindingInitializerCall(value) => {
            let row = &value.row;
            let byte_span = row.start_byte..row.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::BindingInitializerCall,
                key: DetailedCodeQueryKey::BindingInitializerCall {
                    id: row.id.clone(),
                    establishment_event_id: row.establishment_event_id.clone(),
                    site_ast_id: row.site_ast_id.clone(),
                },
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        // A topology row's location is the build file that declares it: the
        // build readers derive it from a build model rather than from a byte
        // span, so it carries no range and its evidence anchors on the whole
        // file, exactly as a `file` row does.
        PipelineValue::SourceSet(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::SourceSet,
            key: topology_rows::source_set_key(value),
            file: value.file().clone(),
            byte_span: Some(results::BUILD_FILE_ANCHOR_SPAN),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::BuildTarget(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::BuildTarget,
            key: topology_rows::build_target_key(value),
            file: value.file().clone(),
            byte_span: Some(results::BUILD_FILE_ANCHOR_SPAN),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::TopologyEdge(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::TopologyEdge,
            key: topology_rows::topology_edge_key(value),
            file: value.file().clone(),
            byte_span: Some(results::BUILD_FILE_ANCHOR_SPAN),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ControlRelation(value) => {
            let (file, range) = control_relations::anchor(value);
            let byte_span = range.start_byte..range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ControlRelation,
                key: control_relations::detailed_key(value),
                file,
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::FailureHandlerState(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::FailureHandlerState,
                key: failure_handler_state::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::BranchRelation(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::BranchRelation,
                key: branch_relations::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::LoopRelation(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::LoopRelation,
                key: loop_relations::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CppExpression(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CppExpression,
                key: cpp_expressions::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::StatementReachability(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::StatementReachability,
                key: statement_reachability::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::PendingCleanupFlow(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::PendingCleanupFlow,
                key: pending_cleanup_flow::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::PythonRuleFact(value) => {
            let byte_span = value.anchor.start_byte..value.anchor.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::PythonRuleFact,
                key: python_rule_facts::detailed_key(value),
                file: value.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::Guard(value) => {
            let (file, range) = guards::anchor(value);
            let byte_span = range.start_byte..range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Guard,
                key: guards::detailed_key(value),
                file,
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::RewritePath(value) => {
            let row = value.row();
            let byte_span = row.origin.range.start_byte..row.origin.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::RewritePath,
                key: DetailedCodeQueryKey::RewritePath {
                    id: value.id(),
                    domain: row.domain.label().to_string(),
                    origin_specifier: row.origin.specifier.clone(),
                    outcome: row.outcome.kind().label().to_string(),
                },
                file: row.origin.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::FlowRelation(value) => {
            let target = value.target();
            let byte_span = target.site.range.start_byte..target.site.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::FlowRelation,
                key: DetailedCodeQueryKey::FlowRelation {
                    id: value.id(),
                    procedure_id: value.procedure_id.to_string(),
                    relation: value.row().relation.label().to_string(),
                    certainty: value.row().certainty.label().to_string(),
                },
                file: target.site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::ReferenceEdge(value) => {
            let row = &value.row;
            let byte_span = row.site.range.start_byte..row.site.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReferenceEdge,
                key: DetailedCodeQueryKey::ReferenceEdge {
                    id: value.id(),
                    ast_id: row.site.ast_id.clone(),
                    target_fq_name: value.target.unit.fq_name(),
                    provenance: row.provenance.label().to_string(),
                },
                file: row.site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .site
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.site.file, unit)),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::DispatchOutcome(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::DispatchOutcome,
            key: DetailedCodeQueryKey::DispatchOutcome {
                id: value.site_id.clone(),
                site_id: value.site_id.clone(),
            },
            file: value.file().clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::DispatchTarget(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::DispatchTarget,
            key: DetailedCodeQueryKey::DispatchTarget {
                id: value.id(),
                site_id: value.site.site_id.clone(),
                ordinal: value.ordinal,
            },
            file: value.file().clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.site.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::MemberFamily(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::MemberFamily,
            key: DetailedCodeQueryKey::MemberFamily {
                id: value.id(),
                member_id: value.member_id.clone(),
            },
            file: value.file().clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.member.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::MemberFamilyEdge(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::MemberFamilyEdge,
            key: DetailedCodeQueryKey::MemberFamilyEdge {
                id: value.id(),
                member_id: value.family.member_id.clone(),
                ordinal: value.ordinal,
            },
            file: value.file().clone(),
            source_slice_sha256: None,
            byte_span: Some(range_byte_span(value.family.member.range)),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::PythonHierarchyFact(value) => {
            let byte_span = range_byte_span(value.site_range.unwrap_or(value.root.range));
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::PythonHierarchyFact,
                key: DetailedCodeQueryKey::PythonHierarchyFact {
                    id: value.id(),
                    root_id: value.root_id.clone(),
                    declaration_id: value.endpoint_ids[0].clone(),
                    owner_id: value.endpoint_ids[1].clone(),
                    target_id: value.endpoint_ids[2].clone(),
                    target_owner_id: value.endpoint_ids[3].clone(),
                    fact_kind: value.fact_kind.to_owned(),
                    outcome: value.outcome.to_owned(),
                    coverage: value.coverage.to_owned(),
                    reason: value.reason.map(str::to_owned),
                    ancestry_basis: value.ancestry_basis.clone(),
                },
                file: value.file().clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::CandidateHop(value) => {
            let row = &value.occurrence;
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CandidateHop,
                key: DetailedCodeQueryKey::CandidateHop {
                    id: value.id(),
                    candidate_id: value.candidate_id(),
                    hop: value.hop.hop,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.file, unit)),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::ResolutionCandidate(value) => {
            let row = &value.occurrence;
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ResolutionCandidate,
                key: DetailedCodeQueryKey::ResolutionCandidate {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: value.ordinal,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: row
                    .enclosing
                    .as_ref()
                    .and_then(|unit| stable_owner_candidate_for_unit(&row.file, unit)),
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::QualifiedPath(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::QualifiedPath,
                key: DetailedCodeQueryKey::QualifiedPath {
                    id: value.id(),
                    ast_id: row.ast_id(),
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::PathSegment(value) => {
            let row = value.row();
            let byte_span = row.range.start_byte..row.range.end_byte;
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::PathSegment,
                key: DetailedCodeQueryKey::PathSegment {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: row.ordinal,
                },
                file: row.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
        PipelineValue::DependencyEvidence(value) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::DependencyEvidence,
            key: dependency_evidence::evidence_key(value),
            file: value.file.clone(),
            source_slice_sha256: value.location.map(|l| l.slice_sha256),
            byte_span: Some(value.row.byte_range.clone()),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            provenance: Vec::new(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        },
        PipelineValue::ConfigurationFact(value) => {
            let fact = value.fact();
            let byte_span = fact.evidence().start_byte()..fact.evidence().end_byte();
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ConfigurationFact,
                key: DetailedCodeQueryKey::ConfigurationFact {
                    id: value.id(),
                    fact_id: value.fact_id(),
                },
                file: value.file.clone(),
                source_slice_sha256: source_slice_sha256(&value.source, &byte_span),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
                decorated_parameter: None,
                runtime_keyed_read: None,
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn detailed_semantic_evidence(
    result_index: usize,
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    byte_span: std::ops::Range<usize>,
    language: &str,
    wire_id: String,
    retained_source: Option<&str>,
) -> DetailedCodeQueryEvidence {
    let candidate = detailed_semantic_wire_id_candidate(language, wire_id);
    DetailedCodeQueryEvidence {
        result_index,
        domain,
        key,
        file: file.clone(),
        source_slice_sha256: retained_source
            .and_then(|source| source_slice_sha256(source, &byte_span)),
        byte_span: Some(byte_span),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(Some(
            DetailedCodeQueryIdentityCandidate {
                file: file.clone(),
                candidate: candidate.clone(),
            },
        )),
        stable_owner_candidate: Some(candidate),
        provenance: Vec::new(),
        decorated_parameter: None,
        runtime_keyed_read: None,
    }
}

fn detailed_semantic_wire_id_candidate(
    language: &str,
    wire_id: String,
) -> CodeQueryStableOwnerCandidate {
    CodeQueryStableOwnerCandidate::Derived {
        namespace: language.to_string(),
        derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
        semantic_key: wire_id,
    }
}

fn range_byte_span(range: Range) -> std::ops::Range<usize> {
    byte_span_from_offsets(range.start_byte, range.end_byte)
}

fn byte_span_from_offsets(start_byte: usize, end_byte: usize) -> std::ops::Range<usize> {
    start_byte..end_byte
}

struct PublicSourceMetadata {
    path: String,
    language: &'static str,
    range: CodeQueryRange,
    start_byte: usize,
    end_byte: usize,
}

fn public_source_metadata(
    file: &ProjectFile,
    source_range: Range,
    range: CodeQueryRange,
) -> PublicSourceMetadata {
    PublicSourceMetadata {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        range,
        start_byte: source_range.start_byte,
        end_byte: source_range.end_byte,
    }
}

fn procedure_point_anchor(
    procedure: &SemanticProcedureValue,
    point: crate::analyzer::semantic::ProgramPointId,
    expectation: &'static str,
) -> (ProjectFile, Range) {
    let point = procedure.point_value(point).expect(expectation);
    (procedure.file().clone(), point.source_range())
}

fn completeness_label_for_coverage(covered: bool) -> &'static str {
    if covered { "complete" } else { "partial" }
}

fn source_slice_sha256(source: &str, byte_span: &std::ops::Range<usize>) -> Option<[u8; 32]> {
    source
        .as_bytes()
        .get(byte_span.clone())
        .map(|bytes| Sha256::digest(bytes).into())
}

fn terminal_source_file(value: &PipelineValue) -> Option<&ProjectFile> {
    match value {
        PipelineValue::StructuralMatch(seed) => Some(&seed.file),
        PipelineValue::Declaration(declaration) => Some(declaration.unit.source()),
        PipelineValue::Semantic(value) => Some(value.file()),
        PipelineValue::ReferenceSite(site) => Some(&site.file),
        PipelineValue::CallSite(site) => Some(&site.0.file),
        PipelineValue::ExpressionSite(site) => Some(&site.call_site.0.file),
        PipelineValue::JsxAttributeValue(value) => Some(&value.seed.file),
        PipelineValue::FieldWriteValue(value) => Some(&value.seed.file),
        PipelineValue::RuntimeKeyedReadValue(value) => Some(&value.file),
        PipelineValue::CallableSignature(value) => Some(value.file()),
        PipelineValue::LiteralOccurrence(value) => Some(&value.file),
        PipelineValue::CallableMetrics(value) => Some(value.file()),
        PipelineValue::SignatureParameter(value) => Some(value.file()),
        PipelineValue::DecoratedParameter(value) => Some(&value.file),
        PipelineValue::CallableApplicability(value) => Some(&value.occurrence.file),
        PipelineValue::OverloadSelection(value) => Some(&value.occurrence.file),
        PipelineValue::CallShape(value) => Some(&value.report.outcome.file),
        PipelineValue::CallArgumentGroup(value) => Some(&value.shape.report.outcome.file),
        PipelineValue::CallArgument(value) => Some(&value.shape.report.outcome.file),
        PipelineValue::CallBinding(value) => Some(value.file()),
        PipelineValue::CallEffect(value) => Some(value.file()),
        PipelineValue::CallResultContract(value) => Some(value.file()),
        PipelineValue::CallResultObligation(value) => Some(value.file()),
        PipelineValue::ResultSubjectUse(value) => Some(&value.file),
        PipelineValue::ResultContractUse(value) => Some(value.file()),
        PipelineValue::ResultContractFailureUse(value) => Some(value.file()),
        PipelineValue::NilnessOperation(value) => Some(value.file()),
        PipelineValue::SwitchCoverage(value) => Some(value.file()),
        PipelineValue::AssignmentRelation(value) => Some(value.file()),
        PipelineValue::ClassSetRow(value) => Some(value.file()),
        PipelineValue::AbsentMemberFinding(value) => Some(value.file()),
        PipelineValue::DetachedTaskTransfer(value) => Some(value.file()),
        PipelineValue::ProcedureEffect(value) => Some(value.file()),
        PipelineValue::Occurrence(value) => Some(value.file()),
        PipelineValue::MemberSelection(value) => Some(&value.occurrence.file),
        PipelineValue::LexicalScope(value) => Some(value.file()),
        PipelineValue::QualifiedPath(value) => Some(value.file()),
        PipelineValue::PathSegment(value) => Some(value.file()),
        PipelineValue::DependencyEvidence(value) => Some(value.file()),
        PipelineValue::ConfigurationFact(value) => Some(value.file()),
        PipelineValue::CrossDomain(value) => Some(value.anchor_file()),
        PipelineValue::Binding(value) => Some(value.file()),
        PipelineValue::ResolutionCandidate(value) => Some(value.file()),
        PipelineValue::CandidateHop(value) => Some(value.file()),
        PipelineValue::DispatchOutcome(value) => Some(value.file()),
        PipelineValue::DispatchTarget(value) => Some(value.file()),
        PipelineValue::MemberFamily(value) => Some(value.file()),
        PipelineValue::MemberFamilyEdge(value) => Some(value.file()),
        PipelineValue::PythonHierarchyFact(value) => Some(value.file()),
        PipelineValue::GenerationSite(value) => Some(value.file()),
        PipelineValue::Export(value) => Some(value.file()),
        PipelineValue::DeclarationState(value) => Some(value.file()),
        PipelineValue::ReferenceEdge(value) => Some(value.file()),
        PipelineValue::StateEvent(value) => Some(value.file()),
        PipelineValue::BindingInitializerCall(value) => Some(&value.file),
        PipelineValue::FlowRelation(value) => Some(value.file()),
        PipelineValue::ControlRelation(value) => Some(value.procedure.file()),
        PipelineValue::BranchRelation(value) => Some(&value.file),
        PipelineValue::LoopRelation(value) => Some(&value.file),
        PipelineValue::CppExpression(value) => Some(&value.file),
        PipelineValue::FailureHandlerState(value) => Some(&value.file),
        PipelineValue::StatementReachability(value) => Some(&value.file),
        PipelineValue::PendingCleanupFlow(value) => Some(&value.file),
        PipelineValue::PythonRuleFact(value) => Some(&value.file),
        PipelineValue::Guard(value) => Some(value.procedure.file()),
        PipelineValue::SourceSet(value) | PipelineValue::BuildTarget(value) => Some(value.file()),
        PipelineValue::TopologyEdge(value) => Some(value.file()),
        PipelineValue::RewritePath(value) => Some(value.file()),
        PipelineValue::ReceiverOutcome(value) => Some(&value.report.site.file),
        PipelineValue::ReceiverEvidence(value) => Some(&value.receiver.report.site.file),
        PipelineValue::PointsToCandidate(value) => Some(&value.file),
        PipelineValue::File(_)
        | PipelineValue::ReceiverAnalysis(_)
        | PipelineValue::MemberTargetAnalysis(_) => None,
    }
}

/// The configuration fact a row carries, if any. A configuration fact holds
/// the document source its byte offsets were ingested from, and that source
/// is the only one its coordinates may be rendered against: configuration
/// formats have no analyzer delegate, so `IAnalyzer::indexed_source` has no
/// snapshot of them.
macro_rules! held_configuration_fact {
    ($value_type:ident, $value:expr) => {
        match $value {
            $value_type::ConfigurationFact(value) => Some(value),
            $value_type::CrossDomain(value) => value.configuration(),
            _ => None,
        }
    };
}

/// Retain every source that full-detail terminal and provenance rendering can
/// consult, before rendering is sealed against untracked cache misses.
fn retain_budgeted_pipeline_sources(
    analyzer: &dyn IAnalyzer,
    row: &PipelineRow,
    cache: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    let mut files = BTreeSet::new();
    let mut exhausted = false;
    collect_pipeline_value_source_files(&row.value, &mut files);
    if let PipelineValue::StructuralMatch(seed) = &row.value {
        exhausted |= retain_held_source_snapshot(
            analyzer,
            cache,
            &seed.file,
            seed.facts.source(),
            seed.language,
            Vec::new(),
            diagnostics,
        );
    }
    if let Some(configuration) = held_configuration_fact!(PipelineValue, &row.value) {
        exhausted |= retain_held_configuration_snapshot(
            analyzer,
            cache,
            configuration,
            Vec::new(),
            diagnostics,
        );
    }
    for trace in &row.traces {
        exhausted |= retain_held_source_snapshot(
            analyzer,
            cache,
            &trace.seed.file,
            trace.seed.facts.source(),
            trace.seed.language,
            trace.branch.clone(),
            diagnostics,
        );
        for step in &trace.steps {
            collect_trace_value_source_files(&step.value, &mut files);
            if let Some(configuration) = held_configuration_fact!(PipelineTraceValue, &step.value) {
                exhausted |= retain_held_configuration_snapshot(
                    analyzer,
                    cache,
                    configuration,
                    trace.branch.clone(),
                    diagnostics,
                );
            }
            if let Some(via) = &step.via {
                collect_via_source_files(via, &mut files);
            }
        }
    }

    for file in files {
        exhausted |=
            retain_budgeted_source_snapshot(analyzer, &file, cache, budget, limits, diagnostics);
    }
    exhausted
}

fn retain_held_configuration_snapshot(
    analyzer: &dyn IAnalyzer,
    cache: &mut PipelineRenderCache,
    configuration: &ConfigurationFactValue,
    branch: Vec<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    retain_held_source_snapshot(
        analyzer,
        cache,
        configuration.file(),
        &configuration.source,
        Language::None,
        branch,
        diagnostics,
    )
}

fn retain_held_source_snapshot(
    analyzer: &dyn IAnalyzer,
    cache: &mut PipelineRenderCache,
    file: &ProjectFile,
    source: &str,
    language: Language,
    branch: Vec<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    let conflict_before = cache.conflicting_sources.contains(file);
    if cache.retain_source_snapshot(file, source) {
        return false;
    }
    if !conflict_before {
        diagnostics.push(QueryExecutionState::diagnostic(analyzer, CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch,
            language: language.config_label(),
            message: format!(
                "conflicting analyzer-generation source snapshots for {} prevent exact result evidence",
                rel_path_string(file)
            ),
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }, Some(DerivationExecutionCause::Snapshot)));
    }
    true
}

macro_rules! collect_pipeline_source_files {
    ($value_type:ident, $value:expr, $files:expr) => {{
        let value = $value;
        let files = $files;

        match value {
            $value_type::StructuralMatch(seed) => {
                files.insert(seed.file.clone());
            }
            $value_type::Declaration(declaration) => {
                files.insert(declaration.unit.source().clone());
            }
            $value_type::Semantic(value) => {
                files.insert(value.file().clone());
            }
            $value_type::File(_) => {}
            $value_type::ReferenceSite(site) => collect_reference_source_files(site, files),
            $value_type::CallSite(site) => collect_call_source_files(site, files),
            $value_type::ExpressionSite(site) => collect_call_source_files(&site.call_site, files),
            $value_type::JsxAttributeValue(value) => {
                files.insert(value.seed.file.clone());
            }
            $value_type::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
            $value_type::MemberTargetAnalysis(value) => collect_receiver_source_files(value, files),
            $value_type::ReceiverOutcome(value) => collect_receiver_source_files(value, files),
            $value_type::ReceiverEvidence(value) => {
                collect_receiver_source_files(&value.receiver, files)
            }
            $value_type::PointsToCandidate(value) => {
                files.insert(value.file.clone());
            }
            $value_type::FieldWriteValue(value) => {
                files.insert(value.seed.file.clone());
                collect_receiver_source_files(&value.analysis, files);
                collect_member_target_source_files(&value.target, files);
            }
            $value_type::RuntimeKeyedReadValue(value) => {
                files.insert(value.file.clone());
            }
            $value_type::CallShape(value) => {
                files.insert(value.report.outcome.file.clone());
            }
            $value_type::CallArgumentGroup(value) => {
                files.insert(value.shape.report.outcome.file.clone());
            }
            $value_type::CallArgument(value) => {
                files.insert(value.shape.report.outcome.file.clone());
            }
            $value_type::CallBinding(value) => {
                files.insert(value.file().clone());
                if let Some(target) = &value.site.target {
                    files.insert(target.unit.source().clone());
                }
            }
            $value_type::CallEffect(value) => {
                files.insert(value.file().clone());
            }
            $value_type::CallResultContract(value) => {
                files.insert(value.file().clone());
            }
            $value_type::CallResultObligation(value) => {
                files.insert(value.file().clone());
            }
            $value_type::ResultSubjectUse(value) => {
                files.insert(value.file.clone());
            }
            $value_type::ResultContractUse(value) => {
                files.insert(value.file().clone());
            }
            $value_type::ResultContractFailureUse(value) => {
                files.insert(value.file().clone());
            }
            $value_type::NilnessOperation(value) => {
                files.insert(value.file().clone());
            }
            $value_type::SwitchCoverage(value) => {
                files.insert(value.file().clone());
            }
            $value_type::AssignmentRelation(value) => {
                files.insert(value.file().clone());
            }
            $value_type::ClassSetRow(value) => {
                files.insert(value.file().clone());
            }
            $value_type::AbsentMemberFinding(value) => {
                files.insert(value.file().clone());
                files.extend(value.roots.iter().map(|root| root.origin_file.clone()));
            }
            $value_type::DetachedTaskTransfer(value) => {
                files.insert(value.file().clone());
            }
            $value_type::ProcedureEffect(value) => {
                files.insert(value.file().clone());
            }
            $value_type::CallableSignature(value) => {
                files.insert(value.file().clone());
            }
            $value_type::LiteralOccurrence(value) => {
                files.insert(value.file.clone());
            }
            $value_type::CallableMetrics(value) => {
                files.insert(value.file().clone());
            }
            $value_type::SignatureParameter(value) => {
                files.insert(value.file().clone());
            }
            $value_type::DecoratedParameter(value) => {
                files.insert(value.file.clone());
            }
            $value_type::CallableApplicability(value) => {
                files.insert(value.occurrence.file.clone());
            }
            $value_type::OverloadSelection(value) => {
                files.insert(value.occurrence.file.clone());
            }
            $value_type::MemberSelection(value) => {
                files.insert(value.occurrence.file.clone());
            }
            $value_type::Occurrence(value) => {
                files.insert(value.file().clone());
            }
            $value_type::LexicalScope(value) => {
                files.insert(value.file().clone());
            }
            $value_type::Binding(value) => {
                files.insert(value.file().clone());
            }
            $value_type::ResolutionCandidate(value) => {
                files.insert(value.file().clone());
            }
            $value_type::CandidateHop(value) => {
                files.insert(value.file().clone());
            }
            $value_type::DispatchOutcome(value) => {
                files.insert(value.file().clone());
            }
            $value_type::DispatchTarget(value) => {
                files.insert(value.file().clone());
            }
            $value_type::MemberFamily(value) => {
                files.insert(value.file().clone());
            }
            $value_type::MemberFamilyEdge(value) => {
                files.insert(value.file().clone());
            }
            $value_type::PythonHierarchyFact(value) => {
                files.insert(value.file().clone());
            }
            $value_type::GenerationSite(value) => {
                files.insert(value.file().clone());
            }
            $value_type::Export(value) => {
                files.insert(value.file().clone());
            }
            $value_type::DeclarationState(value) => {
                files.insert(value.file().clone());
            }
            $value_type::ReferenceEdge(value) => collect_edge_source_files(value, files),
            $value_type::StateEvent(value) => {
                files.insert(value.row().site.file.clone());
            }
            $value_type::BindingInitializerCall(value) => {
                files.insert(value.file.clone());
            }
            $value_type::FlowRelation(value) => {
                files.insert(value.source().site.file.clone());
                files.insert(value.target().site.file.clone());
            }
            $value_type::ControlRelation(value) => {
                files.insert(value.procedure.file().clone());
            }
            $value_type::BranchRelation(value) => {
                files.insert(value.file.clone());
            }
            $value_type::LoopRelation(value) => {
                files.insert(value.file.clone());
            }
            $value_type::CppExpression(value) => {
                files.insert(value.file.clone());
            }
            $value_type::FailureHandlerState(value) => {
                files.insert(value.file.clone());
            }
            $value_type::StatementReachability(value) => {
                files.insert(value.file.clone());
            }
            $value_type::PendingCleanupFlow(value) => {
                files.insert(value.file.clone());
            }
            $value_type::PythonRuleFact(value) => {
                files.insert(value.file.clone());
            }
            $value_type::Guard(value) => {
                files.insert(value.procedure.file().clone());
            }
            $value_type::SourceSet(value) | $value_type::BuildTarget(value) => {
                files.insert(value.file().clone());
            }
            $value_type::TopologyEdge(value) => {
                files.insert(value.file().clone());
            }
            $value_type::RewritePath(value) => {
                files.insert(value.file().clone());
            }
            $value_type::QualifiedPath(value) => {
                files.insert(value.file().clone());
            }
            $value_type::PathSegment(value) => {
                files.insert(value.file().clone());
            }
            $value_type::DependencyEvidence(_) => {}
            // Configuration facts carry their held document source; see
            // `held_configuration_fact`.
            $value_type::ConfigurationFact(_) => {}
            $value_type::CrossDomain(value) => {
                if let Some(code) = value.code() {
                    collect_pipeline_value_source_files(code, files);
                }
            }
        }
    }};
}

fn collect_pipeline_value_source_files(value: &PipelineValue, files: &mut BTreeSet<ProjectFile>) {
    collect_pipeline_source_files!(PipelineValue, value, files);
}

fn collect_trace_value_source_files(value: &PipelineTraceValue, files: &mut BTreeSet<ProjectFile>) {
    collect_pipeline_source_files!(PipelineTraceValue, value, files);
}

fn collect_edge_source_files(value: &EdgeValue, files: &mut BTreeSet<ProjectFile>) {
    collect_reference_target_source_files(
        &value.row.site.file,
        &value.target.unit,
        value.enclosing.as_ref().map(|enclosing| &enclosing.unit),
        files,
    );
}

fn collect_via_source_files(via: &PipelineVia, files: &mut BTreeSet<ProjectFile>) {
    match via {
        PipelineVia::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineVia::CallSite(site) => collect_call_source_files(site, files),
    }
}

fn collect_reference_source_files(site: &ReferenceSiteValue, files: &mut BTreeSet<ProjectFile>) {
    collect_reference_target_source_files(
        &site.file,
        &site.target.unit,
        site.enclosing.as_ref().map(|enclosing| &enclosing.unit),
        files,
    );
}

fn collect_reference_target_source_files(
    site_file: &ProjectFile,
    target: &CodeUnit,
    enclosing: Option<&CodeUnit>,
    files: &mut BTreeSet<ProjectFile>,
) {
    files.insert(site_file.clone());
    files.insert(target.source().clone());
    if let Some(enclosing) = enclosing {
        files.insert(enclosing.source().clone());
    }
}

fn collect_call_source_files(site: &CallSiteValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(site.0.file.clone());
    files.insert(site.0.caller.source().clone());
    files.insert(site.0.callee.source().clone());
}

fn collect_receiver_source_files(value: &ReceiverAnalysisValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(value.report.site.file.clone());
    match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            let mut stack = outcome.values().into_iter().flatten().collect::<Vec<_>>();
            while let Some(value) = stack.pop() {
                match value {
                    ReceiverValue::AllocationSite { ty, file, .. } => {
                        files.insert(ty.source().clone());
                        files.insert(file.clone());
                    }
                    ReceiverValue::InstanceType(unit)
                    | ReceiverValue::ClassOrStaticObject(unit)
                    | ReceiverValue::ModuleOrExportObject(unit)
                    | ReceiverValue::CurrentReceiver(unit) => {
                        files.insert(unit.source().clone());
                    }
                    ReceiverValue::FactoryReturn { factory, value } => {
                        files.insert(factory.source().clone());
                        stack.push(value);
                    }
                }
            }
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            for target in outcome.values().into_iter().flatten() {
                collect_member_target_source_files(target, files);
            }
        }
    }
}

fn collect_member_target_source_files(
    target: &ReceiverMemberTarget,
    files: &mut BTreeSet<ProjectFile>,
) {
    if let ReceiverMemberTarget::Workspace { receiver, member } = target {
        if let Some(receiver) = receiver {
            files.insert(receiver.source().clone());
        }
        files.insert(member.source().clone());
    }
}

/// Hydrate one source through the execution budget.
///
/// Returns `true` when a hard query limit prevented retaining the snapshot.
/// The cache receives a negative entry in that case so public full-detail
/// rendering cannot retry the same read outside the tracker.
fn retain_budgeted_source_snapshot(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cache: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    if cache.sources.contains_key(file) {
        return false;
    }

    let mut projected = *budget;
    projected.scanned_files = projected.scanned_files.saturating_add(1);
    if projected.scanned_files > limits.max_scanned_files {
        cache.retain_loaded_source(file, None);
        push_budget_diagnostic(diagnostics, &projected);
        return true;
    }

    let source = analyzer.indexed_source(file);
    projected.scanned_source_bytes = projected
        .scanned_source_bytes
        .saturating_add(source.as_ref().map_or(0, String::len));
    if projected.scanned_source_bytes > limits.max_scanned_source_bytes {
        cache.retain_loaded_source(file, None);
        push_budget_diagnostic(diagnostics, &projected);
        return true;
    }

    budget.scanned_files = projected.scanned_files;
    budget.scanned_source_bytes = projected.scanned_source_bytes;
    cache.retain_loaded_source(file, source);
    false
}

fn detailed_provenance_for_row(
    row: &PipelineRow,
    cache: &PipelineRenderCache,
) -> Vec<DetailedCodeQueryProvenanceEvidence> {
    row.traces
        .iter()
        .map(|trace| DetailedCodeQueryProvenanceEvidence {
            branch: trace.branch.clone(),
            seed: detailed_seed_provenance_ref(&trace.seed),
            steps: trace
                .steps
                .iter()
                .map(|step| DetailedCodeQueryProvenanceStepEvidence {
                    op: step.op.label().to_string(),
                    result: detailed_trace_provenance_ref(&step.value, cache),
                    via: step
                        .via
                        .as_ref()
                        .map(|via| detailed_via_provenance_ref(via, cache)),
                })
                .collect(),
        })
        .collect()
}

fn detailed_seed_provenance_ref(seed: &SeedMatch) -> DetailedCodeQueryProvenanceRefEvidence {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = seed.fact_match.display_span(&seed.facts);
    let byte_span = span.start_byte..span.end_byte;
    let path = rel_path_string(&seed.file);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::StructuralMatch,
        key: DetailedCodeQueryKey::StructuralMatch {
            kind: fact.kind.label().to_string(),
            analyzer_id: Some(match_id(&path, fact.kind.label(), span)),
        },
        file: seed.file.clone(),
        source_slice_sha256: source_slice_sha256(seed.facts.source(), &byte_span),
        byte_span: Some(byte_span),
        display_range: Some(range_for_span(&seed.facts, span)),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(
            canonical_ast_candidate(seed).map(|candidate| DetailedCodeQueryIdentityCandidate {
                file: seed.file.clone(),
                candidate,
            }),
        ),
    }
}

fn detailed_trace_provenance_ref(
    value: &PipelineTraceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    match value {
        PipelineTraceValue::StructuralMatch(seed) => detailed_seed_provenance_ref(seed),
        PipelineTraceValue::Declaration(value) => detailed_declaration_provenance_ref(value, cache),
        PipelineTraceValue::Semantic(value) => {
            let projection = value.detailed_projection();
            detailed_semantic_provenance_ref(
                projection.domain,
                projection.key,
                projection.file,
                projection.byte_span,
                projection.display_range,
                projection.language,
                projection.stable_id,
                cache,
            )
        }
        PipelineTraceValue::File(file) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            display_range: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::DependencyEvidence(value) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::DependencyEvidence,
            key: dependency_evidence::evidence_key(value),
            file: value.file.clone(),
            byte_span: Some(value.row.byte_range.clone()),
            display_range: value.display_range(),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: value.location.map(|l| l.slice_sha256),
        },
        PipelineTraceValue::ConfigurationFact(value) => {
            let evidence = value.fact().evidence();
            let byte_span = evidence.start_byte()..evidence.end_byte();
            let display_range = cache.sources.get(&value.file).and_then(|coordinates| {
                coordinates.as_ref().map(|coordinates| {
                    range_for_offsets(
                        &coordinates.source,
                        &coordinates.line_starts,
                        byte_span.start,
                        byte_span.end,
                    )
                })
            });
            DetailedCodeQueryProvenanceRefEvidence {
                domain: DetailedCodeQueryDomain::ConfigurationFact,
                key: DetailedCodeQueryKey::ConfigurationFact {
                    id: value.id(),
                    fact_id: value.fact_id(),
                },
                file: value.file().clone(),
                byte_span: Some(byte_span),
                display_range,
                identities: DetailedCodeQueryProvenanceIdentities::None,
                source_slice_sha256: cached_source_slice_sha256(
                    cache,
                    value.file(),
                    &(evidence.start_byte()..evidence.end_byte()),
                ),
            }
        }
        PipelineTraceValue::CrossDomain(value) => {
            // The anchor is the carried code row, or the configuration fact of
            // a configuration witness; the domain and key name the pair.
            let anchor = match value.code() {
                Some(code) => detailed_trace_provenance_ref(
                    &pipeline_trace_value(code)
                        .expect("cross-domain code rows have a provenance value"),
                    cache,
                ),
                None => detailed_trace_provenance_ref(
                    &PipelineTraceValue::ConfigurationFact(
                        value
                            .configuration()
                            .expect("a witness without code carries a configuration fact")
                            .clone(),
                    ),
                    cache,
                ),
            };
            DetailedCodeQueryProvenanceRefEvidence {
                domain: DetailedCodeQueryDomain::CrossDomain,
                key: DetailedCodeQueryKey::CrossDomain {
                    id: value.id(),
                    code_id: value.code_id(),
                    configuration_id: value.configuration_id(),
                },
                identities: DetailedCodeQueryProvenanceIdentities::None,
                ..anchor
            }
        }
        PipelineTraceValue::ReferenceSite(value) => detailed_reference_provenance_ref(value, cache),
        PipelineTraceValue::CallSite(value) => detailed_call_provenance_ref(value, cache),
        PipelineTraceValue::ExpressionSite(value) => {
            detailed_expression_provenance_ref(value, cache)
        }
        PipelineTraceValue::JsxAttributeValue(value) => {
            detailed_jsx_attribute_value_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverAnalysis(value) => {
            detailed_receiver_provenance_ref(value, cache)
        }
        PipelineTraceValue::MemberTargetAnalysis(value) => {
            detailed_member_target_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverOutcome(value) => {
            detailed_receiver_outcome_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverEvidence(value) => {
            detailed_receiver_evidence_provenance_ref(value, cache)
        }
        PipelineTraceValue::PointsToCandidate(value) => {
            detailed_points_to_candidate_provenance_ref(value, cache)
        }
        PipelineTraceValue::FieldWriteValue(value) => {
            detailed_field_write_provenance_ref(value, cache)
        }
        PipelineTraceValue::RuntimeKeyedReadValue(value) => detailed_provenance_ref(
            DetailedCodeQueryDomain::RuntimeKeyedReadValue,
            DetailedCodeQueryKey::RuntimeKeyedReadValue { id: value.id() },
            &value.file,
            value.range,
            cache,
            DetailedCodeQueryProvenanceIdentities::None,
        ),
        PipelineTraceValue::CallShape(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CallShape,
            DetailedCodeQueryKey::CallShape {
                id: value.report.outcome.id.clone(),
                site_id: value.report.outcome.site_id.clone(),
            },
            &value.report.outcome.file,
            value.report.outcome.range,
            cache,
        ),
        PipelineTraceValue::CallArgumentGroup(value) => {
            let group = &value.shape.report.groups[value.group_index];
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::CallArgumentGroup,
                DetailedCodeQueryKey::CallArgumentGroup {
                    id: group.id.clone(),
                    site_id: group.site_id.clone(),
                },
                &value.shape.report.outcome.file,
                value.shape.report.outcome.range,
                cache,
            )
        }
        PipelineTraceValue::CallArgument(value) => {
            let argument = &value.shape.report.arguments[value.argument_index];
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::CallArgument,
                DetailedCodeQueryKey::CallArgument {
                    id: argument.id.clone(),
                    group_id: argument.group_id.clone(),
                },
                &value.shape.report.outcome.file,
                argument.range,
                cache,
            )
        }
        PipelineTraceValue::CallBinding(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::CallBinding,
                DetailedCodeQueryKey::CallBinding {
                    id: row.id.clone(),
                    site_id: row.site_id.clone(),
                },
                value.file(),
                row.range,
                cache,
            )
        }
        PipelineTraceValue::CallEffect(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::CallEffect,
                DetailedCodeQueryKey::CallEffect {
                    id: row.id.clone(),
                    site_id: row.site_id.clone(),
                },
                value.file(),
                row.range,
                cache,
            )
        }
        PipelineTraceValue::CallResultContract(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CallResultContract,
            DetailedCodeQueryKey::CallResultContract {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::CallResultObligation(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CallResultObligation,
            DetailedCodeQueryKey::CallResultObligation {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::ResultSubjectUse(value) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::ResultSubjectUse,
            key: DetailedCodeQueryKey::ResultSubjectUse {
                id: value.row.id.clone(),
            },
            file: value.file.clone(),
            byte_span: None,
            display_range: value.row.receiver_range,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::ResultContractUse(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::ResultContractUse,
            DetailedCodeQueryKey::ResultContractUse {
                id: value.id.clone(),
                acquisition_id: value.acquisition_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::ResultContractFailureUse(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::ResultContractFailureUse,
            DetailedCodeQueryKey::ResultContractFailureUse {
                id: value.id.clone(),
                acquisition_id: value.acquisition_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::NilnessOperation(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::NilnessOperation,
            DetailedCodeQueryKey::NilnessOperation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::SwitchCoverage(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::SwitchCoverage,
            DetailedCodeQueryKey::SwitchCoverage {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::AssignmentRelation(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::AssignmentRelation,
            DetailedCodeQueryKey::AssignmentRelation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::ClassSetRow(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::ClassSetRow,
            DetailedCodeQueryKey::ClassSetRow {
                id: value.id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::AbsentMemberFinding(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::AbsentMemberFinding,
            DetailedCodeQueryKey::AbsentMemberFinding {
                id: value.id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::DetachedTaskTransfer(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::DetachedTaskTransfer,
            DetailedCodeQueryKey::DetachedTaskTransfer {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::ProcedureEffect(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::ProcedureEffect,
                DetailedCodeQueryKey::ProcedureEffect {
                    id: row.id.clone(),
                    procedure_id: row.procedure_declaration_id.clone(),
                    site_id: value.subject.site_id.clone(),
                },
                value.file(),
                value.subject.range,
                cache,
            )
        }
        PipelineTraceValue::MemberSelection(value) => {
            detailed_member_selection_provenance_ref(value, cache)
        }
        PipelineTraceValue::Occurrence(value) => detailed_occurrence_provenance_ref(value, cache),
        PipelineTraceValue::GenerationSite(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::GenerationSite,
                DetailedCodeQueryKey::GenerationSite {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    kind: row.kind.label().to_string(),
                },
                &row.file,
                row.site,
                cache,
            )
        }
        PipelineTraceValue::Export(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::Export,
                DetailedCodeQueryKey::Export {
                    id: value.id(),
                    form: row.form.label().to_string(),
                    exported_name: row.exported_name.clone(),
                    local_definition: detailed_export_local_definition(
                        row.local_definition.as_ref(),
                        detailed_export_binding_range(
                            &row.file,
                            row.local_definition.as_ref(),
                            cache,
                        ),
                    ),
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::DeclarationState(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::DeclarationState,
                DetailedCodeQueryKey::DeclarationState {
                    id: value.id(),
                    fq_name: row.unit.fq_name().to_string(),
                    origin: row.origin.label().to_string(),
                },
                &row.file,
                row.declaration.unwrap_or(Range {
                    start_byte: 0,
                    end_byte: 0,
                    start_line: 1,
                    end_line: 1,
                }),
                cache,
            )
        }
        PipelineTraceValue::LexicalScope(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::LexicalScope,
                DetailedCodeQueryKey::LexicalScope {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    index: row.index,
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::Binding(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::Binding,
                DetailedCodeQueryKey::Binding {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    name: row.name.clone(),
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::ResolutionCandidate(value) => {
            let row = &value.occurrence;
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::ResolutionCandidate,
                DetailedCodeQueryKey::ResolutionCandidate {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: value.ordinal,
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::DispatchOutcome(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::DispatchOutcome,
            DetailedCodeQueryKey::DispatchOutcome {
                id: value.site_id.clone(),
                site_id: value.site_id.clone(),
            },
            value.file(),
            value.range,
            cache,
        ),
        PipelineTraceValue::DispatchTarget(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::DispatchTarget,
            DetailedCodeQueryKey::DispatchTarget {
                id: value.id(),
                site_id: value.site.site_id.clone(),
                ordinal: value.ordinal,
            },
            value.file(),
            value.site.range,
            cache,
        ),
        PipelineTraceValue::CallableSignature(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CallableSignature,
            DetailedCodeQueryKey::CallableSignature {
                id: value.report.signature.id.clone(),
                declaration_id: value.declaration.declaration_id(),
                site_id: value.declaration.site_id(),
            },
            value.file(),
            value.declaration.range,
            cache,
        ),
        PipelineTraceValue::LiteralOccurrence(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::LiteralOccurrence,
            DetailedCodeQueryKey::LiteralOccurrence {
                id: value.row.id.clone(),
            },
            &value.file,
            value.source_range,
            cache,
        ),
        PipelineTraceValue::SignatureParameter(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::SignatureParameter,
            DetailedCodeQueryKey::SignatureParameter {
                id: value.row().id.clone(),
                signature_id: value.row().signature_id.clone(),
            },
            value.file(),
            value.signature.declaration.range,
            cache,
        ),
        PipelineTraceValue::DecoratedParameter(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::DecoratedParameter,
            DetailedCodeQueryKey::DecoratedParameter {
                id: value.row.id.clone(),
                parameter_id: value.row.parameter_id.clone(),
            },
            &value.file,
            value.range,
            cache,
        ),
        PipelineTraceValue::CallableMetrics(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CallableMetrics,
            DetailedCodeQueryKey::CallableMetrics {
                id: value.declaration.site_id(),
                callable_id: Some(value.declaration.declaration_id()),
                site_id: value.declaration.site_id(),
            },
            value.file(),
            value.declaration.range,
            cache,
        ),
        PipelineTraceValue::CallableApplicability(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CallableApplicability,
            DetailedCodeQueryKey::CallableApplicability {
                id: value.row().id.clone(),
                site_ast_id: value.row().site_ast_id.clone(),
            },
            &value.occurrence.file,
            value.occurrence.range,
            cache,
        ),
        PipelineTraceValue::OverloadSelection(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::OverloadSelection,
            DetailedCodeQueryKey::OverloadSelection {
                id: value.row().id.clone(),
                site_ast_id: value.row().site_ast_id.clone(),
            },
            &value.occurrence.file,
            value.occurrence.range,
            cache,
        ),
        PipelineTraceValue::MemberFamily(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::MemberFamily,
            DetailedCodeQueryKey::MemberFamily {
                id: value.id(),
                member_id: value.member_id.clone(),
            },
            value.file(),
            value.member.range,
            cache,
        ),
        PipelineTraceValue::MemberFamilyEdge(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::MemberFamilyEdge,
            DetailedCodeQueryKey::MemberFamilyEdge {
                id: value.id(),
                member_id: value.family.member_id.clone(),
                ordinal: value.ordinal,
            },
            value.file(),
            value.family.member.range,
            cache,
        ),
        PipelineTraceValue::PythonHierarchyFact(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::PythonHierarchyFact,
            DetailedCodeQueryKey::PythonHierarchyFact {
                id: value.id(),
                root_id: value.root_id.clone(),
                declaration_id: value.endpoint_ids[0].clone(),
                owner_id: value.endpoint_ids[1].clone(),
                target_id: value.endpoint_ids[2].clone(),
                target_owner_id: value.endpoint_ids[3].clone(),
                fact_kind: value.fact_kind.to_owned(),
                outcome: value.outcome.to_owned(),
                coverage: value.coverage.to_owned(),
                reason: value.reason.map(str::to_owned),
                ancestry_basis: value.ancestry_basis.clone(),
            },
            value.file(),
            value.site_range.unwrap_or(value.root.range),
            cache,
        ),
        PipelineTraceValue::CandidateHop(value) => {
            let row = &value.occurrence;
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::CandidateHop,
                DetailedCodeQueryKey::CandidateHop {
                    id: value.id(),
                    candidate_id: value.candidate_id(),
                    hop: value.hop.hop,
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::StateEvent(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::StateEvent,
                DetailedCodeQueryKey::StateEvent {
                    id: value.id(),
                    ast_id: row.site.ast_id.clone(),
                    procedure_id: value.procedure_id.to_string(),
                    event_class: row.event_class.label().to_string(),
                },
                &row.site.file,
                row.site.range,
                cache,
            )
        }
        PipelineTraceValue::BindingInitializerCall(value) => {
            let row = &value.row;
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::BindingInitializerCall,
                DetailedCodeQueryKey::BindingInitializerCall {
                    id: row.id.clone(),
                    establishment_event_id: row.establishment_event_id.clone(),
                    site_ast_id: row.site_ast_id.clone(),
                },
                &value.file,
                Range {
                    start_byte: row.start_byte,
                    end_byte: row.end_byte,
                    start_line: row.range.start_line,
                    end_line: row.range.end_line,
                },
                cache,
            )
        }
        PipelineTraceValue::RewritePath(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::RewritePath,
                DetailedCodeQueryKey::RewritePath {
                    id: value.id(),
                    domain: row.domain.label().to_string(),
                    origin_specifier: row.origin.specifier.clone(),
                    outcome: row.outcome.kind().label().to_string(),
                },
                &row.origin.file,
                row.origin.range,
                cache,
            )
        }
        PipelineTraceValue::SourceSet(value) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::SourceSet,
            key: topology_rows::source_set_key(value),
            file: value.file().clone(),
            byte_span: Some(results::BUILD_FILE_ANCHOR_SPAN),
            display_range: Some(results::BUILD_FILE_ANCHOR_RANGE),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::BuildTarget(value) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::BuildTarget,
            key: topology_rows::build_target_key(value),
            file: value.file().clone(),
            byte_span: Some(results::BUILD_FILE_ANCHOR_SPAN),
            display_range: Some(results::BUILD_FILE_ANCHOR_RANGE),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::TopologyEdge(value) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::TopologyEdge,
            key: topology_rows::topology_edge_key(value),
            file: value.file().clone(),
            byte_span: Some(results::BUILD_FILE_ANCHOR_SPAN),
            display_range: Some(results::BUILD_FILE_ANCHOR_RANGE),
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::ControlRelation(value) => {
            let (file, range) = control_relations::anchor(value);
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::ControlRelation,
                control_relations::detailed_key(value),
                &file,
                range,
                cache,
            )
        }
        PipelineTraceValue::FailureHandlerState(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::FailureHandlerState,
            failure_handler_state::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::BranchRelation(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::BranchRelation,
            branch_relations::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::LoopRelation(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::LoopRelation,
            loop_relations::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::CppExpression(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::CppExpression,
            cpp_expressions::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::StatementReachability(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::StatementReachability,
            statement_reachability::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::PendingCleanupFlow(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::PendingCleanupFlow,
            pending_cleanup_flow::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::PythonRuleFact(value) => detailed_provenance_ref_no_identity(
            DetailedCodeQueryDomain::PythonRuleFact,
            python_rule_facts::detailed_key(value),
            &value.file,
            value.anchor,
            cache,
        ),
        PipelineTraceValue::Guard(value) => {
            let (file, range) = guards::anchor(value);
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::Guard,
                guards::detailed_key(value),
                &file,
                range,
                cache,
            )
        }
        PipelineTraceValue::FlowRelation(value) => {
            let target = value.target();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::FlowRelation,
                DetailedCodeQueryKey::FlowRelation {
                    id: value.id(),
                    procedure_id: value.procedure_id.to_string(),
                    relation: value.row().relation.label().to_string(),
                    certainty: value.row().certainty.label().to_string(),
                },
                &target.site.file,
                target.site.range,
                cache,
            )
        }
        PipelineTraceValue::ReferenceEdge(value) => {
            let row = &value.row;
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::ReferenceEdge,
                DetailedCodeQueryKey::ReferenceEdge {
                    id: value.id(),
                    ast_id: row.site.ast_id.clone(),
                    target_fq_name: value.target.unit.fq_name(),
                    provenance: row.provenance.label().to_string(),
                },
                &row.site.file,
                row.site.range,
                cache,
            )
        }
        PipelineTraceValue::QualifiedPath(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::QualifiedPath,
                DetailedCodeQueryKey::QualifiedPath {
                    id: value.id(),
                    ast_id: row.ast_id(),
                },
                &row.file,
                row.range,
                cache,
            )
        }
        PipelineTraceValue::PathSegment(value) => {
            let row = value.row();
            detailed_provenance_ref_no_identity(
                DetailedCodeQueryDomain::PathSegment,
                DetailedCodeQueryKey::PathSegment {
                    id: value.id(),
                    ast_id: row.ast_id(),
                    ordinal: row.ordinal,
                },
                &row.file,
                row.range,
                cache,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn detailed_semantic_provenance_ref(
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    byte_span: std::ops::Range<usize>,
    display_range: CodeQueryRange,
    language: &str,
    wire_id: String,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let candidate = detailed_semantic_wire_id_candidate(language, wire_id);
    DetailedCodeQueryProvenanceRefEvidence {
        domain,
        key,
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: Some(display_range),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(Some(
            DetailedCodeQueryIdentityCandidate {
                file: file.clone(),
                candidate,
            },
        )),
    }
}

fn detailed_via_provenance_ref(
    value: &PipelineVia,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    match value {
        PipelineVia::ReferenceSite(value) => detailed_reference_provenance_ref(value, cache),
        PipelineVia::CallSite(value) => detailed_call_provenance_ref(value, cache),
    }
}

fn detailed_declaration_provenance_ref(
    declaration: &DeclarationValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let kind = declaration.kind_label();
    let fq_name = declaration.unit.fq_name();
    detailed_provenance_ref(
        DetailedCodeQueryDomain::Declaration,
        DetailedCodeQueryKey::Declaration {
            kind: kind.to_string(),
            fq_name,
            analyzer_id: Some(declaration.declaration_id()),
        },
        declaration.unit.source(),
        declaration.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::Primary(detailed_identity_candidate_for_unit(
            &declaration.unit,
        )),
    )
}

fn detailed_reference_provenance_ref(
    site: &ReferenceSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let target_fq_name = site.target.unit.fq_name();
    detailed_provenance_ref(
        DetailedCodeQueryDomain::ReferenceSite,
        DetailedCodeQueryKey::ReferenceSite {
            target_id: Some(site.target.declaration_id()),
            target_fq_name,
        },
        &site.file,
        site.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::ReferenceTarget(
            detailed_identity_candidate_for_unit(&site.target.unit),
        ),
    )
}

fn detailed_call_provenance_ref(
    site: &CallSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = &site.0.file;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::CallSite,
        DetailedCodeQueryKey::CallSite {
            site_id: site.4.clone(),
            caller_fq_name: site.0.caller.fq_name(),
            callee_fq_name: site.0.callee.fq_name(),
        },
        file,
        site.0.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::Call {
            caller: detailed_identity_candidate_for_unit(&site.0.caller),
            callee: detailed_identity_candidate_for_unit(&site.0.callee),
        },
    )
}

fn detailed_expression_provenance_ref(
    site: &ExpressionSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = &site.call_site.0.file;
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    detailed_provenance_ref(
        DetailedCodeQueryDomain::ExpressionSite,
        DetailedCodeQueryKey::ExpressionSite {
            input_kind: input_kind.to_string(),
            parameter_index: parameter_index
                .map(|index| u32::try_from(index).expect("query parameter indexes fit in u32")),
            parameter_name,
        },
        file,
        site.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_jsx_attribute_value_provenance_ref(
    value: &JsxAttributeValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let node = value.seed.facts.node(value.value_node);
    let range = node.range;
    let ast_id = value.ast_id();
    detailed_provenance_ref(
        DetailedCodeQueryDomain::JsxAttributeValue,
        DetailedCodeQueryKey::JsxAttributeValue {
            id: value.id(),
            ast_id,
        },
        &value.seed.file,
        range,
        cache,
        DetailedCodeQueryProvenanceIdentities::Primary(
            canonical_ast_candidate_for_node(&value.seed, value.value_node).map(|candidate| {
                DetailedCodeQueryIdentityCandidate {
                    file: value.seed.file.clone(),
                    candidate,
                }
            }),
        ),
    )
}

fn detailed_receiver_provenance_ref(
    value: &ReceiverAnalysisValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.report.site;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::ReceiverAnalysis,
        DetailedCodeQueryKey::ReceiverAnalysis {
            analysis_kind: value.report.operation.as_str().to_string(),
            outcome: receiver_query_outcome_label(&value.report.analysis).to_string(),
            capture: value.capture.clone(),
        },
        &site.file,
        site.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_member_target_provenance_ref(
    value: &ReceiverAnalysisValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.report.site;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::MemberTargetAnalysis,
        DetailedCodeQueryKey::MemberTargetAnalysis {
            site_id: value.site_id.clone(),
        },
        &site.file,
        site.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_field_write_provenance_ref(
    value: &FieldWriteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let range = value.seed.facts.node(value.rhs_node).range;
    let rhs_ast_id = value.rhs_ast_id();
    detailed_provenance_ref(
        DetailedCodeQueryDomain::FieldWriteValue,
        DetailedCodeQueryKey::FieldWriteValue {
            id: value.id(),
            assignment_ast_id: value.assignment_ast_id(),
            rhs_ast_id,
            receiver_identity_id: value
                .target
                .receiver_identity_id()
                .expect("field-write targets retain an exact receiver identity"),
            member_target_id: value.target.member_identity_id(),
        },
        &value.seed.file,
        range,
        cache,
        DetailedCodeQueryProvenanceIdentities::Primary(
            canonical_ast_candidate_for_node(&value.seed, value.rhs_node).map(|candidate| {
                DetailedCodeQueryIdentityCandidate {
                    file: value.seed.file.clone(),
                    candidate,
                }
            }),
        ),
    )
}

fn detailed_receiver_outcome_provenance_ref(
    value: &ReceiverAnalysisValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.report.site;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::ReceiverOutcome,
        DetailedCodeQueryKey::ReceiverOutcome {
            id: value.site_id.clone(),
            site_id: value.site_id.clone(),
        },
        &site.file,
        site.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_receiver_evidence_provenance_ref(
    value: &ReceiverEvidenceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.receiver.report.site;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::ReceiverEvidence,
        DetailedCodeQueryKey::ReceiverEvidence {
            id: value.id.clone(),
            site_id: value.receiver.site_id.clone(),
        },
        &site.file,
        site.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_points_to_candidate_provenance_ref(
    value: &PointsToCandidateValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    detailed_provenance_ref_no_identity(
        DetailedCodeQueryDomain::PointsToCandidate,
        DetailedCodeQueryKey::PointsToCandidate {
            id: value.id.clone(),
            site_id: value.site_id.clone(),
        },
        &value.file,
        value.range,
        cache,
    )
}

fn detailed_member_selection_provenance_ref(
    value: &MemberSelectionValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let row = &value.occurrence;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::MemberSelection,
        DetailedCodeQueryKey::MemberSelection {
            id: value.stable_id(),
            site_ast_id: row.ast_id(),
        },
        &row.file,
        row.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_occurrence_provenance_ref(
    value: &OccurrenceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let row = &value.row;
    detailed_provenance_ref(
        DetailedCodeQueryDomain::Occurrence,
        DetailedCodeQueryKey::Occurrence {
            id: row.id(),
            ast_id: row.ast_id(),
            role: row.role.label().to_string(),
        },
        &row.file,
        row.range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

/// Builds provenance-ref evidence for row families without identity candidates.
fn detailed_provenance_ref_no_identity(
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    range: Range,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    detailed_provenance_ref(
        domain,
        key,
        file,
        range,
        cache,
        DetailedCodeQueryProvenanceIdentities::None,
    )
}

fn detailed_provenance_ref(
    domain: DetailedCodeQueryDomain,
    key: DetailedCodeQueryKey,
    file: &ProjectFile,
    range: Range,
    cache: &PipelineRenderCache,
    identities: DetailedCodeQueryProvenanceIdentities,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let byte_span = range_byte_span(range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain,
        key,
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, file, range),
        identities,
    }
}

fn cached_source_slice_sha256(
    cache: &PipelineRenderCache,
    file: &ProjectFile,
    byte_span: &std::ops::Range<usize>,
) -> Option<[u8; 32]> {
    cache
        .source_snapshot(file)
        .and_then(|source| source_slice_sha256(source, byte_span))
}

fn cached_display_range(
    cache: &PipelineRenderCache,
    file: &ProjectFile,
    range: Range,
) -> Option<CodeQueryRange> {
    let coordinates = cache.sources.get(file)?.as_ref()?;
    Some(range_for_offsets(
        &coordinates.source,
        &coordinates.line_starts,
        range.start_byte,
        range.end_byte,
    ))
}

fn detailed_identity_candidate_for_unit(
    unit: &CodeUnit,
) -> Option<DetailedCodeQueryIdentityCandidate> {
    stable_identity_candidate_for_unit(unit).map(|candidate| DetailedCodeQueryIdentityCandidate {
        file: unit.source().clone(),
        candidate,
    })
}

fn stable_owner_candidate_for_unit(
    evidence_file: &ProjectFile,
    unit: &CodeUnit,
) -> Option<CodeQueryStableOwnerCandidate> {
    if unit.source() != evidence_file {
        return None;
    }
    stable_identity_candidate_for_unit(unit)
}

fn stable_identity_candidate_for_unit(unit: &CodeUnit) -> Option<CodeQueryStableOwnerCandidate> {
    if unit.is_synthetic() || unit.is_file_scope() || unit.is_anonymous() {
        return None;
    }
    Some(CodeQueryStableOwnerCandidate::Declaration {
        namespace: crate::analyzer::common::language_for_file(unit.source())
            .config_label()
            .to_string(),
        id: unit.declaration_id().to_string(),
    })
}

/// Hard cap on a stable semantic key, mirrored from the policy finding
/// identity validator. Keys over this limit are rejected there, which would
/// downgrade the finding to a weak anchor and mark the whole policy run
/// inconclusive, so the producer must stay within it.
const MAX_CANONICAL_AST_KEY_BYTES: usize = 256;

fn canonical_ast_candidate(seed: &SeedMatch) -> Option<CodeQueryStableOwnerCandidate> {
    canonical_ast_candidate_for_node(seed, seed.fact_match.node)
}

fn canonical_ast_candidate_for_node(
    seed: &SeedMatch,
    node_id: u32,
) -> Option<CodeQueryStableOwnerCandidate> {
    let mut segments = Vec::new();
    let mut current = Some(node_id);
    while let Some(node_id) = current {
        let node = seed.facts.node(node_id);
        segments.push((
            node.kind.label(),
            node.name.map(|name| name.text(seed.facts.source())),
        ));
        current = node.parent;
    }
    segments.reverse();
    let semantic_key = bounded_canonical_ast_key(&segments)?;
    Some(CodeQueryStableOwnerCandidate::Derived {
        namespace: seed.language.config_label().to_string(),
        derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
        semantic_key,
    })
}

/// Serialize an ancestor chain into a canonical AST key that fits the stable
/// identity limit. Deeply nested matches (closures in closures, generated
/// code) can exceed it, so the middle of the chain is deterministically
/// replaced by a digest segment while the outermost and innermost context is
/// kept verbatim; the digest covers the full chain, so distinct chains keep
/// distinct keys.
fn bounded_canonical_ast_key(segments: &[(&str, Option<&str>)]) -> Option<String> {
    let full = serde_json::to_string(segments).ok()?;
    if full.len() <= MAX_CANONICAL_AST_KEY_BYTES {
        return Some(full);
    }
    let digest: [u8; 32] = Sha256::digest(full.as_bytes()).into();
    let mut elided_name = String::with_capacity(33);
    elided_name.push('h');
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        write!(elided_name, "{byte:02x}").ok()?;
    }
    for keep in (0..=3usize).rev() {
        if segments.len() < keep.saturating_mul(2) {
            continue;
        }
        let mut compact: Vec<(&str, Option<&str>)> = Vec::with_capacity(keep * 2 + 1);
        compact.extend_from_slice(&segments[..keep]);
        compact.push(("elided", Some(elided_name.as_str())));
        compact.extend_from_slice(&segments[segments.len() - keep..]);
        let key = serde_json::to_string(&compact).ok()?;
        if key.len() <= MAX_CANONICAL_AST_KEY_BYTES {
            return Some(key);
        }
    }
    None
}

#[derive(Default)]
struct QueryStepInstrumentation {
    rows_visited: usize,
    relation_expansions: usize,
    temporary_capacity_bytes_lower_bound: u64,
}
fn pipeline_expansion(value: PipelineValue) -> PipelineExpansion {
    pipeline_expansion_with_via(
        value,
        None,
        "every semantic query step produces a semantic value",
    )
}

fn parent_path_values<T>(
    mut tail: usize,
    depth: usize,
    mut value_and_parent: impl FnMut(usize) -> (T, Option<usize>),
) -> Vec<T> {
    let mut values = Vec::with_capacity(depth);
    loop {
        let (value, parent) = value_and_parent(tail);
        values.push(value);
        let Some(parent) = parent else {
            break;
        };
        tail = parent;
    }
    values.reverse();
    values
}

fn pipeline_expansion_with_via(
    value: PipelineValue,
    via: Option<PipelineVia>,
    expectation: &'static str,
) -> PipelineExpansion {
    let trace_value = pipeline_trace_value(&value).expect(expectation);
    PipelineExpansion {
        value,
        trace: vec![(trace_value, via)],
        budgeted: false,
    }
}

fn budgeted_declaration_expansion(declaration: DeclarationValue) -> PipelineExpansion {
    PipelineExpansion {
        value: PipelineValue::Declaration(declaration.clone()),
        trace: vec![(PipelineTraceValue::Declaration(declaration), None)],
        budgeted: true,
    }
}

fn pipeline_trace_value(value: &PipelineValue) -> Option<PipelineTraceValue> {
    match value {
        PipelineValue::StructuralMatch(seed) => {
            Some(PipelineTraceValue::StructuralMatch(seed.clone()))
        }
        PipelineValue::Declaration(declaration) => {
            Some(PipelineTraceValue::Declaration(declaration.clone()))
        }
        PipelineValue::Semantic(value) => Some(PipelineTraceValue::Semantic(Box::new(
            SemanticTraceSnapshot::of(value),
        ))),
        PipelineValue::File(file) => Some(PipelineTraceValue::File(file.clone())),
        PipelineValue::ReferenceSite(site) => Some(PipelineTraceValue::ReferenceSite(site.clone())),
        PipelineValue::CallSite(site) => Some(PipelineTraceValue::CallSite(site.clone())),
        PipelineValue::ExpressionSite(site) => {
            Some(PipelineTraceValue::ExpressionSite(site.clone()))
        }
        PipelineValue::JsxAttributeValue(value) => {
            Some(PipelineTraceValue::JsxAttributeValue(value.clone()))
        }
        PipelineValue::ReceiverAnalysis(value) => {
            Some(PipelineTraceValue::ReceiverAnalysis(value.clone()))
        }
        PipelineValue::MemberTargetAnalysis(value) => {
            Some(PipelineTraceValue::MemberTargetAnalysis(value.clone()))
        }
        PipelineValue::ReceiverOutcome(value) => {
            Some(PipelineTraceValue::ReceiverOutcome(value.clone()))
        }
        PipelineValue::ReceiverEvidence(value) => {
            Some(PipelineTraceValue::ReceiverEvidence(value.clone()))
        }
        PipelineValue::PointsToCandidate(value) => {
            Some(PipelineTraceValue::PointsToCandidate(value.clone()))
        }
        PipelineValue::FieldWriteValue(value) => {
            Some(PipelineTraceValue::FieldWriteValue(value.clone()))
        }
        PipelineValue::RuntimeKeyedReadValue(value) => {
            Some(PipelineTraceValue::RuntimeKeyedReadValue(value.clone()))
        }
        PipelineValue::CallShape(value) => Some(PipelineTraceValue::CallShape(value.clone())),
        PipelineValue::CallArgumentGroup(value) => {
            Some(PipelineTraceValue::CallArgumentGroup(value.clone()))
        }
        PipelineValue::CallArgument(value) => Some(PipelineTraceValue::CallArgument(value.clone())),
        PipelineValue::CallBinding(value) => Some(PipelineTraceValue::CallBinding(value.clone())),
        PipelineValue::CallEffect(value) => Some(PipelineTraceValue::CallEffect(value.clone())),
        PipelineValue::CallResultContract(value) => {
            Some(PipelineTraceValue::CallResultContract(value.clone()))
        }
        PipelineValue::CallResultObligation(value) => {
            Some(PipelineTraceValue::CallResultObligation(value.clone()))
        }
        PipelineValue::ResultSubjectUse(value) => {
            Some(PipelineTraceValue::ResultSubjectUse(value.clone()))
        }
        PipelineValue::ResultContractUse(value) => {
            Some(PipelineTraceValue::ResultContractUse(value.clone()))
        }
        PipelineValue::ResultContractFailureUse(value) => {
            Some(PipelineTraceValue::ResultContractFailureUse(value.clone()))
        }
        PipelineValue::NilnessOperation(value) => {
            Some(PipelineTraceValue::NilnessOperation(value.clone()))
        }
        PipelineValue::SwitchCoverage(value) => {
            Some(PipelineTraceValue::SwitchCoverage(value.clone()))
        }
        PipelineValue::AssignmentRelation(value) => {
            Some(PipelineTraceValue::AssignmentRelation(value.clone()))
        }
        PipelineValue::ClassSetRow(value) => Some(PipelineTraceValue::ClassSetRow(value.clone())),
        PipelineValue::AbsentMemberFinding(value) => {
            Some(PipelineTraceValue::AbsentMemberFinding(value.clone()))
        }
        PipelineValue::DetachedTaskTransfer(value) => {
            Some(PipelineTraceValue::DetachedTaskTransfer(value.clone()))
        }
        PipelineValue::ProcedureEffect(value) => {
            Some(PipelineTraceValue::ProcedureEffect(value.clone()))
        }
        PipelineValue::MemberSelection(value) => {
            Some(PipelineTraceValue::MemberSelection(value.clone()))
        }
        PipelineValue::Occurrence(value) => Some(PipelineTraceValue::Occurrence(value.clone())),
        PipelineValue::LexicalScope(value) => Some(PipelineTraceValue::LexicalScope(value.clone())),
        PipelineValue::Binding(value) => Some(PipelineTraceValue::Binding(value.clone())),
        PipelineValue::ResolutionCandidate(value) => {
            Some(PipelineTraceValue::ResolutionCandidate(value.clone()))
        }
        PipelineValue::CandidateHop(value) => Some(PipelineTraceValue::CandidateHop(value.clone())),
        PipelineValue::DispatchOutcome(value) => {
            Some(PipelineTraceValue::DispatchOutcome(value.clone()))
        }
        PipelineValue::DispatchTarget(value) => {
            Some(PipelineTraceValue::DispatchTarget(value.clone()))
        }
        PipelineValue::CallableSignature(value) => {
            Some(PipelineTraceValue::CallableSignature(value.clone()))
        }
        PipelineValue::LiteralOccurrence(value) => {
            Some(PipelineTraceValue::LiteralOccurrence(value.clone()))
        }
        PipelineValue::CallableMetrics(value) => {
            Some(PipelineTraceValue::CallableMetrics(value.clone()))
        }
        PipelineValue::CallableApplicability(value) => {
            Some(PipelineTraceValue::CallableApplicability(value.clone()))
        }
        PipelineValue::OverloadSelection(value) => {
            Some(PipelineTraceValue::OverloadSelection(value.clone()))
        }
        PipelineValue::SignatureParameter(value) => {
            Some(PipelineTraceValue::SignatureParameter(value.clone()))
        }
        PipelineValue::DecoratedParameter(value) => {
            Some(PipelineTraceValue::DecoratedParameter(value.clone()))
        }
        PipelineValue::MemberFamily(value) => Some(PipelineTraceValue::MemberFamily(value.clone())),
        PipelineValue::MemberFamilyEdge(value) => {
            Some(PipelineTraceValue::MemberFamilyEdge(value.clone()))
        }
        PipelineValue::PythonHierarchyFact(value) => {
            Some(PipelineTraceValue::PythonHierarchyFact(value.clone()))
        }
        PipelineValue::GenerationSite(value) => {
            Some(PipelineTraceValue::GenerationSite(value.clone()))
        }
        PipelineValue::Export(value) => Some(PipelineTraceValue::Export(value.clone())),
        PipelineValue::DeclarationState(value) => {
            Some(PipelineTraceValue::DeclarationState(value.clone()))
        }
        PipelineValue::StateEvent(value) => Some(PipelineTraceValue::StateEvent(value.clone())),
        PipelineValue::BindingInitializerCall(value) => {
            Some(PipelineTraceValue::BindingInitializerCall(value.clone()))
        }
        PipelineValue::FlowRelation(value) => Some(PipelineTraceValue::FlowRelation(value.clone())),
        PipelineValue::ControlRelation(value) => {
            Some(PipelineTraceValue::ControlRelation(value.clone()))
        }
        PipelineValue::BranchRelation(value) => {
            Some(PipelineTraceValue::BranchRelation(value.clone()))
        }
        PipelineValue::LoopRelation(value) => Some(PipelineTraceValue::LoopRelation(value.clone())),
        PipelineValue::CppExpression(value) => {
            Some(PipelineTraceValue::CppExpression(value.clone()))
        }
        PipelineValue::FailureHandlerState(value) => {
            Some(PipelineTraceValue::FailureHandlerState(value.clone()))
        }
        PipelineValue::StatementReachability(value) => {
            Some(PipelineTraceValue::StatementReachability(value.clone()))
        }
        PipelineValue::PendingCleanupFlow(value) => {
            Some(PipelineTraceValue::PendingCleanupFlow(value.clone()))
        }
        PipelineValue::PythonRuleFact(value) => {
            Some(PipelineTraceValue::PythonRuleFact(value.clone()))
        }
        PipelineValue::Guard(value) => Some(PipelineTraceValue::Guard(value.clone())),
        PipelineValue::SourceSet(value) => Some(PipelineTraceValue::SourceSet(value.clone())),
        PipelineValue::BuildTarget(value) => Some(PipelineTraceValue::BuildTarget(value.clone())),
        PipelineValue::TopologyEdge(value) => Some(PipelineTraceValue::TopologyEdge(value.clone())),
        PipelineValue::RewritePath(value) => Some(PipelineTraceValue::RewritePath(value.clone())),
        PipelineValue::ReferenceEdge(value) => {
            Some(PipelineTraceValue::ReferenceEdge(value.clone()))
        }
        PipelineValue::QualifiedPath(value) => {
            Some(PipelineTraceValue::QualifiedPath(value.clone()))
        }
        PipelineValue::PathSegment(value) => Some(PipelineTraceValue::PathSegment(value.clone())),
        PipelineValue::DependencyEvidence(value) => {
            Some(PipelineTraceValue::DependencyEvidence(value.clone()))
        }
        PipelineValue::ConfigurationFact(value) => {
            Some(PipelineTraceValue::ConfigurationFact(value.clone()))
        }
        PipelineValue::CrossDomain(value) => Some(PipelineTraceValue::CrossDomain(value.clone())),
    }
}
