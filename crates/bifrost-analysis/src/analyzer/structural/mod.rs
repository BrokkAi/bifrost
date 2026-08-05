//! Normalized structural search (`query_code`, issue #328).
//!
//! Layering, language-independent unless noted:
//! - [`adapter_helpers`]: small shared mechanics for language adapters.
//! - `capabilities`: query feature requirements and capability diagnostics.
//! - [`kinds`]: the normalized node vocabulary with its subtype hierarchy,
//!   and the role-edge vocabulary.
//! - [`query`]: the canonical typed query IR and its JSON frontend.
//! - [`facts`]: the per-file fact arena the matcher runs over.
//! - [`spec`]: the per-language boundary — kind tables and AST-field role
//!   extraction (implementations live next to each language's analyzer,
//!   e.g. `src/analyzer/python/structural.rs`).
//! - [`extract`]: parse + normalize one file through a spec.
//! - [`matcher`]: pattern evaluation with captures and containment.
//! - [`occurrence_rows`]: per-file occurrence rows derived from the arena's
//!   occurrence roles plus definition resolution (issue #1473).
//! - [`lexical_environment`]: per-file scope, binding, import-binder and
//!   package rows, plus the reaching-binding algorithm over them (issue #1474).
//! - [`planner`]: positive-anchor candidate pruning (negation never prunes).
//! - [`provider`]: the capability trait analyzers expose, plus the
//!   source-hash-validated facts cache behind it.
//! - [`search`]: parallel workspace execution and the tool-facing output.
//!
//! See `.agents/plans/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the original plan
//! and `.agents/plans/issue-449-query-code-reference.md` for the public rename.

pub(crate) mod adapter_helpers;
pub mod analysis_context;
pub(crate) mod capabilities;
pub(crate) mod execution;
pub mod extract;
pub mod facts;
pub(crate) mod index;
pub mod lexical_environment;
pub mod matcher;
pub mod occurrence_rows;
pub mod planner;
pub mod provider;
pub mod query;
pub mod reference_edges;
pub mod rune_ir;
pub mod search;

// The normalized kind/role registry and the spec trait a language implements
// live in `brokk-bifrost-core`, below every grammar; only the engine that
// consumes them stays here.
pub use brokk_bifrost_core::analyzer::structural::{edges, kinds, occurrences, resolution, spec};

pub use analysis_context::{
    MAX_PROTOCOL_NAME_BYTES, MAX_PROTOCOL_NAMESPACE_BYTES, MAX_PROTOCOL_REF_BYTES,
    MAX_PROTOCOL_REFS, MAX_PROTOCOL_REGISTRATIONS, MAX_QUERY_REGISTRATION_VALIDATION_ARTIFACTS,
    MAX_QUERY_REGISTRATION_VALIDATION_SOURCE_BYTES, MAX_REGISTRATION_ARTIFACT_SOURCE_BYTES,
    MAX_RETAINED_BINDING_PLAN_BYTES, MAX_RETAINED_PROTOCOL_BYTES,
    MAX_RETAINED_REGISTRATION_ARTIFACT_BYTES, MAX_RETAINED_TAINT_ARTIFACT_BYTES,
    MAX_RETAINED_TAINT_PLAN_BYTES, MAX_RETAINED_TAINT_REPORT_BYTES,
    MAX_RETAINED_VALUE_FLOW_ARTIFACT_BYTES, MAX_RETAINED_VALUE_FLOW_PLAN_BYTES,
    MAX_TAINT_RESULT_REF_BYTES, MAX_TAINT_RESULT_REFS, MAX_TAINT_RESULT_REGISTRATIONS,
    MAX_TAINT_RESULTS_PER_REGISTRATION, MAX_VALUE_FLOW_PLAN_REFS,
    MAX_VALUE_FLOW_PLAN_REGISTRATIONS, ProtocolHandle, ProtocolNameError, ProtocolNamespaceError,
    ProtocolRef, ProtocolRefError, ProtocolRegistration, ProtocolRegistrationError,
    ProtocolRegistrationLimits, ProtocolRegistrationOutcome, ProtocolRegistrationSet,
    ProtocolRegistrationSetError, QueryAnalysisContext, QueryAnalysisContextError,
    QueryAnalysisValidationLimits, TaintResultHandle, TaintResultNameError,
    TaintResultNamespaceError, TaintResultRef, TaintResultRefError, TaintResultRegistration,
    TaintResultRegistrationError, TaintResultRegistrationLimits, TaintResultRegistrationOutcome,
    TaintResultRegistrationSet, TaintResultRegistrationSetError, ValueFlowPlanHandle,
    ValueFlowPlanNameError, ValueFlowPlanNamespaceError, ValueFlowPlanRef, ValueFlowPlanRefError,
    ValueFlowPlanRegistration, ValueFlowPlanRegistrationLimits, ValueFlowPlanRegistrationOutcome,
    ValueFlowPlanRegistrationSet, ValueFlowPlanRegistrationSetError,
};
pub use edges::{
    ALL_EDGE_AXES, ALL_EDGE_PROVENANCES, ALL_OWNER_RELATIONS, ALL_SITE_CLASSES,
    DEEP_REFERENCE_EDGE_SUPPORT, EdgeAxis, EdgeProvenance, EdgeSupport,
    INVERSE_REFERENCE_EDGE_SUPPORT, NO_REFERENCE_EDGE_SUPPORT, OwnerRelation, ReferenceEdgeSupport,
    SiteClass,
};
pub use execution::{
    CodeQueryAccessPathProfile, CodeQueryBoundedDispatchProfile, CodeQueryCacheMetricsKind,
    CodeQueryDerivedLayerCacheCounters, CodeQueryExplain, CodeQueryExplainScheduling,
    CodeQueryLogicalNode, CodeQueryLogicalOperation, CodeQueryLogicalPlan,
    CodeQueryOperatorDisposition, CodeQueryOperatorObservation, CodeQueryOperatorTermination,
    CodeQueryOperatorTimings, CodeQueryPhysicalNode, CodeQueryPhysicalOperator,
    CodeQueryPhysicalPlan, CodeQueryProfile, CodeQueryProfileCacheCounters,
    CodeQueryProfileCacheLayer, CodeQueryProfileScheduling, CodeQueryProfileTimings,
    CodeQueryProfileWork, CodeQuerySchedulingPolicy, CodeQuerySelectedScheduling,
    CodeQueryStructuralFactsCacheCounters,
};
pub use facts::{FileFacts, NormalizedNode, RoleTarget, Span};
pub use kinds::{ALL_KINDS, NormalizedKind, Role};
pub use lexical_environment::{
    BindingRow, ENVIRONMENT_PRODUCER_AXES, EnvironmentCompleteness, EnvironmentFileResult,
    EnvironmentIncompleteReason, ImportBinderDetail, PackageClauseRow, ReachingBindingOutcome,
    ScopeAnchor, ScopeRow, WILDCARD_IMPORT_NAME, environment_for_file, reaching_binding,
};
pub use occurrence_rows::{
    OccurrenceCompleteness, OccurrenceDerivationOptions, OccurrenceFileResult,
    OccurrenceIncompleteReason, OccurrenceRow, OccurrenceTarget, OccurrencesCancelled,
    occurrences_for_file, occurrences_for_file_with_options,
};
pub use occurrences::{
    ALL_OCCURRENCE_ROLES, NO_OCCURRENCE_ROLE_SUPPORT, Namespace, OccurrenceClass, OccurrenceRole,
    OccurrenceRoleSupport, OccurrenceSupport, default_occurrence_namespace,
};
pub use provider::{StructuralFactsCache, StructuralSearchProvider, StructuralSearchSnapshotCache};
pub use query::{
    CodeQuery, CodeQueryExecutionMode, CodeQueryPlan, CodeQueryPlanSource, CodeQueryResultDetail,
    CodeQuerySeed, DEFAULT_LIMIT, MAX_BINDING_NAME_LENGTH, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH,
    MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH,
    MAX_PATTERN_NODES, MAX_QUERY_BRANCHES, MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES,
    MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, Pattern,
    QueryError, QueryStep, QueryValueKind, ReceiverTraversalFilter, ReferenceTraversalFilter,
    SCHEMA_VERSION, SetOperator, StringPredicate,
};
pub use resolution::{
    ALL_BINDING_KINDS, ALL_BOUNDARY_STATUSES, ALL_DECLARED_VISIBILITIES, ALL_ENVIRONMENT_AXES,
    ALL_HOISTING_CLASSES, ALL_PRECEDENCE_TIERS, ALL_REJECTION_REASONS, BindingActivation,
    BindingKind, BoundaryStatus, CandidateOutcome, DEEP_LEXICAL_ENVIRONMENT_SUPPORT,
    DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS, DeclaredVisibility, EnvironmentAxis,
    EnvironmentSupport, HoistingClass, LexicalEnvironmentSupport, NO_LEXICAL_ENVIRONMENT_SUPPORT,
    PrecedenceTier, RejectionReason,
};
pub use rune_ir::{
    RenderedRuneIr, RuneIrError, RuneIrLanguage, RuneIrLimits, RuneIrSelection,
    render_source_rune_ir,
};
pub(crate) use search::{BoundedTaintProjection, project_taint_finding_report_bounded};
pub use search::{
    CodeQueryCallArgument, CodeQueryCallSite, CodeQueryCapture, CodeQueryCompletion,
    CodeQueryControlEdge, CodeQueryDeclaration, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryExecutionLimits, CodeQueryExecutionWork,
    CodeQueryExpressionSite, CodeQueryFile, CodeQueryFlowCarrierSymbol, CodeQueryFlowCertainty,
    CodeQueryFlowCompletion, CodeQueryFlowDeclarationSegment, CodeQueryFlowEndpoint,
    CodeQueryFlowEvent, CodeQueryFlowFactSymbol, CodeQueryFlowMustStatus, CodeQueryFlowPortSymbol,
    CodeQueryFlowReachability, CodeQueryFlowSelectorSymbol, CodeQueryFlowSolverTermination,
    CodeQueryFlowSymbolSite, CodeQueryFlowWitness, CodeQueryFlowWitnessStep,
    CodeQueryFlowWitnessStepKind, CodeQueryMatch, CodeQueryProcedure, CodeQueryProgramPoint,
    CodeQueryProgramPointBoundary, CodeQueryProgramPointRef, CodeQueryProvenance,
    CodeQueryProvenanceStep, CodeQueryRange, CodeQueryReceiverAnalysis, CodeQueryReceiverValue,
    CodeQueryReferenceEdge, CodeQueryReferenceSite, CodeQueryResponse, CodeQueryResult,
    CodeQueryResultItem, CodeQueryResultRef, CodeQueryResultValue, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticLimits, CodeQuerySemanticProof,
    CodeQuerySemanticWork, CodeQuerySourceSite, CodeQueryTaintFinding, CodeQueryTaintLimits,
    CodeQueryTaintOrigin, CodeQueryTaintProjectionLimits, CodeQueryTaintWitness,
    CodeQueryTypestateCertainty, CodeQueryTypestateFinding, CodeQueryTypestateFindingKind,
    CodeQueryTypestateLimits, CodeQueryTypestateSubject, CodeQueryTypestateUncertainty,
    CodeQueryTypestateWitness, CodeQueryTypestateWitnessStep, CodeQueryTypestateWitnessStepKind,
    CodeQueryTypestateWork, CodeQueryValueFlowLimits, CodeQueryValueFlowWork, execute,
    execute_request, execute_request_with_cancellation, execute_request_with_limits,
    execute_with_limits, execute_workspace, execute_workspace_request,
    execute_workspace_request_with_all_analysis_registration_lease,
    execute_workspace_request_with_analysis_registration_lease,
    execute_workspace_request_with_cancellation, execute_workspace_request_with_limits,
    execute_workspace_request_with_registration_cancellation,
    execute_workspace_request_with_registration_lease,
    execute_workspace_request_with_registration_limits,
    execute_workspace_request_with_registrations, execute_workspace_with_limits,
    project_taint_finding_report,
};
pub use spec::{RoleSink, StructuralSpec};
