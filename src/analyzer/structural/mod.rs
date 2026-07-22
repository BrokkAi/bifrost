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
//! - [`planner`]: positive-anchor candidate pruning (negation never prunes).
//! - [`provider`]: the capability trait analyzers expose, plus the
//!   source-hash-validated facts cache behind it.
//! - [`search`]: parallel workspace execution and the tool-facing output.
//!
//! See `.agents/plans/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the original plan
//! and `.agents/plans/issue-449-query-code-reference.md` for the public rename.

pub(crate) mod adapter_helpers;
pub(crate) mod capabilities;
pub(crate) mod execution;
pub mod extract;
pub mod facts;
pub(crate) mod index;
pub mod kinds;
pub mod matcher;
pub mod planner;
pub mod provider;
pub mod query;
pub mod rune_ir;
pub mod search;
pub mod spec;

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
pub use provider::{StructuralFactsCache, StructuralSearchProvider};
pub use query::{
    CodeQuery, CodeQueryExecutionMode, CodeQueryPlan, CodeQueryPlanSource, CodeQueryResultDetail,
    CodeQuerySeed, DEFAULT_LIMIT, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KWARG_NAME_LENGTH,
    MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES,
    MAX_QUERY_BRANCHES, MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES, MAX_QUERY_STEPS,
    MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, Pattern, QueryError,
    QueryStep, QueryValueKind, ReceiverTraversalFilter, ReferenceTraversalFilter, SCHEMA_VERSION,
    SetOperator, StringPredicate,
};
pub use rune_ir::{
    RenderedRuneIr, RuneIrError, RuneIrLanguage, RuneIrLimits, RuneIrSelection,
    render_source_rune_ir,
};
pub use search::{
    CodeQueryCallArgument, CodeQueryCallSite, CodeQueryCapture, CodeQueryCompletion,
    CodeQueryDeclaration, CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryExecutionLimits, CodeQueryExecutionWork, CodeQueryExpressionSite, CodeQueryFile,
    CodeQueryMatch, CodeQueryProvenance, CodeQueryProvenanceStep, CodeQueryRange,
    CodeQueryReceiverAnalysis, CodeQueryReceiverValue, CodeQueryReferenceSite, CodeQueryResponse,
    CodeQueryResult, CodeQueryResultItem, CodeQueryResultRef, CodeQueryResultValue,
    CodeQuerySourceSite, execute, execute_request, execute_request_with_cancellation,
    execute_request_with_limits, execute_with_limits, execute_workspace, execute_workspace_request,
    execute_workspace_request_with_cancellation, execute_workspace_request_with_limits,
    execute_workspace_with_limits,
};
pub use spec::{RoleSink, StructuralSpec};
