//! The canonical typed IR for structural queries (issue #328), plus the JSON
//! frontends. JSON and RQL both parse into this same `CodeQuery` so the
//! matcher never sees syntax.
//!
//! Decoding is hand-rolled over `serde_json::Value` rather than derived: every
//! error carries the JSON path of the offending field (e.g.
//! `match.callee.name`), which is what lets agent callers self-correct, and
//! rules like "role `callee` requires a pattern kind that supports it" are
//! validation, not shape.

mod decode;
pub mod domain;
mod features;
mod ir;
mod json;
pub mod partition;
pub mod schema;
pub mod sexp;
mod source;

fn child_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}

fn index_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

pub(crate) use json::configuration_facts_seed_to_json;
use source::EnvironmentOptionKind;

pub use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationMemberRole, ConfigurationScalarKind, ConfigurationValueProvenance,
};
pub use domain::*;
pub use ir::{
    AbsentMemberProofFilter, ArityConstraint, AssignmentRelationFilter, AssignmentRelationKind,
    BindingFilter, BindingOfOptions, BindingSeed, BranchRelationFilter, BranchRelationKind,
    CSharpRule, CallArgumentSelector, CallIdentity, CallInputSelector, CallSiteTraversalFilter,
    CallTraversalFilter, CandidateFilter, CandidateOutcomeLabel, CodeQuery, CodeQueryPlan,
    CodeQueryPlanSource, CodeQueryResultDetail, CodeQuerySeed, ConfigurationCodeMatch,
    ConfigurationCodeRelation, ConfigurationCompletenessFilter, ConfigurationFactsFilter,
    ConfigurationFactsSeed, ConfigurationKeyRelation, ConfigurationNodeKindFilter,
    ConfigurationRouteFilter, ConfigurationRouteSegmentFilter, ControlRelationFilter,
    CppProvenanceFilter, CppRule, CrossDomainCorrelation, CrossDomainRelation,
    CrossDomainRequirement, DEFAULT_LIMIT, DeclarationModifier, DeclarationStateFilter,
    DecoratorBindingFilter, DependencyConfigurationRelation, DependencyEvidenceFilter,
    DependencyEvidenceSeed, EdgeFilter, ExportFilter, ExportSeed, FailureUseConsumer,
    FailureUseProvenance, FieldWriteValueTraversal, FlowRelationFilter, GenerationSiteFilter,
    GenerationSiteSeed, HierarchyTraversal, JavaRule, JsRule, JsxAttributeValueTraversal,
    JsxElementIdentity, KeyedReadKeySelector, KeyedReadValueTraversal, LanguageRule,
    LanguageScopeConflict, MAX_ARITY, MAX_BINDING_NAME_LENGTH, MAX_CAPTURE_LENGTH,
    MAX_CONFIGURATION_FILTER_ENTRIES, MAX_CONFIGURATION_KEY_LENGTH,
    MAX_CONFIGURATION_ROUTE_SEGMENTS, MAX_CORRELATION_DOCUMENTS,
    MAX_DECORATOR_BINDING_FILTER_LENGTH, MAX_ENVIRONMENT_FILTER_ENTRIES, MAX_GLOB_LENGTH,
    MAX_KIND_LIST_ENTRIES, MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT,
    MAX_OCCURRENCE_FILTER_ENTRIES, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES, MAX_QUERY_BRANCHES,
    MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES, MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES,
    MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, OccurrenceFilter, OccurrenceSeed, PathFilter,
    PathSeed, Pattern, QueryError, QueryPathScope, QueryPathScopeError, QueryRowLiteral,
    QueryRowPredicate, QueryRowPredicateOp, QueryRowPredicateOperand, QueryRowProjectionColumn,
    QueryStep, QueryValueKind, ReceiverTraversalFilter, ReferenceTraversalFilter,
    ResolvedCallFilter, ResolvedCallIdentity, ResolvedCallIdentityKind, ResolvedCallProof,
    ResolvedCallReceiverType, ResolvedValueFilter, ResultContractFailureUseFilter,
    RewritePathFilter, SCHEMA_VERSION, ScopeFilter, ScopeSeed, SegmentsOfOptions, SetOperator,
    StateEventFilter, StringPredicate, TaintTraversal, TypestateTraversal, UNATTRIBUTED_TIER_LABEL,
    ValueFlowTraversal, WitnessTraversal, compile_path_glob, exact_path_globs,
    intersect_language_scopes,
};
pub use partition::PlanPartitioning;
pub use schema::{
    ALL_CODE_QUERY_EXECUTION_MODES, CallTraversalCompleteness, CodeQueryExecutionMode,
    ConfigurationFactsFilterField, QueryStepOp, QueryStepShape, RuntimeKeyKind,
};
pub use source::{
    QuerySourceDiagnostic, QuerySourceEdit, QuerySourceFix, QuerySourceHelp, query_source_help_at,
    validate_query_source,
};

#[cfg(test)]
mod tests;

pub(crate) use json::dependency_evidence_seed_to_json;
