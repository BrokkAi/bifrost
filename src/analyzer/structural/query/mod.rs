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
mod features;
mod ir;
mod json;
pub mod schema;
pub mod sexp;
mod source;

pub use ir::{
    CallInputSelector, CallSiteTraversalFilter, CallTraversalFilter, CodeQuery, CodeQueryPlan,
    CodeQueryPlanSource, CodeQueryResultDetail, CodeQuerySeed, DEFAULT_LIMIT, HierarchyTraversal,
    MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KIND_LIST_ENTRIES, MAX_KWARG_NAME_LENGTH, MAX_KWARGS,
    MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES, MAX_QUERY_BRANCHES,
    MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES, MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES,
    MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, Pattern, QueryError, QueryStep, QueryValueKind,
    ReceiverTraversalFilter, ReferenceTraversalFilter, SCHEMA_VERSION, SetOperator,
    StringPredicate,
};
pub use source::{
    QuerySourceDiagnostic, QuerySourceEdit, QuerySourceFix, QuerySourceHelp, query_source_help_at,
    validate_query_source,
};

#[cfg(test)]
mod tests;
