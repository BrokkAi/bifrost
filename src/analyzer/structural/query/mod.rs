//! The canonical typed IR for structural queries (issue #328), plus the JSON
//! frontend. JSON is the v1 external surface; a later S-expression frontend
//! must parse into this same `AstQuery` so the matcher never sees syntax.
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

pub use ir::{
    AstQuery, DEFAULT_LIMIT, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KIND_LIST_ENTRIES,
    MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH,
    MAX_PATTERN_NODES, MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS,
    Pattern, QueryError, StringPredicate,
};

#[cfg(test)]
mod tests;
