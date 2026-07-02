//! Normalized structural search (`search_ast`, issue #328).
//!
//! Layering, language-independent unless noted:
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
//! See `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the plan and decisions.

pub mod extract;
pub mod facts;
pub mod kinds;
pub mod matcher;
pub mod planner;
pub mod provider;
pub mod query;
pub mod search;
pub mod spec;

pub use facts::{FileFacts, NormalizedNode, RoleTarget, Span};
pub use kinds::{ALL_KINDS, NormalizedKind, Role};
pub use provider::{StructuralFactsCache, StructuralSearchProvider};
pub use query::{
    AstQuery, DEFAULT_LIMIT, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KWARG_NAME_LENGTH,
    MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES,
    MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, Pattern, QueryError,
    StringPredicate,
};
pub use search::{
    SearchAstExecutionLimits, SearchAstMatch, SearchAstOutput, execute, execute_with_limits,
};
pub use spec::{RoleSink, StructuralSpec};
