//! Normalized structural search (`search_ast`, issue #328).
//!
//! This module owns the language-neutral query layer: a normalized node
//! vocabulary with a subtype hierarchy ([`kinds`]), and the canonical typed
//! query IR plus its JSON frontend ([`query`]). Per-language mapping from
//! tree-sitter node types to normalized kinds, fact extraction, the matcher,
//! and the workspace planner land in later milestones — see
//! `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md`.

pub mod kinds;
pub mod query;

pub use kinds::{ALL_KINDS, NormalizedKind, Role};
pub use query::{AstQuery, KindSelector, Pattern, QueryError, StringPredicate};
