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
//! - [`provider`]: the capability trait analyzers expose.
//! - [`search`]: workspace execution and the tool-facing output shape.
//!
//! See `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the plan and decisions.

pub mod extract;
pub mod facts;
pub mod kinds;
pub mod matcher;
pub mod provider;
pub mod query;
pub mod search;
pub mod spec;

pub use facts::{FileFacts, NormalizedNode, RoleTarget, Span};
pub use kinds::{ALL_KINDS, NormalizedKind, Role};
pub use provider::StructuralSearchProvider;
pub use query::{AstQuery, Pattern, QueryError, StringPredicate};
pub use search::{SearchAstMatch, SearchAstOutput, execute};
pub use spec::{RoleSink, StructuralSpec};
