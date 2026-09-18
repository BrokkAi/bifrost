//! The two structural fact values a language spec produces.
//!
//! Everything else in `analyzer::structural::facts` — the normalized-node
//! arena, its snapshot codec, and the `FileFacts` container — stays in
//! `brokk-bifrost-analysis` with the extraction engine and re-exports these at
//! their original paths. A spec only ever builds spans and role edges, so those
//! two types live down here where the spec trait itself does.

use crate::analyzer::structural::kinds::Role;
use serde::{Deserialize, Serialize};

/// A byte span into the file's source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Span {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        source.get(self.start_byte..self.end_byte).unwrap_or("")
    }
}

/// One role edge from a fact to a sub-node.
#[derive(Debug, Clone)]
pub struct RoleTarget {
    pub role: Role,
    /// Whether this argument role was produced by a language spread/unpack
    /// form (`*args`, `...args`, and equivalents). False for non-argument
    /// roles and ordinary arguments.
    pub spread: bool,
    /// For [`Role::Kwarg`]: the span of the keyword name (`shell` in
    /// `run(cmd, shell=True)`). `None` for every other role.
    pub keyword: Option<Span>,
    /// The target's fact id when the target node is itself normalized
    /// (an identifier, literal, field access, lambda, ...). `None` when the
    /// target expression has no normalized kind; kind-constrained sub-patterns
    /// then fail while name/text/capture still work off `span`.
    pub node: Option<u32>,
    /// Full span of the target node.
    pub span: Span,
    /// The derived name span, when the language spec can identify one from
    /// AST fields (rightmost component for qualified callees, the identifier
    /// itself for simple ones).
    pub name: Option<Span>,
}
