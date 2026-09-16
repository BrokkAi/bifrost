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

use crate::analyzer::source_facts::SourceOccurrenceId;
use crate::analyzer::structural::callable::CallSiteFacts;
use crate::analyzer::structural::kinds::NormalizedKind;
use crate::analyzer::structural::occurrences::OccurrenceRole;
use crate::compact_graph::CompactRows;

/// One role edge from a fact to a sub-node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRoleTarget {
    pub role: Role,
    /// Whether this argument role was produced by a language spread/unpack
    /// form (`*args`, `...args`, and equivalents). False for non-argument
    /// roles and ordinary arguments.
    pub spread: bool,
    /// For [`Role::Kwarg`]: the span of the keyword name (`shell` in
    /// `run(cmd, shell=True)`). `None` for every other role.
    pub keyword: Option<SourceOccurrenceId>,
    /// The target's fact id when the target node is itself normalized
    /// (an identifier, literal, field access, lambda, ...). `None` when the
    /// target expression has no normalized kind; kind-constrained sub-patterns
    /// then fail while name/text/capture still work off `span`.
    pub node: Option<u32>,
    /// Full span of the target node.
    pub occurrence: SourceOccurrenceId,
    /// The derived name span, when the language spec can identify one from
    /// AST fields (rightmost component for qualified callees, the identifier
    /// itself for simple ones).
    pub name: Option<SourceOccurrenceId>,
}

/// One normalized node occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedNode {
    pub kind: NormalizedKind,
    /// Exact language-neutral value for a boolean-literal fact. `None` for
    /// every other kind and for adapters that do not support this axis.
    pub boolean_value: Option<bool>,
    /// Grammar-backed source construct used by semantic generator rules.
    pub construct: Option<String>,
    pub occurrence: SourceOccurrenceId,
    /// Nearest enclosing normalized node, forming the containment chain used
    /// by `inside` / `not_inside` / `has`.
    pub parent: Option<u32>,
    /// The fact's own name span (declared identifier for declarations, the
    /// callee name for calls, field name for field accesses, ...).
    pub name: Option<SourceOccurrenceId>,
    /// One-past-the-end fact id for this fact's normalized subtree. Facts are
    /// stored in pre-order, so descendants are exactly
    /// `(self_id + 1)..subtree_end`.
    pub subtree_end: u32,
    /// What the language spec's grammar says about this call site (#1478):
    /// refined call kind, argument-shape coverage, and whether the site
    /// continues its callee's argument-list sequence. Always `None` for a
    /// node that is not a [`NormalizedKind::Call`], and `None` for a call
    /// whose adapter does not refine call sites — the derivation layer then
    /// keeps the receiver-derived baseline rather than guessing.
    pub call_site: Option<CallSiteFacts>,
}

/// The language-owned structural rows for one file.
///
/// Rows are grouped by normalized node. Construction asserts the row
/// boundaries and the node-level boolean-value invariant so consumers can use
/// typed accessors without carrying a partial-state error path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralFactRows {
    nodes: Vec<NormalizedNode>,
    roles: CompactRows<SourceRoleTarget>,
    occurrence_roles: CompactRows<OccurrenceRole>,
}

impl StructuralFactRows {
    pub fn new(
        nodes: Vec<NormalizedNode>,
        roles: CompactRows<SourceRoleTarget>,
        occurrence_roles: CompactRows<OccurrenceRole>,
    ) -> Self {
        assert_eq!(roles.rows(), nodes.len());
        assert_eq!(occurrence_roles.rows(), nodes.len());
        assert!(
            nodes
                .iter()
                .all(|node| node.boolean_value.is_none()
                    || node.kind == NormalizedKind::BooleanLiteral),
            "only normalized boolean-literal facts may carry boolean values"
        );
        Self {
            nodes,
            roles,
            occurrence_roles,
        }
    }

    pub fn nodes(&self) -> &[NormalizedNode] {
        &self.nodes
    }

    pub fn node(&self, id: u32) -> &NormalizedNode {
        &self.nodes[id as usize]
    }

    pub fn roles(&self, id: u32) -> &[SourceRoleTarget] {
        self.roles.row(id as usize)
    }

    pub fn occurrence_roles(&self, id: u32) -> &[OccurrenceRole] {
        self.occurrence_roles.row(id as usize)
    }

    pub fn occurrence_role_count(&self) -> usize {
        self.occurrence_roles.len()
    }

    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    pub fn work_item_count(&self) -> usize {
        self.nodes.len().saturating_add(self.roles.len())
    }

    /// Rough retained heap footprint of the rows, including vector capacity.
    pub fn estimated_bytes(&self) -> u64 {
        (self.nodes.capacity() as u64)
            .saturating_mul(std::mem::size_of::<NormalizedNode>() as u64)
            .saturating_add(
                self.nodes
                    .iter()
                    .map(|node| node.construct.as_ref().map_or(0, String::capacity) as u64)
                    .sum::<u64>(),
            )
            .saturating_add(self.roles.estimated_bytes())
            .saturating_add(self.occurrence_roles.estimated_bytes())
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<NormalizedNode>,
        CompactRows<SourceRoleTarget>,
        CompactRows<OccurrenceRole>,
    ) {
        (self.nodes, self.roles, self.occurrence_roles)
    }
}
