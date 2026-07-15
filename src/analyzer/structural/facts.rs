//! Normalized structural facts for one file: the arena the matcher runs over.
//!
//! Facts are extracted from a tree-sitter parse (see `extract.rs`) and are the
//! only view of a file the matcher ever sees — grammar-specific node types
//! stop at the language spec boundary. Nodes live in a flat `Vec` addressed by
//! `u32` ids with parent links for containment; role edges (`callee`, `args`,
//! `left`, ...) point at either another fact or, when the target expression is
//! not itself normalized, at a raw source span.

use super::kinds::{NormalizedKind, Role};
use crate::analyzer::Range;
use crate::compact_graph::CompactRows;

/// A byte span into the file's source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// One normalized node occurrence.
#[derive(Debug, Clone)]
pub struct NormalizedNode {
    pub kind: NormalizedKind,
    pub range: Range,
    /// Nearest enclosing normalized node, forming the containment chain used
    /// by `inside` / `not_inside` / `has`.
    pub parent: Option<u32>,
    /// The fact's own name span (declared identifier for declarations, the
    /// callee name for calls, field name for field accesses, ...).
    pub name: Option<Span>,
    /// One-past-the-end fact id for this fact's normalized subtree. Facts are
    /// stored in pre-order, so descendants are exactly
    /// `(self_id + 1)..subtree_end`.
    pub subtree_end: u32,
}

impl NormalizedNode {
    pub fn span(&self) -> Span {
        Span {
            start_byte: self.range.start_byte,
            end_byte: self.range.end_byte,
        }
    }
}

/// All normalized facts for one file. `source` is a private copy so spans stay
/// valid however the analyzer's own file state evolves; `line_starts` maps
/// byte offsets to 1-based lines for capture reporting.
#[derive(Debug)]
pub struct FileFacts {
    source: String,
    line_starts: Vec<usize>,
    nodes: Vec<NormalizedNode>,
    /// Role edges grouped by source fact and retained in source order.
    roles: CompactRows<RoleTarget>,
}

impl FileFacts {
    pub(crate) fn new(
        source: String,
        line_starts: Vec<usize>,
        nodes: Vec<NormalizedNode>,
        roles: CompactRows<RoleTarget>,
    ) -> Self {
        assert_eq!(roles.rows(), nodes.len());
        Self {
            source,
            line_starts,
            nodes,
            roles,
        }
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn nodes(&self) -> &[NormalizedNode] {
        &self.nodes
    }

    pub fn node(&self, id: u32) -> &NormalizedNode {
        &self.nodes[id as usize]
    }

    /// Semantic role edges for `id`, in their original source order.
    pub fn roles(&self, id: u32) -> &[RoleTarget] {
        self.roles.row(id as usize)
    }

    pub fn role_targets(&self, id: u32, role: Role) -> impl Iterator<Item = &RoleTarget> {
        self.roles(id)
            .iter()
            .filter(move |target| target.role == role)
    }

    /// Total semantic role edges retained across every fact in this file.
    ///
    /// This is representation-neutral bookkeeping for diagnostics and
    /// memory benchmarks; callers that need the edges themselves should use
    /// the fact-level role accessors.
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    pub fn subtree_end(&self, id: u32) -> u32 {
        self.node(id).subtree_end
    }

    /// 1-based line containing `byte`, matching the `Range` convention used
    /// across the analyzer.
    pub fn line_of_byte(&self, byte: usize) -> usize {
        self.line_starts.partition_point(|&start| start <= byte)
    }

    pub fn line_column_of_byte(&self, byte: usize) -> (usize, usize) {
        crate::text_utils::line_column_for_offset(&self.source, &self.line_starts, byte)
    }

    /// Rough heap footprint for the facts-cache weigher; exactness doesn't
    /// matter, monotonicity with actual size does.
    pub fn estimated_bytes(&self) -> u64 {
        (self.source.capacity() as u64)
            .saturating_add(
                (self.line_starts.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<usize>() as u64),
            )
            .saturating_add(
                (self.nodes.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<NormalizedNode>() as u64),
            )
            .saturating_add(self.roles.estimated_bytes())
    }

    /// Whether `ancestor` lies on `node`'s parent chain (strictly above it).
    pub fn is_ancestor(&self, ancestor: u32, node: u32) -> bool {
        ancestor < node && node < self.subtree_end(ancestor)
    }
}

#[cfg(test)]
mod tests {
    use super::{FileFacts, NormalizedNode, RoleTarget, Span};
    use crate::analyzer::Range;
    use crate::analyzer::structural::kinds::{NormalizedKind, Role};
    use crate::compact_graph::CompactRowsBuilder;

    fn role_target(role: Role, start_byte: usize) -> RoleTarget {
        RoleTarget {
            role,
            spread: false,
            keyword: None,
            node: None,
            span: Span {
                start_byte,
                end_byte: start_byte + 1,
            },
            name: None,
        }
    }

    fn node() -> NormalizedNode {
        NormalizedNode {
            kind: NormalizedKind::Call,
            range: Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
            parent: None,
            name: None,
            subtree_end: 1,
        }
    }

    #[test]
    fn estimated_bytes_counts_retained_allocation_capacity() {
        let mut source = String::with_capacity(128);
        source.push('x');
        let mut line_starts = Vec::with_capacity(32);
        line_starts.push(0);
        let mut nodes = Vec::with_capacity(8);
        nodes.push(node());
        let mut roles = CompactRowsBuilder::with_capacity(1, 1);
        roles.push_row([role_target(Role::Callee, 0)]);
        let facts = FileFacts::new(source, line_starts, nodes, roles.finish());

        let length_based = facts.source.len() as u64
            + (facts.line_starts.len() * std::mem::size_of::<usize>()) as u64
            + (facts.nodes.len() * std::mem::size_of::<NormalizedNode>()) as u64
            + facts.roles.estimated_bytes();
        let capacity_based = facts.source.capacity() as u64
            + (facts.line_starts.capacity() * std::mem::size_of::<usize>()) as u64
            + (facts.nodes.capacity() * std::mem::size_of::<NormalizedNode>()) as u64
            + facts.roles.estimated_bytes();

        assert!(capacity_based > length_based);
        assert_eq!(facts.estimated_bytes(), capacity_based);
        assert_eq!(facts.role_count(), 1);
        assert_eq!(facts.roles(0).len(), 1);
        assert_eq!(facts.role_targets(0, Role::Callee).count(), 1);
    }

    #[test]
    fn compact_role_rows_preserve_boundaries_and_source_order() {
        let mut roles = CompactRowsBuilder::with_capacity(2, 3);
        roles.push_row([role_target(Role::Callee, 1), role_target(Role::Arg, 2)]);
        roles.push_row([role_target(Role::Decorator, 3)]);
        let facts = FileFacts::new(
            "abcd".to_owned(),
            vec![0],
            vec![node(), node()],
            roles.finish(),
        );

        assert_eq!(
            facts
                .roles(0)
                .iter()
                .map(|target| (target.role, target.span.start_byte))
                .collect::<Vec<_>>(),
            vec![(Role::Callee, 1), (Role::Arg, 2)]
        );
        assert_eq!(
            facts
                .roles(1)
                .iter()
                .map(|target| (target.role, target.span.start_byte))
                .collect::<Vec<_>>(),
            vec![(Role::Decorator, 3)]
        );
    }
}
