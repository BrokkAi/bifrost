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
    /// Role edges in source order (argument order matters for `args`).
    pub roles: Vec<RoleTarget>,
}

impl NormalizedNode {
    pub fn span(&self) -> Span {
        Span {
            start_byte: self.range.start_byte,
            end_byte: self.range.end_byte,
        }
    }

    pub fn role_targets<'a>(&'a self, role: Role) -> impl Iterator<Item = &'a RoleTarget> + 'a {
        self.roles.iter().filter(move |target| target.role == role)
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
}

impl FileFacts {
    pub(crate) fn new(source: String, line_starts: Vec<usize>, nodes: Vec<NormalizedNode>) -> Self {
        Self {
            source,
            line_starts,
            nodes,
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

    /// 1-based line containing `byte`, matching the `Range` convention used
    /// across the analyzer.
    pub fn line_of_byte(&self, byte: usize) -> usize {
        self.line_starts.partition_point(|&start| start <= byte)
    }

    /// Rough heap footprint for the facts-cache weigher; exactness doesn't
    /// matter, monotonicity with actual size does.
    pub fn estimated_bytes(&self) -> u64 {
        let roles: usize = self
            .nodes
            .iter()
            .map(|node| node.roles.len() * std::mem::size_of::<RoleTarget>())
            .sum();
        (self.source.len()
            + self.line_starts.len() * std::mem::size_of::<usize>()
            + self.nodes.len() * std::mem::size_of::<NormalizedNode>()
            + roles) as u64
    }

    /// Whether `ancestor` lies on `node`'s parent chain (strictly above it).
    pub fn is_ancestor(&self, ancestor: u32, node: u32) -> bool {
        let mut current = self.node(node).parent;
        while let Some(id) = current {
            if id == ancestor {
                return true;
            }
            current = self.node(id).parent;
        }
        false
    }
}
