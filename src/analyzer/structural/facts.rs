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
use crate::text_utils::compute_line_starts;
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Semantic and binary contract for persisted structural facts.
///
/// Increment this whenever normalization semantics or the snapshot DTO changes,
/// even when older bytes would still deserialize. The version is part of the
/// SQLite row key so incompatible facts are treated as ordinary cache misses.
pub(crate) const STRUCTURAL_FACTS_SNAPSHOT_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StructuralSnapshotError(String);

impl StructuralSnapshotError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StructuralSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StructuralSnapshotError {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SnapshotSpan {
    start: u32,
    end: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotNode {
    kind: u8,
    span: SnapshotSpan,
    parent: Option<u32>,
    name: Option<SnapshotSpan>,
    subtree_end: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotRoleTarget {
    role: u8,
    spread: bool,
    keyword: Option<SnapshotSpan>,
    node: Option<u32>,
    span: SnapshotSpan,
    name: Option<SnapshotSpan>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StructuralFactsSnapshot {
    nodes: Vec<SnapshotNode>,
    role_offsets: Vec<u32>,
    roles: Vec<SnapshotRoleTarget>,
}

fn kind_code(kind: NormalizedKind) -> u8 {
    use NormalizedKind::*;
    match kind {
        Declaration => 0,
        Callable => 1,
        Function => 2,
        Method => 3,
        Constructor => 4,
        Lambda => 5,
        Class => 6,
        Import => 7,
        Call => 8,
        Assignment => 9,
        FieldAccess => 10,
        Identifier => 11,
        Literal => 12,
        StringLiteral => 13,
        NumericLiteral => 14,
        BooleanLiteral => 15,
        NullLiteral => 16,
        Return => 17,
        Throw => 18,
        Catch => 19,
        If => 20,
        Loop => 21,
        Decorator => 22,
    }
}

fn decode_kind(code: u8) -> Result<NormalizedKind, StructuralSnapshotError> {
    use NormalizedKind::*;
    match code {
        0 => Ok(Declaration),
        1 => Ok(Callable),
        2 => Ok(Function),
        3 => Ok(Method),
        4 => Ok(Constructor),
        5 => Ok(Lambda),
        6 => Ok(Class),
        7 => Ok(Import),
        8 => Ok(Call),
        9 => Ok(Assignment),
        10 => Ok(FieldAccess),
        11 => Ok(Identifier),
        12 => Ok(Literal),
        13 => Ok(StringLiteral),
        14 => Ok(NumericLiteral),
        15 => Ok(BooleanLiteral),
        16 => Ok(NullLiteral),
        17 => Ok(Return),
        18 => Ok(Throw),
        19 => Ok(Catch),
        20 => Ok(If),
        21 => Ok(Loop),
        22 => Ok(Decorator),
        _ => Err(StructuralSnapshotError::invalid(format!(
            "unknown structural kind code {code}"
        ))),
    }
}

fn role_code(role: Role) -> u8 {
    match role {
        Role::Callee => 0,
        Role::Receiver => 1,
        Role::Arg => 2,
        Role::Kwarg => 3,
        Role::Left => 4,
        Role::Right => 5,
        Role::Module => 6,
        Role::Decorator => 7,
        Role::Object => 8,
        Role::Field => 9,
    }
}

fn decode_role(code: u8) -> Result<Role, StructuralSnapshotError> {
    match code {
        0 => Ok(Role::Callee),
        1 => Ok(Role::Receiver),
        2 => Ok(Role::Arg),
        3 => Ok(Role::Kwarg),
        4 => Ok(Role::Left),
        5 => Ok(Role::Right),
        6 => Ok(Role::Module),
        7 => Ok(Role::Decorator),
        8 => Ok(Role::Object),
        9 => Ok(Role::Field),
        _ => Err(StructuralSnapshotError::invalid(format!(
            "unknown structural role code {code}"
        ))),
    }
}

fn encode_span(span: Span) -> Result<SnapshotSpan, StructuralSnapshotError> {
    Ok(SnapshotSpan {
        start: u32::try_from(span.start_byte)
            .map_err(|_| StructuralSnapshotError::invalid("structural span start exceeds u32"))?,
        end: u32::try_from(span.end_byte)
            .map_err(|_| StructuralSnapshotError::invalid("structural span end exceeds u32"))?,
    })
}

fn decode_span(span: SnapshotSpan, source: &str) -> Result<Span, StructuralSnapshotError> {
    let start_byte = span.start as usize;
    let end_byte = span.end as usize;
    if start_byte > end_byte || end_byte > source.len() {
        return Err(StructuralSnapshotError::invalid(format!(
            "structural span {start_byte}..{end_byte} is outside source length {}",
            source.len()
        )));
    }
    if !source.is_char_boundary(start_byte) || !source.is_char_boundary(end_byte) {
        return Err(StructuralSnapshotError::invalid(format!(
            "structural span {start_byte}..{end_byte} is not on UTF-8 boundaries"
        )));
    }
    Ok(Span {
        start_byte,
        end_byte,
    })
}

fn line_of_byte(line_starts: &[usize], byte: usize) -> usize {
    line_starts.partition_point(|&start| start <= byte)
}

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

    pub(crate) fn encode_snapshot(&self) -> Result<Vec<u8>, StructuralSnapshotError> {
        u32::try_from(self.source.len()).map_err(|_| {
            StructuralSnapshotError::invalid("structural source length exceeds u32")
        })?;
        let nodes = self
            .nodes
            .iter()
            .map(|node| {
                Ok(SnapshotNode {
                    kind: kind_code(node.kind),
                    span: encode_span(node.span())?,
                    parent: node.parent,
                    name: node.name.map(encode_span).transpose()?,
                    subtree_end: node.subtree_end,
                })
            })
            .collect::<Result<Vec<_>, StructuralSnapshotError>>()?;
        let roles = self
            .roles
            .values()
            .iter()
            .map(|target| {
                Ok(SnapshotRoleTarget {
                    role: role_code(target.role),
                    spread: target.spread,
                    keyword: target.keyword.map(encode_span).transpose()?,
                    node: target.node,
                    span: encode_span(target.span)?,
                    name: target.name.map(encode_span).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, StructuralSnapshotError>>()?;
        let snapshot = StructuralFactsSnapshot {
            nodes,
            role_offsets: self.roles.offsets().to_vec(),
            roles,
        };
        bincode::DefaultOptions::new()
            .with_varint_encoding()
            .reject_trailing_bytes()
            .serialize(&snapshot)
            .map_err(|error| {
                StructuralSnapshotError::invalid(format!(
                    "serialize structural facts snapshot: {error}"
                ))
            })
    }

    pub(crate) fn decode_snapshot(
        source: String,
        payload: &[u8],
    ) -> Result<Self, StructuralSnapshotError> {
        u32::try_from(source.len()).map_err(|_| {
            StructuralSnapshotError::invalid("structural source length exceeds u32")
        })?;
        let snapshot: StructuralFactsSnapshot = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .with_limit(payload.len() as u64)
            .reject_trailing_bytes()
            .deserialize(payload)
            .map_err(|error| {
                StructuralSnapshotError::invalid(format!(
                    "deserialize structural facts snapshot: {error}"
                ))
            })?;
        if snapshot.role_offsets.len() != snapshot.nodes.len().saturating_add(1) {
            return Err(StructuralSnapshotError::invalid(format!(
                "structural role row count {} does not match node count {}",
                snapshot.role_offsets.len().saturating_sub(1),
                snapshot.nodes.len()
            )));
        }
        let node_count = u32::try_from(snapshot.nodes.len()).map_err(|_| {
            StructuralSnapshotError::invalid("structural snapshot node count exceeds u32")
        })?;
        let line_starts = compute_line_starts(&source);
        let mut nodes = Vec::with_capacity(snapshot.nodes.len());
        for (id, node) in snapshot.nodes.into_iter().enumerate() {
            let id = id as u32;
            if node.parent.is_some_and(|parent| parent >= id) {
                return Err(StructuralSnapshotError::invalid(format!(
                    "structural node {id} has invalid parent {:?}",
                    node.parent
                )));
            }
            if node.subtree_end <= id || node.subtree_end > node_count {
                return Err(StructuralSnapshotError::invalid(format!(
                    "structural node {id} has invalid subtree end {} for {node_count} nodes",
                    node.subtree_end
                )));
            }
            let span = decode_span(node.span, &source)?;
            let name = node
                .name
                .map(|name| decode_span(name, &source))
                .transpose()?;
            if name.is_some_and(|name| {
                name.start_byte < span.start_byte || name.end_byte > span.end_byte
            }) {
                return Err(StructuralSnapshotError::invalid(format!(
                    "structural node {id} name is outside its node span"
                )));
            }
            nodes.push(NormalizedNode {
                kind: decode_kind(node.kind)?,
                range: Range {
                    start_byte: span.start_byte,
                    end_byte: span.end_byte,
                    start_line: line_of_byte(&line_starts, span.start_byte),
                    end_line: line_of_byte(&line_starts, span.end_byte),
                },
                parent: node.parent,
                name,
                subtree_end: node.subtree_end,
            });
        }
        for (id, node) in nodes.iter().enumerate() {
            if let Some(parent) = node.parent
                && id as u32 >= nodes[parent as usize].subtree_end
            {
                return Err(StructuralSnapshotError::invalid(format!(
                    "structural node {id} lies outside parent {parent}'s subtree"
                )));
            }
        }

        let mut roles = Vec::with_capacity(snapshot.roles.len());
        for target in snapshot.roles {
            if target.node.is_some_and(|node| node >= node_count) {
                return Err(StructuralSnapshotError::invalid(format!(
                    "structural role target node {:?} is outside {node_count} nodes",
                    target.node
                )));
            }
            roles.push(RoleTarget {
                role: decode_role(target.role)?,
                spread: target.spread,
                keyword: target
                    .keyword
                    .map(|span| decode_span(span, &source))
                    .transpose()?,
                node: target.node,
                span: decode_span(target.span, &source)?,
                name: target
                    .name
                    .map(|span| decode_span(span, &source))
                    .transpose()?,
            });
        }
        let roles = CompactRows::try_from_parts(snapshot.role_offsets, roles)
            .map_err(StructuralSnapshotError::invalid)?;
        Ok(Self::new(source, line_starts, nodes, roles))
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

    /// Total bounded extraction work retained by this snapshot.
    ///
    /// Normalized nodes and their semantic role edges share the CodeQuery
    /// fact budget: either collection can grow independently for valid syntax.
    pub(crate) fn work_item_count(&self) -> usize {
        self.nodes.len().saturating_add(self.roles.len())
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
    use super::{
        FileFacts, NormalizedNode, RoleTarget, SnapshotNode, SnapshotRoleTarget, SnapshotSpan,
        Span, StructuralFactsSnapshot, decode_kind, decode_role, kind_code, role_code,
    };
    use crate::analyzer::Range;
    use crate::analyzer::structural::kinds::{ALL_KINDS, ALL_ROLES, NormalizedKind, Role};
    use crate::compact_graph::CompactRowsBuilder;
    use bincode::Options;

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

    fn snapshot_fixture() -> FileFacts {
        let source = "f(é)\n".to_owned();
        let nodes = vec![
            NormalizedNode {
                kind: NormalizedKind::Call,
                range: Range {
                    start_byte: 0,
                    end_byte: 5,
                    start_line: 1,
                    end_line: 1,
                },
                parent: None,
                name: Some(Span {
                    start_byte: 0,
                    end_byte: 1,
                }),
                subtree_end: 2,
            },
            NormalizedNode {
                kind: NormalizedKind::Identifier,
                range: Range {
                    start_byte: 2,
                    end_byte: 4,
                    start_line: 1,
                    end_line: 1,
                },
                parent: Some(0),
                name: Some(Span {
                    start_byte: 2,
                    end_byte: 4,
                }),
                subtree_end: 2,
            },
        ];
        let mut roles = CompactRowsBuilder::with_capacity(2, 2);
        roles.push_row([
            RoleTarget {
                role: Role::Callee,
                spread: false,
                keyword: None,
                node: None,
                span: Span {
                    start_byte: 0,
                    end_byte: 1,
                },
                name: Some(Span {
                    start_byte: 0,
                    end_byte: 1,
                }),
            },
            RoleTarget {
                role: Role::Arg,
                spread: true,
                keyword: None,
                node: Some(1),
                span: Span {
                    start_byte: 2,
                    end_byte: 4,
                },
                name: Some(Span {
                    start_byte: 2,
                    end_byte: 4,
                }),
            },
        ]);
        roles.push_row([]);
        FileFacts::new(source, vec![0, 6], nodes, roles.finish())
    }

    fn serialize_wire(snapshot: &StructuralFactsSnapshot) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .with_varint_encoding()
            .reject_trailing_bytes()
            .serialize(snapshot)
            .unwrap()
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

    #[test]
    fn snapshot_codes_cover_the_complete_structural_vocabulary() {
        for &kind in ALL_KINDS {
            assert_eq!(decode_kind(kind_code(kind)).unwrap(), kind);
        }
        for &role in ALL_ROLES {
            assert_eq!(decode_role(role_code(role)).unwrap(), role);
        }
    }

    #[test]
    fn snapshot_round_trip_reconstructs_identical_hot_facts() {
        let original = snapshot_fixture();
        let payload = original.encode_snapshot().unwrap();
        let decoded = FileFacts::decode_snapshot(original.source().to_owned(), &payload).unwrap();

        assert_eq!(decoded.source(), original.source());
        assert_eq!(decoded.nodes().len(), original.nodes().len());
        for (actual, expected) in decoded.nodes().iter().zip(original.nodes()) {
            assert_eq!(actual.kind, expected.kind);
            assert_eq!(actual.range, expected.range);
            assert_eq!(actual.parent, expected.parent);
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.subtree_end, expected.subtree_end);
        }
        assert_eq!(decoded.role_count(), original.role_count());
        for node in 0..original.nodes().len() as u32 {
            for (actual, expected) in decoded.roles(node).iter().zip(original.roles(node)) {
                assert_eq!(actual.role, expected.role);
                assert_eq!(actual.spread, expected.spread);
                assert_eq!(actual.keyword, expected.keyword);
                assert_eq!(actual.node, expected.node);
                assert_eq!(actual.span, expected.span);
                assert_eq!(actual.name, expected.name);
            }
        }
        assert_eq!(decoded.line_of_byte(0), 1);
        assert_eq!(decoded.line_of_byte(6), 2);
    }

    #[test]
    fn snapshot_decode_rejects_unknown_codes_and_corrupt_rows() {
        let unknown_kind = StructuralFactsSnapshot {
            nodes: vec![SnapshotNode {
                kind: u8::MAX,
                span: SnapshotSpan { start: 0, end: 1 },
                parent: None,
                name: None,
                subtree_end: 1,
            }],
            role_offsets: vec![0, 0],
            roles: vec![],
        };
        let error =
            FileFacts::decode_snapshot("x".to_owned(), &serialize_wire(&unknown_kind)).unwrap_err();
        assert!(error.to_string().contains("unknown structural kind code"));

        let corrupt_rows = StructuralFactsSnapshot {
            nodes: vec![SnapshotNode {
                kind: kind_code(NormalizedKind::Call),
                span: SnapshotSpan { start: 0, end: 1 },
                parent: None,
                name: None,
                subtree_end: 1,
            }],
            role_offsets: vec![0, 2],
            roles: vec![SnapshotRoleTarget {
                role: role_code(Role::Callee),
                spread: false,
                keyword: None,
                node: None,
                span: SnapshotSpan { start: 0, end: 1 },
                name: None,
            }],
        };
        let error =
            FileFacts::decode_snapshot("x".to_owned(), &serialize_wire(&corrupt_rows)).unwrap_err();
        assert!(error.to_string().contains("offsets must end"));
    }

    #[test]
    fn snapshot_decode_rejects_source_mismatch_and_trailing_bytes() {
        let facts = snapshot_fixture();
        let mut payload = facts.encode_snapshot().unwrap();
        let source_error = FileFacts::decode_snapshot("f".to_owned(), &payload).unwrap_err();
        assert!(source_error.to_string().contains("outside source length"));

        payload.push(0);
        let trailing_error = FileFacts::decode_snapshot(facts.source().to_owned(), &payload)
            .expect_err("snapshot decoder must reject trailing bytes");
        assert!(
            trailing_error
                .to_string()
                .contains("deserialize structural facts snapshot")
        );
    }
}
