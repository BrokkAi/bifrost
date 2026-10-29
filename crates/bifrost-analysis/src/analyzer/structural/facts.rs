//! Normalized structural facts for one file: the arena the matcher runs over.
//!
//! Facts are extracted from a tree-sitter parse (see `extract.rs`) and are the
//! only view of a file the matcher ever sees — grammar-specific node types
//! stop at the language spec boundary. Nodes live in a flat `Vec` addressed by
//! `u32` ids with parent links for containment; role edges (`callee`, `args`,
//! `left`, ...) point at either another fact or, when the target expression is
//! not itself normalized, at a raw source span.

pub use crate::analyzer::store::structural_vocabulary::{
    PersistedCallSite, PersistedOccurrenceRole, PersistedRecoveredRegion, PersistedSpan,
    PersistedStructuralFacts, PersistedStructuralNode, PersistedStructuralRole,
    STRUCTURAL_FACTS_VERSION,
};

pub use brokk_bifrost_core::analyzer::structural::facts::{
    AssignmentSequenceKind, AssignmentShape, IntegerLiteralValue, Span,
};

use brokk_bifrost_core::analyzer::source_facts::SourceFactRows;
use brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows;

use super::kinds::{NormalizedKind, Role};
use super::occurrences::OccurrenceRole;
use super::provider::LiveRegistration;
use crate::analyzer::Range;
use crate::analyzer::semantic::ContentIdentity;
use crate::compact_graph::{CompactRows, CompactRowsBuilder};
use crate::text_utils::compute_line_starts;
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallShapeCoverage, CallSiteFacts,
};

use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;
use std::fmt;

#[derive(Debug, Clone)]
pub struct RoleTarget {
    pub role: Role,
    pub spread: bool,
    pub keyword: Option<Span>,
    pub node: Option<u32>,
    pub span: Span,
    pub name: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct NormalizedNode {
    pub kind: NormalizedKind,
    pub boolean_value: Option<bool>,
    pub parenthesized: Option<bool>,
    pub assignment_shape: Option<AssignmentShape>,
    pub integer_literal_value: Option<IntegerLiteralValue>,
    pub duplicate_key: Option<bool>,
    pub is_async: Option<bool>,
    /// Rust call-site unsafe context; absent on other kinds and languages.
    pub unsafe_context: Option<bool>,
    pub declaration_attributes:
        Option<brokk_bifrost_core::analyzer::structural::facts::DeclarationAttributes>,
    pub string_value: Option<String>,
    pub construct: Option<String>,
    pub range: Range,
    pub parent: Option<u32>,
    pub name: Option<Span>,
    pub subtree_end: u32,
    pub call_site: Option<CallSiteFacts>,
}

impl NormalizedNode {
    pub fn span(&self) -> Span {
        Span {
            start_byte: self.range.start_byte,
            end_byte: self.range.end_byte,
        }
    }
}

/// One region tree-sitter error recovery produced: an outermost `ERROR` node,
/// or a zero-width `MISSING` token (#3777). A node of any kind inside an
/// `ERROR` region may have produced no fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredRegion {
    pub range: Range,
    /// Whether a callable fact's range contains the region: its body, its
    /// signature or a default value. The store answers this in SQL from the
    /// persisted rows when it hydrates them. `None` when these facts were
    /// built from a parse the store has not answered for.
    pub inside_callable: Option<bool>,
}

impl RecoveredRegion {
    /// Whether this region could hold a node of one of `kinds` that recovery
    /// left without a fact, so a selection of those kinds that finds nothing
    /// in the file is not a complete answer for it.
    ///
    /// The rule follows [`NormalizedKind::is_statement_level`]. A selection
    /// whose every kind is statement-level is hidden only by a region inside
    /// a callable. A selection with any other kind, or with no kind
    /// constraint, is hidden by every region. A region whose containment the
    /// store has not answered may be inside a callable.
    pub fn may_hide(&self, kinds: &[NormalizedKind]) -> bool {
        if !kinds.is_empty()
            && kinds
                .iter()
                .all(|kind| *kind == NormalizedKind::SyntaxError)
        {
            return false;
        }
        let statement_level =
            !kinds.is_empty() && kinds.iter().all(|kind| kind.is_statement_level());
        !statement_level || self.inside_callable != Some(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct StructuralFactsPersistenceError(String);

impl StructuralFactsPersistenceError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for StructuralFactsPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StructuralFactsPersistenceError {}

#[cfg(any(test, feature = "test-support"))]
fn persist_span(span: Span) -> Result<PersistedSpan, StructuralFactsPersistenceError> {
    Ok(PersistedSpan {
        start: u32::try_from(span.start_byte).map_err(|_| {
            StructuralFactsPersistenceError::invalid("structural span start exceeds u32")
        })?,
        end: u32::try_from(span.end_byte).map_err(|_| {
            StructuralFactsPersistenceError::invalid("structural span end exceeds u32")
        })?,
    })
}

fn hydrate_span(
    span: PersistedSpan,
    source: &str,
) -> Result<Span, StructuralFactsPersistenceError> {
    let start_byte = span.start as usize;
    let end_byte = span.end as usize;
    if start_byte > end_byte || end_byte > source.len() {
        return Err(StructuralFactsPersistenceError::invalid(format!(
            "structural span {start_byte}..{end_byte} is outside source length {}",
            source.len()
        )));
    }
    if !source.is_char_boundary(start_byte) || !source.is_char_boundary(end_byte) {
        return Err(StructuralFactsPersistenceError::invalid(format!(
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

fn is_canonical_integer_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && ((bytes[0] == b'0' && bytes.len() == 1)
            || (matches!(bytes[0], b'1'..=b'9')
                && bytes[1..].iter().all(|byte| byte.is_ascii_digit())))
}

fn is_valid_integer_literal_value(value: &IntegerLiteralValue) -> bool {
    value.decimal.as_deref().is_none_or(|decimal| {
        is_canonical_integer_decimal(decimal)
            && if value.negative {
                0u32.wrapping_sub(decimal_low_bits(decimal)) == value.low_bits
            } else {
                decimal_low_bits(decimal) == value.low_bits
            }
    })
}

fn decimal_low_bits(value: &str) -> u32 {
    value.bytes().fold(0u32, |low_bits, digit| {
        debug_assert!(digit.is_ascii_digit());
        let next = u64::from(low_bits) * 10 + u64::from(digit - b'0');
        u32::try_from(next & u64::from(u32::MAX)).expect("masked integer literal bits fit in u32")
    })
}

fn materialize_rows(
    source_facts: &SourceFactRows,
    rows: &StructuralFactRows,
) -> (Vec<NormalizedNode>, CompactRows<RoleTarget>) {
    let nodes = rows
        .nodes()
        .iter()
        .map(|node| NormalizedNode {
            kind: node.kind,
            boolean_value: node.boolean_value,
            parenthesized: node.parenthesized,
            assignment_shape: node.assignment_shape,
            integer_literal_value: node.integer_literal_value.clone(),
            duplicate_key: node.duplicate_key,
            is_async: node.is_async,
            unsafe_context: node.unsafe_context,
            declaration_attributes: node.declaration_attributes.clone(),
            string_value: node.string_value.clone(),
            construct: node.construct.clone(),
            range: source_facts.occurrence(node.occurrence).range,
            parent: node.parent,
            name: node
                .name
                .map(|name| source_facts.occurrence(name).range)
                .map(|range| Span {
                    start_byte: range.start_byte,
                    end_byte: range.end_byte,
                }),
            subtree_end: node.subtree_end,
            call_site: node.call_site.clone(),
        })
        .collect::<Vec<_>>();
    let mut roles = CompactRowsBuilder::with_capacity(nodes.len(), rows.role_count());
    for node_id in 0..nodes.len() as u32 {
        roles.push_row(rows.roles(node_id).iter().map(|role| {
            let range = source_facts.occurrence(role.occurrence).range;
            RoleTarget {
                role: role.role,
                spread: role.spread,
                keyword: role.keyword.map(|keyword| {
                    let range = source_facts.occurrence(keyword).range;
                    Span {
                        start_byte: range.start_byte,
                        end_byte: range.end_byte,
                    }
                }),
                node: role.node,
                span: Span {
                    start_byte: range.start_byte,
                    end_byte: range.end_byte,
                },
                name: role.name.map(|name| {
                    let range = source_facts.occurrence(name).range;
                    Span {
                        start_byte: range.start_byte,
                        end_byte: range.end_byte,
                    }
                }),
            }
        }));
    }
    (nodes, roles.finish())
}

fn append_empty_rows<T: Clone>(rows: CompactRows<T>, count: usize) -> CompactRows<T> {
    let mut builder =
        CompactRowsBuilder::with_capacity(rows.rows().saturating_add(count), rows.len());
    for row in 0..rows.rows() {
        builder.push_row(rows.row(row).iter().cloned());
    }
    for _ in 0..count {
        builder.finish_row();
    }
    builder.finish()
}

fn append_syntax_error_facts(
    mut nodes: Vec<NormalizedNode>,
    roles: CompactRows<RoleTarget>,
    occurrence_roles: CompactRows<OccurrenceRole>,
    recovered_regions: &[RecoveredRegion],
) -> (
    Vec<NormalizedNode>,
    CompactRows<RoleTarget>,
    CompactRows<OccurrenceRole>,
) {
    if recovered_regions.is_empty() {
        return (nodes, roles, occurrence_roles);
    }

    let error_count = recovered_regions.len();
    let roles = append_empty_rows(roles, error_count);
    let occurrence_roles = append_empty_rows(occurrence_roles, error_count);
    for region in recovered_regions {
        let node_id = u32::try_from(nodes.len())
            .expect("structural fact ids must fit in u32 before allocation");
        let subtree_end = node_id
            .checked_add(1)
            .expect("synthetic syntax-error fact id must leave room for its subtree end");
        nodes.push(NormalizedNode {
            kind: NormalizedKind::SyntaxError,
            boolean_value: None,
            parenthesized: None,
            assignment_shape: None,
            integer_literal_value: None,
            duplicate_key: None,
            is_async: None,
            unsafe_context: None,
            declaration_attributes: None,
            string_value: None,
            construct: None,
            range: region.range,
            parent: None,
            name: None,
            subtree_end,
            call_site: None,
        });
    }
    (nodes, roles, occurrence_roles)
}

/// All normalized facts for one file. `source` is a private copy so spans stay
/// valid however the analyzer's own file state evolves; `line_starts` maps
/// byte offsets to 1-based lines for capture reporting.
#[derive(Debug)]
pub struct FileFacts {
    pub(super) live_registration: std::sync::OnceLock<LiveRegistration>,
    source: String,
    source_identity: ContentIdentity,
    line_starts: Vec<usize>,
    nodes: Vec<NormalizedNode>,
    roles: CompactRows<RoleTarget>,
    occurrence_roles: CompactRows<OccurrenceRole>,
    recovered_regions: Vec<RecoveredRegion>,
}

impl FileFacts {
    pub(crate) fn new(
        source: String,
        line_starts: Vec<usize>,
        nodes: Vec<NormalizedNode>,
        roles: CompactRows<RoleTarget>,
        occurrence_roles: CompactRows<OccurrenceRole>,
        recovered_regions: Vec<RecoveredRegion>,
    ) -> Self {
        assert_eq!(roles.rows(), nodes.len());
        assert_eq!(occurrence_roles.rows(), nodes.len());
        assert!(nodes.iter().all(
            |node| node.boolean_value.is_none() || node.kind == NormalizedKind::BooleanLiteral
        ));
        assert!(nodes.iter().all(|node| {
            node.parenthesized.is_none() || node.kind == NormalizedKind::StringLiteral
        }));
        assert!(nodes.iter().all(|node| {
            node.assignment_shape.is_none() || node.kind == NormalizedKind::Assignment
        }));
        assert!(nodes.iter().all(|node| {
            node.integer_literal_value.as_ref().is_none_or(|value| {
                node.kind == NormalizedKind::NumericLiteral && is_valid_integer_literal_value(value)
            })
        }));
        assert!(nodes.iter().all(|node| {
            node.duplicate_key.is_none() || node.kind == NormalizedKind::ObjectProperty
        }));
        assert!(nodes.iter().all(|node| {
            node.string_value.is_none() || node.kind == NormalizedKind::StringLiteral
        }));
        assert!(
            nodes
                .iter()
                .all(|node| node.string_value.is_none()
                    || node.kind == NormalizedKind::StringLiteral),
            "string values must be attached only to string literals: {nodes:?}"
        );
        assert!(
            recovered_regions
                .iter()
                .all(|region| region.range.end_byte <= source.len()),
            "recovered regions must lie inside the {}-byte source: {recovered_regions:?}",
            source.len()
        );
        let source_identity = ContentIdentity::hash_bytes(source.as_bytes());
        Self {
            live_registration: std::sync::OnceLock::new(),
            source,
            source_identity,
            line_starts,
            nodes,
            roles,
            occurrence_roles,
            recovered_regions,
        }
    }

    /// Facts built from a parse rather than read from the store, so no
    /// recovered region has a containment answer.
    #[doc(hidden)]
    pub fn from_source_and_rows(
        source: String,
        source_facts: SourceFactRows,
        rows: StructuralFactRows,
    ) -> Self {
        let line_starts = compute_line_starts(&source);
        let (nodes, roles) = materialize_rows(&source_facts, &rows);
        let (_, _, occurrence_roles, recovered_regions) = rows.into_parts();
        let recovered_regions = recovered_regions
            .into_iter()
            .map(|span| RecoveredRegion {
                range: Range {
                    start_byte: span.start_byte,
                    end_byte: span.end_byte,
                    start_line: line_of_byte(&line_starts, span.start_byte),
                    end_line: line_of_byte(&line_starts, span.end_byte),
                },
                inside_callable: None,
            })
            .collect::<Vec<_>>();
        let (nodes, roles, occurrence_roles) =
            append_syntax_error_facts(nodes, roles, occurrence_roles, &recovered_regions);
        Self::new(
            source,
            line_starts,
            nodes,
            roles,
            occurrence_roles,
            recovered_regions,
        )
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub const fn source_identity(&self) -> ContentIdentity {
        self.source_identity
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn persisted_rows(
        &self,
    ) -> Result<PersistedStructuralFacts, StructuralFactsPersistenceError> {
        let source_bytes = u32::try_from(self.source.len()).map_err(|_| {
            StructuralFactsPersistenceError::invalid("structural source length exceeds u32")
        })?;
        let persisted_node_count = self
            .nodes
            .iter()
            .position(|node| node.kind == NormalizedKind::SyntaxError)
            .unwrap_or(self.nodes.len());
        assert!(
            self.nodes[persisted_node_count..]
                .iter()
                .all(|node| node.kind == NormalizedKind::SyntaxError)
        );
        let nodes = self
            .nodes
            .iter()
            .take(persisted_node_count)
            .enumerate()
            .map(|(node_id, node)| {
                Ok(PersistedStructuralNode {
                    node_id: u32::try_from(node_id).map_err(|_| {
                        StructuralFactsPersistenceError::invalid(
                            "structural node count exceeds u32",
                        )
                    })?,
                    kind: node.kind.code(),
                    boolean_value: node.boolean_value,
                    parenthesized: node.parenthesized,
                    assignment_shape: node.assignment_shape,
                    integer_literal_value: node.integer_literal_value.clone(),
                    duplicate_key: node.duplicate_key,
                    is_async: node.is_async,
                    unsafe_context: node.unsafe_context,
                    declaration_attributes: node.declaration_attributes.clone(),
                    string_value: node.string_value.clone(),
                    construct: node.construct.clone(),
                    span: persist_span(node.span())?,
                    parent: node.parent,
                    name: node.name.map(persist_span).transpose()?,
                    subtree_end: node.subtree_end,
                    call_site: node.call_site.as_ref().map(|facts| PersistedCallSite {
                        call_kind: facts.call_kind.map(|kind| kind.code()),
                        coverage: facts.coverage.code(),
                        continues_callee_groups: facts.continues_callee_groups,
                        callee_provenance: facts.callee_provenance.clone(),
                    }),
                })
            })
            .collect::<Result<Vec<_>, StructuralFactsPersistenceError>>()?;
        let mut roles = Vec::with_capacity(self.roles.len());
        for source_node_id in 0..persisted_node_count {
            let source_node_id = u32::try_from(source_node_id).map_err(|_| {
                StructuralFactsPersistenceError::invalid("structural node count exceeds u32")
            })?;
            for (ordinal, target) in self.roles(source_node_id).iter().enumerate() {
                roles.push(PersistedStructuralRole {
                    source_node_id,
                    ordinal: u32::try_from(ordinal).map_err(|_| {
                        StructuralFactsPersistenceError::invalid("structural role row exceeds u32")
                    })?,
                    role: target.role.code(),
                    spread: target.spread,
                    keyword: target.keyword.map(persist_span).transpose()?,
                    node: target.node,
                    span: persist_span(target.span)?,
                    name: target.name.map(persist_span).transpose()?,
                });
            }
        }
        let mut occurrence_roles = Vec::with_capacity(self.occurrence_role_count());
        for node_id in 0..persisted_node_count {
            let node_id = u32::try_from(node_id).map_err(|_| {
                StructuralFactsPersistenceError::invalid("structural node count exceeds u32")
            })?;
            for (ordinal, role) in self.occurrence_roles(node_id).iter().enumerate() {
                occurrence_roles.push(PersistedOccurrenceRole {
                    node_id,
                    ordinal: u32::try_from(ordinal).map_err(|_| {
                        StructuralFactsPersistenceError::invalid(
                            "structural occurrence-role row exceeds u32",
                        )
                    })?,
                    role: role.code(),
                });
            }
        }
        let recovered_regions = self
            .recovered_regions
            .iter()
            .map(|region| {
                Ok(PersistedRecoveredRegion {
                    span: persist_span(Span {
                        start_byte: region.range.start_byte,
                        end_byte: region.range.end_byte,
                    })?,
                    inside_callable: region.inside_callable.ok_or_else(|| {
                        StructuralFactsPersistenceError::invalid(
                            "only store-answered recovered regions have persisted rows",
                        )
                    })?,
                })
            })
            .collect::<Result<Vec<_>, StructuralFactsPersistenceError>>()?;
        Ok(PersistedStructuralFacts {
            source_bytes,
            nodes,
            roles,
            occurrence_roles,
            recovered_regions,
        })
    }

    #[doc(hidden)]
    pub fn from_persisted_rows(
        source: String,
        persisted: PersistedStructuralFacts,
    ) -> Result<Self, StructuralFactsPersistenceError> {
        let source_bytes = u32::try_from(source.len()).map_err(|_| {
            StructuralFactsPersistenceError::invalid("structural source length exceeds u32")
        })?;
        if persisted.source_bytes != source_bytes {
            return Err(StructuralFactsPersistenceError::invalid(format!(
                "persisted structural source length {} does not match source length {source_bytes}",
                persisted.source_bytes
            )));
        }
        let node_count = u32::try_from(persisted.nodes.len()).map_err(|_| {
            StructuralFactsPersistenceError::invalid("structural facts node count exceeds u32")
        })?;
        let line_starts = compute_line_starts(&source);
        let mut nodes: Vec<NormalizedNode> = Vec::with_capacity(persisted.nodes.len());
        for (id, node) in persisted.nodes.into_iter().enumerate() {
            let id = id as u32;
            if node.node_id != id {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "persisted structural node id {} is out of order at {id}",
                    node.node_id
                )));
            }
            if node.parent.is_some_and(|parent| parent >= id) {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} has invalid parent {:?}",
                    node.parent
                )));
            }
            if node.subtree_end <= id || node.subtree_end > node_count {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} has invalid subtree end {} for {node_count} nodes",
                    node.subtree_end
                )));
            }
            let span = hydrate_span(node.span, &source)?;
            let name = node
                .name
                .map(|name| hydrate_span(name, &source))
                .transpose()?;
            if let Some(name) = name
                && (name.start_byte < span.start_byte || name.end_byte > span.end_byte)
            {
                // A constructor can use its enclosing class's written name.
                // Follow the recorded ancestry; unrelated source text is not a name.
                let mut ancestor = node.parent;
                let mut inherited_name = false;
                while let Some(parent) = ancestor {
                    let parent = &nodes[parent as usize];
                    if parent.name == Some(name) {
                        inherited_name = true;
                        break;
                    }
                    ancestor = parent.parent;
                }
                if !inherited_name {
                    return Err(StructuralFactsPersistenceError::invalid(format!(
                        "structural node {id} name is outside its node span and is not an ancestor name"
                    )));
                }
            }
            let call_site = node
                .call_site
                .map(|facts| {
                    Ok::<_, StructuralFactsPersistenceError>(CallSiteFacts {
                        call_kind: facts
                            .call_kind
                            .map(|kind| {
                                CallKind::from_code(kind).ok_or_else(|| {
                                    StructuralFactsPersistenceError::invalid(format!(
                                        "unknown structural call kind {kind}"
                                    ))
                                })
                            })
                            .transpose()?,
                        coverage: CallShapeCoverage::from_code(facts.coverage).ok_or_else(
                            || {
                                StructuralFactsPersistenceError::invalid(format!(
                                    "unknown structural call coverage {}",
                                    facts.coverage
                                ))
                            },
                        )?,
                        continues_callee_groups: facts.continues_callee_groups,
                        callee_provenance: facts.callee_provenance.clone(),
                    })
                })
                .transpose()?;
            let kind = NormalizedKind::from_code(node.kind).ok_or_else(|| {
                StructuralFactsPersistenceError::invalid(format!(
                    "unknown structural kind code {}",
                    node.kind
                ))
            })?;
            if node.boolean_value.is_some() && kind != NormalizedKind::BooleanLiteral {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} carries a boolean value for non-boolean kind {}",
                    kind.label()
                )));
            }
            if node.parenthesized.is_some() && kind != NormalizedKind::StringLiteral {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} carries parenthesized state for non-string kind {}",
                    kind.label()
                )));
            }
            if node.assignment_shape.is_some() && kind != NormalizedKind::Assignment {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} carries assignment shape for non-assignment kind {}",
                    kind.label()
                )));
            }
            if node.integer_literal_value.as_ref().is_some_and(|value| {
                kind != NormalizedKind::NumericLiteral || !is_valid_integer_literal_value(value)
            }) {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} carries an invalid integer value for kind {}",
                    kind.label()
                )));
            }
            if node.duplicate_key.is_some() && kind != NormalizedKind::ObjectProperty {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} carries duplicate-key state for non-object-property kind {}",
                    kind.label()
                )));
            }
            if node.string_value.is_some() && kind != NormalizedKind::StringLiteral {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} carries a decoded string value for non-string kind {}",
                    kind.label()
                )));
            }
            nodes.push(NormalizedNode {
                kind,
                boolean_value: node.boolean_value,
                parenthesized: node.parenthesized,
                assignment_shape: node.assignment_shape,
                integer_literal_value: node.integer_literal_value,
                duplicate_key: node.duplicate_key,
                is_async: node.is_async,
                unsafe_context: node.unsafe_context,
                declaration_attributes: node.declaration_attributes,
                string_value: node.string_value,
                construct: node.construct,
                call_site,
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
        // Preorder intervals must encode exactly the parent chain, including
        // disjoint siblings and roots. Only the active ancestry is needed.
        let mut ancestors: Vec<u32> = Vec::new();
        for (id, node) in nodes.iter().enumerate() {
            let id = id as u32;
            while ancestors
                .last()
                .is_some_and(|parent| id >= nodes[*parent as usize].subtree_end)
            {
                ancestors.pop();
            }
            let interval_parent = ancestors.last().copied();
            if node.parent != interval_parent {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id} has parent {:?} but its interval parent is {interval_parent:?}",
                    node.parent
                )));
            }
            if let Some(parent) = interval_parent
                && node.subtree_end > nodes[parent as usize].subtree_end
            {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "structural node {id}'s interval extends outside parent {parent}'s subtree"
                )));
            }
            ancestors.push(id);
        }

        let mut role_offsets = Vec::with_capacity(nodes.len().saturating_add(1));
        let mut roles = Vec::with_capacity(persisted.roles.len());
        let mut persisted_roles = persisted.roles.into_iter().peekable();
        role_offsets.push(0);
        for source_node_id in 0..node_count {
            let mut ordinal = 0u32;
            while persisted_roles
                .peek()
                .is_some_and(|row| row.source_node_id == source_node_id)
            {
                let target = persisted_roles.next().expect("peeked structural role");
                if target.ordinal != ordinal {
                    return Err(StructuralFactsPersistenceError::invalid(format!(
                        "structural role ordinal {} is out of order for node {source_node_id}",
                        target.ordinal
                    )));
                }
                ordinal += 1;
                if target.node.is_some_and(|node| node >= node_count) {
                    return Err(StructuralFactsPersistenceError::invalid(format!(
                        "structural role target node {:?} is outside {node_count} nodes",
                        target.node
                    )));
                }
                roles.push(RoleTarget {
                    role: Role::from_code(target.role).ok_or_else(|| {
                        StructuralFactsPersistenceError::invalid(format!(
                            "unknown structural role code {}",
                            target.role
                        ))
                    })?,
                    spread: target.spread,
                    keyword: target
                        .keyword
                        .map(|span| hydrate_span(span, &source))
                        .transpose()?,
                    node: target.node,
                    span: hydrate_span(target.span, &source)?,
                    name: target
                        .name
                        .map(|span| hydrate_span(span, &source))
                        .transpose()?,
                });
            }
            role_offsets.push(u32::try_from(roles.len()).map_err(|_| {
                StructuralFactsPersistenceError::invalid("structural role count exceeds u32")
            })?);
        }
        if let Some(role) = persisted_roles.next() {
            return Err(StructuralFactsPersistenceError::invalid(format!(
                "structural role references out-of-order source node {}",
                role.source_node_id
            )));
        }
        let roles = CompactRows::try_from_parts(role_offsets, roles)
            .map_err(StructuralFactsPersistenceError::invalid)?;

        let mut occurrence_role_offsets = Vec::with_capacity(nodes.len().saturating_add(1));
        let mut occurrence_roles = Vec::with_capacity(persisted.occurrence_roles.len());
        let mut persisted_occurrence_roles = persisted.occurrence_roles.into_iter().peekable();
        occurrence_role_offsets.push(0);
        for node_id in 0..node_count {
            let mut ordinal = 0u32;
            while persisted_occurrence_roles
                .peek()
                .is_some_and(|row| row.node_id == node_id)
            {
                let row = persisted_occurrence_roles
                    .next()
                    .expect("peeked structural occurrence role");
                if row.ordinal != ordinal {
                    return Err(StructuralFactsPersistenceError::invalid(format!(
                        "structural occurrence-role ordinal {} is out of order for node {node_id}",
                        row.ordinal
                    )));
                }
                ordinal += 1;
                occurrence_roles.push(OccurrenceRole::from_code(row.role).ok_or_else(|| {
                    StructuralFactsPersistenceError::invalid(format!(
                        "unknown structural occurrence role code {}",
                        row.role
                    ))
                })?);
            }
            occurrence_role_offsets.push(u32::try_from(occurrence_roles.len()).map_err(|_| {
                StructuralFactsPersistenceError::invalid(
                    "structural occurrence-role count exceeds u32",
                )
            })?);
        }
        if let Some(row) = persisted_occurrence_roles.next() {
            return Err(StructuralFactsPersistenceError::invalid(format!(
                "structural occurrence role references out-of-order node {}",
                row.node_id
            )));
        }
        let occurrence_roles =
            CompactRows::try_from_parts(occurrence_role_offsets, occurrence_roles)
                .map_err(StructuralFactsPersistenceError::invalid)?;

        let mut recovered_regions = Vec::with_capacity(persisted.recovered_regions.len());
        for region in persisted.recovered_regions {
            let span = hydrate_span(region.span, &source)?;
            if recovered_regions
                .last()
                .is_some_and(|previous: &RecoveredRegion| previous.range.end_byte > span.start_byte)
            {
                return Err(StructuralFactsPersistenceError::invalid(format!(
                    "recovered region {}..{} is out of order or overlaps its predecessor",
                    span.start_byte, span.end_byte
                )));
            }
            recovered_regions.push(RecoveredRegion {
                range: Range {
                    start_byte: span.start_byte,
                    end_byte: span.end_byte,
                    start_line: line_of_byte(&line_starts, span.start_byte),
                    end_line: line_of_byte(&line_starts, span.end_byte),
                },
                inside_callable: Some(region.inside_callable),
            });
        }

        let (nodes, roles, occurrence_roles) =
            append_syntax_error_facts(nodes, roles, occurrence_roles, &recovered_regions);
        Ok(Self::new(
            source,
            line_starts,
            nodes,
            roles,
            occurrence_roles,
            recovered_regions,
        ))
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

    /// Occurrence-role classifications carried by `id`, in emission order.
    /// Empty for every node the adapter did not classify.
    pub fn occurrence_roles(&self, id: u32) -> &[OccurrenceRole] {
        self.occurrence_roles.row(id as usize)
    }

    /// Total occurrence-role classifications retained across this file.
    pub fn occurrence_role_count(&self) -> usize {
        self.occurrence_roles.len()
    }

    /// The regions tree-sitter error recovery produced, in source order.
    pub fn recovered_regions(&self) -> &[RecoveredRegion] {
        &self.recovered_regions
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
    pub fn work_item_count(&self) -> usize {
        self.nodes.len().saturating_add(self.roles.len())
    }

    pub fn subtree_end(&self, id: u32) -> u32 {
        self.node(id).subtree_end
    }

    /// 1-based line containing `byte`, matching the `Range` convention used
    /// across the analyzer.
    pub fn line_of_byte(&self, byte: usize) -> usize {
        line_of_byte(&self.line_starts, byte)
    }

    pub(crate) fn line_starts(&self) -> &[usize] {
        &self.line_starts
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
            .saturating_add(
                self.nodes
                    .iter()
                    .filter_map(|node| node.declaration_attributes.as_ref())
                    .map(|attributes| {
                        (attributes.modifiers.capacity() * std::mem::size_of::<String>()) as u64
                            + attributes
                                .modifiers
                                .iter()
                                .map(|word| word.capacity() as u64)
                                .sum::<u64>()
                            + attributes
                                .type_kind
                                .as_ref()
                                .map_or(0, |kind| kind.capacity() as u64)
                    })
                    .sum::<u64>(),
            )
            .saturating_add(self.roles.estimated_bytes())
            .saturating_add(self.occurrence_roles.estimated_bytes())
            .saturating_add(
                (self.recovered_regions.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<RecoveredRegion>() as u64),
            )
            .saturating_add(
                self.nodes
                    .iter()
                    .filter_map(|node| node.construct.as_ref())
                    .map(|construct| construct.capacity() as u64)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.nodes
                    .iter()
                    .filter_map(|node| node.string_value.as_ref())
                    .map(|value| value.capacity() as u64)
                    .sum::<u64>(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssignmentSequenceKind, AssignmentShape, FileFacts, IntegerLiteralValue, NormalizedNode,
        PersistedSpan, RoleTarget, Span,
    };

    use crate::analyzer::Range;
    use crate::analyzer::structural::kinds::{NormalizedKind, Role};
    use crate::analyzer::structural::occurrences::OccurrenceRole;
    use crate::compact_graph::{CompactRows, CompactRowsBuilder};
    use brokk_bifrost_core::analyzer::structural::callable::{
        CallKind, CallShapeCoverage, CallSiteFacts,
    };

    use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

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

    fn empty_occurrence_rows(rows: usize) -> CompactRows<OccurrenceRole> {
        CompactRows::from_parts(vec![0; rows + 1], Vec::new())
    }

    fn node() -> NormalizedNode {
        NormalizedNode {
            kind: NormalizedKind::Call,
            boolean_value: None,
            parenthesized: None,
            assignment_shape: None,
            integer_literal_value: None,
            duplicate_key: None,
            is_async: None,
            unsafe_context: None,
            declaration_attributes: None,
            string_value: None,
            construct: None,
            range: Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
            parent: None,
            name: None,
            subtree_end: 1,
            call_site: None,
        }
    }

    fn relational_fixture() -> FileFacts {
        let source = "f(é)\n".to_owned();
        let nodes = vec![
            NormalizedNode {
                kind: NormalizedKind::Call,
                boolean_value: None,
                parenthesized: None,
                assignment_shape: None,
                integer_literal_value: None,
                duplicate_key: None,
                is_async: None,
                unsafe_context: None,
                declaration_attributes: None,
                string_value: None,
                construct: Some("fixture_call".to_owned()),
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
                call_site: Some(CallSiteFacts {
                    callee_provenance: None,
                    call_kind: Some(CallKind::Method),
                    coverage: CallShapeCoverage::Partial,
                    continues_callee_groups: true,
                }),
            },
            NormalizedNode {
                kind: NormalizedKind::BooleanLiteral,
                boolean_value: Some(true),
                parenthesized: None,
                assignment_shape: None,
                integer_literal_value: None,
                duplicate_key: None,
                is_async: None,
                unsafe_context: None,
                declaration_attributes: None,
                string_value: None,
                construct: None,
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
                call_site: None,
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
                role: Role::Kwarg,
                spread: true,
                keyword: Some(Span {
                    start_byte: 0,
                    end_byte: 1,
                }),
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
        let mut occurrence_roles = CompactRowsBuilder::with_capacity(2, 1);
        occurrence_roles.push_row([]);
        occurrence_roles.push_row([OccurrenceRole::ValueReference]);
        FileFacts::new(
            source,
            vec![0, 6],
            nodes,
            roles.finish(),
            occurrence_roles.finish(),
            Vec::new(),
        )
    }

    #[test]
    fn relational_hydration_rejects_nonpreceding_parents_before_name_inheritance() {
        let fixture = relational_fixture();
        // The persisted preorder protocol requires parent < node_id, even
        // when an otherwise valid source name would need ancestor lookup.
        for parent in [1, 2, u32::MAX] {
            for inherited in [false, true] {
                let mut rows = fixture.persisted_rows().unwrap();
                rows.nodes[1].parent = Some(parent);
                if inherited {
                    rows.nodes[1].name = rows.nodes[0].name;
                }
                let result: Result<_, super::StructuralFactsPersistenceError> =
                    FileFacts::from_persisted_rows(fixture.source().into(), rows);
                assert!(result.is_err(), "parent={parent}, inherited={inherited}");
            }
        }
        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[0].parent = Some(1);
        rows.nodes[1].parent = Some(0);
        assert!(FileFacts::from_persisted_rows(fixture.source().into(), rows).is_err());
    }

    #[test]
    #[hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: sibling subtree intervals overlap despite parent ancestry"
    )]
    fn relational_intervals_agree_with_parent_chains() {
        let fixture = relational_fixture();
        // Exhaust all parent links and interval endpoints for four preorder rows.
        // The oracle follows parent links, independently of interval arithmetic.
        for parent_code in 0..24usize {
            let mut code = parent_code;
            let mut parents = [None; 4];
            for (id, parent) in parents.iter_mut().enumerate().skip(1) {
                let choice = code % (id + 1);
                code /= id + 1;
                *parent = (choice < id).then_some(choice as u32);
            }
            for end_code in 0..120usize {
                let mut code = end_code;
                let mut rows = fixture.persisted_rows().unwrap();
                let template = rows.nodes[0].clone();
                rows.nodes = (0..4)
                    .map(|id| {
                        let mut row = template.clone();
                        row.node_id = id;
                        row.parent = parents[id as usize];
                        row.subtree_end = id + (code % (5 - id as usize)) as u32;
                        code /= 5 - id as usize;
                        row
                    })
                    .collect();
                rows.roles.clear();
                rows.occurrence_roles.clear();
                let valid = rows.nodes.iter().enumerate().all(|(ancestor, row)| {
                    row.subtree_end > ancestor as u32
                        && (0..4u32).all(|descendant| {
                            let mut current = parents[descendant as usize];
                            let mut in_chain = false;
                            while let Some(parent) = current {
                                in_chain |= parent == ancestor as u32;
                                current = parents[parent as usize];
                            }
                            in_chain
                                == ((ancestor as u32) < descendant && descendant < row.subtree_end)
                        })
                });
                let description = format!("parents={parents:?}, nodes={:?}", rows.nodes);
                assert_eq!(
                    FileFacts::from_persisted_rows(fixture.source().into(), rows).is_ok(),
                    valid,
                    "{description}"
                );
            }
        }
    }

    #[test]
    fn integer_rows_preserve_bounded_decimal_and_signed_low_bits() {
        let fixture = relational_fixture();
        for negative in [false, true] {
            for decimal in [
                Some("0"),
                Some("1"),
                Some("4294967297"),
                Some("18446744073709551615"),
                Some("340282366920938463463374607431768211455"),
                None,
            ] {
                let magnitude = decimal.map_or(17, |value| {
                    (value.parse::<u128>().unwrap() % (1u128 << 32)) as u32
                });
                let value = IntegerLiteralValue {
                    decimal: decimal.map(str::to_owned),
                    negative,
                    low_bits: if negative {
                        0u32.wrapping_sub(magnitude)
                    } else {
                        magnitude
                    },
                };
                let mut rows = fixture.persisted_rows().unwrap();
                rows.nodes[0].kind = NormalizedKind::NumericLiteral.code();
                rows.nodes[0].call_site = None;
                rows.nodes[0].integer_literal_value = Some(value.clone());
                let hydrated =
                    FileFacts::from_persisted_rows(fixture.source().into(), rows).unwrap();
                assert_eq!(hydrated.node(0).integer_literal_value, Some(value));
            }
        }
        for decimal in ["00", "01", "", "+1", "-1", " 1", "1a"] {
            let mut rows = fixture.persisted_rows().unwrap();
            rows.nodes[0].kind = NormalizedKind::NumericLiteral.code();
            rows.nodes[0].call_site = None;
            rows.nodes[0].integer_literal_value = Some(IntegerLiteralValue {
                decimal: Some(decimal.into()),
                low_bits: if decimal == "00" { 0 } else { 1 },
                negative: false,
            });
            assert!(
                FileFacts::from_persisted_rows(fixture.source().into(), rows).is_err(),
                "{decimal:?}"
            );
        }
    }

    #[test]
    fn parsed_recovery_keeps_containment_unknown_until_hydration() {
        use brokk_bifrost_core::analyzer::source_facts::SourceFactRows;
        use brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows;
        for span in [
            Span {
                start_byte: 0,
                end_byte: 2,
            },
            Span {
                start_byte: 3,
                end_byte: 4,
            },
        ] {
            let parsed = FileFacts::from_source_and_rows(
                "\u{e9} ?".into(),
                SourceFactRows::new(Vec::new(), Vec::new()),
                StructuralFactRows::new(
                    Vec::new(),
                    CompactRows::from_parts(vec![0], Vec::new()),
                    CompactRows::from_parts(vec![0], Vec::new()),
                    vec![span],
                ),
            );
            let unknown = parsed.recovered_regions()[0];
            assert_eq!(unknown.inside_callable, None);
            assert_eq!(unknown.range.start_byte, span.start_byte);
            assert!(unknown.may_hide(&[NormalizedKind::Return]));
            assert!(!unknown.may_hide(&[NormalizedKind::SyntaxError]));
            for contained in [false, true] {
                let rows = super::PersistedStructuralFacts {
                    source_bytes: parsed.source().len() as u32,
                    nodes: Vec::new(),
                    roles: Vec::new(),
                    occurrence_roles: Vec::new(),
                    recovered_regions: vec![super::PersistedRecoveredRegion {
                        span: PersistedSpan {
                            start: span.start_byte as u32,
                            end: span.end_byte as u32,
                        },
                        inside_callable: contained,
                    }],
                };
                let hydrated =
                    FileFacts::from_persisted_rows(parsed.source().into(), rows).unwrap();
                assert_eq!(
                    hydrated.recovered_regions()[0].may_hide(&[NormalizedKind::Return]),
                    contained
                );
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn relational_round_trip_reconstructs_identical_hot_facts() {
        let original = relational_fixture();
        let rows = original.persisted_rows().unwrap();
        assert_eq!(rows.source_bytes, original.source().len() as u32);
        assert_eq!(rows.nodes[0].kind, NormalizedKind::Call.code());
        assert_eq!(rows.roles[1].role, Role::Kwarg.code());
        assert_eq!(
            rows.occurrence_roles[0].role,
            OccurrenceRole::ValueReference.code()
        );

        let decoded = FileFacts::from_persisted_rows(original.source().to_owned(), rows).unwrap();

        assert_eq!(decoded.source(), original.source());
        assert_eq!(decoded.nodes().len(), original.nodes().len());
        for (actual, expected) in decoded.nodes().iter().zip(original.nodes()) {
            assert_eq!(actual.kind, expected.kind);
            assert_eq!(actual.boolean_value, expected.boolean_value);
            assert_eq!(actual.parenthesized, expected.parenthesized);
            assert_eq!(actual.assignment_shape, expected.assignment_shape);
            assert_eq!(actual.integer_literal_value, expected.integer_literal_value);
            assert_eq!(actual.duplicate_key, expected.duplicate_key);
            assert_eq!(actual.construct, expected.construct);
            assert_eq!(
                actual.declaration_attributes,
                expected.declaration_attributes
            );
            assert_eq!(actual.range, expected.range);
            assert_eq!(actual.parent, expected.parent);
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.subtree_end, expected.subtree_end);
            assert_eq!(actual.call_site, expected.call_site);
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
            assert_eq!(
                decoded.occurrence_roles(node),
                original.occurrence_roles(node)
            );
        }
        assert_eq!(decoded.line_of_byte(0), 1);
        assert_eq!(decoded.line_of_byte(6), 2);
    }

    #[cfg(test)]
    #[test]
    fn assignment_shape_survives_relational_hydration() {
        let fixture = relational_fixture();
        let expected = AssignmentShape {
            target_kind: AssignmentSequenceKind::Tuple,
            value_kind: AssignmentSequenceKind::List,
            target_unstarred_count: 2,
            value_unstarred_count: 3,
            target_starred: false,
            value_starred: false,
        };
        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[0].kind = NormalizedKind::Assignment.code();
        rows.nodes[0].call_site = None;
        rows.nodes[0].assignment_shape = Some(expected);

        let hydrated = FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
            .expect("assignment shape persists as typed fields");

        assert_eq!(hydrated.nodes()[0].assignment_shape, Some(expected));
    }

    #[cfg(test)]
    #[test]
    fn duplicate_key_fact_survives_relational_hydration() {
        let fixture = relational_fixture();
        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[0].kind = NormalizedKind::ObjectProperty.code();
        rows.nodes[0].call_site = None;
        rows.nodes[0].duplicate_key = Some(true);

        let hydrated = FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
            .expect("duplicate-key fact persists as a typed scalar");

        assert_eq!(hydrated.nodes()[0].duplicate_key, Some(true));
    }

    #[cfg(test)]
    #[test]
    fn relational_hydration_rejects_inconsistent_rows() {
        let fixture = relational_fixture();

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[1].name = Some(PersistedSpan { start: 0, end: 1 });
        let decoded = FileFacts::from_persisted_rows(fixture.source().to_owned(), rows).unwrap();
        assert_eq!(
            decoded.nodes()[1].name,
            Some(Span {
                start_byte: 0,
                end_byte: 1
            })
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[1].name = Some(PersistedSpan {
            start: 0,
            end: fixture.source().len() as u32 + 1,
        });
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("outside source length")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[1].name = Some(PersistedSpan { start: 4, end: 2 });
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("outside source length")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[1].name = Some(PersistedSpan { start: 2, end: 3 });
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("UTF-8 boundaries")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.source_bytes -= 1;
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("source length")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[0].kind = u8::MAX;
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("unknown structural kind code")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[1].node_id = 7;
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("out of order")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.roles[1].ordinal = 9;
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("role ordinal")
        );

        let mut rows = fixture.persisted_rows().unwrap();
        rows.nodes[0].boolean_value = Some(true);
        assert!(
            FileFacts::from_persisted_rows(fixture.source().to_owned(), rows)
                .unwrap_err()
                .to_string()
                .contains("non-boolean kind call")
        );
    }

    #[cfg(test)]
    #[hardwon("#783: structural fact memory accounting ignored retained allocation capacity")]
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
        let roles = roles.finish();
        let occurrence_roles = empty_occurrence_rows(1);
        let facts = FileFacts::new(
            source,
            line_starts,
            nodes,
            roles,
            occurrence_roles,
            Vec::new(),
        );

        let source_length_based = facts.source.len() as u64
            + (facts.line_starts.len() * std::mem::size_of::<usize>()) as u64
            + (facts.nodes.len() * std::mem::size_of::<NormalizedNode>()) as u64
            + facts.roles.estimated_bytes()
            + facts.occurrence_roles.estimated_bytes()
            + facts
                .nodes
                .iter()
                .filter_map(|node| node.construct.as_ref())
                .map(|construct| construct.capacity() as u64)
                .sum::<u64>();
        let capacity_based = facts.source.capacity() as u64
            + (facts.line_starts.capacity() * std::mem::size_of::<usize>()) as u64
            + (facts.nodes.capacity() * std::mem::size_of::<NormalizedNode>()) as u64
            + facts.roles.estimated_bytes()
            + facts.occurrence_roles.estimated_bytes()
            + facts
                .nodes
                .iter()
                .filter_map(|node| node.construct.as_ref())
                .map(|construct| construct.capacity() as u64)
                .sum::<u64>();

        assert!(capacity_based > source_length_based);
        assert_eq!(facts.estimated_bytes(), capacity_based);
        assert_eq!(facts.role_count(), 1);
        assert_eq!(facts.roles(0).len(), 1);
        assert_eq!(facts.role_targets(0, Role::Callee).count(), 1);
        assert_eq!(facts.occurrence_role_count(), 0);
        assert!(facts.occurrence_roles(0).is_empty());
    }
}
