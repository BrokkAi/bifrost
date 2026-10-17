//! The structural fact values a language spec produces.
//!
//! The language-owned fact rows live here with the vocabulary and spec trait;
//! the snapshot codec and `FileFacts` container stay in
//! `brokk-bifrost-analysis` with the extraction engine.

use crate::analyzer::source_facts::SourceOccurrenceId;
use crate::analyzer::structural::callable::CallSiteFacts;
use crate::analyzer::structural::kinds::{NormalizedKind, Role};
use crate::analyzer::structural::occurrences::OccurrenceRole;
use crate::compact_graph::CompactRows;
use serde::{Deserialize, Serialize};

/// A byte span into the file's source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Exact Python-style integer-literal information. `decimal` is retained when
/// its canonical spelling fits the query value limit; `low_bits` always
/// preserves the lowest 32 bits for mask predicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerLiteralValue {
    pub decimal: Option<String>,
    pub low_bits: u32,
    /// Whether the decoded magnitude is negative. The magnitude stays in
    /// `decimal` so the existing bounded decimal contract remains stable.
    #[serde(default)]
    pub negative: bool,
}

impl IntegerLiteralValue {
    /// Apply a grammar-backed unary minus to this decoded magnitude.
    /// Negative zero has the same canonical identity as zero.
    pub fn negated(mut self) -> Self {
        if self.decimal.as_deref() == Some("0") {
            return self;
        }
        self.negative = true;
        self.low_bits = 0u32.wrapping_sub(self.low_bits);
        self
    }

    /// The canonical signed decimal identity, when the magnitude was small
    /// enough for the query-value bound.
    pub fn signed_decimal(&self) -> Option<String> {
        self.decimal.as_ref().map(|decimal| {
            if self.negative {
                format!("-{decimal}")
            } else {
                decimal.clone()
            }
        })
    }
}

/// Decode the digit sequence of a non-negative integer literal.
///
/// Language adapters own the grammar-specific work of selecting the radix,
/// removing a language's suffix, and deciding whether the token is an integer.
/// Once those choices are made, the decimal spelling and low-bit projection
/// are the same for every language. Keeping the conversion here prevents
/// adapters from drifting on large values or digit separators.
pub fn decode_integer_literal_digits(radix: u32, digits: &[u8]) -> Option<IntegerLiteralValue> {
    assert!((2..=36).contains(&radix));

    // Keep in sync with RQL's MAX_STRING_PREDICATE_LENGTH. Larger canonical
    // values remain useful for low-bit predicates but cannot be named by an
    // exact-value query.
    const MAX_QUERYABLE_INTEGER_DECIMAL_LENGTH: usize = 4096;

    let mut decimal_digits = vec![0u8];
    let mut digit_count = 0usize;
    let mut low_bits = 0u32;
    let mut retain_decimal = true;
    for &byte in digits {
        if byte == b'_' {
            continue;
        }
        let digit = char::from(byte).to_digit(radix)?;
        digit_count += 1;

        let next =
            (u64::from(low_bits) * u64::from(radix) + u64::from(digit)) & u64::from(u32::MAX);
        low_bits = u32::try_from(next).expect("masked integer literal bits fit in u32");

        if retain_decimal {
            let mut carry = digit;
            for decimal_digit in &mut decimal_digits {
                let expanded = u32::from(*decimal_digit) * radix + carry;
                *decimal_digit =
                    u8::try_from(expanded % 10).expect("decimal digit remains below ten");
                carry = expanded / 10;
            }
            while carry != 0 {
                decimal_digits.push(u8::try_from(carry % 10).expect("decimal digit fits"));
                carry /= 10;
            }
            if decimal_digits.len() > MAX_QUERYABLE_INTEGER_DECIMAL_LENGTH {
                decimal_digits.clear();
                retain_decimal = false;
            }
        }
    }
    if digit_count == 0 {
        return None;
    }

    let decimal = retain_decimal.then(|| {
        decimal_digits
            .iter()
            .rev()
            .map(|digit| char::from(b'0' + *digit))
            .collect()
    });
    Some(IntegerLiteralValue {
        decimal,
        low_bits,
        negative: false,
    })
}

impl Span {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        source.get(self.start_byte..self.end_byte).unwrap_or("")
    }
}

/// One role edge from a fact to a sub-node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTarget {
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
    /// Whether a string-literal expression is enclosed by one or more
    /// parenthesized-expression nodes, when its adapter publishes this fact.
    pub parenthesized: Option<bool>,
    /// Direct tuple/list assignment shape when both sides are supported
    /// sequence forms.
    pub assignment_shape: Option<AssignmentShape>,
    /// Exact value and low permission bits for an integer literal.
    pub integer_literal_value: Option<IntegerLiteralValue>,
    /// Whether this Python dictionary entry's key repeats an earlier key by
    /// decoded literal value. `None` means the adapter could not answer.
    pub duplicate_key: Option<bool>,
    /// AST-backed async modifier for a callable fact. `None` means this
    /// adapter cannot answer the property for this node.
    pub is_async: Option<bool>,
    /// Decoded value of a string-literal expression, when the adapter can
    /// classify its complete source spelling. `None` for other kinds or when
    /// the adapter does not support this axis.
    pub string_value: Option<String>,
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
    /// node that does not satisfy [`NormalizedKind::Call`], and `None` for a
    /// call whose adapter does not refine call sites — the derivation layer then
    /// keeps the receiver-derived baseline rather than guessing.
    pub call_site: Option<CallSiteFacts>,
}

/// Sequence syntax directly paired by one multiple assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentSequenceKind {
    List,
    Tuple,
}

impl AssignmentSequenceKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Tuple => "tuple",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "list" => Some(Self::List),
            "tuple" => Some(Self::Tuple),
            _ => None,
        }
    }
}

/// Paired direct sequence sides of a multiple assignment. Counts exclude
/// starred elements; the star flags preserve the unpacking distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentShape {
    pub target_kind: AssignmentSequenceKind,
    pub value_kind: AssignmentSequenceKind,
    pub target_unstarred_count: u32,
    pub value_unstarred_count: u32,
    pub target_starred: bool,
    pub value_starred: bool,
}

/// The language-owned structural rows for one file.
///
/// Rows are grouped by normalized node. Construction asserts the row
/// boundaries and the node-level boolean-value invariant so consumers can use
/// typed accessors without carrying a partial-state error path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralFactRows {
    nodes: Vec<NormalizedNode>,
    roles: CompactRows<RoleTarget>,
    occurrence_roles: CompactRows<OccurrenceRole>,
    /// The regions tree-sitter error recovery produced, in source order: each
    /// outermost `ERROR` node and each `MISSING` token, which is zero-width
    /// (#3777). A node of any kind inside an `ERROR` region may have produced
    /// no fact, so a selection that finds nothing is complete only when no
    /// region could hold a node it selects.
    recovered_regions: Vec<Span>,
}

impl StructuralFactRows {
    pub fn new(
        nodes: Vec<NormalizedNode>,
        roles: CompactRows<RoleTarget>,
        occurrence_roles: CompactRows<OccurrenceRole>,
        recovered_regions: Vec<Span>,
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
        assert!(
            nodes.iter().all(
                |node| node.is_async.is_none() || node.kind.satisfies(NormalizedKind::Callable)
            ),
            "only normalized callable facts may carry async properties"
        );
        assert!(
            nodes
                .iter()
                .all(|node| node.parenthesized.is_none()
                    || node.kind == NormalizedKind::StringLiteral),
            "only normalized string-literal facts may carry parenthesized state"
        );
        assert!(
            nodes
                .iter()
                .all(|node| node.assignment_shape.is_none()
                    || node.kind == NormalizedKind::Assignment),
            "only normalized assignments may carry assignment-shape facts"
        );
        assert!(
            nodes.iter().all(|node| node.integer_literal_value.is_none()
                || node.kind == NormalizedKind::NumericLiteral),
            "only normalized numeric literals may carry integer values"
        );
        assert!(
            nodes
                .iter()
                .all(|node| node.duplicate_key.is_none()
                    || node.kind == NormalizedKind::ObjectProperty),
            "only normalized object properties may carry duplicate-key facts"
        );
        assert!(
            nodes
                .iter()
                .all(|node| node.string_value.is_none()
                    || node.kind == NormalizedKind::StringLiteral),
            "only normalized string literals may carry decoded string values"
        );
        // Pre-order: a node's subtree ends inside the file's facts, and a
        // child comes after its parent and inside the parent's subtree.
        for (index, node) in nodes.iter().enumerate() {
            assert!(
                index < node.subtree_end as usize && node.subtree_end as usize <= nodes.len(),
                "structural node {index} has subtree end {} for {} nodes: {node:?}",
                node.subtree_end,
                nodes.len()
            );
            if let Some(parent) = node.parent {
                assert!(
                    (parent as usize) < index
                        && index < nodes[parent as usize].subtree_end as usize,
                    "structural node {index} lies outside the subtree of parent {parent}: node {node:?}, parent {:?}",
                    nodes.get(parent as usize)
                );
            }
        }
        // Outermost recovered regions are disjoint tree nodes in preorder.
        for pair in recovered_regions.windows(2) {
            assert!(
                pair[0].start_byte <= pair[0].end_byte && pair[0].end_byte <= pair[1].start_byte,
                "recovered regions must be ordered and disjoint: {recovered_regions:?}"
            );
        }
        Self {
            nodes,
            roles,
            occurrence_roles,
            recovered_regions,
        }
    }

    pub fn nodes(&self) -> &[NormalizedNode] {
        &self.nodes
    }

    pub fn node(&self, id: u32) -> &NormalizedNode {
        &self.nodes[id as usize]
    }

    pub fn roles(&self, id: u32) -> &[RoleTarget] {
        self.roles.row(id as usize)
    }

    pub fn occurrence_roles(&self, id: u32) -> &[OccurrenceRole] {
        self.occurrence_roles.row(id as usize)
    }

    pub fn occurrence_role_count(&self) -> usize {
        self.occurrence_roles.len()
    }

    pub fn recovered_regions(&self) -> &[Span] {
        &self.recovered_regions
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
                    .map(|node| {
                        node.construct.as_ref().map_or(0, String::capacity) as u64
                            + node.string_value.as_ref().map_or(0, String::capacity) as u64
                            + node
                                .integer_literal_value
                                .as_ref()
                                .and_then(|value| value.decimal.as_ref())
                                .map_or(0, String::capacity) as u64
                    })
                    .sum::<u64>(),
            )
            .saturating_add(self.roles.estimated_bytes())
            .saturating_add(self.occurrence_roles.estimated_bytes())
            .saturating_add(
                (self.recovered_regions.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<Span>() as u64),
            )
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<NormalizedNode>,
        CompactRows<RoleTarget>,
        CompactRows<OccurrenceRole>,
        Vec<Span>,
    ) {
        (
            self.nodes,
            self.roles,
            self.occurrence_roles,
            self.recovered_regions,
        )
    }
}
