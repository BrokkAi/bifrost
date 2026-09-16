//! Canonical source-backed occurrences for one parsed file.
//!
//! A source occurrence is an exact region produced by the language-owned
//! traversal. Primary tree-sitter nodes are interned by their live AST node
//! identity; explicit subspans are always new occurrences, even when their
//! ranges happen to be equal. Consumer projections hold typed occurrence ids
//! rather than authoring another source range or name authority.

use crate::analyzer::Range;
use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::structural::resolution::DeclaredVisibility;
use crate::analyzer::tree_walk::node_range;
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use serde::{Deserialize, Serialize};
use tree_sitter::Node;

/// Version of the canonical source-declaration visibility publication contract.
pub const SOURCE_DECLARATION_VISIBILITY_VERSION: i64 = 1;

/// The narrow mutable source-arena interface used by consumer projections
/// while the primary syntax tree is live.
pub trait SourceOccurrenceSink {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId;

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId;
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct SourceOccurrenceId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

define_dense_id! {
    /// A content-local identity for one semantic import leaf.
    ///
    /// Separate from consumer ordinals: generic imports omit local-only Rust
    /// bindings, and native root imports omit unsupported or non-root bindings.
    /// The producer allocates one identity per leaf for explicit projection links.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct SourceImportId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceOccurrenceProvenance {
    PrimaryNode,
    ExplicitSubspan,
    Embedded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceOccurrence {
    pub range: Range,
    pub provenance: SourceOccurrenceProvenance,
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct SourceDeclarationId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDeclaration {
    pub occurrence: SourceOccurrenceId,
    pub name: Option<SourceOccurrenceId>,
}

/// The source-owned visibility of one declaration.
///
/// This fact is keyed by the declaration identity allocated by the primary
/// source collector, rather than by a display unit or native resolution site.
/// A producer may therefore publish visibility for declarations that have no
/// native projection (for example Java record components or enum constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceDeclarationVisibilityFact {
    pub declaration: SourceDeclarationId,
    pub visibility: DeclaredVisibility,
}

/// The canonical source-backed rows for one file. The rows own no parser
/// handles and can be cloned into a prepared file product.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceFactRows {
    occurrences: Vec<SourceOccurrence>,
    declarations: Vec<SourceDeclaration>,
}

impl SourceFactRows {
    pub fn new(occurrences: Vec<SourceOccurrence>, declarations: Vec<SourceDeclaration>) -> Self {
        for occurrence in &occurrences {
            assert!(
                occurrence.range.start_byte <= occurrence.range.end_byte
                    && occurrence.range.start_line >= 1
                    && occurrence.range.start_line <= occurrence.range.end_line,
                "source occurrence has invalid range {:?}",
                occurrence.range
            );
        }
        for declaration in &declarations {
            assert!(
                declaration.occurrence.index() < occurrences.len(),
                "source declaration points outside occurrence rows"
            );
            if let Some(name) = declaration.name {
                assert!(
                    name.index() < occurrences.len(),
                    "source declaration name points outside occurrence rows"
                );
                let declaration_range = occurrences[declaration.occurrence.index()].range;
                let name_range = occurrences[name.index()].range;
                assert!(
                    declaration_range.start_byte <= name_range.start_byte
                        && name_range.end_byte <= declaration_range.end_byte,
                    "source declaration name must lie within declaration occurrence"
                );
            }
        }
        Self {
            occurrences,
            declarations,
        }
    }

    pub fn occurrences(&self) -> &[SourceOccurrence] {
        &self.occurrences
    }

    pub fn occurrence(&self, id: SourceOccurrenceId) -> &SourceOccurrence {
        &self.occurrences[id.index()]
    }

    pub fn declarations(&self) -> &[SourceDeclaration] {
        &self.declarations
    }

    pub fn declaration(&self, id: SourceDeclarationId) -> &SourceDeclaration {
        &self.declarations[id.index()]
    }

    pub fn occurrence_count(&self) -> usize {
        self.occurrences.len()
    }

    pub fn declaration_count(&self) -> usize {
        self.declarations.len()
    }

    pub fn estimated_bytes(&self) -> usize {
        self.occurrences
            .capacity()
            .saturating_mul(std::mem::size_of::<SourceOccurrence>())
            .saturating_add(
                self.declarations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceDeclaration>()),
            )
    }
}

/// Mutable producer-side arena shared by native and structural projections
/// while the primary syntax tree is live.
pub struct PrimarySourceFactCollector<'source> {
    source: &'source str,
    line_starts: Vec<usize>,
    occurrences: Vec<SourceOccurrence>,
    declarations: Vec<SourceDeclaration>,
    primary_by_node: HashMap<usize, SourceOccurrenceId>,
    declaration_by_pair:
        HashMap<(SourceOccurrenceId, Option<SourceOccurrenceId>), SourceDeclarationId>,
}

impl<'source> PrimarySourceFactCollector<'source> {
    pub fn new(source: &'source str) -> Self {
        Self {
            source,
            line_starts: compute_line_starts(source),
            occurrences: Vec::new(),
            declarations: Vec::new(),
            primary_by_node: HashMap::default(),
            declaration_by_pair: HashMap::default(),
        }
    }

    /// Intern one exact primary AST node. Repeated requests for the same live
    /// node return the original source identity.
    pub fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        if let Some(id) = self.primary_by_node.get(&node.id()).copied() {
            return id;
        }
        let range = node_range(node);
        self.assert_range(range);
        let id = self.push_occurrence(range, SourceOccurrenceProvenance::PrimaryNode);
        assert!(self.primary_by_node.insert(node.id(), id).is_none());
        id
    }

    /// Exact live-node identities already requested by producer projections.
    /// A language with several dialect projections can use its primary event
    /// ordinals to finalize each content-owned arena deterministically.
    pub fn primary_node_occurrences(
        &self,
    ) -> impl Iterator<Item = (usize, SourceOccurrenceId)> + '_ {
        self.primary_by_node
            .iter()
            .map(|(&node, &occurrence)| (node, occurrence))
    }

    /// Add an explicit source subspan. Equal ranges intentionally do not
    /// deduplicate: callers use this for distinct semantic occurrences whose
    /// source attributes happen to overlap or match.
    pub fn intern_subspan(
        &mut self,
        range: Range,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        assert_ne!(
            provenance,
            SourceOccurrenceProvenance::PrimaryNode,
            "primary occurrences must be interned from their live AST node"
        );
        self.assert_range(range);
        self.push_occurrence(range, provenance)
    }

    /// Add an explicit byte subspan while deriving canonical 1-based line
    /// bounds from the source owned by this collector.
    pub fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        let range = self.range_for_bytes(start_byte, end_byte);
        self.intern_subspan(range, provenance)
    }

    pub fn intern_embedded(&mut self, range: Range) -> SourceOccurrenceId {
        self.intern_subspan(range, SourceOccurrenceProvenance::Embedded)
    }

    /// Link a declaration interpretation to its whole-source occurrence and
    /// optional name-token occurrence. This allocates no new source range.
    pub fn declare(
        &mut self,
        occurrence: SourceOccurrenceId,
        name: Option<SourceOccurrenceId>,
    ) -> SourceDeclarationId {
        if let Some(id) = self.declaration_by_pair.get(&(occurrence, name)).copied() {
            return id;
        }
        let declaration_range = self.occurrence(occurrence).range;
        if let Some(name) = name {
            let name_range = self.occurrence(name).range;
            assert!(
                declaration_range.start_byte <= name_range.start_byte
                    && name_range.end_byte <= declaration_range.end_byte,
                "declaration name occurrence must lie within declaration occurrence"
            );
        }
        let id = SourceDeclarationId::try_from_index(self.declarations.len())
            .expect("source declaration ids must fit in a u32");
        self.declarations
            .push(SourceDeclaration { occurrence, name });
        assert!(
            self.declaration_by_pair
                .insert((occurrence, name), id)
                .is_none(),
            "source declaration pair was inserted twice"
        );
        id
    }

    pub fn occurrence(&self, id: SourceOccurrenceId) -> &SourceOccurrence {
        &self.occurrences[id.index()]
    }

    pub fn declaration(&self, id: SourceDeclarationId) -> &SourceDeclaration {
        &self.declarations[id.index()]
    }

    pub fn finish(self) -> SourceFactRows {
        SourceFactRows::new(self.occurrences, self.declarations)
    }

    fn push_occurrence(
        &mut self,
        range: Range,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        let id = SourceOccurrenceId::try_from_index(self.occurrences.len())
            .expect("source occurrence ids must fit in a u32");
        self.occurrences
            .push(SourceOccurrence { range, provenance });
        id
    }

    fn range_for_bytes(&self, start_byte: usize, end_byte: usize) -> Range {
        assert!(start_byte <= end_byte);
        let start_line = find_line_index_for_offset(&self.line_starts, start_byte) + 1;
        let end_line = find_line_index_for_offset(&self.line_starts, end_byte) + 1;
        Range {
            start_byte,
            end_byte,
            start_line,
            end_line,
        }
    }

    fn assert_range(&self, range: Range) {
        assert!(
            range.start_byte <= range.end_byte
                && range.end_byte <= self.source.len()
                && self.source.is_char_boundary(range.start_byte)
                && self.source.is_char_boundary(range.end_byte),
            "source occurrence range {:?} must be within UTF-8 source bounds",
            range
        );
    }
}

impl SourceOccurrenceSink for PrimarySourceFactCollector<'_> {
    fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
        PrimarySourceFactCollector::intern_node(self, node)
    }

    fn intern_subspan_bytes(
        &mut self,
        start_byte: usize,
        end_byte: usize,
        provenance: SourceOccurrenceProvenance,
    ) -> SourceOccurrenceId {
        PrimarySourceFactCollector::intern_subspan_bytes(self, start_byte, end_byte, provenance)
    }
}
