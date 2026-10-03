//! Canonical source-backed occurrences for one parsed file.
//!
//! A source occurrence is an exact region produced by the language-owned
//! traversal. Primary tree-sitter nodes are interned by their live AST node
//! identity; explicit subspans are always new occurrences, even when their
//! ranges happen to be equal. Consumer projections hold typed occurrence ids
//! rather than authoring another source range or name authority.

use crate::analyzer::Range;
use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::model::DeclarationKind;
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// Presentation metadata for a canonical declaration without a parser unit.
/// The declaration id, not its spelling or range, owns this interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLexicalDeclarationFact {
    pub declaration: SourceDeclarationId,
    pub kind: DeclarationKind,
    pub identifier: String,
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
    lexical_declarations: Vec<SourceLexicalDeclarationFact>,
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
            lexical_declarations: Vec::new(),
        }
    }

    pub fn with_lexical_declarations(
        mut self,
        mut lexical_declarations: Vec<SourceLexicalDeclarationFact>,
    ) -> Self {
        lexical_declarations.sort_unstable_by_key(|fact| fact.declaration);
        for (index, fact) in lexical_declarations.iter().enumerate() {
            assert!(fact.declaration.index() < self.declarations.len());
            assert!(self.declaration(fact.declaration).name.is_some());
            assert!(!fact.identifier.is_empty());
            assert!(index == 0 || lexical_declarations[index - 1].declaration != fact.declaration);
        }
        self.lexical_declarations = lexical_declarations;
        self
    }

    pub fn lexical_declarations(&self) -> &[SourceLexicalDeclarationFact] {
        &self.lexical_declarations
    }

    pub fn lexical_declaration(
        &self,
        declaration: SourceDeclarationId,
    ) -> Option<&SourceLexicalDeclarationFact> {
        self.lexical_declarations
            .binary_search_by_key(&declaration, |fact| fact.declaration)
            .ok()
            .map(|index| &self.lexical_declarations[index])
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
            .saturating_add(
                self.lexical_declarations
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceLexicalDeclarationFact>()),
            )
            .saturating_add(
                self.lexical_declarations
                    .iter()
                    .map(|fact| fact.identifier.capacity())
                    .sum::<usize>(),
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
    lexical_declarations: HashMap<SourceDeclarationId, SourceLexicalDeclarationFact>,
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
            lexical_declarations: HashMap::default(),
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
                "declaration name occurrence must lie within declaration occurrence: declaration={declaration_range:?}, name={name_range:?}, name_text={:?}",
                &self.source[name_range.start_byte..name_range.end_byte]
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

    /// Capture the exact AST-backed name while the producer owns source text.
    pub fn declare_lexical(
        &mut self,
        occurrence: SourceOccurrenceId,
        name: SourceOccurrenceId,
        kind: DeclarationKind,
    ) -> SourceDeclarationId {
        let declaration = self.declare(occurrence, Some(name));
        let range = self.occurrence(name).range;
        let fact = SourceLexicalDeclarationFact {
            declaration,
            kind,
            identifier: self.source[range.start_byte..range.end_byte].to_owned(),
        };
        assert!(!fact.identifier.is_empty());
        match self.lexical_declarations.entry(declaration) {
            std::collections::hash_map::Entry::Occupied(existing) => {
                assert_eq!(
                    existing.get(),
                    &fact,
                    "contradictory lexical declaration metadata"
                );
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(fact);
            }
        }
        declaration
    }

    /// Give an existing canonical declaration its out-of-graph presentation.
    ///
    /// `declare_lexical` is for declarations the producer creates purely for
    /// this purpose. Use this instead when the declaration already exists,
    /// for example an item the property collector captured, and only the
    /// lexical interpretation is missing: creating a second declaration for
    /// the same site would publish two native bridges for one resolution
    /// site, which is a corrupt fact set rather than extra evidence.
    pub fn mark_lexical(&mut self, declaration: SourceDeclarationId, kind: DeclarationKind) {
        let name = self
            .declaration(declaration)
            .name
            .expect("an out-of-graph lexical declaration needs its exact name occurrence");
        let range = self.occurrence(name).range;
        self.mark_lexical_identifier(
            declaration,
            kind,
            self.source[range.start_byte..range.end_byte].to_owned(),
        );
    }

    /// Publish a grammar-derived name when a declaration has no name token,
    /// such as a positional field. Its name occurrence locates the field syntax.
    pub fn mark_lexical_identifier(
        &mut self,
        declaration: SourceDeclarationId,
        kind: DeclarationKind,
        identifier: String,
    ) {
        let fact = SourceLexicalDeclarationFact {
            declaration,
            kind,
            identifier,
        };
        assert!(!fact.identifier.is_empty());
        match self.lexical_declarations.entry(declaration) {
            std::collections::hash_map::Entry::Occupied(existing) => {
                assert_eq!(
                    existing.get(),
                    &fact,
                    "contradictory lexical declaration metadata"
                );
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(fact);
            }
        }
    }

    pub fn finish(self) -> SourceFactRows {
        SourceFactRows::new(self.occurrences, self.declarations)
            .with_lexical_declarations(self.lexical_declarations.into_values().collect())
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
