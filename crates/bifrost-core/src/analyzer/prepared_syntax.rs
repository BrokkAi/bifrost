//! Live parse state prepared from one exact source snapshot.
//!
//! [`PreparedSyntaxTree`] is what request-time code reads when it needs the
//! actual `tree_sitter::Tree` for a file rather than the persisted declaration
//! facts: usage extraction, resolvers, the per-language semantic lowerers. It
//! holds model-layer data plus a tree, so a language crate below
//! `brokk-bifrost-analysis` can consume one; the preparation pipeline that
//! parses, caches and evicts them stays in the analysis crate.
//!
//! The indexed backing is a [`PreparedSourceIndex`] rather than a concrete
//! type because the analyzer's `FileState` -- the full hydrated per-file record
//! -- is storage machinery. Only the three facts below are part of the
//! contract, so the trait names exactly those and `FileState` implements it.

use std::sync::Arc;
use tree_sitter::{Node, Tree};

use crate::analyzer::model::{CodeUnit, LanguageDialect, Range};
use crate::analyzer::project::OverlayRevision;

/// The declaration facts a prepared tree consults when it was prepared from an
/// indexed file rather than a bare source snapshot.
pub trait PreparedSourceIndex: std::fmt::Debug + Send + Sync {
    /// The exact source snapshot the tree was parsed from.
    fn source(&self) -> &str;

    /// Declaration ranges recorded for `code_unit`, preferred range first.
    fn declaration_ranges(&self, code_unit: &CodeUnit) -> Option<&[Range]>;

    /// Declarations directly nested inside `owner`.
    fn direct_children(&self, owner: &CodeUnit) -> Option<&[CodeUnit]>;
}

/// Source backing for an immutable prepared syntax tree.
///
/// Ordinary unbounded queries retain the indexed file record needed by
/// declaration-oriented helpers. Bounded syntax-only queries retain just the
/// exact admitted source snapshot, avoiding analyzer hydration and store
/// writes before their cancellable parse.
#[derive(Debug)]
pub enum PreparedSyntaxSource {
    Indexed(Arc<dyn PreparedSourceIndex>),
    Exact(Arc<str>),
}

impl PreparedSyntaxSource {
    pub fn source(&self) -> &str {
        match self {
            Self::Indexed(index) => index.source(),
            Self::Exact(source) => source,
        }
    }

    fn index(&self) -> Option<&dyn PreparedSourceIndex> {
        match self {
            Self::Indexed(index) => Some(index.as_ref()),
            Self::Exact(_) => None,
        }
    }
}

/// How the exact source snapshot selected for a prepared syntax tree entered
/// the analyzer. The content digest remains authoritative; this marker keeps
/// disk and unsaved-overlay revisions distinct even when their bytes match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreparedSourceOrigin {
    Disk,
    Overlay,
}

/// Immutable syntax prepared from one exact source snapshot. Keeping the
/// backing alive prevents the source bytes and tree from drifting apart while
/// concurrent queries reuse it.
#[derive(Debug)]
pub struct PreparedSyntaxTree {
    source: PreparedSyntaxSource,
    tree: Tree,
    line_starts: Vec<usize>,
    dialect: LanguageDialect,
    origin: PreparedSourceOrigin,
    overlay_revision: Option<OverlayRevision>,
}

impl PreparedSyntaxTree {
    /// Bind an already-parsed tree to the source snapshot it came from. The
    /// caller owns the parse, the line-start computation and the caching; this
    /// only seals the pairing.
    pub fn new(
        source: PreparedSyntaxSource,
        tree: Tree,
        line_starts: Vec<usize>,
        dialect: LanguageDialect,
        origin: PreparedSourceOrigin,
        overlay_revision: Option<OverlayRevision>,
    ) -> Self {
        Self {
            source,
            tree,
            line_starts,
            dialect,
            origin,
            overlay_revision,
        }
    }

    pub fn source(&self) -> &str {
        self.source.source()
    }

    /// Which backing this tree was prepared from. An `Exact` snapshot carries
    /// no declaration facts, so [`Self::declaration_node`] and
    /// [`Self::direct_children`] answer emptily for it.
    pub fn backing(&self) -> &PreparedSyntaxSource {
        &self.source
    }

    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    pub fn declaration_node(&self, code_unit: &CodeUnit) -> Option<Node<'_>> {
        let range = self
            .source
            .index()?
            .declaration_ranges(code_unit)?
            .first()?;
        self.tree
            .root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
    }

    pub fn direct_children(&self, owner: &CodeUnit) -> &[CodeUnit] {
        self.source
            .index()
            .and_then(|index| index.direct_children(owner))
            .unwrap_or_default()
    }

    pub fn line_starts(&self) -> &[usize] {
        &self.line_starts
    }

    pub const fn dialect(&self) -> LanguageDialect {
        self.dialect
    }

    pub const fn origin(&self) -> PreparedSourceOrigin {
        self.origin
    }

    pub const fn overlay_revision(&self) -> Option<OverlayRevision> {
        self.overlay_revision
    }
}
