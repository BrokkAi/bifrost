//! Source-owned Python callable annotations, including declarations that are
//! intentionally absent from the mounted display inventory.

use crate::analyzer::model::{StructuredTypeIdentity, StructuredTypeNodeView};
use crate::analyzer::source_facts::{SourceDeclarationId, SourceFactRows, SourceOccurrenceId};
use crate::hash::HashSet;

pub const PYTHON_SOURCE_FACTS_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonCallableReturnFact {
    pub declaration: SourceDeclarationId,
    /// None explicitly means the callable has no declared return annotation.
    pub return_annotation: Option<SourceOccurrenceId>,
    /// The supported nominal runtime interpretation. An annotation occurrence
    /// with no runtime type retains unsupported syntax without inventing a name.
    pub runtime_type: Option<StructuredTypeIdentity>,
    pub annotation_references: Vec<PythonAnnotationReferenceFact>,
}

/// The ordered name-resolution candidates selected from a declared annotation.
/// Qualified candidates retain their structured path; literal forward names
/// retain their exact string content for the existing lexical-name contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonAnnotationReferenceName {
    Lexical(String),
    Qualified(Vec<String>),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonAnnotationReferenceFact {
    pub occurrence: SourceOccurrenceId,
    pub name: PythonAnnotationReferenceName,
    /// Exclusive preorder end. Successful lookup skips fallback descendants.
    pub subtree_end: usize,
    /// Relative depth charged by the existing bounded annotation resolver.
    pub lookup_depth: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonSourceFacts {
    pub callable_returns: Vec<PythonCallableReturnFact>,
}

impl PythonSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = self
            .callable_returns
            .capacity()
            .saturating_mul(std::mem::size_of::<PythonCallableReturnFact>());
        for fact in &self.callable_returns {
            bytes = bytes.saturating_add(
                fact.runtime_type
                    .as_ref()
                    .map_or(0, StructuredTypeIdentity::estimated_retained_bytes),
            );
            bytes = bytes.saturating_add(
                fact.annotation_references
                    .capacity()
                    .saturating_mul(std::mem::size_of::<PythonAnnotationReferenceFact>()),
            );
            for reference in &fact.annotation_references {
                bytes = bytes.saturating_add(match &reference.name {
                    PythonAnnotationReferenceName::Lexical(name) => name.capacity(),
                    PythonAnnotationReferenceName::Qualified(path) => path
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>())
                        .saturating_add(path.iter().map(String::capacity).sum::<usize>()),
                    PythonAnnotationReferenceName::Unavailable => 0,
                });
            }
        }
        bytes
    }

    pub fn valid_links(&self, source: &SourceFactRows) -> bool {
        let mut declarations = HashSet::default();
        for fact in &self.callable_returns {
            let Some(declaration) = source.declarations().get(fact.declaration.index()) else {
                return false;
            };
            if !declarations.insert(fact.declaration) {
                return false;
            }
            let declaration_range = source.occurrence(declaration.occurrence).range;
            if let Some(annotation) = fact.return_annotation {
                let Some(annotation) = source.occurrences().get(annotation.index()) else {
                    return false;
                };
                if annotation.range.start_byte < declaration_range.start_byte
                    || annotation.range.end_byte > declaration_range.end_byte
                {
                    return false;
                }
            }
            let mut parent_ends = Vec::new();
            for (index, reference) in fact.annotation_references.iter().enumerate() {
                let Some(annotation) = fact.return_annotation else {
                    return false;
                };
                let annotation = source.occurrence(annotation).range;
                let Some(occurrence) = source.occurrences().get(reference.occurrence.index())
                else {
                    return false;
                };
                if occurrence.range.start_byte < annotation.start_byte
                    || occurrence.range.end_byte > annotation.end_byte
                    || reference.subtree_end <= index
                    || reference.subtree_end > fact.annotation_references.len()
                    || reference.lookup_depth > 2
                {
                    return false;
                }
                while parent_ends.last().is_some_and(|end| *end <= index) {
                    parent_ends.pop();
                }
                if parent_ends
                    .last()
                    .is_some_and(|end| reference.subtree_end > *end)
                {
                    return false;
                }
                if reference.subtree_end > index + 1 {
                    parent_ends.push(reference.subtree_end);
                }
                if match &reference.name {
                    PythonAnnotationReferenceName::Lexical(name) => name.is_empty(),
                    PythonAnnotationReferenceName::Qualified(path) => {
                        path.is_empty() || path.iter().any(String::is_empty)
                    }
                    PythonAnnotationReferenceName::Unavailable => false,
                } {
                    return false;
                }
            }
            if let Some(runtime_type) = &fact.runtime_type {
                let Some(StructuredTypeNodeView::Named(name)) =
                    runtime_type.view(runtime_type.root_id())
                else {
                    return false;
                };
                if fact.return_annotation.is_none()
                    || !name.lexical_scope().is_empty()
                    || name.is_absolute()
                {
                    return false;
                }
            }
        }
        true
    }
}
