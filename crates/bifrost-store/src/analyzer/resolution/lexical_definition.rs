use crate::analyzer::DeclarationKind;
use crate::analyzer::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalDefinition {
    /// The defining file for a macro binding whose expansion can occur elsewhere.
    /// Ordinary lexical definitions use the reference file.
    pub source_file: Option<crate::analyzer::ProjectFile>,
    pub identifier: String,
    pub kind: DeclarationKind,
    pub name_range: Range,
    pub declaration_range: Range,
}
