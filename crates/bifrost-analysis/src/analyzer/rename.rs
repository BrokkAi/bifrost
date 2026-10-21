//! Shared rename vocabulary and the language-owned rename provider boundary.

use super::{CodeUnit, IAnalyzer, Project, ProjectFile};

pub const MAX_RENAME_IDENTIFIER_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub enum RenameSelection {
    ByteOffset(usize),
    LineColumn { line: usize, column: usize },
}

#[derive(Debug, Clone)]
pub struct RenameFailure {
    pub kind: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PreparedRename {
    pub start_byte: usize,
    pub end_byte: usize,
    pub placeholder: String,
}

#[derive(Debug, Clone)]
pub struct RenameEdit {
    pub start_byte: usize,
    pub end_byte: usize,
    pub new_text: String,
}

#[derive(Debug, Clone)]
pub struct RenameFileEdits {
    pub file: ProjectFile,
    pub edits: Vec<RenameEdit>,
}

#[derive(Debug, Clone)]
pub struct RenameResult {
    pub target: CodeUnit,
    pub old_name: String,
    pub files: Vec<RenameFileEdits>,
}

/// One language-owned authority for edit discovery and capture validation.
/// Target selection and identifier validation happen before this boundary.
#[doc(hidden)]
pub trait RenameProvider: Send + Sync {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, RenameFailure>;
}
