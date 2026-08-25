use crate::analyzer::ProjectFile;
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;

/// The exact files a usage query is allowed to scan.
///
/// Candidate expansion happens before this value is constructed. Once file
/// and source-byte budgets have admitted the set, language code cannot add a
/// target, importer, or convention-derived file behind the planner's back.
pub struct UsageScanScope<'a> {
    candidate_files: &'a HashSet<ProjectFile>,
    cancellation: Option<&'a CancellationToken>,
}

impl<'a> UsageScanScope<'a> {
    pub fn new(candidate_files: &'a HashSet<ProjectFile>) -> Self {
        Self {
            candidate_files,
            cancellation: None,
        }
    }

    pub fn with_cancellation(
        candidate_files: &'a HashSet<ProjectFile>,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            candidate_files,
            cancellation: Some(cancellation),
        }
    }

    pub fn candidate_files(&self) -> &'a HashSet<ProjectFile> {
        self.candidate_files
    }

    pub fn allows(&self, file: &ProjectFile) -> bool {
        self.candidate_files.contains(file)
    }

    pub fn cancellation(&self) -> Option<&'a CancellationToken> {
        self.cancellation
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(CancellationToken::is_cancelled)
    }
}
