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
    explicit_candidate_files: Option<&'a HashSet<ProjectFile>>,
    cancellation: Option<&'a CancellationToken>,
    include_tests: bool,
}

impl<'a> UsageScanScope<'a> {
    pub fn new(candidate_files: &'a HashSet<ProjectFile>) -> Self {
        Self {
            candidate_files,
            explicit_candidate_files: None,
            cancellation: None,
            include_tests: true,
        }
    }

    pub fn with_cancellation(
        candidate_files: &'a HashSet<ProjectFile>,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            candidate_files,
            explicit_candidate_files: None,
            cancellation: Some(cancellation),
            include_tests: true,
        }
    }

    /// Carry the admitted files the caller named explicitly, separately from discovery.
    pub fn with_explicit_candidates(mut self, files: Option<&'a HashSet<ProjectFile>>) -> Self {
        debug_assert!(files.is_none_or(|files| files.is_subset(self.candidate_files)));
        self.explicit_candidate_files = files;
        self
    }

    pub fn explicit_candidate_files(&self) -> Option<&'a HashSet<ProjectFile>> {
        self.explicit_candidate_files
    }

    /// Set whether test source participates in this usage query's inventory.
    pub fn with_test_inclusion(mut self, include_tests: bool) -> Self {
        self.include_tests = include_tests;
        self
    }

    pub fn candidate_files(&self) -> &'a HashSet<ProjectFile> {
        self.candidate_files
    }

    pub const fn includes_tests(&self) -> bool {
        self.include_tests
    }

    pub fn allows(&self, file: &ProjectFile) -> bool {
        self.candidate_files.contains(file)
    }

    pub fn cancellation(&self) -> Option<&'a CancellationToken> {
        self.cancellation
    }

    pub fn is_cancelled(&self) -> bool {
        crate::cancellation::optional_is_cancelled(self.cancellation)
    }
}
