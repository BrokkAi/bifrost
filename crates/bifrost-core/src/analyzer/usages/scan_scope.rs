use crate::analyzer::ProjectFile;
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;

/// Files a usage query is allowed to scan.
///
/// A non-authoritative scope is a candidate hint: strategies may add importers,
/// definition files, or other structured files. An authoritative scope is a hard
/// boundary from a caller-supplied `paths` filter: any internally-added files
/// must already be present in `candidate_files`.
pub struct UsageScanScope<'a> {
    candidate_files: &'a HashSet<ProjectFile>,
    authoritative: bool,
    cancellation: Option<&'a CancellationToken>,
}

impl<'a> UsageScanScope<'a> {
    pub fn new(candidate_files: &'a HashSet<ProjectFile>, authoritative: bool) -> Self {
        Self {
            candidate_files,
            authoritative,
            cancellation: None,
        }
    }

    pub fn with_cancellation(
        candidate_files: &'a HashSet<ProjectFile>,
        authoritative: bool,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            candidate_files,
            authoritative,
            cancellation: Some(cancellation),
        }
    }

    pub fn candidate_files(&self) -> &'a HashSet<ProjectFile> {
        self.candidate_files
    }

    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    pub fn allows(&self, file: &ProjectFile) -> bool {
        !self.authoritative || self.candidate_files.contains(file)
    }

    pub fn cancellation(&self) -> Option<&'a CancellationToken> {
        self.cancellation
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(CancellationToken::is_cancelled)
    }
}
