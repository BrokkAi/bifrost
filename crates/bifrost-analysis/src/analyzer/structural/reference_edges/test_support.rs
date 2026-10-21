use super::*;

use crate::analyzer::structural::test_support::workspace_fixture;
use crate::analyzer::{Language, WorkspaceAnalyzer};

#[doc(hidden)]
pub struct Fixture {
    pub(super) _temp: tempfile::TempDir,
    pub(super) workspace: WorkspaceAnalyzer,
    #[cfg(test)]
    pub(super) files: Vec<ProjectFile>,
}

impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, sources: &[(&str, &str)]) -> Self {
        let (temp, workspace, _files, _) = workspace_fixture(language, sources);
        Self {
            _temp: temp,
            workspace,
            #[cfg(test)]
            files: _files,
        }
    }

    #[doc(hidden)]
    pub fn analyzer(&self) -> &dyn IAnalyzer {
        self.workspace.analyzer()
    }

    #[doc(hidden)]
    pub fn declaration(&self, fq_suffix: &str) -> CodeUnit {
        crate::analyzer::structural::test_support::declarations_ending_with(
            self.analyzer(),
            fq_suffix,
        )
        .next()
        .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
    }
}
