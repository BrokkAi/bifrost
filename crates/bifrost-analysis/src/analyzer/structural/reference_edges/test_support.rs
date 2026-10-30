use super::*;

use crate::analyzer::structural::test_support::workspace_fixture;
use crate::analyzer::{Language, WorkspaceAnalyzer};
use crate::inline_project::BuiltInlineTestProject;

#[doc(hidden)]
pub struct Fixture {
    pub(super) _project: BuiltInlineTestProject,
    pub(super) workspace: WorkspaceAnalyzer,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub files: Vec<ProjectFile>,
}

impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, sources: &[(&str, &str)]) -> Self {
        let (project, workspace, _files, _) = workspace_fixture(language, sources);
        Self {
            _project: project,
            workspace,
            #[cfg(any(test, feature = "test-support"))]
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
