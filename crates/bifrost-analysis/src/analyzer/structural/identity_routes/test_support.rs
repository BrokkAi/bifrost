use super::*;

use crate::analyzer::Language;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::structural::test_support::workspace_fixture;
use crate::inline_project::BuiltInlineTestProject;

#[doc(hidden)]
pub struct Fixture {
    pub(super) _project: BuiltInlineTestProject,
    pub(super) workspace: WorkspaceAnalyzer,
    #[doc(hidden)]
    pub files: Vec<ProjectFile>,
    pub(super) sources: Vec<String>,
}
impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, files: &[(&str, &str)]) -> Self {
        let (project, workspace, project_files, sources) = workspace_fixture(language, files);
        Self {
            _project: project,
            workspace,
            files: project_files,
            sources,
        }
    }

    #[doc(hidden)]
    pub fn analyzer(&self) -> &dyn IAnalyzer {
        self.workspace.analyzer()
    }

    #[doc(hidden)]
    pub fn declaration(&self, fq_suffix: &str) -> CodeUnit {
        let mut all: Vec<CodeUnit> =
            crate::analyzer::structural::test_support::declarations_ending_with(
                self.analyzer(),
                fq_suffix,
            )
            .collect();
        assert_eq!(
            all.len(),
            1,
            "expected exactly one declaration ending with {fq_suffix:?}, got {all:?}"
        );
        all.remove(0)
    }

    #[doc(hidden)]
    pub fn rows(&self, file_index: usize) -> RouteRelationsFileResult {
        route_relations_for_file(
            self.analyzer(),
            &self.files[file_index],
            &CancellationToken::new(),
        )
        .expect("not cancelled")
    }

    #[doc(hidden)]
    pub fn at(&self, file_index: usize, needle: &str) -> usize {
        crate::test_support::fixture_marker(&self.sources[file_index], needle)
    }
}
#[doc(hidden)]
pub fn rows_of_kind(
    result: &RouteRelationsFileResult,
    kind: RouteHopKind,
) -> Vec<&RouteRelationRow> {
    result.rows.iter().filter(|row| row.kind == kind).collect()
}
