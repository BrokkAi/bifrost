use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, WorkspaceAnalyzer};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

#[doc(hidden)]
pub fn content_identity(seed: u64) -> WorkspaceContentIdentity {
    WorkspaceContentIdentity::for_test(seed)
}

pub(crate) fn declarations_ending_with<'a>(
    analyzer: &'a dyn IAnalyzer,
    suffix: &'a str,
) -> impl Iterator<Item = CodeUnit> + 'a {
    analyzer
        .all_declarations()
        .filter(move |unit| unit.fq_name().ends_with(suffix))
}

pub(crate) fn workspace_fixture(
    language: Language,
    sources: &[(&str, &str)],
) -> (
    BuiltInlineTestProject,
    WorkspaceAnalyzer,
    Vec<ProjectFile>,
    Vec<String>,
) {
    let mut project_builder = InlineTestProject::with_language(language);
    let mut source_texts = Vec::with_capacity(sources.len());
    for (relative_path, source) in sources {
        project_builder = project_builder.file(*relative_path, *source);
        source_texts.push((*source).to_owned());
    }
    let project = project_builder.build();
    let files = sources
        .iter()
        .map(|(relative_path, _)| project.file(relative_path))
        .collect();
    let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
    (project, workspace, files, source_texts)
}
