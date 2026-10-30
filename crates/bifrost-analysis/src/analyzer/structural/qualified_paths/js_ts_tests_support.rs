use super::*;

use crate::analyzer::Language;
use crate::analyzer::WorkspaceAnalyzer;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
#[doc(hidden)]
pub struct Fixture {
    _project: BuiltInlineTestProject,
    workspace: WorkspaceAnalyzer,
    file: ProjectFile,
    source: String,
}
impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, relative_path: &str, source: &str) -> Self {
        Self::with_files(language, &[(relative_path, source)])
    }

    /// The first file is the one rows are derived for.
    #[doc(hidden)]
    pub fn with_files(language: Language, files: &[(&str, &str)]) -> Self {
        assert!(!files.is_empty(), "at least one fixture file");
        let mut builder = InlineTestProject::with_language(language);
        for (relative_path, source) in files {
            builder = builder.file(*relative_path, *source);
        }
        let project = builder.build();
        let file = project.file(files[0].0);
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        Self {
            _project: project,
            workspace,
            file,
            source: files[0].1.to_owned(),
        }
    }

    #[doc(hidden)]
    pub fn rows(&self, options: QualifiedPathDerivationOptions) -> QualifiedPathsFileResult {
        qualified_paths_for_file(
            self.workspace.analyzer(),
            &self.file,
            options,
            &CancellationToken::new(),
        )
        .expect("derivation not cancelled")
    }

    #[doc(hidden)]
    pub fn at(&self, needle: &str) -> usize {
        crate::test_support::fixture_marker(&self.source, needle)
    }
}
/// The segments of the one path whose first segment starts at `start`,
/// ordinal-ordered, with the ordering asserted.
#[doc(hidden)]
pub fn path_segments_at(result: &QualifiedPathsFileResult, start: usize) -> Vec<&PathSegmentRow> {
    let path = result
        .paths
        .iter()
        .find(|path| path.range.start_byte == start)
        .unwrap_or_else(|| {
            panic!(
                "no path starting at byte {start}; paths: {:?}",
                result.paths
            )
        });
    let segments: Vec<_> = result.segments_of(path.terminal_node).collect();
    assert_eq!(segments.len(), path.segment_count as usize);
    for (position, segment) in segments.iter().enumerate() {
        assert_eq!(segment.ordinal as usize, position);
        assert_eq!(segment.path_terminal_node, path.terminal_node);
    }
    segments
}
