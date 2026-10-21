use super::*;

use crate::analyzer::AnalyzerConfig;
use crate::analyzer::Language;
use crate::analyzer::Project;
use crate::analyzer::TestProject;
use crate::analyzer::WorkspaceAnalyzer;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
#[doc(hidden)]
pub struct Fixture {
    _temp: TempDir,
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
        let temp = tempfile::tempdir().expect("temp dir");
        let root: PathBuf = temp.path().canonicalize().expect("canonical root");
        let mut subject = None;
        for (relative_path, source) in files {
            let file = ProjectFile::new(root.clone(), *relative_path);
            file.write(source).expect("write fixture source");
            subject.get_or_insert(file);
        }
        let project = TestProject::new(root, language);
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        Self {
            _temp: temp,
            workspace,
            file: subject.expect("at least one fixture file"),
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
