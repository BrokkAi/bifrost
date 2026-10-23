use super::super::resolution::BoundaryStatus;
use super::*;

use crate::analyzer::AnalyzerConfig;
use crate::analyzer::Language;
use crate::analyzer::Project;
use crate::analyzer::TestProject;
use crate::analyzer::WorkspaceAnalyzer;

use std::path::PathBuf;
use tempfile::TempDir;
#[doc(hidden)]
pub struct Fixture {
    _temp: TempDir,
    #[doc(hidden)]
    pub workspace: WorkspaceAnalyzer,
    #[doc(hidden)]
    pub file: ProjectFile,
    source: String,
}
impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, relative_path: &str, source: &str) -> Self {
        Self::with_supporting_files(language, relative_path, source, &[])
    }

    /// A fixture whose occurrences are read from `relative_path` while the
    /// analyzer also indexes `supporting`, so cross-file resolution has
    /// something to resolve to.
    #[doc(hidden)]
    pub fn with_supporting_files(
        language: Language,
        relative_path: &str,
        source: &str,
        supporting: &[(&str, &str)],
    ) -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let root: PathBuf = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), relative_path);
        file.write(source).expect("write fixture source");
        for (path, contents) in supporting {
            ProjectFile::new(root.clone(), *path)
                .write(contents)
                .expect("write supporting source");
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
            file,
            source: source.to_owned(),
        }
    }

    #[doc(hidden)]
    pub fn result(&self) -> OccurrenceFileResult {
        occurrences_for_file(
            self.workspace.analyzer(),
            &self.file,
            &CancellationToken::new(),
        )
        .expect("uncancelled occurrence derivation")
    }

    #[doc(hidden)]
    pub fn identity_only_result(&self) -> OccurrenceFileResult {
        occurrences_for_file_with_options(
            self.workspace.analyzer(),
            &self.file,
            OccurrenceDerivationOptions::IDENTITY_ONLY,
            &CancellationToken::new(),
        )
        .expect("uncancelled occurrence derivation")
    }

    #[doc(hidden)]
    pub fn identity_only_roles(&self, roles: &[OccurrenceRole]) -> OccurrenceFileResult {
        occurrences_for_file_with_options_and_roles(
            self.workspace.analyzer(),
            &self.file,
            OccurrenceDerivationOptions::IDENTITY_ONLY,
            Some(roles),
            &CancellationToken::new(),
        )
        .expect("uncancelled role-scoped occurrence derivation")
    }

    #[doc(hidden)]
    pub fn traced_result(&self) -> OccurrenceFileResult {
        occurrences_for_file_with_options(
            self.workspace.analyzer(),
            &self.file,
            OccurrenceDerivationOptions::WITH_CANDIDATES,
            &CancellationToken::new(),
        )
        .expect("uncancelled occurrence derivation")
    }

    /// Byte offset of `needle`, whose first token is the occurrence under
    /// test; the marker keeps the assertion readable without re-scanning.
    #[doc(hidden)]
    pub fn at(&self, needle: &str) -> usize {
        crate::test_support::fixture_marker(&self.source, needle)
    }
}
#[doc(hidden)]
pub fn row_at(rows: &[OccurrenceRow], start_byte: usize) -> Option<&OccurrenceRow> {
    rows.iter().find(|row| row.range.start_byte == start_byte)
}
#[doc(hidden)]
pub fn expect_row<'rows>(
    rows: &'rows [OccurrenceRow],
    start_byte: usize,
    label: &str,
) -> &'rows OccurrenceRow {
    row_at(rows, start_byte).unwrap_or_else(|| {
        panic!(
            "no occurrence row for {label} at byte {start_byte}; rows: {:?}",
            rows.iter()
                .map(|row| (row.range.start_byte, row.raw_spelling.as_str(), row.role))
                .collect::<Vec<_>>()
        )
    })
}
#[doc(hidden)]
pub fn trace_of<'rows>(
    rows: &'rows [OccurrenceRow],
    start_byte: usize,
    label: &str,
) -> &'rows ResolutionTraceResult {
    expect_row(rows, start_byte, label)
        .candidates
        .as_ref()
        .unwrap_or_else(|| panic!("no trace attached to {label}"))
}
#[doc(hidden)]
pub fn discovery_declaring_with_stub_artifacts(
    language: &str,
    modules: &[&str],
) -> crate::analyzer::semantic_model::DependencyDiscoveryOutcome {
    use crate::analyzer::semantic_model::{
        DependencyArtifactRole, ExternalArtifactKind, ResolvedDependencyArtifact,
    };

    crate::test_support::discovery_declaring(language, modules, |module| {
        vec![ResolvedDependencyArtifact::module_file(
            DependencyArtifactRole::Declarations,
            ExternalArtifactKind::PythonStub,
            module.to_owned(),
            PathBuf::from("unused-in-this-test.pyi"),
        )]
    })
}
#[doc(hidden)]
pub fn external_boundaries(trace: &ResolutionTraceResult) -> Vec<BoundaryStatus> {
    let external: Vec<BoundaryStatus> = crate::test_support::external_route_candidates(trace)
        .into_iter()
        .map(|row| row.boundary)
        .collect();
    assert!(
        !external.is_empty(),
        "a boundary outcome always reports the route it took: {:?}",
        trace.candidates
    );
    external
}
