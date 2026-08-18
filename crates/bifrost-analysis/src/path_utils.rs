//! Resolving caller-supplied path literals against a workspace listing.
//!
//! The pure normalization half lives in
//! [`brokk_bifrost_core::path_utils`]; only the resolver, which reads a
//! workspace listing off an [`IAnalyzer`], stays here.

pub(crate) use brokk_bifrost_core::path_utils::{
    has_drive_letter_prefix, normalize_pattern, workspace_rel_path,
};
pub use brokk_bifrost_core::path_utils::{percent_decode, rel_path_string};

use crate::analyzer::store::StoreError;
use crate::analyzer::{
    IAnalyzer, Project, ProjectFile, WorkspaceFileIndex, WorkspaceFileIndexCell,
};
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AmbiguousPathInput {
    pub input: String,
    pub matches: Vec<String>,
}

pub enum ResolvedFileInput {
    File(ProjectFile),
    Ambiguous(AmbiguousPathInput),
    NotFound(String),
}

pub struct WorkspaceFileResolver<'a> {
    /// The analyzer this resolver answers for. Held, rather than only its
    /// project, because a failed workspace listing has to reach that analyzer's
    /// active request boundary: a resolver built from a bare `Project` would
    /// have nowhere to report the failure and would silently answer "no such
    /// file" instead (#2325).
    analyzer: &'a dyn IAnalyzer,
    project: &'a dyn Project,
    /// The active request's shared listing cell, when a query scope was open.
    /// Resolvers are built per call site and per symbol, so without this each
    /// one paid its own whole-workspace walk (#1334).
    shared_index: Option<WorkspaceFileIndexCell>,
    /// This resolver's own listing: used when no request scope is available,
    /// and as the fallback if the shared cell turns out to describe a different
    /// workspace than this resolver's project.
    private_index: OnceLock<Arc<WorkspaceFileIndex>>,
}

impl<'a> WorkspaceFileResolver<'a> {
    /// A resolver that shares the active request's workspace listing, so one
    /// request walks the tree at most once however many resolvers it builds.
    /// With no query scope open it walks the tree once for itself.
    pub fn for_analyzer(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            project: analyzer.project(),
            shared_index: analyzer.workspace_file_index_cell(),
            private_index: OnceLock::new(),
        }
    }

    pub fn resolve_literal(&self, input: &str) -> ResolvedFileInput {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        }

        let Some(rel) = workspace_rel_path(trimmed) else {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        };

        if let Some(file) = self.project.file_by_rel_path(&rel) {
            return ResolvedFileInput::File(file);
        }

        if !is_bare_literal_candidate(trimmed, &rel) {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        }

        let basename = rel
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(trimmed)
            .to_string();
        let Some(matches) = self.basename_matches(&basename) else {
            return ResolvedFileInput::NotFound(trimmed.to_string());
        };

        match matches {
            [] => ResolvedFileInput::NotFound(trimmed.to_string()),
            [file] => ResolvedFileInput::File(file.clone()),
            _ => ResolvedFileInput::Ambiguous(AmbiguousPathInput {
                input: trimmed.to_string(),
                matches: matches.iter().map(rel_path_string).collect(),
            }),
        }
    }

    fn basename_matches(&self, basename: &str) -> Option<&[ProjectFile]> {
        match self.index().matches(basename) {
            Ok(matches) => matches,
            // A workspace whose listing failed cannot say whether it holds a
            // file with this basename, and `None` here becomes `NotFound` --
            // the assertion that it definitely does not (#2325). Record the
            // failure on the request boundary that inspects it before
            // presenting a successful response, so the call reports the listing
            // failure instead of an invented absence.
            Err(error) => {
                self.analyzer
                    .record_query_failure(StoreError::new(error.to_string()));
                None
            }
        }
    }

    fn index(&self) -> &WorkspaceFileIndex {
        // `get_or_init` runs on this resolver's own `Arc` handle, which is how
        // the request-shared cell guarantees the walk happens once even when
        // many `rayon` workers miss it at the same instant.
        if let Some(shared) = &self.shared_index {
            let index = shared.get_or_init(|| Arc::new(WorkspaceFileIndex::build(self.project)));
            if index.covers(self.project.root()) {
                return index;
            }
        }
        self.private_index
            .get_or_init(|| Arc::new(WorkspaceFileIndex::build(self.project)))
    }
}

fn is_bare_literal_candidate(input: &str, rel: &Path) -> bool {
    if input.contains('/') || input.contains('\\') || input.contains('*') || input.contains('?') {
        return false;
    }
    rel.components().count() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerQueryContext, Language, RustAnalyzer, TestProject};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// A workspace whose ignore-aware listing fails and whose every other
    /// answer is intact -- the state a permission error or a racing tree
    /// removal puts a real project in.
    struct UnlistableProject {
        delegate: TestProject,
    }

    impl Project for UnlistableProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected workspace listing failure",
            ))
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }
    }

    fn unlistable_workspace() -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root: PathBuf = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/widget.rs")
            .write("pub struct Widget;\n")
            .expect("fixture file");
        let analyzer = RustAnalyzer::from_project(UnlistableProject {
            delegate: TestProject::new(root, Language::Rust),
        });
        (temp, analyzer)
    }

    /// Before #2325 a failed listing produced an empty basename index, so every
    /// bare path anchor resolved to `NotFound` and the tool reported a
    /// confident absence. The listing failure must reach the request boundary
    /// instead.
    #[test]
    fn a_failed_workspace_listing_reports_the_failure_rather_than_a_confident_absence() {
        let (_temp, analyzer) = unlistable_workspace();
        let context = std::sync::Arc::new(AnalyzerQueryContext::default());
        analyzer.begin_query(&context);

        let resolved = WorkspaceFileResolver::for_analyzer(&analyzer).resolve_literal("widget.rs");

        let error = context
            .store_error()
            .expect("a failed workspace listing must reach the request boundary");
        analyzer.end_query(&context);
        assert!(
            matches!(resolved, ResolvedFileInput::NotFound(_)),
            "the bare name still has no answer"
        );
        assert!(
            error
                .to_string()
                .contains("injected workspace listing failure"),
            "the recorded failure must carry the listing error: {error}"
        );
    }

    /// The same resolver on a healthy workspace records nothing: the failure
    /// channel must not fire on a genuine miss.
    #[test]
    fn a_healthy_workspace_miss_records_no_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root: PathBuf = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/widget.rs")
            .write("pub struct Widget;\n")
            .expect("fixture file");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let context = std::sync::Arc::new(AnalyzerQueryContext::default());
        analyzer.begin_query(&context);

        let resolver = WorkspaceFileResolver::for_analyzer(&analyzer);
        assert!(matches!(
            resolver.resolve_literal("widget.rs"),
            ResolvedFileInput::File(_)
        ));
        assert!(matches!(
            resolver.resolve_literal("absent.rs"),
            ResolvedFileInput::NotFound(_)
        ));

        assert!(context.store_error().is_none());
        analyzer.end_query(&context);
    }
}
