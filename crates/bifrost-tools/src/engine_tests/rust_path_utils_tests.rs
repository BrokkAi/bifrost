#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::IAnalyzer;

    use std::path::Path;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::path_utils::ResolvedFileInput;

    use brokk_bifrost_analysis::path_utils::WorkspaceFileResolver;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_rust_analysis::RustAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;
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
    #[brokk_bifrost_test_macros::hardwon(
        "#2325: Injected listing failure crosses resolver and analyzer request boundary, preventing a false confident absence"
    )]
    fn a_failed_workspace_listing_reports_the_failure_rather_than_a_confident_absence() {
        let (_temp, analyzer) = unlistable_workspace();
        let context = std::sync::Arc::new(AnalyzerQueryContext::default());
        let context_attribution = context.enter();
        analyzer.begin_query(&context);

        let resolved = WorkspaceFileResolver::for_analyzer(&analyzer).resolve_literal("widget.rs");

        let error = context
            .store_error()
            .expect("a failed workspace listing must reach the request boundary");
        analyzer.end_query(&context);
        drop(context_attribution);
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
    #[brokk_bifrost_test_macros::hardwon(
        "#2325: Exercises the healthy resolver path alongside the failure contract and distinguishes a real miss from a failed listing"
    )]
    fn a_healthy_workspace_miss_records_no_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root: PathBuf = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/widget.rs")
            .write("pub struct Widget;\n")
            .expect("fixture file");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let context = std::sync::Arc::new(AnalyzerQueryContext::default());
        let context_attribution = context.enter();
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
        drop(context_attribution);
    }
}
