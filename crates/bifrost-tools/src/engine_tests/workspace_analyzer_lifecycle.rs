#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    struct LiveProject(TestProject);

    impl Project for LiveProject {
        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.analyzable_files_from(&self.all_files()?, language)
        }

        fn file_by_rel_path(&self, path: &std::path::Path) -> Option<ProjectFile> {
            self.0.file_by_rel_path(path)
        }

        fn root(&self) -> &std::path::Path {
            self.0.root()
        }
        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.0.all_files()
        }
        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.all_files()
                .unwrap()
                .iter()
                .map(ProjectFile::language)
                .collect()
        }
    }

    fn project(root: &std::path::Path) -> Arc<dyn Project> {
        Arc::new(LiveProject(TestProject::with_languages(
            root,
            BTreeSet::from([Language::Java, Language::Rust]),
        )))
    }

    #[test]
    fn update_from_empty_adds_two_languages_like_fresh_build() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        // The same live project view must supply both snapshots. A fixed empty
        // FileSetProject deliberately excludes every subsequently created file.
        let empty =
            WorkspaceAnalyzer::build_ephemeral_footgun(project(&root), AnalyzerConfig::default())
                .unwrap();
        assert!(matches!(empty, WorkspaceAnalyzer::Empty(_)));
        let java = ProjectFile::new(root.clone(), "src/A.java");
        let rust = ProjectFile::new(root.clone(), "src/lib.rs");
        java.write("package app; public class A {}\n").unwrap();
        rust.write("pub struct Added;\n").unwrap();
        let updated = empty.update(&BTreeSet::from([java, rust]));
        let fresh =
            WorkspaceAnalyzer::build_ephemeral_footgun(project(&root), AnalyzerConfig::default())
                .unwrap();
        let languages = |analyzer: &WorkspaceAnalyzer| {
            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
            >(analyzer.analyzer())
            .expect("the fresh multi-language workspace has delegates")
            .delegates()
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
        };
        assert_eq!(languages(&updated), languages(&fresh));
        assert_eq!(
            BTreeSet::from([Language::Java, Language::Rust]),
            languages(&updated)
        );
    }
}
