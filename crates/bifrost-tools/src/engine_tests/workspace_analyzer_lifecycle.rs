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
        // A hand-written project names its effective ignore rules; this one
        // has none of its own, so it states the delegate's.
        fn ignore_rules_digest(&self) -> std::io::Result<[u8; 32]> {
            self.0.ignore_rules_digest()
        }

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

    /// The usage-ranking graph cache and every other product keyed by the
    /// workspace content identity must not survive an omission that makes the
    /// source inventory incomplete (#12280). A file at an unrelated path leaves
    /// the identity alone, because no Java source could live there.
    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12280: a directory symlink added an omission without changing the non-C# content identity, so a warm Complete graph outlived it"
    )]
    fn an_omission_that_hides_source_rotates_the_content_identity_warm_and_cold() {
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let temp = tempfile::tempdir().unwrap();
        let root = {
            std::fs::create_dir(temp.path().join("workspace")).unwrap();
            temp.path().join("workspace").canonicalize().unwrap()
        };
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("Caller.java"), "class Caller {}\n").unwrap();
        std::fs::write(root.join("A.java"), "class A {}\n").unwrap();
        std::fs::write(root.join("notes.txt"), "notes\n").unwrap();
        // A second language in the workspace: the inventory is whole-workspace.
        std::fs::write(root.join("real.rs"), "pub fn real() {}\n").unwrap();

        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            Arc::new(FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap());
        let mut analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        let identity = |analyzer: &WorkspaceAnalyzer| {
            (
                analyzer.analyzer().workspace_content_identity(),
                analyzer.analyzer().source_file_inventory().complete,
            )
        };
        let cold = || {
            let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
            let project = Arc::new(FilesystemProject::with_cached_listing(&root, cache).unwrap());
            identity(
                &WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                    .unwrap(),
            )
        };
        let link = |analyzer: WorkspaceAnalyzer, name: &str, target: &std::path::Path| {
            std::os::unix::fs::symlink(target, root.join(name)).unwrap();
            if !project.update_cached_listing_for_path(std::path::Path::new(name)) {
                project.invalidate_cached_file_listing();
            }
            analyzer.update(&BTreeSet::from([ProjectFile::new(root.clone(), name)]))
        };

        let complete = identity(&analyzer);
        assert!(complete.0.is_some() && complete.1);
        assert_eq!(complete, cold());

        // A file symlink at a path no Java source can have changes nothing.
        analyzer = link(analyzer, "linked-notes.txt", &root.join("notes.txt"));
        assert_eq!(identity(&analyzer), complete);
        assert_eq!(identity(&analyzer), cold());

        // A directory symlink hides the Java file below it.
        analyzer = link(analyzer, "callers", &outside);
        let hidden = identity(&analyzer);
        assert!(!hidden.1, "the inventory must be incomplete");
        assert_ne!(hidden.0, complete.0, "warm identity must rotate");
        assert_eq!(hidden, cold(), "warm and cold identities agree");

        // Removing it returns to the identity that never folded an omission.
        let unlink = |analyzer: WorkspaceAnalyzer, name: &str| {
            std::fs::remove_file(root.join(name)).unwrap();
            if !project.update_cached_listing_for_path(std::path::Path::new(name)) {
                project.invalidate_cached_file_listing();
            }
            analyzer.update(&BTreeSet::from([ProjectFile::new(root.clone(), name)]))
        };
        analyzer = unlink(analyzer, "callers");
        assert_eq!(identity(&analyzer), complete);
        assert_eq!(identity(&analyzer), cold());

        // The inventory is whole-workspace while a graph is keyed per ecosystem,
        // so a Rust source hidden behind a link rotates the Java identity too.
        analyzer = link(analyzer, "lib.rs", &root.join("A.java"));
        let rust_hidden = identity(&analyzer);
        assert_ne!(rust_hidden.0, complete.0);
        assert_eq!(rust_hidden, cold());
        analyzer = unlink(analyzer, "lib.rs");
        assert_eq!(identity(&analyzer), complete);

        // A file symlink at a Java path is an omission a Java listing cannot see.
        analyzer = link(analyzer, "Alias.java", &root.join("A.java"));
        let aliased = identity(&analyzer);
        assert!(!aliased.1);
        assert_ne!(aliased.0, complete.0);
        assert_eq!(aliased, cold());
    }

    /// The delegate's update must run when the omission that withdrew its
    /// listing proof disappears, even though no file it owns changed.
    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13641: a hiding omission that disappeared left the workspace listing proof withdrawn"
    )]
    fn a_disappearing_omission_restores_the_workspace_listing_proof() {
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let temp = tempfile::tempdir().unwrap();
        let root = {
            std::fs::create_dir(temp.path().join("workspace")).unwrap();
            temp.path().join("workspace").canonicalize().unwrap()
        };
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("A.java"), "class A {}\n").unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            Arc::new(FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap());
        let build = |project: Arc<FilesystemProject>| {
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap()
        };
        let holds_proof = |analyzer: &WorkspaceAnalyzer| {
            analyzer
                .analyzer()
                .workspace_fact_indexes()
                .iter()
                .any(|index| index.holds_workspace_listing_proof())
        };
        let relist = |name: &str| {
            if !project.update_cached_listing_for_path(std::path::Path::new(name)) {
                project.invalidate_cached_file_listing();
            }
        };
        let cold = || {
            let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
            holds_proof(&build(Arc::new(
                FilesystemProject::with_cached_listing(&root, cache).unwrap(),
            )))
        };

        let analyzer = build(project.clone());
        assert!(holds_proof(&analyzer));
        std::os::unix::fs::symlink(&outside, root.join("callers")).unwrap();
        relist("callers");
        let hidden = analyzer.update(&BTreeSet::from([ProjectFile::new(root.clone(), "callers")]));
        assert!(
            !holds_proof(&hidden),
            "the hiding omission withdraws the proof"
        );
        assert_eq!(holds_proof(&hidden), cold());

        std::fs::remove_file(root.join("callers")).unwrap();
        relist("callers");
        let cleared = hidden.update(&BTreeSet::new());
        assert!(cold());
        assert_eq!(
            holds_proof(&cleared),
            cold(),
            "the cleared update matches cold"
        );
    }

    /// C++ adopts a file no language owns when an include names it, so an omitted
    /// extensionless header may be C++ source. A file no language and no include
    /// could adopt, in a workspace without C++, is not.
    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12280: an omitted extensionless C++ header left the C++ inventory complete"
    )]
    fn an_omitted_extensionless_cpp_header_makes_the_inventory_incomplete() {
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        let complete_with = |files: &[(&str, &str)], link: &str| {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            for (name, source) in files {
                std::fs::write(root.join(name), source).unwrap();
            }
            std::os::unix::fs::symlink(root.join(files[0].0), root.join(link)).unwrap();
            let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
            let project = Arc::new(FilesystemProject::with_cached_listing(&root, cache).unwrap());
            let analyzer =
                WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                    .unwrap();
            let complete = analyzer.analyzer().source_file_inventory().complete;
            drop(temp);
            complete
        };
        assert!(
            !complete_with(&[("main.cpp", "int main() { return 0; }\n")], "vector"),
            "an omitted extensionless file may be an included C++ header"
        );
        assert!(
            complete_with(&[("A.java", "class A {}\n")], "README"),
            "without C++ an extensionless link is not a Java or C++ source"
        );
    }

    /// The source inventory spans every language, so an omitted source of a
    /// language the workspace does not hold is still a source the listing hid: a
    /// `.js` link in a TypeScript workspace, a `.ts` link in a JavaScript one. The
    /// JS/TS index is incomplete only for those; a `.py` link is not one of its
    /// sources, though the whole-workspace inventory and its content identity
    /// still account for it.
    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12280: an omitted caller.js in a TypeScript-only workspace left the inventory complete, because only the listed languages were considered"
    )]
    fn an_omitted_source_of_an_absent_language_makes_the_inventory_incomplete() {
        use brokk_bifrost_core::analyzer::project::{FilesystemProject, WorkspaceFileListingCache};
        use brokk_bifrost_js_ts::providers::JsTsSource;
        // (whole-workspace inventory complete, JS/TS inventory complete, identity)
        let observe = |source: &str, link: Option<&str>| {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            std::fs::write(root.join(source), "export const value = 1;\n").unwrap();
            if let Some(link) = link {
                std::os::unix::fs::symlink(root.join(source), root.join(link)).unwrap();
            }
            let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
            let project = Arc::new(FilesystemProject::with_cached_listing(&root, cache).unwrap());
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.clone(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let jsts = brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAnalyzer::from_project(
                FilesystemProject::new(&root).unwrap(),
            );
            (
                workspace.analyzer().source_file_inventory().complete,
                JsTsSource::source_file_inventory(&jsts).complete,
                workspace.analyzer().workspace_content_identity(),
            )
        };
        let (clean_ts, clean_ts_jsts, clean_ts_identity) = observe("a.ts", None);
        assert!(clean_ts && clean_ts_jsts);
        // TypeScript-only workspace, omitted caller.js.
        let (whole, jsts, identity) = observe("a.ts", Some("caller.js"));
        assert!(!whole && !jsts, "an omitted .js is a JavaScript source");
        assert_ne!(identity, clean_ts_identity, "the fold rotates the identity");
        // The mirror: JavaScript-only workspace, omitted .ts.
        let (clean_js, clean_js_jsts, clean_js_identity) = observe("a.js", None);
        assert!(clean_js && clean_js_jsts);
        let (whole, jsts, identity) = observe("a.js", Some("b.ts"));
        assert!(!whole && !jsts, "an omitted .ts is a TypeScript source");
        assert_ne!(identity, clean_js_identity);
        // Control: a .py link is not a JS/TS source. The JS/TS index stays
        // complete (no cross-language false incompleteness, as #10670 rules out for
        // Rust); the whole-workspace inventory and identity still account for it.
        let (whole, jsts, identity) = observe("a.ts", Some("tool.py"));
        assert!(jsts, "an omitted .py is not a JS/TS source");
        assert!(!whole, "it is a source of a language the inventory spans");
        assert_ne!(identity, clean_ts_identity);
    }
}
