#[cfg(test)]
mod php_extraction_tests {
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryScope};
    use brokk_bifrost_analysis::delegate_inner_methods;
    use std::path::PathBuf;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::build_direct_import_topology;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::test_support::completed_topology;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::test_support::generous_limits;

    use brokk_bifrost_php_analysis::PhpAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;
    /// Wraps a real analyzer and reports one extra file that no delegate
    /// claims, so `import_analysis_provider_for_file` returns `None` for it
    /// through the topology's own rule rather than through a language whose
    /// analyzer happens not to implement import analysis. Every method other
    /// than `analyzed_files` and `import_analysis_provider_for_file` is
    /// unreachable from `build_direct_import_topology`'s code path: the
    /// import provider it obtains for a supported file borrows from `inner`
    /// directly and does its own work without going back through this
    /// wrapper, so those bodies are deliberately `unimplemented!()`.
    struct AnalyzerWithUnclaimedFile {
        inner: PhpAnalyzer,
        unclaimed_file: ProjectFile,
    }

    impl IAnalyzer for AnalyzerWithUnclaimedFile {
        fn update(&self, _changed_files: &std::collections::BTreeSet<ProjectFile>) -> Self
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this fixture")
        }

        fn update_all(&self) -> Self
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this fixture")
        }

        fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
            unimplemented!("not exercised by this fixture")
        }

        fn is_access_expression(
            &self,
            _file: &ProjectFile,
            _start_byte: usize,
            _end_byte: usize,
        ) -> bool {
            unimplemented!("not exercised by this fixture")
        }

        fn find_nearest_declaration(
            &self,
            _file: &ProjectFile,
            _start_byte: usize,
            _end_byte: usize,
            _ident: &str,
        ) -> Option<brokk_bifrost_core::analyzer::model::DeclarationInfo> {
            unimplemented!("not exercised by this fixture")
        }

        fn begin_query(
            &self,
            context: &std::sync::Arc<
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext,
            >,
        ) {
            self.inner.begin_query(context);
        }

        fn end_query(
            &self,
            context: &std::sync::Arc<
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext,
            >,
        ) {
            self.inner.end_query(context);
        }

        fn import_analysis_provider_for_file(
            &self,
            file: &ProjectFile,
        ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider>
        {
            if file == &self.unclaimed_file {
                None
            } else {
                self.inner.import_analysis_provider_for_file(file)
            }
        }
    }

    /// The topology marks a pending file unsupported when
    /// `import_analysis_provider_for_file` returns `None` for it (the rule at
    /// `DirectImportTopology`'s construction, ~line 1131). Every real
    /// language now has an import provider (PHP gained one in #1713), so this
    /// exercises that rule through a hand-written `IAnalyzer` fake -- wrapping
    /// a real `PhpAnalyzer` but reporting an extra Ruby file no delegate
    /// claims -- rather than depending on a language accidentally lacking
    /// import support.
    #[test]
    fn unsupported_sources_prevent_exact_reverse_reuse() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.php"));
        file.write("<?php\nfunction target() {}\n")
            .expect("write source");
        let unclaimed_file = ProjectFile::new(root.clone(), PathBuf::from("helper.rb"));
        unclaimed_file
            .write("def helper; end\n")
            .expect("write unclaimed source");
        let analyzer = AnalyzerWithUnclaimedFile {
            inner: PhpAnalyzer::from_project(TestProject::new(root, Language::Php)),
            unclaimed_file: unclaimed_file.clone(),
        };

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let topology = completed_topology(build_direct_import_topology(
            &analyzer,
            token,
            &CancellationToken::default(),
            generous_limits(),
        ));

        assert_eq!(topology.resolved_files(), 2);
        assert_eq!(topology.resolved_edges(), 0);
        assert!(!topology.reverse_relation_complete());
        assert_eq!(topology.imports_of(&file), Some(Vec::new()));
        assert_eq!(topology.importers_of(&file), None);
        assert_eq!(topology.imports_of(&unclaimed_file), None);
        assert_eq!(topology.importers_of(&unclaimed_file), None);
        assert_eq!(topology.unsupported_languages(), vec![Language::Ruby]);
    }

    impl brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex for AnalyzerWithUnclaimedFile {
        delegate_inner_methods! {
            fn project(&self) -> &dyn crate::analyzer::Project;
        }

        fn languages(&self) -> std::collections::BTreeSet<Language> {
            self.inner.languages()
        }

        fn analyzed_files(&self) -> Vec<ProjectFile> {
            let mut files = self.inner.analyzed_files();
            files.push(self.unclaimed_file.clone());
            files
        }

        fn all_declarations(
            &self,
        ) -> Box<dyn Iterator<Item = brokk_bifrost_core::analyzer::model::CodeUnit> + '_> {
            unimplemented!("not exercised by this fixture")
        }

        fn search_definitions(
            &self,
            _pattern: &str,
            _auto_quote: bool,
        ) -> std::collections::BTreeSet<brokk_bifrost_core::analyzer::model::CodeUnit> {
            unimplemented!("not exercised by this fixture")
        }

        fn enclosing_code_unit(
            &self,
            _file: &ProjectFile,
            _range: &brokk_bifrost_core::analyzer::model::Range,
        ) -> Option<brokk_bifrost_core::analyzer::model::CodeUnit> {
            unimplemented!("not exercised by this fixture")
        }

        fn enclosing_code_unit_for_lines(
            &self,
            _file: &ProjectFile,
            _start_line: usize,
            _end_line: usize,
        ) -> Option<brokk_bifrost_core::analyzer::model::CodeUnit> {
            unimplemented!("not exercised by this fixture")
        }

        fn get_skeleton(
            &self,
            _code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
        ) -> Option<String> {
            unimplemented!("not exercised by this fixture")
        }

        fn get_skeleton_header(
            &self,
            _code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
        ) -> Option<String> {
            unimplemented!("not exercised by this fixture")
        }

        fn get_source(
            &self,
            _code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
            _include_comments: bool,
        ) -> Option<String> {
            unimplemented!("not exercised by this fixture")
        }

        fn get_sources(
            &self,
            _code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
            _include_comments: bool,
        ) -> std::collections::BTreeSet<String> {
            unimplemented!("not exercised by this fixture")
        }
    }
}
