#[cfg(test)]
pub(crate) mod fixture {

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;
    #[doc(hidden)]
    pub struct SourceStorageFixtureAdapter(
        pub(crate)  Option<
            &'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage,
        >,
    );
    impl LanguageAdapter for SourceStorageFixtureAdapter {
        fn query_directory(&self) -> &'static str {
            JavaAdapter.query_directory()
        }

        fn file_extension(&self) -> &'static str {
            JavaAdapter.file_extension()
        }

        fn extract_call_receiver(&self, reference: &str) -> Option<String> {
            JavaAdapter.extract_call_receiver(reference)
        }

        fn parse_file(
            &self,
            file: &brokk_bifrost_core::analyzer::model::ProjectFile,
            source: &str,
            tree: &tree_sitter::Tree,
        ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
            JavaAdapter.parse_file(file, source, tree)
        }
    }
    impl StoreLanguageAdapter for SourceStorageFixtureAdapter {
        fn language(&self) -> Language {
            Language::Java
        }
        fn produces_canonical_source_facts(&self) -> bool {
            true
        }
        fn source_fact_storage(
            &self,
        ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
        {
            self.0
        }
    }
}
