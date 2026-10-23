#[cfg(test)]
pub(crate) mod jvm_adapter_helper {

    use brokk_bifrost_analysis::analyzer::cognitive_complexity;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;

    use brokk_bifrost_core::analyzer::fq_name::FqName;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use tree_sitter::Tree;
    /// Java behavior with the pre-canonical source-publication contract.
    ///
    /// Hand-built resolution fixtures can contain synthetic native identities that
    /// do not correspond to the source declarations from their small parse. They
    /// must therefore remain explicitly legacy fixtures rather than inventing
    /// source declaration bridges merely to satisfy the current Java adapter.
    #[derive(Debug, Clone, Copy, Default)]
    #[doc(hidden)]
    pub struct LegacyJavaFixtureAdapter;
    impl LanguageAdapter for LegacyJavaFixtureAdapter {
        fn query_directory(&self) -> &'static str {
            JavaAdapter.query_directory()
        }

        fn file_extension(&self) -> &'static str {
            JavaAdapter.file_extension()
        }

        fn is_anonymous_structure(&self, fq_name: &str) -> bool {
            JavaAdapter.is_anonymous_structure(fq_name)
        }

        fn extract_call_receiver(&self, reference: &str) -> Option<String> {
            JavaAdapter.extract_call_receiver(reference)
        }

        fn contains_tests(
            &self,
            file: &ProjectFile,
            source: &str,
            tree: &Tree,
            parsed: &ParsedFile,
        ) -> bool {
            JavaAdapter.contains_tests(file, source, tree, parsed)
        }

        fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
            JavaAdapter.parse_file(file, source, tree)
        }

        fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
            JavaAdapter.cognitive_complexity_config()
        }
    }
    impl StoreLanguageAdapter for LegacyJavaFixtureAdapter {
        fn source_fact_storage(
            &self,
        ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
        {
            JavaAdapter.source_fact_storage()
        }
        fn language(&self) -> Language {
            JavaAdapter.language()
        }
        fn normalize_full_name(&self, fq_name: &str) -> String {
            JavaAdapter.normalize_full_name(fq_name)
        }
        fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
            JavaAdapter.normalize_fq_name(fq_name)
        }
        fn produces_canonical_source_facts(&self) -> bool {
            false
        }
        fn declaration_visibility_facts_version(&self) -> Option<i64> {
            None
        }
    }
}
