//! Link-time assembly of the complete language implementation table.

use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
use brokk_bifrost_cpp_analysis::CppSupport;
use brokk_bifrost_csharp_analysis::CSharpSupport;
use brokk_bifrost_go_analysis::GoSupport;
use brokk_bifrost_js_ts_analysis::{JavascriptSupport, TypescriptSupport};
use brokk_bifrost_jvm_analysis::{JavaSupport, KotlinSupport, ScalaSupport};
use brokk_bifrost_php_analysis::PhpSupport;
use brokk_bifrost_python_analysis::PythonSupport;
use brokk_bifrost_ruby_analysis::RubySupport;
use brokk_bifrost_rust_analysis::RustSupport;
use std::sync::OnceLock;

#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1() -> &'static LanguageTable {
    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::complete(vec![
            &JavaSupport as &dyn LanguageSupport,
            &KotlinSupport,
            &ScalaSupport,
            &CSharpSupport as &dyn LanguageSupport,
            &GoSupport as &dyn LanguageSupport,
            &RustSupport as &dyn LanguageSupport,
            &PhpSupport as &dyn LanguageSupport,
            &CppSupport as &dyn LanguageSupport,
            &PythonSupport as &dyn LanguageSupport,
            &RubySupport as &dyn LanguageSupport,
            &JavascriptSupport as &dyn LanguageSupport,
            &TypescriptSupport as &dyn LanguageSupport,
        ])
    })
}

#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<brokk_bifrost_analysis::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_owners_compose_models_from_catalog_rows() {
        use brokk_bifrost_analysis::analyzer::languages::registered_language_supports;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            CatalogOptions, SemanticPackCatalog,
        };
        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_store;
        use brokk_bifrost_core::analyzer::project::{Project, TestProject};
        use std::sync::Arc;

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for support in registered_language_supports() {
            let language = support.knowledge().language();
            let root = tempfile::tempdir().unwrap();
            let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), language));
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let context = store_context_from_store(project.as_ref(), store, false);
            let delegate = support
                .build_analyzer(project, Default::default(), context, None)
                .unwrap();
            if delegate
                .analyzer()
                .request_row_reader_source(&catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ))
                .is_some_and(|source| !source.reads_through_activation())
            {
                assert!(
                    support.knowledge().models_compose_from_catalog_rows(),
                    "{language:?} supplies a request owner without catalog row composition"
                );
            }
        }
    }
}
