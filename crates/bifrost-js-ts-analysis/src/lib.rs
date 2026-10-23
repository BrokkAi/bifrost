pub mod analyzer {
    pub use brokk_bifrost_analysis::analyzer::*;
    pub mod javascript;
    pub use javascript::JavascriptAnalyzer;
    pub mod js_ts;
    pub use js_ts::{JsTsDependencyPackAdapter, resolve_js_ts_semantic_pack_dependencies};
    pub mod typescript;
    pub use typescript::TypescriptAnalyzer;
    pub mod usages {
        pub use brokk_bifrost_analysis::analyzer::usages::*;
        pub mod get_definition {
            pub use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
            pub mod js_ts;
        }
        pub mod get_type {
            pub use brokk_bifrost_analysis::analyzer::usages::get_type::*;
            pub mod js_ts;
            pub(crate) use js_ts::resolve_js_ts_type_bounded;
        }
        pub mod js_ts_graph;
    }
}

pub use analyzer::javascript::JavascriptAnalyzer;
pub use analyzer::js_ts::*;
pub use analyzer::typescript::TypescriptAnalyzer;
pub use analyzer::usages::js_ts_graph::JsTsExportUsageGraphStrategy;
#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    use std::sync::OnceLock;

    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::partial_for_tests(vec![
            &JavascriptSupport as &dyn LanguageSupport,
            &TypescriptSupport as &dyn LanguageSupport,
        ])
    })
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_typescript_project(
    source: &str,
) -> (
    tempfile::TempDir,
    brokk_bifrost_analysis::analyzer::ProjectFile,
    TypescriptAnalyzer,
) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = brokk_bifrost_analysis::analyzer::ProjectFile::new(root.clone(), "src/app.ts");
    file.write(source).expect("write source");
    let analyzer =
        TypescriptAnalyzer::from_project(brokk_bifrost_analysis::analyzer::TestProject::new(
            root,
            brokk_bifrost_analysis::analyzer::Language::TypeScript,
        ));
    (temp, file, analyzer)
}

pub use brokk_bifrost_analysis::{CancellationToken, cancellation, hash, path_utils};

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<brokk_bifrost_analysis::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}
