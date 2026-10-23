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
