//! Assembly of language implementations that still reside in the engine.

use crate::analyzer::Language;

use crate::analyzer::languages::LanguageSupport;

static LANGUAGE_SUPPORTS: [&'static dyn LanguageSupport; Language::ANALYZABLE.len() - 9] = [
    &crate::analyzer::java::JavaSupport,
    &crate::analyzer::scala::ScalaSupport,
    &crate::analyzer::kotlin::KotlinSupport,
];

/// The supports whose implementations still reside in the engine.
#[doc(hidden)]
pub fn engine_resident_language_supports() -> &'static [&'static dyn LanguageSupport] {
    &LANGUAGE_SUPPORTS
}

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1() -> &'static crate::analyzer::languages::LanguageTable {
    use crate::analyzer::languages::LanguageTable;
    static TABLE: std::sync::OnceLock<LanguageTable> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::partial_for_tests(engine_resident_language_supports().to_vec())
    })
}
