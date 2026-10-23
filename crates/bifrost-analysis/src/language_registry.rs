//! Test link symbols for language-table consumers in the engine crate.

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1() -> &'static crate::analyzer::languages::LanguageTable {
    use crate::analyzer::languages::LanguageTable;
    static TABLE: std::sync::OnceLock<LanguageTable> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| LanguageTable::partial_for_tests(Vec::new()))
}

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static crate::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<crate::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}
