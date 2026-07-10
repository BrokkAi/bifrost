pub(crate) mod cache;
pub(crate) mod clones;
pub(crate) mod diagnostics;
pub(crate) mod hierarchy;
pub(crate) mod identifiers;
pub(crate) mod imports;
pub(crate) mod model;
pub(crate) mod structural;
pub(crate) mod syntax;
pub(crate) mod tests;
pub(crate) mod tsconfig;

pub(crate) use cache::{
    build_weighted_cache, weight_code_unit_set_by_unit, weight_code_unit_vec_by_unit,
};
pub(crate) use imports::resolve_js_ts_module_specifier;
pub(crate) use tsconfig::AliasResolver;

use crate::analyzer::ProjectFile;

pub(crate) fn source_contains_tests(source: &str) -> bool {
    source.contains("describe(") || source.contains("test(") || source.contains("it(")
}

pub(crate) fn path_contains_tests(file: &ProjectFile) -> bool {
    let rel = file.rel_path().to_string_lossy().to_ascii_lowercase();
    rel.contains(".test.") || rel.contains(".spec.")
}

pub(crate) fn contains_tests(file: &ProjectFile, source: &str) -> bool {
    path_contains_tests(file) || source_contains_tests(source)
}
