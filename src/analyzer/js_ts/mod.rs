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

use crate::analyzer::js_ts::model::module_code_unit;
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::{CodeUnit, ProjectFile, Range};
use crate::text_utils::compute_line_starts;

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

pub(crate) fn should_persist_code_unit(code_unit: &CodeUnit) -> bool {
    !code_unit.is_file_scope() && !code_unit.is_module()
}

pub(crate) fn storage_contains_tests(state: &FileState) -> bool {
    source_contains_tests(&state.source)
}

pub(crate) fn hydrate_contains_tests(stored: bool, file: &ProjectFile, source: &str) -> bool {
    stored || path_contains_tests(file) || source_contains_tests(source)
}

pub(crate) fn synthesize_hydrated_module(file: &ProjectFile, source: &str, state: &mut FileState) {
    if state.imports.is_empty() {
        return;
    }
    let module = module_code_unit(file);
    state.top_level_declarations.push(module.clone());
    state.declarations.insert(module.clone());
    state.ranges.entry(module).or_default().push(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 1,
        end_line: compute_line_starts(source).len(),
    });
}
