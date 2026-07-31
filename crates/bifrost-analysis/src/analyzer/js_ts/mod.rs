pub(crate) mod cache;
pub(crate) mod clones;
pub(crate) mod diagnostics;
pub(crate) mod hierarchy;
pub(crate) mod identifiers;
pub(crate) mod imports;
pub(crate) mod model;
pub(crate) mod providers;
pub(crate) mod semantic;
pub(crate) mod structural;
pub(crate) mod syntax;
pub(crate) mod tests;
pub(crate) mod tsconfig;

pub(crate) use cache::{build_weighted_cache, weight_code_unit_vec_by_unit};
pub(crate) use imports::resolve_js_ts_module_specifier;
pub(crate) use tsconfig::AliasResolver;

use crate::analyzer::cognitive_complexity;
use crate::analyzer::js_ts::model::module_code_unit;
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::{ProjectFile, Range};
use crate::text_utils::compute_line_starts;
use std::sync::LazyLock;

static JS_TS_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["ternary_expression"],
        case_types: &["switch_case"],
        default_case_types: &["switch_default"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "??"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &[
            "function_declaration",
            "function_expression",
            "generator_function",
            "generator_function_declaration",
            "method_definition",
            "arrow_function",
        ],
        else_clause_types: &["else_clause"],
        ..cognitive_complexity::Config::empty()
    });

pub(crate) fn cognitive_complexity_config() -> &'static cognitive_complexity::Config {
    &JS_TS_COGNITIVE_CONFIG
}

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
