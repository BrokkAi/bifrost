pub(crate) use brokk_bifrost_core::analyzer::usages::parsed_tree::{
    ParsedTreeFile, parse_tree_sitter_file, parse_tree_sitter_source,
};

// `js_ts_tree_sitter_language_for_file` used to live here -- a JS/TS-named free
// function in a framework file. Every one of its eight call sites moved with the
// JS/TS seam, so it now lives in `brokk_bifrost_js_ts::parse` and answers from
// the two grammar crates directly instead of through the analyzer registry.
