//! Go's usage-graph knowledge: the AST vocabulary, the reference resolver, and
//! the tree-free project/edge indexes both the per-symbol scan and the
//! whole-workspace inverted pass are built on.
//!
//! What is *not* here: the scan drivers. The forward scan
//! (`go_graph/extractor.rs`) attributes each hit through
//! `IAnalyzer::enclosing_code_unit`, an analysis-owned type with no core
//! equivalent, and the inverted pass's workspace fan-out
//! (`go_graph/inverted.rs`'s `build_go_edges`) needs an analyzer handle to build
//! each file's declaration index. Its per-file walk does not: `scan_go_file`
//! reads a `FileEdgeScanInput` and returns `PerFileEdges`, both core types.

pub mod ast;
pub mod reference;
pub mod resolver;

use brokk_bifrost_core::analyzer::CodeUnit;

/// Whether Go's runtime or test harness calls `candidate` without a written
/// call site.
///
/// Lives here beside the other Go usage-graph facts, as C++'s
/// `is_cpp_global_main` does: dead-code analysis both filters candidates on it
/// and holds such candidates back from the bulk proof, so it cannot live in
/// either caller.
pub fn go_implicit_entry_point(candidate: &CodeUnit) -> bool {
    if !candidate.is_function() {
        return false;
    }
    let name = candidate.identifier();
    name == "init"
        || name == "main" && go_source_declares_package_main(candidate)
        || candidate
            .source()
            .rel_path()
            .to_string_lossy()
            .ends_with("_test.go")
            && go_test_entry_point_name(name)
}

fn go_source_declares_package_main(candidate: &CodeUnit) -> bool {
    candidate
        .source()
        .read_to_string()
        .is_ok_and(|source| source.lines().any(|line| line.trim() == "package main"))
}

fn go_test_entry_point_name(name: &str) -> bool {
    ["Test", "Benchmark", "Fuzz", "Example"]
        .into_iter()
        .any(|prefix| go_test_name_matches_prefix(name, prefix))
}

fn go_test_name_matches_prefix(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    rest.chars().next().is_none_or(|ch| !ch.is_lowercase())
}
