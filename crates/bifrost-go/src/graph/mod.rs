//! Go's usage-graph knowledge: the AST vocabulary, the reference resolver, the
//! tree-free project/edge indexes, and both scan bodies built on them.
//!
//! [`extractor`] is the per-symbol forward scan (one target, every candidate
//! file); it attributes each hit through
//! [`CodeUnitIndex::enclosing_code_unit`], so it needs no analyzer handle.
//! [`inverted`] is the per-file half of the whole-workspace pass, reading a core
//! `FileEdgeScanInput` and returning core `PerFileEdges`. Only that pass's
//! workspace fan-out stays in `brokk-bifrost-analysis`, because it needs an
//! analyzer handle for each file's declaration index.
//!
//! [`CodeUnitIndex::enclosing_code_unit`]:
//! brokk_bifrost_core::analyzer::CodeUnitIndex::enclosing_code_unit

pub mod ast;
pub mod extractor;
mod hits;
pub mod inverted;
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
