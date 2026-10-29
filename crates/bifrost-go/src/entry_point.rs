//! Go entry-point classification hooks.

use brokk_bifrost_core::analyzer::CodeUnit;

/// Whether Go's runtime or test harness calls `candidate` without a written
/// call site.
///
/// `package_clause` is the structured declared package identifier for the
/// candidate's file. A missing or empty clause leaves a function named `main`
/// inconclusive.
///
/// Lives here beside the other Go usage-graph facts, as C++'s
/// `is_cpp_global_main` does: dead-code analysis both filters candidates on it
/// and holds such candidates back from the bulk proof, so it cannot live in
/// either caller.
pub fn go_implicit_entry_point(candidate: &CodeUnit, package_clause: Option<&str>) -> Option<bool> {
    if !candidate.is_function() {
        return Some(false);
    }
    let name = candidate.identifier();
    if name == "init" {
        return Some(true);
    }
    if name == "main" {
        let package_clause = package_clause.filter(|package_clause| !package_clause.is_empty())?;
        return Some(package_clause == "main");
    }
    Some(
        candidate
            .source()
            .rel_path()
            .to_string_lossy()
            .ends_with("_test.go")
            && go_test_entry_point_name(name),
    )
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
