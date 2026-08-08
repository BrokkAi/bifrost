//! Issue #1811: a bare C call with exactly ONE in-workspace candidate answered
//! `ambiguous` with an EMPTY definitions list whenever the call arity could not
//! be proven.
//!
//! An unresolvable quoted include (`#include "missing.h"`) poisons the macro
//! environment, so a bare-identifier argument makes the call arity unknown.
//! `resolve_callable_candidates` then returned `UnprovenFreeFunctions`
//! regardless of candidate count, and the get_definition mapping turned a
//! single-candidate `UnprovenFreeFunctions` into `ambiguous_definition` -
//! discarding the one proven candidate.
//!
//! Unproven arity cannot create ambiguity where there is exactly one name
//! binding: C has no overloading, so one candidate must resolve. Two genuine
//! same-name candidates must still answer `ambiguous`, and must carry both
//! candidates in `definitions`: an ambiguity that shows nothing gives the
//! caller nothing to choose between.

use crate::common::{InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::{Value, json};

/// The `get_definitions_by_location` result for the first byte of `needle` in
/// `source`, which the caller must have written to `path`.
fn definition_at(
    project: &crate::common::BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
) -> Value {
    let start = source
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is not present in {path}"));
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": path, "line": line, "column": column}]}).to_string();
    call_tool(project, "get_definitions_by_location", &args)["results"][0].clone()
}

fn definition_paths(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| {
                    definition["file"].as_str().or(definition["path"].as_str())
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// fx5: poisoned include + one static helper + identifier argument. The single
/// candidate must win even though the argument count is unknown.
#[test]
fn poisoned_include_single_candidate_resolves() {
    let source = r#"#include "missing.h"

static void helper(int v) { (void)v; }

void caller(int x) {
    helper(x);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let result = definition_at(&project, "a.c", source, "helper(x)");
    assert_eq!(
        result["status"], "resolved",
        "one candidate cannot be ambiguous, even with unproven arity: {result:#}"
    );
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "the single proven candidate must be reported: {result:#}"
    );
}

/// fx3 and fx7 controls: a clean include graph and a literal argument both
/// prove the arity today and must stay resolved.
#[test]
fn clean_include_and_literal_argument_controls_stay_resolved() {
    let clean = r#"static void helper(int v) { (void)v; }

void caller(int x) {
    helper(x);
}
"#;
    let clean_project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", clean)
        .build();
    let clean_result = definition_at(&clean_project, "a.c", clean, "helper(x)");
    assert_eq!(
        clean_result["status"], "resolved",
        "clean-include control regressed: {clean_result:#}"
    );

    let literal = r#"#include "missing.h"

static void helper(int v) { (void)v; }

void caller(void) {
    helper(1);
}
"#;
    let literal_project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", literal)
        .build();
    let literal_result = definition_at(&literal_project, "a.c", literal, "helper(1)");
    assert_eq!(
        literal_result["status"], "resolved",
        "literal-argument control regressed: {literal_result:#}"
    );
}

/// Two genuinely distinct same-name candidates with unprovable arity stay
/// ambiguous - and the answer must list both, so a caller can act on it.
#[test]
fn two_same_name_candidates_stay_ambiguous_with_both_listed() {
    let source = r#"#include "missing.h"
#include "alpha.h"
#include "beta.h"

void caller(int x) {
    helper(x);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("alpha.h", "void helper(int v);\n")
        .file(
            "alpha.c",
            "#include \"alpha.h\"\nvoid helper(int v) { (void)v; }\n",
        )
        .file("beta.h", "void helper(const char *s, int v);\n")
        .file(
            "beta.c",
            "#include \"beta.h\"\nvoid helper(const char *s, int v) { (void)s; (void)v; }\n",
        )
        .file("a.c", source)
        .build();
    let result = definition_at(&project, "a.c", source, "helper(x)");
    assert_eq!(
        result["status"], "ambiguous",
        "two same-name candidates with unprovable arity must stay ambiguous: {result:#}"
    );
    let paths = definition_paths(&result);
    assert!(
        paths.len() >= 2,
        "an ambiguous answer must carry its candidates, got {paths:?}: {result:#}"
    );
    assert!(
        paths.iter().any(|path| path.ends_with("alpha.c"))
            && paths.iter().any(|path| path.ends_with("beta.c")),
        "both candidates must be listed, got {paths:?}: {result:#}"
    );
}
