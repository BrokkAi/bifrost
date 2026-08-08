//! Issue #1812: when bare-call resolution found NO candidates and could not
//! prove the call arity, it answered `Ambiguous` - "we found nothing" reported
//! as ambiguity. The `Ambiguous` arm of the get_definition mapping returns
//! early, so the same-file macro fallback (`cpp_macro_candidates`) became
//! unreachable exactly when it was needed: a call to a function-like or
//! object-like macro defined in the referencing file never resolved once an
//! unresolvable quoted include poisoned the macro environment.
//!
//! A no-candidate outcome must be `Missing` so the macro fallback runs, and a
//! name that exists nowhere must answer `no_definition`, not `ambiguous`.

use crate::common::{InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::{Value, json};

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

/// fx18, the libyang `RBN_RIGHT` shape: a function-like macro defined in the
/// same file, called under a poisoned include.
#[test]
fn same_file_function_like_macro_resolves_under_poisoned_include() {
    let source = r#"#include "missing.h"

#define RBN_RIGHT(NODE) ((NODE)->right)

struct node { struct node *right; };

int caller(struct node *iter) {
    if (RBN_RIGHT(iter)) {
        return 1;
    }
    return 0;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let result = definition_at(&project, "a.c", source, "RBN_RIGHT(iter)");
    assert_eq!(
        result["status"], "resolved",
        "the same-file macro must win the fallback instead of a no-candidate ambiguity: {result:#}"
    );
}

/// fx19 control: the same macro call without the poisoned include already
/// resolved and must stay resolved.
#[test]
fn same_file_function_like_macro_control_stays_resolved() {
    let source = r#"#define RBN_RIGHT(NODE) ((NODE)->right)

struct node { struct node *right; };

int caller(struct node *iter) {
    if (RBN_RIGHT(iter)) {
        return 1;
    }
    return 0;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let result = definition_at(&project, "a.c", source, "RBN_RIGHT(iter)");
    assert_eq!(
        result["status"], "resolved",
        "clean-include macro control regressed: {result:#}"
    );
}

/// fx20, the glpk `error` shape: an object-like alias macro forwards the call
/// to another function. The call site names the macro, so the macro is the
/// answer.
#[test]
fn same_file_object_like_alias_macro_resolves() {
    let source = r#"#include "missing.h"

#define error dmx_error

void dmx_error(int *csa, const char *fmt);

void caller(int *csa) {
    error(csa, "boom");
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let result = definition_at(&project, "a.c", source, "error(csa,");
    assert_eq!(
        result["status"], "resolved",
        "an object-like alias macro defined in the same file must resolve: {result:#}"
    );
}

/// fx11 isolates the answer-shape defect: a call to a name that exists nowhere
/// answered `ambiguous` with no candidates. Nothing was found, so the honest
/// answer is `no_definition`.
#[test]
fn nowhere_name_answers_no_definition() {
    let source = r#"#include "missing.h"

void caller(int x) {
    nosuchfunction(x);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.c", source)
        .build();
    let result = definition_at(&project, "a.c", source, "nosuchfunction(x)");
    assert_eq!(
        result["status"], "no_definition",
        "a name that exists nowhere is not ambiguous: {result:#}"
    );
    assert!(
        result["definitions"]
            .as_array()
            .is_none_or(|definitions| definitions.is_empty()),
        "a no-definition answer must not carry definitions: {result:#}"
    );
}
