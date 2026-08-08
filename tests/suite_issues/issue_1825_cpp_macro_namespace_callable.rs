//! Issue #1825: a bare namespace-opening macro token (`ABSL_NAMESPACE_BEGIN`,
//! `FMT_BEGIN_NAMESPACE`) hid every following declaration from C++ forward
//! resolution.
//!
//! The token before `namespace x {` makes tree-sitter build a synthetic
//! `function_definition` whose `compound_statement` holds the real
//! declarations. Extraction already recovers the namespace owner, so the FQNs
//! are right, but the ancestor walk in `callable_declaration_activation_in_file`
//! discarded any declaration under a `compound_statement` and the callable was
//! never activated.
//!
//! The escape hatch for the exported-class recovery shape already existed;
//! these tests pin its namespace twin, plus the control that a declaration
//! inside a *real* function body still must not leak out.

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

/// Fixture `A/ns-macro-token/f6-begin-toplevel`: the macro token at
/// translation-unit scope.
#[test]
fn namespace_macro_token_at_top_level_keeps_callables_visible() {
    let source = r#"ABSL_NAMESPACE_BEGIN
namespace debugging_internal {

static bool ParseOneCharToken(int state, char token) { return state == token; }

static bool ParseName(int state) {
  return ParseOneCharToken(state, 'E');
}

}
ABSL_NAMESPACE_END
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.cc", source)
        .build();
    let result = definition_at(&project, "a.cc", source, "ParseOneCharToken(state, 'E')");
    assert_eq!(
        result["status"], "resolved",
        "a declaration whose only function-like ancestor is a macro-recovery \
         artifact is at namespace scope: {result:#}"
    );
}

/// Fixture `A/ns-macro-token/f2-macro-token`: the exact abseil shape, macro
/// token nested one namespace deep.
#[test]
fn namespace_macro_token_inside_a_namespace_keeps_callables_visible() {
    let source = r#"namespace absl {
ABSL_NAMESPACE_BEGIN
namespace debugging_internal {

static bool ParseOneCharToken(int state, char token) { return state == token; }

static bool ParseName(int state) {
  return ParseOneCharToken(state, 'E');
}

}
ABSL_NAMESPACE_END
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.cc", source)
        .build();
    let result = definition_at(&project, "a.cc", source, "ParseOneCharToken(state, 'E')");
    assert_eq!(
        result["status"], "resolved",
        "the abseil ABSL_NAMESPACE_BEGIN shape must not hide its callables: {result:#}"
    );
}

/// The fmt spelling of the same shape.
#[test]
fn fmt_begin_namespace_keeps_callables_visible() {
    let source = r#"FMT_BEGIN_NAMESPACE
namespace detail {

inline int count_digits(int n) { return n < 10 ? 1 : 2; }

inline int width_of(int n) {
  return count_digits(n);
}

}
FMT_END_NAMESPACE
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("format.h", source)
        .build();
    let result = definition_at(&project, "format.h", source, "count_digits(n);");
    assert_eq!(
        result["status"], "resolved",
        "FMT_BEGIN_NAMESPACE is the same recovery shape: {result:#}"
    );
}

/// The D-report family L-B shape (fixture `D/O4/r.h`): the callee under the
/// macro-opened namespace is a *bodyless* declaration used as a field
/// initializer. It was answered `local_variable_reference` ("is a local C++
/// value") because the synthetic wrapper made the namespace-scope declaration
/// look block local.
#[test]
fn namespace_macro_token_bodyless_declaration_is_not_a_local_value() {
    let header = r#"#pragma once
namespace ns {
ABSL_NAMESPACE_BEGIN
namespace internal {
using GenT = unsigned char;
GenT* PtrDecl();
class C1 {
 private:
  const GenT* a_ = PtrDecl();
};
}  // namespace internal
ABSL_NAMESPACE_END
}  // namespace ns
"#;
    let impl_source = r#"#include "r.h"
namespace ns {
namespace internal {
GenT* PtrDecl() { static GenT g = 0; return &g; }
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("r.h", header)
        .file("r.cc", impl_source)
        .build();
    let result = definition_at(&project, "r.h", header, "PtrDecl();\n};");
    assert_eq!(
        result["status"], "resolved",
        "a namespace-scope declaration under a namespace-opening macro is not a \
         local value: {result:#}"
    );
}

/// Negative control: a block-scope function declaration inside a *real*
/// function body must not become visible to a sibling function. This is the
/// exact rule the `compound_statement` arm of the ancestor walk enforces, so it
/// pins that the recovery escape did not widen into "any compound statement".
#[test]
fn declaration_inside_a_real_function_body_does_not_leak() {
    let source = r#"namespace absl {

void outer() {
  bool ParseOneCharToken(int s, char t);
  (void)ParseOneCharToken(1, 'E');
}

static bool ParseName(int state) {
  return ParseOneCharToken(state, 'E');
}

}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("a.cc", source)
        .build();
    let result = definition_at(&project, "a.cc", source, "ParseOneCharToken(state, 'E')");
    assert_ne!(
        result["status"], "resolved",
        "a block-local declaration in a real function body must not be visible \
         to a sibling function: {result:#}"
    );
}
