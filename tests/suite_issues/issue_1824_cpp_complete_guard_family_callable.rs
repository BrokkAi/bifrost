//! Issue #1824: a C++ callable declared under a *complete* `#if`/`#else`
//! family was invisible to a reference outside the family.
//!
//! `callable_preprocessor_context_is_visible_for_reference` accepted an
//! undecidable guard only when the reference already stood under the same
//! guard. That is right for a lone conditional branch, but it has no notion of
//! a completed family: when every branch of one `#if`/`#elif`/`#else` chain
//! declares the same name, the name is declared on every configuration path and
//! the reference cannot fail to see one of them.
//!
//! The type side already reasons this way through
//! `preprocessor_guard_terms_cover_all_paths`. These tests hold the callable
//! side to the same contract, and pin the negative control: an *incomplete*
//! family (no terminal `#else`) must stay invisible on the uncovered path.

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

/// Fixture `A/macro-prefix/v9-ifdef-else`: the `#ifdef`/`#else` pair covers both
/// configurations, so the unguarded caller below it must resolve.
#[test]
fn ifdef_else_family_is_visible_below_the_family() {
    let source = r#"typedef unsigned long long u64;
#ifdef FORCE_MEM
static u64 readLE64(const void* p)
{
    return 0;
}
#else
static u64 readLE64(const void* p)
{
    return 1;
}
#endif
u64 caller(const void* p)
{
    return readLE64(p);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", source)
        .build();
    let result = definition_at(&project, "main.cpp", source, "readLE64(p);");
    assert_eq!(
        result["status"], "resolved",
        "a name declared on every branch of a completed #if family is declared \
         unconditionally: {result:#}"
    );
}

/// Fixture `A/macro-prefix/v4-plain-guarded`: the real xxhash shape, an
/// undecidable `#if` expression paired with `#else`.
#[test]
fn complex_if_else_family_is_visible_below_the_family() {
    let source = r#"typedef unsigned long long u64;

#if (defined(FORCE_MEM) && (FORCE_MEM==3))
static u64 readLE64(const void* p)
{
    return 0;
}
#else
static u64 readLE64(const void* p)
{
    return *(const u64*)p;
}
#endif

u64 caller(const void* p)
{
    return readLE64(p);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", source)
        .build();
    let result = definition_at(&project, "main.cpp", source, "readLE64(p);");
    assert_eq!(
        result["status"], "resolved",
        "an undecidable guard expression paired with #else still covers all paths: {result:#}"
    );
}

/// A three-way `#if`/`#elif`/`#else` chain is exhaustive in the same way.
#[test]
fn if_elif_else_family_is_visible_below_the_family() {
    let source = r#"typedef unsigned long long u64;

#if defined(MODE_A)
static u64 readLE64(const void* p) { return 0; }
#elif defined(MODE_B)
static u64 readLE64(const void* p) { return 1; }
#else
static u64 readLE64(const void* p) { return 2; }
#endif

u64 caller(const void* p)
{
    return readLE64(p);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", source)
        .build();
    let result = definition_at(&project, "main.cpp", source, "readLE64(p);");
    assert_eq!(
        result["status"], "resolved",
        "an #if/#elif/#else chain covers all paths: {result:#}"
    );
}

/// Negative control, fixture `A/macro-prefix/v6-single-guarded`: without a
/// terminal `#else` the family leaves a configuration in which the name is
/// never declared. The reference outside it must NOT resolve.
#[test]
fn incomplete_guard_family_stays_invisible() {
    let source = r#"typedef unsigned long long u64;
#ifdef FORCE_MEM
static u64 readLE64(const void* p)
{
    return 0;
}
#endif
u64 caller(const void* p)
{
    return readLE64(p);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", source)
        .build();
    let result = definition_at(&project, "main.cpp", source, "readLE64(p);");
    assert_ne!(
        result["status"], "resolved",
        "an #ifdef with no #else leaves an uncovered configuration; the callable \
         must not be reported as visible: {result:#}"
    );
}

/// Negative control: two same-name declarations in *separate* conditional
/// blocks can both be inactive (the macro can change between them), so they do
/// not form a family and must stay invisible.
#[test]
fn separate_conditional_blocks_are_not_a_family() {
    let source = r#"typedef unsigned long long u64;
#ifdef FORCE_MEM
static u64 readLE64(const void* p) { return 0; }
#endif
#ifndef FORCE_MEM
static u64 readLE64(const void* p) { return 1; }
#endif
u64 caller(const void* p)
{
    return readLE64(p);
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", source)
        .build();
    let result = definition_at(&project, "main.cpp", source, "readLE64(p);");
    assert_ne!(
        result["status"], "resolved",
        "two separate #if blocks are not one exhaustive family: {result:#}"
    );
}
