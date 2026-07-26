//! Issue #1142: `const`/`static`/`type` items declared directly inside an
//! inline `mod foo { ... }` block are never indexed at all.
//!
//! `visit_rust_module`'s body-traversal match in
//! `src/analyzer/rust/declarations.rs` handled `function_item`, `struct_item`
//! / `enum_item` / `trait_item`, `mod_item`, `impl_item`, `macro_definition`,
//! and `macro_invocation` -- but had no arm for `const_item`, `static_item`,
//! or `type_item`. Those three kinds fell through the wildcard `_ => {}` and
//! produced no declaration, so a `const`/`static`/`type` alias nested inside
//! an inline module was invisible to every search/usage tool, even though the
//! identical file-scope item (and the identical item nested inside a
//! `struct`/`enum`/`trait` body, and the identical item reparsed out of an
//! item-position macro invocation) indexed fine.
//!
//! Fix: `visit_rust_module` now routes `const_item`/`static_item` through
//! `visit_rust_field` and `type_item` through `visit_rust_alias` -- the same
//! visitors already used for the file-scope and macro-reparse paths -- passing
//! the module's own `CodeUnit` as `parent` so identity/kind/ownership match
//! their top-level equivalents exactly.

mod common;

use brokk_bifrost::Language;
use common::{BuiltInlineTestProject, InlineTestProject, call_tool, symbol_sources};

/// Assert `symbol` resolves unambiguously via `get_symbol_sources` and that
/// one of its source texts contains `expected_snippet`.
fn assert_resolves(project: &BuiltInlineTestProject, symbol: &str, expected_snippet: &str) {
    let result = symbol_sources(project, symbol);
    assert_eq!(
        0,
        result["not_found"].as_array().map_or(0, Vec::len),
        "`{symbol}` must resolve: {result}"
    );
    assert_eq!(
        0,
        result["ambiguous"].as_array().map_or(0, Vec::len),
        "`{symbol}` must resolve unambiguously: {result}"
    );
    let sources = result["sources"].as_array().unwrap();
    assert!(
        sources.iter().any(|source| source["text"]
            .as_str()
            .unwrap_or("")
            .contains(expected_snippet)),
        "`{symbol}` did not resolve to text containing `{expected_snippet}`: {result}"
    );
}

/// A single-package project (`src/mypkg.rs` -> package `mypkg`) with:
/// - an inline `mod settings { ... }` holding a `const`, a `static`, and a
///   `type` alias (the exact bug shape from the issue);
/// - a two-level-nested `mod outer { mod inner { const ... } }` to prove
///   nesting depth beyond one level works;
/// - file-scope `const`/`static`/`type` equivalents, to prove the existing
///   (already-working) path is untouched by the fix.
fn project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"issue-1142\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/mypkg.rs",
            r#"
mod settings {
    pub const MAX_SIZE: usize = 42;
    pub static COUNTER: i32 = 0;
    pub type Alias = i32;
}

mod outer {
    mod inner {
        pub const DEEP_CONST: i32 = 7;
    }
}

pub const TOP_CONST: usize = 100;
pub static TOP_STATIC: i32 = 1;
pub type TopAlias = i32;
"#,
        )
        .build()
}

#[test]
fn inline_mod_const_resolves_under_module_qualified_fqn() {
    let project = project();
    assert_resolves(&project, "mypkg.settings.MAX_SIZE", "MAX_SIZE: usize = 42");
}

#[test]
fn inline_mod_static_resolves_under_module_qualified_fqn() {
    let project = project();
    assert_resolves(&project, "mypkg.settings.COUNTER", "COUNTER: i32 = 0");
}

#[test]
fn inline_mod_type_alias_resolves_under_module_qualified_fqn() {
    let project = project();
    assert_resolves(&project, "mypkg.settings.Alias", "type Alias = i32");
}

/// Two levels of inline-module nesting (`mod outer { mod inner { const ... } }`)
/// must resolve just as well as one level -- the module-body traversal is
/// stack/iterative-recursive over however deep the source actually nests, so
/// this is not a special case in the fix, but it is exactly what the issue
/// asked to be checked explicitly.
#[test]
fn two_level_inline_mod_nesting_resolves() {
    let project = project();
    assert_resolves(
        &project,
        "mypkg.outer.inner.DEEP_CONST",
        "DEEP_CONST: i32 = 7",
    );
}

/// Negative / regression: the file-scope equivalents must still resolve
/// (this fix must not regress or double-index the already-working path).
#[test]
fn file_scope_const_static_type_are_unaffected() {
    let project = project();
    assert_resolves(&project, "mypkg.TOP_CONST", "TOP_CONST: usize = 100");
    assert_resolves(&project, "mypkg.TOP_STATIC", "TOP_STATIC: i32 = 1");
    assert_resolves(&project, "mypkg.TopAlias", "type TopAlias = i32");
}

/// `get_summaries` on the enclosing module must list the nested const/static/
/// type as `field`-kind elements (the same `CodeUnitType` file-scope const/
/// static/type items and struct/enum/trait-nested ones use), proving they are
/// not just resolvable by lookup but actually enumerated as declarations.
#[test]
fn inline_mod_items_appear_in_module_summary() {
    let project = project();
    let summary = call_tool(
        &project,
        "get_summaries",
        r#"{"targets":["mypkg.settings"]}"#,
    );
    assert_eq!(
        0,
        summary["not_found"].as_array().map_or(0, Vec::len),
        "{summary}"
    );
    let elements = summary["summaries"][0]["elements"]
        .as_array()
        .unwrap_or_else(|| panic!("expected elements array: {summary}"));
    let field_symbols: Vec<&str> = elements
        .iter()
        .filter(|element| element["kind"] == "field")
        .map(|element| element["symbol"].as_str().expect("symbol"))
        .collect();

    for expected in ["settings.MAX_SIZE", "settings.COUNTER", "settings.Alias"] {
        assert!(
            field_symbols
                .iter()
                .any(|symbol| symbol.ends_with(expected)),
            "expected a field symbol ending with `{expected}` in {field_symbols:?}: {summary}"
        );
    }
}

/// In-test-region taint (#1102) parity: a `const` nested in an inline `mod`
/// that is itself nested inside a `#[cfg(test)] mod tests { ... }` block must
/// be hidden from `search_symbols` under the default `include_tests:false`
/// (exactly like a `fn`/`struct` in the same position already is) and appear
/// once `include_tests:true` is passed -- proving the fix routes through
/// `mark_test_region` the same way the pre-existing arms do, rather than
/// through a parallel path that skips the taint.
#[test]
fn inline_mod_const_in_test_module_is_tainted_as_test_region() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "widget.rs",
            r#"pub const PROD_LIMIT: usize = 3;

#[cfg(test)]
mod tests {
    const FIXTURE_LIMIT: usize = 3;

    #[test]
    fn uses_fixture_limit() {
        assert_eq!(FIXTURE_LIMIT, 3);
    }
}
"#,
        )
        .build();

    // Default (include_tests:false): the production const is found...
    let production = call_tool(&project, "search_symbols", r#"{"patterns":["PROD_LIMIT"]}"#);
    assert!(
        production["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "production const should surface by default: {production}"
    );

    // ...but the const nested inside the inline `#[cfg(test)] mod tests` is
    // hidden by default.
    let hidden = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["FIXTURE_LIMIT"]}"#,
    );
    assert!(
        hidden["files"]
            .as_array()
            .is_none_or(|files| files.is_empty()),
        "const nested in an inline `mod` under `#[cfg(test)]` must be hidden by default: {hidden}"
    );

    // include_tests:true: the tainted const appears — and it must be the
    // const's OWN symbol resolving, not a text match attributed to the
    // (already-indexed, already-tainted) enclosing `tests` module. Resolving
    // the const's fq spelling through get_symbol_sources is the assertion
    // that discriminates: before the fix the const has no code unit at all
    // and this returns not_found regardless of include_tests.
    let revealed = call_tool(
        &project,
        "search_symbols",
        r#"{"patterns":["FIXTURE_LIMIT"],"include_tests":true}"#,
    );
    assert!(
        revealed["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "const nested in an inline `mod` under `#[cfg(test)]` should appear with include_tests:true: {revealed}"
    );
    let sources = call_tool(
        &project,
        "get_symbol_sources",
        r#"{"symbols":["widget.rs#tests.FIXTURE_LIMIT"],"include_tests":true}"#,
    );
    assert_eq!(
        0,
        sources["not_found"].as_array().map_or(0, Vec::len),
        "the tainted const's own anchored spelling must resolve with include_tests:true: {sources}"
    );
}
