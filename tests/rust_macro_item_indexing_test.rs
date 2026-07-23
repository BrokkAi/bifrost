//! Regression coverage for issue #1015: Rust items written inside item-position
//! macro invocations (tokio's `cfg_rt! { ... }` / `cfg_coop! { ... }`) must be
//! indexed exactly as if the macro braces were absent.
//!
//! Every test here fails before the reparse-based indexing in
//! `src/analyzer/rust/declarations.rs`: the wrapped items returned `not_found`.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::{BuiltInlineTestProject, InlineTestProject};
use serde_json::Value;

fn service(project: &BuiltInlineTestProject) -> SearchToolsService {
    SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).expect("service")
}

fn call(project: &BuiltInlineTestProject, tool: &str, args: Value) -> Value {
    let payload = service(project)
        .call_tool_json(tool, &args.to_string())
        .expect("tool call failed");
    serde_json::from_str(&payload).expect("tool returned invalid JSON")
}

fn symbol_sources(project: &BuiltInlineTestProject, symbol: &str) -> Value {
    call(
        project,
        "get_symbol_sources",
        serde_json::json!({ "symbols": [symbol] }),
    )
}

fn searched_symbols(result: &Value) -> Vec<String> {
    const BUCKETS: [&str; 5] = ["classes", "functions", "fields", "modules", "macros"];
    result["files"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|file| {
            BUCKETS
                .into_iter()
                .flat_map(move |bucket| file[bucket].as_array().into_iter().flatten().cloned())
        })
        .filter_map(|symbol| symbol["symbol"].as_str().map(str::to_string))
        .collect()
}

fn search(project: &BuiltInlineTestProject, pattern: &str) -> Vec<String> {
    let result = call(
        project,
        "search_symbols",
        serde_json::json!({ "patterns": [pattern], "include_tests": true, "limit": 20 }),
    );
    searched_symbols(&result)
}

/// The single resolved source for `symbol`, asserting no not_found/ambiguous.
fn unique_source<'a>(result: &'a Value, symbol: &str) -> &'a Value {
    assert_eq!(
        0,
        result["not_found"].as_array().map_or(0, Vec::len),
        "{symbol} should not be not_found: {result}"
    );
    assert_eq!(
        0,
        result["ambiguous"].as_array().map_or(0, Vec::len),
        "{symbol} should not be ambiguous: {result}"
    );
    let sources = result["sources"].as_array().expect("sources array");
    assert_eq!(
        1,
        sources.len(),
        "{symbol} should resolve to one source: {result}"
    );
    &sources[0]
}

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
}

// A same-file, faithfully-replaying passthrough macro (the shape tokio's
// `cfg_rt!`/`cfg_coop!` use). Wrapped fn, struct, a nested macro block, and a
// `pub mod` declaration must all index and resolve by bare name.
const PASSTHROUGH_LIB: &str = r#"macro_rules! my_cfg {
    ($($item:item)*) => { $(#[cfg(feature = "x")] $item)* };
}

my_cfg! {
    pub fn wrapped_fn() -> u32 {
        42
    }

    pub struct WrappedStruct {
        pub value: u32,
    }

    my_cfg! {
        pub fn nested_fn() -> u32 {
            7
        }
    }

    pub mod child;
}
"#;

#[test]
fn rust_macro_wrapped_items_resolve_by_bare_name() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", PASSTHROUGH_LIB)
        .file("child.rs", "pub fn child_fn() -> u32 {\n    1\n}\n")
        .build();

    // Free fn wrapped by the macro.
    let function = symbol_sources(&project, "wrapped_fn");
    let source = unique_source(&function, "wrapped_fn");
    assert_eq!("lib.rs", source["path"], "{function}");
    assert_eq!(
        line_of(PASSTHROUGH_LIB, "pub fn wrapped_fn"),
        source["start_line"].as_u64().expect("start_line") as usize,
        "{function}"
    );
    let text = source["text"].as_str().expect("text");
    assert!(text.contains("pub fn wrapped_fn"), "{text}");
    assert!(text.contains("42"), "{text}");

    // Struct wrapped by the macro.
    let structure = symbol_sources(&project, "WrappedStruct");
    let structure_source = unique_source(&structure, "WrappedStruct");
    assert!(
        structure_source["text"]
            .as_str()
            .expect("text")
            .contains("pub struct WrappedStruct"),
        "{structure}"
    );

    // Function nested one macro-level deeper (recursion must work).
    let nested = symbol_sources(&project, "nested_fn");
    let nested_source = unique_source(&nested, "nested_fn");
    assert_eq!(
        line_of(PASSTHROUGH_LIB, "pub fn nested_fn"),
        nested_source["start_line"].as_u64().expect("start_line") as usize,
        "{nested}"
    );

    // `pub mod child;` declaration wrapped by the macro is indexed as a module.
    assert!(
        search(&project, "child")
            .iter()
            .any(|symbol| symbol == "child"),
        "module `child` should be indexed"
    );
}

#[test]
fn rust_macro_wrapped_function_range_matches_exact_source_slice() {
    // I1(c): get_symbol_sources text equals the exact file slice for the range.
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", PASSTHROUGH_LIB)
        .file("child.rs", "pub fn child_fn() -> u32 {\n    1\n}\n")
        .build();

    let result = symbol_sources(&project, "wrapped_fn");
    let source = unique_source(&result, "wrapped_fn");
    let start = source["start_line"].as_u64().expect("start_line") as usize;
    let text = source["text"].as_str().expect("text");

    // The returned text must be a verbatim, unique slice of the file (I1(c)):
    // the node begins at `pub`, mid-line, so it is not the whole first line.
    let byte_pos = PASSTHROUGH_LIB
        .find(text)
        .expect("source text must appear verbatim in the file");
    assert_eq!(
        Some(byte_pos),
        PASSTHROUGH_LIB.rfind(text),
        "source text must be a unique slice: {result}"
    );
    let computed_start_line = PASSTHROUGH_LIB[..byte_pos]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1;
    assert_eq!(
        start, computed_start_line,
        "reported start_line must match the verbatim slice position: {result}"
    );
}

// Repro 1 + 2 combined, cross-file macro (the definition lives in another file
// and is unknown to the invoking file, exactly as tokio's `cfg_*` macros are).
// `crate::mymod::coop::poll_proceed` must resolve through the module path even
// though `poll_proceed` (and the `pub mod coop;` declaration) are macro-wrapped.
#[test]
fn rust_macro_wrapped_module_path_resolves_through_module_walk() {
    // `my_cfg!` is defined in the crate root only, so the submodule files that
    // invoke it never see the `macro_rules!` -- the exact cross-file shape of
    // tokio's `cfg_*` macros, where the invoking file has no local definition.
    let lib = r#"macro_rules! my_cfg {
    ($($item:item)*) => { $($item)* };
}

pub mod mymod;

pub fn caller() -> u32 {
    crate::mymod::coop::poll_proceed()
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"macro-mod\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", lib)
        .file("src/mymod.rs", "my_cfg! {\n    pub mod coop;\n}\n")
        .file(
            "src/mymod/coop.rs",
            "my_cfg! {\n    pub fn poll_proceed() -> u32 {\n        42\n    }\n}\n",
        )
        .build();

    // Bare-name resolution of the macro-wrapped free fn in a submodule file.
    let bare = symbol_sources(&project, "poll_proceed");
    let bare_source = unique_source(&bare, "poll_proceed");
    assert_eq!("src/mymod/coop.rs", bare_source["path"], "{bare}");

    // Module-path resolution: the terminal `poll_proceed` in the scoped path.
    let call_line = line_of(lib, "crate::mymod::coop::poll_proceed");
    let column = lib
        .lines()
        .nth(call_line - 1)
        .and_then(|line| line.find("poll_proceed"))
        .expect("terminal column")
        + 1;
    let resolved = call(
        &project,
        "get_definitions_by_location",
        serde_json::json!({
            "references": [{ "path": "src/lib.rs", "line": call_line, "column": column }]
        }),
    );
    let result = &resolved["results"][0];
    assert_eq!("resolved", result["status"], "{resolved}");
    assert_eq!(
        "mymod.coop.poll_proceed", result["definitions"][0]["fqn"],
        "{resolved}"
    );
    assert_eq!(
        "src/mymod/coop.rs", result["definitions"][0]["path"],
        "{resolved}"
    );
}

// cfg-paired declarations name the same module twice in one file; per the
// #1057 M2 same-file distinctness rule this must not create spurious ambiguity.
#[test]
fn rust_cfg_paired_module_declarations_do_not_create_ambiguity() {
    let lib = r#"macro_rules! cfg_rt {
    ($($item:item)*) => { $(#[cfg(feature = "rt")] $item)* };
}
macro_rules! cfg_not_rt {
    ($($item:item)*) => { $(#[cfg(not(feature = "rt"))] $item)* };
}

cfg_rt! {
    pub mod coop;
}

cfg_not_rt! {
    pub(crate) mod coop;
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", lib)
        .file("coop.rs", "pub fn poll_proceed() -> u32 {\n    1\n}\n")
        .build();

    let result = symbol_sources(&project, "coop");
    assert_eq!(
        0,
        result["ambiguous"].as_array().map_or(0, Vec::len),
        "cfg-paired same-file module declarations must not be ambiguous: {result}"
    );
    assert_eq!(
        0,
        result["not_found"].as_array().map_or(0, Vec::len),
        "module `coop` should resolve: {result}"
    );
}

// Negatives: expression-position macros, non-item token trees, and compiler
// builtins that consume rather than replay item tokens index nothing.
#[test]
fn rust_expression_and_non_item_macros_index_nothing() {
    // - `matches!`/`println!` inside a fn body are expression position: never
    //   visited as items, so their token soup produces nothing.
    // - the top-level `println!("...")` IS at item position, but its interior
    //   (`"fn fake_top() {}"`, a bare string literal) fails the parse gate.
    // - `numbers!` is an item-position macro whose interior (`1, 2, 3`) is not a
    //   Rust item stream, so the parse gate rejects it.
    let lib = r#"fn body() {
    let value = Some(1u32);
    let _ = matches!(value, Some(_));
    println!("fn fake_expr() {{}}");
}

println!("fn fake_top() {{}}");

numbers! { 1, 2, 3 }

stringify! {
    pub fn stringified_phantom() {}
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", lib)
        .build();

    for phantom in ["fake_expr", "fake_top", "numbers", "stringified_phantom"] {
        assert!(
            !search(&project, phantom)
                .iter()
                .any(|symbol| symbol == phantom),
            "`{phantom}` must not be indexed"
        );
        let sources = symbol_sources(&project, phantom);
        assert_eq!(
            0,
            sources["sources"].as_array().map_or(0, Vec::len),
            "`{phantom}` must resolve to no sources: {sources}"
        );
    }

    // The real function body item is still indexed.
    assert!(
        search(&project, "body")
            .iter()
            .any(|symbol| symbol == "body"),
        "the enclosing `body` fn should index normally"
    );
}
