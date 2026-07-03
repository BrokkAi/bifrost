//! Go-to-definition corner cases borrowed from rust-analyzer's own
//! `crates/ide/src/goto_definition.rs` inline test corpus (the `check(r#"..."#)`
//! fixtures with `$0` cursor + `//^^^` definition markers). Each case here cites
//! the upstream test name it was ported from.
//!
//! Scope: only rust-analyzer cases that land inside bifrost's CodeUnit envelope
//! (struct/enum/trait/impl items, methods, fields, associated functions). Cases
//! that target locals, params, ranges, macros, or control-flow keywords are out
//! of bifrost's model by architecture and are intentionally not ported.
//!
//! Driven through the real LSP server (`textDocument/definition`) so this also
//! exercises cursor resolution, exactly like the upstream tests drive the IDE.

mod common;

use common::lsp_client::{LspServer, uri_for};
use serde_json::Value;
use std::path::PathBuf;
use tempfile::TempDir;

fn split_caret(source: &str) -> (String, u64, u64) {
    let idx = source
        .find("<caret>")
        .expect("fixture must contain <caret>");
    let before = &source[..idx];
    let line = before.matches('\n').count() as u64;
    let last_line_start = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
    let character = before[last_line_start..].chars().count() as u64;
    (source.replacen("<caret>", "", 1), line, character)
}

fn definition_lines(name: &str, source_with_caret: &str) -> (TempDir, Vec<u64>) {
    let (source, line, character) = split_caret(source_with_caret);
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file: PathBuf = root.join(name);
    std::fs::write(&file, source).expect("write fixture");

    let mut server = LspServer::start(&root);
    let response = server.text_document_position_response(
        "textDocument/definition",
        &uri_for(&file),
        line,
        character,
    );
    server.shutdown();

    let file_uri = uri_for(&file);
    let lines = match &response["result"] {
        Value::Array(items) => items
            .iter()
            .filter(|loc| loc["uri"].as_str() == Some(file_uri.as_str()))
            .filter_map(|loc| loc["range"]["start"]["line"].as_u64())
            .collect(),
        Value::Object(loc) => loc["range"]["start"]["line"].as_u64().into_iter().collect(),
        _ => Vec::new(),
    };
    (temp, lines)
}

fn definition_lines_in_files(
    files: &[(&str, &str)],
    query_name: &str,
    target_name: &str,
) -> (TempDir, Vec<u64>) {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let mut query_position = None;
    for (name, source) in files {
        let file = root.join(name);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).expect("mkdir fixture parent");
        }
        let source = if *name == query_name {
            let (source, line, character) = split_caret(source);
            query_position = Some((line, character));
            source
        } else {
            source.to_string()
        };
        std::fs::write(&file, source).expect("write fixture");
    }

    let (line, character) = query_position.expect("query fixture must contain <caret>");
    let query_file = root.join(query_name);
    let target_file = root.join(target_name);
    let mut server = LspServer::start(&root);
    let response = server.text_document_position_response(
        "textDocument/definition",
        &uri_for(&query_file),
        line,
        character,
    );
    server.shutdown();

    let target_uri = uri_for(&target_file);
    let lines = match &response["result"] {
        Value::Array(items) => items
            .iter()
            .filter(|loc| loc["uri"].as_str() == Some(target_uri.as_str()))
            .filter_map(|loc| loc["range"]["start"]["line"].as_u64())
            .collect(),
        Value::Object(loc) if loc["uri"].as_str() == Some(target_uri.as_str()) => {
            loc["range"]["start"]["line"].as_u64().into_iter().collect()
        }
        _ => Vec::new(),
    };
    (temp, lines)
}

fn assert_resolves_to_line(name: &str, source_with_caret: &str, expected: u64) {
    let (_t, lines) = definition_lines(name, source_with_caret);
    assert!(
        lines.contains(&expected),
        "expected {name} to resolve to line {expected}, got {lines:?}"
    );
}

// rust-analyzer: goto_def_for_methods — `foo.frobnicate()` where `foo: &Foo` is a
// typed parameter; resolves to the inherent method declaration (line 2).
#[test]
fn ra_goto_def_for_methods() {
    assert_resolves_to_line(
        "m.rs",
        "struct Foo;\nimpl Foo {\n    fn frobnicate(&self) { }\n}\n\nfn bar(foo: &Foo) {\n    foo.frobnicate<caret>();\n}\n",
        2,
    );
}

// rust-analyzer: goto_def_for_fields — `foo.spam` field access on a typed
// parameter resolves to the field declaration (line 1).
#[test]
fn ra_goto_def_for_fields() {
    assert_resolves_to_line(
        "f.rs",
        "struct Foo {\n    spam: u32,\n}\n\nfn bar(foo: &Foo) {\n    foo.spam<caret>;\n}\n",
        1,
    );
}

// rust-analyzer: goto_def_for_ufcs_inherent_methods — `Foo::frobnicate()`
// associated-function call resolves to the inherent method (line 2).
#[test]
fn ra_goto_def_for_ufcs_inherent_methods() {
    assert_resolves_to_line(
        "u.rs",
        "struct Foo;\nimpl Foo {\n    fn frobnicate() { }\n}\n\nfn bar(foo: &Foo) {\n    Foo::frobnicate<caret>();\n}\n",
        2,
    );
}

// rust-analyzer: goto_def_for_ufcs_trait_methods_through_traits — `Foo::frob()`
// where `Foo` is a trait resolves to the trait method signature (line 1).
#[test]
fn ra_goto_def_for_ufcs_trait_methods_through_traits() {
    assert_resolves_to_line(
        "t.rs",
        "trait Foo {\n    fn frobnicate();\n}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
        1,
    );
}

// rust-analyzer: goto_def_for_ufcs_trait_methods_through_self — `Foo::frob()`
// where `Foo: Trait` resolves through the trait-candidate lookup (#433) to the
// trait method signature (line 2).
#[test]
fn ra_goto_def_for_ufcs_trait_methods_through_self() {
    assert_resolves_to_line(
        "ts.rs",
        "struct Foo;\ntrait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
        2,
    );
}

// #433: if multiple in-scope implemented traits declare the same associated
// method, `Foo::frobnicate()` is ambiguous and returns no definition.
#[test]
fn ra_goto_def_ufcs_trait_method_ambiguous_traits() {
    let (_t, lines) = definition_lines(
        "ambiguous.rs",
        "struct Foo;\ntrait A {\n    fn frobnicate();\n}\ntrait B {\n    fn frobnicate();\n}\nimpl A for Foo {}\nimpl B for Foo {}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
    );
    assert!(lines.is_empty(), "expected no definitions, got {lines:?}");
}

// #433: cross-file `Worker::frobnicate()` resolves through an imported trait
// implemented for `Worker`.
#[test]
fn ra_goto_def_ufcs_trait_method_cross_file() {
    let (_t, lines) = definition_lines_in_files(
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            ("src/lib.rs", "pub mod contracts;\npub mod worker;\n"),
            (
                "src/contracts.rs",
                "pub trait Runnable {\n    fn frobnicate();\n}\n",
            ),
            (
                "src/worker.rs",
                "use crate::contracts::Runnable;\npub struct Worker;\nimpl Runnable for Worker {}\nfn bar() {\n    Worker::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/worker.rs",
        "src/contracts.rs",
    );
    assert!(
        lines.contains(&1),
        "expected cross-file trait method to resolve to line 1, got {lines:?}"
    );
}

// #433: when two implemented traits declare the method, call-site scope filters
// candidates to the imported trait.
#[test]
fn ra_goto_def_ufcs_trait_method_scope_filtered() {
    let (_t, lines) = definition_lines_in_files(
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            ("src/lib.rs", "pub mod contracts;\npub mod worker;\n"),
            (
                "src/contracts.rs",
                "pub trait Runnable {\n    fn frobnicate();\n}\npub trait Hidden {\n    fn frobnicate();\n}\n",
            ),
            (
                "src/worker.rs",
                "use crate::contracts::Runnable;\npub struct Worker;\nimpl Runnable for Worker {}\nimpl crate::contracts::Hidden for Worker {}\nfn bar() {\n    Worker::frobnicate<caret>();\n}\n",
            ),
        ],
        "src/worker.rs",
        "src/contracts.rs",
    );
    assert!(
        lines.contains(&1),
        "expected scope-filtered trait method to resolve to line 1, got {lines:?}"
    );
}

// rust-analyzer: goto_definition_on_self — `Self {}` in an inherent impl resolves
// to the struct declaration (line 0).
#[test]
fn ra_goto_definition_on_self() {
    assert_resolves_to_line(
        "s.rs",
        "struct Foo;\nimpl Foo {\n    pub fn new() -> Self {\n        Self<caret> {}\n    }\n}\n",
        0,
    );
}

// Module-qualified associated-fn call: `foo::Foo::new()` from outside an inline
// `mod foo { .. }` should resolve to `new` (line 4).
//
// DEFERRED (resolver architecture). Making this work needs two things: (1) impl
// methods inside inline modules to be extracted — `visit_rust_module` never
// dispatches `impl_item`, so `mod foo { impl Foo { fn m } }` yields `foo.Foo` but
// not `foo.Foo.m`; and (2) scope-sensitive name resolution. (1) is a small fix,
// but it exposes (2): `RustReferenceContext.same_file` is keyed by short
// `identifier()`, so same-named declarations in sibling inline modules collide
// nondeterministically in the HashMap, and `collect_factory_return_types` keys
// module-level factories via `resolve_bare` — together yielding nondeterministic
// and spurious cross-module edges in the inverted usage graph (verified: it
// flakes `usage_graph_rust_test::factory_receiver_uses_resolved_callable_...`).
// The real fix is a position/scope-aware `resolve_bare`, which ripples through
// every Rust resolution caller — its own ExecPlan, not a burndown bolt-on.
#[test]
#[ignore = "deferred: needs scope-sensitive Rust name resolution (see suite comment)"]
fn ra_goto_def_module_qualified_assoc_fn() {
    assert_resolves_to_line(
        "p.rs",
        "mod foo {\n    pub struct Foo;\n\n    impl Foo {\n        pub fn new() -> Foo { Foo }\n    }\n}\n\nfn main() {\n    let _f = foo::Foo::new<caret>();\n}\n",
        4,
    );
}

// #431 (scope-aware resolution): a bare `Config` inside `mod b` resolves to
// `b::Config` (line 4), not the same-named `a::Config` (line 1). Previously the
// flat same-file name map picked one nondeterministically; now the shared
// enclosing-scope resolver (generalized from Java) resolves by position.
#[test]
fn ra_goto_def_bare_type_in_enclosing_module() {
    assert_resolves_to_line(
        "lib.rs",
        "mod a {\n    pub struct Config;\n}\nmod b {\n    pub struct Config;\n    pub struct User {\n        c: Config<caret>,\n    }\n}\n",
        4,
    );
}
