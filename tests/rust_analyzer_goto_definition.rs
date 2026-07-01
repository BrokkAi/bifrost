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
// where `Foo: Trait` resolves to the trait method signature (line 2).
//
// DEFERRED: bifrost's name-based `resolve_scoped` maps `Foo` -> its fqn and looks
// up `Foo.frobnicate`, which is not indexed because the method is declared only
// on `Trait`. Resolving it needs a type->implemented-traits linkage (only the
// inverse `trait_implementer_names` exists today) plus an ambiguity policy when
// several implemented traits share the name. Tracked for a dedicated resolver
// change; not a wiring fix.
#[test]
#[ignore = "deferred: assoc-fn call through an implemented trait needs type->trait linkage in the resolver"]
fn ra_goto_def_for_ufcs_trait_methods_through_self() {
    assert_resolves_to_line(
        "ts.rs",
        "struct Foo;\ntrait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n\nfn bar() {\n    Foo::frobnicate<caret>();\n}\n",
        2,
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
