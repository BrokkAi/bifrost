//! Go-to-definition cases for Java, informed by Eclipse JDT LS'
//! `NavigateToDefinitionHandlerTest` shapes (workspace-local types, since bifrost
//! is project-scoped and does not index the JDK). Java is bifrost's parity
//! reference, so the standard receiver/member cases are confirmations; the
//! namespace/nested-scope case is a bifrost-added #431 probe — Java being the most
//! mature analyzer, whether it resolves scope correctly tells us if a correct
//! model already exists to follow.
//!
//! Driven through the real LSP server (`textDocument/definition`).

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

fn assert_does_not_resolve_to_line(name: &str, source_with_caret: &str, forbidden: u64) {
    let (_t, lines) = definition_lines(name, source_with_caret);
    assert!(
        !lines.contains(&forbidden),
        "expected {name} NOT to resolve to line {forbidden}, got {lines:?}"
    );
}

// Method call on a `new` receiver resolves to the method (line 1).
#[test]
fn jdt_def_method_on_new_receiver() {
    assert_resolves_to_line(
        "A.java",
        "class Foo {\n    int bar() { return 1; }\n}\nclass Program {\n    void run() {\n        Foo f = new Foo();\n        f.bar<caret>();\n    }\n}\n",
        1,
    );
}

// Inherited method call on a subclass instance resolves to the base method (line 1).
#[test]
fn jdt_def_inherited_method() {
    assert_resolves_to_line(
        "A.java",
        "class Base {\n    int bar() { return 1; }\n}\nclass Derived extends Base {}\nclass Program {\n    void run() {\n        Derived d = new Derived();\n        d.bar<caret>();\n    }\n}\n",
        1,
    );
}

// bifrost probe (NOT a borrowed case): does the #431 scope-blind collapse reproduce
// in Java's nested-type scoping? A *bare* `Config` used inside class `B` must
// resolve to `B.Config` (line 7), not `A`'s same-named nested type (line 1). Java
// is bifrost's most mature analyzer — if it resolves this correctly, its resolver
// is the scope-aware model #431 should follow.
#[test]
fn jdt_probe_nested_type_collision_bare_inside_scope() {
    let src = "class A {\n    static class Config {}\n    static class UserA {\n        Config a;\n    }\n}\nclass B {\n    static class Config {}\n    static class UserB {\n        Config<caret> b;\n    }\n}\n";
    assert_resolves_to_line("A.java", src, 7);
    assert_does_not_resolve_to_line("A.java", src, 1);
}
