//! Go-to-definition corner cases borrowed from clangd's own `XRefsTests.cpp`
//! (`LocateSymbol` table), whose `^` cursor + `[[...]]` range markers pin a
//! cursor to its expected definition. Each case cites the upstream shape.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (namespace/struct/class
//! types, methods, fields, typedefs). clangd cases targeting locals, macros,
//! offsetof builtins, ObjC, or templates are out of bifrost's model and not
//! ported.
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

// clangd LocateSymbol.All "Struct" in a namespace: `ns1::MyClass` resolves to the
// struct declaration inside the namespace (line 1).
#[test]
fn clangd_def_namespace_qualified_struct() {
    assert_resolves_to_line(
        "a.cpp",
        "namespace ns1 {\nstruct MyClass {};\n}\nint main() {\n    ns1::My<caret>Class* Params;\n}\n",
        1,
    );
}

// clangd LocateSymbol.All "Field": `bar.x` resolves to the field declaration.
#[test]
fn clangd_def_field() {
    assert_resolves_to_line(
        "a.cpp",
        "struct Foo { int x; };\nint main() {\n    Foo bar;\n    (void)bar.<caret>x;\n}\n",
        0,
    );
}

// clangd LocateSymbol.All "Method call": `bar.x()` resolves to the method decl.
#[test]
fn clangd_def_method_call() {
    assert_resolves_to_line(
        "a.cpp",
        "struct Foo { int x(); };\nint main() {\n    Foo bar;\n    bar.<caret>x();\n}\n",
        0,
    );
}

// bifrost probe for #429: an explicit-template free-function call should resolve
// from the template_function's name field, not treat that name as a declaration.
#[test]
fn clangd_def_explicit_template_function_call() {
    assert_resolves_to_line(
        "a.cpp",
        "namespace parity {\ntemplate <typename T>\nT choose(T a, T b) { return a; }\n}\nint main() {\n    auto x = parity::cho<caret>ose<int>(1, 2);\n}\n",
        2,
    );
}

#[test]
fn clangd_def_unqualified_explicit_template_function_call_inside_namespace() {
    assert_resolves_to_line(
        "a.cpp",
        "namespace parity {\ntemplate <typename T>\nT choose(T a, T b) { return a; }\nint use() {\n    return cho<caret>ose<int>(1, 2);\n}\n}\n",
        2,
    );
}

// clangd LocateSymbol.All "Typedef": `Foo bar;` resolves to the typedef decl.
#[test]
fn clangd_def_typedef() {
    assert_resolves_to_line(
        "a.cpp",
        "typedef int Foo;\nint main() {\n    <caret>Foo bar;\n}\n",
        0,
    );
}

// bifrost probe (NOT a borrowed clangd case): tests whether the #431 same-scope
// collapse reproduces in C++. A qualified `b::Config` must resolve to `b`'s
// struct (line 5), never `a`'s same-named struct (line 1).
#[test]
fn clangd_probe_namespace_collision_qualified() {
    let src = "namespace a {\nstruct Config {};\n}\nnamespace b {\n\nstruct Config {};\n}\nint main() {\n    b::Con<caret>fig* p;\n}\n";
    assert_resolves_to_line("a.cpp", src, 5);
    assert_does_not_resolve_to_line("a.cpp", src, 1);
}

// bifrost probe (NOT a borrowed clangd case): the sharper #431 analog — a *bare*
// `Config` used inside namespace `b` (the parameter type on line 5) must resolve
// to b's `Config` (line 4), not a's same-named struct (line 1).
//
// Fixed via the shared enclosing-scope resolver (#431): resolution now uses the
// reference's position, so the bare `Config` inside namespace `b` resolves to b's
// struct. Previously bifrost's C++ visibility index was scope-blind and picked one
// of the same-named namespaces arbitrarily. The qualified `b::Config` case above
// already worked; this was the bare-in-scope collapse.
#[test]
fn clangd_probe_namespace_collision_bare_inside_scope() {
    let src = "namespace a {\nstruct Config {};\n}\nnamespace b {\nstruct Config {};\nvoid use(Con<caret>fig* p) {}\n}\n";
    assert_resolves_to_line("a.cpp", src, 4);
    assert_does_not_resolve_to_line("a.cpp", src, 1);
}
