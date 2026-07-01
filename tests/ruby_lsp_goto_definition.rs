//! Go-to-definition corner cases borrowed from Ruby LSP's own
//! `test/requests/definition_expectations_test.rb`, which drives
//! `textDocument/definition` at explicit positions over inline sources. Each case
//! cites the upstream test it was ported from.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (classes/modules,
//! methods, constants). Ruby LSP cases targeting default gems, require paths, or
//! Sorbet/RBS addons are out of bifrost's model and not ported.
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

// Ruby LSP test_jumping_to_method_definitions_when_declaration_exists: an
// implicit-self call `foo` inside `bar` resolves to `def foo` (line 6).
#[test]
fn ruby_def_implicit_self_method() {
    assert_resolves_to_line(
        "a.rb",
        "class A\n  def bar\n    <caret>foo\n  end\n\n  def foo; end\nend\n",
        5,
    );
}

// Ruby LSP test_constant_precision: each segment of `Foo::Bar::Baz` resolves to
// the correct nested declaration. Caret on `Foo` -> module Foo (line 0).
#[test]
fn ruby_def_constant_path_segment_foo() {
    assert_resolves_to_line(
        "a.rb",
        "module Foo\n  module Bar\n    class Baz\n    end\n  end\nend\n\n<caret>Foo::Bar::Baz\n",
        0,
    );
}

// Ruby LSP test_constant_precision: caret on `Bar` -> module Foo::Bar (line 1).
#[test]
fn ruby_def_constant_path_segment_bar() {
    assert_resolves_to_line(
        "a.rb",
        "module Foo\n  module Bar\n    class Baz\n    end\n  end\nend\n\nFoo::<caret>Bar::Baz\n",
        1,
    );
}

// Ruby LSP test_constant_precision: caret on `Baz` -> class Foo::Bar::Baz (line 2).
#[test]
fn ruby_def_constant_path_segment_baz() {
    assert_resolves_to_line(
        "a.rb",
        "module Foo\n  module Bar\n    class Baz\n    end\n  end\nend\n\nFoo::Bar::<caret>Baz\n",
        2,
    );
}
