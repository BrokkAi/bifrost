//! Cross-language go-to-definition for a *call/construction receiver*
//! (`new Foo().bar()` etc.) — the pattern generalized from the Java/Python
//! IntelliJ-parity work (see `.agent/PARITY_CROSS_LANGUAGE_GENERALIZATION.md`,
//! pattern 1). Each case places the caret on a member accessed on a freshly
//! constructed object and asserts it resolves to the member declaration.

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

// C#: `new Foo().X` resolves `X` through the construction receiver (line 1).
#[test]
fn csharp_construction_receiver() {
    assert_resolves_to_line(
        "R.cs",
        "class Foo {\n    public int X = 0;\n}\n\nclass M {\n    void run() {\n        int y = new Foo().<caret>X;\n    }\n}\n",
        1,
    );
}

// PHP: `(new Foo())->x` resolves `x` through the construction receiver (line 2).
#[test]
fn php_construction_receiver() {
    assert_resolves_to_line(
        "R.php",
        "<?php\nclass Foo {\n    public $x = 0;\n}\nfunction run() {\n    return (new Foo())-><caret>x;\n}\n",
        2,
    );
}

// Ruby: `Foo.new.bar` resolves `bar` through the construction receiver (line 1).
#[test]
fn ruby_construction_receiver() {
    assert_resolves_to_line(
        "r.rb",
        "class Foo\n  def bar\n  end\nend\n\nFoo.new.<caret>bar\n",
        1,
    );
}

// JavaScript: `new Foo().bar()` resolves `bar` (line 1).
#[test]
#[ignore = "pattern 1 gap: js_ts get_definition is text-based (split on '.'); inline construction receiver not typed"]
fn javascript_construction_receiver() {
    assert_resolves_to_line(
        "r.js",
        "class Foo {\n  bar() {}\n}\n\nnew Foo().<caret>bar();\n",
        1,
    );
}

// TypeScript: `new Foo().bar()` resolves `bar` (line 1).
#[test]
#[ignore = "pattern 1 gap: js_ts get_definition is text-based (split on '.'); inline construction receiver not typed"]
fn typescript_construction_receiver() {
    assert_resolves_to_line(
        "r.ts",
        "class Foo {\n  bar() {}\n}\n\nnew Foo().<caret>bar();\n",
        1,
    );
}

// C++: `Foo().bar()` resolves `bar` (line 1).
#[test]
fn cpp_construction_receiver() {
    assert_resolves_to_line(
        "r.cpp",
        "struct Foo {\n  void bar() {}\n};\n\nvoid run() {\n  Foo().<caret>bar();\n}\n",
        1,
    );
}

// Scala: `new Foo().bar` resolves `bar` (line 1).
#[test]
fn scala_construction_receiver() {
    assert_resolves_to_line(
        "R.scala",
        "class Foo {\n  def bar(): Unit = {}\n}\n\nobject M {\n  def run(): Unit = { new Foo().<caret>bar() }\n}\n",
        1,
    );
}
