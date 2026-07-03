//! Cross-language go-to-definition through a *method-call return type*
//! (`getFoo().member`) — the deeper half of pattern 1 in
//! `.agents/docs/PARITY_CROSS_LANGUAGE_GENERALIZATION.md`. The construction leg
//! (`new Foo().member`) is covered by `cross_language_receiver_definition.rs`;
//! here the receiver is typed by the *declared/inferred return type* of the
//! called method.

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

// C#: `GetFoo().X` types the receiver by `GetFoo`'s declared return type `Foo`,
// resolving `X` to its declaration (line 1).
#[test]
fn csharp_return_type_receiver() {
    assert_resolves_to_line(
        "R.cs",
        "class Foo {\n    public int X = 0;\n}\n\nclass M {\n    Foo GetFoo() { return new Foo(); }\n    void run() {\n        int y = GetFoo().<caret>X;\n    }\n}\n",
        1,
    );
}

// C#: qualified `this.GetFoo().X` — the callee is resolved via a member-access
// receiver typed as the enclosing class.
#[test]
fn csharp_return_type_qualified_receiver() {
    assert_resolves_to_line(
        "R.cs",
        "class Foo {\n    public int X = 0;\n}\n\nclass M {\n    Foo GetFoo() { return new Foo(); }\n    void run() {\n        int y = this.GetFoo().<caret>X;\n    }\n}\n",
        1,
    );
}

// Ruby: a bare implicit-`self` call used as a receiver (`get_foo.v`) is typed by
// `get_foo`'s inferred return instance (`Foo.new`), resolving `v` to line 1.
#[test]
fn ruby_return_type_receiver() {
    assert_resolves_to_line(
        "r.rb",
        "class Foo\n  def v\n  end\nend\n\nclass Bar\n  def get_foo\n    Foo.new\n  end\n\n  def use\n    get_foo.<caret>v\n  end\nend\n",
        1,
    );
}
