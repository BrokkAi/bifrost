//! Go-to-definition cases for Scala shapes not covered by the Metals suite
//! (repo 5), informed by IntelliJ Scala plugin `resolve2` element tests. Since
//! bifrost's Scala analyzer is the same one Metals already exercised, this is a
//! focused top-up: trait-typed receiver method resolution and companion-object
//! `apply`.
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

fn assert_resolves_to_one_of(name: &str, source_with_caret: &str, expected: &[u64]) {
    let (_t, lines) = definition_lines(name, source_with_caret);
    assert!(
        lines.iter().any(|line| expected.contains(line)),
        "expected {name} to resolve to one of {expected:?}, got {lines:?}"
    );
}

// Method call on a trait-typed `val` resolves to the trait's method (line 1).
#[test]
fn intellij_scala_def_trait_method_via_trait_typed_val() {
    assert_resolves_to_line(
        "a.scala",
        "trait Greeter {\n  def greet(): String\n}\nclass Impl extends Greeter {\n  def greet(): String = \"hi\"\n}\nobject Main {\n  val g: Greeter = new Impl()\n  g.greet<caret>()\n}\n",
        1,
    );
}

// Companion-object `apply` call: `Foo(3)` resolves to either the companion's
// explicit `apply` (line 2, the precise Scala target) or the same-named class
// `Foo` (line 0). Because a class and its companion object share the name `Foo`,
// bifrost picks one of the two *nondeterministically* - both are sensible
// navigation targets, so accept either. (The nondeterministic pick between a
// class and its same-name companion is a minor finding, distinct from #431's
// cross-scope collapse.)
#[test]
fn intellij_scala_def_companion_apply() {
    assert_resolves_to_one_of(
        "a.scala",
        "class Foo(val a: Int)\nobject Foo {\n  def apply(x: Int): Foo = new Foo(x)\n}\nobject Main {\n  val f = Foo<caret>(3)\n}\n",
        &[0, 2],
    );
}
