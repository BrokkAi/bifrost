//! Go-to-definition corner cases borrowed from Metals' presentation-compiler
//! `PcDefinitionSuite` (`@@` cursor + `<<..>>` expected range). Metals' own cases
//! lean on the Scala stdlib (`List`, `Predef`), which bifrost is project-scoped
//! and does not index; the *shapes* (case-class apply, named-arg -> param,
//! object/method/field member resolution) are ported with workspace-local types.
//!
//! Scope: bifrost's CodeUnit envelope (class/object/trait, methods, fields, case
//! classes). Metals cases targeting locals, for-comprehensions, or stdlib symbols
//! are out of bifrost's model and not ported.
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

// Method call on a `val` receiver resolves to the method declaration (line 1).
#[test]
fn metals_def_method_on_val_receiver() {
    assert_resolves_to_line(
        "a.scala",
        "class Foo {\n  def bar(): Int = 1\n}\nobject Main {\n  val f = new Foo\n  val x = f.bar<caret>()\n}\n",
        1,
    );
}

// Field access on a `val` receiver resolves to the field declaration (line 1).
#[test]
fn metals_def_field_on_val_receiver() {
    assert_resolves_to_line(
        "a.scala",
        "class Foo {\n  val value: Int = 1\n}\nobject Main {\n  val f = new Foo\n  val x = f.value<caret>\n}\n",
        1,
    );
}

// Object member call: `Api.run()` resolves to the method in the object (line 1).
#[test]
fn metals_def_object_member() {
    assert_resolves_to_line(
        "a.scala",
        "object Api {\n  def run(): Int = 1\n}\nobject Main {\n  val x = Api.run<caret>()\n}\n",
        1,
    );
}

// Metals PcDefinitionSuite "case-class-apply" (shape): `Foo(..)` resolves to the
// case class declaration (line 0).
#[test]
fn metals_def_case_class_apply() {
    assert_resolves_to_line(
        "a.scala",
        "case class Foo(a: Int, b: String)\nobject Main {\n  val f = Foo<caret>(3, \"x\")\n}\n",
        0,
    );
}

// Metals PcDefinitionSuite "case-class-apply": a named argument `a` resolves to
// the case class parameter `a` (line 0). A named-argument identifier is the LHS of
// an assignment inside a call's `arguments`; `scala_reference_node` now routes it
// to the callee type's member lookup (case-class params are members `Foo.a`).
#[test]
fn metals_def_case_class_named_arg() {
    assert_resolves_to_line(
        "a.scala",
        "case class Foo(a: Int, b: String)\nobject Main {\n  val f = Foo(<caret>a = 3, b = \"x\")\n}\n",
        0,
    );
}
