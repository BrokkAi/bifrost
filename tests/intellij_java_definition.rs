//! Java go-to-definition corner cases ported from IntelliJ Community's
//! `psi/resolve` suite (`java/java-tests/testData/psi/resolve/`, with the Java
//! assertions in `ResolveVariableTest` / `ResolveMethodTest` / `ResolveClass2Test`).
//!
//! IntelliJ's resolve tests are caret-based; the faithful bifrost surface is the
//! LSP server's `textDocument/definition`. Each test embeds the IntelliJ fixture
//! (with the original `<caret>` preserved inline), strips the caret, writes the
//! file into a temp project, and drives the real server.
//!
//! Envelope: bifrost resolves the cursor to a `CodeUnit` (class / method /
//! field). IntelliJ resolve cases that target a local variable or parameter are
//! out of scope by architecture and are not ported.

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

/// Write a single Java file (with inline `<caret>`), drive
/// `textDocument/definition` at the caret, and return the resolved target lines
/// (0-based) in this file.
fn definition_target_lines(name: &str, source_with_caret: &str) -> (TempDir, Vec<u64>) {
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

fn assert_resolves_to_line(name: &str, source_with_caret: &str, expected_line: u64) {
    let (_temp, lines) = definition_target_lines(name, source_with_caret);
    assert!(
        lines.contains(&expected_line),
        "expected a definition at line {expected_line} in {name}, got {lines:?}"
    );
}

// IntelliJ testFieldFromInterface: `A.FIELD` where `A implements I` and `FIELD`
// is declared in `I`. Resolves to the interface field (line 8).
#[test]
fn field_from_interface() {
    assert_resolves_to_line(
        "FieldFromInterface.java",
        "class Client {\n  int foo(){\n    return A.<caret>FIELD;\n  }\n}\n\nclass A implements I{\n}\n\ninterface I {\n  public static final int FIELD = 1;\n}\n",
        10,
    );
}

// IntelliJ testQualified1: `test.a` where `test` is a `Test` and `Test` has
// field `a`. Resolves to `int a = 0;` (line 1).
#[test]
fn qualified_field_access() {
    assert_resolves_to_line(
        "Qualified1.java",
        "public class Test{\n  int a = 0;\n}\n\nclass Test1 {\n  static Test test = new Test();\n  static {\n    System.out.println(\"\" + test.<caret>a);\n  }\n}\n",
        1,
    );
}

// IntelliJ testVisibility3: `getABC().i` resolves `i` through the method return
// type `ABC` to `public int i = 0;` (line 2). bifrost resolves a member on a
// typed *variable* (see `qualified_field_access`) but does not infer the return
// type of a *method call* receiver, so `getABC().i` does not resolve.
#[test]
#[ignore = "bifrost gap: member access on a method-call result is not resolved (no return-type inference for the call receiver)"]
fn member_through_method_return_type() {
    assert_resolves_to_line(
        "Visibility3.java",
        "class Test {\n  static class ABC{\n    public int i = 0;\n  }\n  static {\n    System.out.println(\"\" + getABC().<caret>i);\n  }\n\n  static ABC getABC(){\n    return new ABC();\n  }\n}\n",
        2,
    );
}

// Baseline: a method call resolves to the method declaration.
#[test]
fn method_call_resolves_to_declaration() {
    assert_resolves_to_line(
        "MethodCall.java",
        "class Test {\n  void target() {}\n  void caller() {\n    this.<caret>target();\n  }\n}\n",
        1,
    );
}

// Baseline: a qualified type reference resolves to the class declaration.
#[test]
fn type_reference_resolves_to_class() {
    assert_resolves_to_line(
        "TypeRef.java",
        "class Holder {}\n\nclass User {\n  <caret>Holder h;\n}\n",
        0,
    );
}
