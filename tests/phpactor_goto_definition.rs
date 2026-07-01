//! Go-to-definition corner cases borrowed from phpactor's
//! `WorseReflectionDefinitionLocatorTest` (`<>` cursor + inline PHP). Each case
//! cites the upstream test it was ported from.
//!
//! Scope: bifrost's CodeUnit envelope (class/interface, methods, properties,
//! static members). phpactor cases targeting locals, stdlib, or plain-text
//! fallbacks are out of bifrost's model and not ported.
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

// phpactor testLocatesToMethod: `$foo->bar()` on a `new Foobar()` receiver
// resolves to the method (line 2).
#[test]
fn phpactor_def_method_on_new_receiver() {
    assert_resolves_to_line(
        "a.php",
        "<?php\nclass Foobar {\n    public function bar() {}\n}\n$foo = new Foobar();\n$foo->bar<caret>();\n",
        2,
    );
}

// phpactor testLocatesProperty: property access resolves to the property (line 2).
#[test]
fn phpactor_def_property() {
    assert_resolves_to_line(
        "a.php",
        "<?php\nclass Foobar {\n    public $prop = 1;\n}\n$foo = new Foobar();\necho $foo->prop<caret>;\n",
        2,
    );
}

// phpactor testLocatesToStaticMethod...: `Foobar::bar()` resolves to the static
// method (line 2).
#[test]
fn phpactor_def_static_method() {
    assert_resolves_to_line(
        "a.php",
        "<?php\nclass Foobar {\n    public static function bar() {}\n}\nFoobar::bar<caret>();\n",
        2,
    );
}

// phpactor testLocatesMethodDeclarationInParentClass: an inherited method call on
// a subclass instance resolves to the parent's method (line 2).
#[test]
fn phpactor_def_inherited_method() {
    assert_resolves_to_line(
        "a.php",
        "<?php\nclass Base {\n    public function bar() {}\n}\nclass Derived extends Base {}\n$d = new Derived();\n$d->bar<caret>();\n",
        2,
    );
}

// phpactor testLocatesMethodInInterface: a method call on an interface-typed
// parameter resolves to the interface method (line 2).
#[test]
fn phpactor_def_interface_method() {
    assert_resolves_to_line(
        "a.php",
        "<?php\ninterface I {\n    public function m();\n}\nfunction run(I $x) {\n    $x->m<caret>();\n}\n",
        2,
    );
}

// phpactor testLocatesNullableMethod: a method call on a nullable-typed parameter
// (`?Foobar`) resolves to the method (line 2).
#[test]
fn phpactor_def_nullable_method() {
    assert_resolves_to_line(
        "a.php",
        "<?php\nclass Foobar {\n    public function bar() {}\n}\nfunction run(?Foobar $foo) {\n    $foo->bar<caret>();\n}\n",
        2,
    );
}
