//! Java find-usages corner cases driven through the LSP server's
//! `textDocument/references`. IntelliJ's Java find-usages suite
//! (`java/java-tests/.../psi/search/findUsages`) is mostly PSI-API driven
//! (overload/override search, decompiled libraries, XML, javadoc), so these are
//! authored in the same spirit but as clean caret-based in-envelope cases
//! (class / method / field targets), mirroring the Python port's conventions.
//!
//! `includeDeclaration = false`, so the declaration site is excluded.

mod common;

use common::lsp_client::{LspServer, uri_for};
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

/// Write a single Java file (with inline `<caret>`), run find-usages at the
/// caret, and return the resolved reference lines (0-based) in this file.
fn reference_lines(name: &str, source_with_caret: &str) -> (TempDir, Vec<u64>) {
    let (source, line, character) = split_caret(source_with_caret);
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file: PathBuf = root.join(name);
    std::fs::write(&file, source).expect("write fixture");

    let mut server = LspServer::start(&root);
    let locations = server.references(&file, line, character, false);
    server.shutdown();

    let file_uri = uri_for(&file);
    let mut lines: Vec<u64> = locations
        .iter()
        .filter(|loc| loc.uri == file_uri)
        .map(|loc| loc.line)
        .collect();
    lines.sort_unstable();
    (temp, lines)
}

fn assert_reference_lines(name: &str, source_with_caret: &str, expected: &[u64]) {
    let (_temp, lines) = reference_lines(name, source_with_caret);
    assert_eq!(lines, expected, "reference lines in {name} mismatch");
}

// Class usage: caret on the class declaration; the `new Foo()` construction is
// the single usage.
#[test]
fn class_usages() {
    assert_reference_lines(
        "ClassUsages.java",
        "class <caret>Foo {}\n\nclass User {\n  Foo make() {\n    return new Foo();\n  }\n}\n",
        // `Foo` appears as the return type (line 3) and the constructor (line 4).
        &[3, 4],
    );
}

// Method usage: caret on the method declaration; the same-class call is a usage.
#[test]
fn method_usages() {
    assert_reference_lines(
        "MethodUsages.java",
        "class Foo {\n  void <caret>target() {}\n  void caller() {\n    this.target();\n  }\n}\n",
        &[3],
    );
}

// Field usage: caret on the field declaration; the read in a method is a usage.
#[test]
fn field_usages() {
    assert_reference_lines(
        "FieldUsages.java",
        "class Foo {\n  int <caret>count;\n  int read() {\n    return this.count;\n  }\n}\n",
        &[3],
    );
}

// Inherited method usage: a subclass calls an inherited method via `this`.
#[test]
fn inherited_method_usage() {
    assert_reference_lines(
        "InheritedMethodUsage.java",
        "class Base {\n  void <caret>run() {}\n}\n\nclass Derived extends Base {\n  void go() {\n    this.run();\n  }\n}\n",
        &[6],
    );
}

// Cross-class method usage: a method called on an instance of another class,
// via a typed local receiver.
#[test]
fn cross_class_method_usage() {
    assert_reference_lines(
        "CrossClassMethod.java",
        "class Service {\n  void <caret>handle() {}\n}\n\nclass Caller {\n  void run() {\n    Service s = new Service();\n    s.handle();\n  }\n}\n",
        &[7],
    );
}

// Static field usage: a static field read from another class via the class name.
#[test]
fn static_field_usage() {
    assert_reference_lines(
        "StaticFieldUsage.java",
        "class Config {\n  static int <caret>LIMIT = 10;\n}\n\nclass User {\n  int read() {\n    return Config.LIMIT;\n  }\n}\n",
        &[6],
    );
}

// Constructor / class usage across classes: `new Widget()` and a `Widget` type
// reference from another class.
#[test]
fn cross_class_construction_usage() {
    assert_reference_lines(
        "CrossClassCtor.java",
        "class <caret>Widget {}\n\nclass Factory {\n  Widget make() {\n    return new Widget();\n  }\n}\n",
        &[3, 4],
    );
}

// ---------------------------------------------------------------------------
// Deepening: more Java find-usages shapes
// ---------------------------------------------------------------------------

// Static method usages across classes (two call sites).
#[test]
fn static_method_usages() {
    assert_reference_lines(
        "StaticMethodUsages.java",
        "class Util {\n  static void <caret>help() {}\n}\n\nclass A {\n  void run() {\n    Util.help();\n    Util.help();\n  }\n}\n",
        &[6, 7],
    );
}

// Enum constant usages.
#[test]
fn enum_constant_usages() {
    assert_reference_lines(
        "EnumConstantUsages.java",
        "enum Color {\n  <caret>RED, GREEN\n}\n\nclass User {\n  Color a = Color.RED;\n  Color b = Color.RED;\n}\n",
        &[5, 6],
    );
}

// Field read and write are both usages.
#[test]
fn field_read_and_write_usages() {
    assert_reference_lines(
        "FieldReadWrite.java",
        "class Box {\n  int <caret>value;\n  void set(int v) {\n    this.value = v;\n  }\n  int get() {\n    return this.value;\n  }\n}\n",
        &[3, 6],
    );
}

// Static field usages across classes via the class name.
#[test]
fn static_field_cross_class_usages() {
    assert_reference_lines(
        "StaticFieldCross.java",
        "class Config {\n  static int <caret>MAX = 5;\n}\n\nclass A {\n  int a() { return Config.MAX; }\n}\n\nclass B {\n  int b() { return Config.MAX; }\n}\n",
        &[5, 9],
    );
}
