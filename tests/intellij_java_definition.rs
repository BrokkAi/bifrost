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
// type `ABC` to `public int i = 0;` (line 2). bifrost infers the call receiver's
// type from the resolved method's declared return type.
#[test]
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

// IntelliJ method/Simple: `a.method("blah")` where `a` is a `Simple` resolves to
// `method(String)` (line 1).
#[test]
fn method_call_on_typed_local() {
    assert_resolves_to_line(
        "Simple.java",
        "public class Simple {\n    public void method(String s) {\n    }\n\n    static {\n        Simple a = new Simple();\n        a.<caret>method(\"blah\");\n    }\n}\n",
        1,
    );
}

// IntelliJ method/Super1: `super.askdh()` in `Super1 extends A` resolves to
// `A.askdh` (line 1).
#[test]
fn super_method_call_resolves_to_superclass() {
    assert_resolves_to_line(
        "Super1.java",
        "class A{\n public void askdh(){\n }\n}\n\nclass Super1 extends A{\n {\n  super.<caret>askdh();\n }\n}\n",
        1,
    );
}

// IntelliJ method/Inherit1: `super.askdh()` in `Super1 extends B` (B extends A,
// B overrides askdh) resolves to the nearest override `B.askdh` (line 7).
#[test]
fn super_method_call_resolves_to_nearest_override() {
    assert_resolves_to_line(
        "Inherit1.java",
        "class A{\n public int askdh(){\n  return 1;\n }\n}\n\nclass B extends A{\n public void askdh(){\n  return 2;\n }\n}\n\nclass Super1 extends B{\n {\n  super.<caret>askdh();\n }\n}\n",
        7,
    );
}

// IntelliJ class/ClassExtendsItsInner1: `class A extends B.Foo` resolves the
// qualified nested class `B.Foo` (the `static class Foo`, line 4).
#[test]
fn qualified_nested_class_reference() {
    assert_resolves_to_line(
        "ClassExtendsItsInner1.java",
        "class A extends B.<caret>Foo implements B{\n}\n\ninterface B{\n  static class Foo{\n  }\n}\n",
        4,
    );
}

// IntelliJ var/InheritedOuter: a bare `string` reference inside `Inner extends
// Outer` resolves to the outer class field `Outer.string` (line 1). bifrost
// resolves qualified field access (`this.f`, `x.f`) but not a bare, unqualified
// field name that binds to an enclosing/inherited class field.
#[test]
fn bare_inherited_outer_field() {
    assert_resolves_to_line(
        "InheritedOuter.java",
        "class Outer {\n  private String string;\n\n  class Inner extends Outer {\n    void test() {\n      System.out.println(<caret>string);\n    }\n  }\n}\n",
        1,
    );
}

// ---------------------------------------------------------------------------
// Deepening: more Java resolution shapes
// ---------------------------------------------------------------------------

// A static method call `Util.help()` resolves to the static method (line 1).
#[test]
fn static_method_call() {
    assert_resolves_to_line(
        "StaticCall.java",
        "class Util {\n  static void help() {}\n}\n\nclass Caller {\n  void run() {\n    Util.<caret>help();\n  }\n}\n",
        1,
    );
}

// An enum constant reference `Color.RED` resolves to the constant (line 1).
#[test]
fn enum_constant_reference() {
    assert_resolves_to_line(
        "EnumConst.java",
        "enum Color {\n  RED, GREEN\n}\n\nclass User {\n  Color c = Color.<caret>RED;\n}\n",
        1,
    );
}

// A `this.field` access resolves to the field declaration (line 1).
#[test]
fn this_field_access() {
    assert_resolves_to_line(
        "ThisField.java",
        "class Box {\n  int value;\n  int read() {\n    return this.<caret>value;\n  }\n}\n",
        1,
    );
}

// A method called on a concrete implementor resolves to the implementation
// (`Impl.go`, line 5), not the interface declaration.
#[test]
fn interface_method_on_implementor() {
    assert_resolves_to_line(
        "InterfaceMethod.java",
        "interface Runnable2 {\n  void go();\n}\n\nclass Impl implements Runnable2 {\n  public void go() {}\n  void call(Impl i) {\n    i.<caret>go();\n  }\n}\n",
        5,
    );
}

// `new Foo()` resolves the type `Foo` to its class declaration (line 0).
#[test]
fn constructor_new_type() {
    assert_resolves_to_line(
        "NewType.java",
        "class Foo {}\n\nclass Maker {\n  Foo make() {\n    return new <caret>Foo();\n  }\n}\n",
        0,
    );
}
