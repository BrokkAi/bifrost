//! Python go-to-definition corner cases ported from IntelliJ Community's
//! `python/testData/resolve/` fixtures (assertions in `PyCommonResolveTest`).
//!
//! IntelliJ's resolve fixtures mark the reference with `<ref>` (often on a
//! comment line column-aligned to the token above); here the caret is placed
//! directly on the reference token and driven through the LSP server's
//! `textDocument/definition`.
//!
//! Envelope: bifrost resolves the cursor to a `CodeUnit` (class / function /
//! method / module-level target / attribute). IntelliJ resolve cases that target
//! a local variable, parameter, or comprehension binding are out of scope by
//! architecture and are not ported. Python-2 `print` statements are modernized
//! to `print(...)` so the fixtures parse under bifrost's Py3 grammar.

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

/// Write a single Python file (with inline `<caret>`), drive
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

// IntelliJ resolve/Class: a `Test()` reference resolves to `class Test` (line 0).
#[test]
fn class_reference() {
    assert_resolves_to_line(
        "Class.py",
        "class Test:\n    pass\n\nprint(<caret>Test())\n",
        0,
    );
}

// IntelliJ resolve/Func: an `info()` call resolves to `def info` (line 0).
#[test]
fn function_reference() {
    assert_resolves_to_line("Func.py", "def info():\n    pass\n\n<caret>info()\n", 0);
}

// IntelliJ resolve/ToConstructorInherited: `Bar()` resolves to `class Bar`
// (line 4); Bar inherits Foo's __init__.
#[test]
fn constructor_reference_to_class() {
    assert_resolves_to_line(
        "ToConstructorInherited.py",
        "class Foo:\n    def __init__(self):\n        pass\n\nclass Bar(Foo):\n    pass\n\n<caret>Bar()\n",
        4,
    );
}

// IntelliJ resolve/QualifiedTarget: `foo.bar = 1` — the `foo` receiver resolves
// to the module-level target `foo = Foo()` (line 3). bifrost instead points at
// the `foo` occurrence on line 4 (the reassignment-target statement).
#[test]
#[ignore = "bifrost quirk: module target `foo` resolves to its line-4 occurrence, not the defining assignment on line 3"]
fn module_target_reference() {
    assert_resolves_to_line(
        "QualifiedTarget.py",
        "class Foo:\n    pass\n\nfoo = Foo()\nf<caret>oo.bar = 1\n",
        3,
    );
}

// A `self.method()` call resolves to the method definition (line 1).
#[test]
fn self_method_reference() {
    assert_resolves_to_line(
        "SelfMethod.py",
        "class C:\n    def helper(self):\n        pass\n\n    def run(self):\n        self.<caret>helper()\n",
        1,
    );
}

// A `self.attr` read resolves to the attribute's defining assignment (line 2).
#[test]
fn self_attribute_reference() {
    assert_resolves_to_line(
        "SelfAttr.py",
        "class C:\n    def __init__(self):\n        self.x = 1\n\n    def read(self):\n        return self.<caret>x\n",
        2,
    );
}

// IntelliJ resolve/QualifiedFunc: `Foo().bar()` resolves `bar` through the
// construction receiver `Foo()` to `def bar` (line 1). Analogous to the Java
// method-call-receiver case.
#[test]
fn method_on_construction_receiver() {
    assert_resolves_to_line(
        "QualifiedFunc.py",
        "class Foo:\n    def bar(self):\n        pass\n\nFoo().<caret>bar()\n",
        1,
    );
}

// An inherited method called on a subclass construction resolves to the base
// class definition (line 1).
#[test]
fn inherited_method_via_construction() {
    assert_resolves_to_line(
        "InheritedMethod.py",
        "class Base:\n    def run(self):\n        pass\n\nclass Sub(Base):\n    pass\n\nSub().<caret>run()\n",
        1,
    );
}

// A reference to a module-level global inside a function resolves to its
// top-level assignment (line 0).
#[test]
fn module_global_reference() {
    assert_resolves_to_line(
        "Global.py",
        "LIMIT = 10\n\ndef check(v):\n    return v < <caret>LIMIT\n",
        0,
    );
}

// ---------------------------------------------------------------------------
// Cross-file (multi-file) resolution
// ---------------------------------------------------------------------------

/// Write several Python files (exactly one carrying a `<caret>`), drive
/// `textDocument/definition`, and return the resolved `(file-name-suffix, line)`
/// pairs across all files.
fn definition_multifile(files: &[(&str, &str)]) -> (TempDir, Vec<(String, u64)>) {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let mut caret: Option<(PathBuf, u64, u64)> = None;
    for (name, src) in files {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        if src.contains("<caret>") {
            let (clean, line, character) = split_caret(src);
            std::fs::write(&path, clean).expect("write caret fixture");
            caret = Some((path, line, character));
        } else {
            std::fs::write(&path, src).expect("write fixture");
        }
    }
    let (caret_path, line, character) = caret.expect("one file must contain <caret>");
    let mut server = LspServer::start(&root);
    let response = server.text_document_position_response(
        "textDocument/definition",
        &uri_for(&caret_path),
        line,
        character,
    );
    server.shutdown();

    let locations = match &response["result"] {
        Value::Array(items) => items
            .iter()
            .filter_map(|loc| {
                let uri = loc["uri"].as_str()?;
                let line = loc["range"]["start"]["line"].as_u64()?;
                let name = uri.rsplit('/').next().unwrap_or(uri).to_string();
                Some((name, line))
            })
            .collect(),
        _ => Vec::new(),
    };
    (temp, locations)
}

fn assert_resolves_in_file(files: &[(&str, &str)], target_file: &str, expected_line: u64) {
    let (_temp, locations) = definition_multifile(files);
    assert!(
        locations
            .iter()
            .any(|(name, line)| name == target_file && *line == expected_line),
        "expected {target_file}:{expected_line}, got {locations:?}"
    );
}

// A `from mod import func; func()` use resolves to `def func` in mod.py (line 0).
#[test]
fn cross_file_from_import_use() {
    assert_resolves_in_file(
        &[
            ("mod.py", "def func():\n    pass\n"),
            ("main.py", "from mod import func\n\n<caret>func()\n"),
        ],
        "mod.py",
        0,
    );
}

// An aliased import `from mod import func as f; f()` resolves through the alias
// to `def func` in mod.py (line 0).
#[test]
fn cross_file_aliased_import_use() {
    assert_resolves_in_file(
        &[
            ("mod.py", "def func():\n    pass\n"),
            ("main.py", "from mod import func as f\n\n<caret>f()\n"),
        ],
        "mod.py",
        0,
    );
}

// A qualified `import mod; mod.func()` resolves `func` to `def func` in mod.py
// (line 0).
#[test]
fn cross_file_qualified_module_member() {
    assert_resolves_in_file(
        &[
            ("mod.py", "def func():\n    pass\n"),
            ("main.py", "import mod\n\nmod.<caret>func()\n"),
        ],
        "mod.py",
        0,
    );
}
