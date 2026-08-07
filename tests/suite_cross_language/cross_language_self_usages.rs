//! Cross-language find-usages for a `self`/`this`-receiver method call — pattern
//! 2 from `.agents/docs/PARITY_CROSS_LANGUAGE_GENERALIZATION.md`. The caret is on a
//! method declaration; the same-class call via `self`/`this` (or the implicit
//! receiver) should be reported as a usage.

use crate::common::lsp_client::{LspServer, uri_for};
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

fn reference_lines(name: &str, source_with_caret: &str) -> (TempDir, Vec<u64>) {
    let (source, line, character) = split_caret(source_with_caret);
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file: PathBuf = root.join(name);
    std::fs::write(&file, &source).expect("write fixture");
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

fn assert_usage_on_line(name: &str, source_with_caret: &str, expected: u64) {
    let (_t, lines) = reference_lines(name, source_with_caret);
    assert!(
        lines.contains(&expected),
        "expected {name} usage on line {expected}, got {lines:?}"
    );
}

/// Assert the *exact* reference line set. The recursion fixtures below need the
/// exact set rather than a containment check: a language whose extractor pushes
/// the target's own declared name as an occurrence would, once the
/// enclosing-equals-target drop is gone, surface the declaration line as a
/// usage. Only an exact set makes that leak fail the test.
fn assert_usage_lines(name: &str, source_with_caret: &str, expected: &[u64]) {
    let (_t, lines) = reference_lines(name, source_with_caret);
    assert_eq!(
        lines, expected,
        "unexpected {name} reference lines (0-based)"
    );
}

#[test]
fn csharp_this_method_usage() {
    assert_usage_on_line(
        "R.cs",
        "class Foo {\n    void <caret>target() {}\n    void caller() {\n        this.target();\n    }\n}\n",
        3,
    );
}

#[test]
fn php_this_method_usage() {
    assert_usage_on_line(
        "R.php",
        "<?php\nclass Foo {\n    function <caret>target() {}\n    function caller() {\n        $this->target();\n    }\n}\n",
        4,
    );
}

#[test]
fn cpp_this_method_usage() {
    assert_usage_on_line(
        "r.cpp",
        "struct Foo {\n  void <caret>target() {}\n  void caller() {\n    this->target();\n  }\n};\n",
        3,
    );
}

#[test]
fn javascript_this_method_usage() {
    assert_usage_on_line(
        "r.js",
        "class Foo {\n  <caret>target() {}\n  caller() {\n    this.target();\n  }\n}\n",
        3,
    );
}

#[test]
fn typescript_this_method_usage() {
    assert_usage_on_line(
        "r.ts",
        "class Foo {\n  <caret>target() {}\n  caller() {\n    this.target();\n  }\n}\n",
        3,
    );
}

#[test]
fn scala_this_method_usage() {
    assert_usage_on_line(
        "R.scala",
        "class Foo {\n  def <caret>target(): Unit = {}\n  def caller(): Unit = { this.target() }\n}\n",
        2,
    );
}

#[test]
fn rust_self_method_usage() {
    assert_usage_on_line(
        "r.rs",
        "struct Foo;\nimpl Foo {\n    fn <caret>target(&self) {}\n    fn caller(&self) {\n        self.target();\n    }\n}\n",
        4,
    );
}

#[test]
fn go_receiver_method_usage() {
    assert_usage_on_line(
        "r.go",
        "package main\n\ntype Foo struct{}\n\nfunc (f Foo) <caret>target() {}\n\nfunc (f Foo) caller() {\n\tf.target()\n}\n",
        7,
    );
}

#[test]
fn ruby_implicit_self_method_usage() {
    assert_usage_on_line(
        "r.rb",
        "class Foo\n  def <caret>target\n  end\n\n  def caller\n    target\n  end\nend\n",
        5,
    );
}

// ---------------------------------------------------------------------------
// Recursion (#1638): a call whose enclosing declaration *is* the target.
//
// The forward occurrence resolver states this edge and classifies it
// `self_reference`. The inverse listing must state it too, on the editor
// surface, as a `self_receiver` hit -- which keeps it out of the external
// usage surface, so dead-code and too-many-callsite counts are unmoved.
//
// Each fixture has exactly one recursive call and exactly one call from a
// sibling, and asserts the exact line set, so a leaked declaration name shows
// up as a failure instead of as a plausible-looking extra row.
// ---------------------------------------------------------------------------

#[test]
fn csharp_recursive_method_usage() {
    assert_usage_lines(
        "Rec.cs",
        "class Foo {\n    void <caret>target(int n) {\n        if (n > 0) this.target(n - 1);\n    }\n    void caller() {\n        this.target(1);\n    }\n}\n",
        &[2, 5],
    );
}

#[test]
fn php_recursive_method_usage() {
    assert_usage_lines(
        "Rec.php",
        "<?php\nclass Foo {\n    function <caret>target($n) {\n        if ($n > 0) { $this->target($n - 1); }\n    }\n    function caller() {\n        $this->target(1);\n    }\n}\n",
        &[3, 6],
    );
}

#[test]
fn cpp_recursive_method_usage() {
    assert_usage_lines(
        "rec.cpp",
        "struct Foo {\n  void <caret>target(int n) {\n    if (n > 0) this->target(n - 1);\n  }\n  void caller() {\n    this->target(1);\n  }\n};\n",
        &[2, 5],
    );
}

#[test]
fn javascript_recursive_method_usage() {
    assert_usage_lines(
        "rec.js",
        "class Foo {\n  <caret>target(n) {\n    if (n > 0) this.target(n - 1);\n  }\n  caller() {\n    this.target(1);\n  }\n}\n",
        &[2, 5],
    );
}

#[test]
fn typescript_recursive_method_usage() {
    assert_usage_lines(
        "rec.ts",
        "class Foo {\n  <caret>target(n: number) {\n    if (n > 0) this.target(n - 1);\n  }\n  caller() {\n    this.target(1);\n  }\n}\n",
        &[2, 5],
    );
}

#[test]
fn scala_recursive_method_usage() {
    assert_usage_lines(
        "Rec.scala",
        "class Foo {\n  def <caret>target(n: Int): Unit = {\n    if (n > 0) this.target(n - 1)\n  }\n  def caller(): Unit = { this.target(1) }\n}\n",
        &[2, 4],
    );
}

#[test]
fn rust_recursive_method_usage() {
    assert_usage_lines(
        "rec.rs",
        "struct Foo;\nimpl Foo {\n    fn <caret>target(&self, n: u32) {\n        if n > 0 {\n            self.target(n - 1);\n        }\n    }\n    fn caller(&self) {\n        self.target(1);\n    }\n}\n",
        &[4, 8],
    );
}

#[test]
fn go_recursive_method_usage() {
    assert_usage_lines(
        "rec.go",
        "package main\n\ntype Foo struct{}\n\nfunc (f Foo) <caret>target(n int) {\n\tif n > 0 {\n\t\tf.target(n - 1)\n\t}\n}\n\nfunc (f Foo) caller() {\n\tf.target(1)\n}\n",
        &[6, 11],
    );
}

#[test]
fn ruby_recursive_method_usage() {
    assert_usage_lines(
        "rec.rb",
        "class Foo\n  def <caret>target(n)\n    target(n - 1) if n > 0\n  end\n\n  def caller\n    target(1)\n  end\nend\n",
        &[2, 6],
    );
}

#[test]
fn python_recursive_method_usage() {
    assert_usage_lines(
        "rec.py",
        "class Foo:\n    def <caret>target(self, n):\n        if n > 0:\n            self.target(n - 1)\n\n    def caller(self):\n        self.target(1)\n",
        &[3, 6],
    );
}
