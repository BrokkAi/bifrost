//! Go-to-definition corner cases borrowed from Roslyn's C# goto-definition tests
//! (`$$` cursor markup), ported with workspace-local types. Two cases are
//! bifrost-added probes (marked): a namespace-collision probe testing whether the
//! #431 scope-blind collapse reproduces in C#, and a nullable-receiver probe
//! testing whether the PHP nullable fix's pattern is needed here too.
//!
//! Scope: bifrost's CodeUnit envelope (class/interface/struct, methods,
//! properties, static members, namespaces).
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
    definition_lines_in_file_set(name, &[(name, source_with_caret)], name)
}

fn definition_lines_in_file_set(
    caret_name: &str,
    files: &[(&str, &str)],
    target_name: &str,
) -> (TempDir, Vec<u64>) {
    let caret_source = files
        .iter()
        .find_map(|(name, contents)| (*name == caret_name).then_some(*contents))
        .expect("caret file must be present");
    let (source, line, character) = split_caret(caret_source);
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let caret_file: PathBuf = root.join(caret_name);
    for (name, contents) in files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("mkdir fixture");
        let contents = if *name == caret_name {
            source.as_str()
        } else {
            contents
        };
        std::fs::write(path, contents).expect("write fixture");
    }

    let mut server = LspServer::start(&root);
    let response = server.text_document_position_response(
        "textDocument/definition",
        &uri_for(&caret_file),
        line,
        character,
    );
    server.shutdown();

    let file_uri = uri_for(&root.join(target_name));
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

fn assert_does_not_resolve_to_line(name: &str, source_with_caret: &str, forbidden: u64) {
    let (_t, lines) = definition_lines(name, source_with_caret);
    assert!(
        !lines.contains(&forbidden),
        "expected {name} NOT to resolve to line {forbidden}, got {lines:?}"
    );
}

fn assert_resolves_to_line_in_file_set(
    caret_name: &str,
    files: &[(&str, &str)],
    target_name: &str,
    expected: u64,
) {
    let (_t, lines) = definition_lines_in_file_set(caret_name, files, target_name);
    assert!(
        lines.contains(&expected),
        "expected {caret_name} to resolve to {target_name}:{expected}, got {lines:?}"
    );
}

// Method call on a `new` receiver resolves to the method (line 1).
#[test]
fn roslyn_def_method_on_new_receiver() {
    assert_resolves_to_line(
        "a.cs",
        "class Foo {\n    public int Bar() { return 1; }\n}\nclass Program {\n    void Run() {\n        var f = new Foo();\n        f.Bar<caret>();\n    }\n}\n",
        1,
    );
}

// Property access resolves to the property (line 1).
#[test]
fn roslyn_def_property() {
    assert_resolves_to_line(
        "a.cs",
        "class Foo {\n    public int Prop { get; set; }\n}\nclass Program {\n    void Run() {\n        var f = new Foo();\n        var x = f.Prop<caret>;\n    }\n}\n",
        1,
    );
}

// Static method call resolves to the static method (line 1).
#[test]
fn roslyn_def_static_method() {
    assert_resolves_to_line(
        "a.cs",
        "class Foo {\n    public static int Bar() { return 1; }\n}\nclass Program {\n    void Run() {\n        Foo.Bar<caret>();\n    }\n}\n",
        1,
    );
}

// Inherited method call on a subclass instance resolves to the base method (line 1).
#[test]
fn roslyn_def_inherited_method() {
    assert_resolves_to_line(
        "a.cs",
        "class Base {\n    public int Bar() { return 1; }\n}\nclass Derived : Base {}\nclass Program {\n    void Run() {\n        var d = new Derived();\n        d.Bar<caret>();\n    }\n}\n",
        1,
    );
}

// Method call on an interface-typed parameter resolves to the interface method (line 1).
#[test]
fn roslyn_def_interface_method() {
    assert_resolves_to_line(
        "a.cs",
        "interface I {\n    int M();\n}\nclass Program {\n    void Run(I x) {\n        x.M<caret>();\n    }\n}\n",
        1,
    );
}

// Roslyn GoToClassDeclaration (shape): a namespace-qualified type resolves to the
// class declaration (line 1).
#[test]
fn roslyn_def_namespace_qualified_type() {
    assert_resolves_to_line(
        "a.cs",
        "namespace NS {\n    class SomeClass {}\n}\nclass Program {\n    void Run() {\n        NS.SomeClass<caret> c = null;\n    }\n}\n",
        1,
    );
}

#[test]
fn roslyn_def_csharp_using_alias_type_cross_file() {
    assert_resolves_to_line_in_file_set(
        "src/Consumers.cs",
        &[
            (
                "src/Handlers.cs",
                "namespace Example.Parity {\n    public class ConsoleHandler {\n        public ConsoleHandler() {}\n    }\n}\n",
            ),
            (
                "src/Consumers.cs",
                "using WorkerAlias = Example.Parity.ConsoleHandler;\n\nclass Consumer {\n    void Run() {\n        var w = new WorkerAlias<caret>();\n    }\n}\n",
            ),
        ],
        "src/Handlers.cs",
        1,
    );
}

// bifrost probe (NOT a borrowed case): does the #431 scope-blind collapse
// reproduce in C# namespaces? A *bare* `Config` used inside namespace `B` must
// resolve to B's class (line 4), not A's same-named class (line 1).
//
// Fixed via the shared enclosing-scope resolver (#431): the bare `Config` inside
// namespace `B` resolves to `B.Config`, not `A.Config`. Resolution now uses the
// reference's position instead of a scope-blind type index.
#[test]
fn roslyn_probe_namespace_collision_bare_inside_scope() {
    let src = "namespace A {\n    class Config {}\n}\nnamespace B {\n    class Config {}\n    class User {\n        Config<caret> c = null;\n    }\n}\n";
    assert_resolves_to_line("a.cs", src, 4);
    assert_does_not_resolve_to_line("a.cs", src, 1);
}

// bifrost probe (NOT a borrowed case): member access on a nullable-reference-typed
// parameter (`Foo?`) resolves to the method (line 2) — the C# analog of the PHP
// nullable-receiver fix.
#[test]
fn roslyn_probe_nullable_receiver() {
    assert_resolves_to_line(
        "a.cs",
        "#nullable enable\nclass Foo {\n    public int Bar() { return 1; }\n}\nclass Program {\n    void Run(Foo? f) {\n        f.Bar<caret>();\n    }\n}\n",
        2,
    );
}
