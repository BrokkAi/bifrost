//! Find-references corner cases borrowed from clangd's own `XRefsTests.cpp`
//! (`FindReferences.WithinAST` table). Each case cites the upstream shape.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (namespace/struct/class
//! types, methods, fields, functions). clangd cases targeting locals, templates,
//! concepts, or ObjC are out of bifrost's model and not ported.
//!
//! Driven through the real LSP server (`textDocument/references`,
//! `includeDeclaration = false`).

mod common;

use common::lsp_client::LspServer;
use std::path::PathBuf;
use tempfile::TempDir;

fn references(files: &[(&str, &str)]) -> Vec<(String, u64)> {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");

    let mut caret: Option<(PathBuf, u64, u64)> = None;
    for (name, content) in files {
        let path = root.join(name);
        if let Some(idx) = content.find("<caret>") {
            let before = &content[..idx];
            let line = before.matches('\n').count() as u64;
            let last_line_start = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
            let character = before[last_line_start..].chars().count() as u64;
            caret = Some((path.clone(), line, character));
            std::fs::write(&path, content.replacen("<caret>", "", 1)).expect("write fixture");
        } else {
            std::fs::write(&path, content).expect("write fixture");
        }
    }
    let (caret_file, line, character) = caret.expect("one fixture file must contain <caret>");

    let mut server = LspServer::start(&root);
    let locations = server.references(&caret_file, line, character, false);
    server.shutdown();

    let mut out: Vec<(String, u64)> = locations
        .into_iter()
        .map(|loc| {
            let name = loc.uri.rsplit('/').next().unwrap_or(&loc.uri).to_string();
            (name, loc.line)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn assert_refs(files: &[(&str, &str)], expected: &[(&str, u64)]) {
    let got = references(files);
    let expected: Vec<(String, u64)> = expected
        .iter()
        .map(|(n, l)| ((*n).to_string(), *l))
        .collect();
    assert_eq!(expected, got, "reference set mismatch");
}

// clangd FindReferences.WithinAST "Field": a field is referenced by a member
// initializer (line 2) and a field access (line 6). Caret on the field decl.
#[test]
fn clangd_refs_field() {
    assert_refs(
        &[(
            "a.cpp",
            "struct Foo {\n    int foo<caret>;\n    Foo() : foo(0) {}\n};\nint main() {\n    Foo f;\n    f.foo = 1;\n}\n",
        )],
        &[("a.cpp", 2), ("a.cpp", 6)],
    );
}

// clangd FindReferences.WithinAST "Method call": an inline method referenced by a
// call site (line 3). Caret on the method decl.
#[test]
fn clangd_refs_method_call() {
    assert_refs(
        &[(
            "a.cpp",
            "struct Foo { int foo<caret>() { return 0; } };\nint main() {\n    Foo f;\n    f.foo();\n}\n",
        )],
        &[("a.cpp", 3)],
    );
}

// clangd FindReferences.WithinAST "Function": a function referenced by address-of
// (line 2) and a call (line 3). Caret on the function decl.
//
// DEFERRED: bifrost counts the call `foo(42)` (line 3) but not the address-of
// value reference `&foo` (line 2). `maybe_record_free_function_hit` only records
// at a `call_expression`, so any non-call reference to a free function (address-of,
// `fp = foo`, passing `foo` as an argument) is missed. The right fix is general —
// count any identifier reference that resolves to the function, with scope/shadow
// care — not a narrow address-of-only special case.
#[test]
#[ignore = "deferred: non-call free-function references (&foo) not counted; needs general function-reference support"]
fn clangd_refs_function() {
    assert_refs(
        &[(
            "a.cpp",
            "int foo<caret>(int) { return 0; }\nint main() {\n    auto *X = &foo;\n    foo(42);\n}\n",
        )],
        &[("a.cpp", 2), ("a.cpp", 3)],
    );
}

// clangd FindReferences.WithinAST "Struct" in a namespace: referenced by a
// qualified use (line 4). Caret on the struct decl.
#[test]
fn clangd_refs_namespace_struct() {
    assert_refs(
        &[(
            "a.cpp",
            "namespace ns1 {\nstruct Foo<caret> {};\n}\nint main() {\n    ns1::Foo* Params;\n}\n",
        )],
        &[("a.cpp", 4)],
    );
}
