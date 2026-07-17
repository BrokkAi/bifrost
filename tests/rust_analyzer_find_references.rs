//! Find-references corner cases borrowed from rust-analyzer's own
//! `crates/ide/src/references.rs` inline test corpus (the `check(r#"..."#)`
//! fixtures with a `$0` cursor and an `expect![[...]]` reference listing). Each
//! case cites the upstream test name it was ported from.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (struct fields, methods,
//! associated functions, module-level functions). rust-analyzer cases targeting
//! locals, params, lifetimes, or patterns are out of bifrost's model and are not
//! ported.
//!
//! Driven through the real LSP server (`textDocument/references`,
//! `includeDeclaration = false`, matching IntelliJ/rust-analyzer find-usages
//! which exclude the declaration). Assertions are on the `LspReferences` surface,
//! so import bindings and self/this receiver hits are visible here.

mod common;

use common::lsp_client::LspServer;
use std::path::PathBuf;
use tempfile::TempDir;

/// Write `files` into a fresh temp project, place the cursor at the `<caret>` in
/// whichever file contains it, request references (excluding the declaration),
/// and return the resulting `(basename, 0-based line)` pairs, sorted.
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

// rust-analyzer: test_find_all_refs_field_name — references of a struct field
// found through a typed parameter receiver (`s: Foo` -> `s.spam`).
#[test]
fn ra_find_all_refs_field_name() {
    assert_refs(
        &[(
            "lib.rs",
            "struct Foo {\n    pub spam<caret>: u32,\n}\n\nfn main(s: Foo) {\n    let f = s.spam;\n}\n",
        )],
        &[("lib.rs", 5)],
    );
}

// rust-analyzer: test_basic_highlight_field_read_write — a field is referenced by
// both a struct-literal initializer (read) and an assignment target (write).
#[test]
fn ra_field_read_and_write() {
    assert_refs(
        &[(
            "lib.rs",
            "struct S {\n    f<caret>: u32,\n}\n\nfn foo() {\n    let mut s = S { f: 0 };\n    s.f = 0;\n}\n",
        )],
        &[("lib.rs", 5), ("lib.rs", 6)],
    );
}

// rust-analyzer: test_find_struct_function_refs_outside_module — an associated
// function referenced through its module path (`foo::Foo::new()`).
//
// DEFERRED (resolver architecture) — same root cause as
// `ra_goto_def_module_qualified_assoc_fn` in the go-to-definition suite: inline
// `mod foo` impl methods aren't extracted, and the fix exposes that the Rust
// reference context resolves bare names against a flat, position-blind short-name
// map, so same-named sibling-module declarations collide nondeterministically.
// The real fix is scope-sensitive name resolution; tracked for its own ExecPlan.
#[test]
#[ignore = "deferred: needs scope-sensitive Rust name resolution (see ra_goto_def_module_qualified_assoc_fn)"]
fn ra_find_struct_function_refs_outside_module() {
    assert_refs(
        &[(
            "lib.rs",
            "mod foo {\n    pub struct Foo;\n\n    impl Foo {\n        pub fn new<caret>() -> Foo { Foo }\n    }\n}\n\nfn main() {\n    let _f = foo::Foo::new();\n}\n",
        )],
        &[("lib.rs", 9)],
    );
}

// rust-analyzer: test_find_all_refs_nested_module — a function used from another
// file appears as both an import binding and a call. Exercises file-scope import
// hits (#412) on the LspReferences surface.
#[test]
fn ra_find_all_refs_cross_file_import_and_call() {
    assert_refs(
        &[
            ("lib.rs", "mod bar;\n\npub fn f<caret>() {}\n"),
            ("bar.rs", "use crate::f;\n\nfn g() { f(); }\n"),
        ],
        &[("bar.rs", 0), ("bar.rs", 2)],
    );
}

#[test]
fn rust_type_references_include_capital_self_but_not_lowercase_self() {
    assert_refs(
        &[(
            "lib.rs",
            "pub struct Service<caret> {\n    value: usize,\n}\n\nimpl Service {\n    fn new() -> Self {\n        Self { value: 0 }\n    }\n\n    fn read(&self) -> usize {\n        self.value\n    }\n}\n",
        )],
        &[("lib.rs", 4), ("lib.rs", 5), ("lib.rs", 6)],
    );
}
