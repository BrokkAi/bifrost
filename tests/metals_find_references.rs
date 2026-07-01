//! Find-references corner cases borrowed from Metals' presentation-compiler
//! reference suites (shapes ported with workspace-local types, since bifrost is
//! project-scoped and does not index the Scala stdlib).
//!
//! Scope: bifrost's CodeUnit envelope (class/object/trait, methods, members). Cases
//! targeting locals / for-comprehension bindings are out of bifrost's model.
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

// References to a method found through a `val` receiver call site (line 5). Caret
// on the method declaration.
#[test]
fn metals_refs_method() {
    assert_refs(
        &[(
            "a.scala",
            "class Foo {\n  def bar<caret>(): Int = 1\n}\nobject Main {\n  val f = new Foo\n  val x = f.bar()\n}\n",
        )],
        &[("a.scala", 5)],
    );
}

// References to a class: the `new Foo` construction (line 4). Caret on the class
// declaration.
#[test]
fn metals_refs_class() {
    assert_refs(
        &[(
            "a.scala",
            "class Foo<caret> {\n  def bar(): Int = 1\n}\nobject Main {\n  val f = new Foo\n  val x = f.bar()\n}\n",
        )],
        &[("a.scala", 4)],
    );
}

// References to a method on an object, called through the object (line 4). Caret
// on the method declaration.
#[test]
fn metals_refs_object_member() {
    assert_refs(
        &[(
            "a.scala",
            "object Api {\n  def run<caret>(): Int = 1\n}\nobject Main {\n  val x = Api.run()\n}\n",
        )],
        &[("a.scala", 4)],
    );
}
