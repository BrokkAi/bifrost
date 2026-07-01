//! Find-references corner cases borrowed from Ruby LSP's own
//! `test/requests/references_test.rb` (+ fixture `rename_me.rb`) and the
//! method-resolution shapes in its definition suite. Each case cites the upstream
//! shape.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (classes/modules,
//! methods, constants).
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

// Ruby LSP test_finds_constant_references (fixture rename_me.rb): a class constant
// is referenced by a bare use (line 3). Caret on the class declaration.
#[test]
fn ruby_refs_constant() {
    assert_refs(
        &[("a.rb", "class RenameMe<caret>\nend\n\nRenameMe\n")],
        &[("a.rb", 3)],
    );
}

// Ruby method references: an implicit-self call site (line 3) references the
// method. Caret on the method declaration.
#[test]
fn ruby_refs_method() {
    assert_refs(
        &[(
            "a.rb",
            "class A\n  def foo<caret>; end\n  def bar\n    foo\n  end\nend\n",
        )],
        &[("a.rb", 3)],
    );
}
