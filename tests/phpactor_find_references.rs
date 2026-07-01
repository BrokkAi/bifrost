//! Find-references corner cases borrowed from phpactor's reference-finder tests
//! (shapes ported with workspace-local PHP). Each case cites the upstream shape.
//!
//! Scope: bifrost's CodeUnit envelope (class/interface, methods, properties,
//! static members).
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

// References to a method found through a `new` receiver call site (line 5). Caret
// on the method declaration.
#[test]
fn phpactor_refs_method() {
    assert_refs(
        &[(
            "a.php",
            "<?php\nclass Foobar {\n    public function bar<caret>() {}\n}\n$foo = new Foobar();\n$foo->bar();\n",
        )],
        &[("a.php", 5)],
    );
}

// References to a static method through a static call (line 4). Caret on the
// static method declaration.
#[test]
fn phpactor_refs_static_method() {
    assert_refs(
        &[(
            "a.php",
            "<?php\nclass Foobar {\n    public static function bar<caret>() {}\n}\nFoobar::bar();\n",
        )],
        &[("a.php", 4)],
    );
}

// References to a method called through a nullable-typed parameter (`?Foobar`) —
// exercises nullable receiver typing on the find-references surface (line 5).
#[test]
fn phpactor_refs_method_via_nullable_receiver() {
    assert_refs(
        &[(
            "a.php",
            "<?php\nclass Foobar {\n    public function bar<caret>() {}\n}\nfunction run(?Foobar $foo) {\n    $foo->bar();\n}\n",
        )],
        &[("a.php", 5)],
    );
}
