//! Go-to-definition corner cases borrowed from gopls' own marker corpus
//! (`gopls/internal/test/marker/testdata/definition/*.txt`), whose `//@def(...)`
//! / `//@loc(...)` markers pin a cursor to an expected definition. Each case
//! cites the upstream fixture it was ported from.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (struct/interface types,
//! methods, fields, functions). gopls cases targeting locals, params, labels,
//! builtins, cgo, or control-flow keywords are out of bifrost's model and not
//! ported.
//!
//! Driven through the real LSP server (`textDocument/definition`), so this also
//! exercises cursor resolution, exactly like gopls' own marker tests.

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

// gopls definition/misc.txt (random.go): `x.field` where `x := &Typ{}` resolves
// to the struct field declaration (line 2).
#[test]
fn gopls_def_field_through_composite_literal_receiver() {
    assert_resolves_to_line(
        "a.go",
        "package a\n\ntype Typ struct{ field string }\n\nfunc useField() {\n\tx := &Typ{}\n\t_ = x.field<caret>\n}\n",
        2,
    );
}

// gopls definition/misc.txt (random.go): `p.Sum()` where `var p Pos` resolves to
// the method declaration (line 6).
#[test]
fn gopls_def_method_through_var_receiver() {
    assert_resolves_to_line(
        "a.go",
        "package a\n\ntype Pos struct {\n\tx, y int\n}\n\nfunc (p *Pos) Sum() int {\n\treturn p.x + p.y\n}\n\nfunc usePos() {\n\tvar p Pos\n\t_ = p.Sum<caret>()\n}\n",
        6,
    );
}

// gopls-style: a method call on an interface-typed parameter resolves to the
// interface method declaration (line 3).
#[test]
fn gopls_def_method_through_interface_param() {
    assert_resolves_to_line(
        "a.go",
        "package a\n\ntype I interface {\n\tM()\n}\n\nfunc useI(x I) {\n\tx.M<caret>()\n}\n",
        3,
    );
}
