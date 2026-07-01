//! Find-references corner cases borrowed from gopls' own marker corpus
//! (`gopls/internal/test/marker/testdata/references/*.txt`), whose `//@refs(...)`
//! markers list the full reference set for a symbol. Each case cites the upstream
//! fixture it was ported from.
//!
//! Scope: only cases inside bifrost's CodeUnit envelope (package-level types,
//! methods, fields, functions). gopls cases targeting locals, params, labels, or
//! shadowed identifiers are out of bifrost's model and not ported.
//!
//! Driven through the real LSP server (`textDocument/references`,
//! `includeDeclaration = false`), asserting on the `LspReferences` surface.

mod common;

use common::lsp_client::LspServer;
use std::path::PathBuf;
use tempfile::TempDir;

/// Write `files` into a fresh temp project, place the cursor at the `<caret>`,
/// request references excluding the declaration, and return `(basename, line)`
/// pairs, sorted.
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

// gopls references/intrapackage.txt: references to a package-level type `i` used
// as a parameter type and a return type. Caret on the type declaration (line 2).
#[test]
fn gopls_refs_type_as_param_and_return() {
    assert_refs(
        &[(
            "a.go",
            "package a\n\ntype i<caret> int\n\nfunc _(_ i) []bool {\n\treturn nil\n}\n\nfunc _(_ []byte) i {\n\treturn 0\n}\n",
        )],
        &[("a.go", 4), ("a.go", 8)],
    );
}

// gopls references/intrapackage.txt: references to a package-level var `q`
// (assignment target + read argument). Caret on the var declaration (line 2).
//
// Was failing: a package-level `var` was seeded as a *local shadow* in both the
// get-definition reference resolver (`go_name_shadowed_at`) and the find-usages
// forward scan (`seed_var_spec`), so references to it were treated as shadowed
// locals and dropped. Fixed by not shadowing top-level (`source_file`-scoped)
// `var` declarations while still seeding their type for receiver inference.
#[test]
fn gopls_refs_package_var_assign_and_read() {
    assert_refs(
        &[(
            "a.go",
            "package a\n\nvar q<caret> string\n\nfunc _() {\n\tq = \"hello\"\n\tbob := func(_ string) {}\n\tbob(q)\n}\n",
        )],
        &[("a.go", 5), ("a.go", 7)],
    );
}

// gopls references/intrapackage.txt: an embedded field `i` is referenced by its
// embedding (`type e struct { i }`) and by field access (`e{}.i`). Caret on the
// type declaration (line 2). Correct behavior: the *type* `i`'s references are
// the embedding (line 5). The `e{}.i` access (line 9) is a reference to the
// embedded *field*, which gopls lists under a separate symbol, so it is correctly
// absent from the type's reference set.
#[test]
fn gopls_refs_type_embedded_in_struct() {
    assert_refs(
        &[(
            "a.go",
            "package a\n\ntype i<caret> int\n\ntype e struct {\n\ti\n}\n\nfunc _() {\n\t_ = e{}.i\n}\n",
        )],
        &[("a.go", 5)],
    );
}

// Member access on a *direct* composite-literal receiver: find-references of the
// field `Name` should include the `e{}.Name` access (line 7).
//
// DEFERRED: bifrost resolves neither `e{}.Name` nor `e{}.i`, while the
// var-receiver form (`x := e{}; x.Name`) works. `resolve_go_local_selector_chain`
// types the chain base from the reference *text* (`split('.')[0]` looked up as a
// binding name), so a base like `e{}` — a composite literal, not a name — can't be
// typed. The right fix types the base from its AST node (composite literal -> its
// type) via the existing `go_expression_type_fqn`, replacing the text mini-parser
// rather than special-casing `{}`. (An initial AST-based attempt did not land
// cleanly and was reverted; tracked for a focused follow-up.)
#[test]
#[ignore = "deferred: member access on a direct composite-literal receiver (e{}.field) not resolved"]
fn gopls_refs_composite_literal_receiver_member() {
    assert_refs(
        &[(
            "a.go",
            "package a\n\ntype e struct {\n\tName<caret> string\n}\n\nfunc _() {\n\t_ = e{}.Name\n}\n",
        )],
        &[("a.go", 7)],
    );
}

// gopls references/interfaces.txt (reduced): a concrete method `common` and its
// interface counterpart are assignability-related; references include both the
// interface-typed and concrete-typed call sites. Caret on the concrete method
// declaration (line 8).
#[test]
fn gopls_refs_interface_and_concrete_method() {
    assert_refs(
        &[(
            "a.go",
            "package a\n\ntype first interface {\n\tcommon()\n}\n\ntype s struct{}\n\nfunc (*s) common<caret>() {}\n\nfunc use() {\n\tvar x first = &s{}\n\tx.common()\n\tvar z *s = &s{}\n\tz.common()\n}\n",
        )],
        &[("a.go", 12), ("a.go", 14)],
    );
}
