//! Regression coverage for issue #1089.
//!
//! Facet A (Rust): `use forc_pkg::{self as pkg}; use pkg::TestPassCondition;` —
//! the `self as pkg` clause aliases the whole crate root to a local name. Every
//! `pkg::Item` reference must resolve through the alias to the workspace crate,
//! and the bare alias qualifier `pkg` (which names a crate namespace, not a
//! single declaration) must never draw a confident "crosses an unindexed
//! boundary" claim.
//!
//! Facet B (Go): a workspace-internal package qualifier such as `fs.Debugf`
//! (clicking `fs`) must not claim the package "may be outside the indexed
//! workspace"; it is an honest workspace package namespace.
//!
//! Negative controls prove a genuinely-external crate/package still draws the
//! boundary claim.

mod common;

use brokk_bifrost::Language;
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

fn loc(
    root: &std::path::Path,
    path: &str,
    source: &str,
    line_marker: &str,
    occ: usize,
    needle: &str,
) -> Value {
    let line_index = source
        .lines()
        .position(|l| l.contains(line_marker))
        .unwrap_or_else(|| panic!("line not found: {line_marker:?}"));
    let line = source.lines().nth(line_index).unwrap();
    let mut idx = 0usize;
    let mut start = 0usize;
    for _ in 0..=occ {
        start = line[idx..]
            .find(needle)
            .map(|f| idx + f)
            .unwrap_or_else(|| panic!("needle {needle} occ {occ} not in {line}"));
        idx = start + 1;
    }
    let args = json!({"references":[{"path": path, "line": line_index + 1, "column": start + 1}]})
        .to_string();
    call_search_tool_json(root, "get_definitions_by_location", &args)
}

fn status(v: &Value) -> String {
    v["results"][0]["status"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}
fn fqn(v: &Value) -> String {
    v["results"][0]["definitions"][0]["fqn"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn assert_resolved(v: &Value, expected_fqn: &str, ctx: &str) {
    assert_eq!(status(v), "resolved", "{ctx}: expected resolved: {v}");
    assert_eq!(fqn(v), expected_fqn, "{ctx}: wrong fqn: {v}");
}
fn assert_boundary(v: &Value, ctx: &str) {
    assert_eq!(
        status(v),
        "unresolvable_import_boundary",
        "{ctx}: expected boundary claim: {v}"
    );
}
/// The reference does not resolve to a single declaration, but the workspace
/// namespace it names must NOT be reported as a crossed/unindexed boundary.
fn assert_workspace_namespace_not_boundary(v: &Value, ctx: &str) {
    let s = status(v);
    assert_ne!(
        s, "unresolvable_import_boundary",
        "{ctx}: must not draw a boundary claim: {v}"
    );
    assert_eq!(
        s, "no_definition",
        "{ctx}: expected honest no_definition: {v}"
    );
    let diag = v["results"][0]["diagnostics"][0]["message"]
        .as_str()
        .unwrap_or("");
    assert!(
        diag.contains("in this workspace"),
        "{ctx}: diagnostic should name the workspace namespace: {v}"
    );
}

fn sway_project() -> common::BuiltInlineTestProject {
    let lib = "use forc_pkg::{self as pkg, BuildOpts};\nuse pkg::TestPassCondition;\nuse pkg::{Built, BuiltPackage};\n\npub fn run(_c: TestPassCondition, _b: BuildOpts, _p: BuiltPackage, _q: Built) {}\n\npub fn nested() -> pkg::BuiltPackage {\n    pkg::BuiltPackage\n}\n";
    InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[workspace]\nmembers = [\"forc-pkg\", \"forc-test\"]\n")
        .file("forc-pkg/Cargo.toml", "[package]\nname = \"forc-pkg\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
        .file("forc-pkg/src/lib.rs", "pub struct TestPassCondition;\npub struct BuildOpts;\npub struct BuiltPackage;\npub struct Built;\n")
        .file("forc-test/Cargo.toml", "[package]\nname = \"forc-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nforc-pkg = { path = \"../forc-pkg\" }\n")
        .file("forc-test/src/lib.rs", lib)
        .build()
}

const SWAY_LIB: &str = "use forc_pkg::{self as pkg, BuildOpts};\nuse pkg::TestPassCondition;\nuse pkg::{Built, BuiltPackage};\n\npub fn run(_c: TestPassCondition, _b: BuildOpts, _p: BuiltPackage, _q: Built) {}\n\npub fn nested() -> pkg::BuiltPackage {\n    pkg::BuiltPackage\n}\n";

// ---------- Facet A: references through the `self as pkg` alias resolve ----------
#[test]
fn sway_self_as_alias_references_resolve_to_workspace_crate() {
    let project = sway_project();
    let p = "forc-test/src/lib.rs";
    // bare use of an item imported via the alias (`use pkg::TestPassCondition;`)
    let bare = loc(
        project.root(),
        p,
        SWAY_LIB,
        "pub fn run(_c: TestPassCondition",
        0,
        "TestPassCondition",
    );
    assert_resolved(
        &bare,
        "forc-pkg.src.TestPassCondition",
        "bare alias-imported item",
    );
    // `pkg::BuiltPackage` terminal in a return type and a body expression
    let ret = loc(
        project.root(),
        p,
        SWAY_LIB,
        "pub fn nested() -> pkg::BuiltPackage {",
        0,
        "BuiltPackage",
    );
    assert_resolved(
        &ret,
        "forc-pkg.src.BuiltPackage",
        "pkg::BuiltPackage return terminal",
    );
    let body = loc(
        project.root(),
        p,
        SWAY_LIB,
        "    pkg::BuiltPackage",
        0,
        "BuiltPackage",
    );
    assert_resolved(
        &body,
        "forc-pkg.src.BuiltPackage",
        "pkg::BuiltPackage body terminal",
    );
    // the import terminal in `use pkg::TestPassCondition;`
    let import_terminal = loc(
        project.root(),
        p,
        SWAY_LIB,
        "use pkg::TestPassCondition;",
        0,
        "TestPassCondition",
    );
    assert_resolved(
        &import_terminal,
        "forc-pkg.src.TestPassCondition",
        "alias import terminal",
    );
    // sanity: the direct (non-aliased) crate path still resolves
    let direct = loc(
        project.root(),
        p,
        SWAY_LIB,
        "use forc_pkg::{self as pkg, BuildOpts};",
        0,
        "BuildOpts",
    );
    assert_resolved(
        &direct,
        "forc-pkg.src.BuildOpts",
        "direct forc_pkg::BuildOpts",
    );
}

#[test]
fn sway_alias_qualifier_is_workspace_namespace_not_boundary() {
    let project = sway_project();
    let p = "forc-test/src/lib.rs";
    // Clicking the alias qualifier `pkg` itself: it names the workspace crate
    // namespace, so honest no_definition — never a boundary claim.
    for (marker, ctx) in [
        ("use pkg::TestPassCondition;", "pkg root in single use"),
        ("use pkg::{Built, BuiltPackage};", "pkg root in grouped use"),
        (
            "pub fn nested() -> pkg::BuiltPackage {",
            "pkg owner in return type",
        ),
        ("    pkg::BuiltPackage", "pkg owner in body"),
    ] {
        let v = loc(project.root(), p, SWAY_LIB, marker, 0, "pkg");
        assert_workspace_namespace_not_boundary(&v, ctx);
    }
}

// ---------- Facet A negative controls: genuinely-external crates still boundary ----------
#[test]
fn genuinely_external_crate_reference_still_draws_boundary() {
    let src = "use serde::Serialize;\n\npub fn f<T: Serialize>(_t: T) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/lib.rs",
        src,
        "pub fn f<T: Serialize>(_t: T) {}",
        0,
        "Serialize",
    );
    assert_boundary(&v, "external serde::Serialize with no workspace target");
}

#[test]
fn genuinely_external_aliased_crate_still_draws_boundary() {
    // `serde` is not a workspace crate, so its `self as s` alias must not be
    // treated as a workspace namespace: both `s::Serialize` and the bare
    // qualifier `s` stay boundary claims.
    let src = "use serde::{self as sd, Serialize};\nuse sd::Serializer;\n\npub fn f<T: Serialize, U: Serializer>(_t: T, _u: U) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", src)
        .build();
    let owner = loc(
        project.root(),
        "src/lib.rs",
        src,
        "use sd::Serializer;",
        0,
        "sd",
    );
    assert_boundary(&owner, "external aliased crate qualifier sd");
    let terminal = loc(
        project.root(),
        "src/lib.rs",
        src,
        "use sd::Serializer;",
        0,
        "Serializer",
    );
    assert_boundary(&terminal, "external aliased crate terminal sd::Serializer");
}

// ---------- Facet B (Go): workspace package qualifier is honest, not a boundary ----------
fn go_workspace_project(caller: &str) -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module myproj\n\ngo 1.22\n")
        .file(
            "fs/fs.go",
            "package fs\n\nfunc Debugf(msg string) {\n\t_ = msg\n}\n",
        )
        .file("app/app.go", caller)
        .build()
}

#[test]
fn go_workspace_package_qualifier_is_namespace_not_boundary() {
    let caller =
        "package app\n\nimport (\n\t\"myproj/fs\"\n)\n\nfunc Run() {\n\tfs.Debugf(\"hi\")\n}\n";
    let project = go_workspace_project(caller);
    let p = "app/app.go";
    // clicking the package qualifier `fs`
    let qualifier = loc(project.root(), p, caller, "fs.Debugf(\"hi\")", 0, "fs");
    assert_workspace_namespace_not_boundary(&qualifier, "go workspace package qualifier fs");
    // the member itself still resolves
    let member = loc(project.root(), p, caller, "fs.Debugf(\"hi\")", 0, "Debugf");
    assert_resolved(
        &member,
        "myproj/fs.Debugf",
        "go workspace package member Debugf",
    );
}

#[test]
fn go_external_package_qualifier_still_draws_boundary() {
    let caller =
        "package app\n\nimport (\n\t\"github.com/x/ext\"\n)\n\nfunc Run() {\n\text.Do()\n}\n";
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module myproj\n\ngo 1.22\n")
        .file("app/app.go", caller)
        .build();
    let v = loc(project.root(), "app/app.go", caller, "ext.Do()", 0, "ext");
    assert_boundary(&v, "external go package qualifier ext");
}
