//! Regression coverage for issue #1162: the shared enclosing-scope resolver
//! (`resolve_qualified_name_in_shrinking_scopes` / `resolve_in_enclosing_scopes`
//! in get_definition/mod.rs) was not separator-aware. It composed candidates as
//! `{scope}.{name}` with `.`, while rust/cpp references arrive `::`-qualified —
//! so the composed candidate kept the source `::` and could never match a
//! `.`-joined fq string, leaving the #1126-class member fallback structurally
//! inert for every `::`-qualified reference.
//!
//! The fix normalizes the *reference* to the canonical `.`-joined segment form
//! (via the structured `parse_symbol_path` splitter, not a text replace) before
//! composing candidates. The scope side is deliberately left verbatim: C++
//! indexes nested-namespace fq names with `::` in the namespace head
//! (`cutlass::gemm::warp.OperandSharedStorage.OperandLayout`), and the scope
//! prefix must keep that `::` to match — normalizing it would break same-owner
//! template-parameter resolution.
//!
//! What this suite proves:
//!   * the invariant the whole exercise defends — a confident boundary claim is
//!     never emitted for a `::`-qualified name the workspace actually owns (the
//!     enclosing-scope shapes resolve through upstream resolution, which is what
//!     keeps rust.rs:1022 / cpp.rs:2107/:2402 claim-correct);
//!   * the negative controls still hold — a genuinely-external `::`-qualified
//!     reference still draws the boundary (the fix does not over-suppress).
//!
//! Findings recorded during the fix (see the NOTEs at the former pinned sites):
//! after the fix, rust's enclosing-scope member fallback is functional for `::`
//! paths (rust fq strings are all-`.`), but Rust's own scoped-associated-item /
//! workspace-module resolution already catches every enclosing-qualified
//! workspace shape upstream, so no reference reaches the rust.rs:1022 net today.
//!
//! For C++ the sibling-nested-namespace shape was pinned as a documented false
//! boundary through M3 (C++ keys nested-namespace declarations with `::` in their
//! fq-name head, which the shared dot-only enclosing-scope walk cannot re-compose
//! from a sibling `::`-joined scope). M4 CLOSES issue #1163: with interned
//! segments authoritative end-to-end, cpp.rs's namespace-outward net
//! (`cpp_resolve_qualified_via_enclosing_namespaces`) re-interns the reference
//! with namespace-aware kinds and descends the scope's `::`-joined namespace head,
//! composing the exact stored key. `cpp_qualified_nested_namespace_type_resolves`
//! now asserts real resolution of that shape.

use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::Language;
use serde_json::{Value, json};

/// Resolve the reference at the `occ`-th occurrence of `needle` on the first
/// source line containing `line_marker`.
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

/// The invariant under test: a workspace-owned target must never draw a
/// confident boundary claim.
fn assert_not_boundary(v: &Value, ctx: &str) {
    assert_ne!(
        status(v),
        "unresolvable_import_boundary",
        "{ctx}: workspace-owned `::`-qualified target must not draw a confident boundary claim: {v}"
    );
}

/// Negative control: a genuinely-external `::`-qualified import must still draw
/// the boundary.
fn assert_boundary(v: &Value, ctx: &str) {
    assert_eq!(
        status(v),
        "unresolvable_import_boundary",
        "{ctx}: genuinely-external `::`-qualified import must still draw a boundary claim: {v}"
    );
}

// ===========================================================================
// Rust
// ===========================================================================

#[test]
fn rust_qualified_enum_variant_in_enclosing_scope_is_not_boundary() {
    // `Config::Value` is `::`-qualified and workspace-owned; it must resolve, not
    // draw a Rust crate/module boundary. (Upstream scoped-associated resolution
    // catches it before the rust.rs:1022 net; the invariant holds regardless.)
    let src = "pub mod inner {\n    pub enum Config {\n        Value,\n        Other,\n    }\n\n    pub fn pick() -> Config {\n        Config::Value\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/lib.rs",
        src,
        "Config::Value",
        0,
        "Config::Value",
    );
    assert_not_boundary(&v, "rust `Config::Value` enum variant in enclosing scope");
}

#[test]
fn rust_qualified_parent_scope_type_is_not_boundary() {
    // `Status::Active` referenced from a sibling module resolves to the
    // parent-scope enum via upstream resolution — never a boundary.
    let src = "pub mod outer {\n    pub enum Status {\n        Active,\n    }\n    pub mod inner {\n        pub fn check() -> u32 {\n            let _s = Status::Active;\n            0\n        }\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/lib.rs",
        src,
        "let _s = Status::Active",
        0,
        "Status::Active",
    );
    assert_not_boundary(&v, "rust `Status::Active` in parent scope");
}

#[test]
fn rust_genuinely_external_qualified_reference_stays_boundary() {
    // `ext_crate::Widget` names a crate the workspace does not index: still a
    // confident boundary (the separator fix must not over-suppress).
    let src = "pub fn build() -> ext_crate::Widget {\n    todo!()\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\next_crate = \"1\"\n",
        )
        .file("src/lib.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/lib.rs",
        src,
        "ext_crate::Widget",
        0,
        "ext_crate::Widget",
    );
    assert_boundary(&v, "rust genuinely-external `ext_crate::Widget`");
}

// ===========================================================================
// C++
// ===========================================================================

#[test]
fn cpp_qualified_type_in_enclosing_scope_is_not_boundary() {
    // `outer::Inner` resolves through the normal owner-member path even with an
    // unresolved include present — never a boundary.
    let src = "#include \"missing.h\"\n\nnamespace outer {\nstruct Inner {};\nstruct User { outer::Inner make(); };\n}\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", src)
        .build();
    let v = loc(
        project.root(),
        "main.cpp",
        src,
        "outer::Inner make()",
        0,
        "Inner",
    );
    assert_not_boundary(
        &v,
        "cpp `outer::Inner` qualified type in enclosing namespace",
    );
}

#[test]
fn cpp_unknown_type_with_unresolved_include_stays_boundary() {
    // Negative control: `Gadget` is declared nowhere and the include is
    // unresolved — a genuine include boundary.
    let src = "#include \"missing.h\"\n\nnamespace outer {\nstruct User { Gadget make(); };\n}\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", src)
        .build();
    let v = loc(
        project.root(),
        "main.cpp",
        src,
        "struct User { Gadget make(); }",
        0,
        "Gadget",
    );
    assert_boundary(&v, "cpp unknown type `Gadget` with unresolved include");
}

#[test]
fn cpp_qualified_nested_namespace_type_resolves() {
    // ISSUE #1163 (was the pinned false boundary at cpp.rs:2402): a `::`-qualified
    // reference to a type in a *sibling* nested namespace
    // (`inner::Gizmo` -> `outer::inner::Gizmo`) is workspace-owned and now RESOLVES.
    // With interned segments authoritative end-to-end (M4), C++'s mixed-separator
    // store no longer blocks it: the namespace-outward net re-interns the reference
    // with namespace-aware kinds and descends the scope's `::`-joined namespace
    // head, composing the exact stored key `outer::inner.Gizmo`. This was the
    // plan's acceptance payoff — the false-boundary pin flips to real resolution.
    let src = "#include \"missing.h\"\n\nnamespace outer {\nnamespace inner {\nstruct Gizmo {};\n}\nnamespace deep {\nstruct User { inner::Gizmo make(); };\n}\n}\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cpp", src)
        .build();
    let v = loc(
        project.root(),
        "main.cpp",
        src,
        "struct User { inner::Gizmo make(); }",
        0,
        "Gizmo",
    );
    assert_not_boundary(&v, "cpp sibling-namespace `inner::Gizmo` (#1163)");
    assert_eq!(
        status(&v),
        "resolved",
        "cpp `inner::Gizmo` must resolve to the workspace-owned `outer::inner::Gizmo`: {v}"
    );
    assert_eq!(
        v["results"][0]["definitions"][0]["fqn"].as_str(),
        Some("outer::inner.Gizmo"),
        "resolves to the sibling-namespace type: {v}"
    );
}
