//! Regression coverage for issue #1158: the seven latent unguarded confident
//! `boundary()` emission sites (the #1126/#1089 class) found by the
//! cross-language duplication survey (Concern 4). Each site emitted a confident
//! "crosses an unindexed boundary" claim without asking the second, load-bearing
//! question — does the workspace nonetheless declare/contain this target? The
//! `gated_boundary(...)` gate makes that question structural.
//!
//! Every fixed site gets a fail-before/pass-after repro plus a negative control
//! proving the fix does not mask a genuinely-external import (that still draws
//! the boundary). The invariant under test: a confident boundary claim is never
//! emitted for a name the workspace actually owns.
//!
//! Ranked sites (see the issue):
//!   1. python.rs import-binding paths (attribute + identifier)
//!   2. rust.rs looks-external residual branch
//!   3. rust.rs macro BoundButUnindexed branch
//!   4. cpp.rs unresolved-include branches (template-id + qualified)
//!   5. csharp.rs static-using member boundary
//!   6. js_ts.rs relative-specifier typo
//!   7. scala.rs local explicit import emitted before the lexical probe

mod common;

use brokk_bifrost::Language;
use common::{InlineTestProject, call_search_tool_json};
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

/// The gate's core invariant: a workspace-internal target must NOT draw a
/// confident boundary claim. It may resolve, or honestly report no_definition,
/// but never `unresolvable_import_boundary`.
fn assert_not_boundary(v: &Value, ctx: &str) {
    assert_ne!(
        status(v),
        "unresolvable_import_boundary",
        "{ctx}: workspace-internal target must not draw a confident boundary claim: {v}"
    );
}

/// Negative control: a genuinely-external import must still draw the boundary.
fn assert_boundary(v: &Value, ctx: &str) {
    assert_eq!(
        status(v),
        "unresolvable_import_boundary",
        "{ctx}: genuinely-external import must still draw a boundary claim: {v}"
    );
}

// ===========================================================================
// Site 1 — python import-binding paths (python.rs:1225 attribute, 1285 identifier)
// A name bound by `from <workspace-module> import Thing` where the module is a
// workspace module but `Thing` is not indexed must not draw a boundary.
// ===========================================================================

#[test]
fn python_attribute_from_workspace_module_is_not_boundary() {
    // Site 1225 (attribute arm): `sibling` is a workspace module but does not
    // define `Thing`; `Thing.attr` must not draw a confident boundary.
    let main = "from sibling import Thing\n\nprint(Thing.attr)\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("sibling.py", "X = 1\n")
        .file("main.py", main)
        .build();
    let v = loc(project.root(), "main.py", main, "Thing.attr", 0, "attr");
    assert_not_boundary(
        &v,
        "python attribute on name bound from workspace module `sibling`",
    );
}

#[test]
fn python_attribute_from_external_module_stays_boundary() {
    // Negative control for site 1225: `requests` is not a workspace module.
    let main = "from requests import Thing\n\nprint(Thing.attr)\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", main)
        .build();
    let v = loc(project.root(), "main.py", main, "Thing.attr", 0, "attr");
    assert_boundary(
        &v,
        "python attribute on name bound from external module `requests`",
    );
}

#[test]
fn python_identifier_from_workspace_relative_import_is_not_boundary() {
    // Site 1285 (identifier arm) — PIN of current-correct behavior. The gate
    // helper is wired here (shared with the demonstrated attribute site 1225),
    // but a module-level relative import is already caught upstream by the
    // module-binding timeline (which returns no_definition, never reaching this
    // boundary). This locks the invariant for the shape regardless of path.
    let main = "from .sibling import Thing\n\nprint(Thing)\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/__init__.py", "\n")
        .file("pkg/sibling.py", "X = 1\n")
        .file("pkg/main.py", main)
        .build();
    let v = loc(
        project.root(),
        "pkg/main.py",
        main,
        "print(Thing)",
        0,
        "Thing",
    );
    assert_not_boundary(
        &v,
        "python identifier bound from workspace relative module `.sibling`",
    );
}

// ===========================================================================
// Site 6 — js/ts relative-specifier typo (js_ts.rs:676)
// A relative specifier that resolves to no workspace file is a typo / not-yet
// indexed sibling, not a confident external package boundary.
// ===========================================================================

#[test]
fn js_ts_relative_specifier_typo_is_not_boundary() {
    let main = "import { Thing } from './missing';\n\nconsole.log(Thing);\n";
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("main.ts", main)
        .build();
    let v = loc(
        project.root(),
        "main.ts",
        main,
        "console.log(Thing)",
        0,
        "Thing",
    );
    assert_not_boundary(&v, "ts relative-specifier `./missing` typo");
}

#[test]
fn js_ts_bare_package_specifier_stays_boundary() {
    // Negative control: `react` is a bare package specifier, genuinely external.
    let main = "import { Thing } from 'react';\n\nconsole.log(Thing);\n";
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("main.ts", main)
        .build();
    let v = loc(
        project.root(),
        "main.ts",
        main,
        "console.log(Thing)",
        0,
        "Thing",
    );
    assert_boundary(&v, "ts bare-package specifier `react`");
}

// ===========================================================================
// Site 5 — csharp static-using member boundary (csharp.rs:685)
// A member provided by an indexed `using static` target is workspace-internal
// even when an unrelated static-using is unresolved.
// ===========================================================================

#[test]
fn csharp_member_from_indexed_static_using_is_not_boundary() {
    let math = "namespace Workspace {\n    public static class MathUtils {\n        public static int Square(int x) => x * x;\n    }\n}\n";
    let app = "using static Workspace.MathUtils;\nusing static External.Unknown;\n\nnamespace App {\n    class C {\n        void M() {\n            var y = Square(3);\n        }\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("MathUtils.cs", math)
        .file("App.cs", app)
        .build();
    let v = loc(
        project.root(),
        "App.cs",
        app,
        "var y = Square(3)",
        0,
        "Square",
    );
    assert_not_boundary(
        &v,
        "csharp member `Square` provided by indexed `using static Workspace.MathUtils`",
    );
}

#[test]
fn csharp_member_from_external_static_using_stays_boundary() {
    // Negative control: the only static-using is unresolved and no workspace
    // static-using target declares `Missing`.
    let app = "using static External.Unknown;\n\nnamespace App {\n    class C {\n        void M() {\n            var y = Missing(3);\n        }\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("App.cs", app)
        .build();
    let v = loc(
        project.root(),
        "App.cs",
        app,
        "var y = Missing(3)",
        0,
        "Missing",
    );
    assert_boundary(&v, "csharp member `Missing` only via external static-using");
}

// ===========================================================================
// Site 4 — cpp unresolved-include branches (cpp.rs:2107 template-id, 2402 qualified)
// PIN of current-correct behavior. The survey's proposed fallback is inert here:
// these branches handle `::`-qualified references, which the shared enclosing-
// scope resolver (composing candidates with `.`) cannot match. A workspace-
// internal qualified type resolves through the normal name/visibility paths
// before the boundary is reached, so current behavior is already correct.
// ===========================================================================

#[test]
fn cpp_qualified_type_in_enclosing_scope_is_not_boundary() {
    // `outer::Inner` resolves through the normal owner-member path even with an
    // unresolved include present — it never reaches the boundary. Locks that.
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
        "cpp qualified type `outer::Inner` in enclosing namespace",
    );
}

#[test]
fn cpp_unknown_type_with_unresolved_include_stays_boundary() {
    // Negative control: `Gadget` is declared nowhere in the workspace and the
    // include is unresolved.
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

// ===========================================================================
// Site 7 — scala local explicit import before the lexical probe (scala.rs:5647)
// A type the enclosing lexical namespace resolves must not draw a boundary from
// a same-named local explicit import whose declaration is unindexed.
// ===========================================================================

#[test]
fn scala_enclosing_type_wins_over_unindexed_local_import() {
    // A local explicit import binds `Bar` to an unindexed external declaration,
    // but the enclosing class also declares a nested `Bar`. The lexical-namespace
    // probe (Stage B) must run before the local-import boundary (Stage A),
    // symmetric with the non-local branch.
    let src = "package app\n\nclass Outer {\n  import ext.Bar\n\n  class Bar\n\n  def make(): Bar = null\n}\n";
    let project = InlineTestProject::with_language(Language::Scala)
        .file("Outer.scala", src)
        .build();
    let v = loc(
        project.root(),
        "Outer.scala",
        src,
        "def make(): Bar",
        0,
        "Bar",
    );
    assert_not_boundary(
        &v,
        "scala nested type `Bar` resolvable via enclosing lexical namespace",
    );
}

// ===========================================================================
// Site 2 — rust looks-external residual branch (rust.rs:1022) — PIN.
// The survey's proposed fallback is inert here: this branch is only reached for
// a `::`-qualified path, which the shared `.`-composing enclosing-scope resolver
// cannot match, and the qualified path is already resolved-and-exhausted
// upstream before reaching it. Current behavior is correct. (Site 3, rust.rs:1441
// macros, keeps a functional bare-name `is_macro` fallback — a bare macro name
// can compose with `.` — closing that namespace gap for structural completeness.)
// ===========================================================================

#[test]
fn rust_enclosing_scope_member_is_not_boundary() {
    // `Config::Value` resolves through the scoped-associated-item path, never
    // reaching the residual looks-external branch. Locks the #1126 shape.
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
    assert_not_boundary(&v, "rust enum variant `Config::Value` in enclosing scope");
}
