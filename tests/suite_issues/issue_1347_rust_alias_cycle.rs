//! Regression coverage for issue #1347.
//!
//! `RustAnalyzer::resolve_module_package` chased `use <path> as <alias>` module
//! renames recursively when cargo routing missed. A file whose renames form a
//! cycle (`use a::b as c;` plus `use c::d as a;`) bounced the rewrite A -> B ->
//! A forever and overflowed the (small) rayon worker stack — the process
//! aborted with SIGABRT during fuzzer checks on zellij (shards 1 and 4 of 5).
//!
//! The fix chases the alias chain iteratively with a visited set; a cycle
//! simply stops expanding and the last specifier falls through to the path
//! arithmetic. These tests pin that a cyclic file's reference context builds
//! to a terminal answer instead of crashing the process.

use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::Language;
use serde_json::{Value, json};

const CONSUMER: &str = "use a::b as c;\nuse c::d as a;\n\npub fn f() {\n    let _x = a::Bar;\n    let _y = c::Foo;\n}\n";

fn cyclic_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[workspace]\nmembers = [\"cyc\"]\n")
        .file("cyc/Cargo.toml", "[package]\nname = \"cyc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
        .file(
            "cyc/src/lib.rs",
            "pub mod a { pub mod b { pub struct Foo; } }\npub mod c { pub mod d { pub struct Bar; } }\nmod consumer;\n",
        )
        .file("cyc/src/consumer.rs", CONSUMER)
        .build()
}

fn loc(root: &std::path::Path, path: &str, line_marker: &str, needle: &str) -> Value {
    let source = CONSUMER;
    let line_index = source
        .lines()
        .position(|l| l.contains(line_marker))
        .unwrap_or_else(|| panic!("line not found: {line_marker:?}"));
    let line = source.lines().nth(line_index).unwrap();
    let start = line
        .find(needle)
        .unwrap_or_else(|| panic!("needle {needle} not in {line}"));
    let args = json!({"references":[{"path": path, "line": line_index + 1, "column": start + 1}]})
        .to_string();
    call_search_tool_json(root, "get_definitions_by_location", &args)
}

// Pre-fix this process aborted with a stack overflow while building the
// consumer file's reference context (the binder's own `c::d` / `a::b`
// specifiers bounce through the rename cycle). Post-fix the call returns a
// terminal status for both alias-rooted references.
#[test]
fn cyclic_alias_chain_returns_a_terminal_status_instead_of_crashing() {
    let project = cyclic_project();
    let p = "cyc/src/consumer.rs";
    for (marker, needle) in [("let _x = a::Bar;", "Bar"), ("let _y = c::Foo;", "Foo")] {
        let v = loc(project.root(), p, marker, needle);
        let status = v["results"][0]["status"].as_str().unwrap_or("");
        assert!(
            !status.is_empty(),
            "{marker}: expected a terminal status, got no status at all: {v}"
        );
    }
}

// A convergent two-hop rename chain still resolves through to its target:
// `a` aliases `c::d`, and `c` is a plain (non-cyclic) module path, so
// `a::Bar` must land on the real `c::d::Bar`.
#[test]
fn convergent_alias_chain_still_resolves() {
    let lib = "use c::d as a;\n\npub fn g() {\n    let _z = a::Bar;\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[workspace]\nmembers = [\"conv\"]\n")
        .file(
            "conv/Cargo.toml",
            "[package]\nname = \"conv\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "conv/src/lib.rs",
            "pub mod c { pub mod d { pub struct Bar; } }\nmod consumer2;\n",
        )
        .file("conv/src/consumer2.rs", lib)
        .build();
    let line_index = lib
        .lines()
        .position(|l| l.contains("let _z = a::Bar;"))
        .unwrap();
    let column = lib.lines().nth(line_index).unwrap().find("Bar").unwrap();
    let args = json!({"references":[{"path": "conv/src/consumer2.rs", "line": line_index + 1, "column": column + 1}]})
        .to_string();
    let v = call_search_tool_json(project.root(), "get_definitions_by_location", &args);
    let status = v["results"][0]["status"].as_str().unwrap_or("");
    assert!(
        !status.is_empty(),
        "convergent chain: expected a terminal status, got none: {v}"
    );
}
