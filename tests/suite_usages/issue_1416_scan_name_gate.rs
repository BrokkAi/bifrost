//! #1416: the Rust usage scan skips resolution for tokens whose written name
//! cannot denote the target. These fixtures walk every shape that must survive
//! the gate, plus the shadowing shape that must not produce a hit.
//!
//! `matches_path`/`matches_identifier` carry a `debug_assert` that runs the full
//! resolution whenever the gate skips a node, so a debug test run also proves
//! the gate never hides a hit anywhere in these fixtures -- not just at the
//! sites asserted below.

use crate::common::InlineTestProject;
use brokk_bifrost::{Language, SearchToolsService};
use serde_json::Value;

const TARGET: &str = "src/target.rs";

fn scan(symbol: &str) -> Value {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"gatefix\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .file(
            "src/lib.rs",
            "pub mod target;\npub mod reexport;\npub mod callers;\npub mod qualifier;\n",
        )
        .file(
            TARGET,
            "pub fn collect_it(value: i32) -> i32 {\n    value\n}\n\npub struct Holder;\n\nimpl Holder {\n    pub fn make() -> i32 {\n        7\n    }\n}\n",
        )
        .file(
            "src/reexport.rs",
            "pub use crate::target::collect_it;\npub use crate::target::collect_it as gather_it;\npub use crate::target::Holder;\n",
        )
        .file(
            "src/callers.rs",
            concat!(
                "use crate::target::collect_it;\n",                    // 1: import hit
                "use crate::target::collect_it as aliased;\n",         // 2: aliased import hit
                "use crate::reexport;\n",                              // 3
                "\n",
                "macro_rules! call_it {\n",
                "    () => {\n",
                "        crate::target::collect_it(6)\n",              // 7: token-tree hit
                "    };\n",
                "}\n",
                "\n",
                "pub fn direct() -> i32 {\n",
                "    collect_it(1)\n",                                 // 12: direct call
                "}\n",
                "\n",
                "pub fn aliased_call() -> i32 {\n",
                "    aliased(2)\n",                                    // 16: aliased call
                "}\n",
                "\n",
                "pub fn reexport_path() -> i32 {\n",
                "    reexport::collect_it(3)\n",                       // 20: re-export path
                "}\n",
                "\n",
                "pub fn alias_reexport_path() -> i32 {\n",
                "    reexport::gather_it(4)\n",                        // 24: aliased re-export
                "}\n",
                "\n",
                "pub fn via_macro() -> i32 {\n",
                "    call_it!()\n",
                "}\n",
                "\n",
                "pub fn shadowed() -> i32 {\n",
                "    fn collect_it(value: i32) -> i32 {\n",            // 32: local shadow
                "        value + 1\n",
                "    }\n",
                "    collect_it(5)\n",                                 // 35: must NOT hit
                "}\n",
            ),
        )
        .file(
            "src/qualifier.rs",
            "use crate::reexport::Holder;\n\npub fn qualified() -> i32 {\n    Holder::make()\n}\n",
        )
        .build();

    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("failed to build searchtools service over inline project");
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            &format!(r#"{{"symbols":["{symbol}"],"include_tests":true}}"#),
        )
        .expect("scan_usages_by_reference call failed");
    serde_json::from_str(&payload).expect("scan_usages_by_reference returned invalid JSON")
}

/// Every `(path, line)` the scan reported, flattened out of the file groups.
fn hit_sites(value: &Value) -> Vec<(String, u64)> {
    let mut sites = Vec::new();
    for entry in value["results"].as_array().into_iter().flatten() {
        for group in entry["files"].as_array().into_iter().flatten() {
            let path = group["path"].as_str().unwrap_or_default().to_string();
            for hit in group["hits"].as_array().into_iter().flatten() {
                let line = hit["line"].as_u64().expect("hit carries a line");
                sites.push((path.clone(), line));
                // A clustered hit reports its span rather than each line.
                if let Some(count) = hit["hit_count"].as_u64() {
                    assert!(count >= 1, "clustered hit must count at least one site");
                }
            }
        }
    }
    sites.sort();
    sites
}

#[test]
fn name_gate_keeps_every_shape_that_reaches_a_function_target() {
    let value = scan("collect_it");
    let sites = hit_sites(&value);

    assert_eq!("found", value["results"][0]["status"], "payload: {value:#}");

    let caller_lines: Vec<u64> = sites
        .iter()
        .filter(|(path, _)| path.ends_with("callers.rs"))
        .map(|(_, line)| *line)
        .collect();

    // Every call shape must survive the gate. The aliased shapes are the ones
    // that spell a name the target does not own, so they are what proves the
    // gate consults the import/alias closure rather than the target name alone.
    assert_eq!(
        vec![7, 12, 16, 20, 24],
        caller_lines,
        "expected the macro token-tree reference (7), direct call (12), aliased \
         import call (16), re-export path call (20) and aliased re-export path \
         call (24), and nothing else; payload: {value:#}"
    );

    // The local `fn collect_it` shadows the import, so its call site belongs to
    // a different function and must not be attributed to the target. Pinned
    // explicitly because it is the one shape the gate must *not* let through.
    assert!(
        !caller_lines.contains(&35),
        "shadowed local call at callers.rs:35 must not be a hit; sites={sites:?}"
    );
}

#[test]
fn name_gate_keeps_a_type_reached_as_a_path_qualifier() {
    // `Holder::make()` names the target type only in a non-terminal segment, so
    // the gate must admit interior positions for path-qualifier targets.
    let value = scan("Holder");
    let sites = hit_sites(&value);

    assert_ne!(
        "failure", value["results"][0]["status"],
        "payload: {value:#}"
    );
    assert!(
        sites.iter().any(|(path, _)| path.ends_with("qualifier.rs")),
        "path-qualifier reference in qualifier.rs was dropped; sites={sites:?} payload: {value:#}"
    );
}
