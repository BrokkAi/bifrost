//! C++17 nested namespace definitions (#1878).
//!
//! `namespace a::b { ... }` is defined to be exactly `namespace a { namespace b
//! { ... } }`: it declares BOTH `a` and `a::b`, and everything inside lands in
//! `a::b`. Bifrost must therefore extract the same declaration set from either
//! spelling, and a reference to `a::b::f` must resolve identically under both.

use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CppAnalyzer, Language};
use std::collections::BTreeSet;

const NESTED: &str = "namespace a::b {\nvoid f() {}\n}\n";
const EXPANDED: &str = "namespace a {\nnamespace b {\nvoid f() {}\n}\n}\n";
const CALLER: &str = "#include \"lib.h\"\n\nint main() { a::b::f(); return 0; }\n";

fn declaration_names(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units.into_iter().map(|unit| unit.fq_name()).collect()
}

fn project_with(declaration: &str) -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Cpp)
        .file("lib.h", declaration)
        .file("main.cc", CALLER)
        .build()
}

#[test]
fn nested_namespace_definition_declares_the_same_units_as_the_expanded_form() {
    let declarations = |source: &str| -> BTreeSet<String> {
        let project = project_with(source);
        let analyzer = CppAnalyzer::from_project(project.project().clone());
        declaration_names(analyzer.get_declarations(&project.file("lib.h")))
    };

    let nested = declarations(NESTED);
    let expanded = declarations(EXPANDED);
    assert_eq!(
        nested, expanded,
        "`namespace a::b` and `namespace a {{ namespace b }}` are the same C++ declaration"
    );
    // The shorthand used to declare only the innermost level, so `a` was
    // missing and the two spellings disagreed.
    assert_eq!(
        expanded,
        BTreeSet::from(["a".to_string(), "a::b".to_string(), "a::b.f".to_string()]),
        "one Module per namespace level, plus the function"
    );
}

#[test]
fn a_reference_resolves_identically_under_both_namespace_spellings() {
    // The resolution verdict for `a::b.f` plus every file carrying a proven
    // hit. An unresolvable symbol reports `not_found` and no hits at all.
    let resolve = |declaration: &str| -> (String, Vec<String>) {
        let project = project_with(declaration);
        let scan = call_tool(
            &project,
            "scan_usages_by_reference",
            &serde_json::json!({ "symbols": ["a::b.f"], "include_tests": true }).to_string(),
        );
        let result = &scan["results"][0];
        let status = result["status"].as_str().unwrap_or("<missing>").to_string();
        let files = result["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|file| file["hits"].as_array().is_some_and(|hits| !hits.is_empty()))
            .filter_map(|file| file["path"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        (status, files)
    };

    let nested = resolve(NESTED);
    let expanded = resolve(EXPANDED);
    assert_eq!(
        nested, expanded,
        "`a::b::f` must resolve the same way under either namespace spelling"
    );
    assert_eq!(
        ("found".to_string(), vec!["main.cc".to_string()]),
        expanded,
        "the baseline must resolve `a::b.f` to the call in main.cc"
    );
}
