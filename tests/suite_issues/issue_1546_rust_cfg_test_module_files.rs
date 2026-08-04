//! Rust's sibling test-module layout hid a file's test-ness from every
//! per-file surface -- #1546.
//!
//! `#[cfg(test)] mod tests;` puts the gate on the *parent's* declaration. The
//! declared file itself carries no path convention (`Language::Rust` has no
//! test filename rule at all), no test directory segment, and -- for the plain
//! helper functions it defines -- no test attribute either. So
//! `most_relevant_files(include_tests=false)` returned `lexer/tests.rs` and
//! `classify_test_files` called it Ambiguous.
//!
//! The signal lives in the module-declaration graph the Rust analyzer already
//! builds. This suite covers the two derivations that graph makes possible:
//! transitive inheritance down an un-gated child edge, and the per-declaration
//! `in_test_region` taint that a test-only file confers on its units.
//!
//! The `most_relevant_files` and `classify_test_files` surfaces themselves,
//! plus the un-gated and composite-`cfg` near-misses, live in
//! `suite_symbols::most_relevant_files`.

use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::searchtools::{ClassifyTestFilesParams, TestFileKind, classify_test_files};
use brokk_bifrost::{IAnalyzer, Language, RustAnalyzer};

/// `#[cfg(test)] mod checks;` -> `checks/mod.rs` -> un-gated `mod helpers;` ->
/// `checks/helpers.rs`. The directory is deliberately *not* named `tests`, so
/// no path convention can rescue the classification.
fn nested_test_module_project() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .file("src/lib.rs", "pub mod lexer;\n")
        .file(
            "src/lexer/mod.rs",
            "#[cfg(test)]\nmod checks;\n\npub mod cursor;\n\npub fn tokenize(input: &str) -> usize {\n    cursor::advance(input)\n}\n",
        )
        .file(
            "src/lexer/cursor.rs",
            "pub fn advance(input: &str) -> usize {\n    input.len()\n}\n",
        )
        .file(
            "src/lexer/checks/mod.rs",
            "mod helpers;\n\n#[test]\nfn tokenizes() {\n    assert_eq!(2, helpers::run(\"ab\"));\n}\n",
        )
        .file(
            "src/lexer/checks/helpers.rs",
            "pub fn run(input: &str) -> usize {\n    crate::lexer::tokenize(input)\n}\n",
        )
        .build()
}

#[test]
fn test_only_module_propagates_to_its_ungated_children() {
    let project = nested_test_module_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let classifications = classify_test_files(
        &analyzer,
        ClassifyTestFilesParams {
            file_paths: vec![
                "src/lexer/checks/mod.rs".to_string(),
                "src/lexer/checks/helpers.rs".to_string(),
                "src/lexer/cursor.rs".to_string(),
            ],
        },
    );

    assert_eq!(
        TestFileKind::Test,
        classifications.classifications["src/lexer/checks/mod.rs"].kind,
        "the directly gated target runs tests"
    );
    assert_eq!(
        TestFileKind::TestSupport,
        classifications.classifications["src/lexer/checks/helpers.rs"].kind,
        "an un-gated child of a test-only module is test-only, and defines no test itself"
    );
    assert_eq!(
        TestFileKind::Ambiguous,
        classifications.classifications["src/lexer/cursor.rs"].kind,
        "an un-gated sibling of the gated module is untouched"
    );
}

/// The per-declaration taint (`in_test_region`, #1102) has to agree with the
/// per-file verdict: a plain helper `fn` in a test-only file carries no test
/// attribute of its own, so only the file-level derivation can taint it. This
/// is what makes `analyze_diff --include_tests=false` and the symbol surfaces
/// drop it.
#[test]
fn declarations_in_a_test_only_module_are_in_a_test_region() {
    let project = nested_test_module_project();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let taint: std::collections::BTreeMap<String, bool> = analyzer
        .all_declarations()
        .filter(|unit| !unit.is_synthetic())
        .map(|unit| {
            (
                unit.short_name().to_string(),
                analyzer.in_test_region(&unit),
            )
        })
        .collect();

    assert_eq!(
        Some(&true),
        taint.get("run"),
        "an unattributed helper in a test-only module is still in a test region: {taint:?}"
    );
    assert_eq!(
        Some(&true),
        taint.get("tokenizes"),
        "the `#[test]` fn stays tainted: {taint:?}"
    );
    assert_eq!(
        Some(&false),
        taint.get("advance"),
        "production declarations must stay untainted: {taint:?}"
    );
    assert_eq!(
        Some(&false),
        taint.get("tokenize"),
        "the declaring module's own API must stay untainted: {taint:?}"
    );
}
