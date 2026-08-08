//! Include-driven language inference for C++ (#1837).
//!
//! `.inc` is a generic extension -- legacy PHP source uses it too -- so no
//! language claims it in `Language::extensions()`. abseil and friends still put
//! real declarations in `.inc` fragments and pull them in with `#include`.
//! These tests pin the claim rule: a workspace file becomes analyzable as C++
//! when an analyzed C++ file's quoted `#include` resolves to it AND no language
//! claims its extension, transitively.

use crate::common::InlineTestProject;
use brokk_bifrost::{
    CodeUnit, CodeUnitIndex, CppAnalyzer, IAnalyzer, ImportAnalysisProvider, Language,
};
use std::collections::BTreeSet;

fn declaration_names(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units.into_iter().map(|unit| unit.fq_name()).collect()
}

fn analyzed_rel_paths(analyzer: &CppAnalyzer) -> BTreeSet<String> {
    analyzer
        .analyzed_files()
        .into_iter()
        .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect()
}

#[test]
fn included_inc_fragment_is_indexed_and_visible_from_its_includer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cc",
            "#include \"tables.inc\"\n\nint main() { return LookupEntry(0); }\n",
        )
        .file(
            "tables.inc",
            "struct TableEntry {\n  int code;\n};\n\nint LookupEntry(int index) { return index; }\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let inc = project.file("tables.inc");
    let names = declaration_names(analyzer.get_declarations(&inc));
    assert!(
        names.iter().any(|name| name.contains("TableEntry")),
        "declarations in the claimed fragment: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.contains("LookupEntry")),
        "declarations in the claimed fragment: {names:?}"
    );
    assert!(
        analyzed_rel_paths(&analyzer).contains("tables.inc"),
        "analyzed files: {:?}",
        analyzed_rel_paths(&analyzer)
    );

    // The include-visibility surface every C++ resolution consults: a
    // reference in `main.cc` reaches the fragment's declarations.
    let imported = analyzer.imported_code_units_of(&project.file("main.cc"));
    let imported_names = declaration_names(imported.as_ref().clone());
    assert!(
        imported_names
            .iter()
            .any(|name| name.contains("LookupEntry")),
        "code units visible to main.cc: {imported_names:?}"
    );

    assert!(
        !analyzer.get_definitions("LookupEntry").is_empty(),
        "the claimed fragment's function must be a workspace definition"
    );
}

#[test]
fn claims_are_transitive_through_claimed_fragments() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "a.cc",
            "#include \"a.inc\"\n\nint main() { return Beta(); }\n",
        )
        .file("a.inc", "#include \"b.inc\"\n\nint Alpha() { return 1; }\n")
        .file("b.inc", "int Beta() { return 2; }\n")
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let analyzed = analyzed_rel_paths(&analyzer);
    assert!(analyzed.contains("a.inc"), "analyzed files: {analyzed:?}");
    assert!(analyzed.contains("b.inc"), "analyzed files: {analyzed:?}");
    assert!(
        !analyzer.get_definitions("Beta").is_empty(),
        "the transitively claimed fragment's function must be a workspace definition"
    );
}

#[test]
fn unreferenced_inc_file_is_not_indexed() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("main.cc", "int main() { return 0; }\n")
        .file("orphan.inc", "int Orphaned() { return 7; }\n")
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let analyzed = analyzed_rel_paths(&analyzer);
    assert!(
        !analyzed.contains("orphan.inc"),
        "nothing includes orphan.inc; analyzed files: {analyzed:?}"
    );
    assert!(
        analyzer.get_definitions("Orphaned").is_empty(),
        "an unreferenced fragment contributes no declarations"
    );
}

#[test]
fn include_of_a_php_owned_extension_is_not_claimed() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cc",
            "#include \"lib.php\"\n\nint main() { return 0; }\n",
        )
        .file("lib.php", "<?php function phpHelper() { return 1; } ?>\n")
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let analyzed = analyzed_rel_paths(&analyzer);
    assert!(
        !analyzed.contains("lib.php"),
        "PHP owns `.php` in the extension registry; analyzed files: {analyzed:?}"
    );
    assert!(
        analyzer
            .get_declarations(&project.file("lib.php"))
            .is_empty(),
        "a file another language claims must never be adopted by C++"
    );
}

#[test]
fn editing_a_claimed_fragment_republishes_its_declaration_surface() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cc",
            "#include \"tables.inc\"\n\nint main() { return 0; }\n",
        )
        .file("tables.inc", "int FirstEntry() { return 1; }\n")
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    assert!(!analyzer.get_definitions("FirstEntry").is_empty());

    let inc = project.file("tables.inc");
    inc.write("int FirstEntry() { return 1; }\nint SecondEntry() { return 2; }\n")
        .unwrap();
    let updated = analyzer.update(&BTreeSet::from([inc.clone()]));

    let names = declaration_names(updated.get_declarations(&inc));
    assert!(
        names.iter().any(|name| name.contains("SecondEntry")),
        "declarations after the edit: {names:?}"
    );
    assert!(
        !updated.get_definitions("SecondEntry").is_empty(),
        "the new declaration must be a workspace definition"
    );
}

#[test]
fn removing_the_include_line_drops_the_claim() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cc",
            "#include \"tables.inc\"\n\nint main() { return 0; }\n",
        )
        .file("tables.inc", "int FirstEntry() { return 1; }\n")
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    assert!(!analyzer.get_definitions("FirstEntry").is_empty());

    let main = project.file("main.cc");
    main.write("int main() { return 0; }\n").unwrap();
    let updated = analyzer.update(&BTreeSet::from([main.clone()]));

    let analyzed = analyzed_rel_paths(&updated);
    assert!(
        !analyzed.contains("tables.inc"),
        "the last include naming the fragment is gone; analyzed files: {analyzed:?}"
    );
    assert!(
        updated.get_definitions("FirstEntry").is_empty(),
        "an unclaimed fragment's declarations must leave the index"
    );
}

#[test]
fn claimed_fragment_that_cannot_parse_standalone_reports_parse_errors() {
    // A fragment whose enclosing braces live in the includer. Claimed files
    // parse standalone and best-effort: this must flow through the typed
    // parse-error path, not panic, and must not disturb the other files.
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cc",
            "struct Holder {\n#include \"members.inc\"\n};\n\nint main() { return 0; }\n",
        )
        .file("members.inc", "  int alpha;\n  int beta;\n};\n\n)))\n")
        .file("other.cc", "int Untouched() { return 3; }\n")
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let inc = project.file("members.inc");
    let errors = analyzer.parse_errors(&inc);
    assert!(
        errors.is_some_and(|errors| !errors.is_empty()),
        "a fragment that cannot parse standalone must report typed parse errors"
    );
    assert!(
        !analyzer.get_definitions("Untouched").is_empty(),
        "an unparseable claimed fragment must not disturb the other analyzed files"
    );
}

#[test]
fn claim_set_does_not_depend_on_file_presentation_order() {
    let files: [(&str, &str); 4] = [
        (
            "main.cc",
            "#include \"a.inc\"\n\nint main() { return 0; }\n",
        ),
        ("a.inc", "#include \"b.inc\"\n\nint Alpha() { return 1; }\n"),
        ("b.inc", "int Beta() { return 2; }\n"),
        ("orphan.inc", "int Orphan() { return 3; }\n"),
    ];

    let build = |order: &[usize]| -> BTreeSet<String> {
        let mut builder = InlineTestProject::with_language(Language::Cpp);
        for index in order {
            let (path, contents) = files[*index];
            builder = builder.file(path, contents);
        }
        let project = builder.build();
        let analyzer = CppAnalyzer::from_project(project.project().clone());
        analyzed_rel_paths(&analyzer)
    };

    let forward = build(&[0, 1, 2, 3]);
    let reversed = build(&[3, 2, 1, 0]);
    let shuffled = build(&[2, 0, 3, 1]);
    assert_eq!(forward, reversed, "claim set must be order-free");
    assert_eq!(forward, shuffled, "claim set must be order-free");
    assert!(forward.contains("a.inc"), "{forward:?}");
    assert!(forward.contains("b.inc"), "{forward:?}");
    assert!(!forward.contains("orphan.inc"), "{forward:?}");
}
