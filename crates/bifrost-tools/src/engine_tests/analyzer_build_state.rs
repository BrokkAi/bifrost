use brokk_bifrost_analysis::analyzer::CodeUnitIndex;
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter;

#[test]
fn deeply_nested_java_declarations_render_in_source_order() {
    const DEPTH: usize = 384;
    let mut source = String::new();
    for depth in 0..DEPTH {
        source.push_str(&format!("class Nested{depth} {{\n"));
    }
    for _ in 0..DEPTH {
        source.push_str("}\n");
    }

    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Nested.java", &source)
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let root = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "Nested0")
        .expect("outer class declaration");

    let mut expected = String::new();
    for depth in 0..DEPTH {
        expected.push_str(&"  ".repeat(depth));
        expected.push_str(&format!("class Nested{depth} {{\n"));
    }
    for depth in (0..DEPTH).rev() {
        expected.push_str(&"  ".repeat(depth));
        expected.push_str("}\n");
    }
    expected.pop();
    let actual = analyzer.get_skeleton(&root).expect("rendered skeleton");
    let first_mismatch = actual
        .bytes()
        .zip(expected.bytes())
        .position(|(actual, expected)| actual != expected);
    assert_eq!(
        actual,
        expected,
        "actual length {}, expected length {}, first mismatch {first_mismatch:?}",
        actual.len(),
        expected.len()
    );

    let siblings = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file(
            "Siblings.java",
            "class First { int firstField; void firstMethod() {} }\nclass Second { String secondField; void secondMethod() {} }\n",
        )
        .build();
    let analyzer = TreeSitterAnalyzer::new(siblings.project_dyn(), JavaAdapter);
    let declarations = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| matches!(unit.identifier(), "First" | "Second"))
        .collect::<Vec<_>>();

    let normal = declarations
        .iter()
        .map(|unit| analyzer.get_skeleton(unit).expect("normal skeleton"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        normal,
        "class First {\n  int firstField;\n  void firstMethod()\n}\nclass Second {\n  String secondField;\n  void secondMethod()\n}"
    );

    let headers = declarations
        .iter()
        .map(|unit| analyzer.get_skeleton_header(unit).expect("header skeleton"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        headers,
        "class First {\n  int firstField;\n  [...]\n}\nclass Second {\n  String secondField;\n  [...]\n}"
    );
}

#[test]
fn c_and_cpp_refusals_are_both_reported_for_their_storage_languages() {
    let long_declaration = format!("int {} = 0;\n", "x".repeat(17_000));
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file("bad.c", &long_declaration)
        .file("bad.cpp", &long_declaration)
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);

    let refusals = analyzer
        .selected_source_admission_refusals()
        .expect("both source refusals are recorded");
    let paths = refusals
        .into_iter()
        .map(|row| row.file.rel_path().to_path_buf())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        paths,
        [
            std::path::PathBuf::from("bad.c"),
            std::path::PathBuf::from("bad.cpp")
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn relevant_java_overlay_blocks_package_inventory_completeness() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("src/Widget.java", "class Widget {}\n")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let overlay = std::sync::Arc::new(brokk_bifrost_analysis::OverlayProject::new(
        fixture.project_dyn(),
    ));
    assert!(overlay.set(
        fixture.file("src/Widget.java").abs_path(),
        "class Widget { class Edited {} }\n".to_owned()
    ));
    assert!(overlay.set(
        ProjectFile::new(fixture.root(), "tools/helper.py").abs_path(),
        "value = 1\n".to_owned()
    ));
    assert!(overlay.set(
        ProjectFile::new(fixture.root(), "tools/Added.java").abs_path(),
        "package tools; class Added {}\n".to_owned()
    ));
    let overlay_analyzer = analyzer.clone_with_project(std::sync::Arc::new(overlay.snapshot()));

    assert!(!overlay_analyzer.workspace_package_inventory_complete());
    assert!(
        overlay_analyzer
            .get_all_declarations()
            .iter()
            .any(|unit| { unit.identifier() == "Added" && unit.fq_name() == "tools.Added" })
    );
}

#[test]
fn callable_metrics_visit_nested_callables_after_the_first_child() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file(
            "src/Nested.java",
            "class Nested { class Inner { void first() { if (true) {} } void second() { if (true) { if (true) {} } } } }\n",
        )
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let metrics = analyzer
        .callable_metrics_for_file(&fixture.file("src/Nested.java"))
        .expect("authoritative Java callable metrics");
    let top_level = analyzer
        .top_level_declarations(&fixture.file("src/Nested.java"))
        .into_iter()
        .map(|unit| unit.identifier().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let names = metrics
        .into_iter()
        .map(|(unit, _)| unit.identifier().to_owned())
        .collect::<std::collections::BTreeSet<_>>();

    assert!(
        !top_level.contains("first"),
        "top-level declarations: {top_level:?}"
    );
    assert!(
        !top_level.contains("second"),
        "top-level declarations: {top_level:?}"
    );
    assert!(names.contains("first"), "callable metrics: {names:?}");
    assert!(names.contains("second"), "callable metrics: {names:?}");
}

#[test]
fn java_record_keeps_its_declaration_syntax_kind() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("src/Point.java", "package sample; record Point(int x) {}\n")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    let record = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "Point")
        .expect("record declaration");

    assert_eq!(
        analyzer.declaration_syntax_kind(&record),
        Some("record_declaration")
    );
}

#[test]
fn proof_required_python_callable_metrics_obey_the_admission_budget() {
    let payload = "x".repeat(17_000);
    let source = format!("def measured():\n    if True:\n        pass\n    return \"{payload}\"\n");
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
        .file("sample.py", &source)
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), PythonAdapter::default());

    let metrics = analyzer
        .callable_metrics_for_file(&fixture.file("sample.py"))
        .expect("authoritative Python callable metrics");
    assert!(
        metrics
            .iter()
            .any(|(unit, _)| unit.identifier() == "measured")
    );
}

#[test]
fn claimed_cpp_second_pass_keeps_first_pass_refusal_incomplete() {
    let long_declaration = format!("int {} = 0;\n", "x".repeat(17_000));
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cc",
            "#include \"claimed.inc\"\nint main() { return 0; }\n",
        )
        .file("claimed.inc", "int claimed() { return 1; }\n")
        .file("refused.cc", &long_declaration)
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);

    assert!(!analyzer.workspace_package_inventory_complete());
    assert!(
        analyzer
            .get_all_declarations()
            .iter()
            .any(|unit| unit.identifier() == "claimed")
    );
}
