use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, TestProject};
use std::collections::BTreeSet;

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

fn names_of(analyzer: &JavaAnalyzer, pattern: &str) -> BTreeSet<String> {
    analyzer
        .search_definitions(pattern, false)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect()
}

#[test]
fn search_definitions_matches_basic_java_patterns() {
    let analyzer = fixture_analyzer();

    let e_class_names: BTreeSet<_> = analyzer
        .search_definitions("e", false)
        .into_iter()
        .filter(|code_unit| code_unit.is_class())
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(e_class_names.contains("E"));
    assert!(e_class_names.contains("UseE"));
    assert!(e_class_names.contains("AnonymousUsage"));
    assert!(e_class_names.contains("Interface"));

    let method1_names = names_of(&analyzer, "method1");
    assert!(method1_names.contains("A.method1"));

    let regex_names = names_of(&analyzer, "method.*1");
    assert!(regex_names.contains("A.method1"));
    assert!(regex_names.contains("D.methodD1"));
}

#[test]
fn search_definitions_is_case_insensitive() {
    let analyzer = fixture_analyzer();

    let upper_e = names_of(&analyzer, "E");
    let lower_e = names_of(&analyzer, "e");
    assert_eq!(upper_e, lower_e);
    assert!(upper_e.contains("E"));
    assert!(upper_e.contains("UseE"));
    assert!(upper_e.contains("Interface"));

    let mixed_use = names_of(&analyzer, "UsE");
    let lower_use = names_of(&analyzer, "use");
    assert_eq!(mixed_use, lower_use);
    assert!(mixed_use.contains("UseE"));
}

#[test]
fn search_definitions_handles_fields_nested_classes_and_missing_patterns() {
    let analyzer = fixture_analyzer();

    let field_names = names_of(&analyzer, ".*field.*");
    assert!(field_names.contains("D.field1"));
    assert!(field_names.contains("D.field2"));
    assert!(field_names.contains("E.iField"));
    assert!(field_names.contains("E.sField"));

    let inner_names = names_of(&analyzer, "Inner");
    assert!(inner_names.contains("A.AInner"));
    assert!(inner_names.contains("A.AInner.AInnerInner"));

    assert!(names_of(&analyzer, "NonExistentPatternXYZ123").is_empty());
}
