use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, ProjectFile, Range, TestProject};
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

fn autocomplete_names_of(analyzer: &JavaAnalyzer, query: &str) -> Vec<String> {
    analyzer
        .autocomplete_definitions(query)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect()
}

fn file_by_name(analyzer: &JavaAnalyzer, name: &str) -> ProjectFile {
    ProjectFile::new(analyzer.project().root().to_path_buf(), name)
}

fn byte_range(source: &str, start: usize, end: usize) -> Range {
    let start_line = source[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let end_line = source[..end].bytes().filter(|byte| *byte == b'\n').count() + 1;
    Range {
        start_byte: start,
        end_byte: end,
        start_line,
        end_line,
    }
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

#[test]
fn autocomplete_matches_java_search_expectations() {
    let analyzer = fixture_analyzer();

    let field_names: BTreeSet<_> = autocomplete_names_of(&analyzer, "D.field1")
        .into_iter()
        .collect();
    assert!(field_names.contains("D.field1"));

    let method_names = autocomplete_names_of(&analyzer, "method1");
    let method_set: BTreeSet<_> = method_names.iter().cloned().collect();
    assert!(method_set.contains("A.method1"));
    let position = method_names
        .iter()
        .position(|name| name == "A.method1")
        .unwrap();
    assert!(position < 3);

    let camel_set: BTreeSet<_> = autocomplete_names_of(&analyzer, "CC").into_iter().collect();
    assert!(camel_set.contains("CamelClass"));

    let hierarchical_set: BTreeSet<_> = autocomplete_names_of(&analyzer, "A.method2")
        .into_iter()
        .collect();
    assert!(hierarchical_set.contains("A.method2"));

    let upper = autocomplete_names_of(&analyzer, "E");
    let lower = autocomplete_names_of(&analyzer, "e");
    let upper_set: BTreeSet<_> = upper.clone().into_iter().collect();
    let lower_set: BTreeSet<_> = lower.into_iter().collect();
    assert_eq!(upper_set, lower_set);
    assert!(upper.contains(&"E".to_string()));
    assert!(upper.contains(&"UseE".to_string()));
}

#[test]
fn autocomplete_finds_record_components_as_fields() {
    let analyzer = fixture_analyzer();

    let full_query: BTreeSet<_> = autocomplete_names_of(&analyzer, "C.Foo.x")
        .into_iter()
        .collect();
    assert!(full_query.contains("C.Foo.x"));

    let short_query: BTreeSet<_> = autocomplete_names_of(&analyzer, "x").into_iter().collect();
    assert!(short_query.contains("C.Foo.x"));
}

#[test]
fn enclosing_code_unit_by_byte_range_matches_java_search_tests() {
    let analyzer = fixture_analyzer();

    let a_file = file_by_name(&analyzer, "A.java");
    let a_source = a_file.read_to_string().unwrap();
    let method1_start = a_source.find("System.out.println(\"hello\");").unwrap();
    let method1_end = method1_start + "System.out.println(\"hello\");".len();
    assert_eq!(
        "A.method1",
        analyzer
            .enclosing_code_unit(&a_file, &byte_range(&a_source, method1_start, method1_end))
            .unwrap()
            .fq_name()
    );

    let method7_start = a_source.find("public void method7()").unwrap();
    let method7_end = method7_start + "public void method7()".len();
    assert_eq!(
        "A.AInner.AInnerInner.method7",
        analyzer
            .enclosing_code_unit(&a_file, &byte_range(&a_source, method7_start, method7_end))
            .unwrap()
            .fq_name()
    );

    let d_file = file_by_name(&analyzer, "D.java");
    let d_source = d_file.read_to_string().unwrap();
    let d_start = d_source.find("field1 = 42;").unwrap();
    let d_end = d_start + "field1 = 42;".len();
    assert_eq!(
        "D.methodD2",
        analyzer
            .enclosing_code_unit(&d_file, &byte_range(&d_source, d_start, d_end))
            .unwrap()
            .fq_name()
    );

    let c_file = file_by_name(&analyzer, "C.java");
    let c_source = c_file.read_to_string().unwrap();
    let c_start = c_source.find("int x").unwrap();
    let c_end = c_start + "int x".len();
    assert_eq!(
        "C.Foo.x",
        analyzer
            .enclosing_code_unit(&c_file, &byte_range(&c_source, c_start, c_end))
            .unwrap()
            .fq_name()
    );
}

#[test]
fn enclosing_code_unit_rejects_empty_ranges() {
    let analyzer = fixture_analyzer();
    let file = file_by_name(&analyzer, "A.java");
    let source = file.read_to_string().unwrap();
    let idx = source.find("class A").unwrap();
    let empty = Range {
        start_byte: idx,
        end_byte: idx,
        start_line: 1,
        end_line: 1,
    };

    assert!(analyzer.enclosing_code_unit(&file, &empty).is_none());
}
