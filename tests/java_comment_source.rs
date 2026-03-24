use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, TestProject};

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

#[test]
fn includes_class_javadocs_and_annotations() {
    let analyzer = fixture_analyzer();
    let class_cu = analyzer
        .get_definitions("AnnotatedClass")
        .into_iter()
        .next()
        .unwrap();
    let source = analyzer.get_source(&class_cu, true).unwrap();

    assert!(source.contains("/**"));
    assert!(source.contains("A comprehensive test class with various annotations"));
    assert!(source.contains("@author Test Author"));
    assert!(source.contains("@CustomAnnotation(value = \"class-level\", priority = 1)"));
    assert!(source.contains("public class AnnotatedClass"));
}

#[test]
fn includes_method_javadocs_before_annotations() {
    let analyzer = fixture_analyzer();
    let method = analyzer
        .get_definitions("AnnotatedClass.toString")
        .into_iter()
        .next()
        .unwrap();
    let source = analyzer.get_source(&method, true).unwrap();

    assert!(source.contains("Gets the current configuration value"));
    assert!(source.contains("@return the configuration value, never null"));
    assert!(source.contains("@Deprecated(since = \"1.1\")"));
    assert!(source.contains("@Override"));
}

#[test]
fn preserves_indentation_for_inner_class_comment_block() {
    let analyzer = fixture_analyzer();
    let inner = analyzer
        .get_definitions("AnnotatedClass.InnerHelper")
        .into_iter()
        .next()
        .unwrap();
    let source = analyzer.get_source(&inner, true).unwrap();

    assert!(source.starts_with("    "));
    assert!(source.contains("Inner class with its own documentation"));
    assert!(source.contains("@CustomAnnotation(\"inner-class\")"));
}

#[test]
fn inline_javadoc_does_not_pull_in_preceding_code() {
    let analyzer = fixture_analyzer();
    let method = analyzer
        .get_definitions("InlineComment.methodAfterInlineJavadoc")
        .into_iter()
        .next()
        .unwrap();
    let source = analyzer.get_source(&method, true).unwrap();

    assert!(source.contains("/** Inline Javadoc on same line as code */"));
    assert!(!source.contains("private int other"));
    assert!(!source.contains("= 1;"));
}
