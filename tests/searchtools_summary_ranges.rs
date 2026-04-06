use brokk_analyzer::{
    GoAnalyzer, JavaAnalyzer, Language, TestProject,
    searchtools::{FilePatternsParams, SummaryElement, get_file_summaries},
};

fn java_fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

fn go_fixture_analyzer() -> GoAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-go")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Go);
    GoAnalyzer::from_project(project)
}

fn render_summary_element(element: &SummaryElement) -> String {
    let mut lines = element.text.lines();
    let first_line = lines.next().unwrap_or_default();
    let prefix = if element.start_line == element.end_line {
        format!("{}: {}", element.start_line, first_line)
    } else {
        format!("{}..{}: {}", element.start_line, element.end_line, first_line)
    };

    std::iter::once(prefix)
        .chain(lines.map(str::to_string))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn file_summaries_preserve_fixture_line_numbers() {
    let analyzer = java_fixture_analyzer();
    let result = get_file_summaries(
        &analyzer,
        FilePatternsParams {
            file_patterns: vec!["A.java".to_string()],
        },
    );

    assert!(result.not_found.is_empty());
    assert_eq!(1, result.summaries.len());

    let summary = &result.summaries[0];
    assert_eq!("A.java", summary.path);
    assert_eq!("A.java", summary.label);

    let rendered: Vec<_> = summary
        .elements
        .iter()
        .map(render_summary_element)
        .collect();
    assert!(rendered.contains(&"3..52: public class A".to_string()));
    assert!(rendered.contains(&"4..6: void method1()".to_string()));
    assert!(rendered.contains(&"8..10: public String method2(String input)".to_string()));
    assert!(
        rendered.contains(&"12..15: public String method2(String input, int otherInput)".to_string())
    );
    assert!(rendered.contains(&"17..19: public Function<Integer, Integer> method3()".to_string()));
    assert!(
        rendered.contains(&"21..23: public static int method4(double foo, Integer bar)".to_string())
    );
    assert!(rendered.contains(&"39..45: public class AInner".to_string()));
    assert!(rendered.contains(&"40..44: public class AInnerInner".to_string()));
    assert!(rendered.contains(&"41..43: public void method7()".to_string()));
    assert!(rendered.contains(&"47: public static class AInnerStatic".to_string()));
    assert!(rendered.contains(&"49..51: private void usesInnerClass()".to_string()));

    assert!(
        summary
            .elements
            .iter()
            .all(|element| !element.text.contains("[...]"))
    );
    assert!(
        summary
            .elements
            .iter()
            .all(|element| !element.text.lines().any(|line| line.trim() == "}"))
    );
}

#[test]
fn go_file_summaries_use_full_declaration_ranges() {
    let analyzer = go_fixture_analyzer();
    let result = get_file_summaries(
        &analyzer,
        FilePatternsParams {
            file_patterns: vec!["declarations.go".to_string()],
        },
    );

    assert!(result.not_found.is_empty());
    assert_eq!(1, result.summaries.len());

    let summary = &result.summaries[0];
    assert_eq!("declarations.go", summary.path);
    assert_eq!("declarations.go", summary.label);

    let rendered: Vec<_> = summary
        .elements
        .iter()
        .map(render_summary_element)
        .collect();

    assert!(rendered.contains(&"6..8: func MyTopLevelFunction(param int) string".to_string()));
    assert!(rendered.contains(&"10..12: type MyStruct struct".to_string()));
    assert!(rendered.contains(&"14..16: type MyInterface interface".to_string()));
    assert!(rendered.contains(&"19..21: func (s MyStruct) GetFieldA() int".to_string()));
    assert!(rendered.contains(&"34: func anotherFunc()".to_string()));
}

#[test]
fn summary_renderer_uses_ranges_for_multiline_elements() {
    let rendered = render_summary_element(&SummaryElement {
        path: "A.java".to_string(),
        start_line: 12,
        end_line: 14,
        text: "class Foo(\n  x: int,\n  y: int".to_string(),
    });

    assert_eq!("12..14: class Foo(\n  x: int,\n  y: int", rendered);
}
