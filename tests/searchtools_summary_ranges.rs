use brokk_bifrost::{
    GoAnalyzer, JavaAnalyzer, JavascriptAnalyzer, Language, ScalaAnalyzer, TestProject,
    TypescriptAnalyzer,
    searchtools::{SummariesParams, SummaryElement, get_summaries},
};

mod common;
use common::InlineTestProject;

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
        format!(
            "{}..{}: {}",
            element.start_line, element.end_line, first_line
        )
    };

    std::iter::once(prefix)
        .chain(lines.map(str::to_string))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn file_summaries_preserve_fixture_line_numbers() {
    let analyzer = java_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["A.java".to_string()],
        },
    );

    assert!(result.not_found.is_empty());
    assert_eq!(1, result.summaries.len());

    let summary = &result.summaries[0];
    assert_eq!("A.java", summary.path);
    assert_eq!("A.java", summary.label);
    assert_eq!("import java.util.function.Function;", summary.preamble);

    let rendered: Vec<_> = summary
        .elements
        .iter()
        .map(render_summary_element)
        .collect();
    assert!(
        summary
            .elements
            .iter()
            .any(|element| element.symbol == "A" && element.kind == "class")
    );
    assert!(
        summary
            .elements
            .iter()
            .any(|element| element.symbol == "A.method2" && element.kind == "function")
    );
    assert!(rendered.contains(&"3..52: public class A".to_string()));
    assert!(rendered.contains(&"4..6: void method1()".to_string()));
    assert!(rendered.contains(&"8..10: public String method2(String input)".to_string()));
    assert!(
        rendered
            .contains(&"12..15: public String method2(String input, int otherInput)".to_string())
    );
    assert!(rendered.contains(&"17..19: public Function<Integer, Integer> method3()".to_string()));
    assert!(
        rendered
            .contains(&"21..23: public static int method4(double foo, Integer bar)".to_string())
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
fn get_summaries_accepts_mixed_file_and_class_targets() {
    let analyzer = java_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["A.java".to_string(), "A.AInner".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{:?}", result.not_found);
    assert!(result.ambiguous.is_empty(), "{:?}", result.ambiguous);
    assert!(
        result
            .summaries
            .iter()
            .any(|summary| summary.label == "A.java" && summary.path == "A.java")
    );
    assert!(
        result
            .summaries
            .iter()
            .any(|summary| summary.label == "A.AInner" && summary.path == "A.java")
    );
}

#[test]
fn get_summaries_reports_directory_targets_as_not_found() {
    let analyzer = go_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["anotherpkg".to_string()],
        },
    );

    assert_eq!(vec!["anotherpkg"], result.not_found);
    assert!(result.ambiguous.is_empty(), "{:?}", result.ambiguous);
    assert!(result.summaries.is_empty(), "{:?}", result.summaries);
}

#[test]
fn get_summaries_reports_workspace_root_directory_target_as_not_found() {
    let analyzer = go_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec![".".to_string()],
        },
    );

    assert_eq!(vec!["."], result.not_found);
    assert!(result.ambiguous.is_empty(), "{:?}", result.ambiguous);
    assert!(result.summaries.is_empty(), "{:?}", result.summaries);
}

#[test]
fn file_summaries_do_not_include_same_package_sibling_elements() {
    let analyzer = java_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["Packaged.java".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{:?}", result.not_found);
    assert_eq!(1, result.summaries.len());
    let summary = &result.summaries[0];
    assert_eq!("Packaged.java", summary.path);
    assert!(
        summary
            .elements
            .iter()
            .all(|element| element.path == "Packaged.java")
    );
    assert!(
        summary
            .elements
            .iter()
            .any(|element| element.symbol == "io.github.jbellis.brokk.Foo")
    );
    assert!(
        summary
            .elements
            .iter()
            .all(|element| element.symbol != "io.github.jbellis.brokk.PackagedSibling")
    );
}

#[test]
fn get_summaries_reports_unmatched_file_like_targets() {
    let analyzer = java_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["Missing.java".to_string()],
        },
    );

    assert!(result.summaries.is_empty());
    assert_eq!(vec!["Missing.java"], result.not_found);
    assert!(result.ambiguous.is_empty());
}

#[test]
fn go_file_summaries_use_full_declaration_ranges() {
    let analyzer = go_fixture_analyzer();
    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["declarations.go".to_string()],
        },
    );

    assert!(result.not_found.is_empty());
    assert_eq!(1, result.summaries.len());

    let summary = &result.summaries[0];
    assert_eq!("declarations.go", summary.path);
    assert_eq!("declarations.go", summary.label);
    assert_eq!("package declpkg", summary.preamble);

    let rendered: Vec<_> = summary
        .elements
        .iter()
        .map(render_summary_element)
        .collect();
    assert!(summary.elements.iter().any(
        |element| element.symbol.ends_with("MyTopLevelFunction") && element.kind == "function"
    ));
    assert!(
        summary
            .elements
            .iter()
            .any(|element| element.symbol.ends_with("MyStruct") && element.kind == "class")
    );

    assert!(
        rendered.contains(&"6..8: func MyTopLevelFunction(param int) string { ... }".to_string())
    );
    assert!(rendered.contains(&"10..12: MyStruct struct".to_string()));
    assert!(rendered.contains(&"14..16: MyInterface interface".to_string()));
    assert!(rendered.contains(&"19..21: func (s MyStruct) GetFieldA() int { ... }".to_string()));
    assert!(rendered.contains(&"34: func anotherFunc() { ... }".to_string()));
}

#[test]
fn get_summaries_accept_nested_scala_object_targets_in_idiomatic_and_jvm_forms() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "src/ai/brokk/ScalaObjects.scala",
            r#"package ai.brokk

object ir {
  object PrimOp {
    case object AsClockOp
    case object AsAsyncResetOp
  }
}

object InstanceChoiceControl {
  def select: Unit = {}
}
"#,
        )
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec![
                "ai.brokk.ir$.PrimOp$".to_string(),
                "ai.brokk.InstanceChoiceControl".to_string(),
            ],
        },
    );

    assert!(result.not_found.is_empty(), "{:?}", result.not_found);
    assert!(result.ambiguous.is_empty(), "{:?}", result.ambiguous);
    assert_eq!(2, result.summaries.len());
    assert!(
        result
            .summaries
            .iter()
            .flat_map(|summary| summary.elements.iter())
            .any(|element| element.symbol == "ai.brokk.ir.PrimOp.AsClockOp"
                && element.kind == "class"),
        "{:#?}",
        result.summaries
    );
    assert!(
        result
            .summaries
            .iter()
            .any(|summary| summary.label == "ai.brokk.ir.PrimOp"
                && summary.path == "src/ai/brokk/ScalaObjects.scala"),
        "{:#?}",
        result.summaries
    );
    assert!(
        result
            .summaries
            .iter()
            .any(|summary| summary.label == "ai.brokk.InstanceChoiceControl"
                && summary.elements.iter().any(|element| element.symbol
                    == "ai.brokk.InstanceChoiceControl.select"
                    && element.kind == "function")),
        "{:#?}",
        result.summaries
    );
}

#[test]
fn js_file_summaries_skip_synthetic_module_import_entries() {
    let project = common::InlineTestProject::with_language(Language::JavaScript)
        .file(
            "main.js",
            "import { absVal } from './abs';\n\nexport function run() {\n  return absVal(1);\n}\n",
        )
        .file(
            "abs.js",
            "export function absVal(value) {\n  return value;\n}\n",
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());

    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["main.js".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{:?}", result.not_found);
    assert_eq!(1, result.summaries.len());
    let summary = &result.summaries[0];
    assert!(
        summary
            .elements
            .iter()
            .all(|element| !(element.kind == "module" && element.text.contains("import "))),
        "{:?}",
        summary.elements
    );
    assert!(
        summary
            .elements
            .iter()
            .any(|element| element.symbol == "run" && element.kind == "function"),
        "{:?}",
        summary.elements
    );
}

#[test]
fn ts_file_summaries_skip_synthetic_module_import_entries() {
    let project = common::InlineTestProject::with_language(Language::TypeScript)
        .file(
            "main.ts",
            "import { absVal } from './abs';\n\nexport function run(): number {\n  return absVal(1);\n}\n",
        )
        .file("abs.ts", "export function absVal(value: number): number {\n  return value;\n}\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let result = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["main.ts".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{:?}", result.not_found);
    assert_eq!(1, result.summaries.len());
    let summary = &result.summaries[0];
    assert!(
        summary
            .elements
            .iter()
            .all(|element| !(element.kind == "module" && element.text.contains("import "))),
        "{:?}",
        summary.elements
    );
    assert!(
        summary
            .elements
            .iter()
            .any(|element| element.symbol == "run" && element.kind == "function"),
        "{:?}",
        summary.elements
    );
}

#[test]
fn summary_renderer_uses_ranges_for_multiline_elements() {
    let rendered = render_summary_element(&SummaryElement {
        path: "A.java".to_string(),
        symbol: "Foo".to_string(),
        kind: "class".to_string(),
        start_line: 12,
        end_line: 14,
        text: "class Foo(\n  x: int,\n  y: int".to_string(),
    });

    assert_eq!("12..14: class Foo(\n  x: int,\n  y: int", rendered);
}
