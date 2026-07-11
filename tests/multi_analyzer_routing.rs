mod common;

use brokk_bifrost::{
    AnalyzerConfig, AnalyzerDelegate, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer,
    ProjectFile, TestProject,
};
use common::InlineTestProject;
use std::collections::{BTreeMap, BTreeSet};

fn java_project(files: &[(&str, &str)]) -> (tempfile::TempDir, TestProject) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(contents)
            .unwrap();
    }

    (temp, TestProject::new(root, Language::Java))
}

#[test]
fn language_from_extension_matches_supported_values() {
    assert_eq!(Language::Java, Language::from_extension("java"));
    assert_eq!(Language::JavaScript, Language::from_extension(".jsx"));
    assert_eq!(Language::TypeScript, Language::from_extension("tsx"));
    assert_eq!(Language::Cpp, Language::from_extension("hpp"));
    assert_eq!(Language::None, Language::from_extension("unknown"));
}

#[test]
fn multi_analyzer_routes_java_queries_and_capabilities() {
    let (_temp, project) = java_project(&[(
        "pkg/TestClass.java",
        "package pkg; import java.util.List; public class TestClass { @org.junit.jupiter.api.Test void testMethod() {} List<String> values; }",
    )]);
    let java = JavaAnalyzer::from_project(project);
    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::Java(java),
    )]));

    let file = ProjectFile::new(multi.project().root().to_path_buf(), "pkg/TestClass.java");
    let class_unit = multi
        .get_definitions("pkg.TestClass")
        .into_iter()
        .next()
        .unwrap();

    let top_level = multi.top_level_declarations(&file);
    assert!(top_level.contains(&class_unit));
    assert!(
        multi
            .get_skeleton(&class_unit)
            .unwrap()
            .contains("testMethod")
    );
    assert!(multi.contains_tests(&file));
    assert!(multi.import_analysis_provider().is_some());
    assert!(multi.type_hierarchy_provider().is_some());
    assert!(multi.test_detection_provider().is_some());

    let imports = multi
        .import_analysis_provider()
        .unwrap()
        .relevant_imports_for(&class_unit);
    assert!(imports.iter().any(|value| value.contains("java.util.List")));
}

#[test]
fn workspace_analyzer_routes_inferred_ruby_and_python_files() {
    let project = InlineTestProject::new()
        .file(
            "app/service.rb",
            r#"
class Service
  def call
  end
end
"#,
        )
        .file("pkg/tool.py", "def helper():\n    return 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    assert_eq!(
        BTreeSet::from([Language::Python, Language::Ruby]),
        analyzer.languages()
    );

    let ruby_file = project.file("app/service.rb");
    let ruby_declarations = analyzer.top_level_declarations(&ruby_file);
    assert!(
        ruby_declarations
            .iter()
            .any(|unit| unit.identifier() == "Service"),
        "{ruby_declarations:?}"
    );
    assert!(!analyzer.contains_tests(&project.file("pkg/tool.py")));
    let python_file = project.file("pkg/tool.py");
    let python_declarations = analyzer.top_level_declarations(&python_file);
    assert!(
        python_declarations
            .iter()
            .any(|unit| unit.identifier() == "helper"),
        "{python_declarations:?}"
    );
}

#[test]
fn multi_analyzer_handles_unknown_extensions_conservatively() {
    let (_temp, project) = java_project(&[("TestClass.java", "public class TestClass {}")]);
    let multi = MultiAnalyzer::with_java(JavaAnalyzer::from_project(project));
    let unknown_file = ProjectFile::new(multi.project().root().to_path_buf(), "script.unknown");

    assert!(multi.top_level_declarations(&unknown_file).is_empty());
    assert!(multi.import_statements(&unknown_file).is_empty());
    assert!(!multi.contains_tests(&unknown_file));
    assert!(multi.is_access_expression(&unknown_file, 0, 0));
}

#[test]
fn multi_analyzer_get_test_modules_uses_delegate_logic() {
    let (_temp, project) = java_project(&[
        (
            "src/com/example/TestClass.java",
            "package com.example; public class TestClass {}",
        ),
        (
            "src/com/example/Other.java",
            "package com.example; public class Other {}",
        ),
    ]);
    let multi = MultiAnalyzer::with_java(JavaAnalyzer::from_project(project));
    let files = vec![
        ProjectFile::new(
            multi.project().root().to_path_buf(),
            "src/com/example/TestClass.java",
        ),
        ProjectFile::new(
            multi.project().root().to_path_buf(),
            "src/com/example/Other.java",
        ),
    ];

    assert_eq!(
        vec!["com.example".to_string()],
        multi.get_test_modules(&files)
    );
}
