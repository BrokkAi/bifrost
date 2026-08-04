use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, CodeUnitType, ImportAnalysisProvider, JavaAnalyzer, Language,
    MultiAnalyzer, ProjectFile, ScalaAnalyzer, WorkspaceAnalyzer,
};
use std::collections::BTreeMap;

use crate::common::InlineTestProject;

fn built_java_project(files: &[(&str, &str)]) -> crate::common::BuiltInlineTestProject {
    files
        .iter()
        .fold(
            InlineTestProject::with_language(Language::Java),
            |project, (path, contents)| project.file(*path, *contents),
        )
        .build()
}

fn java_multi(project: &crate::common::BuiltInlineTestProject) -> MultiAnalyzer {
    MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.project().clone())),
    )]))
}

#[test]
fn test_get_top_level_declarations_java_file() {
    let project = built_java_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]);
    let multi = java_multi(&project);
    let java_file = ProjectFile::new(multi.project().root().to_path_buf(), "TestClass.java");
    let top_level = multi.top_level_declarations(&java_file);

    assert_eq!(1, top_level.len());
    assert_eq!("TestClass", top_level[0].fq_name());
    assert!(top_level[0].is_class());
}

#[test]
fn test_get_top_level_declarations_non_existent_file() {
    let project = built_java_project(&[("TestClass.java", "public class TestClass {}")]);
    let multi = java_multi(&project);
    let missing = ProjectFile::new(multi.project().root().to_path_buf(), "NonExistent.java");
    assert!(multi.top_level_declarations(&missing).is_empty());
}

#[test]
fn test_delegate_routing_java_file_get_skeleton() {
    let project = built_java_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]);
    let multi = java_multi(&project);
    let class_unit = multi
        .get_definitions("TestClass")
        .into_iter()
        .next()
        .unwrap();
    let skeleton = multi.get_skeleton(&class_unit).unwrap();

    assert!(skeleton.contains("TestClass"));
    assert!(skeleton.contains("testMethod"));
}

#[test]
fn test_delegate_routing_java_file_get_sources() {
    let project = built_java_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]);
    let multi = java_multi(&project);
    let method_unit = multi
        .get_definitions("TestClass.testMethod")
        .into_iter()
        .next()
        .unwrap();
    let sources = multi.get_sources(&method_unit, true);

    assert!(!sources.is_empty());
    assert!(sources.iter().any(|source| source.contains("testMethod")));
}

#[test]
fn test_delegate_routing_java_file_get_source() {
    let project = built_java_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]);
    let multi = java_multi(&project);
    let class_unit = multi
        .get_definitions("TestClass")
        .into_iter()
        .next()
        .unwrap();
    let source = multi.get_source(&class_unit, true).unwrap();

    assert!(source.contains("TestClass"));
    assert!(source.contains("testMethod"));
}

#[test]
fn test_unknown_extension_returns_empty_get_sources() {
    let project = built_java_project(&[("TestClass.java", "public class TestClass {}")]);
    let multi = java_multi(&project);
    let unknown_file = ProjectFile::new(multi.project().root().to_path_buf(), "test.xyz");
    let unknown_unit = CodeUnit::new(
        unknown_file,
        CodeUnitType::Function,
        "",
        "SomeClass.someMethod",
    );
    assert!(multi.get_sources(&unknown_unit, true).is_empty());
}

#[test]
fn inferred_inline_project_builds_multi_workspace_analyzer() {
    let project = InlineTestProject::new()
        .file("TestClass.java", "public class TestClass {}")
        .file("helpers.py", "VALUE = 1\n")
        .build();
    let workspace = project.workspace_analyzer(brokk_bifrost::AnalyzerConfig::default());

    assert!(matches!(workspace, WorkspaceAnalyzer::Multi(_)));
    assert_eq!(
        std::collections::BTreeSet::from([Language::Java, Language::Python]),
        workspace.analyzer().languages()
    );
}

#[test]
fn scala_import_analysis_does_not_pollute_non_scala_candidates() {
    let project = InlineTestProject::new()
        .file("A.java", "class A {}")
        .file("Default.scala", "class Default\n")
        .build();
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.project().clone())),
        ),
        (
            Language::Scala,
            AnalyzerDelegate::Scala(ScalaAnalyzer::from_project(project.project().clone())),
        ),
    ]));
    let java_file = ProjectFile::new(project.root().to_path_buf(), "A.java");

    assert!(
        multi.referencing_files_of(&java_file).is_empty(),
        "Scala import analysis should ignore non-Scala target files"
    );
}
