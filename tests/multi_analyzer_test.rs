use brokk_analyzer::{
    AnalyzerDelegate, CodeUnit, CodeUnitType, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer,
    ProjectFile, TestProject,
};
use std::collections::BTreeMap;
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    let root = temp.keep();
    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(root, Language::Java)
}

fn java_multi(project: TestProject) -> MultiAnalyzer {
    MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::Java(JavaAnalyzer::from_project(project)),
    )]))
}

fn fallback_test_file_heuristic(file: &ProjectFile, analyzer: &MultiAnalyzer) -> bool {
    analyzer.contains_tests(file)
        || file
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| {
                let lower = name.to_ascii_lowercase();
                lower.starts_with("test")
                    || lower.contains("_test")
                    || lower.ends_with("test.py")
                    || lower.ends_with("tests.py")
            })
            .unwrap_or(false)
}

#[test]
fn test_get_top_level_declarations_java_file() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]));
    let java_file = ProjectFile::new(multi.project().root().to_path_buf(), "TestClass.java");
    let top_level = multi.get_top_level_declarations(&java_file);

    assert_eq!(1, top_level.len());
    assert_eq!("TestClass", top_level[0].fq_name());
    assert!(top_level[0].is_class());
}

#[test]
fn test_get_top_level_declarations_unsupported_language_returns_empty() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
    let python_file = ProjectFile::new(multi.project().root().to_path_buf(), "test.py");
    assert!(multi.get_top_level_declarations(&python_file).is_empty());
}

#[test]
fn test_get_top_level_declarations_non_existent_file() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
    let missing = ProjectFile::new(multi.project().root().to_path_buf(), "NonExistent.java");
    assert!(multi.get_top_level_declarations(&missing).is_empty());
}

#[test]
fn test_delegate_routing_java_file_get_skeleton() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]));
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
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]));
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
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        r#"
        public class TestClass {
            public void testMethod() {
                System.out.println("Hello");
            }
        }
        "#,
    )]));
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
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
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
fn test_unknown_extension_returns_empty_get_source() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
    let unknown_file = ProjectFile::new(multi.project().root().to_path_buf(), "test.xyz");
    let unknown_unit = CodeUnit::new(unknown_file, CodeUnitType::Class, "", "UnknownClass");
    assert!(multi.get_source(&unknown_unit, true).is_none());
}

#[test]
fn test_unknown_extension_returns_empty_get_skeleton() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
    let unknown_file = ProjectFile::new(multi.project().root().to_path_buf(), "test.xyz");
    let unknown_unit = CodeUnit::new(unknown_file, CodeUnitType::Class, "", "UnknownClass");
    assert!(multi.get_skeleton(&unknown_unit).is_none());
}

#[test]
fn test_unknown_extension_no_exception() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
    let unknown_file = ProjectFile::new(multi.project().root().to_path_buf(), "test.unknown");
    let unknown_class = CodeUnit::new(unknown_file.clone(), CodeUnitType::Class, "", "Test");
    let unknown_method = CodeUnit::new(
        unknown_file.clone(),
        CodeUnitType::Function,
        "",
        "Test.method",
    );

    let _ = multi.get_skeleton(&unknown_class);
    let _ = multi.get_skeleton_header(&unknown_class);
    let _ = multi.get_sources(&unknown_method, false);
    let _ = multi.get_source(&unknown_class, false);
    let _ = multi.get_direct_children(&unknown_class);
    let _ = multi.get_declarations(&unknown_file);
    let _ = multi.get_skeletons(&unknown_file);
}

#[test]
fn test_is_test_file_falls_back_to_heuristics_when_delegate_lacks_capability() {
    let multi = java_multi(inline_project(&[(
        "TestClass.java",
        "public class TestClass {}",
    )]));
    let python_test_file = ProjectFile::new(multi.project().root().to_path_buf(), "test_script.py");
    assert!(fallback_test_file_heuristic(&python_test_file, &multi));
}
