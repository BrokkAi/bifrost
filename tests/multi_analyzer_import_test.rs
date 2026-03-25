use brokk_analyzer::{
    AnalyzerDelegate, GoAnalyzer, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ProjectFile,
    PythonAnalyzer, TestProject,
};
use std::collections::{BTreeMap, BTreeSet};
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    let root = temp.keep();
    for (path, contents) in files {
        ProjectFile::new(root.clone(), path).write(*contents).unwrap();
    }
    TestProject::new(root, Language::Java)
}

#[test]
fn test_delegation_to_java_analyzer() {
    let project = inline_project(&[(
        "JavaClass.java",
        r#"
        import java.util.List;
        public class JavaClass {
            private List<String> items;
        }
        "#,
    )]);

    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
    )]));

    let java_file = ProjectFile::new(project.root_path().to_path_buf(), "JavaClass.java");
    let provider = multi.import_analysis_provider().unwrap();
    let java_imports = provider.import_info_of(&java_file);
    assert_eq!(1, java_imports.len());
    assert_eq!("List", java_imports[0].identifier.as_deref().unwrap());

    let java_unit = multi
        .get_declarations(&java_file)
        .into_iter()
        .find(|cu| cu.short_name() == "JavaClass")
        .unwrap();
    let relevant = provider.relevant_imports_for(&java_unit);
    assert!(relevant.iter().any(|value| value.contains("java.util.List")));
}

#[test]
fn test_delegation_to_python_analyzer() {
    let project = inline_project(&[(
        "script.py",
        r#"
        import os
        def python_fn():
            print(os.name)
        "#,
    )]);

    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Python,
        AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.clone())),
    )]));

    let python_file = ProjectFile::new(project.root_path().to_path_buf(), "script.py");
    let provider = multi.import_analysis_provider().unwrap();
    let imports = provider.import_info_of(&python_file);
    assert!(imports.iter().any(|import| import.identifier.as_deref() == Some("os")));

    let python_unit = multi
        .get_declarations(&python_file)
        .into_iter()
        .find(|cu| cu.short_name() == "python_fn")
        .unwrap();
    let _ = provider.relevant_imports_for(&python_unit);
}

#[test]
fn test_delegation_routes_to_correct_language() {
    let project = inline_project(&[
        (
            "JavaClass.java",
            r#"
            import java.util.List;
            public class JavaClass {
                private List<String> items;
            }
            "#,
        ),
        (
            "script.py",
            r#"
            import os
            def python_fn():
                print(os.name)
            "#,
        ),
    ]);

    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Python,
            AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.clone())),
        ),
    ]));

    let provider = multi.import_analysis_provider().unwrap();
    let java_file = ProjectFile::new(project.root_path().to_path_buf(), "JavaClass.java");
    let python_file = ProjectFile::new(project.root_path().to_path_buf(), "script.py");

    let java_imports = provider.import_info_of(&java_file);
    assert_eq!(1, java_imports.len());
    assert_eq!("List", java_imports[0].identifier.as_deref().unwrap());

    let python_imports = provider.import_info_of(&python_file);
    assert!(python_imports.iter().any(|import| import.identifier.as_deref() == Some("os")));

    let java_unit = multi
        .get_declarations(&java_file)
        .into_iter()
        .find(|cu| cu.short_name() == "JavaClass")
        .unwrap();
    let relevant_java = provider.relevant_imports_for(&java_unit);
    assert!(relevant_java.iter().any(|value| value.contains("java.util.List")));

    python_file
        .write("import os\ndef python_fn():\n    print(os.name)\n")
        .unwrap();
    let changed = BTreeSet::from([python_file.clone()]);
    let updated = multi.update(&changed);
    let updated_provider = updated.import_analysis_provider().unwrap();
    let updated_python_unit = updated
        .get_declarations(&python_file)
        .into_iter()
        .find(|cu| cu.short_name() == "python_fn")
        .unwrap();
    let relevant_python = updated_provider.relevant_imports_for(&updated_python_unit);
    assert!(relevant_python.iter().any(|value| value.contains("import os")));
}

#[test]
fn test_three_way_routing_java_python_go() {
    let project = inline_project(&[
        (
            "main.go",
            r#"
            package main
            import "fmt"
            func main() { fmt.Println() }
            "#,
        ),
        (
            "lib.py",
            r#"
            import math
            def f():
                return math.sqrt(2)
            "#,
        ),
        (
            "C.java",
            r#"
            import java.util.Set;
            class C { Set s; }
            "#,
        ),
    ]);

    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Python,
            AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Go,
            AnalyzerDelegate::Go(GoAnalyzer::from_project(project.clone())),
        ),
    ]));
    let provider = multi.import_analysis_provider().unwrap();

    let go_file = ProjectFile::new(project.root_path().to_path_buf(), "main.go");
    let py_file = ProjectFile::new(project.root_path().to_path_buf(), "lib.py");
    let java_file = ProjectFile::new(project.root_path().to_path_buf(), "C.java");

    let go_imports = provider.import_info_of(&go_file);
    assert!(go_imports.iter().any(|import| import.raw_snippet.contains("fmt")));

    let py_imports = provider.import_info_of(&py_file);
    assert!(py_imports.iter().any(|import| import.identifier.as_deref() == Some("math")));

    let java_unit = multi
        .get_declarations(&java_file)
        .into_iter()
        .find(|cu| cu.short_name() == "C")
        .unwrap();
    let java_relevant = provider.relevant_imports_for(&java_unit);
    assert!(java_relevant.iter().any(|value| value.contains("java.util.Set")));
}
