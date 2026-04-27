use brokk_analyzer::{
    AnalyzerDelegate, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, MultiAnalyzer,
    Project, ProjectFile, TestProject, TypeAliasProvider,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn go_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-go").unwrap(),
        Language::Go,
    )
}

fn inline_go_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Go)
}

#[test]
fn go_fixture_declarations_match_expected_shapes() {
    let analyzer = GoAnalyzer::from_project(go_fixture_project());
    let root = analyzer.project().root().to_path_buf();
    let declarations = ProjectFile::new(root, "declarations.go");

    let file_declarations = analyzer.get_declarations(&declarations);
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg.MyTopLevelFunction")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg.MyStruct")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg.MyStruct.GetFieldA")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg.MyStruct.FieldA")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg.MyInterface.DoSomething")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg._module_.MyGlobalVar")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg._module_.MyGlobalConst")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg._module_.StringAlias")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg.GroupedNamedType")
    );
    assert!(
        file_declarations
            .iter()
            .any(|cu| cu.fq_name() == "declpkg._module_.GroupedAlias")
    );

    let my_struct = analyzer
        .get_definitions("declpkg.MyStruct")
        .into_iter()
        .next()
        .unwrap();
    let string_alias = analyzer
        .get_definitions("declpkg._module_.StringAlias")
        .into_iter()
        .next()
        .unwrap();
    let grouped_alias = analyzer
        .get_definitions("declpkg._module_.GroupedAlias")
        .into_iter()
        .next()
        .unwrap();

    assert!(
        analyzer
            .get_skeleton(&my_struct)
            .unwrap()
            .contains("FieldA int")
    );
    assert!(analyzer.is_type_alias(&string_alias));
    assert!(analyzer.is_type_alias(&grouped_alias));
}

#[test]
fn go_import_resolution_and_test_detection_work() {
    let project = inline_go_project(&[
        (
            "fmt/fmt.go",
            r#"
            package fmt
            func Println() {}
            "#,
        ),
        (
            "os/os.go",
            r#"
            package os
            func Exit(code int) {}
            "#,
        ),
        (
            "main.go",
            r#"
            package main
            import (
                "fmt"
                alias "os"
                . "fmt"
                _ "image/png"
            )
            func main() { fmt.Println(); alias.Exit(0); Println() }
            "#,
        ),
        (
            "pkg/ptr.go",
            r#"
            package foo
            import "testing"
            func TestPointer(t *testing.T) {}
            "#,
        ),
        (
            "pkg/bench.go",
            r#"
            package foo
            import "testing"
            func BenchmarkOnly(b *testing.B) {}
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone());
    let main_file = ProjectFile::new(project.root().to_path_buf(), "main.go");
    let test_file = ProjectFile::new(project.root().to_path_buf(), "pkg/ptr.go");
    let bench_file = ProjectFile::new(project.root().to_path_buf(), "pkg/bench.go");

    let imports = analyzer.imported_code_units_of(&main_file);
    assert!(imports.iter().any(|cu| cu.package_name() == "fmt"));
    assert!(imports.iter().any(|cu| cu.package_name() == "os"));
    assert!(!imports.iter().any(|cu| cu.package_name() == "png"));

    assert!(analyzer.contains_tests(&test_file));
    assert!(!analyzer.contains_tests(&bench_file));

    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Go,
        AnalyzerDelegate::Go(analyzer.clone()),
    )]));
    assert!(multi.contains_tests(&test_file));
    assert_eq!(BTreeSet::from([Language::Go]), multi.languages());
}

#[test]
fn go_module_helpers_and_updates_match_expected_behavior() {
    assert_eq!(".", GoAnalyzer::format_test_module(Path::new(".")));
    assert_eq!(".", GoAnalyzer::format_test_module(Path::new("/")));
    assert_eq!(
        "./callbacks",
        GoAnalyzer::format_test_module(Path::new("callbacks"))
    );
    assert_eq!(
        "./a/b/c",
        GoAnalyzer::format_test_module(Path::new("a\\b\\c"))
    );

    let root: PathBuf = if cfg!(windows) {
        PathBuf::from("C:\\tmp\\go-modules")
    } else {
        PathBuf::from("/tmp/go-modules")
    };
    let modules = GoAnalyzer::get_test_modules_static(&[
        ProjectFile::new(root.clone(), "callbacks/test.go"),
        ProjectFile::new(root.clone(), "main_test.go"),
    ]);
    assert_eq!(vec![".".to_string(), "./callbacks".to_string()], modules);

    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "a.go");
    file.write(
        r#"
        package main
        func Foo() int { return 1 }
        "#,
    )
    .unwrap();

    let analyzer = GoAnalyzer::from_project(TestProject::new(root, Language::Go));
    assert!(!analyzer.get_definitions("main.Foo").is_empty());
    assert!(analyzer.get_definitions("main.Bar").is_empty());

    file.write(
        r#"
        package main
        func Foo() int { return 1 }
        func Bar() int { return 2 }
        "#,
    )
    .unwrap();

    let updated = analyzer.update(&BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("main.Bar").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("main.Foo").is_empty());
}
