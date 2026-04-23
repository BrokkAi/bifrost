use brokk_analyzer::{
    GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, Project, ProjectFile, TestProject,
};
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Go)
}

#[test]
fn test_go_import_resolution_variants() {
    let project = inline_project(&[
        ("fmt/fmt.go", "package fmt\nfunc Println() {}\n"),
        ("os/os.go", "package os\nfunc Exit(code int) {}\n"),
        (
            "main.go",
            r#"
            package main
            import (
                "fmt"
                "os"
            )
            func main() { fmt.Println(); os.Exit(0) }
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone());
    let main_file = ProjectFile::new(project.root().to_path_buf(), "main.go");
    let resolved = analyzer.imported_code_units_of(&main_file);
    assert!(resolved.iter().any(|cu| cu.package_name() == "fmt"));
    assert!(resolved.iter().any(|cu| cu.package_name() == "os"));
    assert_eq!(
        vec!["import \"fmt\"".to_string(), "import \"os\"".to_string()],
        analyzer.import_statements_of(&main_file)
    );
}

#[test]
fn test_go_import_alias_dot_blank_comments_and_versioned_paths() {
    let project = inline_project(&[
        ("fmt/fmt.go", "package fmt\nfunc Println() {}\n"),
        (
            "vendor/gopkg.in/yaml.v3/yaml.go",
            "package yaml\nfunc Marshal(in any) ([]byte, error) { return nil, nil }\n",
        ),
        (
            "main.go",
            r#"
            package main
            import (
                f "fmt"
                . "fmt"
                _ "image/png"
            )
            func main() { f.Println(); Println() }
            "#,
        ),
        (
            "yaml_main.go",
            r#"
            package main
            import "gopkg.in/yaml.v3"
            func main() { yaml.Marshal(nil) }
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone());
    let main_file = ProjectFile::new(project.root().to_path_buf(), "main.go");
    let yaml_file = ProjectFile::new(project.root().to_path_buf(), "yaml_main.go");

    let resolved = analyzer.imported_code_units_of(&main_file);
    assert!(resolved.iter().any(|cu| cu.package_name() == "fmt"));
    assert!(!resolved.iter().any(|cu| cu.package_name() == "png"));

    let versioned = analyzer.imported_code_units_of(&yaml_file);
    assert!(
        versioned
            .iter()
            .any(|cu| cu.package_name() == "yaml" && cu.identifier() == "Marshal")
    );

    let infos = analyzer.import_info_of(&main_file);
    assert_eq!("f", infos[0].identifier.as_deref().unwrap());
    assert_eq!("f", infos[0].alias.as_deref().unwrap());
    assert_eq!(".", infos[1].identifier.as_deref().unwrap());
    assert_eq!("_", infos[2].identifier.as_deref().unwrap());
}

#[test]
fn test_go_relevant_imports_and_could_import_file() {
    let project = inline_project(&[
        ("fmt/f.go", "package fmt\nfunc Println() {}\n"),
        ("os/o.go", "package os\nfunc Exit(i int) {}\n"),
        (
            "main.go",
            r#"
            package main
            import "fmt"
            import "os"
            func main() { fmt.Println() }
            "#,
        ),
        ("pkg/utils/helper.go", "package utils\n"),
        (
            "importer.go",
            r#"
            package main
            import f "pkg/utils"
            func helper() {}
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone());
    let main_file = ProjectFile::new(project.root().to_path_buf(), "main.go");
    let main_fn = analyzer
        .get_declarations(&main_file)
        .into_iter()
        .find(|cu| cu.identifier() == "main")
        .unwrap();
    let relevant = analyzer.relevant_imports_for(&main_fn);
    assert!(relevant.contains("import \"fmt\""));
    assert!(!relevant.contains("import \"os\""));

    let importer = ProjectFile::new(project.root().to_path_buf(), "importer.go");
    let target = ProjectFile::new(project.root().to_path_buf(), "pkg/utils/helper.go");
    let imports = analyzer.import_info_of(&importer);
    assert!(analyzer.could_import_file(&importer, &imports, &target));
}

#[test]
fn test_go_referencing_files_uses_resolved_import_targets() {
    let project = inline_project(&[
        ("pkg/utils/helper.go", "package utils\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
            package main
            import f "pkg/utils"
            func main() { f.Helper() }
            "#,
        ),
    ]);
    let analyzer = GoAnalyzer::from_project(project.clone());
    let target = ProjectFile::new(project.root().to_path_buf(), "pkg/utils/helper.go");
    let consumer = ProjectFile::new(project.root().to_path_buf(), "main.go");

    assert_eq!(
        std::collections::BTreeSet::from([consumer]),
        analyzer.referencing_files_of(&target).into_iter().collect()
    );
}
