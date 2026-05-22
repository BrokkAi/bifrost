use brokk_bifrost::{
    IAnalyzer, ImportAnalysisProvider, Language, Project, ProjectFile, ScalaAnalyzer, TestProject,
};
use std::collections::BTreeSet;
use tempfile::tempdir;

fn inline_scala_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Scala)
}

#[test]
fn test_ordinary_import() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        import foo.bar.Baz
        import Bar

        class Foo
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Foo.scala");
    let imports: BTreeSet<_> = analyzer.import_statements_of(&file).into_iter().collect();
    assert_eq!(
        BTreeSet::from(["import foo.bar.Baz".to_string(), "import Bar".to_string()]),
        imports
    );
}

#[test]
fn test_static_import() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        import foo.bar.{Baz as Bar}

        class Foo
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Foo.scala");
    let imports: BTreeSet<_> = analyzer.import_statements_of(&file).into_iter().collect();
    assert_eq!(
        BTreeSet::from(["import foo.bar.{Baz as Bar}".to_string()]),
        imports
    );
}

#[test]
fn test_wildcard_import() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        import foo.bar.*

        class Foo
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Foo.scala");
    let imports: BTreeSet<_> = analyzer.import_statements_of(&file).into_iter().collect();
    assert_eq!(BTreeSet::from(["import foo.bar.*".to_string()]), imports);
}

#[test]
fn test_structured_import_info_for_group_alias_and_wildcard() {
    let project = inline_scala_project(&[(
        "Foo.scala",
        r#"
        import foo.bar.Baz
        import foo.bar.{Qux, Quux as Alias}
        import foo.bar.*

        class Foo
        "#,
    )]);
    let analyzer = ScalaAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "Foo.scala");
    let infos = analyzer.import_info_of(&file);

    let rendered: BTreeSet<_> = infos
        .iter()
        .map(|info| {
            format!(
                "{}|wildcard={}|identifier={:?}|alias={:?}",
                info.raw_snippet, info.is_wildcard, info.identifier, info.alias
            )
        })
        .collect();

    assert_eq!(
        BTreeSet::from([
            r#"import foo.bar.*|wildcard=true|identifier=None|alias=None"#.to_string(),
            r#"import foo.bar.Baz|wildcard=false|identifier=Some("Baz")|alias=None"#.to_string(),
            r#"import foo.bar.Quux as Alias|wildcard=false|identifier=Some("Alias")|alias=Some("Alias")"#.to_string(),
            r#"import foo.bar.Qux|wildcard=false|identifier=Some("Qux")|alias=None"#.to_string(),
        ]),
        rendered
    );
}
