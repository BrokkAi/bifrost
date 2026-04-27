use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile, TestProject,
};

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

fn analyzer_for(files: &[(&str, &str)]) -> JavaAnalyzer {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(contents)
            .unwrap();
    }

    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    std::mem::forget(temp);
    analyzer
}

#[test]
fn top_level_declarations_match_java_fixture_shapes() {
    let analyzer = fixture_analyzer();

    let d_file = ProjectFile::new(analyzer.project().root().to_path_buf(), "D.java");
    let d_top_level = analyzer.get_top_level_declarations(&d_file);
    assert_eq!(1, d_top_level.len());
    assert_eq!("D", d_top_level[0].fq_name());

    let packaged_file = ProjectFile::new(analyzer.project().root().to_path_buf(), "Packaged.java");
    let packaged_top_level = analyzer.get_top_level_declarations(&packaged_file);
    assert_eq!(2, packaged_top_level.len());
    assert!(
        packaged_top_level
            .iter()
            .any(|code_unit| code_unit.is_module()
                && code_unit.fq_name() == "io.github.jbellis.brokk")
    );
    assert!(
        packaged_top_level
            .iter()
            .any(|code_unit| code_unit.is_class()
                && code_unit.fq_name() == "io.github.jbellis.brokk.Foo")
    );
}

#[test]
fn direct_children_match_fixture_class_members() {
    let analyzer = fixture_analyzer();
    let class_d = analyzer.get_definitions("D").into_iter().next().unwrap();

    let child_kinds_and_names: Vec<_> = analyzer
        .get_direct_children(&class_d)
        .into_iter()
        .map(|code_unit| format!("{:?}:{}", code_unit.kind(), code_unit.fq_name()))
        .collect();

    assert_eq!(
        vec![
            "Field:D.field1".to_string(),
            "Field:D.field2".to_string(),
            "Function:D.methodD1".to_string(),
            "Function:D.methodD2".to_string(),
            "Class:D.DSubStatic".to_string(),
            "Class:D.DSub".to_string(),
            "Function:D.D".to_string(),
        ],
        child_kinds_and_names
    );
}

#[test]
fn enclosing_code_unit_for_line_ranges_matches_fixture_expectations() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "A.java");

    let method1 = analyzer
        .get_definitions("A.method1")
        .into_iter()
        .next()
        .unwrap();
    let method1_line = analyzer.ranges_of(&method1)[0].start_line;
    assert_eq!(
        "A.method1",
        analyzer
            .enclosing_code_unit_for_lines(&file, method1_line, method1_line)
            .unwrap()
            .fq_name()
    );

    let method7 = analyzer
        .get_definitions("A.AInner.AInnerInner.method7")
        .into_iter()
        .next()
        .unwrap();
    let method7_line = analyzer.ranges_of(&method7)[0].start_line;
    assert_eq!(
        "A.AInner.AInnerInner.method7",
        analyzer
            .enclosing_code_unit_for_lines(&file, method7_line, method7_line + 1)
            .unwrap()
            .fq_name()
    );

    let method2 = analyzer
        .get_definitions("A.method2")
        .into_iter()
        .next()
        .unwrap();
    let method2_line = analyzer.ranges_of(&method2)[0].start_line;
    assert_eq!(
        "A",
        analyzer
            .enclosing_code_unit_for_lines(
                &file,
                method1_line.min(method2_line),
                method1_line.max(method2_line),
            )
            .unwrap()
            .fq_name()
    );
}

#[test]
fn could_import_file_matches_java_specific_cases() {
    let analyzer = analyzer_for(&[
        (
            "com/example/Foo.java",
            "package com.example; public class Foo { public static final int METHOD = 1; public static class Inner {} }",
        ),
        (
            "Bar.java",
            "import com.example.Foo; import static com.example.Foo.METHOD; import com.example.Foo.Inner; public class Bar {}",
        ),
        (
            "com/example/Baz.java",
            "package com.example; public class Baz {}",
        ),
    ]);

    let foo_file = analyzer
        .get_definitions("com.example.Foo")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    let bar_file = analyzer
        .get_definitions("Bar")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    let baz_file = analyzer
        .get_definitions("com.example.Baz")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();

    let imports = analyzer.import_info_of(&bar_file);
    assert!(analyzer.could_import_file_without_source(imports, &foo_file));
    assert!(analyzer.could_import_file(&bar_file, imports, &foo_file));
    assert!(!analyzer.could_import_file_without_source(imports, &baz_file));

    let same_package_imports = analyzer.import_info_of(&baz_file);
    assert!(same_package_imports.is_empty());
    assert!(analyzer.could_import_file(&baz_file, same_package_imports, &foo_file));
}
