use brokk_analyzer::{
    IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject, TypeHierarchyProvider,
};
use std::collections::BTreeSet;

fn analyzer_for(files: &[(&str, &str)]) -> (tempfile::TempDir, JavaAnalyzer) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(contents)
            .unwrap();
    }

    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    (temp, analyzer)
}

#[test]
fn explicit_update_with_provided_set_matches_java_update_test() {
    let (_temp, analyzer) = analyzer_for(&[
        (
            "A.java",
            "public class A { public int method1() { return 1; } }",
        ),
        (
            "B.java",
            "public class B { public int methodB() { return 1; } }",
        ),
    ]);
    let mut analyzer = analyzer;
    let file_a = ProjectFile::new(analyzer.project().root().to_path_buf(), "A.java");

    assert!(!analyzer.get_definitions("A.method1").is_empty());
    assert!(analyzer.get_definitions("A.method2").is_empty());

    file_a
        .write(
            "public class A { public int method1() { return 1; } public int method2() { return 2; } }",
        )
        .unwrap();
    assert!(analyzer.get_definitions("A.method2").is_empty());

    analyzer = analyzer.update(&BTreeSet::from([file_a.clone()]));
    assert!(!analyzer.get_definitions("A.method2").is_empty());

    file_a
        .write(
            "public class A { public int method1() { return 1; } public int method2() { return 2; } public int method3() { return 3; } }",
        )
        .unwrap();
    analyzer = analyzer.update(&BTreeSet::new());
    assert!(analyzer.get_definitions("A.method3").is_empty());
}

#[test]
fn automatic_update_and_supertype_refresh_match_java_update_test() {
    let (_temp, analyzer) = analyzer_for(&[
        (
            "A.java",
            "public class A { public int method1() { return 1; } }",
        ),
        (
            "B.java",
            "public class B { public int methodB() { return 1; } }",
        ),
    ]);
    let mut analyzer = analyzer;

    ProjectFile::new(analyzer.project().root().to_path_buf(), "B.java")
        .write("public class B {}")
        .unwrap();
    ProjectFile::new(analyzer.project().root().to_path_buf(), "C.java")
        .write("public class C {}")
        .unwrap();
    let file_a = ProjectFile::new(analyzer.project().root().to_path_buf(), "A.java");
    file_a.write("public class A extends B {}").unwrap();

    analyzer = analyzer.update_all();

    let unit_a = analyzer.get_definitions("A").into_iter().next().unwrap();
    let ancestors = analyzer.get_direct_ancestors(&unit_a);
    assert_eq!(1, ancestors.len());
    assert_eq!("B", ancestors[0].short_name());

    file_a.write("public class A extends C {}").unwrap();
    analyzer = analyzer.update_all();

    let updated_a = analyzer.get_definitions("A").into_iter().next().unwrap();
    let updated_ancestors = analyzer.get_direct_ancestors(&updated_a);
    assert_eq!(1, updated_ancestors.len());
    assert_eq!("C", updated_ancestors[0].short_name());

    file_a
        .write("public class A { public int method1() { return 1; } public int method4() { return 4; } }")
        .unwrap();
    analyzer = analyzer.update_all();
    assert!(!analyzer.get_definitions("A.method4").is_empty());

    std::fs::remove_file(file_a.abs_path()).unwrap();
    analyzer = analyzer.update_all();
    assert!(analyzer.get_definitions("A").is_empty());
}

#[test]
fn explicit_partial_update_preserves_unchanged_files_semantically() {
    let (_temp, analyzer) = analyzer_for(&[
        (
            "A.java",
            "public class A { public int method1() { return 1; } }",
        ),
        (
            "B.java",
            "public class B { public int methodB() { return 1; } }",
        ),
    ]);
    let mut analyzer = analyzer;
    let file_a = ProjectFile::new(analyzer.project().root().to_path_buf(), "A.java");

    file_a
        .write(
            "public class A { public int method1() { return 1; } public int modified() { return 2; } }",
        )
        .unwrap();

    analyzer = analyzer.update(&BTreeSet::from([file_a]));

    assert!(!analyzer.get_definitions("A.method1").is_empty());
    assert!(!analyzer.get_definitions("A.modified").is_empty());
    assert!(!analyzer.get_definitions("B.methodB").is_empty());
}

#[test]
fn multi_step_update_reproduction_cases_match_remaining_java_update_tests() {
    let (_temp, analyzer) = analyzer_for(&[(
        "pkg/Target.java",
        "package pkg; class Target { void baseline() {} }",
    )]);
    let mut analyzer = analyzer;
    let target = ProjectFile::new(analyzer.project().root().to_path_buf(), "pkg/Target.java");

    target
        .write("package pkg; class Target; class Target { void method() {} }")
        .unwrap();
    analyzer = analyzer.update(&BTreeSet::from([target.clone()]));

    let target_cu = analyzer
        .get_definitions("pkg.Target")
        .into_iter()
        .next()
        .unwrap();
    let children = analyzer.get_direct_children(&target_cu);
    assert!(
        children
            .iter()
            .any(|code_unit| code_unit.short_name() == "Target.method")
    );
    let skeleton = analyzer.get_skeleton(&target_cu).unwrap();
    assert!(skeleton.contains("method"));
    assert!(!skeleton.contains("baseline"));

    let (_temp2, analyzer2) = analyzer_for(&[("pkg/Target.java", "package pkg; class Target {}")]);
    let mut analyzer2 = analyzer2;
    let target2 = ProjectFile::new(analyzer2.project().root().to_path_buf(), "pkg/Target.java");
    target2
        .write("package pkg; class Target { void method() {} }")
        .unwrap();
    analyzer2 = analyzer2.update_all();

    let target_cu2 = analyzer2
        .get_definitions("pkg.Target")
        .into_iter()
        .next()
        .unwrap();
    let children2 = analyzer2.get_direct_children(&target_cu2);
    assert!(
        children2
            .iter()
            .any(|code_unit| code_unit.short_name() == "Target.method")
    );
    assert!(
        analyzer2
            .get_skeleton(&target_cu2)
            .unwrap()
            .contains("method")
    );
}
