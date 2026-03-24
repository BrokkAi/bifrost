use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile, TestProject,
    TypeHierarchyProvider,
};
use std::collections::BTreeSet;

fn analyzer_for(files: &[(&str, &str)]) -> (tempfile::TempDir, JavaAnalyzer) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path).write(contents).unwrap();
    }

    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    (temp, analyzer)
}

#[test]
fn multi_step_incremental_update_preserves_prior_state() {
    let (_temp, analyzer) = analyzer_for(&[(
        "pkg1/BaseClass.java",
        "package pkg1; public class BaseClass { public void baseMethod() {} }",
    )]);
    let mut analyzer = analyzer;

    let derived = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "pkg2/DerivedClass.java",
    );
    derived
        .write("package pkg2; public class DerivedClass { public void derivedMethod() {} }")
        .unwrap();
    analyzer = analyzer.update_all();

    let derived_cu = analyzer
        .get_definitions("pkg2.DerivedClass")
        .into_iter()
        .next()
        .unwrap();
    assert!(analyzer.get_skeleton(&derived_cu).unwrap().contains("derivedMethod"));

    derived
        .write(
            "package pkg2; import pkg1.BaseClass; public class DerivedClass { public void derivedMethod() {} }",
        )
        .unwrap();
    analyzer = analyzer.update_all();

    let base_cu = analyzer
        .get_definitions("pkg1.BaseClass")
        .into_iter()
        .next()
        .unwrap();
    let imported = analyzer.imported_code_units_of(&derived);
    assert!(imported.contains(&base_cu));

    derived
        .write(
            "package pkg2; import pkg1.BaseClass; public class DerivedClass extends BaseClass { public void derivedMethod() {} }",
        )
        .unwrap();
    analyzer = analyzer.update_all();

    let derived_cu = analyzer
        .get_definitions("pkg2.DerivedClass")
        .into_iter()
        .next()
        .unwrap();
    assert!(analyzer
        .get_direct_ancestors(&derived_cu)
        .into_iter()
        .any(|code_unit| code_unit == base_cu));
    assert!(analyzer.imported_code_units_of(&derived).contains(&base_cu));
}

#[test]
fn duplicate_overload_preserves_distinct_signature() {
    let (_temp, analyzer) = analyzer_for(&[(
        "C.java",
        r#"class C {
  void m(int x) { int a = 1; }
  void m(String s) { int b = 2; }
  void m(int x) { int c = 3; }
}"#,
    )]);

    let definitions = analyzer.get_definitions("C.m");
    assert_eq!(2, definitions.len());
    let signatures: BTreeSet<_> = definitions
        .iter()
        .filter_map(|code_unit| code_unit.signature().map(str::to_string))
        .collect();
    assert_eq!(
        BTreeSet::from(["(String)".to_string(), "(int)".to_string()]),
        signatures
    );

    let class_cu = analyzer.get_definitions("C").into_iter().next().unwrap();
    let child_sigs: BTreeSet<_> = analyzer
        .get_direct_children(&class_cu)
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .filter_map(|code_unit| code_unit.signature().map(str::to_string))
        .collect();
    assert_eq!(
        BTreeSet::from(["(String)".to_string(), "(int)".to_string()]),
        child_sigs
    );
}

#[test]
fn incremental_class_replacement_keeps_new_children() {
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
    assert!(children.iter().any(|code_unit| code_unit.short_name() == "Target.method"));
    let skeleton = analyzer.get_skeleton(&target_cu).unwrap();
    assert!(skeleton.contains("method"));
    assert!(!skeleton.contains("baseline"));
}
