use brokk_analyzer::{CodeUnitType, IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject};

fn analyzer_for(files: &[(&str, &str)]) -> JavaAnalyzer {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path).write(contents).unwrap();
    }

    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    std::mem::forget(temp);
    analyzer
}

#[test]
fn creates_package_module_with_top_level_children() {
    let analyzer = analyzer_for(&[(
        "p1/A_B.java",
        "package p1; class A { class Inner {} } class B {}",
    )]);

    let module = analyzer.get_definitions("p1").into_iter().next().unwrap();
    assert!(module.is_module());

    let children: Vec<_> = analyzer
        .get_direct_children(&module)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(vec!["p1.A".to_string(), "p1.B".to_string()], children);
}

#[test]
fn synthesizes_implicit_constructor_for_plain_class_only() {
    let analyzer = analyzer_for(&[
        ("Foo.java", "public class Foo {}"),
        ("I.java", "public interface I {}"),
        ("E.java", "public enum E { A, B }"),
        ("R.java", "public record R(int x) {}"),
        ("A.java", "public @interface A {}"),
    ]);

    let foo_ctors = analyzer.get_definitions("Foo.Foo");
    assert!(foo_ctors.iter().any(|code_unit| code_unit.kind() == CodeUnitType::Function));
    let foo_ctor = foo_ctors
        .into_iter()
        .find(|code_unit| code_unit.kind() == CodeUnitType::Function)
        .unwrap();
    assert!(foo_ctor.is_synthetic());
    assert!(analyzer.get_source(&foo_ctor, true).is_none());

    assert!(analyzer.get_definitions("I.I").is_empty());
    assert!(analyzer.get_definitions("E.E").is_empty());
    assert!(analyzer.get_definitions("R.R").is_empty());
    assert!(analyzer.get_definitions("A.A").is_empty());
}

#[test]
fn explicit_constructor_prevents_implicit_synthesis() {
    let analyzer = analyzer_for(&[("Bar.java", "public class Bar { public Bar(int x) {} }")]);
    let ctors = analyzer.get_definitions("Bar.Bar");
    assert_eq!(1, ctors.len());
    let ctor = &ctors[0];
    assert!(!ctor.is_synthetic());
    assert!(analyzer.get_source(ctor, true).is_some());
}
