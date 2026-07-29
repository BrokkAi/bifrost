use brokk_bifrost::{
    CodeUnitType, IAnalyzer, JavaAnalyzer, Language, ProjectFile, Range, TestProject,
};

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
fn creates_package_module_with_top_level_children() {
    let analyzer = analyzer_for(&[(
        "p1/A_B.java",
        "package p1; class A { class Inner {} } class B {}",
    )]);

    let module = analyzer.get_definitions("p1").into_iter().next().unwrap();
    assert!(module.is_module());
    assert_eq!(1, analyzer.ranges(&module).len());

    let children: Vec<_> = analyzer
        .direct_children(&module)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(vec!["p1.A".to_string(), "p1.B".to_string()], children);
}

#[test]
fn merges_package_module_children_once_in_canonical_order() {
    let analyzer = analyzer_for(&[
        ("p1/A.java", "package p1; class A {}"),
        ("p1/B.java", "\n\npackage p1; class B {}"),
        ("p1/C.java", "package p1; class C {}"),
    ]);

    let module = analyzer.get_definitions("p1").into_iter().next().unwrap();
    assert!(module.is_module());

    let children: Vec<_> = analyzer
        .direct_children(&module)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(
        vec!["p1.A".to_string(), "p1.C".to_string(), "p1.B".to_string()],
        children
    );
}

#[test]
fn file_scope_encloses_imports_without_stealing_class_references() {
    let source = "package app;\n\nimport app.Target;\n\nclass UseTarget { Target value; }\n";
    let analyzer = analyzer_for(&[
        ("Target.java", "package app; class Target {}\n"),
        ("UseTarget.java", source),
    ]);
    let file = analyzer
        .get_analyzed_files()
        .into_iter()
        .find(|file| file.rel_path().ends_with("UseTarget.java"))
        .unwrap();

    let import_start = source.find("Target;").unwrap();
    let import_range = Range {
        start_byte: import_start,
        end_byte: import_start + "Target".len(),
        start_line: 2,
        end_line: 2,
    };
    let import_owner = analyzer.enclosing_code_unit(&file, &import_range).unwrap();
    assert_eq!(CodeUnitType::FileScope, import_owner.kind());
    assert!(import_owner.is_synthetic());

    let field_start = source.rfind("Target value").unwrap();
    let field_range = Range {
        start_byte: field_start,
        end_byte: field_start + "Target".len(),
        start_line: 4,
        end_line: 4,
    };
    let field_owner = analyzer.enclosing_code_unit(&file, &field_range).unwrap();
    assert_eq!("app.UseTarget.value", field_owner.fq_name());
    assert_ne!(CodeUnitType::FileScope, field_owner.kind());
}

#[test]
fn classes_without_explicit_constructors_do_not_synthesize_constructor_units() {
    let analyzer = analyzer_for(&[
        ("Foo.java", "public class Foo {}"),
        ("I.java", "public interface I {}"),
        ("E.java", "public enum E { A, B }"),
        ("R.java", "public record R(int x) {}"),
        ("A.java", "public @interface A {}"),
    ]);

    assert!(analyzer.get_definitions("Foo.Foo").is_empty());
    assert!(analyzer.get_definitions("I.I").is_empty());
    assert!(analyzer.get_definitions("E.E").is_empty());
    assert!(analyzer.get_definitions("R.R").is_empty());
    assert!(analyzer.get_definitions("A.A").is_empty());
}

#[test]
fn explicit_constructor_is_source_backed() {
    let analyzer = analyzer_for(&[("Bar.java", "public class Bar { public Bar(int x) {} }")]);
    let ctors = analyzer.get_definitions("Bar.Bar");
    assert_eq!(1, ctors.len());
    let ctor = &ctors[0];
    assert!(!ctor.is_synthetic());
    assert!(analyzer.get_source(ctor, true).is_some());
}
