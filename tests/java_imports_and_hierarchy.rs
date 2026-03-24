use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile, TestProject,
    TypeHierarchyProvider,
};
use std::collections::BTreeSet;

fn analyzer_for(files: &[(&str, &str)]) -> JavaAnalyzer {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(contents)
            .unwrap();
    }

    let project = TestProject::new(root.clone(), Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    std::mem::forget(temp);
    analyzer
}

#[test]
fn resolves_explicit_imports() {
    let analyzer = analyzer_for(&[
        ("example/Baz.java", "package example; public class Baz {}"),
        ("Foo.java", "import example.Baz; public class Foo {}"),
    ]);

    let foo = analyzer.get_definitions("Foo").into_iter().next().unwrap();
    let imports = analyzer.imported_code_units_of(foo.source());

    assert!(
        imports
            .iter()
            .any(|code_unit| code_unit.fq_name() == "example.Baz")
    );
}

#[test]
fn explicit_import_beats_wildcard() {
    let analyzer = analyzer_for(&[
        (
            "pkg1/Ambiguous.java",
            "package pkg1; public class Ambiguous {}",
        ),
        (
            "pkg2/Ambiguous.java",
            "package pkg2; public class Ambiguous {}",
        ),
        (
            "consumer/Consumer.java",
            "package consumer; import pkg1.Ambiguous; import pkg2.*; public class Consumer { private Ambiguous field; }",
        ),
    ]);

    let consumer = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .next()
        .unwrap();
    let imports = analyzer.imported_code_units_of(consumer.source());
    let ambiguous: Vec<_> = imports
        .into_iter()
        .filter(|code_unit| code_unit.identifier() == "Ambiguous")
        .collect();

    assert_eq!(1, ambiguous.len());
    assert_eq!("pkg1.Ambiguous", ambiguous[0].fq_name());
}

#[test]
fn wildcard_imports_are_deterministic() {
    let analyzer = analyzer_for(&[
        (
            "pkg1/Ambiguous.java",
            "package pkg1; public class Ambiguous {}",
        ),
        (
            "pkg2/Ambiguous.java",
            "package pkg2; public class Ambiguous {}",
        ),
        (
            "consumer/Consumer.java",
            "package consumer; import pkg1.*; import pkg2.*; public class Consumer { private Ambiguous field; }",
        ),
    ]);

    let consumer = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .next()
        .unwrap();
    let imports = analyzer.imported_code_units_of(consumer.source());
    let ambiguous: Vec<_> = imports
        .into_iter()
        .filter(|code_unit| code_unit.identifier() == "Ambiguous")
        .collect();

    assert_eq!(1, ambiguous.len());
    assert_eq!("pkg1.Ambiguous", ambiguous[0].fq_name());
}

#[test]
fn same_package_files_reference_without_import() {
    let analyzer = analyzer_for(&[
        (
            "com/example/Foo.java",
            "package com.example; public class Foo {}",
        ),
        (
            "com/example/Bar.java",
            "package com.example; public class Bar { private Foo foo; }",
        ),
    ]);

    let foo = analyzer
        .get_definitions("com.example.Foo")
        .into_iter()
        .next()
        .unwrap();
    let bar = analyzer
        .get_definitions("com.example.Bar")
        .into_iter()
        .next()
        .unwrap();

    assert!(analyzer.could_import_file(bar.source(), &[], foo.source()));
    let referencing = analyzer.referencing_files_of(foo.source());
    assert!(referencing.contains(bar.source()));
}

#[test]
fn resolves_direct_ancestors() {
    let analyzer = analyzer_for(&[(
        "AllInOne.java",
        "class BaseClass {} interface ServiceInterface {} interface Marker {} class Child extends BaseClass implements ServiceInterface, Marker {}",
    )]);

    let child = analyzer
        .get_definitions("Child")
        .into_iter()
        .next()
        .unwrap();
    let ancestors: Vec<_> = analyzer
        .get_direct_ancestors(&child)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();

    assert_eq!(
        vec![
            "BaseClass".to_string(),
            "ServiceInterface".to_string(),
            "Marker".to_string()
        ],
        ancestors
    );
}

#[test]
fn resolves_direct_and_transitive_descendants() {
    let analyzer = analyzer_for(&[(
        "Hierarchy.java",
        "public class A {} class B extends A {} class C extends B {}",
    )])
    .update_all();

    let a = analyzer.get_definitions("A").into_iter().next().unwrap();
    let b = analyzer.get_definitions("B").into_iter().next().unwrap();
    let c = analyzer.get_definitions("C").into_iter().next().unwrap();

    let direct = analyzer.get_direct_descendants(&a);
    let transitive = analyzer.get_descendants(&a);

    assert_eq!(BTreeSet::from([b.clone()]), direct);
    assert_eq!(vec![b, c], transitive);
}

#[test]
fn resolves_fully_qualified_extends() {
    let analyzer = analyzer_for(&[
        ("p1/Base.java", "package p1; public class Base {}"),
        (
            "p2/Child.java",
            "package p2; public class Child extends p1.Base {}",
        ),
    ])
    .update_all();

    let base = analyzer
        .get_definitions("p1.Base")
        .into_iter()
        .next()
        .unwrap();
    let child = analyzer
        .get_definitions("p2.Child")
        .into_iter()
        .next()
        .unwrap();

    assert_eq!(
        BTreeSet::from([child]),
        analyzer.get_direct_descendants(&base)
    );
}
