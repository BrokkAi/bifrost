use brokk_bifrost::{
    AnalyzerConfig, IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, JavaExternalDependencies,
    JavaMavenCoordinate, Language, ProjectFile, TestProject, TypeHierarchyProvider,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

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

fn analyzer_for_with_config(files: &[(&str, &str)], config: AnalyzerConfig) -> JavaAnalyzer {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(contents)
            .unwrap();
    }

    let project = TestProject::new(root.clone(), Language::Java);
    let analyzer = JavaAnalyzer::from_project_with_config(project, config);
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
fn java_external_type_resolution_uses_exact_maven_coordinate_without_workspace_declarations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    create_external_dependency_fixture(&root);

    let config = AnalyzerConfig {
        java_external_dependencies: JavaExternalDependencies {
            coordinates: vec![JavaMavenCoordinate::new(
                "com.example",
                "external-lib",
                "1.2.3",
            )],
            repository_roots: vec![root.join("m2")],
            ..JavaExternalDependencies::default()
        },
        ..AnalyzerConfig::default()
    };

    let analyzer = analyzer_for_with_config(
        &[(
            "src/App.java",
            "package app;\n\
             import com.example.dep.ExternalService;\n\
             import com.example.dep.*;\n\
             public class App { ExternalService explicit; ExternalHelper wildcard; }\n",
        )],
        config,
    );
    let app = analyzer
        .get_definitions("app.App")
        .into_iter()
        .next()
        .unwrap();

    assert!(analyzer.is_known_type_name_in_file(app.source(), "ExternalService"));
    assert!(analyzer.is_known_type_name_in_file(app.source(), "ExternalHelper"));
    assert!(
        analyzer
            .resolve_type_name_in_file(app.source(), "ExternalService")
            .is_none(),
        "source-only resolution must not create CodeUnits for external dependencies"
    );
    assert!(
        analyzer
            .get_all_declarations()
            .into_iter()
            .all(|code_unit| !code_unit.fq_name().starts_with("com.example.dep.")),
        "external dependency types must not leak into normal analyzer declarations"
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

    let direct: BTreeSet<_> = analyzer.get_direct_descendants(&a).into_iter().collect();
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
        analyzer.get_direct_descendants(&base).into_iter().collect()
    );
}

fn create_external_dependency_fixture(root: &Path) {
    require_jdk_tool("javac");
    require_jdk_tool("jar");

    let repo_dir = root.join("m2/com/example/external-lib/1.2.3");
    let source_dir = root.join("dep-src");
    let package_dir = source_dir.join("com/example/dep");
    let classes_dir = root.join("dep-classes");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&package_dir).unwrap();
    fs::create_dir_all(&classes_dir).unwrap();

    fs::write(
        package_dir.join("ExternalService.java"),
        "package com.example.dep; public class ExternalService {}\n",
    )
    .unwrap();
    fs::write(
        package_dir.join("ExternalHelper.java"),
        "package com.example.dep; public class ExternalHelper {}\n",
    )
    .unwrap();

    run_jdk_command(
        Command::new("javac")
            .arg("-d")
            .arg(&classes_dir)
            .arg(package_dir.join("ExternalService.java"))
            .arg(package_dir.join("ExternalHelper.java")),
    );
    run_jdk_command(
        Command::new("jar")
            .current_dir(&classes_dir)
            .arg("cf")
            .arg(repo_dir.join("external-lib-1.2.3.jar"))
            .arg("."),
    );
}

fn require_jdk_tool(tool: &str) {
    let Ok(output) = Command::new(tool).arg("--version").output() else {
        panic!(
            "Java external declaration tests require `{tool}` on PATH. Install a JDK and rerun."
        );
    };
    assert!(
        output.status.success(),
        "Java external declaration tests require `{tool}` on PATH. Install a JDK and rerun."
    );
}

fn run_jdk_command(command: &mut Command) {
    let output = command
        .output()
        .unwrap_or_else(|err| panic!("failed to run JDK fixture command {command:?}: {err}"));
    assert!(
        output.status.success(),
        "JDK fixture command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
