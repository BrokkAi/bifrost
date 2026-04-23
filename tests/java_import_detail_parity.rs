use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile, TestProject,
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
fn import_info_preserves_java_import_structure() {
    let analyzer = analyzer_for(&[(
        "Foo.java",
        r#"
        import java.util.List;
        import java.util.Map;
        import static java.lang.Math.PI;
        import com.example.*;
        import static org.junit.Assert.*;

        public class Foo {}
        "#,
    )]);

    let foo_file = analyzer
        .get_definitions("Foo")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    let import_infos = analyzer.import_info_of(&foo_file);
    assert_eq!(5, import_infos.len());

    let list_import = import_infos
        .iter()
        .find(|import| import.raw_snippet.contains("java.util.List"))
        .unwrap();
    assert!(!list_import.is_wildcard);
    assert_eq!(Some("List"), list_import.identifier.as_deref());
    assert_eq!(None, list_import.alias.as_deref());

    let static_import = import_infos
        .iter()
        .find(|import| import.raw_snippet.contains("Math.PI"))
        .unwrap();
    assert!(!static_import.is_wildcard);
    assert_eq!(Some("PI"), static_import.identifier.as_deref());

    let wildcard_import = import_infos
        .iter()
        .find(|import| import.raw_snippet.contains("com.example.*"))
        .unwrap();
    assert!(wildcard_import.is_wildcard);
    assert_eq!(None, wildcard_import.identifier.as_deref());
}

#[test]
fn resolved_imports_exclude_static_imports_and_keep_mixed_resolution() {
    let analyzer = analyzer_for(&[
        ("pkg1/TypeA.java", "package pkg1; public class TypeA {}"),
        (
            "pkg2/TypeB.java",
            "package pkg2; public class TypeB {} class TypeC {}",
        ),
        (
            "Consumer.java",
            r#"
            import pkg1.TypeA;
            import pkg2.*;
            import static java.lang.System.out;

            public class Consumer {}
            "#,
        ),
    ]);

    let consumer_file = analyzer
        .get_definitions("Consumer")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    let mut resolved: Vec<_> = analyzer
        .imported_code_units_of(&consumer_file)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    resolved.sort();

    assert_eq!(
        vec![
            "pkg1.TypeA".to_string(),
            "pkg2.TypeB".to_string(),
            "pkg2.TypeC".to_string(),
        ],
        resolved
    );
}

#[test]
fn unresolved_and_circular_imports_stay_stable() {
    let unresolved = analyzer_for(&[(
        "Foo.java",
        "import nonexistent.package.Class; public class Foo {}",
    )]);
    let foo_file = unresolved
        .get_definitions("Foo")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    assert!(unresolved.imported_code_units_of(&foo_file).is_empty());

    let circular = analyzer_for(&[
        ("pkg/A.java", "package pkg; import pkg.B; public class A {}"),
        ("pkg/B.java", "package pkg; import pkg.C; public class B {}"),
        ("pkg/C.java", "package pkg; import pkg.A; public class C {}"),
    ]);

    let a_file = circular
        .get_definitions("pkg.A")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    let b_file = circular
        .get_definitions("pkg.B")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();
    let c_file = circular
        .get_definitions("pkg.C")
        .into_iter()
        .next()
        .unwrap()
        .source()
        .clone();

    assert_eq!(
        vec!["pkg.B".to_string()],
        circular
            .imported_code_units_of(&a_file)
            .into_iter()
            .map(|code_unit| code_unit.fq_name())
            .collect::<Vec<_>>()
    );
    assert!(circular.referencing_files_of(&a_file).contains(&c_file));
    assert!(circular.referencing_files_of(&b_file).contains(&a_file));
    assert!(circular.referencing_files_of(&c_file).contains(&b_file));
}

#[test]
fn relevant_imports_ignore_fully_qualified_types() {
    let analyzer = analyzer_for(&[(
        "consumer/Consumer.java",
        r#"
        package consumer;
        import java.util.List;
        import other.*;

        public class Consumer {
            public void method(java.util.ArrayList fq, List explicit, UnknownType wildcard) {}
        }
        "#,
    )]);

    let consumer = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .next()
        .unwrap();
    let method = analyzer
        .get_direct_children(&consumer)
        .into_iter()
        .find(|code_unit| code_unit.identifier() == "method")
        .unwrap();

    let relevant = analyzer.relevant_imports_for(&method);
    assert_eq!(2, relevant.len());
    assert!(relevant.contains("import java.util.List;"));
    assert!(relevant.contains("import other.*;"));
}

#[test]
fn extracted_type_identifiers_include_qualified_java_types() {
    let analyzer = analyzer_for(&[(
        "Foo.java",
        "public class Foo { List simple; java.util.List qualified; }",
    )]);

    let identifiers = analyzer
        .extract_type_identifiers("public class Foo { List simple; java.util.List qualified; }");
    assert!(identifiers.contains("List"));
    assert!(identifiers.contains("java.util.List"));
}
