use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile, TestProject};

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
fn import_info_records_static_and_wildcard_structure() {
    use brokk_bifrost::analyzer::StructuredImportPathKind;

    let analyzer = analyzer_for(&[(
        "Foo.java",
        r#"
        import java.util.List;
        import java.util.concurrent.*;
        import static java.lang.Math.max;
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
    let import_named = |needle: &str| {
        import_infos
            .iter()
            .find(|import| import.raw_snippet.contains(needle))
            .unwrap()
    };

    let list_import = import_named("java.util.List");
    let list_path = list_import.path.as_ref().unwrap();
    assert_eq!(Some(StructuredImportPathKind::Namespace), list_path.kind);
    assert_eq!("java.util.List", list_path.render_segments("."));

    // The asterisk is not a segment; the parser records the package.
    let on_demand = import_named("java.util.concurrent.*");
    let on_demand_path = on_demand.path.as_ref().unwrap();
    assert!(on_demand.is_wildcard);
    assert_eq!(
        Some(StructuredImportPathKind::Namespace),
        on_demand_path.kind
    );
    assert_eq!("java.util.concurrent", on_demand_path.render_segments("."));

    let static_member = import_named("Math.max");
    let static_member_path = static_member.path.as_ref().unwrap();
    assert!(!static_member.is_wildcard);
    assert_eq!(
        Some(StructuredImportPathKind::StaticMember),
        static_member_path.kind
    );
    assert_eq!(
        "java.lang.Math.max",
        static_member_path.render_segments(".")
    );

    let static_on_demand = import_named("org.junit.Assert");
    let static_on_demand_path = static_on_demand.path.as_ref().unwrap();
    assert!(static_on_demand.is_wildcard);
    assert_eq!(
        Some(StructuredImportPathKind::StaticMember),
        static_on_demand_path.kind
    );
    assert_eq!(
        "org.junit.Assert",
        static_on_demand_path.render_segments(".")
    );
}

#[test]
fn could_import_distinguishes_static_wildcard_and_explicit_imports() {
    let analyzer = analyzer_for(&[
        (
            "pkg1/TypeA.java",
            "package pkg1; public class TypeA { public static int helper() { return 1; } }",
        ),
        ("pkg2/TypeB.java", "package pkg2; public class TypeB {}"),
        ("pkg3/TypeC.java", "package pkg3; public class TypeC {}"),
        (
            "consumer/Consumer.java",
            r#"
            package consumer;

            import static pkg1.TypeA.helper;
            import pkg2.*;

            public class Consumer {}
            "#,
        ),
    ]);

    let file_of = |name: &str| {
        analyzer
            .get_definitions(name)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("no definition named {name}"))
            .source()
            .clone()
    };
    let imports = analyzer.import_info_of(&file_of("consumer.Consumer"));

    // The static import names a member of TypeA, so TypeA is importable.
    assert!(analyzer.could_import_file_without_source(&imports, &file_of("pkg1.TypeA")));
    // The on-demand import covers pkg2.
    assert!(analyzer.could_import_file_without_source(&imports, &file_of("pkg2.TypeB")));
    // Nothing names pkg3.
    assert!(!analyzer.could_import_file_without_source(&imports, &file_of("pkg3.TypeC")));
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
        .direct_children(&consumer)
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
