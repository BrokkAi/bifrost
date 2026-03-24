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
fn extracts_java_call_receivers_with_brokk_heuristics() {
    let analyzer = analyzer_for(&[("Foo.java", "class Foo {}")]);

    assert_eq!(
        Some("MyClass".to_string()),
        analyzer.extract_call_receiver("MyClass.myMethod")
    );
    assert_eq!(
        Some("com.example.MyClass".to_string()),
        analyzer.extract_call_receiver("com.example.MyClass.myMethod")
    );
    assert_eq!(
        Some("java.lang.String".to_string()),
        analyzer.extract_call_receiver("java.lang.String.valueOf")
    );
    assert_eq!(
        Some("SwingUtilities".to_string()),
        analyzer.extract_call_receiver("SwingUtilities.invokeLater(task)")
    );

    assert_eq!(None, analyzer.extract_call_receiver("MyClass"));
    assert_eq!(None, analyzer.extract_call_receiver("myclass.myMethod"));
    assert_eq!(None, analyzer.extract_call_receiver("MyClass.MyMethod"));
    assert_eq!(
        None,
        analyzer.extract_call_receiver("com.example.Outer$Inner.method")
    );
}

#[test]
fn normalizes_java_definition_names_for_lookup() {
    let analyzer = analyzer_for(&[
        ("A.java", "class A { void method1() {} void method6() {} }"),
        ("B.java", "class B { B() {} }"),
    ]);

    assert!(!analyzer.get_definitions("A<String>").is_empty());
    assert!(!analyzer.get_definitions("A<Integer>.method1").is_empty());
    assert!(!analyzer.get_definitions("A.method1:16").is_empty());
    assert!(!analyzer.get_definitions("A.method6$1").is_empty());
    assert!(!analyzer.get_definitions("B<B>.B").is_empty());
}

#[test]
fn merges_package_modules_across_package_info_and_sources() {
    let analyzer = analyzer_for(&[
        ("p1/package-info.java", "@Deprecated\npackage p1;\n"),
        ("p1/A.java", "package p1; public class A {}"),
    ]);

    let definitions = analyzer.get_definitions("p1");
    assert_eq!(1, definitions.len());
    let module = &definitions[0];
    assert!(module.is_module());

    let children: Vec<_> = analyzer
        .get_direct_children(module)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert_eq!(vec!["p1.A".to_string()], children);
}

#[test]
fn attaches_lambda_to_the_correct_java_overload() {
    let analyzer = analyzer_for(&[(
        "C.java",
        r#"
        class C {
          void m(int x) {
            System.out.println(x);
          }
          void m(String s) {
            Runnable r = () -> System.out.println(s);
            r.run();
          }
        }
        "#,
    )]);

    let definitions = analyzer.get_definitions("C.m");
    assert_eq!(2, definitions.len());

    let int_overload = definitions
        .iter()
        .find(|code_unit| code_unit.signature() == Some("(int)"))
        .unwrap();
    let string_overload = definitions
        .iter()
        .find(|code_unit| code_unit.signature() == Some("(String)"))
        .unwrap();

    assert!(analyzer.get_direct_children(int_overload).is_empty());

    let string_children = analyzer.get_direct_children(string_overload);
    assert_eq!(1, string_children.len());
    assert!(string_children[0].is_function());
    assert!(string_children[0].is_anonymous());
    assert!(string_children[0].fq_name().contains("m$anon$"));
}

#[test]
fn computes_relevant_imports_like_brokk_java() {
    let analyzer = analyzer_for(&[
        ("pkg/Foo.java", "package pkg; public class Foo {}"),
        (
            "consumer/Consumer.java",
            r#"
            package consumer;
            import pkg.Foo;
            import other.*;

            public class Consumer {
                public void bar(Foo a, UnknownType b) {}
            }
            "#,
        ),
    ]);

    let consumer_class = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .find(|code_unit| code_unit.is_class())
        .unwrap();
    let bar_method = analyzer
        .get_direct_children(&consumer_class)
        .into_iter()
        .find(|code_unit| code_unit.identifier() == "bar")
        .unwrap();

    let relevant = ImportAnalysisProvider::relevant_imports_for(&analyzer, &bar_method);
    assert_eq!(2, relevant.len());
    assert!(relevant.contains("import pkg.Foo;"));
    assert!(relevant.contains("import other.*;"));
}

#[test]
fn resolves_relevant_wildcard_imports_to_known_project_types() {
    let analyzer = analyzer_for(&[
        (
            "internal/InternalService.java",
            "package internal; public class InternalService {}",
        ),
        (
            "consumer/Consumer.java",
            r#"
            package consumer;
            import internal.*;
            import external.*;

            public class Consumer {
                public void process(InternalService svc) {}
            }
            "#,
        ),
    ]);

    let consumer_class = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .find(|code_unit| code_unit.is_class())
        .unwrap();
    let process_method = analyzer
        .get_direct_children(&consumer_class)
        .into_iter()
        .find(|code_unit| code_unit.identifier() == "process")
        .unwrap();

    let relevant = ImportAnalysisProvider::relevant_imports_for(&analyzer, &process_method);
    assert_eq!(1, relevant.len());
    assert!(relevant.contains("import internal.*;"));
}
