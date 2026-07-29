use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject};
use tempfile::tempdir;

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

#[test]
fn lists_all_fixture_classes() {
    let analyzer = fixture_analyzer();

    let classes: Vec<_> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|code_unit| code_unit.is_class())
        .map(|code_unit| code_unit.fq_name())
        .collect::<Vec<_>>();
    let mut classes = classes;
    classes.sort();

    assert_eq!(
        vec![
            "A",
            "A.AInner",
            "A.AInner.AInnerInner",
            "A.AInnerStatic",
            "AnnotatedClass",
            "AnnotatedClass.InnerHelper",
            "AnonymousUsage",
            "AnonymousUsage.NestedClass",
            "B",
            "BaseClass",
            "C",
            "C.Foo",
            "CamelClass",
            "ClassUsagePatterns",
            "CustomAnnotation",
            "CyclicMethods",
            "D",
            "D.DSub",
            "D.DSubStatic",
            "E",
            "EnumClass",
            "F",
            "InlineComment",
            "Interface",
            "MethodReferenceUsage",
            "MethodReturner",
            "Overloads",
            "OverloadsUser",
            "ServiceImpl",
            "ServiceInterface",
            "UseE",
            "UsePackaged",
            "XExtendsY",
            "io.github.jbellis.brokk.Foo",
            "io.github.jbellis.brokk.PackagedSibling",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>(),
        classes
    );
}

#[test]
fn java_supertype_collection_handles_deep_generic_shape_iteratively() {
    let temp = tempdir().unwrap();
    let mut source = String::from("class Box<T> {}\nclass Deep extends ");
    for _ in 0..256 {
        source.push_str("Box<");
    }
    source.push_str("String");
    for _ in 0..256 {
        source.push('>');
    }
    source.push_str(" {}\n");
    ProjectFile::new(temp.path().to_path_buf(), "Deep.java")
        .write(&source)
        .unwrap();

    let project = TestProject::new(temp.keep(), Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);

    assert!(
        analyzer
            .get_all_declarations()
            .into_iter()
            .any(|unit| unit.fq_name() == "Deep")
    );
}

#[test]
fn packaged_file_declarations_include_module_and_members() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "Packaged.java");

    let declarations: Vec<_> = analyzer
        .declarations(&file)
        .into_iter()
        .map(|code_unit| format!("{:?}:{}", code_unit.kind(), code_unit.fq_name()))
        .collect();

    assert_eq!(
        vec![
            "Module:io.github.jbellis.brokk".to_string(),
            "Class:io.github.jbellis.brokk.Foo".to_string(),
            "Function:io.github.jbellis.brokk.Foo.bar".to_string(),
        ],
        declarations
    );

    let foo = analyzer
        .declarations(&file)
        .into_iter()
        .find(|code_unit| code_unit.fq_name() == "io.github.jbellis.brokk.Foo")
        .unwrap();
    assert_eq!("Foo", foo.short_name());
    assert_eq!("Foo", foo.identifier());
}

#[test]
fn nested_class_identifiers_match_java_expectations() {
    let analyzer = fixture_analyzer();

    let class_d = analyzer.get_definitions("D").into_iter().next().unwrap();
    assert_eq!("D", class_d.short_name());
    assert_eq!("D", class_d.identifier());

    let class_d_sub = analyzer
        .get_definitions("D.DSub")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!("D.DSub", class_d_sub.short_name());
    assert_eq!("DSub", class_d_sub.identifier());

    let inner_inner = analyzer
        .get_definitions("A.AInner.AInnerInner")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!("A.AInner.AInnerInner", inner_inner.short_name());
    assert_eq!("AInnerInner", inner_inner.identifier());

    let inner_static = analyzer
        .get_definitions("A.AInnerStatic")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!("A.AInnerStatic", inner_static.short_name());
    assert_eq!("AInnerStatic", inner_static.identifier());
}
