use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject};
use std::collections::BTreeSet;

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

fn file_by_name(analyzer: &JavaAnalyzer, name: &str) -> ProjectFile {
    ProjectFile::new(analyzer.project().root().to_path_buf(), name)
}

#[test]
fn discovers_fixture_lambdas_and_extracts_their_sources() {
    let analyzer = fixture_analyzer();

    let interface_file = file_by_name(&analyzer, "Interface.java");
    let interface_lambda = analyzer
        .get_declarations(&interface_file)
        .into_iter()
        .find(|code_unit| code_unit.fq_name() == "Interface.Interface$anon$5:24")
        .unwrap();
    assert_eq!(
        Some("root -> { }".to_string()),
        analyzer.get_source(&interface_lambda, false)
    );

    let anon_file = file_by_name(&analyzer, "AnonymousUsage.java");
    let nested_lambda = analyzer
        .get_declarations(&anon_file)
        .into_iter()
        .find(|code_unit| {
            code_unit.fq_name() == "AnonymousUsage.NestedClass.getSomething$anon$15:37"
        })
        .unwrap();
    assert_eq!(
        Some("s -> map.put(\"foo\", \"test\")".to_string()),
        analyzer.get_source(&nested_lambda, false)
    );
}

#[test]
fn lambda_is_child_of_enclosing_method_and_counts_as_anonymous() {
    let analyzer = fixture_analyzer();

    let method = analyzer
        .get_definitions("AnonymousUsage.NestedClass.getSomething")
        .into_iter()
        .next()
        .unwrap();
    let child_names: BTreeSet<_> = analyzer
        .get_direct_children(&method)
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .map(|code_unit| code_unit.fq_name())
        .collect();

    assert!(child_names.contains("AnonymousUsage.NestedClass.getSomething$anon$15:37"));
    assert!(analyzer.is_anonymous_structure("AnonymousUsage.NestedClass.getSomething$anon$15:37"));
    assert!(!analyzer.is_anonymous_structure("AnonymousUsage.NestedClass.getSomething"));
}

#[test]
fn lambda_names_are_discoverable_but_filtered_from_search_results() {
    let analyzer = fixture_analyzer();

    let interface_file = file_by_name(&analyzer, "Interface.java");
    let function_names: BTreeSet<_> = analyzer
        .get_declarations(&interface_file)
        .into_iter()
        .filter(|code_unit| code_unit.is_function())
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(function_names.contains("Interface.Interface$anon$5:24"));

    let search_names: BTreeSet<_> = analyzer
        .search_definitions("AnonymousUsage.NestedClass.getSomething.*", true)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    assert!(!search_names.iter().any(|name| name.contains("$anon$")));
}

#[test]
fn normalize_full_name_matches_java_helper_surface() {
    let analyzer = fixture_analyzer();

    assert_eq!(
        "package.Class.method",
        analyzer.normalize_full_name("package.Class.method")
    );
    assert_eq!(
        "package.Class.method",
        analyzer.normalize_full_name("package.Class.method$1")
    );
    assert_eq!(
        "package.A.AInner.method",
        analyzer.normalize_full_name("package.A.AInner.method")
    );
    assert_eq!(
        "io.github.jbellis.brokk.util.SlidingWindowCache.getCachedKeys",
        analyzer.normalize_full_name(
            "io.github.jbellis.brokk.util.SlidingWindowCache<K, V extends Disposable>.getCachedKeys",
        )
    );
}
