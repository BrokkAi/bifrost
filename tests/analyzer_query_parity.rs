mod common;

use brokk_bifrost::{
    AnalyzerDelegate, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, PythonAnalyzer,
};
use common::InlineTestProject;
use std::collections::{BTreeMap, BTreeSet};

fn as_set<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn assert_query_alias_parity(analyzer: &dyn IAnalyzer, file: &brokk_bifrost::ProjectFile) {
    assert_eq!(
        analyzer.top_level_declarations(file),
        analyzer.get_top_level_declarations(file)
    );
    assert_eq!(
        as_set(analyzer.analyzed_files()),
        analyzer.get_analyzed_files()
    );
    assert_eq!(
        as_set(analyzer.all_declarations()),
        as_set(analyzer.get_all_declarations())
    );
    assert_eq!(analyzer.declarations(file), analyzer.get_declarations(file));
    assert_eq!(
        analyzer.import_statements(file),
        analyzer.import_statements_of(file)
    );
}

fn assert_unit_query_alias_parity(analyzer: &dyn IAnalyzer, unit: &brokk_bifrost::CodeUnit) {
    assert_eq!(
        analyzer.direct_children(unit),
        analyzer.get_direct_children(unit)
    );
    assert_eq!(analyzer.ranges(unit), analyzer.ranges_of(unit));
    assert_eq!(analyzer.signatures(unit), analyzer.signatures_of(unit));
    assert_eq!(
        analyzer.signature_metadata(unit),
        analyzer.signature_metadata_of(unit)
    );
}

fn definition(analyzer: &dyn IAnalyzer, fq_name: &str) -> brokk_bifrost::CodeUnit {
    let primitive: Vec<_> = analyzer.definitions(fq_name).collect();
    assert_eq!(primitive, analyzer.get_definitions(fq_name));
    primitive
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition {fq_name}"))
}

fn assert_primary_range(analyzer: &dyn IAnalyzer, expected: &brokk_bifrost::CodeUnit) {
    let (_, primary_range) = analyzer
        .all_declarations_with_primary_ranges()
        .into_iter()
        .find(|(unit, _)| unit == expected)
        .unwrap_or_else(|| panic!("missing declaration {}", expected.fq_name()));
    let expected_range = analyzer
        .ranges(expected)
        .into_iter()
        .min_by_key(|range| (range.start_line, range.start_byte));
    assert_eq!(primary_range, expected_range);
    assert!(primary_range.is_some());
}

#[test]
fn java_primitive_queries_match_forwarding_aliases() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Service.java",
            r#"package pkg;
import java.util.List;

public class Service {
    private int count;

    public String greet(String name) {
        return name;
    }
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    let file = project.file("pkg/Service.java");

    assert_query_alias_parity(&analyzer, &file);
    let class = definition(&analyzer, "pkg.Service");
    let method = definition(&analyzer, "pkg.Service.greet");
    assert_unit_query_alias_parity(&analyzer, &class);
    assert_unit_query_alias_parity(&analyzer, &method);

    assert!(
        analyzer
            .direct_children(&class)
            .iter()
            .any(|unit| unit == &method)
    );
    assert!(!analyzer.import_statements(&file).is_empty());
    assert!(!analyzer.signatures(&method).is_empty());
    assert!(!analyzer.signature_metadata(&method).is_empty());
    assert_primary_range(&analyzer, &class);
    assert_primary_range(&analyzer, &method);
}

#[test]
fn python_primitive_queries_match_forwarding_aliases() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "worker.py",
            r#"import os

class Worker:
    def run(self):
        return os.getcwd()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let file = project.file("worker.py");

    assert_query_alias_parity(&analyzer, &file);
    let class = definition(&analyzer, "worker.Worker");
    let method = definition(&analyzer, "worker.Worker.run");
    assert_unit_query_alias_parity(&analyzer, &class);
    assert_unit_query_alias_parity(&analyzer, &method);

    assert!(
        analyzer
            .direct_children(&class)
            .iter()
            .any(|unit| unit == &method)
    );
    assert!(!analyzer.import_statements(&file).is_empty());
    assert!(!analyzer.signatures(&method).is_empty());
    assert_primary_range(&analyzer, &class);
    assert_primary_range(&analyzer, &method);
}

#[test]
fn multi_analyzer_preserves_owned_query_results_across_languages() {
    let project = InlineTestProject::new()
        .file("pkg/Service.java", "package pkg; public class Service {}\n")
        .file("worker.py", "class Worker:\n    pass\n")
        .build();
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.project().clone())),
        ),
        (
            Language::Python,
            AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.project().clone())),
        ),
    ]));
    let java_file = project.file("pkg/Service.java");
    let python_file = project.file("worker.py");

    assert_query_alias_parity(&multi, &java_file);
    assert_query_alias_parity(&multi, &python_file);
    let java_class = definition(&multi, "pkg.Service");
    let python_class = definition(&multi, "worker.Worker");
    assert_primary_range(&multi, &java_class);
    assert_primary_range(&multi, &python_class);

    let declarations = as_set(multi.all_declarations());
    assert!(declarations.contains(&java_class));
    assert!(declarations.contains(&python_class));
    assert_eq!(
        multi.get_analyzed_files(),
        BTreeSet::from([java_file, python_file])
    );
}
