// Ruby usage discovery via `RubyUsageGraphStrategy`. Ruby's dynamic dispatch
// rarely exposes a receiver's type statically, so usages are resolved by
// method/constant name. These tests pin name-based cross-file call discovery,
// including calls reaching a method through an included module.

use brokk_bifrost::{CodeUnit, IAnalyzer, RubyAnalyzer, TestProject};

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/usage-graph-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn definition(analyzer: &RubyAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

#[test]
fn finds_cross_file_method_usage() {
    let analyzer = analyzer();
    let target = definition(&analyzer, "Greeter.greet");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    // The only call site is App#run in app.rb.
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "run"),
        "expected Greeter#greet usage inside App#run, got {:?}",
        hits.iter()
            .map(|h| h.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn finds_method_usage_through_a_mixin() {
    let analyzer = analyzer();
    // `log` is defined on module Loggable and called inside Service (which
    // includes Loggable). Name-based resolution finds both call sites.
    let target = definition(&analyzer, "Loggable.log");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits
        .iter()
        .map(|h| h.enclosing.identifier().to_string())
        .collect();
    assert!(enclosing.iter().any(|id| id == "work"), "got {enclosing:?}");
    assert!(
        enclosing.iter().any(|id| id == "retry_work"),
        "got {enclosing:?}"
    );
}

#[test]
fn does_not_report_the_declaration_as_a_usage() {
    let analyzer = analyzer();
    let target = definition(&analyzer, "Greeter.greet");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    // The `def greet` declaration itself must not be counted as a usage.
    assert!(hits.iter().all(|hit| hit.enclosing.identifier() != "greet"));
}
