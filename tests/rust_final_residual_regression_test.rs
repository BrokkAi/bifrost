mod common;

use brokk_bifrost::usages::{UsageFinder, UsageHit};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, RustAnalyzer};
use common::InlineTestProject;

fn analyzer_for(source: &str) -> (common::BuiltInlineTestProject, RustAnalyzer) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn member(analyzer: &RustAnalyzer, owner: &str, name: &str) -> CodeUnit {
    let file = analyzer
        .get_analyzed_files()
        .into_iter()
        .next()
        .expect("Rust test file");
    analyzer
        .exact_member(&file, owner, name, true)
        .or_else(|| analyzer.exact_member(&file, owner, name, false))
        .unwrap_or_else(|| panic!("missing member {owner}.{name}"))
}

fn hits(analyzer: &RustAnalyzer, target: CodeUnit) -> Vec<UsageHit> {
    UsageFinder::new()
        .find_usages_default(analyzer, &[target])
        .into_either()
        .expect("Rust inverse lookup")
        .into_iter()
        .collect()
}

#[test]
fn inverse_rust_usages_find_unqualified_tuple_pattern_variants() {
    let source = r#"
enum ExpectedValue { I64(i64), Other }
enum Decoy { I64(i64) }

fn same(left: ExpectedValue, right: ExpectedValue) -> bool {
    use ExpectedValue::*;
    match (left, right) {
        (I64(a), I64(b)) => a == b,
        _ => false,
    }
}

fn decoy(value: Decoy) -> i64 {
    match value { Decoy::I64(inner) => inner }
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let variant = member(&analyzer, "ExpectedValue", "I64");
    let found = hits(&analyzer, variant);
    let expected: Vec<_> = source
        .match_indices("I64")
        .skip(2)
        .take(2)
        .map(|(start, name)| (start, start + name.len()))
        .collect();

    assert_eq!(2, found.len(), "tuple-pattern variant hits: {found:#?}");
    assert!(expected.into_iter().all(|range| {
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == range)
    }));
}

#[test]
fn inverse_rust_tuple_pattern_variants_fail_closed_on_shadowing_and_ambiguity() {
    let source = r#"
enum Wanted { I64(i64), Other }
enum Decoy { I64(i64), Other }

fn explicit_decoy(value: Decoy) -> i64 {
    use Wanted::*;
    use Decoy::I64;
    match value { I64(inner) => inner, _ => 0 }
}

fn ambiguous(value: Wanted) -> i64 {
    use Wanted::*;
    use Decoy::*;
    match value { I64(inner) => inner, _ => 0 }
}

fn local_item() -> i64 {
    use Wanted::*;
    struct I64(i64);
    let value = I64(1);
    match value { I64(inner) => inner }
}

fn scoped_decoy(value: Decoy) -> i64 {
    match value { Decoy::I64(inner) => inner, _ => 0 }
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let wanted = member(&analyzer, "Wanted", "I64");
    let found = hits(&analyzer, wanted);

    assert!(
        found.is_empty(),
        "decoy, ambiguous, local-item, and scoped-decoy patterns must not cross-match: {found:#?}"
    );
}

#[test]
fn inverse_rust_usages_keep_nested_struct_initializer_field_owner() {
    let source = r#"
struct Waiter { pointers: usize }
struct WaiterCell(Waiter);
struct Recv { waiter: WaiterCell }
struct Decoy { pointers: usize }

fn make() -> Recv {
    Recv { waiter: WaiterCell(Waiter { pointers: 1 }) }
}

fn decoy() -> Decoy {
    Decoy { pointers: 2 }
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let field = member(&analyzer, "Waiter", "pointers");
    let found = hits(&analyzer, field);
    let expected = source
        .match_indices("pointers")
        .nth(2)
        .map(|(start, name)| (start, start + name.len()))
        .expect("Waiter initializer field");

    assert_eq!(1, found.len(), "nested initializer field hits: {found:#?}");
    assert_eq!(
        expected,
        (found[0].start_offset, found[0].end_offset),
        "the Decoy field must not cross-match"
    );
}

#[test]
fn inverse_rust_usages_keep_both_nested_same_file_calls() {
    let source = r#"
fn filter_as_usize(value: usize) -> usize { value }

fn compare(left: usize, right: usize) -> std::cmp::Ordering {
    filter_as_usize(left).cmp(&filter_as_usize(right))
}

fn shadowed(filter_as_usize: fn(usize) -> usize) -> usize {
    filter_as_usize(0)
}
"#;
    let (_project, analyzer) = analyzer_for(source);
    let target = definition(&analyzer, "filter_as_usize");
    let found = hits(&analyzer, target);
    let expected: Vec<_> = source
        .match_indices("filter_as_usize")
        .skip(1)
        .take(2)
        .map(|(start, name)| (start, start + name.len()))
        .collect();

    assert_eq!(2, found.len(), "nested same-file call hits: {found:#?}");
    assert!(expected.into_iter().all(|range| {
        found
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == range)
    }));
}
