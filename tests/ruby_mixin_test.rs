// Ruby mixin facts (#263): include/prepend/extend are modeled distinctly from
// superclass ancestry. `include`/`prepend` feed instance-method lookup;
// `extend` feeds class/singleton lookup.

use brokk_bifrost::{CodeUnit, IAnalyzer, ProjectFile, RubyAnalyzer, TestProject};
use std::collections::BTreeSet;

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn decls(analyzer: &RubyAnalyzer, rel: &str) -> BTreeSet<CodeUnit> {
    analyzer.get_declarations(&ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        rel,
    ))
}

fn find<'a>(decls: &'a BTreeSet<CodeUnit>, identifier: &str) -> &'a CodeUnit {
    decls
        .iter()
        .find(|cu| cu.identifier() == identifier)
        .unwrap_or_else(|| panic!("no declaration {identifier:?}"))
}

fn identifiers(units: &[CodeUnit]) -> BTreeSet<String> {
    units.iter().map(|cu| cu.identifier().to_string()).collect()
}

#[test]
fn include_and_prepend_facts_are_distinct() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/mixins.rb");
    let duck = find(&decls, "Duck");

    let included = identifiers(&analyzer.included_modules(duck));
    assert!(included.contains("Walkable"), "got {included:?}");
    assert!(included.contains("Swimmable"), "got {included:?}");

    let prepended = identifiers(&analyzer.prepended_modules(duck));
    assert!(prepended.contains("Quackable"), "got {prepended:?}");

    // `prepend Quackable` is not an `include`.
    assert!(!included.contains("Quackable"), "got {included:?}");
}

#[test]
fn include_feeds_instance_lookup_extend_feeds_class_lookup() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/mixin_kinds.rb");
    let user = find(&decls, "User");

    let included = identifiers(&analyzer.included_modules(user));
    let extended = identifiers(&analyzer.extended_modules(user));

    // `include Auditable` -> instance lookup; `extend Findable` -> class lookup.
    assert!(included.contains("Auditable"), "got {included:?}");
    assert!(extended.contains("Findable"), "got {extended:?}");
}

#[test]
fn extend_does_not_contribute_to_instance_lookup() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/mixin_kinds.rb");
    let user = find(&decls, "User");

    // Negative: `extend Findable` must NOT make Findable an instance-lookup mixin.
    let included = identifiers(&analyzer.included_modules(user));
    assert!(!included.contains("Findable"), "got {included:?}");
}

#[test]
fn include_does_not_contribute_to_class_lookup() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/mixin_kinds.rb");
    let user = find(&decls, "User");

    // Negative: `include Auditable` must NOT make Auditable a class-lookup mixin.
    let extended = identifiers(&analyzer.extended_modules(user));
    assert!(!extended.contains("Auditable"), "got {extended:?}");
}

#[test]
fn mixin_modules_resolve_to_declarations() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/mixin_kinds.rb");
    let user = find(&decls, "User");

    // The fact resolves to the actual module declaration, not just a name.
    let auditable = analyzer
        .included_modules(user)
        .into_iter()
        .find(|cu| cu.identifier() == "Auditable")
        .expect("Auditable resolved");
    assert!(auditable.is_module());
}
