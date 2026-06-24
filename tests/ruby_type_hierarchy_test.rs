// Ruby inheritance + mixin hierarchy. Covers ISC-5 (superclass + mixins) and
// ISC-10 (scope_resolution superclass).

use brokk_bifrost::{
    CodeUnit, IAnalyzer, ProjectFile, RubyAnalyzer, TestProject, TypeHierarchyProvider,
};
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

fn ancestor_identifiers(analyzer: &RubyAnalyzer, code_unit: &CodeUnit) -> BTreeSet<String> {
    analyzer
        .get_direct_ancestors(code_unit)
        .iter()
        .map(|cu| cu.identifier().to_string())
        .collect()
}

#[test]
fn direct_superclass_resolves() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/simple.rb");
    let dog = find(&decls, "Dog");
    let ancestors = ancestor_identifiers(&analyzer, dog);
    assert!(ancestors.contains("Animal"), "got {ancestors:?}");
}

#[test]
fn multilevel_ancestors_chain() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/multilevel.rb");
    let child = find(&decls, "Child");

    let direct = ancestor_identifiers(&analyzer, child);
    assert!(direct.contains("Middle"), "got {direct:?}");

    let all: BTreeSet<String> = analyzer
        .get_ancestors(child)
        .iter()
        .map(|cu| cu.identifier().to_string())
        .collect();
    assert!(
        all.contains("Middle") && all.contains("Base"),
        "got {all:?}"
    );
}

#[test]
fn mixins_are_not_type_hierarchy_ancestors() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/mixins.rb");
    let duck = find(&decls, "Duck");
    let ancestors = ancestor_identifiers(&analyzer, duck);
    assert!(!ancestors.contains("Walkable"), "got {ancestors:?}");
    assert!(!ancestors.contains("Swimmable"), "got {ancestors:?}");
    assert!(!ancestors.contains("Comparable"), "got {ancestors:?}");
    assert!(!ancestors.contains("Findable"), "got {ancestors:?}");
}

#[test]
fn scope_resolution_superclass_resolves() {
    let analyzer = analyzer();
    let decls = decls(&analyzer, "inheritance/scope_super.rb");
    let derived = find(&decls, "Derived");
    // class Derived < Outer::Base
    let ancestors = ancestor_identifiers(&analyzer, derived);
    assert!(ancestors.contains("Base"), "got {ancestors:?}");
}
