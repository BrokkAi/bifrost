mod common;

use brokk_analyzer::usages::{
    FuzzyResult, JsTsExportUsageGraphStrategy, UsageAnalyzer, UsageFinder,
};
use brokk_analyzer::{
    CodeUnit, IAnalyzer, JavascriptAnalyzer, Language, ProjectFile, TypescriptAnalyzer,
};
use common::{InlineTestProject, js_fixture_project, ts_fixture_project};
use std::collections::BTreeSet;

fn js_analyzer() -> JavascriptAnalyzer {
    JavascriptAnalyzer::from_project(js_fixture_project())
}

fn ts_analyzer() -> TypescriptAnalyzer {
    TypescriptAnalyzer::from_project(ts_fixture_project())
}

fn definition_in<'a, I>(units: I, predicate: impl Fn(&CodeUnit) -> bool) -> CodeUnit
where
    I: IntoIterator<Item = &'a CodeUnit>,
{
    units
        .into_iter()
        .find(|cu| predicate(cu))
        .cloned()
        .expect("definition not found")
}

#[test]
fn js_graph_strategy_finds_in_file_references() {
    let analyzer = js_analyzer();
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.js")
    });

    let strategy = JsTsExportUsageGraphStrategy::new();
    let candidate_files: brokk_analyzer::hash::HashSet<ProjectFile> =
        std::iter::once(target.source().clone()).collect();
    let result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidate_files,
        1000,
    );

    let hits: BTreeSet<_> = match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    };

    assert!(
        hits.len() >= 3,
        "graph strategy should resolve multiple in-file BaseClass references, got {} hits",
        hits.len()
    );
    for hit in &hits {
        assert!(hit.start_offset < hit.end_offset);
        assert_ne!(hit.enclosing, target);
    }
}

#[test]
fn ts_graph_strategy_finds_in_file_references() {
    let analyzer = ts_analyzer();
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.ts")
    });

    let strategy = JsTsExportUsageGraphStrategy::new();
    let candidate_files: brokk_analyzer::hash::HashSet<ProjectFile> =
        std::iter::once(target.source().clone()).collect();
    let result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidate_files,
        1000,
    );

    let hits: BTreeSet<_> = match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    };

    assert!(
        hits.len() >= 4,
        "ts graph strategy should pick up extends/new/type annotations, got {} hits",
        hits.len()
    );
}

#[test]
fn usage_finder_routes_jsts_targets_to_graph_strategy() {
    let analyzer = ts_analyzer();
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.ts")
    });

    let finder = UsageFinder::new();
    let result = finder.find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result.into_either().expect("expected Ok hits");
    assert!(
        !hits.is_empty(),
        "UsageFinder should resolve at least one reference for BaseClass via the graph strategy"
    );
}

#[test]
fn ts_graph_strategy_resolves_local_alias_of_imported_owner() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "base.ts",
            r#"
export class BaseClass {}
"#,
        )
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";

const Alias = BaseClass;

export function build(): Alias {
    return new Alias();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("local alias graph success");

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.ts")),
        "expected local alias usage in consumer.ts"
    );
}

#[test]
fn ts_graph_strategy_does_not_match_redeclared_import_name() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass { static build() {} }\n")
        .file("evil.ts", "export class Evil { static build() {} }\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";
import { Evil } from "./evil";

const BaseClass = Evil;

export function build() {
    return BaseClass.build();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("shadowed import graph success");

    assert!(hits.is_empty(), "redeclared import name must not count");
}

#[test]
fn ts_graph_strategy_keeps_function_local_alias_scoped() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass {}\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";

function inside(): Alias {
    const Alias = BaseClass;
    return new Alias();
}

const Alias = Other;

export class Other {}

export function outside() {
    return new Alias();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("function-local alias success");

    assert!(
        hits.iter()
            .all(|hit| hit.enclosing.short_name() == "inside"),
        "only the inner scoped alias should match BaseClass"
    );
}

#[test]
fn ts_graph_strategy_prefers_later_same_scope_redeclaration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass {}\n")
        .file("other.ts", "export class Other {}\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";
import { Other } from "./other";

var Alias = BaseClass;
var Alias = Other;

export function build() {
    return new Alias();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("same-scope redeclaration success");

    assert!(
        hits.iter().all(|hit| hit.enclosing.short_name() != "build"),
        "later same-scope redeclaration must block subsequent build() usage attribution"
    );
}
