mod common;

use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, JsTsExportUsageGraphStrategy, UsageAnalyzer,
    UsageFinder, UsageHitKind,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, JavascriptAnalyzer, Language, MultiAnalyzer,
    ProjectFile, TypescriptAnalyzer,
};
use common::{InlineTestProject, js_fixture_project, ts_fixture_project};
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn js_analyzer() -> JavascriptAnalyzer {
    JavascriptAnalyzer::from_project(js_fixture_project())
}

fn ts_analyzer() -> TypescriptAnalyzer {
    TypescriptAnalyzer::from_project(ts_fixture_project())
}

fn definition_in<I, T>(units: I, predicate: impl Fn(&CodeUnit) -> bool) -> CodeUnit
where
    I: IntoIterator<Item = T>,
    T: Borrow<CodeUnit>,
{
    units
        .into_iter()
        .find(|cu| predicate(cu.borrow()))
        .map(|cu| cu.borrow().clone())
        .expect("definition not found")
}

#[test]
fn js_graph_strategy_finds_in_file_references() {
    let analyzer = js_analyzer();
    let units: Vec<_> = analyzer.all_declarations().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.js")
    });

    let strategy = JsTsExportUsageGraphStrategy::new();
    let candidate_files: brokk_bifrost::hash::HashSet<ProjectFile> =
        std::iter::once(target.source().clone()).collect();
    let result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidate_files,
        1000,
    );

    let hits: BTreeSet<_> = match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
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
    let units: Vec<_> = analyzer.all_declarations().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.ts")
    });

    let strategy = JsTsExportUsageGraphStrategy::new();
    let candidate_files: brokk_bifrost::hash::HashSet<ProjectFile> =
        std::iter::once(target.source().clone()).collect();
    let result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidate_files,
        1000,
    );

    let hits: BTreeSet<_> = match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
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
    let units: Vec<_> = analyzer.all_declarations().collect();
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
    let units: Vec<_> = analyzer.all_declarations().collect();
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
    let units: Vec<_> = analyzer.all_declarations().collect();
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
    let units: Vec<_> = analyzer.all_declarations().collect();
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
    let units: Vec<_> = analyzer.all_declarations().collect();
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

#[test]
fn ts_graph_strategy_parameter_blocks_top_level_alias_match() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass {}\n")
        .file("other.ts", "export class Other {}\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";
import { Other } from "./other";

const Alias = BaseClass;

export function inside(Alias: typeof Other) {
    return new Alias();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("parameter shadow success");

    assert!(
        hits.iter()
            .all(|hit| hit.enclosing.short_name() != "inside"),
        "parameter named Alias must block top-level alias matches inside the function"
    );
}

#[test]
fn ts_graph_strategy_parameter_blocks_imported_owner_fallback() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass { static build() {} }\n")
        .file("other.ts", "export class Other { static build() {} }\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";
import { Other } from "./other";

export function inside(BaseClass: typeof Other) {
    return BaseClass.build();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("parameter import shadow success");

    assert!(
        hits.is_empty(),
        "parameter named BaseClass must block imported-owner fallback inside the function"
    );
}

#[test]
fn ts_graph_strategy_destructured_parameter_blocks_alias_match() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("base.ts", "export class BaseClass {}\n")
        .file("other.ts", "export class Other {}\n")
        .file(
            "consumer.ts",
            r#"
import { BaseClass } from "./base";
import { Other } from "./other";

const Alias = BaseClass;

export function inside({ Alias }: { Alias: typeof Other }) {
    return new Alias();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let units: Vec<_> = analyzer.all_declarations().collect();
    let base_file = project.file("base.ts");
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "BaseClass" && cu.source() == &base_file
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("destructured parameter shadow success");

    assert!(
        hits.iter()
            .all(|hit| hit.enclosing.short_name() != "inside"),
        "destructured parameter binding Alias must block top-level alias matches"
    );
}

fn ts_inline_analyzer(
    build: impl FnOnce(InlineTestProject) -> common::BuiltInlineTestProject,
) -> (common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let project = build(InlineTestProject::with_language(
        brokk_bifrost::Language::TypeScript,
    ));
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn js_inline_analyzer(
    build: impl FnOnce(InlineTestProject) -> common::BuiltInlineTestProject,
) -> (common::BuiltInlineTestProject, JavascriptAnalyzer) {
    let project = build(InlineTestProject::with_language(
        brokk_bifrost::Language::JavaScript,
    ));
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn find_ts_target(
    analyzer: &TypescriptAnalyzer,
    source_file: &ProjectFile,
    predicate: impl Fn(&CodeUnit) -> bool,
) -> CodeUnit {
    analyzer
        .all_declarations()
        .find(|cu| cu.source() == source_file && predicate(cu))
        .expect("target definition not found")
}

fn find_js_target(
    analyzer: &JavascriptAnalyzer,
    source_file: &ProjectFile,
    predicate: impl Fn(&CodeUnit) -> bool,
) -> CodeUnit {
    analyzer
        .all_declarations()
        .find(|cu| cu.source() == source_file && predicate(cu))
        .expect("target definition not found")
}

fn authoritative_js_hits(
    analyzer: &JavascriptAnalyzer,
    target: &CodeUnit,
    candidate: ProjectFile,
) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            100,
        );
    match query.result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload.get(target).cloned().unwrap_or_default(),
        other => panic!("expected authoritative JS usage success, got {other:#?}"),
    }
}

fn authoritative_ts_hits(
    analyzer: &TypescriptAnalyzer,
    target: &CodeUnit,
    candidate: ProjectFile,
) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            100,
        );
    match query.result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload.get(target).cloned().unwrap_or_default(),
        other => panic!("expected authoritative TS usage success, got {other:#?}"),
    }
}

fn identifier_occurrence_range(
    source: &str,
    identifier: &str,
    occurrence: usize,
) -> (usize, usize) {
    let start = source
        .match_indices(identifier)
        .nth(occurrence)
        .map(|(start, _)| start)
        .unwrap_or_else(|| panic!("missing occurrence {occurrence} of {identifier:?}"));
    (start, start + identifier.len())
}

#[test]
fn js_window_global_property_finds_bare_global_without_widening_members() {
    let source = r#"window.Promise = makePromise();
function readGlobal() { return typeof Promise; }
function readExplicit() { return window.Promise; }
function shadowed(Promise) { return typeof Promise; }
function shadowedWindow(window) { return window.Promise; }
function readOther() { return other.Promise; }
other.Promise = makeOtherPromise();
"#;
    let (project, analyzer) = js_inline_analyzer(|p| p.file("polyfills.js", source).build());
    let file = project.file("polyfills.js");
    let target = find_js_target(&analyzer, &file, |unit| {
        unit.is_field() && unit.fq_name() == "window.Promise"
    });

    let hits = authoritative_js_hits(&analyzer, &target, file);
    let ranges: BTreeSet<_> = hits
        .iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();

    assert_eq!(
        BTreeSet::from([
            identifier_occurrence_range(source, "Promise", 2),
            identifier_occurrence_range(source, "Promise", 3),
        ]),
        ranges,
        "only exact explicit and unshadowed bare browser globals should resolve: {hits:#?}"
    );
}

#[test]
fn js_window_global_property_rejects_named_expression_receiver_bindings() {
    for source in [
        r#"const holder = function* window() {
  window.Promise = makePromise();
  return typeof Promise;
};
"#,
        r#"const Holder = class window {
  readGlobal() {
    window.Promise = makePromise();
    return typeof Promise;
  }
};
"#,
    ] {
        let (project, analyzer) = js_inline_analyzer(|p| p.file("polyfills.js", source).build());
        let file = project.file("polyfills.js");
        let target = find_js_target(&analyzer, &file, |unit| {
            unit.is_field() && unit.fq_name() == "window.Promise"
        });

        let hits = authoritative_js_hits(&analyzer, &target, file);
        assert!(
            hits.is_empty(),
            "a named expression's self-binding is not the browser global: {hits:#?}"
        );
    }
}

#[test]
fn js_window_global_property_respects_later_lexical_bindings() {
    for source in [
        r#"window.Promise = makePromise();
function readBeforeFileBinding() { return typeof Promise; }
const Promise = makeLocalPromise();
"#,
        r#"window.Promise = makePromise();
function readBeforeFunctionBinding() {
    const before = typeof Promise;
    var Promise;
    return before;
}
"#,
    ] {
        let (project, analyzer) = js_inline_analyzer(|p| p.file("polyfills.js", source).build());
        let file = project.file("polyfills.js");
        let target = find_js_target(&analyzer, &file, |unit| {
            unit.is_field() && unit.fq_name() == "window.Promise"
        });

        let hits = authoritative_js_hits(&analyzer, &target, file);
        assert!(
            hits.is_empty(),
            "TDZ and var-hoisted bindings must shadow earlier reads: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_js_usage_counts_assignment_pattern_default_rhs() {
    let source = r#"const UNKNOWN = 0;
class Path {
  newChild(name, type = UNKNOWN) { return type; }
  nested({ [UNKNOWN]: [{ value = UNKNOWN } = UNKNOWN] } = UNKNOWN) { return value; }
  shadow(UNKNOWN = 1) { return UNKNOWN; }
}
"#;
    let (project, analyzer) = js_inline_analyzer(|p| p.file("assignment.js", source).build());
    let file = project.file("assignment.js");
    let target = find_js_target(&analyzer, &file, |unit| {
        unit.is_field() && unit.identifier() == "UNKNOWN"
    });

    let hits = authoritative_js_hits(&analyzer, &target, file.clone());
    let ranges = hits
        .iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        identifier_occurrence_range(source, "UNKNOWN", 1),
        identifier_occurrence_range(source, "UNKNOWN", 2),
        identifier_occurrence_range(source, "UNKNOWN", 3),
        identifier_occurrence_range(source, "UNKNOWN", 4),
        identifier_occurrence_range(source, "UNKNOWN", 5),
    ]);

    assert_eq!(
        expected, ranges,
        "computed keys and nested default RHS reads must reference UNKNOWN, while the real UNKNOWN parameter shadows its body; hits: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == file));
}

#[test]
fn authoritative_js_commonjs_usage_counts_default_rhs_and_later_value() {
    let target_source = "const kEmptyObject = {};\nmodule.exports = { kEmptyObject };\n";
    let consumer_source = r#"const { kEmptyObject } = require('./target');
function use(options = kEmptyObject) {
  return { attributes: kEmptyObject };
}
"#;
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("target.js", target_source)
            .file("consumer.js", consumer_source)
            .build()
    });
    let target_file = project.file("target.js");
    let consumer = project.file("consumer.js");
    let target = find_js_target(&analyzer, &target_file, |unit| {
        unit.is_field() && unit.identifier() == "kEmptyObject"
    });

    let hits = authoritative_js_hits(&analyzer, &target, consumer.clone());
    let ranges = hits
        .iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    let default_rhs = identifier_occurrence_range(consumer_source, "kEmptyObject", 1);
    let object_value = identifier_occurrence_range(consumer_source, "kEmptyObject", 2);

    assert!(
        ranges.contains(&default_rhs),
        "the imported assignment-pattern default RHS must be retained at {default_rhs:?}; hits: {hits:#?}"
    );
    assert!(
        ranges.contains(&object_value),
        "the later object value must remain a reference at {object_value:?}; hits: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == consumer));
}

#[test]
fn authoritative_ts_typed_destructuring_only_types_real_binder_as_receiver() {
    let consumer_source = r#"import { Foo } from './target';
import { Other } from './other';
declare const COMPUTED: string;
declare const DEFAULT: Other;
export function use({ [COMPUTED]: real = DEFAULT }: Record<string, Foo>) {
  real.bar();
  DEFAULT.bar();
  COMPUTED.bar();
}
"#;
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("target.ts", "export class Foo { bar() {} }\n")
            .file("other.ts", "export class Other { bar() {} }\n")
            .file("consumer.ts", consumer_source)
            .build()
    });
    let target_file = project.file("target.ts");
    let consumer = project.file("consumer.ts");
    let target = find_ts_target(&analyzer, &target_file, |unit| {
        unit.is_function() && unit.identifier().starts_with("bar")
    });

    let hits = authoritative_ts_hits(&analyzer, &target, consumer.clone());
    let ranges = hits
        .iter()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        BTreeSet::from([identifier_occurrence_range(consumer_source, "bar", 0)]),
        ranges,
        "the typed destructuring binder is a Foo receiver, but its computed key and default expression are reads rather than receiver bindings; hits: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == consumer));
}

#[test]
fn authoritative_js_array_binder_shadows_import_but_keeps_default_rhs_read() {
    let consumer_source = r#"import { TARGET, DEFAULT } from './target';
export function use(values) {
  const [TARGET = DEFAULT] = values;
  return TARGET;
}
"#;
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "target.js",
            "export const TARGET = 0;\nexport const DEFAULT = 1;\n",
        )
        .file("consumer.js", consumer_source)
        .build()
    });
    let target_file = project.file("target.js");
    let consumer = project.file("consumer.js");
    let target = find_js_target(&analyzer, &target_file, |unit| {
        unit.is_field() && unit.identifier() == "TARGET"
    });
    let default = find_js_target(&analyzer, &target_file, |unit| {
        unit.is_field() && unit.identifier() == "DEFAULT"
    });

    let target_hits = authoritative_js_hits(&analyzer, &target, consumer.clone());
    assert!(
        target_hits
            .iter()
            .all(|hit| hit.kind == UsageHitKind::Import),
        "the array binder must shadow every non-import TARGET reference in its function scope: {target_hits:#?}"
    );

    let default_hits = authoritative_js_hits(&analyzer, &default, consumer.clone());
    let default_ranges = default_hits
        .iter()
        .filter(|hit| hit.kind != UsageHitKind::Import)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        BTreeSet::from([identifier_occurrence_range(consumer_source, "DEFAULT", 1,)]),
        default_ranges,
        "the array binding's default RHS must remain an imported DEFAULT read: {default_hits:#?}"
    );
}

// Models the call-graph hit surface (`all_hits`): `Import` and self-receiver hits
// belong to find-references, not to usage/call-graph counts, so they are filtered here.
fn flatten_hits(result: FuzzyResult) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .filter(|hit| {
                hit.kind
                    .included_in(brokk_bifrost::usages::UsageHitSurface::ExternalUsages)
            })
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    }
}

fn flatten_lsp_hits(result: FuzzyResult) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .filter(|hit| {
                hit.kind
                    .included_in(brokk_bifrost::usages::UsageHitSurface::LspReferences)
            })
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    }
}

fn flatten_unproven_hits(result: FuzzyResult) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    match result {
        FuzzyResult::Success {
            unproven_by_overload,
            ..
        } => unproven_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .filter(|hit| {
                hit.kind
                    .included_in(brokk_bifrost::usages::UsageHitSurface::ExternalUsages)
            })
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn ts_jsx_attributes_use_exact_imported_component_props_owner() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "child.tsx",
            r#"
export interface ChildProps { title: string }
export interface OtherProps { title: string }
export function Child(_props: ChildProps) { return null }
export function Other(_props: OtherProps) { return null }
"#,
        )
        .file(
            "view.tsx",
            r#"
import { Child, Other } from './child'
export function ViewOne() { return <Child title="one" /> }
export function ViewTwo() { return <Child title="two" /> }
export function OtherView() { return <Other title="other" /> }
export function ExternalView() { return <External title="external" /> }
"#,
        )
        .build()
    });
    let target = find_ts_target(&analyzer, &project.file("child.tsx"), |unit| {
        unit.fq_name() == "ChildProps.title"
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(
        2,
        hits.len(),
        "expected only Child.title attributes: {hits:?}"
    );
    let enclosings = hits
        .iter()
        .map(|hit| hit.enclosing.short_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(BTreeSet::from(["ViewOne", "ViewTwo"]), enclosings);
}

#[test]
fn js_seedless_factory_returned_unexported_class_method_is_proven() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "duration.js",
            "class Duration {\n  asDays() {}\n}\nexport function duration() { return new Duration(); }\n",
        )
        .file(
            "consumer.js",
            "import { duration } from './duration';\nexport function run() { return duration().asDays(); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("duration.js"), |cu| {
        cu.short_name() == "Duration.asDays" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js") && hit.snippet.contains("asDays")),
        "structured factory-return analysis should prove the external method call, got {hits:?}"
    );
}

#[test]
fn js_commonjs_barrel_factory_returned_class_method_is_proven() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib.js",
            "class Client {\n  request() {}\n}\nfunction create() { return new Client(); }\nmodule.exports = { Client, create };\n",
        )
        .file("barrel.js", "module.exports = require('./lib');\n")
        .file(
            "app.js",
            "const { Client } = require('./barrel');\nnew Client().request();\nrequire('./barrel').create().request();\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.short_name() == "Client.request" && cu.is_function()
    });
    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(
        2,
        hits.iter()
            .filter(|hit| hit.file == project.file("app.js"))
            .count(),
        "both direct construction and CommonJS barrel factory calls should be proven: {hits:#?}"
    );
}

#[test]
fn js_seedless_method_with_self_call_proves_external_factory_receiver() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "duration.js",
            "class Duration {\n  toISOString() {}\n  clone() { return this.toISOString(); }\n}\nexport function duration() { return new Duration(); }\n",
        )
        .file(
            "consumer.js",
            "import { duration } from './duration';\nexport function run() { return duration().toISOString(); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("duration.js"), |cu| {
        cu.short_name() == "Duration.toISOString" && cu.is_function()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    assert!(
        result.all_hits_including_imports().iter().any(|hit| {
            hit.file == project.file("duration.js") && hit.snippet.contains("this.toISOString")
        }),
        "self-call should remain editor-visible: {result:?}"
    );
    let proven_hits = flatten_hits(result);
    assert!(
        proven_hits.iter().any(|hit| {
            hit.file == project.file("consumer.js") && hit.snippet.contains("toISOString")
        }),
        "seedless scan must prove the external factory receiver even when the declaring file has a self-call, got {proven_hits:?}"
    );
}

#[test]
fn js_seedless_unprovable_external_member_match_is_unproven() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "duration.js",
            "class Duration {\n  asDays() {}\n}\nexport function duration() { return new Duration(); }\n",
        )
        .file(
            "consumer.js",
            "export function run(value) { return value.asDays(); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("duration.js"), |cu| {
        cu.short_name() == "Duration.asDays" && cu.is_function()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    assert!(
        result.all_hits().is_empty(),
        "unprovable receiver match must not be reported as proven: {result:?}"
    );
    let unproven_hits = flatten_unproven_hits(result);
    assert!(
        unproven_hits
            .iter()
            .any(|hit| hit.file == project.file("consumer.js") && hit.snippet.contains("asDays")),
        "unprovable external member match should be preserved as unproven, got {unproven_hits:?}"
    );
}

#[test]
fn ts_instance_method_scan_keeps_js_emitted_import_boundary_calls_unproven() {
    let project = InlineTestProject::new()
        .file(
            "src/core.ts",
            "export class ProcessPromise {\n  pipe(dest: unknown): ProcessPromise { return this; }\n}\n",
        )
        .file(
            "test/core.test.js",
            "import { ProcessPromise } from '../build/index.js';\nconst p1 = makeProcess();\nconst p2 = p1.pipe(makeProcess());\n",
        )
        .build();
    let analyzer = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::JavaScript,
            AnalyzerDelegate::JavaScript(JavascriptAnalyzer::from_project(
                project.project().clone(),
            )),
        ),
        (
            Language::TypeScript,
            AnalyzerDelegate::TypeScript(TypescriptAnalyzer::from_project(
                project.project().clone(),
            )),
        ),
    ]));
    let target = analyzer
        .all_declarations()
        .find(|unit| {
            unit.source() == &project.file("src/core.ts")
                && unit.short_name() == "ProcessPromise.pipe"
                && unit.is_function()
        })
        .expect("ProcessPromise.pipe target");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);
    let unproven_hits = flatten_unproven_hits(result);

    assert!(
        unproven_hits.iter().any(|hit| {
            hit.file == project.file("test/core.test.js") && hit.snippet.contains("p1.pipe")
        }),
        "the unresolved emitted-file import boundary must retain the structured member call as unproven, got {unproven_hits:?}"
    );
}

#[test]
fn js_parent_of_module_scoped_export_const_returns_file_scope_module() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "src/constant.js",
            "export const MILLISECONDS_A_DAY = 86400000;\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("src/constant.js"), |cu| {
        cu.identifier() == "MILLISECONDS_A_DAY" && cu.is_field()
    });

    assert_eq!("constant.js.MILLISECONDS_A_DAY", target.short_name());

    let parent = analyzer
        .parent_of(&target)
        .expect("module-scoped exported const should have a file-scope parent");
    assert!(parent.is_file_scope());
    assert_eq!("src/constant.js", parent.fq_name());
}

#[test]
fn ts_uninitialized_module_variable_bare_reads_preserve_exact_identity() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "target.ts",
            r#"
type HttpSetup = {};
declare function send(client: HttpSetup, config: unknown): unknown;
let httpClient: HttpSetup;

export function request(config: unknown) {
  if (!httpClient) {
    throw new Error('missing client');
  }
  return send(httpClient, config);
}

export function shadowed(httpClient: HttpSetup) {
  return send(httpClient, {});
}

export function uninitializedLocalShadow() {
  let httpClient: HttpSetup;
  return { client: httpClient };
}
"#,
        )
        .file(
            "unrelated.ts",
            r#"
type HttpSetup = {};
let httpClient: HttpSetup;

export function request(config: unknown) {
  if (!httpClient) {
    throw new Error('missing client');
  }
  return send(httpClient, config);
}
"#,
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("target.ts"), |cu| {
        cu.identifier() == "httpClient" && cu.is_field()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(
        hits.len(),
        2,
        "only the target module variable's two unshadowed reads should match: {hits:?}"
    );
    assert!(
        hits.iter().all(|hit| hit.file == project.file("target.ts")),
        "a same-name variable in another module must not match: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("if (!httpClient)")),
        "the function-body read should be present: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("send(httpClient, config)")),
        "the call-argument read should be present: {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("client: httpClient")),
        "an uninitialized function-local binding must shadow the module target: {hits:?}"
    );
}

#[test]
fn js_export_const_seed_resolves_destructured_import_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "src/constant.js",
            "export const MILLISECONDS_A_DAY = 86400000;\n",
        )
        .file(
            "src/plugin/duration/index.js",
            "import { MILLISECONDS_A_DAY } from '../../constant.js';\n\
                 export function days(ms) {\n\
                   return ms / MILLISECONDS_A_DAY;\n\
                 }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("src/constant.js"), |cu| {
        cu.identifier() == "MILLISECONDS_A_DAY" && cu.is_field()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/plugin/duration/index.js")
                && hit.snippet.contains("MILLISECONDS_A_DAY")
        }),
        "expected destructured import usage to be counted, got {hits:?}"
    );
}

#[test]
fn js_export_const_seed_resolves_namespace_import_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "src/constant.js",
            "export const MILLISECONDS_A_DAY = 86400000;\n",
        )
        .file(
            "src/index.js",
            "import * as C from './constant.js';\n\
                 export function days(ms) {\n\
                   return ms / C.MILLISECONDS_A_DAY;\n\
                 }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("src/constant.js"), |cu| {
        cu.identifier() == "MILLISECONDS_A_DAY" && cu.is_field()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/index.js") && hit.snippet.contains("C.MILLISECONDS_A_DAY")
        }),
        "expected namespace import usage to be counted, got {hits:?}"
    );
}

#[test]
fn multi_analyzer_delegates_parent_for_js_export_const_seed() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/constant.js",
            "export const MILLISECONDS_A_DAY = 86400000;\n",
        )
        .file(
            "src/plugin/duration/index.js",
            "import { MILLISECONDS_A_DAY } from '../../constant';\n\
             export function days(ms) {\n\
               return ms / MILLISECONDS_A_DAY;\n\
             }\n",
        )
        .build();
    let analyzer = MultiAnalyzer::new(BTreeMap::from([(
        Language::JavaScript,
        AnalyzerDelegate::JavaScript(JavascriptAnalyzer::from_project(project.project().clone())),
    )]));
    let target = analyzer
        .all_declarations()
        .find(|cu| {
            cu.source() == &project.file("src/constant.js")
                && cu.identifier() == "MILLISECONDS_A_DAY"
                && cu.is_field()
        })
        .expect("target definition not found");

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/plugin/duration/index.js")
                && hit.snippet.contains("MILLISECONDS_A_DAY")
        }),
        "expected multi-analyzer destructured import usage to be counted, got {hits:?}"
    );
}

#[test]
fn ts_named_import_alias_resolves_to_exported_symbol() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export function foo() {}\n")
            .file(
                "b.ts",
                "import { foo as bar } from './a';\nexport function run() { bar(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier() == "foo" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
    assert!(hits.iter().all(|hit| hit.file == project.file("b.ts")));
}

#[test]
fn ts_imported_class_static_member_call_counts_as_class_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "core/Ky.ts",
            "export class Ky { static create(input: string): Ky { return new Ky(); } }\n",
        )
        .file("index.ts", "export { Ky } from './core/Ky';\n")
        .file(
            "consumer.ts",
            "import { Ky } from './index';\nexport function run() { return Ky.create('url'); }\n",
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("core/Ky.ts"), |cu| {
        cu.identifier() == "Ky" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.ts")),
        "expected Ky.create call in importing file to count as a Ky usage, got {hits:?}"
    );
    assert!(
        hits.iter().all(|hit| hit.enclosing != target),
        "definition site must stay excluded from Ky usage hits, got {hits:?}"
    );
}

#[test]
fn js_named_export_imported_from_parent_directory_counts_calls_in_test_file() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "Maths/Abs.js",
            "const absVal = (num) => (num < 0 ? -num : num);\nexport { absVal };\n",
        )
        .file(
            "Maths/test/Abs.test.js",
            "import { absVal } from '../Abs';\n\ndescribe('absVal', () => {\n  const absOfNegativeNumber = absVal(-34);\n});\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("Maths/Abs.js"), |cu| {
        cu.identifier() == "absVal" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Maths/test/Abs.test.js")),
        "expected absVal call in importing test file to be counted, got {hits:?}"
    );
}

#[test]
fn ts_namespace_import_resolves_member_reference() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export function foo() {}\n")
            .file(
                "b.ts",
                "import * as NS from './a';\nexport function run() { NS.foo(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier() == "foo" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
}

#[test]
fn ts_qualified_type_references_resolve_exact_owners() {
    let consumer_source = r#"
import * as helper from "./options";

enum EntityType { SECURITY_SERVICE }
enum OtherEntityType { SECURITY_SERVICE }

export function select(value: EntityType.SECURITY_SERVICE): helper.PageOptions {
  return { enabled: true };
}

export function otherType(value: OtherEntityType.SECURITY_SERVICE): void {}
export function runtime(helper: { PageOptions: number }, value: OtherEntityType) {
  return helper.PageOptions + value.SECURITY_SERVICE;
}
"#;
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "options.ts",
            "export interface PageOptions { enabled: boolean }\n",
        )
        .file("consumer.ts", consumer_source)
        .build()
    });
    let consumer = project.file("consumer.ts");

    let enum_member = find_ts_target(&analyzer, &consumer, |cu| {
        cu.identifier() == "SECURITY_SERVICE"
            && cu.is_field()
            && analyzer
                .parent_of(cu)
                .is_some_and(|parent| parent.identifier() == "EntityType")
    });
    let enum_hits = authoritative_ts_hits(&analyzer, &enum_member, consumer.clone());
    let enum_start = consumer_source
        .find("EntityType.SECURITY_SERVICE):")
        .expect("enum-member discriminant")
        + "EntityType.".len();
    assert_eq!(
        BTreeSet::from([(enum_start, enum_start + "SECURITY_SERVICE".len())]),
        enum_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reference)
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect(),
        "the enum owner must distinguish the discriminant from the other type and ordinary member expression: {enum_hits:#?}"
    );

    let page_options = find_ts_target(&analyzer, &project.file("options.ts"), |cu| {
        cu.identifier() == "PageOptions" && cu.is_class()
    });
    let option_hits = authoritative_ts_hits(&analyzer, &page_options, consumer);
    let option_start = consumer_source
        .find("helper.PageOptions {")
        .expect("namespace-qualified imported type")
        + "helper.".len();
    assert_eq!(
        BTreeSet::from([(option_start, option_start + "PageOptions".len())]),
        option_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reference)
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect(),
        "a shadowed ordinary member expression must not match the namespace-qualified imported type: {option_hits:#?}"
    );
}

#[test]
fn ts_ambient_companion_preserves_merged_type_references() {
    let source = r#"
declare namespace interop { interface StructType<T> {} }
interface Packet { value: number }
declare var Packet: interop.StructType<Packet>;
declare var PacketConstructor: { prototype: Packet };

function consume(value: Packet): Packet { return value; }

function valueShadow() {
  const Packet = 1;
  let value: Packet;
  return value;
}

function typeShadow() {
  type Packet = { local: true };
  let value: Packet;
  return value;
}
"#;
    let (project, analyzer) = ts_inline_analyzer(|p| p.file("ambient.d.ts", source).build());
    let file = project.file("ambient.d.ts");
    let target = find_ts_target(&analyzer, &file, |cu| {
        cu.identifier() == "Packet" && cu.is_class()
    });

    let hits = authoritative_ts_hits(&analyzer, &target, file);
    let range_after = |anchor: &str, prefix: &str| {
        let start = source.find(anchor).expect("reference anchor") + prefix.len();
        (start, start + "Packet".len())
    };
    let expected = BTreeSet::from([
        range_after("interop.StructType<Packet>", "interop.StructType<"),
        range_after("prototype: Packet", "prototype: "),
        range_after("consume(value: Packet", "consume(value: "),
        range_after("Packet): Packet", "Packet): "),
        range_after(
            "let value: Packet;\n  return value;\n}\n\nfunction typeShadow",
            "let value: ",
        ),
    ]);
    let actual = hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    assert_eq!(
        expected, actual,
        "the ambient value companion and an ordinary value shadow must preserve type-space Packet, while the nested type alias must suppress it: {hits:#?}"
    );
}

#[test]
fn ts_local_barrel_reexport_is_followed() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("layout.service.ts", "export class LayoutService {}\n")
            .file(
                "index.ts",
                "import { LayoutService } from './layout.service';\nexport { LayoutService };\n",
            )
            .file(
                "consumer.ts",
                "import { LayoutService } from './index';\nexport function run() { new LayoutService(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("layout.service.ts"), |cu| {
        cu.identifier() == "LayoutService" && cu.is_class()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = flatten_hits(result.clone());
    let lsp_hits = flatten_lsp_hits(result);

    assert_eq!(
        1,
        hits.len(),
        "external usages should omit the barrel: {hits:?}"
    );
    assert_eq!(
        1,
        lsp_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reexport)
            .count(),
        "IDE references should retain the barrel re-export: {lsp_hits:?}"
    );
    assert_eq!(
        2,
        lsp_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Import)
            .count(),
        "IDE references should retain both import bindings: {lsp_hits:?}"
    );
}

#[test]
fn ts_chained_local_barrel_reexport_is_followed() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("layout.service.ts", "export class LayoutService {}\n")
            .file(
                "index.ts",
                "import { LayoutService } from './layout.service';\nexport { LayoutService };\n",
            )
            .file(
                "feature/index.ts",
                "export { LayoutService } from '../index';\n",
            )
            .file(
                "consumer.ts",
                "import { LayoutService } from './feature/index';\nexport function run() { new LayoutService(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("layout.service.ts"), |cu| {
        cu.identifier() == "LayoutService" && cu.is_class()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = flatten_hits(result.clone());
    let lsp_hits = flatten_lsp_hits(result);

    assert_eq!(
        1,
        hits.len(),
        "external usages should omit both barrels: {hits:?}"
    );
    assert_eq!(
        2,
        lsp_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reexport)
            .count(),
        "IDE references should retain both barrel re-exports: {lsp_hits:?}"
    );
    assert_eq!(
        2,
        lsp_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Import)
            .count(),
        "IDE references should retain both import bindings: {lsp_hits:?}"
    );
}

#[test]
fn ts_export_specifier_value_references_are_reported_without_aliases() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("source.ts", "export class SuccessCorpus {}\n")
            .file(
                "local-exports.ts",
                r#"
import { SuccessCorpus } from "./source";

export { SuccessCorpus };
export { type SuccessCorpus };
export type { SuccessCorpus as TypeSuccessCorpus };
export { SuccessCorpus as default };
export { SuccessCorpus as RenamedSuccessCorpus };
"#,
            )
            .file(
                "cross-file-export.ts",
                "export type { SuccessCorpus as CrossFileSuccessCorpus } from \"./source\";\n",
            )
            .file(
                "unrelated.ts",
                r#"
class UnrelatedSuccessCorpus {}
export { UnrelatedSuccessCorpus as SuccessCorpus };
"#,
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("source.ts"), |cu| {
        cu.identifier() == "SuccessCorpus" && cu.is_class()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = flatten_hits(result.clone());
    let lsp_hits = flatten_lsp_hits(result);

    assert!(
        hits.is_empty(),
        "binding-only exports should be absent from external usages: {hits:?}"
    );
    let reexport_hits: Vec<_> = lsp_hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reexport)
        .collect();
    assert_eq!(
        6,
        reexport_hits.len(),
        "expected one re-export hit per export value: {lsp_hits:?}"
    );
    assert!(
        reexport_hits
            .iter()
            .filter(|hit| hit.file == project.file("local-exports.ts"))
            .count()
            == 5,
        "local named, type, default, and renamed export values should resolve: {lsp_hits:?}"
    );
    assert!(
        reexport_hits
            .iter()
            .any(|hit| hit.file == project.file("cross-file-export.ts")),
        "cross-file type re-export should resolve to the source declaration: {lsp_hits:?}"
    );
    assert!(
        reexport_hits.iter().all(|hit| {
            let source = hit.file.read_to_string().expect("read hit source");
            source
                .get(hit.start_offset..hit.end_offset)
                .is_some_and(|text| text == "SuccessCorpus")
        }),
        "only export-specifier value names, never aliases, should be reported: {lsp_hits:?}"
    );
    assert!(
        reexport_hits
            .iter()
            .all(|hit| hit.file != project.file("unrelated.ts")),
        "an unrelated export alias must not count as a SuccessCorpus reference: {lsp_hits:?}"
    );
}

#[test]
fn ts_local_shadowing_does_not_count_as_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export function foo() {}\n").file(
            "b.ts",
            "import { foo as bar } from './a';\nexport function run() {\n  function f() {\n    const bar = 1;\n    bar;\n  }\n  bar();\n}\n",
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier() == "foo" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
}

#[test]
fn ts_type_annotation_and_return_type_count_as_usages() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export class Foo {}\n")
            .file(
                "b.ts",
                "import { Foo } from './a';\nconst value: Foo | null = null;\nfunction load(): Foo { return null as Foo; }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(3, hits.len());
}

#[test]
fn ts_generic_type_argument_counts_as_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "a.ts",
            "export class Foo {}\nexport type Box<T> = { value: T };\n",
        )
        .file(
            "b.ts",
            "import { Foo, Box } from './a';\nconst value: Box<Foo> = { value: null as Foo };\n",
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(2, hits.len());
}

#[test]
fn ts_class_inheritance_counts_as_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "a.ts",
            "export class Base {}\nexport class Child extends Base {}\n",
        )
        .file(
            "b.ts",
            "import { Child } from './a';\nexport function run() { new Child(); }\n",
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier() == "Base" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
}

#[test]
fn ts_duplicate_owner_names_do_not_cross_match_members() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export class Foo { bar() {} }\n")
            .file("other.ts", "export class Foo { bar() {} }\n")
            .file(
                "b.ts",
                "import { Foo } from './a';\nexport function run() { const value = new Foo(); value.bar(); }\n",
            )
            .build()
    });

    let target_a = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier().starts_with("bar") && cu.is_function()
    });
    let target_other = find_ts_target(&analyzer, &project.file("other.ts"), |cu| {
        cu.identifier().starts_with("bar") && cu.is_function()
    });

    let strategy = JsTsExportUsageGraphStrategy::new();
    let candidate_files: brokk_bifrost::hash::HashSet<ProjectFile> = [
        project.file("a.ts"),
        project.file("other.ts"),
        project.file("b.ts"),
    ]
    .into_iter()
    .collect();

    let hits_a = flatten_hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target_a),
        &candidate_files,
        1000,
    ));
    let hits_other = flatten_hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target_other),
        &candidate_files,
        1000,
    ));

    assert_eq!(1, hits_a.len());
    assert!(hits_other.is_empty());
}

#[test]
fn ts_member_receiver_inference_handles_direct_and_aliased_receivers() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export class Foo { bar() {} }\n")
            .file(
                "b.ts",
                "import { Foo } from './a';\nexport function run() {\n  new Foo().bar();\n  const x = new Foo();\n  const y = x;\n  y.bar();\n}\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier().starts_with("bar") && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(2, hits.len());
}

#[test]
fn ts_intersection_alias_object_receiver_resolves_exact_property_owner() {
    let consumer_source = r#"
import type { OtherOutput, SerializableHookOutput, UnrelatedAlias } from "./types";

export function targetRead() {
  const sanitized: SerializableHookOutput = { message: "ok", serialized: true };
  return sanitized.message;
}

export function controls() {
  const unrelated: UnrelatedAlias = { message: "other", other: true };
  const untyped = { message: "plain" };
  return unrelated.message + untyped.message;
}

export function shadowed(sanitized: OtherOutput) {
  return sanitized.message;
}
"#;
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "types.ts",
            r#"
export interface HookOutput { message: string }
export interface OtherOutput { message: string }
export type SerializableHookOutput = HookOutput & { serialized: boolean };
export type UnrelatedAlias = OtherOutput & { other: boolean };
"#,
        )
        .file("consumer.ts", consumer_source)
        .build()
    });
    let target = find_ts_target(&analyzer, &project.file("types.ts"), |unit| {
        unit.short_name() == "HookOutput.message" && unit.is_field()
    });
    let consumer = project.file("consumer.ts");
    let expected_read = identifier_occurrence_range(consumer_source, "message", 1);

    let targeted = authoritative_ts_hits(&analyzer, &target, consumer.clone());
    assert!(
        targeted
            .iter()
            .any(|hit| (hit.start_offset, hit.end_offset) == expected_read),
        "the intersection-alias receiver read must resolve to HookOutput.message: {targeted:#?}"
    );

    let workspace = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );
    assert!(
        workspace.iter().any(|hit| {
            hit.file == consumer && (hit.start_offset, hit.end_offset) == expected_read
        }),
        "workspace inverse lookup must retain the exact receiver read: {workspace:#?}"
    );

    for occurrence in [2, 3, 4, 5, 6] {
        let control = identifier_occurrence_range(consumer_source, "message", occurrence);
        assert!(
            workspace.iter().all(|hit| {
                hit.file != consumer || (hit.start_offset, hit.end_offset) != control
            }),
            "unrelated, untyped, and shadowed receivers must not match HookOutput.message: {workspace:#?}"
        );
    }
}

#[test]
fn tsx_class_method_call_inside_jsx_is_found() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "components.tsx",
            r#"
export type User = {
  name: string;
};

export default class Greeter {
  greet(user: User): string {
    return user.name;
  }
}

export function WelcomeCard({ user }: { user: User }) {
  const greeter = new Greeter();
  return <section>{greeter.greet(user)}</section>;
}
"#,
        )
        .file(
            "app.tsx",
            r#"
import Greeter, { User } from "./components";

export function render(user: User) {
  return new Greeter().greet(user);
}
"#,
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("components.tsx"), |cu| {
        cu.short_name() == "Greeter.greet" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(
        2,
        hits.len(),
        "expected both TSX method calls, got {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("components.tsx")),
        "expected same-file JSX call to Greeter.greet, got {hits:?}"
    );
    assert!(
        hits.iter().any(|hit| hit.file == project.file("app.tsx")),
        "expected cross-file call to Greeter.greet, got {hits:?}"
    );
}

#[test]
fn js_imported_factory_receiver_method_call_is_found() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "components.js",
            r#"
export class Greeter {
  greet(user) {
    return user.name;
  }
}

export function createGreeter() {
  return new Greeter();
}
"#,
        )
        .file(
            "app.js",
            r#"
import { createGreeter } from "./components.js";

const greeter = createGreeter();
const message = greeter.greet({ name: "Ada" });
"#,
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("components.js"), |cu| {
        cu.short_name() == "Greeter.greet" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("app.js") && hit.snippet.contains("greeter.greet")),
        "imported factory receiver call should count as Greeter.greet usage: {hits:?}"
    );
}

#[test]
fn js_commonjs_object_literal_method_member_calls_are_found() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "library.js",
            r#"
class Task {
  finish() {
    return helpers.formatTask(this);
  }
}

const helpers = {
  formatTask(task) {
    return task.label;
  },
};

exports.helpers = helpers;
"#,
        )
        .file(
            "consumer.js",
            r#"
const { helpers } = require("./library");

helpers.formatTask({ label: "direct" });
"#,
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("library.js"), |cu| {
        cu.short_name().ends_with(".helpers.formatTask") && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("library.js")
                && hit.snippet.contains("helpers.formatTask(this)")
        }),
        "same-file CommonJS object-literal method call should count: {hits:?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("consumer.js") && hit.snippet.contains("helpers.formatTask")
        }),
        "destructured CommonJS object-literal method call should count: {hits:?}"
    );
}

#[test]
fn js_default_exported_object_literal_member_resolves_default_import_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lang/en.js",
            r#"
const messages = {
  malformedRegistryResponse: "Malformed registry response",
  requestRetry: "Retrying request",
};

export default messages;
"#,
        )
        .file(
            "consumer.js",
            r#"
import en from "./lang/en.js";

export function render() {
  return en.malformedRegistryResponse;
}
"#,
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lang/en.js"), |cu| {
        cu.short_name()
            .ends_with(".messages.malformedRegistryResponse")
            && cu.is_field()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("consumer.js")
                && hit.snippet.contains("en.malformedRegistryResponse")
        }),
        "expected default-imported object member usage, got {hits:?}"
    );
}

#[test]
fn js_anonymous_default_object_binding_has_exact_targeted_and_workspace_usages() {
    let consumer_source = r#"import selected from "./selected.js";
import other from "./other.js";
import { named } from "./named.js";

export function readSelected() {
  return selected;
}

export function readSelectedMember() {
  return selected.value;
}

export function controls() {
  return other.value + named;
}
"#;
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("selected.js", "export default { value: 1 };\n")
            .file("other.js", "export default { value: 2 };\n")
            .file("named.js", "export const named = 3;\n")
            .file("consumer.js", consumer_source)
            .build()
    });
    let target = find_js_target(&analyzer, &project.file("selected.js"), |unit| {
        unit.short_name() == "default"
    });
    let expected = BTreeSet::from([
        identifier_occurrence_range(consumer_source, "selected", 2),
        identifier_occurrence_range(consumer_source, "selected", 3),
    ]);

    let targeted = authoritative_js_hits(&analyzer, &target, project.file("consumer.js"))
        .into_iter()
        .filter(|hit| {
            hit.kind
                .included_in(brokk_bifrost::usages::UsageHitSurface::ExternalUsages)
        })
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert_eq!(expected, targeted, "targeted inverse hits must stay exact");

    let workspace = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    )
    .into_iter()
    .filter(|hit| hit.file == project.file("consumer.js"))
    .map(|hit| (hit.start_offset, hit.end_offset))
    .collect::<BTreeSet<_>>();
    assert_eq!(
        expected, workspace,
        "workspace inverse hits must not widen to another default or named export"
    );
}

#[test]
fn ts_anonymous_default_value_binding_has_exact_targeted_and_workspace_usages() {
    let consumer_source = r#"import selected from "./selected";
import other from "./other";
import { named } from "./named";

export function readSelected() {
  return selected;
}

export function controls() {
  return other + named;
}
"#;
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("selected.ts", "export default (): number => 1;\n")
            .file("other.ts", "export default (): number => 2;\n")
            .file("named.ts", "export const named = 3;\n")
            .file("consumer.ts", consumer_source)
            .build()
    });
    let target = find_ts_target(&analyzer, &project.file("selected.ts"), |unit| {
        unit.short_name() == "default"
    });
    let expected = BTreeSet::from([identifier_occurrence_range(consumer_source, "selected", 2)]);

    let targeted = authoritative_ts_hits(&analyzer, &target, project.file("consumer.ts"))
        .into_iter()
        .filter(|hit| {
            hit.kind
                .included_in(brokk_bifrost::usages::UsageHitSurface::ExternalUsages)
        })
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert_eq!(expected, targeted, "targeted inverse hits must stay exact");

    let workspace = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    )
    .into_iter()
    .filter(|hit| hit.file == project.file("consumer.ts"))
    .map(|hit| (hit.start_offset, hit.end_offset))
    .collect::<BTreeSet<_>>();
    assert_eq!(
        expected, workspace,
        "workspace inverse hits must not widen to another default or named export"
    );
}

#[test]
fn js_commonjs_module_exports_object_literal_member_resolves_required_module_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lang/en.js",
            r#"
module.exports = {
  malformedRegistryResponse: "Malformed registry response",
  requestRetry: "Retrying request",
};
"#,
        )
        .file(
            "consumer.js",
            r#"
const en = require("./lang/en");

function render() {
  return en.malformedRegistryResponse;
}
"#,
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lang/en.js"), |cu| {
        cu.identifier() == "malformedRegistryResponse" && cu.is_field()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("consumer.js")
                && hit.snippet.contains("en.malformedRegistryResponse")
        }),
        "expected CommonJS required object member usage, got {hits:?}"
    );
}

#[test]
fn ts_receiver_shadowing_and_unknown_sources_do_not_count() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export class Foo { bar() {} }\n")
            .file(
                "b.ts",
                "import { Foo } from './a';\nexport function run() {\n  const x = new Foo();\n  {\n    const x = { bar() {} };\n    x.bar();\n  }\n  const y = missing;\n  y.bar();\n}\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier().starts_with("bar") && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(hits.is_empty());
}

#[test]
fn ts_typed_receivers_count_as_member_usages() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export class Foo { bar() {} }\n")
            .file(
                "b.ts",
                "import { Foo } from './a';\ndeclare const seed: Foo;\nconst x: Foo = seed;\nexport function run(value: Foo) { value.bar(); x.bar(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier().starts_with("bar") && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(2, hits.len());
}

#[test]
fn ts_interface_property_usages_include_typed_reads_and_contextual_return_keys() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "api.ts",
            "export interface User {\n  id: string;\n  name: string;\n}\nexport interface Other {\n  name: string;\n}\nexport class ApiClient {\n  makeUser(): User {\n    return { id: '', name: this.baseUrl };\n  }\n}\n",
        )
        .file(
            "app.ts",
            "import { User } from './api';\nfunction show(user: User) {\n  return user.name;\n}\n",
        )
        .build()
    });

    let user_name = find_ts_target(&analyzer, &project.file("api.ts"), |cu| {
        cu.fq_name() == "User.name" && cu.is_field()
    });
    let other_name = find_ts_target(&analyzer, &project.file("api.ts"), |cu| {
        cu.fq_name() == "Other.name" && cu.is_field()
    });

    let candidate_files: brokk_bifrost::hash::HashSet<ProjectFile> =
        [project.file("api.ts"), project.file("app.ts")]
            .into_iter()
            .collect();
    let strategy = JsTsExportUsageGraphStrategy::new();
    let user_hits = flatten_hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&user_name),
        &candidate_files,
        1000,
    ));
    let other_hits = flatten_hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&other_name),
        &candidate_files,
        1000,
    ));

    assert_eq!(2, user_hits.len(), "User.name hits: {user_hits:?}");
    assert!(
        user_hits
            .iter()
            .any(|hit| hit.file == project.file("app.ts") && hit.snippet.contains("user.name")),
        "expected typed parameter read, got {user_hits:?}"
    );
    assert!(
        user_hits
            .iter()
            .any(|hit| hit.file == project.file("api.ts") && hit.snippet.contains("name:")),
        "expected declared-return literal key, got {user_hits:?}"
    );
    assert!(
        other_hits.is_empty(),
        "unrelated same-name interface property must not match: {other_hits:?}"
    );
}

#[test]
fn ts_interface_property_usages_include_typed_iterable_and_receiver_destructuring_labels() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "api.ts",
            "export interface SyncSourceEntry { source: string; }\nexport interface OtherEntry { source: string; }\n",
        )
        .file(
            "app.ts",
            r#"import { SyncSourceEntry, OtherEntry } from './api';
function collect(entries: Array<SyncSourceEntry>) {
  for (const { source } of entries) {
    consume(source);
  }
}
function collectRenamed(entries: SyncSourceEntry[]) {
  for (const { source: sourceValue } of entries) {
    consume(sourceValue);
  }
}
function collectSet(entries: Set<SyncSourceEntry>) {
  for (const { source: setSource } of entries) {
    consume(setSource);
  }
}
function collectIterable(entries: Iterable<SyncSourceEntry>) {
  for (const { source: iterableSource } of entries) {
    consume(iterableSource);
  }
}
function direct(entry: SyncSourceEntry) {
  const { source: directSource } = entry;
  consume(directSource);
}
function renamedDefault(entry: SyncSourceEntry) {
  const { source: defaultSource = fallback } = entry;
  defaultSource.trim();
}
function shorthandDefault(entry: SyncSourceEntry) {
  const { source = fallback } = entry;
  source.trim();
}
function forIn(entry: SyncSourceEntry) {
  for (const { source } in entry) {
    consume(source);
  }
}
function unrelated(entries: OtherEntry[]) {
  for (const { source } of entries) {
    consume(source);
  }
}
declare const fallback: string;
declare function consume(value: string): void;
"#,
        )
        .build()
    });

    let source = find_ts_target(&analyzer, &project.file("api.ts"), |cu| {
        cu.fq_name() == "SyncSourceEntry.source" && cu.is_field()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&source)),
    );

    let app_hits: Vec<_> = hits
        .iter()
        .filter(|hit| hit.file == project.file("app.ts"))
        .collect();
    assert_eq!(
        9,
        app_hits.len(),
        "SyncSourceEntry.source hits: {app_hits:?}"
    );
    assert!(
        app_hits
            .iter()
            .any(|hit| hit.snippet.contains("{ source }")),
        "expected shorthand destructuring label, got {app_hits:?}"
    );
    assert!(
        app_hits
            .iter()
            .any(|hit| hit.snippet.contains("{ source: sourceValue }")),
        "expected renamed destructuring label, got {app_hits:?}"
    );
    assert!(
        app_hits
            .iter()
            .any(|hit| hit.snippet.contains("{ source: directSource }")),
        "expected typed receiver destructuring label, got {app_hits:?}"
    );
    assert!(
        app_hits
            .iter()
            .any(|hit| hit.snippet.contains("{ source: setSource }")),
        "expected Set element destructuring label, got {app_hits:?}"
    );
    assert!(
        app_hits
            .iter()
            .any(|hit| hit.snippet.contains("{ source: iterableSource }")),
        "expected Iterable element destructuring label, got {app_hits:?}"
    );
    assert_eq!(
        2,
        app_hits
            .iter()
            .filter(|hit| hit.enclosing.short_name() == "renamedDefault")
            .count(),
        "renamed default binding should record its field label and carry the field value: {app_hits:?}"
    );
    assert_eq!(
        2,
        app_hits
            .iter()
            .filter(|hit| hit.enclosing.short_name() == "shorthandDefault")
            .count(),
        "shorthand default binding should record its field label and carry the field value: {app_hits:?}"
    );
}

#[test]
fn js_this_receiver_is_editor_only_member_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "a.js",
            "class Foo {\n  target() {}\n  caller() { this.target(); }\n}\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("a.js"), |cu| {
        cu.short_name() == "Foo.target" && cu.is_function()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    assert!(
        result.all_hits().is_empty(),
        "scan_usages/external surface must not count self-receiver hits: {:?}",
        result.all_hits()
    );
    let editor_hits = result.all_hits_including_imports();
    assert_eq!(1, editor_hits.len(), "editor hits: {editor_hits:?}");
    assert!(
        editor_hits
            .iter()
            .all(|hit| hit.snippet.contains("this.target"))
    );
}

#[test]
fn js_this_property_assignment_is_editor_visible_field_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "components.js",
            r#"
export class Greeter {
  constructor(title) {
    this.title = title;
  }

  greet(user) {
    return `${this.title}, ${user.name}`;
  }
}
"#,
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("components.js"), |cu| {
        cu.short_name() == "Greeter.title" && cu.is_field()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result.all_hits();
    assert_eq!(1, hits.len(), "field hits: {hits:?}");
    assert!(hits.iter().all(|hit| hit.snippet.contains("this.title")));
}

#[test]
fn ts_this_receiver_is_editor_only_member_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "a.ts",
            "class Foo {\n  target() {}\n  caller() { this.target(); }\n}\n",
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.short_name() == "Foo.target" && cu.is_function()
    });

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    assert!(
        result.all_hits().is_empty(),
        "scan_usages/external surface must not count self-receiver hits: {:?}",
        result.all_hits()
    );
    let editor_hits = result.all_hits_including_imports();
    assert_eq!(1, editor_hits.len(), "editor hits: {editor_hits:?}");
    assert!(
        editor_hits
            .iter()
            .all(|hit| hit.snippet.contains("this.target"))
    );
}

#[test]
fn ts_self_receiver_hits_do_not_trigger_external_usage_cap() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "a.ts",
            "class Foo {\n  target() {}\n  caller() { this.target(); this.target(); }\n}\n",
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.short_name() == "Foo.target" && cu.is_function()
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = JsTsExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        0,
    );

    assert!(
        !matches!(result, FuzzyResult::TooManyCallsites { .. }),
        "self-receiver hits are editor-visible but must not count against the external usage cap: {result:?}"
    );
    assert!(result.all_hits().is_empty(), "result: {result:?}");
    assert_eq!(2, result.all_hits_including_imports().len());
}

#[test]
fn ts_seedless_local_external_hits_still_enforce_usage_cap() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "a.ts",
            r#"
class Foo {
  target() {}
}

function caller(foo: Foo) {
  foo.target();
  foo.target();
}
"#,
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.short_name() == "Foo.target" && cu.is_function()
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = JsTsExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );

    match result {
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => {
            assert_eq!(2, total_callsites);
            assert_eq!(1, limit);
        }
        other => panic!("expected seedless local external hits to enforce cap, got {other:?}"),
    }
}

#[test]
fn ts_static_member_on_namespace_import_resolves_member_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("a.ts", "export class Foo { static make() {} }\n")
            .file(
                "b.ts",
                "import * as NS from './a';\nexport function run() { NS.Foo.make(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("a.ts"), |cu| {
        cu.identifier().starts_with("make") && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
}

#[test]
fn ts_static_member_on_class_value_resolves_member_usage() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file(
            "api.ts",
            r#"
export class ApiClient {
  static create(baseUrl: string): ApiClient {
    return new ApiClient(baseUrl);
  }
  constructor(readonly baseUrl: string) {}
}

export function boot() {
  return ApiClient.create("/api");
}
"#,
        )
        .file(
            "app.ts",
            r#"
import { ApiClient } from "./api";

export function bootDirect() {
  return ApiClient.create("/direct");
}
"#,
        )
        .build()
    });

    let target = find_ts_target(&analyzer, &project.file("api.ts"), |cu| {
        cu.short_name() == "ApiClient.create$static" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(2, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("ApiClient.create")),
        "static class-value call should be a usage of the static member: {hits:?}"
    );
}

#[test]
fn js_object_literal_method_member_calls_resolve_to_plain_key() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "library.js",
            r#"
const helpers = {
  formatTask(task) {
    return task.label;
  },
  render(task) {
    return helpers.formatTask(this);
  },
};
export { helpers };
"#,
        )
        .file(
            "consumer.js",
            r#"
import { helpers } from './library.js';

export function run(directTask) {
  return helpers.formatTask(directTask);
}
"#,
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("library.js"), |cu| {
        cu.short_name().ends_with(".helpers.formatTask") && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("library.js")
                && hit.snippet.contains("helpers.formatTask(this)")
        }),
        "same-file object-literal member call should use the plain declaration key: {hits:?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("consumer.js")
                && hit.snippet.contains("helpers.formatTask(directTask)")
        }),
        "imported object-literal member call should use the plain declaration key: {hits:?}"
    );
}

#[test]
fn js_commonjs_exports_property_resolves_destructured_require() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nexports.Foo = Foo;\n")
            .file(
                "consumer.js",
                "const { Foo } = require('./lib');\nfunction run() { return new Foo(); }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("lib.js")
                && hit.kind == brokk_bifrost::usages::UsageHitKind::Reference
                && hit
                    .file
                    .read_to_string()
                    .ok()
                    .and_then(|source| {
                        source
                            .get(hit.start_offset..hit.end_offset)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some("Foo")
        }),
        "a CommonJS export RHS reads the exported value and remains an external usage: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js"))
    );
}

#[test]
fn js_self_file_scan_keeps_selected_local_require_binding_unshadowed() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib/request.js",
            "var accepts = require('accepts');\nvar req = {};\nmodule.exports = req;\nreq.accepts = function(){ return accepts(this); };\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib/request.js"), |cu| {
        cu.identifier() == "accepts" && cu.short_name() == "request.js.accepts"
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("lib/request.js") && hit.snippet.contains("accepts(this)")
        }),
        "selected local require binding should stay visible during self-file scan: {hits:?}"
    );
}

#[test]
fn js_commonjs_exports_property_resolves_member_declaration() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib/request.js",
            "const request = {};\nrequest.accepts = function accepts(type) { return type; };\nexports.accepts = request.accepts;\n",
        )
        .file(
            "consumer.js",
            "const request = require('./lib/request');\nfunction run() { return request.accepts('json'); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib/request.js"), |cu| {
        cu.short_name() == "request.accepts" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js")),
        "expected CommonJS module-object use of exported member declaration"
    );
}

#[test]
fn js_commonjs_exports_named_function_expression_resolves_module_object_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "commonjs-request.js",
            "exports.accepts = function accepts(contentType) { return contentType; };\n",
        )
        .file(
            "consumer.js",
            "const request = require('./commonjs-request');\nfunction run() { return request.accepts('json'); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("commonjs-request.js"), |cu| {
        cu.short_name() == "accepts" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js")),
        "expected direct CommonJS exported named function expression to resolve module-object usage"
    );
}

#[test]
fn js_commonjs_module_exports_local_object_resolves_later_member_declaration() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib/request.js",
            "const req = {};\nmodule.exports = req;\nreq.accepts = function() { return true; };\n",
        )
        .file(
            "consumer.js",
            "const request = require('./lib/request');\nfunction run() { return request.accepts('json'); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib/request.js"), |cu| {
        cu.short_name() == "req.accepts" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js")),
        "expected module.exports local object member declaration to resolve module-object usage"
    );
}

#[test]
fn js_commonjs_reexported_module_object_member_resolves_nested_usage() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib/request.js",
            "const req = {};\nmodule.exports = req;\nreq.accepts = function() { return true; };\n",
        )
        .file(
            "lib/express.js",
            "const req = require('./request');\nexports.request = req;\n",
        )
        .file("index.js", "module.exports = require('./lib/express');\n")
        .file(
            "consumer.js",
            "const express = require('./');\nfunction run() { return express.request.accepts('json'); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib/request.js"), |cu| {
        cu.short_name() == "req.accepts" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js")),
        "expected CommonJS re-exported module-object member to resolve nested usage"
    );
}

#[test]
fn js_commonjs_exports_property_does_not_seed_unrelated_member_by_short_name() {
    let (_project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib/request.js",
            "function accepts(type) { return type; }\nconst request = {};\nrequest.accepts = function acceptsMember(type) { return type; };\nexports.accepts = accepts;\n",
        )
        .file(
            "consumer.js",
            "const request = require('./lib/request');\nfunction run() { return request.accepts('json'); }\n",
        )
        .build()
    });

    assert!(
        analyzer
            .all_declarations()
            .all(|cu| cu.short_name() != "request.accepts"),
        "unexported plain-local member function assignment must not be declared"
    );
}

#[test]
fn js_commonjs_barrel_reexports_required_member_declaration() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file(
            "lib/request.js",
            "const request = {};\nrequest.accepts = function accepts(type) { return type; };\nexports.accepts = request.accepts;\n",
        )
        .file(
            "index.js",
            "const request = require('./lib/request');\nexports.accepts = request.accepts;\n",
        )
        .file(
            "consumer.js",
            "const api = require('./index');\nfunction run() { return api.accepts('json'); }\n",
        )
        .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib/request.js"), |cu| {
        cu.short_name() == "request.accepts" && cu.is_function()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js")),
        "expected CommonJS barrel re-export of member declaration to reach consumer"
    );
}

#[test]
fn js_commonjs_module_exports_object_resolves_required_module_member() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nmodule.exports = { Foo };\n")
            .file(
                "consumer.js",
                "const lib = require('./lib');\nfunction run() { return new lib.Foo(); }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js"))
    );
}

#[test]
fn js_commonjs_module_exports_default_resolves_required_value() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nmodule.exports = Foo;\n")
            .file(
                "consumer.js",
                "const Foo = require('./lib');\nfunction run() { return new Foo(); }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js"))
    );
}

#[test]
fn ts_commonjs_exports_property_resolves_destructured_require() {
    let (project, analyzer) = ts_inline_analyzer(|p| {
        p.file("lib.ts", "class Foo {}\nexports.Foo = Foo;\n")
            .file(
                "consumer.ts",
                "const { Foo } = require('./lib');\nexport function run() { return new Foo(); }\n",
            )
            .build()
    });

    let target = find_ts_target(&analyzer, &project.file("lib.ts"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.ts"))
    );
}

#[test]
fn js_esm_import_resolves_commonjs_named_export() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nmodule.exports = { Foo };\n")
            .file(
                "consumer.js",
                "import { Foo } from './lib';\nfunction run() { return new Foo(); }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js"))
    );
}

#[test]
fn js_commonjs_side_effect_and_dynamic_require_do_not_create_graph_usages() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nexports.Foo = Foo;\n")
            .file(
                "consumer.js",
                "require('./lib');\nconst name = './lib';\nconst dynamic = require(name);\nfunction run() { return dynamic.Foo; }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("commonjs graph success");

    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("consumer.js")),
        "side-effect and dynamic require consumers must not count"
    );
}

#[test]
fn js_commonjs_required_binding_shadowing_does_not_count() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nexports.Foo = Foo;\n")
            .file("other.js", "class Other {}\nexports.Other = Other;\n")
            .file(
                "consumer.js",
                "const { Foo } = require('./lib');\nconst { Other } = require('./other');\nfunction run() { const Foo = Other; return new Foo(); }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("commonjs graph success");

    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("consumer.js")),
        "shadowed required binding must not count as a consumer usage"
    );
}

#[test]
fn js_commonjs_module_object_bare_identifier_does_not_count() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nexports.Foo = Foo;\n")
            .file(
                "consumer.js",
                "const lib = require('./lib');\nfunction run() { return lib; }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("commonjs graph success");

    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("consumer.js")),
        "bare required module object must not count"
    );
}

#[test]
fn js_commonjs_module_object_uses_exported_alias_name() {
    let (project, analyzer) = js_inline_analyzer(|p| {
        p.file("lib.js", "class Foo {}\nmodule.exports = { Bar: Foo };\n")
            .file(
                "consumer.js",
                "const lib = require('./lib');\nfunction run() { return [new lib.Bar(), lib.Foo]; }\n",
            )
            .build()
    });

    let target = find_js_target(&analyzer, &project.file("lib.js"), |cu| {
        cu.identifier() == "Foo" && cu.is_class()
    });

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(2, hits.len());
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("lib.js") && hit.snippet.contains("{ Bar: Foo }")
        }),
        "the local value used on the export RHS should count"
    );
    assert!(
        hits.iter()
            .filter(|hit| hit.file == project.file("consumer.js"))
            .count()
            == 1,
        "only the exported property alias should count in the consumer"
    );
}

// tsconfig/jsconfig `paths` + `baseUrl` alias resolution acceptance tests live in
// `usages_js_ts_path_alias_test.rs`.

#[test]
#[ignore = "Brokk parity marker: external frontier reporting needs a richer result model than bifrost v1"]
fn parity_external_frontier_reporting_is_follow_up_work() {}

#[test]
#[ignore = "Brokk parity marker: cross-query caches and thread-safety hardening are follow-up work"]
fn parity_jsts_cache_and_thread_safety_hardening_is_follow_up_work() {}

// --- Phase 5: analyzer-cached JsTsUsageIndex invalidation guards (issue #191) ---
//
// The JS/TS resolution maps are now cached on the analyzer and reused across queries, so
// correctness hinges on the cache being dropped on `update`/`update_all`. These edit →
// `update` → re-query tests prove a stale cached index never survives an edit.

fn widget_usages_in_consumer(analyzer: &dyn IAnalyzer, consumer: &ProjectFile) -> bool {
    let units: Vec<_> = analyzer.all_declarations().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class() && cu.identifier() == "Widget"
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    JsTsExportUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph success")
        .iter()
        .any(|hit| &hit.file == consumer)
}

#[test]
fn jsts_usage_index_invalidates_when_reexport_removed_on_update() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("core/widget.ts", "export class Widget {}\n")
        .file("index.ts", "export { Widget } from \"./core/widget\";\n")
        .file(
            "consumer.ts",
            "import { Widget } from \"./index\";\n\nexport function build(): Widget {\n    return new Widget();\n}\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.ts");

    assert!(
        widget_usages_in_consumer(&analyzer, &consumer),
        "expected the re-exported Widget usage in consumer.ts initially"
    );

    // Drop the barrel re-export: consumer's `import { Widget } from "./index"` no longer
    // resolves to core/widget.ts's Widget. A stale cached reexport index would still report it.
    let index_file = project.file("index.ts");
    index_file.write("").expect("rewrite index.ts");
    let updated = analyzer.update(&BTreeSet::from([index_file.clone()]));

    assert!(
        !widget_usages_in_consumer(&updated, &consumer),
        "after removing the re-export and updating, the stale Widget usage must be gone"
    );
}

#[test]
fn jsts_usage_index_invalidates_when_importer_stops_using_symbol_on_update() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("core/widget.ts", "export class Widget {}\n")
        .file("index.ts", "export { Widget } from \"./core/widget\";\n")
        .file(
            "consumer.ts",
            "import { Widget } from \"./index\";\n\nexport function build(): Widget {\n    return new Widget();\n}\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.ts");

    assert!(
        widget_usages_in_consumer(&analyzer, &consumer),
        "expected the Widget usage in consumer.ts initially"
    );

    // Rewrite the importer so it no longer imports or uses Widget. A stale importer
    // reverse-index would still point at consumer.ts.
    consumer
        .write("export function build(): number {\n    return 1;\n}\n")
        .expect("rewrite consumer.ts");
    let updated = analyzer.update(&BTreeSet::from([consumer.clone()]));

    assert!(
        !widget_usages_in_consumer(&updated, &consumer),
        "after the importer stops using Widget and updating, the stale usage must be gone"
    );
}

#[test]
fn jsts_usage_index_invalidates_when_reexport_removed_on_update_javascript() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("core/widget.js", "export class Widget {}\n")
        .file("index.js", "export { Widget } from \"./core/widget\";\n")
        .file(
            "consumer.js",
            "import { Widget } from \"./index\";\n\nexport function build() {\n    return new Widget();\n}\n",
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let consumer = project.file("consumer.js");

    assert!(
        widget_usages_in_consumer(&analyzer, &consumer),
        "expected the re-exported Widget usage in consumer.js initially"
    );

    let index_file = project.file("index.js");
    index_file.write("").expect("rewrite index.js");
    let updated = analyzer.update(&BTreeSet::from([index_file.clone()]));

    assert!(
        !widget_usages_in_consumer(&updated, &consumer),
        "after removing the re-export and updating, the stale Widget usage must be gone (JS)"
    );
}
