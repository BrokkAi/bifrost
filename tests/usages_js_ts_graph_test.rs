mod common;

use brokk_bifrost::usages::{
    FuzzyResult, JsTsExportUsageGraphStrategy, UsageAnalyzer, UsageFinder,
};
use brokk_bifrost::{
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
    let candidate_files: brokk_bifrost::hash::HashSet<ProjectFile> =
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
    let candidate_files: brokk_bifrost::hash::HashSet<ProjectFile> =
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
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
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
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
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
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
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
        .cloned()
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
        .cloned()
        .expect("target definition not found")
}

fn flatten_hits(result: FuzzyResult) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    }
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

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
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

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert_eq!(1, hits.len());
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
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.js"))
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
fn js_commonjs_exports_property_does_not_seed_unrelated_member_by_short_name() {
    let (project, analyzer) = js_inline_analyzer(|p| {
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

    let target = find_js_target(&analyzer, &project.file("lib/request.js"), |cu| {
        cu.short_name() == "request.accepts" && cu.is_function()
    });
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = JsTsExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );

    assert!(
        matches!(result, FuzzyResult::Failure { .. }),
        "member-qualified target must not seed from an unrelated local export with the same property name"
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

    assert!(hits.is_empty());
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
        hits.is_empty(),
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

    assert_eq!(1, hits.len());
    assert!(
        hits.iter().all(|hit| hit.snippet.contains("lib.Bar")),
        "only the exported property alias should count"
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
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
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
