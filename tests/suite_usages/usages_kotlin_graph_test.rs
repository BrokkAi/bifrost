//! Kotlin usage-query behaviour (issue #1239).
//!
//! Each test builds a small Kotlin workspace, asks `UsageFinder` who uses a
//! declaration, and asserts on the tokens it reports. Assertions are on observable
//! results — which line a hit landed on, what kind it is, which lines are *not*
//! reported — rather than on internal structure.
//!
//! Kotlin fixtures here are written multi-line with blank lines between
//! declarations, because the vendored grammar emits `MISSING _automatic_semicolon`
//! error nodes for single-line bodies such as `class D { fun f() {} }`, and can
//! degrade `object O { val p = 1 }` into expression recovery. Real Kotlin is
//! written this way, so the fixtures are too.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, KotlinUsageGraphStrategy, UsageFinder, UsageHit,
    UsageHitKind,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, KotlinAnalyzer, Language};
use std::sync::Arc;

fn kotlin_workspace(
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, KotlinAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Kotlin);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &KotlinAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing Kotlin definition for {fq_name}"))
}

/// Every Kotlin file in the workspace is a candidate, so a test asserts on what
/// the *strategy* proves rather than on what candidate discovery happened to
/// admit.
fn usages(analyzer: &KotlinAnalyzer, target: &CodeUnit) -> FuzzyResult {
    let files = analyzer.get_analyzed_files().into_iter().collect();
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    UsageFinder::new()
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1000,
            1000,
        )
        .result
}

fn hits(result: &FuzzyResult) -> Vec<UsageHit> {
    result.all_hits_including_imports().into_iter().collect()
}

fn assert_hit_line(hits: &[UsageHit], line: usize) {
    assert!(
        hits.iter().any(|hit| hit.line == line),
        "expected a hit on line {line}, got {hits:#?}"
    );
}

fn assert_no_hit_line(hits: &[UsageHit], line: usize) {
    assert!(
        hits.iter().all(|hit| hit.line != line),
        "expected no hit on line {line}, got {hits:#?}"
    );
}

fn assert_hit_text(hits: &[UsageHit], line: usize, text: &str) {
    let hit = hits
        .iter()
        .find(|hit| hit.line == line)
        .unwrap_or_else(|| panic!("expected a hit on line {line}, got {hits:#?}"));
    assert!(
        hit.snippet.contains(text),
        "expected the hit on line {line} to be inside {text:?}, got {hit:#?}"
    );
}

const BASE_KT: &str = "package lib

open class Base {

    fun greet(name: String): String = \"hello $name\"
}

class Other
";

#[test]
fn kotlin_type_usage_reports_type_annotation_and_constructor_call() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun make(): Base {

    val held: Base = Base()

    return held
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let result = usages(&analyzer, &target);
    let hits = hits(&result);

    // The import, the return type, the declared type of the local, and the
    // constructor call's type all name `lib.Base`.
    assert_hit_line(&hits, 3); // import lib.Base
    assert_hit_line(&hits, 5); // fun make(): Base
    assert_hit_line(&hits, 7); // val held: Base = Base()
    assert_hit_text(&hits, 7, "Base");
}

#[test]
fn kotlin_type_usage_reports_supertype_reference() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/Derived.kt",
            "package app

import lib.Base

class Derived : Base() {

    fun run(): String = greet(\"x\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    assert_hit_line(&hits, 5); // class Derived : Base()
}

#[test]
fn kotlin_type_usage_marks_an_import_as_an_import_hit() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun hold(value: Base): Base = value
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));
    let import = hits
        .iter()
        .find(|hit| hit.line == 3)
        .expect("expected a hit on the import line");

    assert_eq!(
        import.kind,
        UsageHitKind::Import,
        "an import must be reported as an import, not as a call site: {import:#?}"
    );
}

#[test]
fn kotlin_type_usage_reports_an_aliased_import_at_the_alias_token() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base as Parent

fun hold(value: Parent): Parent = value
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    // The alias token is what a reader would rename, so the import hit lands
    // there rather than on the `Base` segment of the path.
    let import = hits
        .iter()
        .find(|hit| hit.line == 3)
        .expect("expected a hit on the aliased import");
    assert!(
        import.snippet.contains("as Parent"),
        "expected the aliased import to be reported: {import:#?}"
    );
    // The alias is a real binding, so uses of the alias are uses of the class.
    assert_hit_line(&hits, 5);
}

#[test]
fn kotlin_type_usage_reports_each_nested_segment_at_its_own_token() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Outer.kt",
            "package lib

class Outer {

    class Inner
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Outer

fun inner(): Outer.Inner? = null

fun outer(): Outer? = null
",
        ),
    ]);

    let inner = definition(&analyzer, "lib.Outer.Inner");
    let inner_hits = hits(&usages(&analyzer, &inner));
    // `Outer.Inner` is one `user_type` with two segments; only the `Inner`
    // segment names `lib.Outer.Inner`.
    assert_hit_line(&inner_hits, 5);
    assert_no_hit_line(&inner_hits, 7);

    let outer = definition(&analyzer, "lib.Outer");
    let outer_hits = hits(&usages(&analyzer, &outer));
    assert_hit_line(&outer_hits, 3); // the import
    assert_hit_line(&outer_hits, 7); // fun outer(): Outer?
}

#[test]
fn kotlin_type_usage_reports_a_static_qualifier() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Registry.kt",
            "package lib

object Registry {

    fun lookup(): String = \"x\"
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Registry

fun read(): String = Registry.lookup()
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Registry");
    let hits = hits(&usages(&analyzer, &target));

    // `Registry` in `Registry.lookup()` is a reference to the object, even
    // though it is spelled as a bare identifier rather than in a type position.
    assert_hit_line(&hits, 5);
}

#[test]
fn kotlin_type_usage_excludes_the_declaration_site() {
    let (_project, analyzer) = kotlin_workspace(&[("src/lib/Base.kt", BASE_KT)]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    // `open class Base` declares the name; it does not use it.
    assert_no_hit_line(&hits, 3);
}

#[test]
fn kotlin_type_usage_excludes_a_same_named_type_in_another_package() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/other/Base.kt",
            "package other

class Base
",
        ),
        (
            "src/app/App.kt",
            "package app

import other.Base

fun hold(value: Base): Base = value
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    // `App.kt` imports `other.Base`. The spelling matches, the identity does
    // not, so nothing in that file is a usage of `lib.Base`.
    assert!(
        hits.is_empty(),
        "a same-named type in another package must not be reported: {hits:#?}"
    );
}

#[test]
fn kotlin_type_usage_excludes_a_shadowing_local_binding() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Registry.kt",
            "package lib

object Registry {

    fun lookup(): String = \"x\"
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Registry

fun shadowed(): Int {

    val Registry = \"text\"

    return Registry.length
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Registry");
    let hits = hits(&usages(&analyzer, &target));

    // `Registry.length` reads a property of a local string, not of the object.
    assert_no_hit_line(&hits, 9);
}

#[test]
fn kotlin_callable_target_abstains_with_a_specific_diagnostic() {
    // Milestone 2 of issue #1239 resolves callable references. Until then the
    // query must say so rather than report "no usages", which a caller would
    // read as proof the function is unused. Delete this test when milestone 2
    // lands and replace it with the real call-site behaviour.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun run(): String {

    val base = Base()

    return base.greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base.greet");
    let result = usages(&analyzer, &target);

    let FuzzyResult::Failure { reason_kind, .. } = result else {
        panic!("expected an explicit abstention for a Kotlin callable, got {result:?}");
    };
    assert_eq!(reason_kind, "unsupported_target_shape");
}

#[test]
fn kotlin_target_is_routed_to_the_kotlin_strategy() {
    let (_project, analyzer) = kotlin_workspace(&[("src/lib/Base.kt", BASE_KT)]);
    let target = definition(&analyzer, "lib.Base");

    assert!(
        KotlinUsageGraphStrategy::can_handle(&target),
        "a .kt declaration must be handled by the Kotlin strategy"
    );
}
