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
    ExplicitCandidateProvider, FuzzyResult, KotlinUsageGraphStrategy, UsageAnalyzer, UsageFinder,
    UsageHit, UsageHitKind,
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

// ---------------------------------------------------------------------------
// Type-position shapes. Each of these has a Java or Scala counterpart in the
// sibling suites; the shapes differ, the guarantee does not.
// ---------------------------------------------------------------------------

#[test]
fn kotlin_type_usage_reports_generic_arguments_annotations_and_type_checks() {
    // Java counterpart: java_graph_strategy_counts_generic_type_arguments_as_type_usages
    // and java_graph_strategy_counts_annotation_type_references_without_same_name_confusion.
    // All three shapes are ordinary `user_type` nodes in Kotlin, so one fixture
    // proves the walk reaches them wherever they nest.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun generic(items: List<Base>): Map<String, Base>? = null

fun narrow(value: Any): Boolean = value is Base

fun cast(value: Any): Base = value as Base
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    assert_hit_line(&hits, 5); // List<Base> and Map<String, Base>
    assert_hit_line(&hits, 7); // value is Base
    assert_hit_line(&hits, 9); // value as Base
}

#[test]
fn kotlin_type_usage_reports_an_annotation_use() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Marker.kt",
            "package lib

annotation class Marker
",
        ),
        (
            "src/app/Tagged.kt",
            "package app

import lib.Marker

@Marker
class Tagged
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Marker");
    let hits = hits(&usages(&analyzer, &target));

    assert_hit_line(&hits, 5); // @Marker
}

#[test]
fn kotlin_type_usage_reports_an_enum_type_and_its_entry_qualifier() {
    // Java counterpart: java_graph_strategy_counts_enum_type_references.
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Color.kt",
            "package lib

enum class Color {

    RED,

    GREEN
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Color

fun pick(): Color = Color.RED
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Color");
    let hits = hits(&usages(&analyzer, &target));

    // Both the return type and the `Color` qualifier of `Color.RED` name the enum.
    assert_hit_line(&hits, 5);
}

#[test]
fn kotlin_type_usage_reports_a_data_class_and_an_interface_supertype() {
    // Java counterpart: java_graph_strategy_counts_record_type_references and
    // java_graph_strategy_handles_interface_references_and_receivers.
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Contract.kt",
            "package lib

interface Contract

data class Payload(val value: Int)
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Contract
import lib.Payload

class Impl : Contract

fun send(payload: Payload): Payload = payload
",
        ),
    ]);

    let contract = definition(&analyzer, "lib.Contract");
    let contract_hits = hits(&usages(&analyzer, &contract));
    assert_hit_line(&contract_hits, 6); // class Impl : Contract

    let payload = definition(&analyzer, "lib.Payload");
    let payload_hits = hits(&usages(&analyzer, &payload));
    assert_hit_line(&payload_hits, 8); // fun send(payload: Payload): Payload
}

#[test]
fn kotlin_type_usage_reports_a_typealias_target_and_the_alias_itself() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/Aliases.kt",
            "package app

import lib.Base

typealias Parent = Base

fun hold(value: Parent): Parent = value
",
        ),
    ]);

    // The right-hand side of a `typealias` is a real reference to the aliased
    // class; the alias's own name is a declaration, not a reference.
    let base_hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));
    assert_hit_line(&base_hits, 5);

    // Uses of the alias are uses of the alias declaration.
    let alias_hits = hits(&usages(&analyzer, &definition(&analyzer, "app.Parent")));
    assert_hit_line(&alias_hits, 7);
    assert_no_hit_line(&alias_hits, 5);
}

// ---------------------------------------------------------------------------
// Name resolution edge cases. Kotlin's ladder differs from Java's and Scala's,
// so these are the cases where copying either would have been wrong.
// ---------------------------------------------------------------------------

#[test]
fn kotlin_type_usage_reports_a_same_package_reference_without_an_import() {
    // Java counterpart: java_graph_strategy_counts_same_package_implicit_type_and_method_references.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/lib/Neighbour.kt",
            "package lib

fun hold(value: Base): Base = value
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));
    assert_hit_line(&hits, 3);
}

#[test]
fn kotlin_type_usage_reports_a_star_imported_reference() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.*

fun hold(value: Base): Base = value
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));
    assert_hit_line(&hits, 5);
}

#[test]
fn kotlin_colliding_star_imports_report_no_usage() {
    // Kotlin rejects a name two star imports bind to different owners. The
    // reference is a compile error, so it is a usage of neither candidate --
    // reporting it for one would be picking a winner the language refuses to.
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

import lib.*
import other.*

fun hold(value: Base): Base = value
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));
    assert_no_hit_line(&hits, 6);
}

#[test]
fn kotlin_explicit_import_of_an_unknown_type_does_not_fall_through_to_the_package() {
    // The subtle tier rule from kotlin/types.rs: an explicit import *claims* the
    // name whether or not its target exists, so it does not fall through to the
    // same-package tier. A file importing a nonexistent `other.Base` therefore
    // does not reference its own package's `Base`. Java has no equivalent rule --
    // this is why the Kotlin ladder is reused rather than reimplemented.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/lib/Consumer.kt",
            "package lib

import other.Base

fun hold(value: Base): Base = value
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));
    assert_no_hit_line(&hits, 5);
}

#[test]
fn kotlin_type_usage_reports_a_nested_type_named_from_inside_its_owner() {
    let (_project, analyzer) = kotlin_workspace(&[(
        "src/lib/Outer.kt",
        "package lib

class Outer {

    class Inner

    fun make(value: Inner): Inner = value
}
",
    )]);

    // Inside `Outer`, the nested `Inner` is nameable unqualified: the enclosing
    // scope is the first tier of the ladder.
    let hits = hits(&usages(
        &analyzer,
        &definition(&analyzer, "lib.Outer.Inner"),
    ));
    assert_hit_line(&hits, 7);
    assert_no_hit_line(&hits, 5); // the declaration itself
}

#[test]
fn kotlin_generic_parameter_shadows_a_class_of_the_same_name() {
    // Kotlin has separate namespaces for types and values, so a shadowing test
    // has to exist for each. This is the type side: inside `class Box<Base>`,
    // every `Base` is the parameter, not the class. The value side is
    // kotlin_type_usage_excludes_a_shadowing_local_binding.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/Box.kt",
            "package app

import lib.Base

class Box<Base> {

    fun get(value: Base): Base = value
}

fun real(value: Base): Base = value
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));

    // Inside the class, `Base` is the type parameter.
    assert_no_hit_line(&hits, 7);
    // Outside it, the same spelling is the imported class again.
    assert_hit_line(&hits, 10);
}

#[test]
fn kotlin_duplicate_source_copies_of_one_fqn_are_both_reported() {
    // Java counterpart: java_graph_strategy_uses_java_fqn_identity_across_duplicate_source_copies.
    // Two source files declaring `lib.Base` -- a vendored copy, or one package
    // built by two modules -- are one classpath entry and therefore one
    // usage-graph node. A reference to `Base` is a reference to both, so querying
    // either copy must report it. Failing closed on the ambiguity would report
    // zero usages for every duplicated type in a monorepo.
    let (_project, analyzer) = kotlin_workspace(&[
        ("copy-one/lib/Base.kt", BASE_KT),
        ("copy-two/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun hold(value: Base): Base = value
",
        ),
    ]);

    let copies: Vec<CodeUnit> = analyzer
        .get_definitions("lib.Base")
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect();
    assert_eq!(2, copies.len(), "expected two source copies of lib.Base");

    for copy in copies {
        let hits = hits(&usages(&analyzer, &copy));
        assert_hit_line(&hits, 5);
    }
}

#[test]
fn kotlin_script_files_resolve_type_references_like_source_files() {
    // `.kts` goes through the same path as `.kt` with no script special casing,
    // which is the boundary #1236 and #1238 both settled on. A declaration in a
    // script is indexed, so a reference to one is a usage.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/setup.main.kts",
            "package app

import lib.Base

fun hold(value: Base): Base = value
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));
    assert_hit_line(&hits, 5);
}

// ---------------------------------------------------------------------------
// Result-surface and budget contracts. These are language-agnostic guarantees
// the sibling suites also assert; Kotlin must not be the one language that
// reports them differently.
// ---------------------------------------------------------------------------

#[test]
fn kotlin_import_hits_are_editor_visible_but_external_usage_free() {
    // Java counterpart: java_import_hits_are_editor_visible_but_external_usage_free.
    // An import is a reference a rename must rewrite, but it is not a *use* of
    // the class, so the two surfaces must disagree about it on purpose.
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

    let result = usages(&analyzer, &definition(&analyzer, "lib.Base"));
    let external: Vec<UsageHit> = result.all_hits().into_iter().collect();
    let editor: Vec<UsageHit> = result.all_hits_including_imports().into_iter().collect();

    assert!(
        external
            .iter()
            .all(|hit| !hit.snippet.contains("import lib")),
        "the external usage surface must exclude import hits: {external:#?}"
    );
    assert!(
        editor.iter().any(|hit| hit.snippet.contains("import lib")),
        "the editor surface must include the import hit: {editor:#?}"
    );
}

#[test]
fn kotlin_usage_query_respects_the_candidate_file_set() {
    // Java counterpart: java_graph_strategy_respects_candidate_files. A caller
    // that narrows the scan to a file with no references must get no references,
    // not a whole-workspace answer.
    let (project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun hold(value: Base): Base = value
",
        ),
        (
            "src/app/Unrelated.kt",
            "package app

class Unrelated
",
        ),
    ]);

    let candidates = [project.file("src/app/Unrelated.kt")].into_iter().collect();
    let target = definition(&analyzer, "lib.Base");
    let result = KotlinUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits: Vec<UsageHit> = result.all_hits_including_imports().into_iter().collect();

    assert!(
        hits.is_empty(),
        "a scan restricted to an unrelated file must report nothing: {hits:#?}"
    );
}

#[test]
fn kotlin_usage_query_reports_too_many_callsites_past_the_limit() {
    // Java counterpart: java_graph_strategy_reports_too_many_callsites_for_high_fanout_symbol,
    // Scala counterpart: scala_graph_enforces_max_usages_limit. Truncation must be
    // reported as truncation, never as a complete answer.
    let mut files: Vec<(String, String)> =
        vec![("src/lib/Base.kt".to_string(), BASE_KT.to_string())];
    for index in 0..6 {
        files.push((
            format!("src/app/User{index}.kt"),
            format!(
                "package app

import lib.Base

fun hold{index}(value: Base): Base = value
"
            ),
        ));
    }
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect();
    let (_project, analyzer) = kotlin_workspace(&borrowed);

    let target = definition(&analyzer, "lib.Base");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = KotlinUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        3,
    );

    let FuzzyResult::TooManyCallsites { limit, .. } = result else {
        panic!("expected a truncated result past the usage limit, got {result:?}");
    };
    assert_eq!(3, limit);
}

#[test]
fn kotlin_usage_scan_is_stack_safe_for_deeply_nested_scopes() {
    // Scala counterpart: scala_usage_scan_is_stack_safe_for_deep_lexical_scopes.
    // The walk is iterative, so depth costs heap rather than stack; a recursive
    // walk overflows here instead of answering.
    const DEPTH: usize = 400;
    let mut body = String::new();
    for _ in 0..DEPTH {
        body.push_str("    run {\n");
    }
    body.push_str("        hold(null)\n");
    for _ in 0..DEPTH {
        body.push_str("    }\n");
    }
    let source = format!(
        "package app

import lib.Base

fun hold(value: Base?): Base? = value

fun deep() {{
{body}}}
"
    );

    let (_project, analyzer) =
        kotlin_workspace(&[("src/lib/Base.kt", BASE_KT), ("src/app/Deep.kt", &source)]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    // The point is that the scan returns at all; the `hold` signature above is a
    // real reference, so a successful scan also finds something.
    assert_hit_line(&hits, 5);
}
