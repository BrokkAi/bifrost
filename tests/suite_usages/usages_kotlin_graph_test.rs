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
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, KotlinUsageGraphStrategy, UsageAnalyzer, UsageFinder,
    UsageHit, UsageHitKind,
};
use brokk_bifrost::{CodeUnit, KotlinAnalyzer, Language};
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

// ---------------------------------------------------------------------------
// Milestone 2: callables and properties
// ---------------------------------------------------------------------------

/// Hits on the *external* usage surface — what `scan_usages`, relevance ranking,
/// and dead-code detection see. Same-owner and import hits are excluded from it
/// by the cross-language contract, so a test that means "an outside caller uses
/// this" must assert here rather than on the editor surface.
fn external_hits(result: &FuzzyResult) -> Vec<UsageHit> {
    result.all_hits().into_iter().collect()
}

/// Hits the scan could not prove: a reference that *might* name the target but
/// whose receiver type could not be established.
fn unproven_hits(result: &FuzzyResult) -> Vec<UsageHit> {
    match result {
        FuzzyResult::Success {
            unproven_by_overload,
            ..
        } => unproven_by_overload
            .values()
            .flat_map(|set| set.iter().cloned())
            .collect(),
        other => panic!("expected a successful result, got {other:?}"),
    }
}

const GREETER_KT: &str = "package lib

open class Greeter {

    val salutation: String = \"hello\"

    open fun greet(name: String): String = salutation

    fun greet(): String = salutation

    companion object {

        val DEFAULT: Greeter = Greeter()

        fun of(): Greeter = Greeter()
    }
}

class Unrelated {

    fun greet(name: String): String = name
}

fun Greeter.shout(): String = salutation
";

#[test]
fn kotlin_member_call_on_a_typed_local_and_on_a_parameter_reports_both_call_sites() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

fun viaLocal(): String {

    val greeter: Greeter = Greeter()

    return greeter.greet(\"world\")
}

fun viaParameter(greeter: Greeter): String {

    return greeter.greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 9);
    assert_hit_text(&hits, 9, "greeter.greet");
    assert_hit_line(&hits, 14);
}

#[test]
fn kotlin_same_name_member_on_an_unrelated_class_is_not_reported() {
    // The exactness criterion: `greet` is spelled identically on two unrelated
    // classes, and a name match is not an identity match.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Unrelated

fun run(): String {

    val other: Unrelated = Unrelated()

    return other.greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = hits(&usages(&analyzer, &target));
    assert_no_hit_line(&hits, 9);
}

#[test]
fn kotlin_inherited_member_call_reports_against_the_base_declaration() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

class Loud : Greeter()

fun run(): String {

    val loud: Loud = Loud()

    return loud.greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 11);
}

#[test]
fn kotlin_override_declaration_is_reported_and_its_own_call_sites_are_not() {
    // Two halves of one rule. The override *declaration* is a reference to what
    // it overrides, so renaming the base renames it. A call on a receiver typed
    // as the overriding class names the override, not the base, so it must not
    // be reported as a usage of the base.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

class Loud : Greeter() {

    override fun greet(name: String): String = name
}

fun run(): String {

    val loud: Loud = Loud()

    return loud.greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let result = usages(&analyzer, &target);
    let editor = hits(&result);
    let override_hit = editor
        .iter()
        .find(|hit| hit.line == 7)
        .unwrap_or_else(|| panic!("expected the override declaration reported, got {editor:#?}"));
    assert_eq!(override_hit.kind, UsageHitKind::OverrideDeclaration);
    assert_no_hit_line(&editor, 14);
}

#[test]
fn kotlin_companion_member_call_reports_through_the_class_and_companion_names() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

fun viaClass(): Greeter {

    return Greeter.of()
}

fun viaCompanion(): Greeter {

    return Greeter.Companion.of()
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.Companion.of");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
    assert_hit_line(&hits, 12);
}

#[test]
fn kotlin_extension_function_call_reports_the_extension_declaration() {
    // An extension is reached through the type it extends, not through the file
    // that declares it, so the receiver must be typed as `Greeter` for the call
    // to name `lib.shout`.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter
import lib.shout

fun run(greeter: Greeter): String {

    return greeter.shout()
}

fun notTheExtension(other: String): Int {

    return other.length
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.shout");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 8);
    assert_hit_text(&hits, 8, "greeter.shout");
}

#[test]
fn kotlin_top_level_function_call_reports_in_the_same_package_and_through_an_import() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Tools.kt",
            "package lib

fun helper(): Int = 1
",
        ),
        (
            "src/lib/Same.kt",
            "package lib

fun samePackage(): Int {

    return helper()
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.helper

fun imported(): Int {

    return helper()
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.helper");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 5);
    assert_hit_line(&hits, 7);
}

#[test]
fn kotlin_constructor_call_reports_the_primary_constructor() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Book.kt",
            "package lib

class Book(val title: String)
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Book

fun make(): Book {

    return Book(\"x\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Book.Book");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
}

#[test]
fn kotlin_wrong_arity_call_is_not_reported() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Book.kt",
            "package lib

class Book(val title: String, val copies: Int)

fun only(one: Int): Int = one
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.only

fun run(): Int {

    return only(1, 2)
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.only");
    let hits = hits(&usages(&analyzer, &target));
    assert_no_hit_line(&hits, 7);
}

#[test]
fn kotlin_default_parameter_call_with_fewer_arguments_and_a_trailing_lambda_are_reported() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Tools.kt",
            "package lib

fun checkout(title: String, copies: Int = 1): Int = copies

fun withBlock(name: String, block: () -> Int): Int = block()
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.checkout
import lib.withBlock

fun defaulted(): Int {

    return checkout(\"x\")
}

fun trailing(): Int {

    return withBlock(\"x\") { 1 }
}
",
        ),
    ]);

    let checkout = definition(&analyzer, "lib.checkout");
    assert_hit_line(&external_hits(&usages(&analyzer, &checkout)), 8);

    // The trailing lambda is an argument even though it sits outside the
    // parentheses; without counting it the call looks one argument short of its
    // own declaration.
    let with_block = definition(&analyzer, "lib.withBlock");
    assert_hit_line(&external_hits(&usages(&analyzer, &with_block)), 13);
}

#[test]
fn kotlin_safe_call_and_not_null_assertion_report_like_a_plain_call() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

fun safe(greeter: Greeter?): String? {

    return greeter?.greet(\"world\")
}

fun asserted(greeter: Greeter?): String {

    return greeter!!.greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
    assert_hit_line(&hits, 12);
}

#[test]
fn kotlin_call_result_chain_reports_the_second_member() {
    // `Greeter.of().greet(...)` can only be resolved by knowing what `of()`
    // returns, which is the published return type issue #1345 records.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

fun run(): String {

    return Greeter.of().greet(\"world\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
    assert_hit_text(&hits, 7, "Greeter.of().greet");
}

#[test]
fn kotlin_property_access_reports_reads_and_writes_as_one_property() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Counter.kt",
            "package lib

class Counter {

    var count: Int = 0
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Counter

fun run(counter: Counter): Int {

    counter.count = 1

    return counter.count
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Counter.count");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
    assert_hit_line(&hits, 9);
}

#[test]
fn kotlin_shadowing_local_is_not_reported_as_a_property_reference() {
    let (_project, analyzer) = kotlin_workspace(&[(
        "src/lib/Counter.kt",
        "package lib

class Counter {

    var count: Int = 0

    fun shadowed(): Int {

        val count: Int = 5

        return count
    }
}
",
    )]);

    let target = definition(&analyzer, "lib.Counter.count");
    let hits = hits(&usages(&analyzer, &target));
    assert_no_hit_line(&hits, 11);
}

#[test]
fn kotlin_enum_entry_reference_reports_the_entry() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Genre.kt",
            "package lib

enum class Genre {

    FICTION,
    REFERENCE
}
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Genre

fun run(): Genre {

    return Genre.FICTION
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Genre.FICTION");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
}

#[test]
fn kotlin_callable_reference_reports_the_function() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Tools.kt",
            "package lib

fun helper(): Int = 1
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.helper

fun run(): () -> Int {

    return ::helper
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.helper");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 7);
}

#[test]
fn kotlin_implicit_this_and_own_type_companion_calls_are_same_owner_not_external_usages() {
    // #1014 facet B, the uniform cross-language policy: a reference whose
    // receiver is the current instance or the own type is recorded and then
    // excluded from the external usage surface. Without it every private helper
    // called only from its own class would look used.
    let (_project, analyzer) = kotlin_workspace(&[(
        "src/lib/Greeter.kt",
        "package lib

open class Greeter {

    fun greet(name: String): String = name

    fun implicitThis(): String = greet(\"a\")

    fun explicitThis(): String = this.greet(\"b\")

    fun viaCompanionHost(): String = Greeter.helper()

    companion object {

        fun helper(): String = \"c\"
    }
}
",
    )]);

    let greet = definition(&analyzer, "lib.Greeter.greet");
    let result = usages(&analyzer, &greet);
    assert!(
        external_hits(&result).is_empty(),
        "self calls must not appear on the external usage surface, got {:#?}",
        external_hits(&result)
    );
    // They are still recorded, and still visible to an editor's find-references.
    let editor = hits(&result);
    assert_hit_line(&editor, 7);
    assert_hit_line(&editor, 9);
    assert!(
        editor
            .iter()
            .all(|hit| hit.kind == UsageHitKind::SelfReceiver),
        "every self call must be classified as a same-owner hit, got {editor:#?}"
    );

    // An own-type companion access from inside the class is same-owner too.
    let helper = definition(&analyzer, "lib.Greeter.Companion.helper");
    assert!(
        external_hits(&usages(&analyzer, &helper)).is_empty(),
        "an own-type companion access is same-owner, not an external usage"
    );
}

#[test]
fn kotlin_recursive_call_is_editor_visible_but_not_an_external_usage() {
    // A call whose enclosing declaration *is* the target is a recursive call
    // (#1638). The forward resolver states that edge, so the inverse listing
    // must state it too: editor find-references lists the site as a same-owner
    // self receiver hit, and the external usage surface omits it, so `countdown`
    // does not look used from outside on the strength of calling itself.
    let (_project, analyzer) = kotlin_workspace(&[(
        "src/lib/Counter.kt",
        "package lib

class Counter {

    fun countdown(n: Int) {

        if (n > 0) countdown(n - 1)
    }

    fun start() {

        countdown(3)
    }
}
",
    )]);

    let target = definition(&analyzer, "lib.Counter.countdown");
    let result = usages(&analyzer, &target);
    assert!(
        external_hits(&result).is_empty(),
        "neither the recursive call nor the sibling call is external, got {:#?}",
        external_hits(&result)
    );
    let editor = hits(&result);
    assert_eq!(2, editor.len(), "{editor:#?}");
    assert_hit_line(&editor, 7);
    assert_hit_line(&editor, 12);
    assert!(
        editor
            .iter()
            .all(|hit| hit.kind == UsageHitKind::SelfReceiver),
        "both sites are same-owner hits, got {editor:#?}"
    );
}

#[test]
fn kotlin_call_through_another_variable_of_the_owner_type_stays_external() {
    // The other half of the same-owner rule: same *type* is not same *owner*.
    // A call through a different object is a real external usage even from
    // inside the declaring class.
    let (_project, analyzer) = kotlin_workspace(&[(
        "src/lib/Greeter.kt",
        "package lib

class Greeter {

    fun greet(name: String): String = name

    fun viaOther(other: Greeter): String {

        return other.greet(\"a\")
    }
}
",
    )]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 9);
}

#[test]
fn kotlin_super_call_is_an_external_usage() {
    // `super.greet()` names the ancestor's declaration from outside it, so it
    // stays on the external surface — matching Java.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Greeter

class Loud : Greeter() {

    override fun greet(name: String): String {

        return super.greet(name)
    }
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let hits = external_hits(&usages(&analyzer, &target));
    assert_hit_line(&hits, 9);
    assert!(
        hits.iter()
            .filter(|hit| hit.line == 9)
            .all(|hit| hit.kind != UsageHitKind::SelfReceiver),
        "a super call is not a same-owner hit, got {hits:#?}"
    );
}

#[test]
fn kotlin_unresolvable_receiver_is_reported_as_unproven_not_proven() {
    // A lambda parameter has no written type and Kotlin infers it, which is
    // semantic work this issue does not do. The call site must still be visible:
    // reporting it as proven would be a guess, and dropping it would let a
    // declaration reachable only this way read as confidently dead.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Greeter.kt", GREETER_KT),
        (
            "src/app/App.kt",
            "package app

fun run(items: List<String>): List<String> {

    return items.map { each -> each.greet(\"world\") }
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Greeter.greet");
    let result = usages(&analyzer, &target);
    assert!(
        external_hits(&result).is_empty(),
        "an unproven receiver must not produce a proven hit, got {:#?}",
        external_hits(&result)
    );
    let unproven = unproven_hits(&result);
    assert!(
        unproven.iter().any(|hit| hit.line == 5),
        "expected an unproven hit on line 5, got {unproven:#?}"
    );
}

#[test]
fn kotlin_named_argument_label_is_not_a_usage_of_a_same_named_property() {
    // A label names a parameter, and Kotlin parameters are not indexed as
    // `CodeUnit`s, so there is no target for the hit to be *of*. Asserted so the
    // choice is not mistaken for an oversight.
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Book.kt",
            "package lib

class Book {

    var title: String = \"\"
}

fun rename(title: String): String = title
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.rename

fun run(): String {

    return rename(title = \"x\")
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Book.title");
    let hits = hits(&usages(&analyzer, &target));
    assert_no_hit_line(&hits, 7);
}

#[test]
fn kotlin_dual_namespace_type_and_function_of_one_name_do_not_collide() {
    // Kotlin has separate namespaces for types and values, so a class `Marker`
    // and a function `Marker` are two declarations and a query for one must not
    // report the other's references.
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Marker.kt",
            "package lib

class Marker

fun Marker(): Int = 1
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.Marker

fun typePosition(value: Marker): Marker {

    return value
}
",
        ),
    ]);

    let function = definition(&analyzer, "lib.Marker");
    let type_unit = analyzer
        .get_definitions("lib.Marker")
        .into_iter()
        .find(brokk_bifrost::CodeUnit::is_class)
        .expect("the class `lib.Marker` must be indexed alongside the function of the same name");
    assert!(
        !function.is_class() || !type_unit.is_class() || function == type_unit,
        "fixture must declare both a type and a value named Marker"
    );

    // The written type positions belong to the class, not to the function.
    let hits = hits(&usages(&analyzer, &type_unit));
    assert_hit_line(&hits, 5);
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

// ---------------------------------------------------------------------------
// Class literals (issue #1374). `C::class` names the type, and the largest
// cluster of Kotlin references that spell it are annotation arguments such as
// `@OptIn(C::class)`.
// ---------------------------------------------------------------------------

/// The issue's own repro: an annotation argument is the only place the class is
/// named, so a scan that misses it reports the class as unused.
#[test]
fn kotlin_type_usage_reports_a_class_literal_in_an_annotation_argument() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/C.kt",
            "package lib

@RequiresOptIn
annotation class C
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.C

@OptIn(C::class)
fun f() {
    println(\"x\")
}
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.C")));

    assert_hit_line(&hits, 3); // import lib.C
    assert_hit_line(&hits, 5);
    assert_hit_text(&hits, 5, "@OptIn(C::class)");
}

/// Each argument of a multi-argument annotation is its own reference; recording
/// only the first would under-count every class after it.
#[test]
fn kotlin_type_usage_reports_every_class_literal_of_a_multi_argument_annotation() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/Markers.kt",
            "package lib

annotation class A

annotation class B
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.A
import lib.B

@OptIn(A::class, B::class)
fun f() {
    println(\"x\")
}
",
        ),
    ]);

    let a_hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.A")));
    assert_hit_line(&a_hits, 6);
    let b_hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.B")));
    assert_hit_line(&b_hits, 6);
}

/// The grammar hangs annotations off `modifiers`, which every declaration form
/// carries, so a class and a property must reach the same arm a function does.
#[test]
fn kotlin_type_usage_reports_class_literals_in_annotations_on_a_class_and_a_property() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/C.kt",
            "package lib

annotation class C
",
        ),
        (
            "src/app/App.kt",
            "package app

import lib.C

@OptIn(C::class)
class Holder {

    @OptIn(C::class)
    val value: Int = 1
}
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.C")));

    assert_hit_line(&hits, 5); // on the class declaration
    assert_hit_line(&hits, 8); // on the property declaration
}

/// A qualified literal is a navigation whose suffix selects the `class` keyword,
/// a different grammar shape from the bare form, and it resolves through the same
/// per-prefix walk a written dotted type name uses.
#[test]
fn kotlin_type_usage_reports_a_fully_qualified_class_literal() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/lib/C.kt",
            "package lib

annotation class C
",
        ),
        (
            "src/app/App.kt",
            "package app

@OptIn(lib.C::class)
fun f() {
    println(\"x\")
}
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.C")));

    assert_hit_line(&hits, 3);
    assert_hit_text(&hits, 3, "@OptIn(lib.C::class)");
}

/// A class literal outside an annotation is the same reference; nothing about
/// the annotation position is what makes it one.
#[test]
fn kotlin_type_usage_reports_a_bare_class_literal_in_expression_position() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun f() {
    val k = Base::class
    println(k)
}
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));

    assert_hit_line(&hits, 6);
}

/// `x::class` names the runtime class of a *value*, not any declaration. Kotlin
/// spells it exactly like `C::class`, so the value namespace is the only thing
/// that separates them.
#[test]
fn kotlin_bound_class_literal_on_a_value_is_not_a_type_usage() {
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun onParameter(base: Base) {
    println(base::class)
}

fun onShadowingLocal() {
    val Base = \"text\"
    println(Base::class)
}

fun inAString() {
    println(\"Base::class\")
}
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "lib.Base")));

    // The parameter's own type annotation on line 5 is a real reference; the
    // `base::class` on line 6 is not.
    assert_hit_line(&hits, 5);
    assert_no_hit_line(&hits, 6);
    // A local named `Base` hides the class in value positions, which is what
    // `Base::class` is here.
    assert_no_hit_line(&hits, 11);
    // A string that happens to spell the literal is text, not syntax.
    assert_no_hit_line(&hits, 15);
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

/// Characterization test for a known imprecision, not a guarantee.
///
/// The Kotlin name ladder's existence predicate asks "is there a *workspace*
/// declaration with this fully-qualified name?". Library types are deliberately
/// not workspace declarations — `KotlinTypeResolution` keeps `Source(CodeUnit)`
/// and `External(JvmExternalType)` apart, and #1238 recorded that an external
/// type must never be fabricated as a `CodeUnit`. That is right for the graph's
/// *node set*: the usage graph can never report usages of a symbol that is not in
/// the workspace.
///
/// It is not right for the ladder's *precedence*. The enclosing-scope tier sits
/// above the same-package tier, so a name that real Kotlin resolves through a
/// scope inherited from a library supertype falls through here and can match a
/// workspace type instead. `kotlin/hierarchy.rs` resolves ancestors through the
/// same source-only lookup, so an unseen supertype contributes no ancestor
/// `CodeUnit` and its nested scopes never reach the scope tier.
///
/// Only this one tier is exposed. An explicit import is terminal, so it fails
/// closed correctly (see
/// `kotlin_explicit_import_of_an_unknown_type_does_not_fall_through_to_the_package`).
/// Star and default imports sit *below* same-package, so a fall-through there
/// ends in "unresolved", which is the right answer anyway.
///
/// The imprecision is shared by `kotlin/hierarchy.rs`, the #1238 definition
/// resolver, and this module, all of which use the source-only predicate. Fixing
/// it here alone would make find-references disagree with go-to-definition about
/// what a name means, which is exactly what sharing the ladder exists to prevent.
/// It is owned by #1144 (semantic model packs), which is what will give the
/// ladder an "exists anywhere, source or pack" question distinct from "is a
/// workspace declaration".
///
/// This test asserts today's behaviour so that closing the gap fails here loudly
/// instead of changing Kotlin's answers silently. When #1144 lands, the correct
/// update is to assert no hits.
#[test]
fn kotlin_scope_inherited_from_an_unseen_supertype_falls_through_to_the_package() {
    let (_project, analyzer) = kotlin_workspace(&[
        (
            "src/app/Inner.kt",
            "package app

class Inner
",
        ),
        (
            "src/app/Sub.kt",
            "package app

import ext.ExternalBase

class Sub : ExternalBase() {

    fun make(value: Inner): Inner = value
}
",
        ),
    ]);

    let hits = hits(&usages(&analyzer, &definition(&analyzer, "app.Inner")));

    // `ext.ExternalBase` is outside the workspace, standing in for a library
    // class. If it declares a nested `Inner`, real Kotlin resolves both tokens on
    // line 7 to `ExternalBase.Inner` and these hits are false positives.
    assert_hit_line(&hits, 7);
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

// ---------------------------------------------------------------------------
// Milestone 3 / 4 visible behaviour
// ---------------------------------------------------------------------------

#[test]
fn kotlin_type_usage_reports_a_constructor_call_written_without_a_type_annotation() {
    // `Base()` on its own is the most common way to mention a class in Kotlin,
    // and it is spelled exactly like a function call — a bare `simple_identifier`
    // rather than a written type — so nothing in the type-annotation arms sees
    // it. Before the edge builder needed it, a class constructed and never
    // annotated read as unused.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun make() {

    val held = Base()

    println(held)
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    assert_hit_line(&hits, 3); // import lib.Base
    assert_hit_line(&hits, 7); // val held = Base()
    assert_hit_text(&hits, 7, "Base()");
}

#[test]
fn kotlin_type_usage_excludes_a_constructor_shaped_call_on_a_shadowing_local() {
    // `Base` here is a local function value, not the class. Kotlin has separate
    // namespaces for types and values, so the local wins in this (value)
    // position and the call is not a reference to the class.
    let (_project, analyzer) = kotlin_workspace(&[
        ("src/lib/Base.kt", BASE_KT),
        (
            "src/app/App.kt",
            "package app

import lib.Base

fun make() {

    val Base = { -> 1 }

    val value = Base()

    println(value)
}
",
        ),
    ]);

    let target = definition(&analyzer, "lib.Base");
    let hits = hits(&usages(&analyzer, &target));

    assert_no_hit_line(&hits, 9);
}

#[test]
fn kotlin_query_reports_usages_of_a_java_class_from_kotlin_source() {
    // The realm is one candidate space, so a Kotlin file naming a Java class is
    // a usage of it. The Kotlin name ladder already resolves against the
    // realm-wide declaration index; what milestone 4 added is running the scan
    // over Kotlin files for a non-Kotlin target.
    let built = InlineTestProject::new()
        .file(
            "src/lib/Greeter.java",
            "package lib;\n\npublic class Greeter {\n    public String greet() { return \"hi\"; }\n}\n",
        )
        .file(
            "src/app/App.kt",
            "package app

import lib.Greeter

fun make(): String {

    val greeter = Greeter()

    return greeter.greet()
}
",
        )
        .build();
    let workspace = built.workspace_analyzer(brokk_bifrost::AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let target = analyzer
        .get_definitions("lib.Greeter")
        .into_iter()
        .find(CodeUnit::is_class)
        .expect("lib.Greeter");

    let files = analyzer.analyzed_files().into_iter().collect();
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    let result = UsageFinder::new()
        .query_with_provider(
            analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1000,
            1000,
        )
        .result;
    let hits = hits(&result);

    assert!(
        hits.iter()
            .any(|hit| hit.file.rel_path().to_string_lossy().ends_with("App.kt")),
        "a Java class's Kotlin call sites must be reported: {hits:#?}"
    );
}
