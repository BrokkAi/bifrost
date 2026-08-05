//! Conformance fixture pairs for the RQLP resolution asserts (#1474, M6),
//! policy side.
//!
//! `code_query_resolution_conformance.rs` in `suite_cross_language` runs the
//! same mined shapes through the query surface; this module runs them as
//! policies, because a row an author cannot turn into a verdict is only half a
//! capability.
//!
//! The discipline is the one Milestone 5 established. A pair is two sources
//! differing in exactly one structural fact, evaluated under one policy, with
//! opposite outcomes. Every test reads `run.completion()` before it reads
//! `run.findings()`: the assertion kind returns zero findings on any incomplete
//! input, so a test that only counted findings would pass just as happily on a
//! broken query as on a satisfied invariant.
//!
//! Three families reach a verdict of `Inconclusive` on purpose, and each says
//! so in its name. That is the fourth acceptance criterion of the issue -- an
//! ambiguous or incomplete environment must never become a complete empty
//! answer -- and it is a claim these fixtures test rather than a shortfall they
//! tolerate.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
    PolicyEvaluator, PolicyIncompleteReason, PolicyRegistry, PolicyRegistryLimits, PolicyRun,
    PolicyRunCompletion, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language, RustAnalyzer, TypescriptAnalyzer};

fn policy(id: &str, subject: &str, asserts: &str) -> String {
    format!(
        r#"(policy
  :id "{id}"
  :name "Resolution conformance"
  :message "the resolution invariant does not hold"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql {subject})
    :asserts [{asserts}]))"#
    )
}

fn evaluate(source: &str, analyzer: &dyn IAnalyzer) -> PolicyRun {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:resolution-conformance"),
            source.as_bytes(),
        )
        .expect("valid resolution assertion policy");
    let policy = registry.policies().next().expect("one policy");
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer,
                workspace: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
            },
            &mut PolicyBudget::default(),
        )
        .expect("resolution assertion evaluation")
}

/// Build an analyzer over an inline project of one or more files.
///
/// The project is returned so its temporary root outlives the analyzer.
fn analyzer_for(
    language: Language,
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, Box<dyn IAnalyzer>) {
    let mut project = InlineTestProject::with_language(language);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let owned = project.project().clone();
    let analyzer: Box<dyn IAnalyzer> = match language {
        Language::Java => Box::new(JavaAnalyzer::from_project(owned)),
        Language::Rust => Box::new(RustAnalyzer::from_project(owned)),
        Language::TypeScript => Box::new(TypescriptAnalyzer::from_project(owned)),
        other => panic!("no conformance analyzer for {other:?}"),
    };
    (project, analyzer)
}

/// The pair contract: one policy, one finding on the positive half, none on the
/// near-miss half, and a complete run on both.
///
/// A near-miss that is clean because the run could not conclude would prove
/// nothing, which is why completion is asserted on both halves rather than only
/// where a finding is expected.
fn assert_pair(
    policy: &str,
    language: Language,
    positive: &[(&str, &str)],
    near_miss: &[(&str, &str)],
) {
    let (_positive_project, positive_analyzer) = analyzer_for(language, positive);
    let run = evaluate(policy, positive_analyzer.as_ref());
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "the positive half must reach a verdict: {:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        1,
        "the positive half must report exactly one violation: {:?}",
        run.findings()
    );

    let (_near_miss_project, near_miss_analyzer) = analyzer_for(language, near_miss);
    let clean = evaluate(policy, near_miss_analyzer.as_ref());
    assert_eq!(
        clean.completion(),
        &PolicyRunCompletion::Complete,
        "the near-miss half must be clean for the right reason: {:?}",
        clean.diagnostics()
    );
    assert!(
        clean.findings().is_empty(),
        "the near-miss half must report nothing: {:?}",
        clean.findings()
    );
}

fn inconclusive_reasons(run: &PolicyRun) -> &[PolicyIncompleteReason] {
    match run.completion() {
        PolicyRunCompletion::Inconclusive { reasons } => reasons,
        other => panic!("expected an inconclusive run, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Scenario 1 -- sibling imports versus the true target (Java).
// ---------------------------------------------------------------------------

const API_WIDGET: &str =
    "package api;\n\npublic class Widget {\n    public int size() { return 1; }\n}\n";

/// One type operand per half -- the parameter's declared type -- so the pair
/// contract stays "exactly one violation" rather than counting how many times
/// the fixture happens to name the type.
const HOST_WILDCARD_IMPORT: &str = "package app;\n\nimport api.*;\n\nclass Host {\n    int run(Widget widget) {\n        return widget.size();\n    }\n}\n";

const HOST_EXPLICIT_IMPORT: &str = "package app;\n\nimport api.Widget;\n\nclass Host {\n    int run(Widget widget) {\n        return widget.size();\n    }\n}\n";

/// "This type must be reached by an explicit import, not by an on-demand one."
///
/// Both halves resolve `Widget` to the same declaration, so a rule that could
/// only see the target would be blind here. The tier is what moves.
#[test]
fn a_wildcard_route_violates_an_explicit_import_requirement() {
    assert_pair(
        &policy(
            "test.conformance.sibling-imports",
            r#"(identifier :text/regex "^Widget$" :capture "target")"#,
            r#"(assert-resolution :id explicit :at "target" :role type_operand
                          :expect-tier explicit_import)"#,
        ),
        Language::Java,
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_WILDCARD_IMPORT),
        ],
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_EXPLICIT_IMPORT),
        ],
    );
}

// ---------------------------------------------------------------------------
// Scenario 2 -- before/after-use declarations (Java).
// ---------------------------------------------------------------------------

const READ_AFTER_DECLARATION: &str = "class Order {\n    int run() {\n        int seed = 1;\n        int copy = seed;\n        return copy;\n    }\n}\n";

const READ_BEFORE_DECLARATION: &str = "class Order {\n    int run() {\n        int copy = seed;\n        int seed = 1;\n        return copy;\n    }\n}\n";

/// The same tokens in two orders. The requirement is that the read reach a
/// binding declared *outside* the method, so the half where the local is in
/// effect violates it and the half where the read sits above the declarator has
/// no reaching binding at all.
///
/// The near-miss is clean because a missing reaching binding is a complete
/// negative -- the name resolves to something that is not a lexical binding, so
/// there is no declaring scope for a containment requirement to constrain. It
/// is not clean because the run failed to conclude, which is what the
/// completion assertion in `assert_pair` proves.
#[test]
fn a_read_above_its_declarator_reaches_no_binding_to_constrain() {
    assert_pair(
        &policy(
            "test.conformance.before-after-use",
            r#"(inside (callable :capture "region")
                     (identifier :text/regex "^seed$" :capture "target"))"#,
            r#"(assert-reaching :id declared-outside :at "target" :role value_reference
                          :declared outside :relative-to "region")"#,
        ),
        Language::Java,
        &[("app/Order.java", READ_AFTER_DECLARATION)],
        &[("app/Order.java", READ_BEFORE_DECLARATION)],
    );
}

// ---------------------------------------------------------------------------
// Scenario 3 -- a nearer namesake changes the verdict (Rust).
// ---------------------------------------------------------------------------

const RUST_OUTER_ONLY: &str = "fn render() -> usize {\n    let value = 1;\n    let mut total = 0;\n    while total < 3 {\n        total = total + value;\n    }\n    total\n}\n";

const RUST_NEARER_NAMESAKE: &str = "fn render() -> usize {\n    let value = 1;\n    let mut total = 0;\n    while total < 3 {\n        let value = 2;\n        total = total + value;\n    }\n    total\n}\n";

/// The near-miss adds one `let` inside the loop and changes nothing else. The
/// read is spelled identically in both halves and refers to a different binding
/// in each, which is the whole point of reaching-binding semantics: source-order
/// co-presence cannot tell these apart.
#[test]
fn a_nearer_namesake_inside_the_loop_satisfies_a_containment_requirement() {
    assert_pair(
        &policy(
            "test.conformance.namesakes",
            r#"(inside (loop :capture "region")
                     (identifier :text/regex "^value$" :capture "target"))"#,
            r#"(assert-reaching :id declared-inside :at "target" :role value_reference
                          :declared inside :relative-to "region")"#,
        ),
        Language::Rust,
        &[("src/render.rs", RUST_OUTER_ONLY)],
        &[("src/render.rs", RUST_NEARER_NAMESAKE)],
    );
}

// ---------------------------------------------------------------------------
// Scenario 4 -- type/value namespace collision (Java).
// ---------------------------------------------------------------------------

const JAVA_NAMESPACE_COLLISION: &str = "package app;\n\nclass Item {\n    int weigh() { return 2; }\n}\n\nclass Holder {\n    int run() {\n        Item Item = new Item();\n        return Item.weigh();\n    }\n}\n";

const JAVA_NAMESPACE_COLLISION_TYPE_ONLY: &str = "package app;\n\nclass Item {\n    int weigh() { return 2; }\n}\n\nclass Holder {\n    int run() {\n        Item Item = new Item();\n        return 0;\n    }\n}\n";

/// One spelling, five occurrences, two namespaces. The near-miss deletes only
/// the value-position read; the local binder and both type operands stay, so
/// the spelling `Item` is just as present as before and the verdict still
/// flips. A rule that resolved by name could not do that.
#[test]
fn a_type_operand_of_a_colliding_spelling_never_triggers_a_value_assert() {
    assert_pair(
        &policy(
            "test.conformance.namespace-collision",
            r#"(inside (callable :capture "region")
                     (identifier :text/regex "^Item$" :capture "target"))"#,
            r#"(assert-reaching :id declared-outside :at "target" :role receiver_position
                          :declared outside :relative-to "region")"#,
        ),
        Language::Java,
        &[("app/Item.java", JAVA_NAMESPACE_COLLISION)],
        &[("app/Item.java", JAVA_NAMESPACE_COLLISION_TYPE_ONLY)],
    );
}

// ---------------------------------------------------------------------------
// Scenario 5 -- an unindexed declared dependency (Java).
// ---------------------------------------------------------------------------

const HOST_EXTERNAL_DEPENDENCY: &str = "package app;\n\nimport java.util.List;\n\nclass Host {\n    int run(List<String> rows) {\n        List<String> copy = rows;\n        return copy.size();\n    }\n}\n";

/// A dependency the build declares and the workspace does not contain cannot
/// be assigned a precedence tier, and the honest verdict is that the rule could
/// not conclude -- never that the requirement held.
///
/// The near-miss is the same import shape against a target that *is* indexed:
/// one structural fact differs, and the run goes from inconclusive to a
/// complete, clean verdict.
#[test]
fn an_unindexed_declared_dependency_is_inconclusive_rather_than_a_clean_pass() {
    let source = policy(
        "test.conformance.unindexed-dependency",
        r#"(identifier :text/regex "^(List|Widget)$" :capture "target")"#,
        r#"(assert-resolution :id imported :at "target" :role type_operand
                      :expect-tier explicit_import)"#,
    );

    let (_external_project, external) = analyzer_for(
        Language::Java,
        &[("app/Host.java", HOST_EXTERNAL_DEPENDENCY)],
    );
    let unindexed = evaluate(&source, external.as_ref());
    assert!(
        inconclusive_reasons(&unindexed).contains(&PolicyIncompleteReason::CapabilityIncomplete),
        "{:?}",
        unindexed.completion()
    );
    assert!(
        unindexed.findings().is_empty(),
        "an inconclusive run never yields a verdict: {:?}",
        unindexed.findings()
    );

    let (_indexed_project, indexed) = analyzer_for(
        Language::Java,
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_EXPLICIT_IMPORT),
        ],
    );
    let resolved = evaluate(&source, indexed.as_ref());
    assert_eq!(
        resolved.completion(),
        &PolicyRunCompletion::Complete,
        "an indexed target is answerable: {:?}",
        resolved.diagnostics()
    );
    assert!(
        resolved.findings().is_empty(),
        "and it satisfies the requirement: {:?}",
        resolved.findings()
    );
}

// ---------------------------------------------------------------------------
// Scenario 6 -- wildcard ambiguity stays explicit (Java).
// ---------------------------------------------------------------------------

const UTIL_WIDGET: &str =
    "package util;\n\npublic class Widget {\n    public int size() { return 2; }\n}\n";

const HOST_TWO_WILDCARDS: &str = "package app;\n\nimport api.*;\nimport util.*;\n\nclass Host {\n    int run(Widget widget) {\n        return widget.size();\n    }\n}\n";

/// Two on-demand imports that both supply `Widget`, and the boundary this
/// milestone pins rather than claims.
///
/// The environment keeps the ambiguity explicit: both import binder rows carry
/// `wildcard_ambiguous: true`, which the query-surface conformance suite
/// asserts. The *trace* does not. Java's workspace wildcard route selects the
/// first package that supplies the name and records one confident selection, so
/// a tier assert concludes here and concludes cleanly -- the same verdict it
/// reaches on the unambiguous half.
///
/// That is a real gap between two producers about one file, and this test is
/// its executable statement: the assert vocabulary has no reader for
/// `wildcard_ambiguous`, and the trace it does read reports no ambiguity to
/// read. The day the resolver reports the collision -- see the follow-up issue
/// recorded in the ExecPlan -- the ambiguous half stops being clean and this
/// test fails, which is exactly when someone should look at it.
#[test]
fn colliding_wildcard_imports_are_ambiguous_on_the_binding_row_and_not_yet_on_the_trace() {
    let source = policy(
        "test.conformance.wildcard-ambiguity",
        r#"(identifier :text/regex "^Widget$" :capture "target")"#,
        r#"(assert-resolution :id unique :at "target" :role type_operand
                      :expect-tier wildcard_import :require-unique true)"#,
    );

    let (_ambiguous_project, ambiguous) = analyzer_for(
        Language::Java,
        &[
            ("api/Widget.java", API_WIDGET),
            ("util/Widget.java", UTIL_WIDGET),
            ("app/Host.java", HOST_TWO_WILDCARDS),
        ],
    );
    let run = evaluate(&source, ambiguous.as_ref());
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "the trace states one selection, so the assert concludes: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "the resolver reports no peer to be non-unique against: {:?}",
        run.findings()
    );

    let (_single_project, single) = analyzer_for(
        Language::Java,
        &[
            ("api/Widget.java", API_WIDGET),
            ("app/Host.java", HOST_WILDCARD_IMPORT),
        ],
    );
    let unambiguous = evaluate(&source, single.as_ref());
    assert_eq!(
        unambiguous.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        unambiguous.diagnostics()
    );
    assert!(
        unambiguous.findings().is_empty(),
        "one on-demand route is genuinely unique: {:?}",
        unambiguous.findings()
    );
}

// ---------------------------------------------------------------------------
// Scenario 7 -- the authoritative-boundary anti-fallback contract (Java).
// ---------------------------------------------------------------------------

/// The contract is a prohibition, and no resolver in the workspace commits the
/// offence: `PrecedenceTier::NameOnlyFallback` has no producer, which the query
/// suite asserts across all four claimed languages. This fixture therefore
/// states the contract and proves it *concludes* -- a clean, complete run at a
/// real external boundary -- rather than seeding a firing that would require
/// writing a resolver that falls back by bare name.
///
/// The day a resolver admits to such a fallback, this policy fires with no
/// further work.
#[test]
fn the_anti_fallback_contract_concludes_cleanly_at_a_real_boundary() {
    let (_project, analyzer) = analyzer_for(
        Language::Java,
        &[("app/Host.java", HOST_EXTERNAL_DEPENDENCY)],
    );
    let run = evaluate(
        &policy(
            "test.conformance.anti-fallback",
            r#"(identifier :text/regex "^List$" :capture "target")"#,
            r#"(assert-boundary :id no-fallback :at "target" :role type_operand
                          :forbid-fallback-past external_unknown)"#,
        ),
        analyzer.as_ref(),
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "a prohibition concludes even where a positive requirement cannot: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "nothing is selected by bare name past the boundary: {:?}",
        run.findings()
    );
}

// ---------------------------------------------------------------------------
// Scenario 8 -- a deferred body inside a loop (Java).
// ---------------------------------------------------------------------------

const JAVA_DEFERRED_BODY: &str = "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n\nclass Deferred {\n    void run() {\n        List<String> rows = new ArrayList<>();\n        int index = 0;\n        while (index < 3) {\n            Runnable task = () -> Collections.sort(rows);\n            task.run();\n            index = index + 1;\n        }\n    }\n}\n";

const JAVA_DEFERRED_BODY_LOOP_LOCAL: &str = "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n\nclass Deferred {\n    void run() {\n        int index = 0;\n        while (index < 3) {\n            List<String> rows = new ArrayList<>();\n            Runnable task = () -> Collections.sort(rows);\n            task.run();\n            index = index + 1;\n        }\n    }\n}\n";

/// The boundary the repository's policy rules require to be pinned rather than
/// claimed. Lexical containment can say the call is written inside the loop; it
/// cannot say how many times the closure runs. This fixture makes the behaviour
/// explicit and tested: the call inside the closure *is* reported when its
/// receiver is declared outside the loop, and is not reported when the receiver
/// is loop-local.
///
/// A rule shipped on this predicate must therefore say in its message that the
/// match is a lexically deferred body, so a reader is not told that the work
/// certainly happens once per iteration.
#[test]
fn a_closure_body_inside_a_loop_is_an_explicit_tested_lexical_positive() {
    assert_pair(
        &policy(
            "test.conformance.deferred-body",
            r#"(inside (loop :capture "region")
                     (call :callee (name "sort") :args [(capture "target")]))"#,
            r#"(assert-reaching :id declared-inside :at "target" :role value_reference
                          :declared inside :relative-to "region")"#,
        ),
        Language::Java,
        &[("app/Deferred.java", JAVA_DEFERRED_BODY)],
        &[("app/Deferred.java", JAVA_DEFERRED_BODY_LOOP_LOCAL)],
    );
}

// ---------------------------------------------------------------------------
// Scenario 9 -- a selection-only language (TypeScript).
// ---------------------------------------------------------------------------

const TS_MODULE: &str = "export function render(rows: string[]): string {\n    const first = rows[0];\n    return first;\n}\n";

/// TypeScript's resolver records selections but not rejections. An assert that
/// needs the whole considered set therefore cannot conclude there, and the same
/// assert without that option can -- which is what makes the first verdict a
/// statement about the option rather than about the language.
///
/// Milestone 5 states this for Python; this is the claim for the other
/// selection-only adapter, and it is why no fixture in this file uses
/// `:require-unique` outside a full-trace language.
#[test]
fn a_rejection_dependent_assert_is_inconclusive_on_typescript() {
    let (_project, analyzer) = analyzer_for(Language::TypeScript, &[("src/widget.ts", TS_MODULE)]);

    let unique = evaluate(
        &policy(
            "test.conformance.selection-only",
            r#"(identifier :text/regex "^first$" :capture "target")"#,
            r#"(assert-resolution :id unique :at "target" :role value_reference
                          :expect-tier lexical_binding :require-unique true)"#,
        ),
        analyzer.as_ref(),
    );
    assert!(
        inconclusive_reasons(&unique).contains(&PolicyIncompleteReason::CapabilityIncomplete),
        "{:?}",
        unique.completion()
    );
    assert!(unique.findings().is_empty());

    let tier_only = evaluate(
        &policy(
            "test.conformance.selection-only-tier",
            r#"(identifier :text/regex "^first$" :capture "target")"#,
            r#"(assert-resolution :id tier :at "target" :role value_reference
                          :expect-tier lexical_binding)"#,
        ),
        analyzer.as_ref(),
    );
    assert_eq!(
        tier_only.completion(),
        &PolicyRunCompletion::Complete,
        "the selection axis alone is answerable in TypeScript: {:?}",
        tier_only.diagnostics()
    );
}
