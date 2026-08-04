//! Conformance fixture pairs for the RQLP `assertion` analysis kind (#1473,
//! Milestone 5).
//!
//! Every pair below is minimized from the 46-commit inventory in the issue
//! body and follows one discipline: the two halves differ only in *where* a
//! token sits, never in how it is spelled. The positive half reproduces the
//! role-fidelity shape the original regression got wrong and must report a
//! finding; the near-miss half is the realistic neighbouring shape -- the same
//! API names, the same operation, one structural context away -- and must be
//! clean.
//!
//! The join between the subject capture and the occurrence rows is `ast_id`
//! equality, so nothing here can pass by matching a spelling.
//!
//! `code_query_occurrences.rs` in `suite_cross_language` exercises the same six
//! scenarios through the query surface; this module is the policy surface.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
    PolicyEvaluator, PolicyFinding, PolicyRegistry, PolicyRegistryLimits, PolicyRunCompletion,
    PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{
    IAnalyzer, JavaAnalyzer, Language, PythonAnalyzer, RustAnalyzer, TypescriptAnalyzer,
};

/// A policy asserting that no token captured as `target` carries an occurrence
/// of `role`. Every conformance pair below is expressible this way because the
/// invariant each mined regression violated is "this position is not that".
fn forbid_role(name: &str, spelling: &str, role: &str) -> String {
    format!(
        r#"(policy
  :id "test.conformance.{name}"
  :name "Conformance {name}"
  :message "{spelling} must never occur as {role}"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql (identifier :text/regex "^{spelling}$" :capture "target"))
    :asserts [
      (assert :id forbidden :at "target" :role {role} :expect none)
    ]))"#
    )
}

fn findings_for(policy: &str, analyzer: &dyn IAnalyzer) -> Vec<PolicyFinding> {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:conformance"),
            policy.as_bytes(),
        )
        .expect("valid assertion policy");
    let policy = registry.policies().next().expect("one policy");
    let run = DefaultPolicyEvaluator::new()
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
        .expect("assertion evaluation");
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "a conformance fixture that cannot be answered completely proves nothing"
    );
    run.findings().to_vec()
}

/// Build the analyzer for `language` over a single-file inline project.
///
/// Returning the project keeps its temporary root alive for the caller.
fn analyzer_for(
    language: Language,
    path: &str,
    source: &str,
) -> (crate::common::BuiltInlineTestProject, Box<dyn IAnalyzer>) {
    let project = InlineTestProject::with_language(language)
        .file(path, source)
        .build();
    let owned = project.project().clone();
    let analyzer: Box<dyn IAnalyzer> = match language {
        Language::TypeScript => Box::new(TypescriptAnalyzer::from_project(owned)),
        Language::Java => Box::new(JavaAnalyzer::from_project(owned)),
        Language::Python => Box::new(PythonAnalyzer::from_project(owned)),
        Language::Rust => Box::new(RustAnalyzer::from_project(owned)),
        other => panic!("no conformance analyzer for {other:?}"),
    };
    (project, analyzer)
}

/// Assert the fixture pair contract: the positive half reports exactly one
/// finding for the named assert, the near-miss half reports none.
fn assert_pair(policy: &str, language: Language, path: &str, positive: &str, near_miss: &str) {
    let (_positive_project, positive_analyzer) = analyzer_for(language, path, positive);
    let findings = findings_for(policy, positive_analyzer.as_ref());
    assert_eq!(
        findings.len(),
        1,
        "the positive fixture must report exactly one role-fidelity violation: {findings:?}"
    );

    let (_near_miss_project, near_miss_analyzer) = analyzer_for(language, path, near_miss);
    let clean = findings_for(policy, near_miss_analyzer.as_ref());
    assert!(
        clean.is_empty(),
        "the near-miss fixture must be clean: {clean:?}"
    );
}

/// Scenario 1: renamed destructuring (JS/TS), from `009e510bc` ("Fix TypeScript
/// destructuring field usages").
///
/// `alpha` is introduced by a renaming destructure, so every `alpha` token must
/// be a binder. The positive half adds a shorthand property in an object
/// *expression*: the identical spelling in a position that reads.
#[test]
fn renamed_destructuring_binders_are_never_shorthand_reads() {
    assert_pair(
        &forbid_role("destructuring", "alpha", "value_reference"),
        Language::TypeScript,
        "src/destructure.ts",
        concat!(
            "const source = { first: 1 };\n",
            "const { first: alpha } = source;\n",
            "export const echo = { alpha };\n",
        ),
        concat!(
            "const source = { first: 1 };\n",
            "const { first: alpha } = source;\n",
            "export const echo = { first: 2 };\n",
        ),
    );
}

/// Scenario 2: type operands versus binders (Python), from `ee82b7b0b` ("Fix
/// Python annotation usage edges", #413) and `031e3be78` ("Resolve non-class
/// Python annotation usages").
///
/// A class named in an annotation is a type operand; the same class read in
/// expression position is a value reference. The near-miss keeps the class,
/// the parameter and the annotation and only drops the expression-position
/// read.
#[test]
fn a_class_used_only_as_an_annotation_never_reads_as_a_value() {
    assert_pair(
        &forbid_role("annotation", "Widget", "value_reference"),
        Language::Python,
        "src/widget.py",
        concat!(
            "class Widget:\n",
            "    pass\n",
            "\n",
            "def render(widget: Widget) -> int:\n",
            "    return 1\n",
            "\n",
            "def build():\n",
            "    return Widget()\n",
        ),
        concat!(
            "class Widget:\n",
            "    pass\n",
            "\n",
            "def render(widget: Widget) -> int:\n",
            "    return 1\n",
            "\n",
            "def build():\n",
            "    return 2\n",
        ),
    );
}

/// Scenario 2b: the binder half of the same invariant.
///
/// A parameter name never occupies a type slot, in either half of the pair, so
/// this assert is a standing invariant rather than a fixture pair -- which is
/// exactly the property the regression above violated in the other direction.
#[test]
fn a_parameter_name_never_carries_a_type_operand_row() {
    let (_project, analyzer) = analyzer_for(
        Language::Python,
        "src/widget.py",
        concat!(
            "class Widget:\n",
            "    pass\n",
            "\n",
            "def render(widget: Widget) -> int:\n",
            "    return 1\n",
        ),
    );
    assert!(
        findings_for(
            &forbid_role("parameter", "widget", "type_operand"),
            analyzer.as_ref()
        )
        .is_empty(),
        "the parameter binds; only its annotation is a type operand"
    );
}

/// Scenario 3: keyed fields versus map keys (TS), from `91cddbf29` ("Resolve Go
/// struct literal field usages"), whose shape is language-independent.
///
/// The two halves differ by two brackets. A static key names a field and reads
/// nothing; a computed key is an expression and reads the binding.
#[test]
fn a_computed_record_key_reads_while_a_static_one_does_not() {
    assert_pair(
        &forbid_role("keyed", "label", "value_reference"),
        Language::TypeScript,
        "src/keyed.ts",
        concat!(
            "const label = 1;\n",
            "export const record = { [label]: 2 };\n"
        ),
        concat!(
            "const label = 1;\n",
            "export const record = { label: 2 };\n"
        ),
    );
}

/// Scenario 4: static qualifiers versus shadowing values (Java), from
/// `8d5df9d0e`, `642e3214d` and `abb34275d` (#978).
///
/// `Config` is a type: it may head its own declaration and qualify a static
/// member, but it is never a plain value read. The positive half adds a local
/// variable of the same spelling in a sibling method -- the shadowing shape the
/// mined regressions resolved to the wrong declaration.
#[test]
fn a_static_qualifier_is_never_confused_with_a_shadowing_local() {
    assert_pair(
        &forbid_role("qualifier", "Config", "value_reference"),
        Language::Java,
        "app/Config.java",
        concat!(
            "class Config {\n",
            "    static int LIMIT = 7;\n",
            "    int qualified() { return Config.LIMIT; }\n",
            "    int shadowed() { int Config = 1; return Config; }\n",
            "}\n",
        ),
        concat!(
            "class Config {\n",
            "    static int LIMIT = 7;\n",
            "    int qualified() { return Config.LIMIT; }\n",
            "    int plain() { int limit = 1; return limit; }\n",
            "}\n",
        ),
    );
}

/// Scenario 5: escaped identifier spellings (Rust).
///
/// The assertion surface addresses AST nodes, so it can only speak about
/// tokens that exist. A Python deferred annotation (`x: "Widget"`) is string
/// content and produces no identifier node at all, which is why that half of
/// the "quoted annotations versus strings" scenario lives on the query surface
/// (`conformance_quoted_annotations_and_strings_never_become_type_operands`)
/// and is recorded as a boundary in the ExecPlan. What the policy surface can
/// prove is the neighbouring claim: an escaped identifier is an ordinary token,
/// and the capture-to-occurrence join works on its raw spelling.
#[test]
fn an_escaped_identifier_joins_and_classifies_like_any_other_token() {
    assert_pair(
        &forbid_role("escaped", "r#match", "value_reference"),
        Language::Rust,
        "src/raw.rs",
        "pub fn make(r#match: u32) -> u32 { r#match }\n",
        "pub fn make(r#match: u32) -> u32 { 0 }\n",
    );
}

/// Scenario 6: declaration heads versus genuine reads (Rust), from `6e0ce0284`
/// ("reject declaration-head pseudo references") and `81ff35b3b` (#884).
///
/// A declaration head is not a reference to the thing it declares. The positive
/// half calls the function; nothing else changes.
#[test]
fn a_declaration_head_is_not_a_read_of_what_it_declares() {
    assert_pair(
        &forbid_role("heads", "render", "value_reference"),
        Language::Rust,
        "src/heads.rs",
        concat!(
            "pub fn render() -> u32 {\n",
            "    1\n",
            "}\n",
            "\n",
            "pub fn caller() -> u32 {\n",
            "    render()\n",
            "}\n",
        ),
        concat!("pub fn render() -> u32 {\n", "    1\n", "}\n"),
    );
}

/// The exit-code half of the contract, once, over the CLI: a conformance
/// positive is exit 1 and its near-miss is exit 0. The in-process tests above
/// cover the verdicts; this covers the process contract an agent or CI job
/// actually observes.
#[test]
fn the_policy_cli_exits_one_on_the_positive_half_and_zero_on_the_near_miss() {
    let policy = forbid_role("qualifier", "Config", "value_reference");
    let run = |source: &str| -> Option<i32> {
        let project = InlineTestProject::with_language(Language::Java)
            .file("app/Config.java", source)
            .file("policies/qualifier.rqlp", &policy)
            .build();
        bifrost_policy_exit(project.root(), "policies/qualifier.rqlp")
    };

    assert_eq!(
        run(concat!(
            "class Config {\n",
            "    static int LIMIT = 7;\n",
            "    int qualified() { return Config.LIMIT; }\n",
            "    int shadowed() { int Config = 1; return Config; }\n",
            "}\n",
        )),
        Some(1)
    );
    assert_eq!(
        run(concat!(
            "class Config {\n",
            "    static int LIMIT = 7;\n",
            "    int qualified() { return Config.LIMIT; }\n",
            "    int plain() { int limit = 1; return limit; }\n",
            "}\n",
        )),
        Some(0)
    );
}

fn bifrost_policy_exit(root: &Path, policy_path: &str) -> Option<i32> {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
        .args([
            "--policy-file",
            policy_path,
            "--evaluation-date",
            "2026-08-04",
            "--format",
            "json",
        ])
        .env("BIFROST_PARALLELISM", "1")
        .output()
        .expect("run bifrost policy");
    assert!(
        !output.stdout.is_empty(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.status.code()
}
