//! End-to-end coverage for the RQLP materialization asserts (issue #1476, M5).
//!
//! `assert-generation` pins the exact cardinality of a generation site's
//! generated set — the invariant the mined attr_* regressions violated — and
//! `assert-declaration-state` pins a declaration's origin and declaration-only
//! flag, which is what the @overload dead-code regression (da26602) needed.
//!
//! Every test asserts the run's completion before reading its findings: the
//! soundness rule returns zero findings whenever an input is incomplete, so a
//! test that only counted findings would pass just as happily on a broken
//! query as on a satisfied invariant.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyAnalysisType, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyLocationRelationship, PolicyRegistry,
    PolicyRegistryLimits, PolicyRun, PolicyRunCompletion, PolicySourceIdentity,
    TaintCatalogRegistry,
};
use brokk_bifrost::{IAnalyzer, Language, PythonAnalyzer, RubyAnalyzer};

/// A literal accessor generating three declarations (the backing field, the
/// reader and the writer) plus a two-argument reader generating four (two
/// backing fields, two readers) whose naming arguments are two distinct
/// source locations.
const RUBY_LITERAL: &str =
    "class Widget\n  attr_accessor :name\n  attr_reader :first, :second\nend\n";

/// A dynamic accessor: the analyzer cannot name what it generates, and the
/// honest verdict over its generated set is inconclusive.
const RUBY_DYNAMIC: &str = "class Widget\n  attr_reader label.to_sym\nend\n";

/// Two @overload stubs and their runnable implementation, plus an ordinary
/// runnable helper.
const PYTHON_OVERLOADS: &str = concat!(
    "from typing import overload\n",
    "@overload\n",
    "def parse(value: int) -> int: ...\n",
    "@overload\n",
    "def parse(value: str) -> str: ...\n",
    "def parse(value):\n",
    "    return value\n",
    "def helper(value):\n",
    "    return value\n",
);

fn policy(id: &str, subject: &str, asserts: &str) -> String {
    format!(
        r#"(policy
  :id "{id}"
  :name "Materialization assertion"
  :message "the materialization invariant does not hold"
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
            PolicySourceIdentity::new("test:materialization-assertion"),
            source.as_bytes(),
        )
        .expect("valid materialization assertion policy");
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
        .expect("materialization assertion evaluation")
}

fn ruby_project(source: &str) -> (crate::common::BuiltInlineTestProject, RubyAnalyzer) {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("lib/widget.rb", source)
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

/// The generating call itself is the subject: the site row's AST identity is
/// the `call` fact, so the capture joins it exactly.
const ACCESSOR_SUBJECT: &str = r#"(call :text/regex "^attr_accessor" :capture "site")"#;
const READER_SUBJECT: &str = r#"(call :text/regex "^attr_reader" :capture "site")"#;

/// The satisfied case: a literal `attr_accessor` generates exactly three
/// declarations (backing field, reader, writer).
#[test]
fn a_literal_accessor_satisfies_its_exact_cardinality() {
    let (_project, analyzer) = ruby_project(RUBY_LITERAL);
    let run = evaluate(
        &policy(
            "test.generation.exact",
            ACCESSOR_SUBJECT,
            r#"(assert-generation :id exact :at "site" :kind accessor_macro
                          :cardinality (exactly 3))"#,
        ),
        &analyzer,
    );
    assert_eq!(run.analysis_type(), PolicyAnalysisType::Assertion);
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "the verdict must be read only from a complete run: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "attr_accessor generates field + reader + writer: {:?}",
        run.findings()
    );
}

/// The seeded miss: demanding a two-argument reader generate three
/// declarations when it generates four. The finding's related locations carry
/// the site and the generated declarations' naming arguments — the
/// multi-location evidence the issue's acceptance requires. The four
/// declarations share two naming arguments (`:first` names its field and its
/// reader), and identical related locations dedupe, so two distinct argument
/// locations remain.
#[test]
fn a_missed_cardinality_reports_the_site_and_every_generated_declaration() {
    let (_project, analyzer) = ruby_project(RUBY_LITERAL);
    let run = evaluate(
        &policy(
            "test.generation.miss",
            READER_SUBJECT,
            r#"(assert-generation :id miss :at "site" :kind accessor_macro
                          :cardinality (exactly 3))"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
    let finding = &run.findings()[0];
    let relationships: Vec<_> = finding
        .related()
        .iter()
        .map(|related| related.relationship())
        .collect();
    assert!(
        relationships.contains(&PolicyLocationRelationship::GenerationSite),
        "the site itself is evidence: {relationships:?}"
    );
    assert_eq!(
        relationships
            .iter()
            .filter(|relationship| {
                **relationship == PolicyLocationRelationship::GeneratedDeclaration
            })
            .count(),
        2,
        "the two naming arguments are two distinct generated-declaration locations: {relationships:?}"
    );
}

/// A dynamic site makes a cardinality inconclusive: the generated set is
/// honestly unknown, so the verdict is neither a pass nor a finding.
#[test]
fn a_dynamic_site_is_inconclusive_under_a_cardinality() {
    let (_project, analyzer) = ruby_project(RUBY_DYNAMIC);
    let run = evaluate(
        &policy(
            "test.generation.dynamic",
            READER_SUBJECT,
            r#"(assert-generation :id dynamic :at "site" :kind accessor_macro
                          :cardinality (exactly 2))"#,
        ),
        &analyzer,
    );
    assert!(
        matches!(run.completion(), PolicyRunCompletion::Inconclusive { .. }),
        "a dynamic generated set can neither pass nor fail: {:?}",
        run.completion()
    );
    assert!(run.findings().is_empty());
}

/// The same dynamic site under `:forbid-dynamic true` is the finding itself.
#[test]
fn forbid_dynamic_turns_the_dynamic_site_into_the_finding() {
    let (_project, analyzer) = ruby_project(RUBY_DYNAMIC);
    let run = evaluate(
        &policy(
            "test.generation.forbid",
            READER_SUBJECT,
            r#"(assert-generation :id forbid :at "site" :kind accessor_macro
                          :forbid-dynamic true)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(run.findings().len(), 1, "{:?}", run.findings());
}

/// The da26602 invariant as a policy: a captured `def` under `@overload` must
/// be declaration-only. The stub satisfies it; the runnable helper, asserted
/// with the same expectation, is the finding.
#[test]
fn declaration_state_separates_stubs_from_runnable_definitions() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app/over.py", PYTHON_OVERLOADS)
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());

    let run = evaluate(
        &policy(
            "test.state.stub",
            r#"(function :name "helper" :capture "declaration")"#,
            r#"(assert-declaration-state :id stub :at "declaration"
                          :declaration-only true)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(
        run.findings().len(),
        1,
        "the runnable helper is not declaration-only: {:?}",
        run.findings()
    );

    let run = evaluate(
        &policy(
            "test.state.origin",
            r#"(function :name "helper" :capture "declaration")"#,
            r#"(assert-declaration-state :id origin :at "declaration"
                          :origin parsed :declaration-only false)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "the helper is a parsed, runnable declaration: {:?}",
        run.findings()
    );
}
