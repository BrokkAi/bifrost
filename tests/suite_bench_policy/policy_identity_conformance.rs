//! Conformance fixtures for the identity assert families against the mined
//! shapes of issue #1475: transitive aliases, alias declarations as their own
//! identities, cycles staying explicit, and a cross-file facade round trip.
//!
//! The conventions are the sibling suites': every test reads the run's
//! completion before its findings; a near miss differs from its positive in
//! exactly one structural fact; and behaviour the system gets wrong today is
//! pinned with a comment rather than asserted as it ought to be.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
    PolicyEvaluator, PolicyRegistry, PolicyRegistryLimits, PolicyRun, PolicyRunCompletion,
    PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{IAnalyzer, JavascriptAnalyzer, Language, RustAnalyzer};

/// A two-hop alias chain: `B` names `A` names `Widget`. `convert` spells the
/// chained alias and the direct struct in one signature, so one match binds
/// both tokens.
const RUST_ALIAS_CHAIN: &str = "\
pub struct Widget;
pub type A = Widget;
pub type B = A;
pub fn convert(x: B) -> Widget {
    Widget
}
";

/// The mutual alias cycle. Parseable, resolvable token by token, and
/// unterminating as a route.
const RUST_ALIAS_CYCLE: &str = "\
pub type A = B;
pub type B = A;
pub fn observe(x: A) -> A {
    x
}
";

fn policy(id: &str, subject: &str, asserts: &str) -> String {
    format!(
        r#"(policy
  :id "{id}"
  :name "Identity conformance"
  :message "the identity invariant does not hold"
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
            PolicySourceIdentity::new("test:identity-conformance"),
            source.as_bytes(),
        )
        .expect("valid identity conformance policy");
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
        .expect("identity conformance evaluation")
}

fn rust_project(source: &str) -> (crate::common::BuiltInlineTestProject, RustAnalyzer) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

/// One match binding the chained alias token and the direct struct token.
const CHAIN_SUBJECT: &str = r#"(inside
                (callable (has (identifier :text/regex "^Widget$" :capture "direct")))
                (identifier :text/regex "^B$" :capture "chained"))"#;

/// A transitive alias chain routes hop by hop to the origin struct, and the
/// `:via alias` requirement names exactly the relation it travelled.
#[test]
fn a_transitive_alias_chain_routes_to_the_origin() {
    let (_project, analyzer) = rust_project(RUST_ALIAS_CHAIN);
    let run = evaluate(
        &policy(
            "test.conformance.alias-chain",
            CHAIN_SUBJECT,
            r#"(assert-route :id chain :at "chained" :role type_operand
                          :to "direct" :to-role type_operand :via alias)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "diagnostics: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "B routes to Widget through alias hops: {:?}",
        run.findings()
    );
}

/// The near miss differs in one fact: the traversal may not follow alias
/// hops, and no other relation connects the chain, so the required route does
/// not exist.
#[test]
fn forbidding_the_alias_relation_breaks_the_chain_route() {
    let (_project, analyzer) = rust_project(RUST_ALIAS_CHAIN);
    let run = evaluate(
        &policy(
            "test.conformance.alias-chain-forbid",
            CHAIN_SUBJECT,
            r#"(assert-route :id chain :at "chained" :role type_operand
                          :to "direct" :to-role type_operand :forbid alias)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "diagnostics: {:?}",
        run.diagnostics()
    );
    assert_eq!(run.findings().len(), 1, "findings: {:?}", run.findings());
}

/// An alias declaration is its own canonical identity: the chained alias and
/// the origin struct compare distinct, because the identity comparison never
/// collapses a route. The route surface, not the identity surface, carries
/// transitivity — which is why both families exist.
#[test]
fn an_alias_declaration_is_a_distinct_canonical_identity() {
    let (_project, analyzer) = rust_project(RUST_ALIAS_CHAIN);
    let run = evaluate(
        &policy(
            "test.conformance.alias-identity",
            CHAIN_SUBJECT,
            r#"(assert-canonical :id own :at "chained" :role type_operand
                          :equals "direct" :equals-role type_operand :distinct true)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "diagnostics: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "an alias unit and its target are different declarations: {:?}",
        run.findings()
    );
}

/// A mutual alias cycle never terminates a route, and the assert says so:
/// inconclusive with zero findings, never a violation and never a pass.
#[test]
fn an_alias_cycle_is_inconclusive_not_an_answer() {
    let (_project, analyzer) = rust_project(RUST_ALIAS_CYCLE);
    let run = evaluate(
        &policy(
            "test.conformance.alias-cycle",
            r#"(inside (callable :capture "region")
                (identifier :text/regex "^A$" :capture "chained"))"#,
            r#"(assert-route :id chain :at "chained" :role type_operand
                          :to "chained" :to-role type_operand :via alias)"#,
        ),
        &analyzer,
    );
    assert_ne!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "a cycle-terminated traversal must not read as a verdict"
    );
    assert!(run.findings().is_empty());
}

/// The cross-file facade closes its round trip: forward resolution reaches
/// the origin declaration in the other file, and inverse enumeration over
/// both files walks back to the export site.
#[test]
fn a_cross_file_facade_round_trips() {
    // The import renames its binding so the export specifier is the only
    // `thing` token with the import-target role: a JS import specifier
    // itself resolves to nothing today (the recorded resolver gap), and a
    // round trip cannot start from a token whose forward leg is missing.
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "index.js",
            "import { widget as thing } from './widget.js';\nexport { thing };\n",
        )
        .file("widget.js", "export function widget() { return 1; }\n")
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let run = evaluate(
        &policy(
            "test.conformance.facade-round-trip",
            r#"(where "index.js" (identifier :text/regex "^thing$" :capture "site"))"#,
            r#"(assert-round-trip :id closes :at "site" :role import_target)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "diagnostics: {:?}",
        run.diagnostics()
    );
    assert!(
        run.findings().is_empty(),
        "the facade's forward and inverse routes agree: {:?}",
        run.findings()
    );
}
