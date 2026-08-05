//! End-to-end coverage for the RQLP edge asserts (issue #1479, M5).
//!
//! `assert-edge-parity` states that the two production analyses answering
//! "what does this token reference" and "who references this declaration"
//! agree field for field, within one workspace generation. The load-bearing
//! test is `a_recursive_call_is_a_one_sided_edge_the_parity_assert_reports`:
//! the forward producer states the recursive edge and the inverse listing
//! omits the site entirely, on every surface -- precisely the one-sided-edge
//! shape the mined regressions (02abec289, 7cac14b63) fixed by hand, present
//! in the engine today and reported as a finding that names the edge. The
//! sibling-call pair then shows the surface comparison working in both
//! directions: the complete row sets agree, and narrowing to the
//! external-usage surface exposes the self-receiver classification gap.
//!
//! Every test asserts the run's completion before reading its findings: the
//! soundness rule returns zero findings whenever an input is incomplete, so a
//! test that only counted findings would pass just as happily on an
//! unsupported language as on a satisfied invariant.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyAnalysisType, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFindingEvidence, PolicyRegistry,
    PolicyRegistryLimits, PolicyRun, PolicyRunCompletion, PolicySourceIdentity,
    TaintCatalogRegistry,
};
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, KotlinAnalyzer, Language};

/// A plain proven cross-file call: the forward and inverse producers agree on
/// every compared field, so parity is clean whichever surface is compared.
const JAVA_REGISTRY: &str =
    "package fixture;\n\npublic class Registry {\n    public void register() {\n    }\n}\n";
const JAVA_STARTUP: &str = "package fixture;\n\npublic class Startup {\n    void boot(Registry registry) {\n        registry.register();\n    }\n}\n";

/// A recursive call: the forward producer states an ordinary reference edge,
/// while the inverse listing omits the site entirely -- a genuine one-sided
/// edge in the current engine, on every surface.
const JAVA_RECURSIVE: &str = "package fixture;\n\npublic class Countdown {\n    void tick(int remaining) {\n        if (remaining > 0) {\n            tick(remaining - 1);\n        }\n    }\n}\n";

/// A sibling call through the implicit receiver: both producers state the
/// edge, but the inverse row is classified `self_receiver`, which the
/// external-usage surface omits while the complete row set keeps it.
const JAVA_SIBLING: &str = "package fixture;\n\npublic class Worker {\n    void run() {\n        helper();\n    }\n\n    void helper() {\n    }\n}\n";

const KOTLIN_MAIN: &str = "class Registry {\n    fun register() {\n    }\n\n    fun boot() {\n        register()\n    }\n}\n";

fn policy(id: &str, subject: &str, asserts: &str) -> String {
    format!(
        r#"(policy
  :id "{id}"
  :name "Edge assertion"
  :message "the edge invariant does not hold"
  :severity warning
  :analysis (analysis
    :type assertion
    :subject (rql {subject})
    :asserts [{asserts}]))"#
    )
}

fn registry_with_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:edge-assertion"),
            source.as_bytes(),
        )
        .expect("valid edge assertion policy");
    registry
}

fn evaluate(source: &str, analyzer: &dyn IAnalyzer) -> PolicyRun {
    let registry = registry_with_policy(source);
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
        .expect("edge assertion evaluation")
}

fn java_cross_file() -> (crate::common::BuiltInlineTestProject, JavaAnalyzer) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Registry.java", JAVA_REGISTRY)
        .file("src/Startup.java", JAVA_STARTUP)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn java_recursive() -> (crate::common::BuiltInlineTestProject, JavaAnalyzer) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Countdown.java", JAVA_RECURSIVE)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn java_sibling() -> (crate::common::BuiltInlineTestProject, JavaAnalyzer) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Worker.java", JAVA_SIBLING)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

/// The capture must land on the identifier token itself: the assert joins by
/// the captured node's AST identity, and a capture on the call node would
/// correctly join nothing.
const CALL_TOKEN_SUBJECT: &str = r#"(identifier :text/regex "^register$" :capture "site")"#;
const RECURSIVE_TOKEN_SUBJECT: &str = r#"(identifier :text/regex "^tick$" :capture "site")"#;
const SIBLING_TOKEN_SUBJECT: &str = r#"(identifier :text/regex "^helper$" :capture "site")"#;

/// The satisfied case: a plain proven cross-file call agrees field for field
/// through both producers, on the complete row set and per surface.
#[test]
fn parity_is_clean_on_a_plain_proven_cross_file_call() {
    let (_project, analyzer) = java_cross_file();
    let run = evaluate(
        &policy(
            "test.edge.parity",
            CALL_TOKEN_SUBJECT,
            r#"(assert-edge-parity :id parity :at "site" :role member_position)"#,
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
        "both producers state the same edge: {:?}",
        run.findings()
    );
}

/// The one-sided edge: the forward producer states the recursive call and the
/// inverse listing omits the site entirely. The finding names the unmatched
/// edge and both provenance chains.
#[test]
fn a_recursive_call_is_a_one_sided_edge_the_parity_assert_reports() {
    let (_project, analyzer) = java_recursive();
    let run = evaluate(
        &policy(
            "test.edge.parity.recursive",
            RECURSIVE_TOKEN_SUBJECT,
            r#"(assert-edge-parity :id parity :at "site" :role member_position)"#,
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
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.assert_kind(), "edge_parity");
    assert_eq!(evidence.asserted_role(), "member_position");
    let observed = evidence.observed().expect("the finding names the edge");
    assert!(
        observed.contains("has no inverse counterpart") && observed.contains("Countdown.tick"),
        "the observed text must name the unmatched edge: {observed}"
    );
}

/// The near miss: a sibling call through the implicit receiver. Both
/// producers state the edge, so the complete row sets agree field for field
/// (usage kind is deliberately not a compared field).
#[test]
fn the_complete_row_set_is_parity_clean_on_the_sibling_call() {
    let (_project, analyzer) = java_sibling();
    let run = evaluate(
        &policy(
            "test.edge.parity.sibling",
            SIBLING_TOKEN_SUBJECT,
            r#"(assert-edge-parity :id parity :at "site" :role member_position)"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert!(run.findings().is_empty(), "{:?}", run.findings());
}

/// The usage-surface comparison, explicit: the same sibling call compared on
/// the external-usage surface alone is one-sided, because the inverse row is
/// classified `self_receiver` and that surface omits it while the forward
/// producer's row stays.
#[test]
fn the_external_surface_exposes_the_self_receiver_classification_gap() {
    let (_project, analyzer) = java_sibling();
    let run = evaluate(
        &policy(
            "test.edge.parity.sibling.external",
            SIBLING_TOKEN_SUBJECT,
            r#"(assert-edge-parity :id parity :at "site" :role member_position
                          :surface external-usages)"#,
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

/// A language without the forward projection is inconclusive, never clean:
/// the assert cannot compare what one producer cannot state.
#[test]
fn an_unsupported_language_is_inconclusive_not_clean() {
    let project = InlineTestProject::with_language(Language::Kotlin)
        .file("src/Registry.kt", KOTLIN_MAIN)
        .build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    let run = evaluate(
        &policy(
            "test.edge.parity.kotlin",
            CALL_TOKEN_SUBJECT,
            r#"(assert-edge-parity :id parity :at "site" :role member_position)"#,
        ),
        &analyzer,
    );
    assert!(
        !matches!(run.completion(), PolicyRunCompletion::Complete),
        "Kotlin has no forward projection, so the run must not read as complete: {:?}",
        run.completion()
    );
    assert!(run.findings().is_empty(), "{:?}", run.findings());
}

/// The classification assert: forbidding external edges on a cross-class call
/// fires, and the finding names the offending edge's relation.
#[test]
fn a_forbidden_owner_relation_is_a_finding_with_the_offending_edge() {
    let (_project, analyzer) = java_cross_file();
    let run = evaluate(
        &policy(
            "test.edge.class.external",
            CALL_TOKEN_SUBJECT,
            r#"(assert-edge-class :id no-external :at "site" :role member_position
                          :axis relation :forbid [external])"#,
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
    let PolicyFindingEvidence::Assertion { evidence } = run.findings()[0].evidence() else {
        panic!("assertion policies produce assertion evidence");
    };
    assert_eq!(evidence.assert_kind(), "edge_class");
    let observed = evidence.observed().expect("the finding names the edge");
    assert!(
        observed.contains("forbidden value external"),
        "the observed text must name the forbidden relation: {observed}"
    );
}

/// The class near miss: requiring the relation the edge actually carries is
/// clean.
#[test]
fn a_required_owner_relation_is_clean_when_the_edge_carries_it() {
    let (_project, analyzer) = java_cross_file();
    let run = evaluate(
        &policy(
            "test.edge.class.required",
            CALL_TOKEN_SUBJECT,
            r#"(assert-edge-class :id external-only :at "site" :role member_position
                          :axis relation :require [external])"#,
        ),
        &analyzer,
    );
    assert_eq!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "{:?}",
        run.diagnostics()
    );
    assert!(run.findings().is_empty(), "{:?}", run.findings());
}

/// An empty constraint has a fixed verdict and is rejected at load time.
#[test]
fn an_empty_class_constraint_is_rejected_at_load_time() {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let error = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:edge-assertion-empty"),
            policy(
                "test.edge.class.empty",
                CALL_TOKEN_SUBJECT,
                r#"(assert-edge-class :id empty :at "site" :role member_position :axis relation)"#,
            )
            .as_bytes(),
        )
        .expect_err("an empty edge-class constraint must not load");
    let message = format!("{error:?}");
    assert!(
        message.contains("at least one :require or :forbid"),
        "{message}"
    );
}
