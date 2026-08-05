//! End-to-end coverage for the RQLP identity asserts (issue #1475, M5).
//!
//! The three families state that *identity survives indirection*: two
//! spellings resolve to one canonical declaration (`assert-canonical`), a
//! site's identity route reaches its target through the required hop kinds
//! (`assert-route`), and forward resolution and inverse enumeration
//! round-trip the same site (`assert-round-trip`).
//!
//! Every test asserts the run's completion before reading its findings. The
//! soundness rule returns zero findings whenever an input is incomplete, so a
//! test that only counted findings would pass just as happily on a broken
//! producer as on a satisfied invariant.

use std::sync::Arc;

use crate::common::InlineTestProject;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyAnalysisType, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFindingEvidence, PolicyLocationRelationship,
    PolicyRegistry, PolicyRegistryLimits, PolicyRun, PolicyRunCompletion, PolicySourceIdentity,
    TaintCatalogRegistry,
};
use brokk_bifrost::{GoAnalyzer, IAnalyzer, Language, RustAnalyzer};

/// One function whose return type spells the struct directly and whose local
/// annotation spells it through a `use ... as` alias. Both tokens resolve to
/// `util::Widget`, so their canonical identities agree — which is exactly
/// what a rendered-string comparison could not have proven for the alias.
const RUST_ALIASED_SPELLINGS: &str = "\
pub mod util {
    pub struct Widget;
}
use crate::util::Widget as W;
pub fn build() -> util::Widget {
    let alias: W = W;
    alias
}
";

/// A facade re-export: the `pub use` makes the identity route from the use
/// site to the struct a re-export hop.
const RUST_REEXPORT: &str = "\
pub mod util {
    pub struct Widget;
}
pub use crate::util::Widget as Exported;
";

/// The near miss: a private `use` is an import, not a re-export. The route
/// exists but carries no re-export hop.
const RUST_PRIVATE_IMPORT: &str = "\
pub mod util {
    pub struct Widget;
}
use crate::util::Widget as Exported;
pub fn build() -> Exported {
    Exported
}
";

fn policy(id: &str, subject: &str, asserts: &str) -> String {
    format!(
        r#"(policy
  :id "{id}"
  :name "Identity assertion"
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
            PolicySourceIdentity::new("test:identity-assertion"),
            source.as_bytes(),
        )
        .expect("valid identity assertion policy");
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
        .expect("identity assertion evaluation")
}

fn rust_project(source: &str) -> (crate::common::BuiltInlineTestProject, RustAnalyzer) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

/// Both captures of one match: the aliased spelling as the root, the direct
/// one bound through the containment pattern's own capture — one `has` per
/// pattern node is the grammar's rule, and `inside` carries the second.
const ALIASED_SUBJECT: &str = r#"(inside
                (callable (has (identifier :text/regex "^Widget$" :capture "canon")))
                (identifier :text/regex "^W$" :capture "alias"))"#;

/// A use declaration's target token: the site identity routes anchor at.
const USE_SITE_SUBJECT: &str =
    r#"(import (has (identifier :text/regex "^Widget$" :capture "site")))"#;

/// The satisfied case: an aliased spelling and the direct one share the
/// canonical identity, because the comparison reads structure, not text.
#[test]
fn canonical_equality_is_clean_across_an_alias() {
    let (_project, analyzer) = rust_project(RUST_ALIASED_SPELLINGS);
    let run = evaluate(
        &policy(
            "test.identity.canonical-equals",
            ALIASED_SUBJECT,
            r#"(assert-canonical :id same :at "alias" :role type_operand
                          :equals "canon" :equals-role type_operand)"#,
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
        "the two spellings resolve to one canonical identity: {:?}",
        run.findings()
    );
}

/// The inverted polarity on the same fixture: requiring the identities to be
/// distinct is violated by exactly the equality the previous test proves, and
/// the finding names both captures' identities and points at the compared
/// token.
#[test]
fn canonical_distinct_reports_the_shared_identity() {
    let (_project, analyzer) = rust_project(RUST_ALIASED_SPELLINGS);
    let run = evaluate(
        &policy(
            "test.identity.canonical-distinct",
            ALIASED_SUBJECT,
            r#"(assert-canonical :id decoy :at "alias" :role type_operand
                          :equals "canon" :equals-role type_operand :distinct true)"#,
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
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion evidence expected");
    };
    assert_eq!(evidence.assert_kind(), "canonical");
    assert!(
        finding
            .related()
            .iter()
            .any(|related| related.relationship() == PolicyLocationRelationship::Evidence),
        "the compared token must arrive as a related location"
    );
}

/// A `pub use` forwards identity onward, so the route from the use site to
/// what the site resolves to carries a re-export hop.
#[test]
fn a_reexport_route_satisfies_the_via_requirement() {
    let (_project, analyzer) = rust_project(RUST_REEXPORT);
    let run = evaluate(
        &policy(
            "test.identity.route-reexport",
            USE_SITE_SUBJECT,
            r#"(assert-route :id forwards :at "site" :role import_target
                          :to "site" :to-role import_target :via re_export)"#,
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
        "the pub use is a re-export route: {:?}",
        run.findings()
    );
}

/// The near miss: a private `use` routes through an import hop, so the same
/// requirement is violated — the route exists, and its hop kinds are wrong.
#[test]
fn a_plain_import_fails_the_reexport_route_requirement() {
    let (_project, analyzer) = rust_project(RUST_PRIVATE_IMPORT);
    let run = evaluate(
        &policy(
            "test.identity.route-import",
            USE_SITE_SUBJECT,
            r#"(assert-route :id forwards :at "site" :role import_target
                          :to "site" :to-role import_target :via re_export)"#,
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
    let PolicyFindingEvidence::Assertion { evidence } = run.findings()[0].evidence() else {
        panic!("assertion evidence expected");
    };
    assert_eq!(evidence.assert_kind(), "route");
}

/// Forward resolution reaches the struct and inverse enumeration walks back
/// to the use site, so the round trip holds on the re-export fixture.
#[test]
fn round_trip_holds_for_the_reexport_site() {
    let (_project, analyzer) = rust_project(RUST_REEXPORT);
    let run = evaluate(
        &policy(
            "test.identity.round-trip",
            USE_SITE_SUBJECT,
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
        "the forward and inverse routes agree: {:?}",
        run.findings()
    );
}

/// A language whose adapter classifies no occurrences cannot join the subject
/// to any row, so the run is inconclusive — never a clean pass.
#[test]
fn an_unclaimed_language_is_inconclusive_not_clean() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "main.go",
            "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(1) }\n",
        )
        .build();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
    let run = evaluate(
        &policy(
            "test.identity.unclaimed",
            r#"(identifier :text/regex "^fmt$" :capture "site")"#,
            r#"(assert-canonical :id same :at "site" :role import_target
                          :equals "site2" :equals-role import_target)"#,
        ),
        &analyzer,
    );
    assert_ne!(
        run.completion(),
        &PolicyRunCompletion::Complete,
        "an unclaimed adapter must not read as a clean verdict"
    );
    assert!(run.findings().is_empty());
}
