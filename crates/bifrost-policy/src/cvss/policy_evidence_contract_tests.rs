use std::sync::Arc;

use super::*;
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::definition::{
    CvssBaseMetric, CvssMetricValueToken, PolicyAnalysisType, PolicyCvssBasis,
};
use crate::finding_identity::{MatchFindingAnchor, MatchResultDomain, OpaqueFindingKey};
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::source::PolicySourceIdentity;

fn loaded_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:cvss-evidence"),
            source.as_bytes(),
        )
        .unwrap();
    registry
}

fn match_policy(selector: &str) -> String {
    format!(
        r#"(policy :id "test.evidence" :name "Evidence" :message "M" :severity warning
      :analysis (analysis :type match :selector (rql (call :callee (name "{selector}"))))
      :classification (classification :fallback (classification-id :taxonomy "test" :id "fallback")))"#
    )
}

fn rule(
    value: CvssMetricValueToken,
    when: CvssEvidencePredicate,
    assumptions: &[&str],
) -> CvssMetricRule {
    let metric = CvssBaseMetric::Av;
    CvssMetricRule::try_new(
        metric,
        super::super::CvssMetricValue::try_new(CvssMetric::Base { metric }, value).unwrap(),
        when,
        PolicyCvssBasis::PolicyAssertion,
        metric.required_scope(),
        vec![PolicyEvidenceRef::PolicySelf],
        "Observed evidence".to_string(),
        assumptions.iter().map(|s| (*s).to_string()).collect(),
    )
    .unwrap()
}

fn identity(policy: &LoadedPolicy, rule: &CvssMetricRule) -> CvssEvidenceContentHash {
    policy_assertion_record(policy, rule, None)
        .unwrap()
        .content_hash()
}

fn match_predicate() -> CvssEvidencePredicate {
    CvssEvidencePredicate::AnalysisType {
        analysis_type: PolicyAnalysisType::Match,
    }
}

#[test]
fn assertion_identity_distinguishes_value_and_all_assumptions() {
    let registry = loaded_policy(&match_policy("call"));
    let policy = registry.policies().next().unwrap();
    let original = rule(
        CvssMetricValueToken::N,
        match_predicate(),
        &["first", "second"],
    );
    let other_value = rule(
        CvssMetricValueToken::A,
        match_predicate(),
        &["first", "second"],
    );
    let other_assumption = rule(
        CvssMetricValueToken::N,
        match_predicate(),
        &["first", "third"],
    );
    assert_ne!(identity(policy, &original), identity(policy, &other_value));
    assert_ne!(
        identity(policy, &original),
        identity(policy, &other_assumption)
    );
}

#[test]
fn assertion_identity_distinguishes_predicate_quantifiers() {
    let registry = loaded_policy(&match_policy("call"));
    let policy = registry.policies().next().unwrap();
    let child = match_predicate();
    let any = rule(
        CvssMetricValueToken::N,
        CvssEvidencePredicate::Any {
            predicates: vec![child.clone()],
        },
        &[],
    );
    let all = rule(
        CvssMetricValueToken::N,
        CvssEvidencePredicate::All {
            predicates: vec![child],
        },
        &[],
    );
    assert_ne!(identity(policy, &any), identity(policy, &all));
}

#[test]
fn assertion_identity_distinguishes_string_membership_quantifiers() {
    let registry = loaded_policy(&match_policy("call"));
    let policy = registry.policies().next().unwrap();
    let values = vec![crate::definition::PolicyCategoryId::new("input.user").unwrap()];
    let any = rule(
        CvssMetricValueToken::N,
        CvssEvidencePredicate::SinkCategories {
            quantifier: AnyOrAll::Any,
            values: values.clone(),
        },
        &[],
    );
    let all = rule(
        CvssMetricValueToken::N,
        CvssEvidencePredicate::SinkCategories {
            quantifier: AnyOrAll::All,
            values,
        },
        &[],
    );
    assert_ne!(identity(policy, &any), identity(policy, &all));
}

#[test]
fn selector_semantics_change_assertion_identity() {
    let first = loaded_policy(&match_policy("read"));
    let second = loaded_policy(&match_policy("write"));
    let rule = CvssMetricRule::try_new(
        CvssBaseMetric::Av,
        super::super::CvssMetricValue::try_new(
            CvssMetric::Base {
                metric: CvssBaseMetric::Av,
            },
            CvssMetricValueToken::N,
        )
        .unwrap(),
        match_predicate(),
        PolicyCvssBasis::PolicyAssertion,
        CvssBaseMetric::Av.required_scope(),
        vec![PolicyEvidenceRef::Selector {
            path: crate::definition::PolicySelectorPath::new("/analysis/selector").unwrap(),
        }],
        "Observed evidence".to_string(),
        Vec::new(),
    )
    .unwrap();
    let left = identity(first.policies().next().unwrap(), &rule);
    let right = identity(second.policies().next().unwrap(), &rule);
    assert_ne!(left, right);
}

#[test]
fn match_policy_assertion_reaches_collection() {
    let source = r#"(policy :id "test.evidence" :name "Evidence" :message "M" :severity warning
      :analysis (analysis :type match :selector (rql (call)))
      :classification (classification :fallback (classification-id :taxonomy "test" :id "fallback")
        :cvss (cvss :version "4.0" :emit when-base-complete :metric-rules [
          (metric :name AV :value N :when (analysis-type :is match) :basis policy-assertion
            :scope vulnerable-system :evidence-refs [policy:self] :rationale "Network")])) )"#;
    let registry = loaded_policy(source);
    let policy = registry.policies().next().unwrap();
    let anchor = MatchFindingAnchor::weak(
        MatchResultDomain::File,
        brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new("src/lib.rs")
            .unwrap(),
        OpaqueFindingKey::try_new("test", "finding").unwrap(),
    );
    let records = collect_policy_assertions(
        policy,
        CvssFindingProjection::Match { anchor: &anchor },
        &mut || true,
    )
    .unwrap();
    assert!(matches!(records, EvidenceCollection::Complete(records) if records.len() == 1));
}

fn taint_policy(predicate: &str) -> String {
    format!(
        r#"(policy
      :id "test.taint-evidence" :name "Taint evidence"
      :message (generated-message :relation can-reach)
      :severity (cvss-severity :when-unscored warning)
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [(source :id request :display-name "request"
          :categories [input.user] :selector (rql (name "request"))
          :bind return-value :labels [alpha]
          :evidence (evidence :trust-boundary external :system-entry local-input))])
        :sinks (endpoint-set :entries [(sink :id store :display-name "store"
          :categories [data.sensitive] :selector (rql (name "store"))
          :dangerous-operand matched-value :accepts [alpha] :tags [internet])]))
      :classification (classification :fallback (classification-id :taxonomy "test" :id "TAINT")
        :cvss (cvss :version "4.0" :emit when-base-complete :metric-rules [
          (metric :name AV :value N :when {predicate} :basis policy-assertion
            :scope vulnerable-system :evidence-refs [policy:self] :rationale "Evidence")])) )"#
    )
}

fn taint_evidence_count(predicate: &str) -> usize {
    use crate::definition::{
        TaintLabel, TaintSourceEvidence, TaintSystemEntry, TaintTrustBoundary,
    };
    use crate::finding_identity::{EvidenceRef, SourceScenarioId};
    use crate::future_evidence::{TaintFindingAnchor, TaintPolicyProjectionFacts};

    let registry = loaded_policy(&taint_policy(predicate));
    let policy = registry.policies().next().unwrap();
    let spec = policy.resolved_taint().unwrap();
    let source = &spec.sources[0];
    let sink = &spec.sinks[0];
    let fact = crate::test_support::taint_source_projection_fact(
        source.identity.clone(),
        source.semantic_hash,
        source.analysis_projection_hash,
        source.definition.display_name.clone(),
        source.definition.categories.clone(),
        TaintLabel::new("alpha").unwrap(),
        Some(TaintSourceEvidence {
            trust_boundary: Some(TaintTrustBoundary::External),
            system_entry: Some(TaintSystemEntry::LocalInput),
        }),
        vec![SourceScenarioId::try_new("test", "request").unwrap()],
        EvidenceRef::try_new("test-source", "request").unwrap(),
    );
    let projection = TaintPolicyProjectionFacts::try_new(
        sink.identity.clone(),
        sink.semantic_hash,
        sink.analysis_projection_hash,
        sink.definition.display_name.clone(),
        sink.definition.categories.clone(),
        sink.definition.tags.clone(),
        sink.definition.impacts.clone(),
        vec![TaintLabel::new("alpha").unwrap()],
        vec![fact],
        &crate::budget::PolicyBudget::default(),
    )
    .unwrap();
    let anchor = TaintFindingAnchor::weak(OpaqueFindingKey::try_new("test", "taint").unwrap());
    let finding = CvssFindingProjection::Taint {
        anchor: &anchor,
        projection: &projection,
        sources: &projection.source_facts,
    };
    match collect_policy_assertions(policy, finding, &mut || true).unwrap() {
        EvidenceCollection::Complete(records) => records.len(),
        EvidenceCollection::BudgetExceeded => panic!("unbounded charge exhausted"),
    }
}

#[test]
fn any_sink_tag_applies_when_one_tag_matches() {
    assert_eq!(
        taint_evidence_count("(sink-tags :any [internet internal])"),
        1
    );
    assert_eq!(
        taint_evidence_count("(sink-tags :all [internet internal])"),
        0
    );
}

#[test]
fn source_entry_predicate_does_not_require_trust_boundary() {
    assert_eq!(
        taint_evidence_count("(source-evidence :system-entry local-input)"),
        1
    );
    assert_eq!(
        taint_evidence_count("(source-evidence :system-entry physical)"),
        0
    );
}

#[test]
fn source_label_quantifiers_check_the_complete_expected_set() {
    assert_eq!(taint_evidence_count("(source-labels :all [alpha beta])"), 0);
    assert_eq!(taint_evidence_count("(source-labels :any [alpha beta])"), 1);
}
