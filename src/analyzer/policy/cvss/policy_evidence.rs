//! Closure of authored CVSS assertions and typed evaluation overlays.

use sha2::{Digest, Sha256};

use super::identity::update_field;
use super::reduction::{CvssFindingProjection, CvssReductionError};
use super::{CvssEvidenceBasis, CvssEvidenceContentHash, CvssMetricEvidence, PolicyOverlayScope};
use crate::analyzer::policy::definition::{
    AnyOrAll, CvssEvidencePredicate, CvssEvidenceScope, CvssMetric, CvssMetricRule, EndpointRef,
    PolicyAnalysisType, PolicyEvidenceRef, TaintSourceEvidence, TaintSystemEntry,
    TaintTrustBoundary,
};
use crate::analyzer::policy::evaluator::{
    CvssAnalystOverlayEvidence, CvssEnvironmentOverlayEvidence, CvssEvaluationOverlay,
    CvssThreatOverlayEvidence,
};
use crate::analyzer::policy::finding_identity::EvidenceRef;
use crate::analyzer::policy::future_evidence::TaintSourceProjectionFact;
use crate::analyzer::policy::resolved::{
    LoadedPolicy, ResolvedEndpointDependency, ResolvedEndpointIdentity,
};

const POLICY_EVIDENCE_DOMAIN: &[u8] = b"bifrost-cvss-policy-evidence/v1";
const POLICY_REDUCER: &str = "bifrost-policy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScopedMetricEvidence {
    pub(super) target_scope: PolicyOverlayScope,
    pub(super) evidence: CvssMetricEvidence,
}

pub(super) enum EvidenceCollection {
    Complete(Vec<ScopedMetricEvidence>),
    BudgetExceeded,
}

pub(super) fn collect_policy_assertions(
    policy: &LoadedPolicy,
    projection: CvssFindingProjection<'_>,
    charge: &mut impl FnMut() -> bool,
) -> Result<EvidenceCollection, CvssReductionError> {
    let Some(spec) = policy
        .definition()
        .classification
        .as_ref()
        .and_then(|classification| classification.cvss.as_ref())
    else {
        return Ok(EvidenceCollection::Complete(Vec::new()));
    };

    let mut evidence = Vec::new();
    for rule in &spec.metric_rules {
        if projection.taint_sources().is_empty() {
            let Some(matches) = evaluate_predicate(rule.when(), projection, None, charge) else {
                return Ok(EvidenceCollection::BudgetExceeded);
            };
            if !matches {
                continue;
            }
            if !charge() {
                return Ok(EvidenceCollection::BudgetExceeded);
            }
            evidence.push(ScopedMetricEvidence {
                target_scope: PolicyOverlayScope::Policy {
                    policy_id: policy.definition().metadata.id.clone(),
                },
                evidence: policy_assertion_record(policy, rule, None)?,
            });
            continue;
        }

        // A taint predicate is evaluated against one complete source fact at
        // a time. Its assertion is then attached only to scenarios belonging
        // to that same fact, preserving label/evidence/scenario correlation.
        for source in projection.taint_sources() {
            let Some(matches) = evaluate_predicate(rule.when(), projection, Some(source), charge)
            else {
                return Ok(EvidenceCollection::BudgetExceeded);
            };
            if !matches || source.source_scenario_ids.is_empty() {
                continue;
            }
            if !charge() {
                return Ok(EvidenceCollection::BudgetExceeded);
            }
            let record = policy_assertion_record(policy, rule, Some(source))?;
            for scenario in &source.source_scenario_ids {
                if !charge() {
                    return Ok(EvidenceCollection::BudgetExceeded);
                }
                evidence.push(ScopedMetricEvidence {
                    target_scope: PolicyOverlayScope::SourceScenario {
                        scenario_id: scenario.clone(),
                    },
                    evidence: record.clone(),
                });
            }
        }
    }
    sort_scoped_evidence(&mut evidence);
    Ok(EvidenceCollection::Complete(evidence))
}

fn policy_assertion_record(
    policy: &LoadedPolicy,
    rule: &CvssMetricRule,
    source: Option<&TaintSourceProjectionFact>,
) -> Result<CvssMetricEvidence, CvssReductionError> {
    let mut resolved_refs = resolve_evidence_refs(policy, rule.evidence_refs())?;
    if let Some(source) = source {
        resolved_refs.push(ResolvedEvidenceRef {
            report_ref: source.evidence_ref.clone(),
            semantic_hash: Some(*source.content_hash.as_bytes()),
        });
        normalize_resolved_refs(&mut resolved_refs)?;
    }
    let report_refs = resolved_refs
        .iter()
        .map(|reference| reference.report_ref.clone())
        .collect::<Vec<_>>();
    let content_hash = policy_assertion_hash(rule, &resolved_refs);
    let metric = CvssMetric::Base {
        metric: rule.metric(),
    };
    Ok(CvssMetricEvidence::try_new(
        metric,
        rule.value(),
        CvssEvidenceBasis::PolicyAssertion,
        report_refs,
        rule.rationale().to_string(),
        rule.assumptions().to_vec(),
        POLICY_REDUCER.to_string(),
        None,
        rule.scope(),
        content_hash,
    )?)
}

pub(super) fn collect_overlays(
    overlays: &[CvssEvaluationOverlay],
) -> Result<Vec<ScopedMetricEvidence>, CvssReductionError> {
    let mut records = Vec::with_capacity(overlays.len());
    for overlay in overlays {
        let (target_scope, record) = match overlay {
            CvssEvaluationOverlay::EnvironmentProfile { scope, evidence } => {
                (scope.clone(), environment_record(evidence)?)
            }
            CvssEvaluationOverlay::ThreatFeed { scope, evidence } => {
                (scope.clone(), threat_record(evidence)?)
            }
            CvssEvaluationOverlay::AnalystOverride { scope, evidence } => {
                (scope.clone(), analyst_record(evidence)?)
            }
        };
        records.push(ScopedMetricEvidence {
            target_scope,
            evidence: record,
        });
    }
    sort_scoped_evidence(&mut records);
    Ok(records)
}

fn environment_record(
    input: &CvssEnvironmentOverlayEvidence,
) -> Result<CvssMetricEvidence, CvssReductionError> {
    overlay_record(
        CvssMetric::EnvironmentalOrSupplemental {
            metric: input.metric(),
        },
        *input.value(),
        CvssEvidenceBasis::EnvironmentProfile,
        input.metadata(),
        input.content_hash(),
    )
}

fn threat_record(
    input: &CvssThreatOverlayEvidence,
) -> Result<CvssMetricEvidence, CvssReductionError> {
    overlay_record(
        CvssMetric::Threat {
            metric: input.metric(),
        },
        *input.value(),
        CvssEvidenceBasis::ThreatFeed,
        input.metadata(),
        input.content_hash(),
    )
}

fn analyst_record(
    input: &CvssAnalystOverlayEvidence,
) -> Result<CvssMetricEvidence, CvssReductionError> {
    overlay_record(
        input.metric(),
        *input.value(),
        CvssEvidenceBasis::AnalystOverride,
        input.metadata(),
        input.content_hash(),
    )
}

fn overlay_record(
    metric: CvssMetric,
    value: super::CvssMetricValue,
    basis: CvssEvidenceBasis,
    metadata: &crate::analyzer::policy::evaluator::CvssOverlayEvidenceMetadata,
    content_hash: CvssEvidenceContentHash,
) -> Result<CvssMetricEvidence, CvssReductionError> {
    Ok(CvssMetricEvidence::try_new(
        metric,
        value,
        basis,
        metadata.evidence_refs().to_vec(),
        metadata.rationale().to_string(),
        metadata.assumptions().to_vec(),
        metadata.assessor_or_tool().to_string(),
        Some(metadata.assessed_at().to_string()),
        metadata.system_scope(),
        content_hash,
    )?)
}

fn sort_scoped_evidence(records: &mut [ScopedMetricEvidence]) {
    records.sort_by(|left, right| {
        super::metric_rank(left.evidence.metric())
            .cmp(&super::metric_rank(right.evidence.metric()))
            .then_with(|| left.target_scope.cmp(&right.target_scope))
            .then_with(|| left.evidence.basis().cmp(&right.evidence.basis()))
            .then_with(|| {
                left.evidence
                    .value()
                    .first_label()
                    .cmp(right.evidence.value().first_label())
            })
            .then_with(|| {
                left.evidence
                    .content_hash()
                    .cmp(&right.evidence.content_hash())
            })
    });
}

fn evaluate_predicate<'a>(
    root: &CvssEvidencePredicate,
    projection: CvssFindingProjection<'a>,
    taint_source: Option<&'a TaintSourceProjectionFact>,
    charge: &mut impl FnMut() -> bool,
) -> Option<bool> {
    enum Frame<'a> {
        Enter(&'a CvssEvidencePredicate),
        Combine { all: bool, count: usize },
    }

    let mut frames = vec![Frame::Enter(root)];
    let mut values = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Enter(predicate) => {
                if !charge() {
                    return None;
                }
                match predicate {
                    CvssEvidencePredicate::All { predicates } => {
                        frames.push(Frame::Combine {
                            all: true,
                            count: predicates.len(),
                        });
                        frames.extend(predicates.iter().rev().map(Frame::Enter));
                    }
                    CvssEvidencePredicate::Any { predicates } => {
                        frames.push(Frame::Combine {
                            all: false,
                            count: predicates.len(),
                        });
                        frames.extend(predicates.iter().rev().map(Frame::Enter));
                    }
                    leaf => values.push(evaluate_leaf(leaf, projection, taint_source)),
                }
            }
            Frame::Combine { all, count } => {
                let start = values.len().checked_sub(count)?;
                let combined = if all {
                    values[start..].iter().all(|value| *value)
                } else {
                    values[start..].iter().any(|value| *value)
                };
                values.truncate(start);
                values.push(combined);
            }
        }
    }
    (values.len() == 1).then(|| values[0])
}

fn evaluate_leaf<'a>(
    predicate: &CvssEvidencePredicate,
    projection: CvssFindingProjection<'a>,
    taint_source: Option<&'a TaintSourceProjectionFact>,
) -> bool {
    match predicate {
        CvssEvidencePredicate::AnalysisType { analysis_type } => {
            projection.analysis_type() == *analysis_type
        }
        CvssEvidencePredicate::SourceEvidence { evidence } => projection
            .source_evidence(taint_source)
            .is_some_and(|actual| source_evidence_matches(actual, evidence)),
        CvssEvidencePredicate::SourceCategories { quantifier, values } => quantified_contains(
            projection.source_categories(taint_source),
            values,
            *quantifier,
        ),
        CvssEvidencePredicate::SinkCategories { quantifier, values } => {
            quantified_contains(projection.sink_categories(), values, *quantifier)
        }
        CvssEvidencePredicate::SourceLabels { quantifier, values } => {
            source_labels_match(projection, values, *quantifier)
        }
        CvssEvidencePredicate::SinkTags { quantifier, values } => {
            quantified_contains(projection.sink_tags(), values, *quantifier)
        }
        CvssEvidencePredicate::SinkImpacts { quantifier, values } => {
            quantified_contains(projection.sink_impacts(), values, *quantifier)
        }
        CvssEvidencePredicate::All { .. } | CvssEvidencePredicate::Any { .. } => false,
    }
}

fn source_labels_match(
    projection: CvssFindingProjection<'_>,
    expected: &[crate::analyzer::policy::definition::TaintLabel],
    quantifier: AnyOrAll,
) -> bool {
    let contains = |label: &crate::analyzer::policy::definition::TaintLabel| {
        projection
            .taint_sources()
            .iter()
            .any(|source| source.source_label == *label)
    };
    match quantifier {
        AnyOrAll::Any => expected.iter().any(contains),
        AnyOrAll::All => expected.iter().all(contains),
    }
}

fn quantified_contains<T: Eq>(haystack: &[T], needles: &[T], quantifier: AnyOrAll) -> bool {
    match quantifier {
        AnyOrAll::Any => needles.iter().any(|needle| haystack.contains(needle)),
        AnyOrAll::All => needles.iter().all(|needle| haystack.contains(needle)),
    }
}

fn source_evidence_matches(actual: &TaintSourceEvidence, expected: &TaintSourceEvidence) -> bool {
    expected
        .trust_boundary
        .is_none_or(|value| actual.trust_boundary == Some(value))
        && expected
            .system_entry
            .is_none_or(|value| actual.system_entry == Some(value))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedEvidenceRef {
    report_ref: EvidenceRef,
    semantic_hash: Option<[u8; 32]>,
}

fn resolve_evidence_refs(
    policy: &LoadedPolicy,
    references: &[PolicyEvidenceRef],
) -> Result<Vec<ResolvedEvidenceRef>, CvssReductionError> {
    let mut resolved = Vec::with_capacity(references.len());
    for reference in references {
        let value = match reference {
            PolicyEvidenceRef::PolicySelf => ResolvedEvidenceRef {
                report_ref: EvidenceRef::try_new(
                    "policy",
                    policy.definition().metadata.id.as_str(),
                )
                .map_err(|_| CvssReductionError::Invariant("invalid policy evidence ref"))?,
                semantic_hash: None,
            },
            PolicyEvidenceRef::Selector { path } => {
                let selector = policy
                    .resolved_selectors()
                    .binary_search_by(|selector| selector.path.cmp(path))
                    .ok()
                    .map(|index| &policy.resolved_selectors()[index])
                    .ok_or(CvssReductionError::Invariant(
                        "closed CVSS selector evidence ref is missing",
                    ))?;
                ResolvedEvidenceRef {
                    report_ref: EvidenceRef::try_new("selector", path.as_str()).map_err(|_| {
                        CvssReductionError::Invariant("invalid selector evidence ref")
                    })?,
                    semantic_hash: Some(*selector.semantic_hash.as_bytes()),
                }
            }
            PolicyEvidenceRef::Endpoint { endpoint } => {
                let dependency = resolve_endpoint(policy, endpoint).ok_or(
                    CvssReductionError::Invariant("closed CVSS endpoint evidence ref is missing"),
                )?;
                ResolvedEvidenceRef {
                    report_ref: EvidenceRef::try_new(
                        "endpoint",
                        resolved_endpoint_key(dependency.identity()),
                    )
                    .map_err(|_| CvssReductionError::Invariant("invalid endpoint evidence ref"))?,
                    semantic_hash: Some(*dependency.semantic_hash().as_bytes()),
                }
            }
        };
        resolved.push(value);
    }
    normalize_resolved_refs(&mut resolved)?;
    Ok(resolved)
}

fn normalize_resolved_refs(
    references: &mut Vec<ResolvedEvidenceRef>,
) -> Result<(), CvssReductionError> {
    references.sort_by(|left, right| {
        left.report_ref
            .cmp(&right.report_ref)
            .then_with(|| left.semantic_hash.cmp(&right.semantic_hash))
    });
    if references.windows(2).any(|pair| {
        pair[0].report_ref == pair[1].report_ref && pair[0].semantic_hash != pair[1].semantic_hash
    }) {
        return Err(CvssReductionError::Invariant(
            "one CVSS evidence reference resolved to different semantic facts",
        ));
    }
    references.dedup_by(|left, right| {
        left.report_ref == right.report_ref && left.semantic_hash == right.semantic_hash
    });
    Ok(())
}

fn resolve_endpoint<'a>(
    policy: &'a LoadedPolicy,
    reference: &EndpointRef,
) -> Option<&'a ResolvedEndpointDependency> {
    policy.endpoint_dependencies().iter().find(|dependency| {
        match (reference, dependency.identity()) {
            (
                EndpointRef::Local { entry_id },
                ResolvedEndpointIdentity::Local {
                    policy_id,
                    entry_id: actual,
                },
            ) => policy_id == &policy.definition().metadata.id && actual == entry_id,
            (
                EndpointRef::Catalog { catalog, entry_id },
                ResolvedEndpointIdentity::Catalog {
                    catalog: actual_catalog,
                    entry_id: actual_entry,
                },
            ) => {
                actual_entry == entry_id
                    && actual_catalog.name == catalog.name
                    && actual_catalog.version == catalog.version
                    && catalog
                        .sha256
                        .is_none_or(|hash| hash == actual_catalog.semantic_hash)
            }
            (
                EndpointRef::MatchEndpoint { endpoint_id },
                ResolvedEndpointIdentity::MatchEndpoint {
                    endpoint_id: actual,
                },
            ) => actual == endpoint_id,
            _ => false,
        }
    })
}

fn resolved_endpoint_key(identity: &ResolvedEndpointIdentity) -> String {
    match identity {
        ResolvedEndpointIdentity::Local {
            policy_id,
            entry_id,
        } => format!("local:{policy_id}:{entry_id}"),
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => format!(
            "catalog:{}@{}:{}:{entry_id}",
            catalog.name, catalog.version, catalog.semantic_hash
        ),
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => {
            format!("match:{endpoint_id}")
        }
    }
}

fn policy_assertion_hash(
    rule: &CvssMetricRule,
    references: &[ResolvedEvidenceRef],
) -> CvssEvidenceContentHash {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, POLICY_EVIDENCE_DOMAIN);
    update_field(&mut hasher, rule.metric().first_label().as_bytes());
    update_field(&mut hasher, rule.value().first_label().as_bytes());
    update_field(&mut hasher, b"policy-assertion");
    hash_system_scope(&mut hasher, rule.scope());
    update_field(&mut hasher, &predicate_hash(rule.when()));

    let mut semantic_hashes = references
        .iter()
        .filter_map(|reference| reference.semantic_hash)
        .collect::<Vec<_>>();
    semantic_hashes.sort_unstable();
    semantic_hashes.dedup();
    update_field(
        &mut hasher,
        &u64::try_from(semantic_hashes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for hash in semantic_hashes {
        update_field(&mut hasher, &hash);
    }
    update_field(&mut hasher, rule.rationale().as_bytes());
    let mut assumptions = rule
        .assumptions()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assumptions.sort_unstable();
    for assumption in assumptions {
        update_field(&mut hasher, assumption.as_bytes());
    }
    CvssEvidenceContentHash::from_bytes(hasher.finalize().into())
}

fn predicate_hash(predicate: &CvssEvidencePredicate) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match predicate {
        CvssEvidencePredicate::All { predicates } | CvssEvidencePredicate::Any { predicates } => {
            update_field(
                &mut hasher,
                if matches!(predicate, CvssEvidencePredicate::All { .. }) {
                    b"all"
                } else {
                    b"any"
                },
            );
            let mut children = predicates.iter().map(predicate_hash).collect::<Vec<_>>();
            children.sort_unstable();
            for child in children {
                update_field(&mut hasher, &child);
            }
        }
        CvssEvidencePredicate::AnalysisType { analysis_type } => {
            update_field(&mut hasher, b"analysis-type");
            update_field(&mut hasher, analysis_type_label(*analysis_type));
        }
        CvssEvidencePredicate::SourceEvidence { evidence } => {
            update_field(&mut hasher, b"source-evidence");
            if let Some(value) = evidence.trust_boundary {
                update_field(&mut hasher, trust_boundary_label(value));
            }
            if let Some(value) = evidence.system_entry {
                update_field(&mut hasher, system_entry_label(value));
            }
        }
        CvssEvidencePredicate::SourceCategories { quantifier, values }
        | CvssEvidencePredicate::SinkCategories { quantifier, values } => {
            update_field(
                &mut hasher,
                if matches!(predicate, CvssEvidencePredicate::SourceCategories { .. }) {
                    b"source-categories"
                } else {
                    b"sink-categories"
                },
            );
            hash_string_values(
                &mut hasher,
                *quantifier,
                values.iter().map(|value| value.as_str()),
            );
        }
        CvssEvidencePredicate::SourceLabels { quantifier, values } => {
            update_field(&mut hasher, b"source-labels");
            hash_string_values(
                &mut hasher,
                *quantifier,
                values.iter().map(|value| value.as_str()),
            );
        }
        CvssEvidencePredicate::SinkTags { quantifier, values } => {
            update_field(&mut hasher, b"sink-tags");
            hash_string_values(
                &mut hasher,
                *quantifier,
                values.iter().map(|value| value.as_str()),
            );
        }
        CvssEvidencePredicate::SinkImpacts { quantifier, values } => {
            update_field(&mut hasher, b"sink-impacts");
            hash_string_values(
                &mut hasher,
                *quantifier,
                values.iter().map(|value| value.as_str()),
            );
        }
    }
    hasher.finalize().into()
}

fn hash_string_values<'a>(
    hasher: &mut Sha256,
    quantifier: AnyOrAll,
    values: impl Iterator<Item = &'a str>,
) {
    update_field(
        hasher,
        match quantifier {
            AnyOrAll::Any => b"any",
            AnyOrAll::All => b"all",
        },
    );
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    for value in values {
        update_field(hasher, value.as_bytes());
    }
}

fn hash_system_scope(hasher: &mut Sha256, scope: CvssEvidenceScope) {
    match scope {
        CvssEvidenceScope::Global => update_field(hasher, b"global"),
        CvssEvidenceScope::System { system } => {
            update_field(hasher, b"system");
            update_field(
                hasher,
                match system {
                    super::CvssSystemScope::VulnerableSystem => b"vulnerable-system",
                    super::CvssSystemScope::SubsequentSystem => b"subsequent-system",
                },
            );
        }
    }
}

const fn analysis_type_label(value: PolicyAnalysisType) -> &'static [u8] {
    match value {
        PolicyAnalysisType::Match => b"match",
        PolicyAnalysisType::Taint => b"taint",
        PolicyAnalysisType::Typestate => b"typestate",
    }
}

const fn trust_boundary_label(value: TaintTrustBoundary) -> &'static [u8] {
    match value {
        TaintTrustBoundary::External => b"external",
        TaintTrustBoundary::Internal => b"internal",
        TaintTrustBoundary::SameTrustZone => b"same-trust-zone",
    }
}

const fn system_entry_label(value: TaintSystemEntry) -> &'static [u8] {
    match value {
        TaintSystemEntry::VulnerableSystemNetworkStack => b"vulnerable-system-network-stack",
        TaintSystemEntry::DownloadedArtifact => b"downloaded-artifact",
        TaintSystemEntry::LocalInput => b"local-input",
        TaintSystemEntry::AdjacentNetwork => b"adjacent-network",
        TaintSystemEntry::Physical => b"physical",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analyzer::policy::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
    use crate::analyzer::policy::definition::{
        CvssBaseMetric, CvssMetricValue, CvssMetricValueToken, CvssSystemScope, PolicyCvssBasis,
        TaintLabel,
    };
    use crate::analyzer::policy::finding_identity::{OpaqueFindingKey, SourceScenarioId};
    use crate::analyzer::policy::future_evidence::{
        TaintFindingAnchor, TaintPolicyProjectionFacts, TaintSourceProjectionFact,
    };
    use crate::analyzer::policy::registry::{PolicyRegistry, PolicyRegistryLimits};
    use crate::analyzer::policy::resolved::{ResolvedTaintEndpoint, ResolvedTaintSourceDefinition};
    use crate::analyzer::policy::source::PolicySourceIdentity;

    fn av_rule() -> CvssMetricRule {
        let metric = CvssBaseMetric::Av;
        CvssMetricRule::try_new(
            metric,
            CvssMetricValue::try_new(CvssMetric::Base { metric }, CvssMetricValueToken::N).unwrap(),
            CvssEvidencePredicate::AnalysisType {
                analysis_type: PolicyAnalysisType::Taint,
            },
            PolicyCvssBasis::PolicyAssertion,
            CvssEvidenceScope::System {
                system: CvssSystemScope::VulnerableSystem,
            },
            vec![PolicyEvidenceRef::PolicySelf],
            "Network-reachable taint source".to_string(),
            Vec::new(),
        )
        .unwrap()
    }

    fn pair_policy_source() -> &'static str {
        r#"(policy
          :id "test.cvss-pair"
          :name "CVSS pair"
          :message (generated-message :relation can-reach)
          :severity (cvss-severity :when-unscored warning)
          :analysis (analysis
            :type taint
            :mode may
            :sources (endpoint-set :entries [
              (source
                :id request
                :display-name "request input"
                :categories [input.user]
                :selector (rql (name "request"))
                :bind return-value
                :labels [alpha beta]
                :evidence (evidence :trust-boundary external :system-entry local-input))])
            :sinks (endpoint-set :entries [
              (sink
                :id store
                :display-name "sensitive store"
                :categories [data.sensitive]
                :selector (rql (name "store"))
                :dangerous-operand matched-value
                :accepts [alpha beta])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Bifrost" :id "PAIR")
            :cvss (cvss
              :version "4.0"
              :emit when-base-complete
              :metric-rules [
                (metric
                  :name AV
                  :value N
                  :when (all [
                    (source-labels :all [alpha beta])
                    (source-evidence :trust-boundary external)])
                  :basis policy-assertion
                  :scope vulnerable-system
                  :evidence-refs [policy:self]
                  :rationale "alpha source")
                (metric
                  :name AV
                  :value A
                  :when (all [
                    (source-labels :all [alpha beta])
                    (source-evidence :trust-boundary internal)])
                  :basis policy-assertion
                  :scope vulnerable-system
                  :evidence-refs [policy:self]
                  :rationale "beta source")])))"#
    }

    fn source_fact(
        source: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
        label: &str,
        scenario: &str,
    ) -> TaintSourceProjectionFact {
        TaintSourceProjectionFact::try_new(
            source.identity.clone(),
            source.semantic_hash,
            source.analysis_projection_hash,
            source.definition.display_name.clone(),
            source.definition.categories.clone(),
            TaintLabel::new(label).unwrap(),
            Some(TaintSourceEvidence {
                trust_boundary: Some(if label == "alpha" {
                    TaintTrustBoundary::External
                } else {
                    TaintTrustBoundary::Internal
                }),
                system_entry: source
                    .definition
                    .evidence
                    .as_ref()
                    .and_then(|value| value.system_entry),
            }),
            vec![SourceScenarioId::try_new("test", scenario).unwrap()],
            EvidenceRef::try_new("test-source", scenario).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn source_evidence_fields_must_match_one_record() {
        let expected = TaintSourceEvidence {
            trust_boundary: Some(TaintTrustBoundary::External),
            system_entry: Some(TaintSystemEntry::VulnerableSystemNetworkStack),
        };
        let only_boundary = TaintSourceEvidence {
            trust_boundary: Some(TaintTrustBoundary::External),
            system_entry: Some(TaintSystemEntry::DownloadedArtifact),
        };
        let only_entry = TaintSourceEvidence {
            trust_boundary: Some(TaintTrustBoundary::Internal),
            system_entry: Some(TaintSystemEntry::VulnerableSystemNetworkStack),
        };
        assert!(!source_evidence_matches(&only_boundary, &expected));
        assert!(!source_evidence_matches(&only_entry, &expected));
        assert!(source_evidence_matches(&expected, &expected));
    }

    #[test]
    fn policy_assertion_hash_binds_the_exact_static_source_fact() {
        let authored = ResolvedEvidenceRef {
            report_ref: EvidenceRef::try_new("policy", "bifrost.test.cvss").unwrap(),
            semantic_hash: None,
        };
        let source_ref = EvidenceRef::try_new("taint-source", "request-body").unwrap();
        let references = |source_hash, report_ref| {
            vec![
                ResolvedEvidenceRef {
                    report_ref,
                    semantic_hash: Some(source_hash),
                },
                authored.clone(),
            ]
        };

        let one = policy_assertion_hash(&av_rule(), &references([1; 32], source_ref.clone()));
        let same_semantics_different_display_ref = policy_assertion_hash(
            &av_rule(),
            &references(
                [1; 32],
                EvidenceRef::try_new("taint-source", "renamed-display-ref").unwrap(),
            ),
        );
        let different_source = policy_assertion_hash(&av_rule(), &references([2; 32], source_ref));

        assert_eq!(one, same_semantics_different_display_ref);
        assert_ne!(one, different_source);
    }

    #[test]
    fn authored_and_source_reference_collision_fails_closed() {
        let report_ref = EvidenceRef::try_new("policy", "bifrost.test.cvss").unwrap();
        let mut references = vec![
            ResolvedEvidenceRef {
                report_ref: report_ref.clone(),
                semantic_hash: None,
            },
            ResolvedEvidenceRef {
                report_ref,
                semantic_hash: Some([7; 32]),
            },
        ];

        assert!(matches!(
            normalize_resolved_refs(&mut references),
            Err(CvssReductionError::Invariant(
                "one CVSS evidence reference resolved to different semantic facts"
            ))
        ));
    }

    #[test]
    fn pair_facts_keep_predicates_hashes_and_scenarios_correlated() {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:cvss-pair"),
                pair_policy_source().as_bytes(),
            )
            .unwrap();
        let policy = registry.policies().next().unwrap();
        let spec = policy.resolved_taint().unwrap();
        let facts = vec![
            source_fact(&spec.sources[0], "alpha", "scenario-alpha"),
            source_fact(&spec.sources[0], "beta", "scenario-beta"),
        ];
        let sink = &spec.sinks[0];
        let projection = TaintPolicyProjectionFacts::try_new(
            sink.identity.clone(),
            sink.semantic_hash,
            sink.analysis_projection_hash,
            sink.definition.display_name.clone(),
            sink.definition.categories.clone(),
            sink.definition.tags.clone(),
            sink.definition.impacts.clone(),
            vec![
                TaintLabel::new("alpha").unwrap(),
                TaintLabel::new("beta").unwrap(),
            ],
            facts,
            &crate::analyzer::policy::budget::PolicyBudget::default(),
        )
        .unwrap();
        let anchor = TaintFindingAnchor::weak(OpaqueFindingKey::try_new("test", "pair").unwrap());
        let finding = CvssFindingProjection::Taint {
            anchor: &anchor,
            projection: &projection,
            sources: &projection.source_facts,
        };

        let aggregate_labels = CvssEvidencePredicate::SourceLabels {
            quantifier: AnyOrAll::All,
            values: vec![
                TaintLabel::new("alpha").unwrap(),
                TaintLabel::new("beta").unwrap(),
            ],
        };
        for fact in &projection.source_facts {
            assert_eq!(
                evaluate_predicate(&aggregate_labels, finding, Some(fact), &mut || true),
                Some(true)
            );
        }

        let records = match collect_policy_assertions(policy, finding, &mut || true).unwrap() {
            EvidenceCollection::Complete(records) => records,
            EvidenceCollection::BudgetExceeded => panic!("unbounded test charge must not exhaust"),
        };
        assert_eq!(records.len(), 2);
        let selected = records
            .iter()
            .map(|record| {
                let PolicyOverlayScope::SourceScenario { scenario_id } = &record.target_scope
                else {
                    panic!("taint policy assertions must be scenario-scoped");
                };
                (
                    scenario_id.as_str(),
                    record.evidence.value().first_label(),
                    record.evidence.content_hash(),
                    record.evidence.evidence_refs().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(selected[0].0, "test:scenario-alpha");
        assert_eq!(selected[0].1, "N");
        assert_eq!(selected[1].0, "test:scenario-beta");
        assert_eq!(selected[1].1, "A");
        assert_ne!(selected[0].2, selected[1].2);
        assert!(
            selected[0]
                .3
                .contains(&projection.source_facts[0].evidence_ref)
        );
        assert!(
            selected[1]
                .3
                .contains(&projection.source_facts[1].evidence_ref)
        );
    }
}
