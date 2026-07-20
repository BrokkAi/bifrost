//! Bounded, order-independent CVSS evidence reduction.

use std::cmp::Ordering;
use std::fmt;

use super::identity::evidence_set_hash;
use super::policy_evidence::{
    EvidenceCollection, ScopedMetricEvidence, collect_overlays, collect_policy_assertions,
};
use super::vector::score_metrics;
use super::{
    CvssAssessment, CvssAssessmentProvenance, CvssAssessmentSet, CvssAssessmentVariant,
    CvssBaseMetric, CvssEvidenceBasis, CvssMetric, CvssMetricEvidence, CvssUnscoredReason,
    CvssValidationError, CvssVersion, PolicyOverlayScope, SourceScenarioSetHash,
    VulnerabilityIdentity, metric_rank,
};
use crate::analyzer::policy::budget::PolicyBudget;
use crate::analyzer::policy::definition::{
    PolicyAnalysisType, PolicyCategoryId, TaintImpact, TaintSourceEvidence, TaintTag,
};
use crate::analyzer::policy::evaluator::CvssEvaluationOverlay;
use crate::analyzer::policy::finding::PolicyIncompleteReason;
use crate::analyzer::policy::finding_identity::{
    EvidenceRef, MatchFindingAnchor, PolicyFindingId, SourceScenarioId,
};
use crate::analyzer::policy::future_evidence::{
    TaintFindingAnchor, TaintPolicyProjectionFacts, TaintSourceProjectionFact,
    TypestateFindingAnchor, TypestatePolicyProjectionFacts, empty_source_scenario_set_hash,
    taint_vulnerability_digest, typestate_vulnerability_digest,
};
use crate::analyzer::policy::resolved::LoadedPolicy;
use crate::analyzer::policy::retained::RetainedSize;

const REDUCER_ID: &str = "bifrost.cvss.reducer.v1";

const BASE_METRICS: [CvssBaseMetric; 11] = [
    CvssBaseMetric::Av,
    CvssBaseMetric::Ac,
    CvssBaseMetric::At,
    CvssBaseMetric::Pr,
    CvssBaseMetric::Ui,
    CvssBaseMetric::Vc,
    CvssBaseMetric::Vi,
    CvssBaseMetric::Va,
    CvssBaseMetric::Sc,
    CvssBaseMetric::Si,
    CvssBaseMetric::Sa,
];

#[derive(Debug, Clone, Copy)]
pub(crate) enum CvssFindingProjection<'a> {
    Match {
        anchor: &'a MatchFindingAnchor,
    },
    Taint {
        anchor: &'a TaintFindingAnchor,
        projection: &'a TaintPolicyProjectionFacts,
        sources: &'a [TaintSourceProjectionFact],
    },
    Typestate {
        anchor: &'a TypestateFindingAnchor,
        projection: &'a TypestatePolicyProjectionFacts,
    },
}

impl<'a> CvssFindingProjection<'a> {
    pub(super) const fn analysis_type(self) -> PolicyAnalysisType {
        match self {
            Self::Match { .. } => PolicyAnalysisType::Match,
            Self::Taint { .. } => PolicyAnalysisType::Taint,
            Self::Typestate { .. } => PolicyAnalysisType::Typestate,
        }
    }

    pub(super) fn source_categories(
        self,
        taint_source: Option<&'a TaintSourceProjectionFact>,
    ) -> &'a [PolicyCategoryId] {
        match (self, taint_source) {
            (Self::Match { .. }, _) => &[],
            (Self::Taint { .. }, Some(source)) => &source.source_categories,
            (Self::Taint { .. }, None) => &[],
            (Self::Typestate { projection, .. }, _) => &projection.source_categories,
        }
    }

    pub(super) fn sink_categories(self) -> &'a [PolicyCategoryId] {
        match self {
            Self::Taint { projection, .. } => &projection.sink_categories,
            Self::Match { .. } | Self::Typestate { .. } => &[],
        }
    }

    pub(super) fn source_evidence(
        self,
        taint_source: Option<&'a TaintSourceProjectionFact>,
    ) -> Option<&'a TaintSourceEvidence> {
        match (self, taint_source) {
            (Self::Taint { .. }, Some(source)) => source.source_evidence.as_ref(),
            (Self::Match { .. } | Self::Typestate { .. }, _) | (Self::Taint { .. }, None) => None,
        }
    }

    pub(super) fn sink_tags(self) -> &'a [TaintTag] {
        match self {
            Self::Taint { projection, .. } => &projection.sink_tags,
            Self::Match { .. } | Self::Typestate { .. } => &[],
        }
    }

    pub(super) fn sink_impacts(self) -> &'a [TaintImpact] {
        match self {
            Self::Taint { projection, .. } => &projection.sink_impacts,
            Self::Match { .. } | Self::Typestate { .. } => &[],
        }
    }

    pub(super) fn taint_sources(self) -> &'a [TaintSourceProjectionFact] {
        match self {
            Self::Taint { sources, .. } => sources,
            Self::Match { .. } | Self::Typestate { .. } => &[],
        }
    }

    fn source_scenarios(self) -> Vec<SourceScenarioId> {
        let mut scenarios = self
            .taint_sources()
            .iter()
            .flat_map(|source| source.source_scenario_ids.iter().cloned())
            .collect::<Vec<_>>();
        scenarios.sort();
        scenarios.dedup();
        scenarios
    }

    fn source_scenario_set_hash(
        self,
        scenarios: &[SourceScenarioId],
    ) -> Result<SourceScenarioSetHash, CvssReductionError> {
        // Match and typestate do not have taint source scenarios. Keep their
        // grouping identity explicit instead of deriving it through the taint
        // validation path, while retaining the same domain-separated empty
        // set identity used by the public report boundary.
        if matches!(self, Self::Match { .. } | Self::Typestate { .. }) {
            if !scenarios.is_empty() {
                return Err(CvssReductionError::Invariant(
                    "non-taint CVSS projection contains taint source scenarios",
                ));
            }
            return Ok(empty_source_scenario_set_hash());
        }

        let hash = SourceScenarioSetHash::try_from_scenarios(scenarios.to_vec())
            .map_err(|_| CvssReductionError::Invariant("invalid pair-local source scenario set"))?;
        if let Self::Taint { anchor, .. } = self
            && let Some(strong) = anchor.strong_fields()
            && strong.source_scenario_set_hash() != hash
        {
            return Err(CvssReductionError::Invariant(
                "CVSS pair scenario set does not match its strong taint anchor",
            ));
        }
        Ok(hash)
    }
}

#[derive(Debug)]
pub(crate) struct CvssReductionOutcome {
    pub(crate) assessment: Option<CvssAssessmentSet>,
    pub(crate) incomplete_reason: Option<PolicyIncompleteReason>,
    pub(crate) evidence_refs_truncated: bool,
    pub(crate) omitted_evidence_refs_lower_bound: u64,
    pub(crate) omitted_evidence_refs: Vec<EvidenceRef>,
}

#[derive(Debug)]
pub(crate) enum CvssReductionError {
    Invariant(&'static str),
    InvalidAssessment(CvssValidationError),
}

impl fmt::Display for CvssReductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invariant(message) => formatter.write_str(message),
            Self::InvalidAssessment(error) => write!(formatter, "invalid CVSS assessment: {error}"),
        }
    }
}

impl std::error::Error for CvssReductionError {}

impl From<CvssValidationError> for CvssReductionError {
    fn from(value: CvssValidationError) -> Self {
        Self::InvalidAssessment(value)
    }
}

pub(crate) fn reduce_cvss_for_finding(
    policy: &LoadedPolicy,
    projection: CvssFindingProjection<'_>,
    overlays: &[CvssEvaluationOverlay],
    preexisting_evidence_refs: &[EvidenceRef],
    allowed_source_scenario_display: &[SourceScenarioId],
    max_cvss_retained_bytes: usize,
    budget: &PolicyBudget,
) -> Result<CvssReductionOutcome, CvssReductionError> {
    let Some(spec) = policy
        .definition()
        .classification
        .as_ref()
        .and_then(|classification| classification.cvss.as_ref())
    else {
        return Ok(CvssReductionOutcome {
            assessment: None,
            incomplete_reason: None,
            evidence_refs_truncated: false,
            omitted_evidence_refs_lower_bound: 0,
            omitted_evidence_refs: Vec::new(),
        });
    };
    if spec.version != CvssVersion::V4_0 {
        return Err(CvssReductionError::Invariant(
            "loaded policy contains an unsupported CVSS version",
        ));
    }
    validate_projection_pair(projection)?;

    let policy_id = &policy.definition().metadata.id;
    let finding_id = finding_id(policy_id, projection);
    let vulnerability = vulnerability_identity(projection);
    let source_scenarios = projection.source_scenarios();
    let scenario_set_hash = projection.source_scenario_set_hash(&source_scenarios)?;

    if overlays.len() > budget.max_cvss_overlays() {
        return budget_outcome(
            vulnerability,
            &source_scenarios,
            scenario_set_hash,
            allowed_source_scenario_display,
            max_cvss_retained_bytes,
            budget,
        );
    }

    let mut meter = ReductionMeter::new(budget.max_cvss_reduction_steps());
    let authored = match collect_policy_assertions(policy, projection, &mut || meter.charge())? {
        EvidenceCollection::Complete(evidence) => evidence,
        EvidenceCollection::BudgetExceeded => {
            return budget_outcome(
                vulnerability,
                &source_scenarios,
                scenario_set_hash,
                allowed_source_scenario_display,
                max_cvss_retained_bytes,
                budget,
            );
        }
    };
    let runtime = collect_overlays(overlays)?;
    let mut evidence = authored;
    evidence.extend(runtime);
    evidence.sort_by(compare_scoped_evidence);

    let mut groups = Vec::<OutcomeGroup>::new();
    if source_scenarios.is_empty() {
        let Some(outcome) = reduce_scenario(&evidence, policy_id, finding_id, None, &mut meter)
        else {
            return budget_outcome(
                vulnerability,
                &[],
                scenario_set_hash,
                allowed_source_scenario_display,
                max_cvss_retained_bytes,
                budget,
            );
        };
        if !push_outcome_group(&mut groups, outcome, None, &mut meter, budget) {
            return budget_outcome(
                vulnerability,
                &[],
                scenario_set_hash,
                allowed_source_scenario_display,
                max_cvss_retained_bytes,
                budget,
            );
        }
    } else {
        for scenario in &source_scenarios {
            let Some(outcome) =
                reduce_scenario(&evidence, policy_id, finding_id, Some(scenario), &mut meter)
            else {
                return budget_outcome(
                    vulnerability,
                    &source_scenarios,
                    scenario_set_hash,
                    allowed_source_scenario_display,
                    max_cvss_retained_bytes,
                    budget,
                );
            };
            if !push_outcome_group(&mut groups, outcome, Some(scenario), &mut meter, budget) {
                return budget_outcome(
                    vulnerability,
                    &source_scenarios,
                    scenario_set_hash,
                    allowed_source_scenario_display,
                    max_cvss_retained_bytes,
                    budget,
                );
            }
        }
    }

    if groups.len() > budget.max_cvss_variants_per_finding() {
        return budget_outcome(
            vulnerability,
            &source_scenarios,
            scenario_set_hash,
            allowed_source_scenario_display,
            max_cvss_retained_bytes,
            budget,
        );
    }

    if !evidence_records_fit_budget(&groups, budget) {
        return budget_outcome(
            vulnerability,
            &source_scenarios,
            scenario_set_hash,
            allowed_source_scenario_display,
            max_cvss_retained_bytes,
            budget,
        );
    }

    let evidence_ref_retention =
        EvidenceRefRetention::for_groups(&groups, preexisting_evidence_refs, budget)?;
    let mut variants = Vec::with_capacity(groups.len());
    for group in groups {
        if !meter.charge() {
            return budget_outcome(
                vulnerability,
                &source_scenarios,
                scenario_set_hash,
                allowed_source_scenario_display,
                max_cvss_retained_bytes,
                budget,
            );
        }
        variants.push(seal_group(
            vulnerability,
            scenario_set_hash,
            group,
            &evidence_ref_retention.retained,
        )?);
    }

    let assessment = retain_source_scenario_display(
        variants,
        allowed_source_scenario_display,
        max_cvss_retained_bytes,
        budget.max_projection_scenario_memberships(),
    )?;
    let omitted_evidence_refs = evidence_ref_retention.omitted;
    let omitted_evidence_refs_lower_bound =
        u64::try_from(omitted_evidence_refs.len()).unwrap_or(u64::MAX);
    Ok(CvssReductionOutcome {
        assessment: Some(assessment),
        incomplete_reason: None,
        evidence_refs_truncated: !omitted_evidence_refs.is_empty(),
        omitted_evidence_refs_lower_bound,
        omitted_evidence_refs,
    })
}

fn validate_projection_pair(
    projection: CvssFindingProjection<'_>,
) -> Result<(), CvssReductionError> {
    if let CvssFindingProjection::Taint {
        anchor,
        projection,
        sources,
    } = projection
    {
        let Some(first) = sources.first() else {
            return Err(CvssReductionError::Invariant(
                "CVSS taint pair requires at least one source fact",
            ));
        };
        if sources
            .iter()
            .any(|source| source.source_endpoint != first.source_endpoint)
        {
            return Err(CvssReductionError::Invariant(
                "CVSS taint pair contains facts from different source endpoints",
            ));
        }
        let expected = projection
            .source_facts
            .iter()
            .filter(|source| source.source_endpoint == first.source_endpoint);
        if !expected.eq(sources.iter()) {
            return Err(CvssReductionError::Invariant(
                "CVSS taint pair is not the complete canonical fact set for its source endpoint",
            ));
        }
        if let Some(strong) = anchor.strong_fields()
            && (strong.source_endpoint_analysis_projection_hash()
                != first.source_endpoint_analysis_projection_hash
                || strong.sink_endpoint_analysis_projection_hash()
                    != projection.sink_endpoint_analysis_projection_hash)
        {
            return Err(CvssReductionError::Invariant(
                "CVSS taint pair does not match its strong endpoint anchors",
            ));
        }
    }
    Ok(())
}

fn finding_id(
    policy_id: &super::PolicyId,
    projection: CvssFindingProjection<'_>,
) -> PolicyFindingId {
    match projection {
        CvssFindingProjection::Match { anchor } => {
            PolicyFindingId::from_match_anchor(policy_id, anchor)
        }
        CvssFindingProjection::Taint { anchor, .. } => {
            PolicyFindingId::from_taint_anchor(policy_id, anchor)
        }
        CvssFindingProjection::Typestate { anchor, .. } => {
            PolicyFindingId::from_typestate_anchor(policy_id, anchor)
        }
    }
}

fn vulnerability_identity(projection: CvssFindingProjection<'_>) -> VulnerabilityIdentity {
    let digest = match projection {
        CvssFindingProjection::Match { anchor } => {
            crate::analyzer::policy::finding_identity::match_vulnerability_digest(anchor)
        }
        CvssFindingProjection::Taint { anchor, .. } => taint_vulnerability_digest(anchor),
        CvssFindingProjection::Typestate { anchor, .. } => typestate_vulnerability_digest(anchor),
    };
    VulnerabilityIdentity::from_bytes(digest)
}

#[derive(Debug)]
struct ReductionMeter {
    remaining: usize,
}

impl ReductionMeter {
    const fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    fn charge(&mut self) -> bool {
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

#[derive(Debug, Clone)]
struct MetricConflict {
    metric: CvssMetric,
    evidence: Vec<CvssMetricEvidence>,
}

#[derive(Debug, Clone)]
struct ScenarioOutcome {
    selected: Vec<CvssMetricEvidence>,
    conflicts: Vec<MetricConflict>,
    provenance: Vec<ScopedMetricEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScenarioOutcomeKey {
    selected: Vec<SelectedMetricKey>,
    conflicts: Vec<ConflictKey>,
    provenance_evidence_set_hash: super::CvssEvidenceSetHash,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SelectedMetricKey {
    rank: u8,
    value: &'static str,
    hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ConflictKey {
    rank: u8,
    evidence_set_hash: super::CvssEvidenceSetHash,
}

impl ScenarioOutcome {
    fn key(&self) -> ScenarioOutcomeKey {
        let mut by_metric = Vec::<SelectedMetricKey>::new();
        for evidence in &self.selected {
            let rank = metric_rank(evidence.metric());
            if let Some(existing) = by_metric.iter_mut().find(|entry| entry.rank == rank) {
                existing.hashes.push(*evidence.content_hash().as_bytes());
            } else {
                by_metric.push(SelectedMetricKey {
                    rank,
                    value: evidence.value().first_label(),
                    hashes: vec![*evidence.content_hash().as_bytes()],
                });
            }
        }
        for entry in &mut by_metric {
            entry.hashes.sort_unstable();
            entry.hashes.dedup();
        }
        by_metric.sort_unstable();

        let mut conflicts = self
            .conflicts
            .iter()
            .map(|conflict| ConflictKey {
                rank: metric_rank(conflict.metric),
                evidence_set_hash: evidence_set_hash(
                    conflict
                        .evidence
                        .iter()
                        .map(CvssMetricEvidence::content_hash),
                ),
            })
            .collect::<Vec<_>>();
        conflicts.sort_unstable();
        let provenance_evidence_set_hash = evidence_set_hash(
            self.provenance
                .iter()
                .map(|record| record.evidence.content_hash()),
        );
        ScenarioOutcomeKey {
            selected: by_metric,
            conflicts,
            provenance_evidence_set_hash,
        }
    }
}

#[derive(Debug)]
struct OutcomeGroup {
    key: ScenarioOutcomeKey,
    scenarios: Vec<SourceScenarioId>,
    outcome: ScenarioOutcome,
}

struct EvidenceRefRetention {
    retained: Vec<EvidenceRef>,
    omitted: Vec<EvidenceRef>,
}

fn evidence_records_fit_budget(groups: &[OutcomeGroup], budget: &PolicyBudget) -> bool {
    let selected_and_conflicts = groups.iter().fold(0usize, |count, group| {
        count.saturating_add(
            group
                .outcome
                .selected
                .len()
                .saturating_add(group.outcome.conflicts.len()),
        )
    });
    if selected_and_conflicts > budget.max_cvss_evidence_records_per_finding() {
        return false;
    }

    let mut provenance_hashes = groups
        .iter()
        .flat_map(|group| group.outcome.provenance.iter())
        .map(|record| record.evidence.content_hash())
        .collect::<Vec<_>>();
    provenance_hashes.sort_unstable();
    provenance_hashes.dedup();
    provenance_hashes.len() <= budget.max_cvss_evidence_records_per_finding()
}

impl EvidenceRefRetention {
    fn for_groups(
        groups: &[OutcomeGroup],
        preexisting_evidence_refs: &[EvidenceRef],
        budget: &PolicyBudget,
    ) -> Result<Self, CvssReductionError> {
        let mut preexisting = preexisting_evidence_refs.to_vec();
        preexisting.sort();
        preexisting.dedup();
        if preexisting.len() > budget.max_evidence_refs_per_finding() {
            return Err(CvssReductionError::Invariant(
                "preexisting evidence references exceed the finding budget",
            ));
        }

        let mut candidates = groups
            .iter()
            .flat_map(|group| group.outcome.provenance.iter())
            .flat_map(|record| record.evidence.evidence_refs().iter().cloned())
            .collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();

        let mut remaining = budget
            .max_evidence_refs_per_finding()
            .saturating_sub(preexisting.len());
        let mut retained = Vec::with_capacity(candidates.len().min(remaining));
        let mut omitted = Vec::new();
        for reference in candidates {
            if preexisting.binary_search(&reference).is_ok() {
                retained.push(reference);
            } else if remaining > 0 {
                retained.push(reference);
                remaining -= 1;
            } else {
                omitted.push(reference);
            }
        }
        Ok(Self { retained, omitted })
    }
}

fn push_outcome_group(
    groups: &mut Vec<OutcomeGroup>,
    outcome: ScenarioOutcome,
    scenario: Option<&SourceScenarioId>,
    meter: &mut ReductionMeter,
    budget: &PolicyBudget,
) -> bool {
    if !meter.charge() {
        return false;
    }
    let key = outcome.key();
    if let Some(group) = groups.iter_mut().find(|group| group.key == key) {
        if let Some(scenario) = scenario {
            group.scenarios.push(scenario.clone());
        }
        group.outcome.provenance.extend(outcome.provenance);
        return true;
    }
    if groups.len() >= budget.max_cvss_variants_per_finding() {
        // The caller converts this typed budget signal into the required
        // unscored marker rather than retaining a prefix of coherent variants.
        return false;
    }
    groups.push(OutcomeGroup {
        key,
        scenarios: scenario.into_iter().cloned().collect(),
        outcome,
    });
    true
}

fn reduce_scenario(
    evidence: &[ScopedMetricEvidence],
    policy_id: &super::PolicyId,
    finding_id: PolicyFindingId,
    scenario: Option<&SourceScenarioId>,
    meter: &mut ReductionMeter,
) -> Option<ScenarioOutcome> {
    let mut applicable = Vec::new();
    for record in evidence {
        if !meter.charge() {
            return None;
        }
        if scope_applies(&record.target_scope, policy_id, finding_id, scenario) {
            applicable.push(record.clone());
        }
    }

    let mut metrics = applicable
        .iter()
        .map(|record| record.evidence.metric())
        .collect::<Vec<_>>();
    metrics.sort_by_key(|metric| metric_rank(*metric));
    metrics.dedup();

    let mut selected = Vec::new();
    let mut conflicts = Vec::new();
    for metric in metrics {
        let metric_records = applicable
            .iter()
            .filter(|record| record.evidence.metric() == metric)
            .collect::<Vec<_>>();
        let mut scopes = metric_records
            .iter()
            .map(|record| &record.target_scope)
            .collect::<Vec<_>>();
        scopes.sort_unstable();
        scopes.dedup();
        let mut maximal = Vec::new();
        for candidate in &scopes {
            let mut shadowed = false;
            for other in &scopes {
                if !meter.charge() {
                    return None;
                }
                if scope_strictly_refines(other, candidate) {
                    shadowed = true;
                    break;
                }
            }
            if !shadowed {
                maximal.push(*candidate);
            }
        }

        let mut highest = Vec::<CvssMetricEvidence>::new();
        for scope in maximal {
            let at_scope = metric_records
                .iter()
                .filter(|record| &record.target_scope == scope)
                .collect::<Vec<_>>();
            let rank = at_scope
                .iter()
                .map(|record| basis_rank(record.evidence.basis()))
                .max()
                .expect("maximal scope has evidence");
            for record in at_scope {
                if !meter.charge() {
                    return None;
                }
                if basis_rank(record.evidence.basis()) == rank {
                    highest.push(record.evidence.clone());
                }
            }
        }
        highest.sort_by(super::CvssMetricEvidence::canonical_cmp);
        highest.dedup();
        let distinct_values = highest
            .iter()
            .map(|record| record.value())
            .collect::<HashlessSet<_>>();
        if distinct_values.len() == 1 {
            selected.extend(highest);
        } else if !highest.is_empty() {
            conflicts.push(MetricConflict {
                metric,
                evidence: highest,
            });
        }
    }
    selected.sort_by(super::CvssMetricEvidence::canonical_cmp);
    conflicts.sort_by_key(|conflict| metric_rank(conflict.metric));
    Some(ScenarioOutcome {
        selected,
        conflicts,
        provenance: applicable,
    })
}

/// Tiny deterministic set helper that avoids hashing/sorted-map overhead for
/// the at-most-five legal values of one metric.
struct HashlessSet<T>(Vec<T>);

impl<T: Eq> FromIterator<T> for HashlessSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut values = Vec::new();
        for value in iter {
            if !values.contains(&value) {
                values.push(value);
            }
        }
        Self(values)
    }
}

impl<T> HashlessSet<T> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

fn scope_applies(
    scope: &PolicyOverlayScope,
    policy_id: &super::PolicyId,
    finding_id: PolicyFindingId,
    scenario: Option<&SourceScenarioId>,
) -> bool {
    match scope {
        PolicyOverlayScope::AllFindings => true,
        PolicyOverlayScope::Policy {
            policy_id: expected,
        } => expected == policy_id,
        PolicyOverlayScope::Finding {
            finding_id: expected,
        } => *expected == finding_id,
        PolicyOverlayScope::SourceScenario { scenario_id } => scenario == Some(scenario_id),
        PolicyOverlayScope::FindingScenario {
            finding,
            scenario: expected,
        } => *finding == finding_id && scenario == Some(expected),
    }
}

fn scope_strictly_refines(left: &PolicyOverlayScope, right: &PolicyOverlayScope) -> bool {
    use PolicyOverlayScope as S;
    match (left, right) {
        (S::Policy { .. }, S::AllFindings) => true,
        (S::Finding { .. } | S::SourceScenario { .. }, S::AllFindings | S::Policy { .. }) => true,
        (
            S::FindingScenario {
                finding: left_finding,
                ..
            },
            S::Finding {
                finding_id: right_finding,
            },
        ) => left_finding == right_finding,
        (
            S::FindingScenario {
                scenario: left_scenario,
                ..
            },
            S::SourceScenario {
                scenario_id: right_scenario,
            },
        ) => left_scenario == right_scenario,
        (S::FindingScenario { .. }, S::AllFindings | S::Policy { .. }) => true,
        _ => false,
    }
}

const fn basis_rank(basis: CvssEvidenceBasis) -> u8 {
    match basis {
        CvssEvidenceBasis::PolicyAssertion => 1,
        CvssEvidenceBasis::StaticWitness => 2,
        CvssEvidenceBasis::EnvironmentProfile | CvssEvidenceBasis::ThreatFeed => 3,
        CvssEvidenceBasis::AnalystOverride => 4,
    }
}

fn compare_scoped_evidence(left: &ScopedMetricEvidence, right: &ScopedMetricEvidence) -> Ordering {
    metric_rank(left.evidence.metric())
        .cmp(&metric_rank(right.evidence.metric()))
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
}

fn seal_group(
    vulnerability: VulnerabilityIdentity,
    scenario_set_hash: SourceScenarioSetHash,
    mut group: OutcomeGroup,
    retained_evidence_refs: &[EvidenceRef],
) -> Result<CvssAssessmentVariant, CvssReductionError> {
    group.scenarios.sort();
    group.scenarios.dedup();
    group.scenarios.shrink_to_fit();
    group.outcome.provenance.sort_by(compare_scoped_evidence);
    group.outcome.provenance.dedup();
    for evidence in &mut group.outcome.selected {
        evidence.retain_evidence_refs(retained_evidence_refs);
    }
    for record in &mut group.outcome.provenance {
        record.evidence.retain_evidence_refs(retained_evidence_refs);
    }

    let mut evidence_refs = group
        .outcome
        .provenance
        .iter()
        .flat_map(|record| record.evidence.evidence_refs().iter().cloned())
        .collect::<Vec<_>>();
    evidence_refs.sort();
    evidence_refs.dedup();
    let overlay_scopes = group
        .outcome
        .provenance
        .iter()
        .filter(|record| {
            matches!(
                record.evidence.basis(),
                CvssEvidenceBasis::EnvironmentProfile
                    | CvssEvidenceBasis::ThreatFeed
                    | CvssEvidenceBasis::AnalystOverride
            )
        })
        .map(|record| record.target_scope.clone())
        .collect::<Vec<_>>();
    let content_hashes = group
        .outcome
        .provenance
        .iter()
        .map(|record| record.evidence.content_hash())
        .collect::<Vec<_>>();
    let provenance = CvssAssessmentProvenance::try_new(
        REDUCER_ID.to_string(),
        evidence_refs,
        overlay_scopes,
        content_hashes,
    )?;

    let missing = missing_base_metrics(&group.outcome.selected);
    let mut reasons = Vec::new();
    if !missing.is_empty() {
        reasons.push(CvssUnscoredReason::MissingBaseEvidence);
    }
    for conflict in &group.outcome.conflicts {
        let hash = evidence_set_hash(
            conflict
                .evidence
                .iter()
                .map(CvssMetricEvidence::content_hash),
        );
        let mut refs = conflict
            .evidence
            .iter()
            .flat_map(|evidence| evidence.evidence_refs().iter().cloned())
            .collect::<Vec<_>>();
        refs.sort();
        refs.dedup();
        let original_len = refs.len();
        refs.retain(|reference| retained_evidence_refs.binary_search(reference).is_ok());
        let omitted = original_len.saturating_sub(refs.len());
        reasons.push(CvssUnscoredReason::conflicting_metric_evidence(
            conflict.metric,
            hash,
            refs,
            omitted > 0,
            u64::try_from(omitted).unwrap_or(u64::MAX),
        )?);
    }

    let assessment = if reasons.is_empty() {
        let scored = score_metrics(&group.outcome.selected)?;
        CvssAssessment::scored(
            CvssVersion::V4_0,
            scored.nomenclature,
            scored.full_vector,
            scored.components,
            group.outcome.selected,
            provenance,
        )?
    } else {
        CvssAssessment::unscored(
            CvssVersion::V4_0,
            group.outcome.selected,
            missing,
            reasons,
            provenance,
        )?
    };
    CvssAssessmentVariant::try_new(
        vulnerability,
        group.scenarios,
        false,
        0,
        scenario_set_hash,
        Vec::new(),
        false,
        assessment,
    )
    .map_err(Into::into)
}

/// Retain one canonical prefix of the variant/scenario membership order that
/// fits the CVSS share of the finding evidence budget. The full scenario-set
/// hash, semantic assessment, and derived variant ID remain unchanged; only
/// bounded display provenance is removed.
fn retain_source_scenario_display(
    variants: Vec<CvssAssessmentVariant>,
    allowed_scenarios: &[SourceScenarioId],
    max_retained_bytes: usize,
    max_memberships: usize,
) -> Result<CvssAssessmentSet, CvssReductionError> {
    if allowed_scenarios.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CvssReductionError::Invariant(
            "allowed CVSS scenario display is not canonical",
        ));
    }
    let selected = super::deterministic_display_selection(&variants);
    let full = CvssAssessmentSet::try_new(variants, selected)?;
    let full_memberships = full
        .variants()
        .iter()
        .map(|variant| variant.source_scenarios().len())
        .sum::<usize>();
    let mut full_scenarios = full
        .variants()
        .iter()
        .flat_map(|variant| variant.source_scenarios().iter().cloned())
        .collect::<Vec<_>>();
    full_scenarios.sort();
    full_scenarios.dedup();
    if full_scenarios.len() != full_memberships {
        return Err(CvssReductionError::Invariant(
            "one CVSS source scenario belongs to multiple variants",
        ));
    }
    if allowed_scenarios
        .iter()
        .any(|scenario| full_scenarios.binary_search(scenario).is_err())
    {
        return Err(CvssReductionError::Invariant(
            "allowed CVSS scenario display is not a subset of the full projection",
        ));
    }
    let all_display_allowed = full_scenarios.len() == allowed_scenarios.len();
    if all_display_allowed
        && full.retained_size() <= max_retained_bytes
        && full_memberships <= max_memberships
    {
        return Ok(full);
    }

    let scenario_bytes = full
        .variants()
        .iter()
        .flat_map(|variant| variant.source_scenarios())
        .map(RetainedSize::retained_size)
        .sum::<usize>();
    let base_bytes =
        full.retained_size()
            .checked_sub(scenario_bytes)
            .ok_or(CvssReductionError::Invariant(
                "CVSS scenario retained-size accounting underflowed",
            ))?;
    let mut remaining_bytes = max_retained_bytes.saturating_sub(base_bytes);
    let mut remaining_memberships = max_memberships;
    let mut prefix_open = true;

    let CvssAssessmentSet { variants, .. } = full;
    let mut retained_variants = Vec::with_capacity(variants.len());
    for variant in variants {
        let CvssAssessmentVariant {
            id: expected_id,
            vulnerability_identity,
            source_scenarios,
            source_scenarios_truncated,
            omitted_source_scenarios_lower_bound,
            source_scenario_set_hash,
            witness_refs,
            witness_refs_truncated,
            assessment,
        } = variant;
        if source_scenarios_truncated || omitted_source_scenarios_lower_bound != 0 {
            return Err(CvssReductionError::Invariant(
                "CVSS source-scenario retention was applied more than once",
            ));
        }

        let full_len = source_scenarios.len();
        let mut retained = Vec::with_capacity(full_len.min(allowed_scenarios.len()));
        for scenario in source_scenarios {
            if allowed_scenarios.binary_search(&scenario).is_err() || !prefix_open {
                continue;
            }
            let bytes = scenario.retained_size();
            if remaining_memberships == 0 || bytes > remaining_bytes {
                prefix_open = false;
                continue;
            }
            remaining_memberships -= 1;
            remaining_bytes -= bytes;
            retained.push(scenario);
        }
        retained.shrink_to_fit();
        let omitted = full_len.saturating_sub(retained.len());
        let rebuilt = CvssAssessmentVariant::try_new(
            vulnerability_identity,
            retained,
            omitted > 0,
            u64::try_from(omitted).unwrap_or(u64::MAX),
            source_scenario_set_hash,
            witness_refs,
            witness_refs_truncated,
            assessment,
        )?;
        if rebuilt.id() != expected_id {
            return Err(CvssReductionError::Invariant(
                "CVSS scenario display retention changed variant identity",
            ));
        }
        retained_variants.push(rebuilt);
    }

    let selected = super::deterministic_display_selection(&retained_variants);
    let retained = CvssAssessmentSet::try_new(retained_variants, selected)?;
    if base_bytes <= max_retained_bytes && retained.retained_size() > max_retained_bytes {
        return Err(CvssReductionError::Invariant(
            "CVSS scenario display retention exceeded its byte allowance",
        ));
    }
    Ok(retained)
}

fn missing_base_metrics(selected: &[CvssMetricEvidence]) -> Vec<CvssBaseMetric> {
    BASE_METRICS
        .into_iter()
        .filter(|metric| {
            !selected
                .iter()
                .any(|evidence| evidence.metric() == CvssMetric::Base { metric: *metric })
        })
        .collect()
}

fn budget_outcome(
    vulnerability: VulnerabilityIdentity,
    scenarios: &[SourceScenarioId],
    scenario_set_hash: SourceScenarioSetHash,
    allowed_source_scenario_display: &[SourceScenarioId],
    max_cvss_retained_bytes: usize,
    budget: &PolicyBudget,
) -> Result<CvssReductionOutcome, CvssReductionError> {
    if budget.max_cvss_variants_per_finding() == 0 {
        return Ok(CvssReductionOutcome {
            assessment: None,
            incomplete_reason: Some(PolicyIncompleteReason::CvssVariantBudget),
            evidence_refs_truncated: false,
            omitted_evidence_refs_lower_bound: 0,
            omitted_evidence_refs: Vec::new(),
        });
    }
    let provenance = CvssAssessmentProvenance::try_new(
        REDUCER_ID.to_string(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    let assessment = CvssAssessment::unscored(
        CvssVersion::V4_0,
        Vec::new(),
        Vec::new(),
        vec![CvssUnscoredReason::RunIncomplete {
            reason: PolicyIncompleteReason::CvssVariantBudget,
        }],
        provenance,
    )?;
    let variant = CvssAssessmentVariant::try_new(
        vulnerability,
        scenarios.to_vec(),
        false,
        0,
        scenario_set_hash,
        Vec::new(),
        false,
        assessment,
    )?;
    let assessment = retain_source_scenario_display(
        vec![variant],
        allowed_source_scenario_display,
        max_cvss_retained_bytes,
        budget.max_projection_scenario_memberships(),
    )?;
    Ok(CvssReductionOutcome {
        assessment: Some(assessment),
        incomplete_reason: Some(PolicyIncompleteReason::CvssVariantBudget),
        evidence_refs_truncated: false,
        omitted_evidence_refs_lower_bound: 0,
        omitted_evidence_refs: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::cvss::CvssEvidenceContentHash;
    use crate::analyzer::policy::definition::{
        CvssMetricValue, CvssMetricValueToken, PolicyId, PolicySemanticEvent, TaintEntryId,
        TypestateExitScope, TypestateExpectationId, TypestateStateId,
    };
    use crate::analyzer::policy::finding_identity::{
        EvidenceRef, OpaqueFindingKey, TypestateScenarioId,
    };
    use crate::analyzer::policy::future_evidence::{
        ResolvedTypestateTerminal, TypestateBindingPlanHash, TypestateProtocolHash,
        TypestateViolationEvidence,
    };
    use crate::analyzer::policy::identity::{
        EndpointAnalysisProjectionHash, EndpointSemanticHash, TypestateAuthoringProjectionHash,
    };
    use crate::analyzer::policy::resolved::ResolvedEndpointIdentity;

    fn test_policy_and_finding() -> (PolicyId, PolicyFindingId) {
        let policy: PolicyId = "bifrost.test.cvss".parse().unwrap();
        let anchor = MatchFindingAnchor::weak(
            crate::analyzer::policy::finding_identity::MatchResultDomain::File,
            crate::analyzer::semantic::WorkspaceRelativePath::new("src/lib.rs").unwrap(),
            crate::analyzer::policy::finding_identity::OpaqueFindingKey::try_new("test", "finding")
                .unwrap(),
        );
        let finding = PolicyFindingId::from_match_anchor(&policy, &anchor);
        (policy, finding)
    }

    #[test]
    fn match_and_typestate_use_the_domain_separated_empty_source_scenario_identity() {
        let match_anchor = MatchFindingAnchor::weak(
            crate::analyzer::policy::finding_identity::MatchResultDomain::File,
            crate::analyzer::semantic::WorkspaceRelativePath::new("src/lib.rs").unwrap(),
            OpaqueFindingKey::try_new("test", "match-empty-scenarios").unwrap(),
        );
        let match_projection = CvssFindingProjection::Match {
            anchor: &match_anchor,
        };
        let match_scenarios = match_projection.source_scenarios();
        assert!(match_scenarios.is_empty());
        assert_eq!(
            match_projection
                .source_scenario_set_hash(&match_scenarios)
                .unwrap(),
            empty_source_scenario_set_hash()
        );

        let typestate_facts = TypestatePolicyProjectionFacts::try_new(
            TypestateAuthoringProjectionHash::from_bytes([1; 32]),
            TypestateProtocolHash::from_canonical_bytes(b"protocol"),
            TypestateBindingPlanHash::from_canonical_bytes(b"bindings"),
            ResolvedEndpointIdentity::Local {
                policy_id: PolicyId::new("bifrost.test.cvss").unwrap(),
                entry_id: TaintEntryId::new("subject").unwrap(),
            },
            EndpointSemanticHash::from_bytes([2; 32]),
            EndpointAnalysisProjectionHash::from_bytes([3; 32]),
            Vec::new(),
            "resource handle".to_string(),
            None,
            TypestateViolationEvidence::try_terminal_expectation(
                TypestateExpectationId::new("closed-at-exit").unwrap(),
                ResolvedTypestateTerminal::SemanticEvent {
                    event: PolicySemanticEvent::NormalProcedureExit {
                        scope: TypestateExitScope::AnalysisRoot,
                    },
                },
                TypestateStateId::new("open").unwrap(),
                vec![TypestateStateId::new("closed").unwrap()],
            )
            .unwrap(),
            vec![TypestateScenarioId::try_new("test", "typestate-scenario").unwrap()],
            &PolicyBudget::default(),
        )
        .unwrap();
        let typestate_anchor = TypestateFindingAnchor::weak(
            OpaqueFindingKey::try_new("test", "typestate-empty-source-scenarios").unwrap(),
        );
        let typestate_projection = CvssFindingProjection::Typestate {
            anchor: &typestate_anchor,
            projection: &typestate_facts,
        };
        let typestate_source_scenarios = typestate_projection.source_scenarios();
        assert!(typestate_source_scenarios.is_empty());
        assert_eq!(
            typestate_projection
                .source_scenario_set_hash(&typestate_source_scenarios)
                .unwrap(),
            empty_source_scenario_set_hash()
        );
    }

    fn scoped_base(
        metric: CvssBaseMetric,
        token: CvssMetricValueToken,
        basis: CvssEvidenceBasis,
        target_scope: PolicyOverlayScope,
        hash_byte: u8,
    ) -> ScopedMetricEvidence {
        scoped_base_with_reference(
            metric,
            token,
            basis,
            target_scope,
            hash_byte,
            &format!("evidence-{hash_byte}"),
        )
    }

    fn scoped_base_with_reference(
        metric: CvssBaseMetric,
        token: CvssMetricValueToken,
        basis: CvssEvidenceBasis,
        target_scope: PolicyOverlayScope,
        hash_byte: u8,
        evidence_ref: &str,
    ) -> ScopedMetricEvidence {
        let metric = CvssMetric::Base { metric };
        ScopedMetricEvidence {
            target_scope,
            evidence: CvssMetricEvidence::try_new(
                metric,
                CvssMetricValue::try_new(metric, token).unwrap(),
                basis,
                vec![EvidenceRef::try_new("cvss-test", evidence_ref).unwrap()],
                "Reducer test evidence".to_string(),
                Vec::new(),
                "bifrost-test".to_string(),
                None,
                match metric {
                    CvssMetric::Base { metric } => metric.required_scope(),
                    _ => unreachable!(),
                },
                CvssEvidenceContentHash::from_bytes([hash_byte; 32]),
            )
            .unwrap(),
        }
    }

    fn default_base_token(metric: CvssBaseMetric) -> CvssMetricValueToken {
        match metric {
            CvssBaseMetric::Ac => CvssMetricValueToken::L,
            CvssBaseMetric::Av | CvssBaseMetric::At | CvssBaseMetric::Pr | CvssBaseMetric::Ui => {
                CvssMetricValueToken::N
            }
            CvssBaseMetric::Vc
            | CvssBaseMetric::Vi
            | CvssBaseMetric::Va
            | CvssBaseMetric::Sc
            | CvssBaseMetric::Si
            | CvssBaseMetric::Sa => CvssMetricValueToken::H,
        }
    }

    fn reduce_one(
        evidence: &[ScopedMetricEvidence],
        policy: &PolicyId,
        finding: PolicyFindingId,
        scenario: Option<&SourceScenarioId>,
    ) -> ScenarioOutcome {
        reduce_scenario(
            evidence,
            policy,
            finding,
            scenario,
            &mut ReductionMeter::new(32_768),
        )
        .unwrap()
    }

    fn sealed_assessment(
        evidence: &[ScopedMetricEvidence],
        scenarios: &[SourceScenarioId],
    ) -> CvssAssessmentSet {
        let (policy, finding) = test_policy_and_finding();
        let budget = PolicyBudget::default();
        let mut meter = ReductionMeter::new(budget.max_cvss_reduction_steps());
        let mut groups = Vec::new();
        for scenario in scenarios {
            let outcome =
                reduce_scenario(evidence, &policy, finding, Some(scenario), &mut meter).unwrap();
            assert!(push_outcome_group(
                &mut groups,
                outcome,
                Some(scenario),
                &mut meter,
                &budget,
            ));
        }
        let vulnerability = VulnerabilityIdentity::from_bytes([91; 32]);
        let scenario_set_hash = SourceScenarioSetHash::try_from_scenarios(scenarios.to_vec())
            .expect("test scenarios are valid");
        let retention = EvidenceRefRetention::for_groups(&groups, &[], &budget).unwrap();
        let variants = groups
            .into_iter()
            .map(|group| {
                seal_group(vulnerability, scenario_set_hash, group, &retention.retained).unwrap()
            })
            .collect::<Vec<_>>();
        let selected = super::super::deterministic_display_selection(&variants);
        CvssAssessmentSet::try_new(variants, selected).unwrap()
    }

    #[test]
    fn finding_and_source_scenario_are_incomparable_maxima() {
        let (policy, finding) = test_policy_and_finding();
        let scenario = SourceScenarioId::try_new("test", "scenario").unwrap();
        let finding_scope = PolicyOverlayScope::Finding {
            finding_id: finding,
        };
        let scenario_scope = PolicyOverlayScope::SourceScenario {
            scenario_id: scenario.clone(),
        };
        let combined = PolicyOverlayScope::FindingScenario {
            finding,
            scenario: scenario.clone(),
        };
        assert!(!scope_strictly_refines(&finding_scope, &scenario_scope));
        assert!(!scope_strictly_refines(&scenario_scope, &finding_scope));
        assert!(scope_strictly_refines(&combined, &finding_scope));
        assert!(scope_strictly_refines(&combined, &scenario_scope));

        let other_scenario = PolicyOverlayScope::SourceScenario {
            scenario_id: SourceScenarioId::try_new("test", "other-scenario").unwrap(),
        };
        let other_anchor = MatchFindingAnchor::weak(
            crate::analyzer::policy::finding_identity::MatchResultDomain::File,
            crate::analyzer::semantic::WorkspaceRelativePath::new("src/other.rs").unwrap(),
            OpaqueFindingKey::try_new("test", "other-finding").unwrap(),
        );
        let other_finding = PolicyOverlayScope::Finding {
            finding_id: PolicyFindingId::from_match_anchor(&policy, &other_anchor),
        };
        assert!(!scope_strictly_refines(&combined, &other_scenario));
        assert!(!scope_strictly_refines(&combined, &other_finding));
    }

    #[test]
    fn basis_precedence_is_explicit() {
        assert!(
            basis_rank(CvssEvidenceBasis::AnalystOverride)
                > basis_rank(CvssEvidenceBasis::ThreatFeed)
        );
        assert_eq!(
            basis_rank(CvssEvidenceBasis::ThreatFeed),
            basis_rank(CvssEvidenceBasis::EnvironmentProfile)
        );
        assert!(
            basis_rank(CvssEvidenceBasis::StaticWitness)
                > basis_rank(CvssEvidenceBasis::PolicyAssertion)
        );
    }

    #[test]
    fn equal_rank_equal_values_merge_but_distinct_values_conflict() {
        let (policy, finding) = test_policy_and_finding();
        let policy_scope = PolicyOverlayScope::Policy {
            policy_id: policy.clone(),
        };
        let corroborating = vec![
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::PolicyAssertion,
                policy_scope.clone(),
                1,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::PolicyAssertion,
                policy_scope,
                2,
            ),
        ];
        let merged = reduce_one(&corroborating, &policy, finding, None);
        assert_eq!(merged.selected.len(), 2);
        assert!(merged.conflicts.is_empty());

        let scenario = SourceScenarioId::try_new("test", "same-scenario").unwrap();
        let scenario_scope = PolicyOverlayScope::SourceScenario {
            scenario_id: scenario.clone(),
        };
        let conflicting = vec![
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                scenario_scope.clone(),
                3,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::A,
                CvssEvidenceBasis::AnalystOverride,
                scenario_scope,
                4,
            ),
        ];
        let conflicted = reduce_one(&conflicting, &policy, finding, Some(&scenario));
        assert!(conflicted.selected.is_empty());
        assert_eq!(conflicted.conflicts.len(), 1);
        assert_eq!(conflicted.conflicts[0].evidence.len(), 2);
    }

    #[test]
    fn correlated_scenario_metric_pairs_create_two_variants_not_a_cartesian_product() {
        let (policy, finding) = test_policy_and_finding();
        let one = SourceScenarioId::try_new("test", "scenario-one").unwrap();
        let two = SourceScenarioId::try_new("test", "scenario-two").unwrap();
        let evidence = vec![
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: one.clone(),
                },
                10,
            ),
            scoped_base(
                CvssBaseMetric::Ac,
                CvssMetricValueToken::H,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: one.clone(),
                },
                11,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::A,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: two.clone(),
                },
                12,
            ),
            scoped_base(
                CvssBaseMetric::Ac,
                CvssMetricValueToken::L,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: two.clone(),
                },
                13,
            ),
        ];
        let budget = PolicyBudget::default();
        let mut meter = ReductionMeter::new(budget.max_cvss_reduction_steps());
        let mut groups = Vec::new();
        for scenario in [&one, &two] {
            let outcome =
                reduce_scenario(&evidence, &policy, finding, Some(scenario), &mut meter).unwrap();
            assert!(push_outcome_group(
                &mut groups,
                outcome,
                Some(scenario),
                &mut meter,
                &budget,
            ));
        }

        assert_eq!(groups.len(), 2);
        let combinations = groups
            .iter()
            .map(|group| {
                group
                    .outcome
                    .selected
                    .iter()
                    .map(|item| (item.metric().first_label(), item.value().first_label()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(combinations.contains(&vec![("AV", "N"), ("AC", "H")]));
        assert!(combinations.contains(&vec![("AV", "A"), ("AC", "L")]));
    }

    #[test]
    fn scenario_display_intersects_retained_evidence_across_two_outcomes() {
        let one = SourceScenarioId::try_new("test", "retained-a").unwrap();
        let two = SourceScenarioId::try_new("test", "omitted-b").unwrap();
        let evidence = vec![
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::PolicyAssertion,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: one.clone(),
                },
                90,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::A,
                CvssEvidenceBasis::PolicyAssertion,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: two.clone(),
                },
                91,
            ),
        ];
        let full = sealed_assessment(&evidence, &[one.clone(), two.clone()]);
        assert_eq!(full.variants().len(), 2);
        // Exercise the adversarial order: variant identity places the omitted
        // scenario first, while the finding evidence retains lexical scenario A.
        assert_eq!(
            full.variants()[0].source_scenarios(),
            std::slice::from_ref(&two)
        );
        let full_ids = full
            .variants()
            .iter()
            .map(CvssAssessmentVariant::id)
            .collect::<Vec<_>>();
        let full_scenario_hash = full.variants()[0].source_scenario_set_hash();

        let retained = retain_source_scenario_display(
            full.variants().to_vec(),
            std::slice::from_ref(&one),
            usize::MAX,
            1,
        )
        .unwrap();
        assert_eq!(
            retained
                .variants()
                .iter()
                .map(CvssAssessmentVariant::id)
                .collect::<Vec<_>>(),
            full_ids
        );
        let displayed = retained
            .variants()
            .iter()
            .flat_map(|variant| variant.source_scenarios().iter().cloned())
            .collect::<Vec<_>>();
        assert_eq!(displayed, vec![one.clone()]);
        assert!(
            retained
                .variants()
                .iter()
                .flat_map(|variant| variant.source_scenarios())
                .all(|scenario| scenario == &one)
        );
        let omitted_variant = retained
            .variants()
            .iter()
            .find(|variant| variant.source_scenarios().is_empty())
            .expect("the disallowed scenario must not leak into CVSS display provenance");
        assert!(omitted_variant.source_scenarios_truncated());
        assert_eq!(omitted_variant.omitted_source_scenarios_lower_bound(), 1);
        assert!(
            retained
                .variants()
                .iter()
                .all(|variant| { variant.source_scenario_set_hash() == full_scenario_hash })
        );
    }

    #[test]
    fn shadowed_scenario_evidence_remains_correlated_in_distinct_variants() {
        let (policy, finding) = test_policy_and_finding();
        let one = SourceScenarioId::try_new("test", "shadowed-one").unwrap();
        let two = SourceScenarioId::try_new("test", "shadowed-two").unwrap();
        let mut evidence = BASE_METRICS
            .into_iter()
            .filter(|metric| *metric != CvssBaseMetric::Av)
            .enumerate()
            .map(|(index, metric)| {
                scoped_base(
                    metric,
                    default_base_token(metric),
                    CvssEvidenceBasis::PolicyAssertion,
                    PolicyOverlayScope::AllFindings,
                    u8::try_from(index + 20).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        evidence.extend([
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::A,
                CvssEvidenceBasis::PolicyAssertion,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: one.clone(),
                },
                80,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::P,
                CvssEvidenceBasis::PolicyAssertion,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: two.clone(),
                },
                81,
            ),
            // These two records intentionally carry identical semantic
            // evidence. Their finding-scenario scopes refine and shadow the
            // distinct source-scenario policy assertions above.
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::FindingScenario {
                    finding,
                    scenario: one.clone(),
                },
                82,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::FindingScenario {
                    finding,
                    scenario: two.clone(),
                },
                82,
            ),
        ]);

        let first = reduce_one(&evidence, &policy, finding, Some(&one));
        let second = reduce_one(&evidence, &policy, finding, Some(&two));
        assert_eq!(first.selected, second.selected);
        assert_ne!(first.key(), second.key());

        let forward = sealed_assessment(&evidence, &[one.clone(), two.clone()]);
        assert_eq!(forward.variants().len(), 2);
        assert_ne!(forward.variants()[0].id(), forward.variants()[1].id());
        let vectors = forward
            .variants()
            .iter()
            .map(|variant| match variant.assessment() {
                CvssAssessment::Scored { vector, .. } => vector.as_str(),
                CvssAssessment::Unscored { .. } => panic!("complete Base evidence must score"),
            })
            .collect::<Vec<_>>();
        assert_eq!(vectors[0], vectors[1]);

        let provenance_hashes = |scenario: &SourceScenarioId| {
            let variant = forward
                .variants()
                .iter()
                .find(|variant| variant.source_scenarios() == std::slice::from_ref(scenario))
                .expect("each scenario must retain its own variant");
            match variant.assessment() {
                CvssAssessment::Scored { provenance, .. }
                | CvssAssessment::Unscored { provenance, .. } => {
                    provenance.content_hashes().to_vec()
                }
            }
        };
        let first_hashes = provenance_hashes(&one);
        let second_hashes = provenance_hashes(&two);
        let first_policy = CvssEvidenceContentHash::from_bytes([80; 32]);
        let second_policy = CvssEvidenceContentHash::from_bytes([81; 32]);
        let common_override = CvssEvidenceContentHash::from_bytes([82; 32]);
        assert!(first_hashes.contains(&first_policy));
        assert!(!first_hashes.contains(&second_policy));
        assert!(first_hashes.contains(&common_override));
        assert!(second_hashes.contains(&second_policy));
        assert!(!second_hashes.contains(&first_policy));
        assert!(second_hashes.contains(&common_override));

        evidence.reverse();
        let reverse = sealed_assessment(&evidence, &[two, one]);
        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reverse).unwrap()
        );
    }

    #[test]
    fn report_reference_changes_do_not_change_semantic_variant_identity() {
        let scenario = SourceScenarioId::try_new("test", "stable-report-ref").unwrap();
        let evidence = |reference_prefix: &str| {
            BASE_METRICS
                .into_iter()
                .enumerate()
                .map(|(index, metric)| {
                    scoped_base_with_reference(
                        metric,
                        default_base_token(metric),
                        CvssEvidenceBasis::PolicyAssertion,
                        PolicyOverlayScope::AllFindings,
                        u8::try_from(index + 1).unwrap(),
                        &format!("{reference_prefix}-{index}"),
                    )
                })
                .collect::<Vec<_>>()
        };

        let original = sealed_assessment(&evidence("original"), std::slice::from_ref(&scenario));
        let renamed = sealed_assessment(&evidence("renamed"), std::slice::from_ref(&scenario));
        assert_eq!(original.variants().len(), 1);
        assert_eq!(renamed.variants().len(), 1);
        assert_eq!(original.variants()[0].id(), renamed.variants()[0].id());
        assert_ne!(
            serde_json::to_vec(&original).unwrap(),
            serde_json::to_vec(&renamed).unwrap()
        );
    }

    #[test]
    fn scenario_display_retention_is_byte_bounded_deterministic_and_identity_neutral() {
        let scenarios = [
            SourceScenarioId::try_new("test", format!("a-{}", "x".repeat(120))).unwrap(),
            SourceScenarioId::try_new("test", format!("b-{}", "y".repeat(120))).unwrap(),
            SourceScenarioId::try_new("test", format!("c-{}", "z".repeat(120))).unwrap(),
        ];
        let evidence = BASE_METRICS
            .into_iter()
            .enumerate()
            .map(|(index, metric)| {
                scoped_base(
                    metric,
                    default_base_token(metric),
                    CvssEvidenceBasis::PolicyAssertion,
                    PolicyOverlayScope::AllFindings,
                    u8::try_from(index + 100).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let full = sealed_assessment(&evidence, &scenarios);
        assert_eq!(full.variants().len(), 1);
        let full_variant = &full.variants()[0];
        assert_eq!(full_variant.source_scenarios(), &scenarios);
        let full_variant_id = full_variant.id();
        let full_scenario_set_hash = full_variant.source_scenario_set_hash();
        let full_scenario_bytes = full_variant
            .source_scenarios()
            .iter()
            .map(RetainedSize::retained_size)
            .sum::<usize>();
        let base_bytes = full.retained_size() - full_scenario_bytes;
        let allowance = base_bytes + scenarios[0].retained_size();
        let CvssAssessmentSet {
            variants: full_variants,
            ..
        } = full;

        let retained = retain_source_scenario_display(
            full_variants,
            &scenarios,
            allowance,
            PolicyBudget::default().max_projection_scenario_memberships(),
        )
        .unwrap();
        let retained_variant = &retained.variants()[0];
        assert_eq!(
            retained_variant.source_scenarios(),
            std::slice::from_ref(&scenarios[0])
        );
        assert!(retained_variant.source_scenarios_truncated());
        assert_eq!(retained_variant.omitted_source_scenarios_lower_bound(), 2);
        assert_eq!(retained_variant.id(), full_variant_id);
        assert_eq!(
            retained_variant.source_scenario_set_hash(),
            full_scenario_set_hash
        );
        assert!(retained.retained_size() <= allowance);

        let reverse_full = sealed_assessment(
            &evidence,
            &[
                scenarios[2].clone(),
                scenarios[1].clone(),
                scenarios[0].clone(),
            ],
        );
        let CvssAssessmentSet {
            variants: reverse_variants,
            ..
        } = reverse_full;
        let reverse = retain_source_scenario_display(
            reverse_variants,
            &scenarios,
            allowance,
            PolicyBudget::default().max_projection_scenario_memberships(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&retained).unwrap(),
            serde_json::to_vec(&reverse).unwrap()
        );
    }

    #[test]
    fn reversing_all_inputs_produces_byte_identical_assessments() {
        let one = SourceScenarioId::try_new("test", "scenario-one").unwrap();
        let two = SourceScenarioId::try_new("test", "scenario-two").unwrap();
        let mut evidence = BASE_METRICS
            .into_iter()
            .enumerate()
            .map(|(index, metric)| {
                scoped_base(
                    metric,
                    default_base_token(metric),
                    CvssEvidenceBasis::PolicyAssertion,
                    PolicyOverlayScope::AllFindings,
                    u8::try_from(index + 1).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        evidence.extend([
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: one.clone(),
                },
                50,
            ),
            scoped_base(
                CvssBaseMetric::Ac,
                CvssMetricValueToken::H,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: one.clone(),
                },
                51,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::A,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: two.clone(),
                },
                52,
            ),
            scoped_base(
                CvssBaseMetric::Ac,
                CvssMetricValueToken::L,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::SourceScenario {
                    scenario_id: two.clone(),
                },
                53,
            ),
        ]);

        let forward = sealed_assessment(&evidence, &[one.clone(), two.clone()]);
        evidence.reverse();
        let reverse = sealed_assessment(&evidence, &[two, one]);
        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reverse).unwrap()
        );
    }

    #[test]
    fn evidence_record_budget_is_enforced_across_all_variant_provenance() {
        let (policy, finding) = test_policy_and_finding();
        let group = |policy_hash: u8, analyst_hash: u8| {
            let evidence = vec![
                scoped_base(
                    CvssBaseMetric::Av,
                    CvssMetricValueToken::N,
                    CvssEvidenceBasis::PolicyAssertion,
                    PolicyOverlayScope::AllFindings,
                    policy_hash,
                ),
                scoped_base(
                    CvssBaseMetric::Av,
                    CvssMetricValueToken::N,
                    CvssEvidenceBasis::AnalystOverride,
                    PolicyOverlayScope::AllFindings,
                    analyst_hash,
                ),
            ];
            let outcome = reduce_one(&evidence, &policy, finding, None);
            OutcomeGroup {
                key: outcome.key(),
                scenarios: Vec::new(),
                outcome,
            }
        };
        let first = group(80, 81);
        let second = group(82, 83);
        let budget = PolicyBudget::builder()
            .with_max_cvss_evidence_records_per_finding(3)
            .unwrap()
            .build()
            .unwrap();

        assert!(evidence_records_fit_budget(
            std::slice::from_ref(&first),
            &budget
        ));
        assert!(evidence_records_fit_budget(
            std::slice::from_ref(&second),
            &budget
        ));
        assert!(!evidence_records_fit_budget(&[first, second], &budget));
    }

    #[test]
    fn preexisting_shared_reference_consumes_no_new_cvss_slot() {
        let (policy, finding) = test_policy_and_finding();
        let evidence = vec![
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::AllFindings,
                84,
            ),
            scoped_base(
                CvssBaseMetric::Ac,
                CvssMetricValueToken::L,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::AllFindings,
                85,
            ),
        ];
        let outcome = reduce_one(&evidence, &policy, finding, None);
        let group = OutcomeGroup {
            key: outcome.key(),
            scenarios: Vec::new(),
            outcome,
        };
        let preexisting = EvidenceRef::try_new("cvss-test", "evidence-84").unwrap();
        let budget = PolicyBudget::builder()
            .with_max_evidence_refs_per_finding(1)
            .unwrap()
            .build()
            .unwrap();
        let retention =
            EvidenceRefRetention::for_groups(&[group], std::slice::from_ref(&preexisting), &budget)
                .unwrap();

        assert_eq!(retention.retained, vec![preexisting]);
        assert_eq!(
            retention.omitted,
            vec![EvidenceRef::try_new("cvss-test", "evidence-85").unwrap()]
        );
    }

    #[test]
    fn synthetic_policy_scenario_scopes_are_not_reported_as_runtime_overlays() {
        let (policy, finding) = test_policy_and_finding();
        let scenario = SourceScenarioId::try_new("test", "policy-scenario").unwrap();
        let evidence = vec![scoped_base(
            CvssBaseMetric::Av,
            CvssMetricValueToken::N,
            CvssEvidenceBasis::PolicyAssertion,
            PolicyOverlayScope::SourceScenario {
                scenario_id: scenario.clone(),
            },
            86,
        )];
        let outcome = reduce_one(&evidence, &policy, finding, Some(&scenario));
        let group = OutcomeGroup {
            key: outcome.key(),
            scenarios: vec![scenario.clone()],
            outcome,
        };
        let budget = PolicyBudget::default();
        let retention =
            EvidenceRefRetention::for_groups(std::slice::from_ref(&group), &[], &budget).unwrap();
        let variant = seal_group(
            VulnerabilityIdentity::from_bytes([94; 32]),
            SourceScenarioSetHash::try_from_scenarios(vec![scenario]).unwrap(),
            group,
            &retention.retained,
        )
        .unwrap();
        let CvssAssessment::Unscored { provenance, .. } = variant.assessment() else {
            panic!("one metric cannot score");
        };
        assert!(provenance.overlay_scopes().is_empty());
    }

    #[test]
    fn display_reference_caps_do_not_change_conflict_or_variant_identity() {
        let (policy, finding) = test_policy_and_finding();
        let evidence = vec![
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::N,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::AllFindings,
                70,
            ),
            scoped_base(
                CvssBaseMetric::Av,
                CvssMetricValueToken::A,
                CvssEvidenceBasis::AnalystOverride,
                PolicyOverlayScope::AllFindings,
                71,
            ),
        ];
        let outcome = reduce_one(&evidence, &policy, finding, None);
        let vulnerability = VulnerabilityIdentity::from_bytes([92; 32]);
        let scenario_set_hash = empty_source_scenario_set_hash();
        let group = || OutcomeGroup {
            key: outcome.key(),
            scenarios: Vec::new(),
            outcome: outcome.clone(),
        };
        let low_budget = PolicyBudget::builder()
            .with_max_evidence_refs_per_finding(1)
            .unwrap()
            .build()
            .unwrap();
        let low_group = group();
        let low_retention =
            EvidenceRefRetention::for_groups(std::slice::from_ref(&low_group), &[], &low_budget)
                .unwrap();
        let low = seal_group(
            vulnerability,
            scenario_set_hash,
            low_group,
            &low_retention.retained,
        )
        .unwrap();
        let high_group = group();
        let high_retention = EvidenceRefRetention::for_groups(
            std::slice::from_ref(&high_group),
            &[],
            &PolicyBudget::default(),
        )
        .unwrap();
        let high = seal_group(
            vulnerability,
            scenario_set_hash,
            high_group,
            &high_retention.retained,
        )
        .unwrap();

        assert_eq!(low.id(), high.id());
        let conflict = |variant: &CvssAssessmentVariant| {
            let CvssAssessment::Unscored { reasons, .. } = variant.assessment() else {
                panic!("conflicting evidence must remain unscored");
            };
            reasons
                .iter()
                .find_map(|reason| match reason {
                    CvssUnscoredReason::ConflictingMetricEvidence {
                        evidence_set_hash,
                        evidence_refs_truncated,
                        ..
                    } => Some((*evidence_set_hash, *evidence_refs_truncated)),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(conflict(&low).0, conflict(&high).0);
        assert!(conflict(&low).1);
        assert!(!conflict(&high).1);
        assert_eq!(low_retention.omitted.len(), 1);
        let mut retained_refs = Vec::new();
        low.assessment().append_evidence_refs(&mut retained_refs);
        retained_refs.sort();
        retained_refs.dedup();
        assert_eq!(retained_refs.len(), 1);
    }
}
