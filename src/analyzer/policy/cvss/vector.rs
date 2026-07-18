//! Canonical CVSS v4 vector construction and RustSec-backed scoring.
//!
//! The policy reducer owns evidence selection and coherence. This module owns
//! the narrower boundary from one coherent metric set to canonical FIRST
//! vectors, component projections, scores, nomenclatures, and severities.

use std::fmt::Write as _;
use std::str::FromStr as _;

use cvss::Severity as RustSecSeverity;
use cvss::v4::{Nomenclature as RustSecNomenclature, Vector as RustSecVector};

use super::{
    CvssComponentResult, CvssMetricEvidence, CvssNomenclature, CvssSeverity, CvssValidationError,
    metric_rank,
};
use crate::analyzer::policy::definition::{
    CvssEnvironmentalOrSupplementalMetric, CvssMetric, CvssMetricValue, CvssMetricValueToken,
};

const METRIC_COUNT: usize = 32;

/// RustSec-derived vectors for one coherent metric set.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ScoredVectors {
    pub(super) full_vector: String,
    pub(super) nomenclature: CvssNomenclature,
    pub(super) components: Vec<CvssComponentResult>,
}

/// Construct, canonicalize, and score the full vector and every applicable
/// B/BT/BE/BTE component projection.
///
/// Multiple evidence records may corroborate the same metric value. They
/// collapse to one vector atom. Different values for one metric are not a
/// coherent input and fail closed; the reducer must branch or retain an
/// unscored conflict before calling this function.
pub(super) fn score_metrics(
    metrics: &[CvssMetricEvidence],
) -> Result<ScoredVectors, CvssValidationError> {
    let selected = select_metric_values(metrics)?;
    let full = score_projection(&selected, Projection::Full)?;

    let has_threat = selected.iter().flatten().any(|(metric, value)| {
        matches!(metric_group(*metric), MetricGroup::Threat) && !is_not_defined(*value)
    });
    let has_environmental = selected.iter().flatten().any(|(metric, value)| {
        matches!(metric_group(*metric), MetricGroup::Environmental) && !is_not_defined(*value)
    });

    let mut components = Vec::with_capacity(match (has_threat, has_environmental) {
        (true, true) => 4,
        (true, false) | (false, true) => 2,
        (false, false) => 1,
    });
    components.push(component(&selected, Projection::Base)?);
    if has_threat {
        components.push(component(&selected, Projection::BaseThreat)?);
    }
    if has_environmental {
        components.push(component(&selected, Projection::BaseEnvironmental)?);
    }
    if has_threat && has_environmental {
        components.push(component(&selected, Projection::BaseThreatEnvironmental)?);
    }

    Ok(ScoredVectors {
        full_vector: full.vector,
        nomenclature: full.nomenclature,
        components,
    })
}

/// Recompute a scored assessment and require its full vector and complete
/// component set to match exactly. The returned value is the full vector's
/// RustSec-derived nomenclature, allowing the report layer to validate its
/// stored nomenclature without trusting it as input.
pub(super) fn validate_scored_vectors(
    full_vector: &str,
    components: &[CvssComponentResult],
    metrics: &[CvssMetricEvidence],
) -> Result<CvssNomenclature, CvssValidationError> {
    let expected = score_metrics(metrics)?;
    if full_vector != expected.full_vector || components != expected.components {
        return Err(CvssValidationError::InvalidVector);
    }
    Ok(expected.nomenclature)
}

/// Require one component's canonical vector, nomenclature, score, and
/// severity to agree with RustSec's CVSS v4 implementation.
pub(super) fn validate_component_values(
    nomenclature: CvssNomenclature,
    vector: &str,
    score: f64,
    severity: CvssSeverity,
) -> Result<(), CvssValidationError> {
    super::validate_score(score, severity)?;
    let computed = parse_and_score(vector)?;
    if computed.vector != vector || computed.nomenclature != nomenclature {
        return Err(CvssValidationError::InvalidVector);
    }
    if computed.score != score || computed.severity != severity {
        return Err(CvssValidationError::InvalidScore);
    }
    Ok(())
}

type SelectedMetrics = [Option<(CvssMetric, CvssMetricValue)>; METRIC_COUNT];

fn select_metric_values(
    evidence: &[CvssMetricEvidence],
) -> Result<SelectedMetrics, CvssValidationError> {
    let mut selected = [None; METRIC_COUNT];
    for item in evidence {
        let metric = item.metric();
        let value = item.value();
        let slot = &mut selected[usize::from(metric_rank(metric))];
        match slot {
            Some((selected_metric, selected_value))
                if *selected_metric != metric || *selected_value != value =>
            {
                return Err(CvssValidationError::InvalidVector);
            }
            Some(_) => {}
            None => *slot = Some((metric, value)),
        }
    }
    Ok(selected)
}

fn component(
    selected: &SelectedMetrics,
    projection: Projection,
) -> Result<CvssComponentResult, CvssValidationError> {
    let scored = score_projection(selected, projection)?;
    CvssComponentResult::try_new(
        scored.nomenclature,
        scored.vector,
        scored.score,
        scored.severity,
    )
}

fn score_projection(
    selected: &SelectedMetrics,
    projection: Projection,
) -> Result<CanonicalScoredVector, CvssValidationError> {
    let mut vector = String::from("CVSS:4.0");
    for &(metric, value) in selected.iter().flatten() {
        let group = metric_group(metric);
        if !projection.includes(group) || (group != MetricGroup::Base && is_not_defined(value)) {
            continue;
        }
        write!(vector, "/{}:{}", metric.first_label(), value.first_label())
            .expect("writing to a String is infallible");
    }
    parse_and_score(&vector)
}

fn parse_and_score(vector: &str) -> Result<CanonicalScoredVector, CvssValidationError> {
    let parsed = RustSecVector::from_str(vector).map_err(|_| CvssValidationError::InvalidVector)?;
    let score = parsed.score();
    let severity = map_severity(score.clone().severity());
    Ok(CanonicalScoredVector {
        vector: parsed.to_string(),
        nomenclature: map_nomenclature(parsed.nomenclature()),
        score: score.value(),
        severity,
    })
}

#[derive(Debug, Clone, PartialEq)]
struct CanonicalScoredVector {
    vector: String,
    nomenclature: CvssNomenclature,
    score: f64,
    severity: CvssSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Projection {
    Full,
    Base,
    BaseThreat,
    BaseEnvironmental,
    BaseThreatEnvironmental,
}

impl Projection {
    const fn includes(self, group: MetricGroup) -> bool {
        match self {
            Self::Full => true,
            Self::Base => matches!(group, MetricGroup::Base),
            Self::BaseThreat => matches!(group, MetricGroup::Base | MetricGroup::Threat),
            Self::BaseEnvironmental => {
                matches!(group, MetricGroup::Base | MetricGroup::Environmental)
            }
            Self::BaseThreatEnvironmental => {
                matches!(
                    group,
                    MetricGroup::Base | MetricGroup::Threat | MetricGroup::Environmental
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricGroup {
    Base,
    Threat,
    Environmental,
    Supplemental,
}

const fn metric_group(metric: CvssMetric) -> MetricGroup {
    match metric {
        CvssMetric::Base { .. } => MetricGroup::Base,
        CvssMetric::Threat { .. } => MetricGroup::Threat,
        CvssMetric::EnvironmentalOrSupplemental { metric } => match metric {
            CvssEnvironmentalOrSupplementalMetric::Cr
            | CvssEnvironmentalOrSupplementalMetric::Ir
            | CvssEnvironmentalOrSupplementalMetric::Ar
            | CvssEnvironmentalOrSupplementalMetric::Mav
            | CvssEnvironmentalOrSupplementalMetric::Mac
            | CvssEnvironmentalOrSupplementalMetric::Mat
            | CvssEnvironmentalOrSupplementalMetric::Mpr
            | CvssEnvironmentalOrSupplementalMetric::Mui
            | CvssEnvironmentalOrSupplementalMetric::Mvc
            | CvssEnvironmentalOrSupplementalMetric::Mvi
            | CvssEnvironmentalOrSupplementalMetric::Mva
            | CvssEnvironmentalOrSupplementalMetric::Msc
            | CvssEnvironmentalOrSupplementalMetric::Msi
            | CvssEnvironmentalOrSupplementalMetric::Msa => MetricGroup::Environmental,
            CvssEnvironmentalOrSupplementalMetric::S
            | CvssEnvironmentalOrSupplementalMetric::Au
            | CvssEnvironmentalOrSupplementalMetric::R
            | CvssEnvironmentalOrSupplementalMetric::V
            | CvssEnvironmentalOrSupplementalMetric::Re
            | CvssEnvironmentalOrSupplementalMetric::U => MetricGroup::Supplemental,
        },
    }
}

const fn is_not_defined(value: CvssMetricValue) -> bool {
    matches!(value.token(), CvssMetricValueToken::X)
}

const fn map_nomenclature(value: RustSecNomenclature) -> CvssNomenclature {
    match value {
        RustSecNomenclature::CvssB => CvssNomenclature::B,
        RustSecNomenclature::CvssBT => CvssNomenclature::BT,
        RustSecNomenclature::CvssBE => CvssNomenclature::BE,
        RustSecNomenclature::CvssBTE => CvssNomenclature::BTE,
    }
}

const fn map_severity(value: RustSecSeverity) -> CvssSeverity {
    match value {
        RustSecSeverity::None => CvssSeverity::None,
        RustSecSeverity::Low => CvssSeverity::Low,
        RustSecSeverity::Medium => CvssSeverity::Medium,
        RustSecSeverity::High => CvssSeverity::High,
        RustSecSeverity::Critical => CvssSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::cvss::{
        CvssEvidenceBasis, CvssEvidenceContentHash, required_scope,
    };
    use crate::analyzer::policy::definition::{
        CvssBaseMetric as B, CvssEnvironmentalOrSupplementalMetric as ES, CvssThreatMetric as T,
    };
    use crate::analyzer::policy::finding_identity::EvidenceRef;

    fn base(metric: B) -> CvssMetric {
        CvssMetric::Base { metric }
    }

    fn threat() -> CvssMetric {
        CvssMetric::Threat { metric: T::E }
    }

    fn environmental(metric: ES) -> CvssMetric {
        CvssMetric::EnvironmentalOrSupplemental { metric }
    }

    fn evidence(values: &[(CvssMetric, CvssMetricValueToken)]) -> Vec<CvssMetricEvidence> {
        values
            .iter()
            .enumerate()
            .map(|(index, &(metric, token))| {
                let basis = match metric_group(metric) {
                    MetricGroup::Base => CvssEvidenceBasis::PolicyAssertion,
                    MetricGroup::Threat => CvssEvidenceBasis::ThreatFeed,
                    MetricGroup::Environmental | MetricGroup::Supplemental => {
                        CvssEvidenceBasis::EnvironmentProfile
                    }
                };
                CvssMetricEvidence::try_new(
                    metric,
                    CvssMetricValue::try_new(metric, token).unwrap(),
                    basis,
                    vec![EvidenceRef::try_new("cvss", format!("metric-{index}")).unwrap()],
                    "Pinned CVSS vector evidence".to_string(),
                    Vec::new(),
                    "bifrost-test".to_string(),
                    None,
                    required_scope(metric),
                    CvssEvidenceContentHash::from_bytes([u8::try_from(index + 1).unwrap(); 32]),
                )
                .unwrap()
            })
            .collect()
    }

    fn assert_projection(
        values: &[(CvssMetric, CvssMetricValueToken)],
        expected_vector: &str,
        expected_nomenclature: CvssNomenclature,
        expected_score: f64,
        expected_severity: CvssSeverity,
    ) {
        let metrics = evidence(values);
        let scored = score_metrics(&metrics).unwrap();
        assert_eq!(scored.full_vector, expected_vector);
        assert_eq!(scored.nomenclature, expected_nomenclature);
        let named = scored
            .components
            .iter()
            .find(|component| component.nomenclature() == expected_nomenclature)
            .unwrap();
        assert_eq!(named.vector(), expected_vector);
        assert_eq!(named.score(), expected_score);
        assert_eq!(named.severity(), expected_severity);
        assert_eq!(
            validate_scored_vectors(expected_vector, &scored.components, &metrics).unwrap(),
            expected_nomenclature
        );
    }

    #[test]
    fn scores_pinned_first_vectors_through_typed_evidence() {
        assert_projection(
            &[
                (base(B::Av), CvssMetricValueToken::L),
                (base(B::Ac), CvssMetricValueToken::L),
                (base(B::At), CvssMetricValueToken::P),
                (base(B::Pr), CvssMetricValueToken::L),
                (base(B::Ui), CvssMetricValueToken::N),
                (base(B::Vc), CvssMetricValueToken::H),
                (base(B::Vi), CvssMetricValueToken::H),
                (base(B::Va), CvssMetricValueToken::H),
                (base(B::Sc), CvssMetricValueToken::N),
                (base(B::Si), CvssMetricValueToken::N),
                (base(B::Sa), CvssMetricValueToken::N),
            ],
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            CvssNomenclature::B,
            7.3,
            CvssSeverity::High,
        );
        assert_projection(
            &[
                (base(B::Av), CvssMetricValueToken::N),
                (base(B::Ac), CvssMetricValueToken::L),
                (base(B::At), CvssMetricValueToken::P),
                (base(B::Pr), CvssMetricValueToken::N),
                (base(B::Ui), CvssMetricValueToken::P),
                (base(B::Vc), CvssMetricValueToken::H),
                (base(B::Vi), CvssMetricValueToken::H),
                (base(B::Va), CvssMetricValueToken::H),
                (base(B::Sc), CvssMetricValueToken::N),
                (base(B::Si), CvssMetricValueToken::N),
                (base(B::Sa), CvssMetricValueToken::N),
                (threat(), CvssMetricValueToken::U),
            ],
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
            CvssNomenclature::BT,
            5.2,
            CvssSeverity::Medium,
        );
        assert_projection(
            &[
                (base(B::Av), CvssMetricValueToken::N),
                (base(B::Ac), CvssMetricValueToken::L),
                (base(B::At), CvssMetricValueToken::P),
                (base(B::Pr), CvssMetricValueToken::N),
                (base(B::Ui), CvssMetricValueToken::N),
                (base(B::Vc), CvssMetricValueToken::H),
                (base(B::Vi), CvssMetricValueToken::L),
                (base(B::Va), CvssMetricValueToken::L),
                (base(B::Sc), CvssMetricValueToken::N),
                (base(B::Si), CvssMetricValueToken::N),
                (base(B::Sa), CvssMetricValueToken::N),
                (environmental(ES::Cr), CvssMetricValueToken::H),
                (environmental(ES::Ir), CvssMetricValueToken::L),
                (environmental(ES::Ar), CvssMetricValueToken::L),
                (environmental(ES::Mav), CvssMetricValueToken::N),
                (environmental(ES::Mac), CvssMetricValueToken::H),
                (environmental(ES::Mvc), CvssMetricValueToken::H),
                (environmental(ES::Mvi), CvssMetricValueToken::L),
                (environmental(ES::Mva), CvssMetricValueToken::L),
            ],
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
            CvssNomenclature::BE,
            8.1,
            CvssSeverity::High,
        );
        assert_projection(
            &[
                (base(B::Av), CvssMetricValueToken::N),
                (base(B::Ac), CvssMetricValueToken::H),
                (base(B::At), CvssMetricValueToken::P),
                (base(B::Pr), CvssMetricValueToken::N),
                (base(B::Ui), CvssMetricValueToken::N),
                (base(B::Vc), CvssMetricValueToken::H),
                (base(B::Vi), CvssMetricValueToken::H),
                (base(B::Va), CvssMetricValueToken::H),
                (base(B::Sc), CvssMetricValueToken::N),
                (base(B::Si), CvssMetricValueToken::N),
                (base(B::Sa), CvssMetricValueToken::N),
                (threat(), CvssMetricValueToken::P),
                (environmental(ES::Mac), CvssMetricValueToken::L),
                (environmental(ES::Mat), CvssMetricValueToken::N),
                (environmental(ES::Mvc), CvssMetricValueToken::N),
                (environmental(ES::Mvi), CvssMetricValueToken::N),
                (environmental(ES::Mva), CvssMetricValueToken::L),
            ],
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L",
            CvssNomenclature::BTE,
            5.5,
            CvssSeverity::Medium,
        );
    }

    #[test]
    fn scores_complete_all_none_impacts_as_zero() {
        assert_projection(
            &[
                (base(B::Av), CvssMetricValueToken::N),
                (base(B::Ac), CvssMetricValueToken::L),
                (base(B::At), CvssMetricValueToken::N),
                (base(B::Pr), CvssMetricValueToken::N),
                (base(B::Ui), CvssMetricValueToken::N),
                (base(B::Vc), CvssMetricValueToken::N),
                (base(B::Vi), CvssMetricValueToken::N),
                (base(B::Va), CvssMetricValueToken::N),
                (base(B::Sc), CvssMetricValueToken::N),
                (base(B::Si), CvssMetricValueToken::N),
                (base(B::Sa), CvssMetricValueToken::N),
            ],
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            CvssNomenclature::B,
            0.0,
            CvssSeverity::None,
        );
    }

    #[test]
    fn omits_x_and_keeps_supplemental_metrics_out_of_components() {
        let values = [
            (base(B::Av), CvssMetricValueToken::N),
            (base(B::Ac), CvssMetricValueToken::L),
            (base(B::At), CvssMetricValueToken::N),
            (base(B::Pr), CvssMetricValueToken::N),
            (base(B::Ui), CvssMetricValueToken::N),
            (base(B::Vc), CvssMetricValueToken::N),
            (base(B::Vi), CvssMetricValueToken::N),
            (base(B::Va), CvssMetricValueToken::N),
            (base(B::Sc), CvssMetricValueToken::N),
            (base(B::Si), CvssMetricValueToken::N),
            (base(B::Sa), CvssMetricValueToken::N),
            (threat(), CvssMetricValueToken::X),
            (environmental(ES::Cr), CvssMetricValueToken::X),
            (environmental(ES::Mav), CvssMetricValueToken::X),
            (environmental(ES::S), CvssMetricValueToken::X),
            (environmental(ES::Au), CvssMetricValueToken::Y),
            (environmental(ES::U), CvssMetricValueToken::Red),
        ];
        let scored = score_metrics(&evidence(&values)).unwrap();
        assert_eq!(
            scored.full_vector,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/AU:Y/U:Red"
        );
        assert_eq!(scored.nomenclature, CvssNomenclature::B);
        assert_eq!(scored.components.len(), 1);
        assert_eq!(
            scored.components[0].vector(),
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        );
    }

    #[test]
    fn emits_every_applicable_component_without_supplemental_metrics() {
        let values = [
            (base(B::Av), CvssMetricValueToken::N),
            (base(B::Ac), CvssMetricValueToken::H),
            (base(B::At), CvssMetricValueToken::P),
            (base(B::Pr), CvssMetricValueToken::N),
            (base(B::Ui), CvssMetricValueToken::N),
            (base(B::Vc), CvssMetricValueToken::H),
            (base(B::Vi), CvssMetricValueToken::H),
            (base(B::Va), CvssMetricValueToken::H),
            (base(B::Sc), CvssMetricValueToken::N),
            (base(B::Si), CvssMetricValueToken::N),
            (base(B::Sa), CvssMetricValueToken::N),
            (threat(), CvssMetricValueToken::P),
            (environmental(ES::Mac), CvssMetricValueToken::L),
            (environmental(ES::Mat), CvssMetricValueToken::N),
            (environmental(ES::Mvc), CvssMetricValueToken::N),
            (environmental(ES::Mvi), CvssMetricValueToken::N),
            (environmental(ES::Mva), CvssMetricValueToken::L),
            (environmental(ES::S), CvssMetricValueToken::P),
        ];
        let scored = score_metrics(&evidence(&values)).unwrap();
        assert_eq!(scored.components.len(), 4);
        assert_eq!(
            scored
                .components
                .iter()
                .map(CvssComponentResult::nomenclature)
                .collect::<Vec<_>>(),
            [
                CvssNomenclature::B,
                CvssNomenclature::BT,
                CvssNomenclature::BE,
                CvssNomenclature::BTE,
            ]
        );
        assert!(scored.full_vector.ends_with("/S:P"));
        assert!(
            scored
                .components
                .iter()
                .all(|component| !component.vector().contains("/S:P"))
        );
    }

    #[test]
    fn canonical_order_is_independent_of_evidence_order() {
        let canonical = [
            (base(B::Av), CvssMetricValueToken::N),
            (base(B::Ac), CvssMetricValueToken::L),
            (base(B::At), CvssMetricValueToken::P),
            (base(B::Pr), CvssMetricValueToken::N),
            (base(B::Ui), CvssMetricValueToken::P),
            (base(B::Vc), CvssMetricValueToken::H),
            (base(B::Vi), CvssMetricValueToken::H),
            (base(B::Va), CvssMetricValueToken::H),
            (base(B::Sc), CvssMetricValueToken::N),
            (base(B::Si), CvssMetricValueToken::N),
            (base(B::Sa), CvssMetricValueToken::N),
            (threat(), CvssMetricValueToken::U),
        ];
        let mut reversed = canonical;
        reversed.reverse();

        assert_eq!(
            score_metrics(&evidence(&canonical)).unwrap(),
            score_metrics(&evidence(&reversed)).unwrap()
        );
        assert_eq!(
            validate_component_values(
                CvssNomenclature::BT,
                "CVSS:4.0/AC:L/AV:N/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
                5.2,
                CvssSeverity::Medium,
            ),
            Err(CvssValidationError::InvalidVector)
        );
    }

    #[test]
    fn rejects_incomplete_or_conflicting_metric_sets_and_tampered_results() {
        let mut values = vec![(base(B::Av), CvssMetricValueToken::N)];
        assert_eq!(
            score_metrics(&evidence(&values)),
            Err(CvssValidationError::InvalidVector)
        );

        values.extend([
            (base(B::Ac), CvssMetricValueToken::L),
            (base(B::At), CvssMetricValueToken::N),
            (base(B::Pr), CvssMetricValueToken::N),
            (base(B::Ui), CvssMetricValueToken::N),
            (base(B::Vc), CvssMetricValueToken::N),
            (base(B::Vi), CvssMetricValueToken::N),
            (base(B::Va), CvssMetricValueToken::N),
            (base(B::Sc), CvssMetricValueToken::N),
            (base(B::Si), CvssMetricValueToken::N),
            (base(B::Sa), CvssMetricValueToken::N),
            (base(B::Av), CvssMetricValueToken::L),
        ]);
        assert_eq!(
            score_metrics(&evidence(&values)),
            Err(CvssValidationError::InvalidVector)
        );

        values.pop();
        let metrics = evidence(&values);
        let scored = score_metrics(&metrics).unwrap();
        let mut tampered = scored.components.clone();
        tampered.pop();
        assert_eq!(
            validate_scored_vectors(&scored.full_vector, &tampered, &metrics),
            Err(CvssValidationError::InvalidVector)
        );
        assert_eq!(
            validate_component_values(
                CvssNomenclature::B,
                scored.components[0].vector(),
                9.9,
                CvssSeverity::Critical,
            ),
            Err(CvssValidationError::InvalidScore)
        );
    }
}
