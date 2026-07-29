//! Domain-separated identities for CVSS evidence and coherent variants.

use sha2::{Digest, Sha256};

use super::{
    CvssAssessment, CvssAssessmentVariantId, CvssEvidenceContentHash, CvssEvidenceSetHash,
    CvssUnscoredReason, SourceScenarioSetHash, VulnerabilityIdentity,
};

const EVIDENCE_SET_DOMAIN: &[u8] = b"bifrost-cvss-evidence-set/v1";
const VARIANT_DOMAIN: &[u8] = b"bifrost-policy-cvss-variant/v1";

pub(super) fn evidence_set_hash(
    hashes: impl IntoIterator<Item = CvssEvidenceContentHash>,
) -> CvssEvidenceSetHash {
    let mut hashes = hashes.into_iter().collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes.dedup();

    let mut hasher = Sha256::new();
    update_field(&mut hasher, EVIDENCE_SET_DOMAIN);
    update_count(&mut hasher, hashes.len());
    for hash in hashes {
        update_field(&mut hasher, hash.as_bytes());
    }
    CvssEvidenceSetHash::from_bytes(hasher.finalize().into())
}

pub(super) fn variant_id(
    vulnerability: VulnerabilityIdentity,
    scenario_set_hash: SourceScenarioSetHash,
    assessment: &CvssAssessment,
) -> CvssAssessmentVariantId {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, VARIANT_DOMAIN);
    update_field(&mut hasher, vulnerability.as_bytes());
    update_field(&mut hasher, scenario_set_hash.as_bytes());

    let mut content_hashes = assessment
        .metric_evidence()
        .map(|evidence| evidence.content_hash())
        .collect::<Vec<_>>();
    content_hashes.sort_unstable();
    content_hashes.dedup();
    update_count(&mut hasher, content_hashes.len());
    for hash in content_hashes {
        update_field(&mut hasher, hash.as_bytes());
    }

    // Shadowed evidence remains part of the exact scenario correlation even
    // though it cannot change the selected vector. Bind the complete
    // applicable semantic evidence set into the variant identity so scenarios
    // with different shadowed assertions cannot be merged or assigned the
    // same ID. Display references are intentionally absent from this hash.
    let provenance = match assessment {
        CvssAssessment::Scored { provenance, .. } | CvssAssessment::Unscored { provenance, .. } => {
            provenance
        }
    };
    let provenance_evidence_set_hash =
        evidence_set_hash(provenance.content_hashes().iter().copied());
    update_field(&mut hasher, provenance_evidence_set_hash.as_bytes());

    match assessment {
        CvssAssessment::Scored { vector, .. } => {
            update_field(&mut hasher, b"scored");
            update_field(&mut hasher, vector.as_bytes());
        }
        CvssAssessment::Unscored { reasons, .. } => {
            update_field(&mut hasher, b"unscored");
            update_count(&mut hasher, reasons.len());
            for reason in reasons {
                hash_unscored_reason(&mut hasher, reason);
            }
        }
    }

    CvssAssessmentVariantId::from_bytes(hasher.finalize().into())
}

fn hash_unscored_reason(hasher: &mut Sha256, reason: &CvssUnscoredReason) {
    match reason {
        CvssUnscoredReason::MissingBaseEvidence => update_field(hasher, b"missing-base"),
        CvssUnscoredReason::ConflictingMetricEvidence {
            metric,
            evidence_set_hash,
            ..
        } => {
            update_field(hasher, b"conflicting-metric");
            update_field(hasher, metric.first_label().as_bytes());
            update_field(hasher, evidence_set_hash.as_bytes());
        }
        CvssUnscoredReason::IncoherentScenario {
            scenario_set_hash, ..
        } => {
            update_field(hasher, b"incoherent-scenario");
            update_field(hasher, scenario_set_hash.as_bytes());
        }
        CvssUnscoredReason::RunIncomplete { reason } => {
            update_field(hasher, b"run-incomplete");
            update_field(hasher, incomplete_reason_label(*reason));
        }
    }
}

const fn incomplete_reason_label(reason: super::PolicyIncompleteReason) -> &'static [u8] {
    use super::PolicyIncompleteReason as R;
    match reason {
        R::Cancelled => b"cancelled",
        R::QueryResultLimit => b"query-result-limit",
        R::BatchFindingLimit => b"batch-finding-limit",
        R::ScannedFileBudget => b"scanned-file-budget",
        R::SourceByteBudget => b"source-byte-budget",
        R::FactNodeBudget => b"fact-node-budget",
        R::PipelineRowBudget => b"pipeline-row-budget",
        R::ImportGraphBudget => b"import-graph-budget",
        R::ReferenceCandidateBudget => b"reference-candidate-budget",
        R::PartialDiscovery => b"partial-discovery",
        R::CapabilityIncomplete => b"capability-incomplete",
        R::EndpointDominanceUndecidable => b"endpoint-dominance-undecidable",
        R::StableAnchorUnavailable => b"stable-anchor-unavailable",
        R::ReportRetentionBudget => b"report-retention-budget",
        R::CvssVariantBudget => b"cvss-variant-budget",
        R::ProjectionScenarioMembershipBudget => b"projection-scenario-membership-budget",
        R::OrganizationalRiskOverlayBudget => b"organizational-risk-overlay-budget",
    }
}

fn update_count(hasher: &mut Sha256, count: usize) {
    let count = u64::try_from(count).unwrap_or(u64::MAX);
    update_field(hasher, &count.to_be_bytes());
}

pub(super) fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_set_hash_is_order_and_duplicate_independent() {
        let one = CvssEvidenceContentHash::from_bytes([1; 32]);
        let two = CvssEvidenceContentHash::from_bytes([2; 32]);
        assert_eq!(
            evidence_set_hash([one, two, one]),
            evidence_set_hash([two, one])
        );
        assert_ne!(evidence_set_hash([one]), evidence_set_hash([two]));
    }
}
