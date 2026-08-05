use super::*;

pub(super) fn validate_overlay_evidence(
    basis: CvssEvidenceBasis,
    metric: CvssMetric,
    value: CvssMetricValue,
    metadata: &CvssOverlayEvidenceMetadata,
) -> Result<CvssEvidenceContentHash, CvssEvidenceError> {
    let content_hash = overlay_content_hash(basis, metric, value, metadata);
    CvssMetricEvidence::try_new(
        metric,
        value,
        basis,
        metadata.evidence_refs.clone(),
        metadata.rationale.clone(),
        metadata.assumptions.clone(),
        metadata.assessor_or_tool.clone(),
        Some(metadata.assessed_at.clone()),
        metadata.system_scope,
        content_hash,
    )
    .map_err(CvssEvidenceError::InvalidMetricEvidence)?;
    Ok(content_hash)
}

pub(super) fn overlay_content_hash(
    basis: CvssEvidenceBasis,
    metric: CvssMetric,
    value: CvssMetricValue,
    metadata: &CvssOverlayEvidenceMetadata,
) -> CvssEvidenceContentHash {
    let mut hasher = Sha256::new();
    update_hash(&mut hasher, CVSS_OVERLAY_HASH_DOMAIN);
    update_hash(&mut hasher, cvss_evidence_basis_label(basis).as_bytes());
    update_hash(&mut hasher, metric.first_label().as_bytes());
    update_hash(&mut hasher, value.first_label().as_bytes());
    for evidence_ref in &metadata.evidence_refs {
        update_hash(&mut hasher, evidence_ref.as_str().as_bytes());
    }
    update_hash(&mut hasher, metadata.rationale.as_bytes());
    for assumption in &metadata.assumptions {
        update_hash(&mut hasher, assumption.as_bytes());
    }
    update_hash(&mut hasher, metadata.assessor_or_tool.as_bytes());
    update_hash(&mut hasher, metadata.assessed_at.as_bytes());
    let (scope_type, system) = cvss_evidence_scope_labels(metadata.system_scope);
    update_hash(&mut hasher, scope_type.as_bytes());
    if let Some(system) = system {
        update_hash(&mut hasher, system.as_bytes());
    }
    if let Some(hash) = metadata.external_artifact_hash {
        update_hash(&mut hasher, hash.as_bytes());
    }
    CvssEvidenceContentHash::from_bytes(hasher.finalize().into())
}

pub(super) const fn cvss_evidence_basis_label(basis: CvssEvidenceBasis) -> &'static str {
    match basis {
        CvssEvidenceBasis::StaticWitness => "static_witness",
        CvssEvidenceBasis::PolicyAssertion => "policy_assertion",
        CvssEvidenceBasis::EnvironmentProfile => "environment_profile",
        CvssEvidenceBasis::ThreatFeed => "threat_feed",
        CvssEvidenceBasis::AnalystOverride => "analyst_override",
    }
}

pub(super) const fn cvss_evidence_scope_labels(
    scope: CvssEvidenceScope,
) -> (&'static str, Option<&'static str>) {
    match scope {
        CvssEvidenceScope::Global => ("global", None),
        CvssEvidenceScope::System {
            system: CvssSystemScope::VulnerableSystem,
        } => ("system", Some("vulnerable_system")),
        CvssEvidenceScope::System {
            system: CvssSystemScope::SubsequentSystem,
        } => ("system", Some("subsequent_system")),
    }
}
