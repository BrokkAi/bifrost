//! Crate-owned authority for diagnostic-neutral taint and typestate projections.
//!
//! Analysis adapters may claim solver exhaustion and emit raw projection facts,
//! but they cannot construct report findings or runs.  The evaluator mints an
//! authority from one exact [`LoadedPolicy`], passes it to an in-crate adapter,
//! and validates every returned fact against the captured resolved model before
//! any report-domain value is assembled.  The authority is a drift/forgery
//! boundary; it is deliberately not described as a proof that a solver really
//! exhausted its state space.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::budget::PolicyBudget;
use super::definition::{PolicyAnalysisType, PolicyId, PolicyReportOptions};
use super::finding::{
    BoundedWitness, FindingCertainty, FindingCompleteness, FindingIncompleteReason,
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyFailureReason, PolicyIncompleteReason, PolicyRunCompletion, PolicySourceLocation,
    PolicyWorkReport, ProofMetadata, ProofState, RelatedPolicyLocation,
    insert_policy_diagnostic_bounded, normalize_policy_diagnostics_bounded,
};
use super::finding_identity::{
    AnalysisEventRef, AnalysisFindingId, AnalysisSubjectRef, EvidenceRef, FindingIdentityStability,
    PolicyFindingId, SourceScenarioId, WitnessId,
};
use super::future_evidence::{
    FutureEvidenceError, ResolvedTypestateTerminal, TaintFindingAnchor, TaintOriginEvidence,
    TaintPolicyProjectionFacts, TaintProjectionFactsHash, TypestateBindingPlanHash,
    TypestateFindingAnchor, TypestatePolicyProjectionFacts, TypestateProjectionFactsHash,
    TypestateProtocolHash, TypestateViolationEvidence, typestate_violation_hash,
};
use super::identity::{PolicySemanticHash, TypestateAuthoringProjectionHash};
use super::resolved::{
    LoadedPolicy, ResolvedEndpointIdentity, ResolvedTaintPolicySpec, ResolvedTypestateEventTrigger,
    ResolvedTypestatePolicySpec, ResolvedTypestateTerminalTrigger,
};

/// The sealing supertraits are crate-visible so #824 can implement an adapter,
/// but downstream crates cannot self-register as a trusted analysis producer.
pub(crate) mod sealed {
    pub trait TaintAdapter {}
    pub trait TypestateAdapter {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionSeal {
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    authoring_projection_hash: Option<TypestateAuthoringProjectionHash>,
    protocol_hash: Option<TypestateProtocolHash>,
    binding_plan_hash: Option<TypestateBindingPlanHash>,
}

/// Exact loaded taint model captured before invoking an adapter.
pub(crate) struct TaintProjectionAuthority<'a> {
    seal: ProjectionSeal,
    spec: &'a ResolvedTaintPolicySpec,
    report: &'a PolicyReportOptions,
}

impl<'a> TaintProjectionAuthority<'a> {
    pub(crate) fn from_loaded(policy: &'a LoadedPolicy) -> Result<Self, ProjectionAuthorityError> {
        let spec = policy.resolved_taint().ok_or(
            ProjectionAuthorityError::MissingResolvedSpecification {
                analysis_type: PolicyAnalysisType::Taint,
            },
        )?;
        Ok(Self {
            seal: ProjectionSeal {
                policy_id: policy.definition().metadata.id.clone(),
                policy_hash: policy.semantic_hash(),
                analysis_type: PolicyAnalysisType::Taint,
                authoring_projection_hash: None,
                protocol_hash: None,
                binding_plan_hash: None,
            },
            spec,
            report: &policy.definition().report,
        })
    }

    /// Seal one adapter result to this exact loaded-policy authority.
    ///
    /// Projection batch fields remain private so an in-crate adapter can only
    /// return a batch by using the authority supplied for the current run.
    pub(crate) fn seal_batch(&self, payload: TaintProjectionPayload) -> TaintProjectionBatch {
        let TaintProjectionPayload {
            projections,
            completion,
            diagnostics,
            diagnostics_truncated,
            work,
        } = payload;
        TaintProjectionBatch {
            seal: self.seal.clone(),
            projections,
            completion,
            diagnostics,
            diagnostics_truncated,
            work,
        }
    }
}

/// Exact loaded typestate model plus the hashes minted by the in-crate #824
/// compiler for that model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypestateCompilationHashes {
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
}

impl TypestateCompilationHashes {
    /// Bind the two domain-separated compiler outputs into the typed claim
    /// accepted by the typestate evaluator seam.
    pub(crate) const fn new(
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
    ) -> Self {
        Self {
            protocol_hash,
            binding_plan_hash,
        }
    }

    pub(crate) const fn protocol_hash(self) -> TypestateProtocolHash {
        self.protocol_hash
    }

    pub(crate) const fn binding_plan_hash(self) -> TypestateBindingPlanHash {
        self.binding_plan_hash
    }
}

pub(crate) struct TypestateProjectionAuthority<'a> {
    seal: ProjectionSeal,
    spec: &'a ResolvedTypestatePolicySpec,
    report: &'a PolicyReportOptions,
}

impl<'a> TypestateProjectionAuthority<'a> {
    pub(crate) fn from_loaded_compilation(
        policy: &'a LoadedPolicy,
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
    ) -> Result<Self, ProjectionAuthorityError> {
        let compilation = TypestateCompilationHashes::new(protocol_hash, binding_plan_hash);
        let spec = policy.resolved_typestate().ok_or(
            ProjectionAuthorityError::MissingResolvedSpecification {
                analysis_type: PolicyAnalysisType::Typestate,
            },
        )?;
        Ok(Self {
            seal: ProjectionSeal {
                policy_id: policy.definition().metadata.id.clone(),
                policy_hash: policy.semantic_hash(),
                analysis_type: PolicyAnalysisType::Typestate,
                authoring_projection_hash: Some(spec.authoring_projection_hash),
                protocol_hash: Some(compilation.protocol_hash()),
                binding_plan_hash: Some(compilation.binding_plan_hash()),
            },
            spec,
            report: &policy.definition().report,
        })
    }

    pub(crate) fn protocol_hash(&self) -> TypestateProtocolHash {
        self.seal
            .protocol_hash
            .expect("typestate authority always captures a protocol hash")
    }

    pub(crate) fn binding_plan_hash(&self) -> TypestateBindingPlanHash {
        self.seal
            .binding_plan_hash
            .expect("typestate authority always captures a binding-plan hash")
    }

    /// Seal one adapter result to this exact loaded-policy and compilation
    /// authority.
    pub(crate) fn seal_batch(
        &self,
        payload: TypestateProjectionPayload,
    ) -> TypestateProjectionBatch {
        let TypestateProjectionPayload {
            projections,
            completion,
            diagnostics,
            diagnostics_truncated,
            work,
        } = payload;
        TypestateProjectionBatch {
            seal: self.seal.clone(),
            projections,
            completion,
            diagnostics,
            diagnostics_truncated,
            work,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct EffectiveReportLimits {
    origins_per_finding: usize,
    witnesses_per_finding: usize,
    witness_steps: usize,
    witness_bytes: usize,
}

impl EffectiveReportLimits {
    fn new(report: &PolicyReportOptions, budget: &PolicyBudget) -> Self {
        Self {
            origins_per_finding: report
                .origins_per_finding
                .min(budget.max_origins_per_finding()),
            witnesses_per_finding: report
                .witnesses_per_finding
                .min(budget.max_witnesses_per_finding()),
            witness_steps: report.witness.max_steps.min(budget.max_witness_steps()),
            witness_bytes: report.witness.max_bytes.min(budget.max_witness_bytes()),
        }
    }
}

/// Diagnostic-neutral report facts which an analysis adapter must establish;
/// policy presentation, classification, CVSS, organizational risk, finding
/// identity, and run construction remain crate-owned.
#[derive(Debug, Clone)]
pub(crate) struct ProjectedFindingReport {
    pub(crate) primary: PolicySourceLocation,
    pub(crate) certainty: FindingCertainty,
    pub(crate) completeness: FindingCompleteness,
    pub(crate) related: Vec<RelatedPolicyLocation>,
    pub(crate) related_truncated: bool,
    pub(crate) omitted_related_locations_lower_bound: u64,
    pub(crate) evidence_refs_truncated: bool,
    pub(crate) omitted_evidence_refs_lower_bound: u64,
    pub(crate) proof: ProofMetadata,
    pub(crate) witnesses: Vec<BoundedWitness>,
    pub(crate) witnesses_truncated: bool,
    pub(crate) omitted_witnesses_lower_bound: u64,
}

/// One adapter-established taint origin. It is intentionally not final report
/// evidence: authority validation still joins it to one exact pair-local source
/// fact before constructing [`TaintOriginEvidence`].
#[derive(Debug, Clone)]
pub(crate) struct TaintOriginProjection {
    pub(crate) source_endpoint: ResolvedEndpointIdentity,
    pub(crate) source_label: super::definition::TaintLabel,
    pub(crate) source_evidence: Option<super::definition::TaintSourceEvidence>,
    pub(crate) primary: PolicySourceLocation,
    pub(crate) scenario_id: SourceScenarioId,
    pub(crate) evidence_refs: Vec<EvidenceRef>,
}

/// Analysis evidence for exactly one source endpoint at the aggregate sink
/// meeting. A taint envelope carries one such row for every source endpoint;
/// authority validation flattens these to one pair-local finding candidate.
#[derive(Debug, Clone)]
pub(crate) struct TaintPairProjection {
    pub(crate) source_endpoint: ResolvedEndpointIdentity,
    pub(crate) analysis_finding_id: AnalysisFindingId,
    pub(crate) anchor: TaintFindingAnchor,
    /// Opaque run-local event provenance. The sealed #824 adapter asserts that
    /// this ref and the strong anchor name the same sink event; #709 can verify
    /// the anchor path/common stable identity but cannot derive a semantic site
    /// from an opaque ref.
    pub(crate) sink: AnalysisEventRef,
    pub(crate) origins: Vec<TaintOriginProjection>,
    pub(crate) origins_truncated: bool,
    pub(crate) witness_refs: Vec<WitnessId>,
    pub(crate) witness_refs_truncated: bool,
    pub(crate) report: ProjectedFindingReport,
}

/// One dominance-resolved sink meeting and the exact analysis evidence needed
/// to turn each of its source endpoint partitions into a report finding.
#[derive(Debug, Clone)]
pub(crate) struct TaintProjectedFinding {
    pub(crate) facts: TaintPolicyProjectionFacts,
    pub(crate) pairs: Vec<TaintPairProjection>,
}

/// One diagnostic-neutral typestate violation plus every analysis-owned field
/// needed for final policy finding assembly.
#[derive(Debug, Clone)]
pub(crate) struct TypestateProjectedFinding {
    pub(crate) facts: TypestatePolicyProjectionFacts,
    pub(crate) analysis_finding_id: AnalysisFindingId,
    pub(crate) anchor: TypestateFindingAnchor,
    /// Opaque run-local subject provenance. The sealed compiler/adapter binds
    /// it to `facts.source_endpoint` under the exact `binding_plan_hash`.
    /// #709 independently verifies that compiled hash, the resolved endpoint,
    /// and event/expectation applicability; the opaque ref itself has no
    /// semantic fields from which to reconstruct that binding.
    pub(crate) subject: AnalysisSubjectRef,
    pub(crate) witness_refs: Vec<WitnessId>,
    pub(crate) witness_refs_truncated: bool,
    pub(crate) report: ProjectedFindingReport,
}

/// Unsealed taint adapter output. The production evaluator binds this payload
/// to its freshly minted authority before validation and assembly.
pub(crate) struct TaintProjectionPayload {
    pub(crate) projections: Vec<TaintProjectedFinding>,
    pub(crate) completion: PolicyRunCompletion,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) work: PolicyWorkReport,
}

/// Unsealed typestate adapter output. It deliberately carries no policy or
/// compilation seal; only the evaluator-owned authority can add one.
pub(crate) struct TypestateProjectionPayload {
    pub(crate) projections: Vec<TypestateProjectedFinding>,
    pub(crate) completion: PolicyRunCompletion,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) work: PolicyWorkReport,
}

/// Raw adapter output for one taint evaluation.
///
/// `completion` is the adapter's explicit exhaustion claim.  Bifrost still
/// downgrades it for every rejection, omission, weak anchor, truncation, and
/// report budget event observed during projection and retention.
pub(crate) struct TaintProjectionBatch {
    seal: ProjectionSeal,
    projections: Vec<TaintProjectedFinding>,
    completion: PolicyRunCompletion,
    diagnostics: Vec<PolicyDiagnostic>,
    diagnostics_truncated: bool,
    work: PolicyWorkReport,
}

/// Raw adapter output for one typestate evaluation.
pub(crate) struct TypestateProjectionBatch {
    seal: ProjectionSeal,
    projections: Vec<TypestateProjectedFinding>,
    completion: PolicyRunCompletion,
    diagnostics: Vec<PolicyDiagnostic>,
    diagnostics_truncated: bool,
    work: PolicyWorkReport,
}

pub(crate) struct ValidatedTaintProjectionBatch {
    pub(crate) projections: Vec<ValidatedTaintPairProjection>,
    pub(crate) completion: PolicyRunCompletion,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) work: PolicyWorkReport,
}

pub(crate) struct ValidatedTypestateProjectionBatch {
    pub(crate) projections: Vec<ValidatedTypestateProjection>,
    pub(crate) completion: PolicyRunCompletion,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) work: PolicyWorkReport,
}

#[derive(Debug)]
pub(crate) struct ValidatedTaintPairProjection {
    pub(crate) facts: TaintPolicyProjectionFacts,
    pub(crate) analysis_finding_id: AnalysisFindingId,
    pub(crate) anchor: TaintFindingAnchor,
    pub(crate) sink: AnalysisEventRef,
    pub(crate) origins: Vec<TaintOriginEvidence>,
    pub(crate) origins_truncated: bool,
    pub(crate) witness_refs: Vec<WitnessId>,
    pub(crate) witness_refs_truncated: bool,
    pub(crate) report: ProjectedFindingReport,
}

#[derive(Debug)]
pub(crate) struct ValidatedTypestateProjection {
    pub(crate) facts: TypestatePolicyProjectionFacts,
    pub(crate) analysis_finding_id: AnalysisFindingId,
    pub(crate) anchor: TypestateFindingAnchor,
    pub(crate) subject: AnalysisSubjectRef,
    pub(crate) witness_refs: Vec<WitnessId>,
    pub(crate) witness_refs_truncated: bool,
    pub(crate) report: ProjectedFindingReport,
}

pub(crate) fn validate_taint_batch(
    authority: &TaintProjectionAuthority<'_>,
    mut batch: TaintProjectionBatch,
    budget: &PolicyBudget,
) -> Result<ValidatedTaintProjectionBatch, ProjectionAuthorityError> {
    if batch.seal != authority.seal {
        return Err(ProjectionAuthorityError::AuthorityMismatch);
    }
    let mut completion = batch.completion;
    let mut diagnostics = batch.diagnostics;
    let mut diagnostics_truncated = batch.diagnostics_truncated;
    if normalize_policy_diagnostics_bounded(&mut diagnostics, budget.max_diagnostics()) {
        diagnostics_truncated = true;
        downgrade_completion(
            &mut completion,
            PolicyIncompleteReason::ReportRetentionBudget,
        );
    }
    for projection in &mut batch.projections {
        projection.pairs.sort_by(|left, right| {
            left.source_endpoint
                .cmp(&right.source_endpoint)
                .then_with(|| {
                    PolicyFindingId::from_taint_anchor(&authority.seal.policy_id, &left.anchor).cmp(
                        &PolicyFindingId::from_taint_anchor(
                            &authority.seal.policy_id,
                            &right.anchor,
                        ),
                    )
                })
        });
    }
    batch.projections.sort_by(|left, right| {
        taint_envelope_sort_key(authority, left).cmp(&taint_envelope_sort_key(authority, right))
    });
    let raw_projection_count = batch.projections.len();
    let (unique_projections, duplicate_finding_ids, had_duplicate_projections) =
        reject_duplicate_taint_envelopes(authority, batch.projections);
    batch.projections = unique_projections;
    let processing_limit = budget.max_findings();
    let mut projections = Vec::with_capacity(raw_projection_count.min(processing_limit));
    let bounded_omissions = batch.projections.len() > processing_limit;
    let mut omitted_finding_ids = duplicate_finding_ids;
    for projection in batch.projections.iter().skip(processing_limit) {
        omitted_finding_ids.extend(taint_projection_finding_ids(authority, projection));
    }
    if had_duplicate_projections {
        record_rejection(
            ProjectionAuthorityError::DuplicateProjectionIdentity,
            &mut diagnostics,
            &mut diagnostics_truncated,
            &mut completion,
            budget,
        );
    }
    if bounded_omissions {
        record_rejection(
            ProjectionAuthorityError::ProjectionCountBudget {
                max_items: processing_limit,
            },
            &mut diagnostics,
            &mut diagnostics_truncated,
            &mut completion,
            budget,
        );
    }
    let report_limits = EffectiveReportLimits::new(authority.report, budget);
    for projection in batch.projections.into_iter().take(processing_limit) {
        let candidate_finding_ids = taint_projection_finding_ids(authority, &projection);
        match validate_taint_projection(authority, projection, budget, report_limits) {
            Ok(validated) => {
                omitted_finding_ids.extend(validated.omitted_finding_ids);
                for error in validated.rejections {
                    record_rejection(
                        error,
                        &mut diagnostics,
                        &mut diagnostics_truncated,
                        &mut completion,
                        budget,
                    );
                }
                if let Some(mut pairs) = validated.value {
                    pairs.sort_by_key(|projection| {
                        super::finding_identity::PolicyFindingId::from_taint_anchor(
                            &authority.seal.policy_id,
                            &projection.anchor,
                        )
                    });
                    for projection in pairs {
                        let finding_id = PolicyFindingId::from_taint_anchor(
                            &authority.seal.policy_id,
                            &projection.anchor,
                        );
                        if projections.len() >= budget.max_findings() {
                            omitted_finding_ids.insert(finding_id);
                            record_rejection(
                                ProjectionAuthorityError::ProjectionCountBudget {
                                    max_items: budget.max_findings(),
                                },
                                &mut diagnostics,
                                &mut diagnostics_truncated,
                                &mut completion,
                                budget,
                            );
                            continue;
                        }
                        if projection.anchor.stability() == FindingIdentityStability::Weak {
                            record_weak_anchor(
                                &mut diagnostics,
                                &mut diagnostics_truncated,
                                &mut completion,
                                budget,
                            );
                        }
                        projections.push(projection);
                    }
                }
            }
            Err(error) => {
                omitted_finding_ids.extend(candidate_finding_ids);
                record_rejection(
                    error,
                    &mut diagnostics,
                    &mut diagnostics_truncated,
                    &mut completion,
                    budget,
                );
            }
        }
    }
    if diagnostics_truncated {
        downgrade_completion(
            &mut completion,
            PolicyIncompleteReason::ReportRetentionBudget,
        );
    }
    for projection in &projections {
        omitted_finding_ids.remove(&PolicyFindingId::from_taint_anchor(
            &authority.seal.policy_id,
            &projection.anchor,
        ));
    }
    let mut work = batch.work;
    work.set_retention(
        0,
        work.omitted_findings_lower_bound()
            .saturating_add(u64::try_from(omitted_finding_ids.len()).unwrap_or(u64::MAX)),
        0,
    );
    Ok(ValidatedTaintProjectionBatch {
        projections,
        completion,
        diagnostics,
        diagnostics_truncated,
        work,
    })
}

pub(crate) fn validate_typestate_batch(
    authority: &TypestateProjectionAuthority<'_>,
    mut batch: TypestateProjectionBatch,
    budget: &PolicyBudget,
) -> Result<ValidatedTypestateProjectionBatch, ProjectionAuthorityError> {
    if batch.seal != authority.seal {
        return Err(ProjectionAuthorityError::AuthorityMismatch);
    }
    let mut completion = batch.completion;
    let mut diagnostics = batch.diagnostics;
    let mut diagnostics_truncated = batch.diagnostics_truncated;
    if normalize_policy_diagnostics_bounded(&mut diagnostics, budget.max_diagnostics()) {
        diagnostics_truncated = true;
        downgrade_completion(
            &mut completion,
            PolicyIncompleteReason::ReportRetentionBudget,
        );
    }
    batch.projections.sort_by(|left, right| {
        typestate_envelope_sort_key(authority, left)
            .cmp(&typestate_envelope_sort_key(authority, right))
    });
    let raw_projection_count = batch.projections.len();
    let (unique_projections, duplicate_finding_ids, had_duplicate_projections) =
        reject_duplicate_typestate_envelopes(authority, batch.projections);
    batch.projections = unique_projections;
    let processing_limit = budget.max_findings();
    let mut projections = Vec::with_capacity(raw_projection_count.min(processing_limit));
    let bounded_omissions = batch.projections.len() > processing_limit;
    let mut omitted_finding_ids = duplicate_finding_ids;
    for projection in batch.projections.iter().skip(processing_limit) {
        omitted_finding_ids.insert(PolicyFindingId::from_typestate_anchor(
            &authority.seal.policy_id,
            &projection.anchor,
        ));
    }
    if had_duplicate_projections {
        record_rejection(
            ProjectionAuthorityError::DuplicateProjectionIdentity,
            &mut diagnostics,
            &mut diagnostics_truncated,
            &mut completion,
            budget,
        );
    }
    if bounded_omissions {
        record_rejection(
            ProjectionAuthorityError::ProjectionCountBudget {
                max_items: processing_limit,
            },
            &mut diagnostics,
            &mut diagnostics_truncated,
            &mut completion,
            budget,
        );
    }
    let report_limits = EffectiveReportLimits::new(authority.report, budget);
    for projection in batch.projections.into_iter().take(processing_limit) {
        let candidate_finding_id =
            PolicyFindingId::from_typestate_anchor(&authority.seal.policy_id, &projection.anchor);
        match validate_typestate_projection(authority, projection, budget, report_limits) {
            Ok(projection) if projections.len() < budget.max_findings() => {
                if projection.anchor.stability() == FindingIdentityStability::Weak {
                    record_weak_anchor(
                        &mut diagnostics,
                        &mut diagnostics_truncated,
                        &mut completion,
                        budget,
                    );
                }
                projections.push(projection);
            }
            Ok(_) => {
                omitted_finding_ids.insert(candidate_finding_id);
                record_rejection(
                    ProjectionAuthorityError::ProjectionCountBudget {
                        max_items: budget.max_findings(),
                    },
                    &mut diagnostics,
                    &mut diagnostics_truncated,
                    &mut completion,
                    budget,
                );
            }
            Err(error) => {
                omitted_finding_ids.insert(candidate_finding_id);
                record_rejection(
                    error,
                    &mut diagnostics,
                    &mut diagnostics_truncated,
                    &mut completion,
                    budget,
                );
            }
        }
    }
    if diagnostics_truncated {
        downgrade_completion(
            &mut completion,
            PolicyIncompleteReason::ReportRetentionBudget,
        );
    }
    for projection in &projections {
        omitted_finding_ids.remove(&PolicyFindingId::from_typestate_anchor(
            &authority.seal.policy_id,
            &projection.anchor,
        ));
    }
    let mut work = batch.work;
    work.set_retention(
        0,
        work.omitted_findings_lower_bound()
            .saturating_add(u64::try_from(omitted_finding_ids.len()).unwrap_or(u64::MAX)),
        0,
    );
    Ok(ValidatedTypestateProjectionBatch {
        projections,
        completion,
        diagnostics,
        diagnostics_truncated,
        work,
    })
}

fn taint_envelope_sort_key(
    authority: &TaintProjectionAuthority<'_>,
    projection: &TaintProjectedFinding,
) -> (TaintProjectionFactsHash, Vec<PolicyFindingId>) {
    let mut finding_ids = projection
        .pairs
        .iter()
        .map(|pair| PolicyFindingId::from_taint_anchor(&authority.seal.policy_id, &pair.anchor))
        .collect::<Vec<_>>();
    finding_ids.sort();
    (projection.facts.semantic_hash, finding_ids)
}

fn taint_projection_finding_ids(
    authority: &TaintProjectionAuthority<'_>,
    projection: &TaintProjectedFinding,
) -> HashSet<PolicyFindingId> {
    projection
        .pairs
        .iter()
        .map(|pair| PolicyFindingId::from_taint_anchor(&authority.seal.policy_id, &pair.anchor))
        .collect()
}

fn typestate_envelope_sort_key(
    authority: &TypestateProjectionAuthority<'_>,
    projection: &TypestateProjectedFinding,
) -> (TypestateProjectionFactsHash, PolicyFindingId) {
    (
        projection.facts.semantic_hash,
        PolicyFindingId::from_typestate_anchor(&authority.seal.policy_id, &projection.anchor),
    )
}

fn reject_duplicate_taint_envelopes(
    authority: &TaintProjectionAuthority<'_>,
    projections: Vec<TaintProjectedFinding>,
) -> (Vec<TaintProjectedFinding>, HashSet<PolicyFindingId>, bool) {
    let mut retained = Vec::with_capacity(projections.len());
    let mut rejected = HashSet::new();
    let mut rejected_duplicates = false;
    let mut projections = projections.into_iter().peekable();
    while let Some(projection) = projections.next() {
        let key = taint_envelope_sort_key(authority, &projection);
        let mut has_duplicate = false;
        while projections
            .peek()
            .is_some_and(|next| taint_envelope_sort_key(authority, next) == key)
        {
            projections.next();
            has_duplicate = true;
        }
        if has_duplicate {
            rejected_duplicates = true;
            rejected.extend(key.1);
        } else {
            retained.push(projection);
        }
    }
    (retained, rejected, rejected_duplicates)
}

fn reject_duplicate_typestate_envelopes(
    authority: &TypestateProjectionAuthority<'_>,
    projections: Vec<TypestateProjectedFinding>,
) -> (
    Vec<TypestateProjectedFinding>,
    HashSet<PolicyFindingId>,
    bool,
) {
    let mut retained = Vec::with_capacity(projections.len());
    let mut rejected = HashSet::new();
    let mut rejected_duplicates = false;
    let mut projections = projections.into_iter().peekable();
    while let Some(projection) = projections.next() {
        let key = typestate_envelope_sort_key(authority, &projection);
        let mut has_duplicate = false;
        while projections
            .peek()
            .is_some_and(|next| typestate_envelope_sort_key(authority, next) == key)
        {
            projections.next();
            has_duplicate = true;
        }
        if has_duplicate {
            rejected_duplicates = true;
            rejected.insert(key.1);
        } else {
            retained.push(projection);
        }
    }
    (retained, rejected, rejected_duplicates)
}

fn validate_taint_projection(
    authority: &TaintProjectionAuthority<'_>,
    mut projection: TaintProjectedFinding,
    budget: &PolicyBudget,
    report_limits: EffectiveReportLimits,
) -> Result<PartialProjection<Vec<ValidatedTaintPairProjection>>, ProjectionAuthorityError> {
    let normalized_facts = projection
        .facts
        .try_normalized(budget)
        .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?;
    let mut expected_endpoints = normalized_facts
        .source_facts
        .iter()
        .map(|fact| fact.source_endpoint.clone())
        .collect::<Vec<_>>();
    expected_endpoints.sort();
    expected_endpoints.dedup();
    projection
        .pairs
        .sort_by(|left, right| left.source_endpoint.cmp(&right.source_endpoint));
    if projection.pairs.len() != expected_endpoints.len()
        || projection
            .pairs
            .iter()
            .map(|pair| &pair.source_endpoint)
            .ne(expected_endpoints.iter())
    {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "taint_pair_coverage",
        });
    }
    if let Some(first) = projection.pairs.first()
        && projection
            .pairs
            .iter()
            .skip(1)
            .any(|pair| pair.sink != first.sink || pair.report.primary != first.report.primary)
    {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "taint_common_sink",
        });
    }
    let mut strong_sink_identity = None;
    for pair in &projection.pairs {
        if let Some(strong) = pair.anchor.strong_fields() {
            if strong.sink_identity().path().as_str() != pair.report.primary.path() {
                return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                    field: "taint_sink_anchor_path",
                });
            }
            match strong_sink_identity {
                Some(expected) if expected != strong.sink_identity() => {
                    return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                        field: "taint_common_sink_identity",
                    });
                }
                None => strong_sink_identity = Some(strong.sink_identity()),
                Some(_) => {}
            }
        }
    }

    let PartialTaintFacts {
        value: validated_facts,
        mut rejections,
        invalid_source_endpoints,
    } = validate_taint_facts(authority, normalized_facts, budget)?;
    let mut pairs_by_endpoint = projection
        .pairs
        .into_iter()
        .map(|pair| (pair.source_endpoint.clone(), pair))
        .collect::<HashMap<_, _>>();
    let mut omitted_finding_ids = HashSet::new();
    for source_endpoint in invalid_source_endpoints {
        if let Some(pair) = pairs_by_endpoint.remove(&source_endpoint) {
            omitted_finding_ids.insert(PolicyFindingId::from_taint_anchor(
                &authority.seal.policy_id,
                &pair.anchor,
            ));
        }
    }
    let Some(validated_facts) = validated_facts else {
        return Ok(PartialProjection {
            value: None,
            rejections,
            omitted_finding_ids,
        });
    };
    let mut retained_endpoints = validated_facts
        .source_facts
        .iter()
        .map(|fact| fact.source_endpoint.clone())
        .collect::<Vec<_>>();
    retained_endpoints.sort();
    retained_endpoints.dedup();
    let mut validated_pairs =
        Vec::with_capacity(retained_endpoints.len().min(budget.max_findings()));
    for source_endpoint in retained_endpoints {
        let Some(pair) = pairs_by_endpoint.remove(&source_endpoint) else {
            rejections.push(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_pair_coverage_after_validation",
            });
            continue;
        };
        let finding_id =
            PolicyFindingId::from_taint_anchor(&authority.seal.policy_id, &pair.anchor);
        let source_facts = validated_facts
            .source_facts
            .iter()
            .filter(|fact| fact.source_endpoint == source_endpoint)
            .cloned()
            .collect::<Vec<_>>();
        let reached_source_labels = source_facts
            .iter()
            .map(|fact| fact.source_label.clone())
            .collect::<Vec<_>>();
        let pair_facts = TaintPolicyProjectionFacts::try_new(
            validated_facts.sink_endpoint.clone(),
            validated_facts.sink_endpoint_semantic_hash,
            validated_facts.sink_endpoint_analysis_projection_hash,
            validated_facts.sink_display_name.clone(),
            validated_facts.sink_categories.clone(),
            validated_facts.sink_tags.clone(),
            validated_facts.sink_impacts.clone(),
            reached_source_labels,
            source_facts,
            budget,
        )
        .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?;
        match validate_taint_pair(pair_facts, pair, budget, report_limits) {
            Ok(pair) => validated_pairs.push(pair),
            Err(error) => {
                omitted_finding_ids.insert(finding_id);
                rejections.push(error);
            }
        }
    }
    Ok(PartialProjection {
        value: (!validated_pairs.is_empty()).then_some(validated_pairs),
        rejections,
        omitted_finding_ids,
    })
}

fn validate_taint_pair(
    facts: TaintPolicyProjectionFacts,
    mut pair: TaintPairProjection,
    budget: &PolicyBudget,
    report_limits: EffectiveReportLimits,
) -> Result<ValidatedTaintPairProjection, ProjectionAuthorityError> {
    if pair.source_endpoint != facts.source_facts[0].source_endpoint {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "taint_pair_source_endpoint",
        });
    }
    let mut scenarios = facts
        .source_facts
        .iter()
        .flat_map(|fact| fact.source_scenario_ids.iter().cloned())
        .collect::<Vec<_>>();
    scenarios.sort();
    scenarios.dedup();
    let scenario_set_hash =
        super::cvss::SourceScenarioSetHash::try_from_scenarios(scenarios.clone())
            .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?;
    if let Some(anchor) = pair.anchor.strong_fields()
        && (anchor.source_endpoint_analysis_projection_hash()
            != facts.source_facts[0].source_endpoint_analysis_projection_hash
            || anchor.sink_endpoint_analysis_projection_hash()
                != facts.sink_endpoint_analysis_projection_hash
            || anchor.source_scenario_set_hash() != scenario_set_hash)
    {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "taint_anchor",
        });
    }

    if pair.origins.len() > report_limits.origins_per_finding {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "origins",
            limit: report_limits.origins_per_finding,
        });
    }
    let mut distinct_evidence_refs = HashSet::new();
    for origin in &pair.origins {
        if origin.evidence_refs.len() > budget.max_evidence_refs_per_finding() {
            return Err(ProjectionAuthorityError::ReportBudgetExceeded {
                field: "origin_evidence_refs",
                limit: budget.max_evidence_refs_per_finding(),
            });
        }
        for reference in &origin.evidence_refs {
            distinct_evidence_refs.insert(reference.clone());
        }
    }
    validate_projected_evidence_ref_budget(
        &pair.report,
        distinct_evidence_refs,
        budget,
        report_limits,
    )?;
    let mut expected_origin_memberships = facts
        .source_facts
        .iter()
        .flat_map(|fact| {
            fact.source_scenario_ids
                .iter()
                .cloned()
                .map(|scenario| (fact.source_label.clone(), scenario))
        })
        .collect::<HashSet<_>>();
    let fact_by_membership = facts
        .source_facts
        .iter()
        .flat_map(|fact| {
            fact.source_scenario_ids
                .iter()
                .cloned()
                .map(move |scenario| ((fact.source_label.clone(), scenario), fact))
        })
        .collect::<HashMap<_, _>>();
    let mut origins = Vec::with_capacity(pair.origins.len());
    for origin in pair.origins {
        if origin.source_endpoint != pair.source_endpoint {
            return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_origin_source_endpoint",
            });
        }
        let membership = (origin.source_label.clone(), origin.scenario_id.clone());
        let Some(source_fact) = fact_by_membership.get(&membership).copied() else {
            return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_origin_scenario_label",
            });
        };
        if source_fact.source_evidence != origin.source_evidence {
            return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_origin_source_evidence",
            });
        }
        if !origin.evidence_refs.contains(&source_fact.evidence_ref) {
            return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_origin_evidence_reference",
            });
        }
        if !expected_origin_memberships.remove(&membership) {
            return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "duplicate_taint_origin_membership",
            });
        }
        origins.push(
            TaintOriginEvidence::try_new(
                origin.source_endpoint,
                origin.source_label,
                origin.source_evidence,
                origin.primary,
                origin.scenario_id,
                origin.evidence_refs,
            )
            .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?,
        );
    }
    if !pair.origins_truncated && !expected_origin_memberships.is_empty() {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "taint_origin_coverage",
        });
    }
    validate_witness_references(
        &pair.witness_refs,
        pair.witness_refs_truncated,
        &pair.report,
        report_limits,
    )?;
    let mut required_reasons = Vec::new();
    if pair.anchor.stability() == FindingIdentityStability::Weak {
        required_reasons.push(FindingIncompleteReason::StableAnchorWeak);
    }
    if pair.origins_truncated {
        required_reasons.push(FindingIncompleteReason::OriginsTruncated);
    }
    if pair.witness_refs_truncated {
        required_reasons.push(FindingIncompleteReason::WitnessTruncated);
    }
    pair.report = validate_projected_report(pair.report, required_reasons, budget, report_limits)?;
    Ok(ValidatedTaintPairProjection {
        facts,
        analysis_finding_id: pair.analysis_finding_id,
        anchor: pair.anchor,
        sink: pair.sink,
        origins,
        origins_truncated: pair.origins_truncated,
        witness_refs: pair.witness_refs,
        witness_refs_truncated: pair.witness_refs_truncated,
        report: pair.report,
    })
}

fn validate_typestate_projection(
    authority: &TypestateProjectionAuthority<'_>,
    mut projection: TypestateProjectedFinding,
    budget: &PolicyBudget,
    report_limits: EffectiveReportLimits,
) -> Result<ValidatedTypestateProjection, ProjectionAuthorityError> {
    validate_projected_evidence_ref_budget(
        &projection.report,
        HashSet::new(),
        budget,
        report_limits,
    )?;
    let facts = validate_typestate_facts(authority, projection.facts, budget)?;
    if let Some(anchor) = projection.anchor.strong_fields()
        && (anchor.protocol_hash() != facts.protocol_hash
            || anchor.binding_plan_hash() != facts.binding_plan_hash
            || anchor.scenario_set_hash() != facts.scenario_set_hash
            || facts.violation_site.as_ref() != Some(anchor.violation_site_identity())
            || anchor.violation_hash()
                != typestate_violation_hash(
                    &facts.violation,
                    anchor.violation_site_identity(),
                    facts.scenario_set_hash,
                ))
    {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "typestate_anchor",
        });
    }
    if let Some(site) = &facts.violation_site
        && site.path().as_str() != projection.report.primary.path()
    {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "typestate_primary_site",
        });
    }
    validate_witness_references(
        &projection.witness_refs,
        projection.witness_refs_truncated,
        &projection.report,
        report_limits,
    )?;
    let mut required_reasons = Vec::new();
    if projection.anchor.stability() == FindingIdentityStability::Weak {
        required_reasons.push(FindingIncompleteReason::StableAnchorWeak);
    }
    if projection.witness_refs_truncated {
        required_reasons.push(FindingIncompleteReason::WitnessTruncated);
    }
    projection.report =
        validate_projected_report(projection.report, required_reasons, budget, report_limits)?;
    Ok(ValidatedTypestateProjection {
        facts,
        analysis_finding_id: projection.analysis_finding_id,
        anchor: projection.anchor,
        subject: projection.subject,
        witness_refs: projection.witness_refs,
        witness_refs_truncated: projection.witness_refs_truncated,
        report: projection.report,
    })
}

fn validate_projected_evidence_ref_budget(
    report: &ProjectedFindingReport,
    mut distinct_refs: HashSet<EvidenceRef>,
    budget: &PolicyBudget,
    report_limits: EffectiveReportLimits,
) -> Result<(), ProjectionAuthorityError> {
    if report.related.len() > budget.max_related_locations_per_finding() {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "related_locations",
            limit: budget.max_related_locations_per_finding(),
        });
    }
    if report.witnesses.len() > report_limits.witnesses_per_finding {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "witnesses",
            limit: report_limits.witnesses_per_finding,
        });
    }
    let limit = budget.max_evidence_refs_per_finding();
    if distinct_refs.len() > limit {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "evidence_references",
            limit,
        });
    }
    let mut retain = |reference: &EvidenceRef| {
        distinct_refs.insert(reference.clone());
        if distinct_refs.len() > limit {
            return Err(ProjectionAuthorityError::ReportBudgetExceeded {
                field: "evidence_references",
                limit,
            });
        }
        Ok::<(), ProjectionAuthorityError>(())
    };
    for reference in report.proof.evidence_refs() {
        retain(reference)?;
    }
    for related in &report.related {
        for reference in related.evidence_refs() {
            retain(reference)?;
        }
    }
    for witness in &report.witnesses {
        for step in witness.steps() {
            for reference in step.evidence_refs() {
                retain(reference)?;
            }
        }
    }
    Ok(())
}

fn validate_projected_report(
    mut report: ProjectedFindingReport,
    mut required_reasons: Vec<FindingIncompleteReason>,
    budget: &PolicyBudget,
    report_limits: EffectiveReportLimits,
) -> Result<ProjectedFindingReport, ProjectionAuthorityError> {
    if report.related_truncated != (report.omitted_related_locations_lower_bound > 0) {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "related_location_truncation",
        });
    }
    if report.evidence_refs_truncated != (report.omitted_evidence_refs_lower_bound > 0) {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "evidence_reference_truncation",
        });
    }
    if report.witnesses_truncated != (report.omitted_witnesses_lower_bound > 0) {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "witness_truncation",
        });
    }
    if report.related.len() > budget.max_related_locations_per_finding() {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "related_locations",
            limit: budget.max_related_locations_per_finding(),
        });
    }
    if report.witnesses.len() > report_limits.witnesses_per_finding {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "witnesses",
            limit: report_limits.witnesses_per_finding,
        });
    }
    if report
        .witnesses
        .iter()
        .any(|witness| witness.steps().len() > report_limits.witness_steps)
    {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "witness_steps",
            limit: report_limits.witness_steps,
        });
    }
    if report.witnesses.iter().any(|witness| {
        usize::try_from(witness.retained_bytes()).unwrap_or(usize::MAX)
            > report_limits.witness_bytes
    }) {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "witness_bytes",
            limit: report_limits.witness_bytes,
        });
    }
    let mut witness_ids = report
        .witnesses
        .iter()
        .map(|witness| witness.id().clone())
        .collect::<Vec<_>>();
    witness_ids.sort();
    if witness_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "duplicate_witness_id",
        });
    }
    if report.related_truncated {
        required_reasons.push(FindingIncompleteReason::RelatedLocationsTruncated);
    }
    if report.evidence_refs_truncated {
        required_reasons.push(FindingIncompleteReason::EvidenceTruncated);
    }
    if report.proof.state() != ProofState::Proven {
        required_reasons.push(FindingIncompleteReason::ProofPartial);
    }
    if report.witnesses_truncated || report.witnesses.iter().any(BoundedWitness::truncated) {
        required_reasons.push(FindingIncompleteReason::WitnessTruncated);
    }
    required_reasons.extend_from_slice(report.completeness.reasons());
    required_reasons.sort();
    required_reasons.dedup();
    report.completeness = if required_reasons.is_empty() {
        FindingCompleteness::Complete
    } else {
        FindingCompleteness::partial(required_reasons).map_err(|_| {
            ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "finding_completeness",
            }
        })?
    };
    report.certainty = match report.certainty {
        FindingCertainty::Definite => FindingCertainty::Definite,
        FindingCertainty::Possible { reasons } => {
            FindingCertainty::possible(reasons).map_err(|_| {
                ProjectionAuthorityError::FindingEnvelopeMismatch {
                    field: "finding_certainty",
                }
            })?
        }
    };
    Ok(report)
}

fn validate_witness_references(
    witness_refs: &[WitnessId],
    witness_refs_truncated: bool,
    report: &ProjectedFindingReport,
    report_limits: EffectiveReportLimits,
) -> Result<(), ProjectionAuthorityError> {
    if witness_refs.len() > report_limits.witnesses_per_finding {
        return Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "witness_references",
            limit: report_limits.witnesses_per_finding,
        });
    }
    let mut refs = witness_refs.to_vec();
    refs.sort();
    let mut retained = report
        .witnesses
        .iter()
        .map(|witness| witness.id().clone())
        .collect::<Vec<_>>();
    retained.sort();
    if refs.windows(2).any(|pair| pair[0] == pair[1])
        || retained.windows(2).any(|pair| pair[0] == pair[1])
        || refs != retained
        || witness_refs_truncated != report.witnesses_truncated
    {
        return Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "witness_references",
        });
    }
    Ok(())
}

struct PartialProjection<T> {
    value: Option<T>,
    rejections: Vec<ProjectionAuthorityError>,
    omitted_finding_ids: HashSet<PolicyFindingId>,
}

struct PartialTaintFacts {
    value: Option<TaintPolicyProjectionFacts>,
    rejections: Vec<ProjectionAuthorityError>,
    invalid_source_endpoints: HashSet<ResolvedEndpointIdentity>,
}

fn validate_taint_facts(
    authority: &TaintProjectionAuthority<'_>,
    facts: TaintPolicyProjectionFacts,
    budget: &PolicyBudget,
) -> Result<PartialTaintFacts, ProjectionAuthorityError> {
    let facts = facts
        .try_normalized(budget)
        .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?;
    let sink = authority
        .spec
        .sinks
        .iter()
        .find(|sink| sink.identity == facts.sink_endpoint)
        .ok_or(ProjectionAuthorityError::UnknownTaintSink)?;
    if sink.semantic_hash != facts.sink_endpoint_semantic_hash
        || sink.analysis_projection_hash != facts.sink_endpoint_analysis_projection_hash
    {
        return Err(ProjectionAuthorityError::EndpointHashMismatch { role: "taint sink" });
    }
    if sink.definition.display_name != facts.sink_display_name
        || sink.definition.categories != facts.sink_categories
        || sink.definition.tags != facts.sink_tags
        || sink.definition.impacts != facts.sink_impacts
    {
        return Err(ProjectionAuthorityError::EndpointModelMismatch { role: "taint sink" });
    }
    if facts
        .reached_source_labels
        .iter()
        .any(|label| !sink.definition.accepts.contains(label))
    {
        return Err(ProjectionAuthorityError::SinkRejectedReachedLabel);
    }

    let mut scenario_owners = HashMap::new();
    for source_fact in &facts.source_facts {
        for scenario in &source_fact.source_scenario_ids {
            scenario_owners
                .entry(scenario.clone())
                .or_insert_with(Vec::new)
                .push(source_fact.source_endpoint.clone());
        }
    }
    let colliding_scenarios = scenario_owners
        .into_iter()
        .filter_map(|(scenario, mut owners)| {
            owners.sort();
            owners.dedup();
            (owners.len() > 1).then_some(scenario)
        })
        .collect::<HashSet<_>>();
    let mut valid_source_facts = Vec::with_capacity(facts.source_facts.len());
    let mut rejections = Vec::new();
    let mut invalid_source_endpoints = HashSet::new();
    for source_fact in facts.source_facts.iter().cloned() {
        let source_endpoint = source_fact.source_endpoint.clone();
        let source = authority
            .spec
            .sources
            .iter()
            .find(|source| source.identity == source_fact.source_endpoint)
            .ok_or(ProjectionAuthorityError::UnknownTaintSource);
        let source = match source {
            Ok(source) => source,
            Err(error) => {
                invalid_source_endpoints.insert(source_endpoint);
                rejections.push(error);
                continue;
            }
        };
        if source.semantic_hash != source_fact.source_endpoint_semantic_hash
            || source.analysis_projection_hash
                != source_fact.source_endpoint_analysis_projection_hash
        {
            invalid_source_endpoints.insert(source_endpoint);
            rejections.push(ProjectionAuthorityError::EndpointHashMismatch {
                role: "taint source",
            });
            continue;
        }
        if source.definition.display_name != source_fact.source_display_name
            || source.definition.categories != source_fact.source_categories
            || source.definition.evidence != source_fact.source_evidence
            || !source.definition.labels.contains(&source_fact.source_label)
        {
            invalid_source_endpoints.insert(source_endpoint);
            rejections.push(ProjectionAuthorityError::EndpointModelMismatch {
                role: "taint source",
            });
            continue;
        }
        let collides = source_fact
            .source_scenario_ids
            .iter()
            .any(|scenario| colliding_scenarios.contains(scenario));
        if collides {
            invalid_source_endpoints.insert(source_endpoint);
            rejections.push(ProjectionAuthorityError::SourceScenarioIdentityCollision);
            continue;
        }
        valid_source_facts.push(source_fact);
    }
    valid_source_facts.retain(|fact| !invalid_source_endpoints.contains(&fact.source_endpoint));
    if valid_source_facts.is_empty() {
        return Ok(PartialTaintFacts {
            value: None,
            rejections,
            invalid_source_endpoints,
        });
    }
    if rejections.is_empty() {
        return Ok(PartialTaintFacts {
            value: Some(facts),
            rejections,
            invalid_source_endpoints,
        });
    }
    let mut reached_source_labels = valid_source_facts
        .iter()
        .map(|fact| fact.source_label.clone())
        .collect::<Vec<_>>();
    reached_source_labels.sort();
    reached_source_labels.dedup();
    let rebuilt = TaintPolicyProjectionFacts::try_new(
        facts.sink_endpoint,
        facts.sink_endpoint_semantic_hash,
        facts.sink_endpoint_analysis_projection_hash,
        facts.sink_display_name,
        facts.sink_categories,
        facts.sink_tags,
        facts.sink_impacts,
        reached_source_labels,
        valid_source_facts,
        budget,
    )
    .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?;
    Ok(PartialTaintFacts {
        value: Some(rebuilt),
        rejections,
        invalid_source_endpoints,
    })
}

fn validate_typestate_facts(
    authority: &TypestateProjectionAuthority<'_>,
    facts: TypestatePolicyProjectionFacts,
    budget: &PolicyBudget,
) -> Result<TypestatePolicyProjectionFacts, ProjectionAuthorityError> {
    let facts = facts
        .try_normalized(budget)
        .map_err(ProjectionAuthorityError::InvalidProjectionFacts)?;
    if facts.authoring_projection_hash != authority.spec.authoring_projection_hash
        || facts.protocol_hash != authority.protocol_hash()
        || facts.binding_plan_hash != authority.binding_plan_hash()
    {
        return Err(ProjectionAuthorityError::CompiledProjectionHashMismatch);
    }
    let subject = authority
        .spec
        .subjects
        .iter()
        .find(|subject| subject.identity == facts.source_endpoint)
        .ok_or(ProjectionAuthorityError::UnknownTypestateSubject)?;
    if subject.semantic_hash != facts.source_endpoint_hash
        || subject.analysis_projection_hash != facts.source_endpoint_analysis_projection_hash
    {
        return Err(ProjectionAuthorityError::EndpointHashMismatch {
            role: "typestate subject",
        });
    }
    let dependency = authority
        .spec
        .endpoint_dependencies
        .iter()
        .find(|dependency| dependency.identity() == &facts.source_endpoint)
        .ok_or(ProjectionAuthorityError::UnknownTypestateSubject)?;
    if dependency.model().display_name != facts.source_display_name
        || dependency.model().categories != facts.source_categories
    {
        return Err(ProjectionAuthorityError::EndpointModelMismatch {
            role: "typestate subject",
        });
    }
    validate_typestate_violation(authority.spec, &facts)?;
    Ok(facts)
}

fn validate_typestate_violation(
    spec: &ResolvedTypestatePolicySpec,
    facts: &TypestatePolicyProjectionFacts,
) -> Result<(), ProjectionAuthorityError> {
    match &facts.violation {
        TypestateViolationEvidence::ErrorTransition {
            event_id,
            endpoint,
            from,
            to,
        } => {
            let event = spec
                .automaton
                .events
                .iter()
                .find(|event| &event.id == event_id)
                .ok_or(ProjectionAuthorityError::UnknownTypestateEvent)?;
            if !event.applies_to_subjects.contains(&facts.source_endpoint) {
                return Err(ProjectionAuthorityError::TypestateSubjectJoinMismatch);
            }
            let trigger_matches = match &event.trigger {
                ResolvedTypestateEventTrigger::Calls { .. }
                | ResolvedTypestateEventTrigger::SemanticEvent { .. } => endpoint.is_none(),
                ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, .. } => endpoint
                    .as_ref()
                    .is_some_and(|endpoint| endpoints.contains(endpoint)),
            };
            if !trigger_matches {
                return Err(ProjectionAuthorityError::TypestateEventJoinMismatch);
            }
            if !spec.automaton.transitions.iter().any(|transition| {
                &transition.from == from && &transition.on == event_id && &transition.to == to
            }) || !spec.automaton.error_states.contains(to)
            {
                return Err(ProjectionAuthorityError::TypestateTransitionJoinMismatch);
            }
        }
        TypestateViolationEvidence::TerminalExpectation {
            expectation_id,
            terminal,
            observed_state,
            expected_states,
        } => {
            let expectation = spec
                .automaton
                .terminal_expectations
                .iter()
                .find(|expectation| &expectation.id == expectation_id)
                .ok_or(ProjectionAuthorityError::UnknownTypestateExpectation)?;
            if !expectation
                .applies_to_subjects
                .contains(&facts.source_endpoint)
            {
                return Err(ProjectionAuthorityError::TypestateSubjectJoinMismatch);
            }
            let trigger_matches = match (&expectation.trigger, terminal) {
                (
                    ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase },
                    ResolvedTypestateTerminal::Endpoint {
                        endpoint,
                        phase: actual_phase,
                    },
                ) => phase == actual_phase && endpoints.contains(endpoint),
                (
                    ResolvedTypestateTerminalTrigger::SemanticEvent { event },
                    ResolvedTypestateTerminal::SemanticEvent {
                        event: actual_event,
                    },
                ) => event == actual_event,
                _ => false,
            };
            if !trigger_matches
                || &expectation.expected_states != expected_states
                || !spec.automaton.states.contains(observed_state)
                || expected_states.contains(observed_state)
            {
                return Err(ProjectionAuthorityError::TypestateExpectationJoinMismatch);
            }
        }
    }
    Ok(())
}

fn downgrade_completion(completion: &mut PolicyRunCompletion, reason: PolicyIncompleteReason) {
    match completion {
        PolicyRunCompletion::Complete => {
            *completion = PolicyRunCompletion::inconclusive(vec![reason])
                .expect("one typed incomplete reason is canonical");
        }
        PolicyRunCompletion::Inconclusive { reasons } => {
            reasons.push(reason);
            reasons.sort();
            reasons.dedup();
        }
        PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. } => {}
    }
}

fn record_rejection(
    error: ProjectionAuthorityError,
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    completion: &mut PolicyRunCompletion,
    budget: &PolicyBudget,
) {
    if matches!(error, ProjectionAuthorityError::DuplicateProjectionIdentity) {
        *completion = PolicyRunCompletion::Failed {
            reasons: vec![PolicyFailureReason::InternalInvariant],
        };
        let diagnostic = PolicyDiagnostic::try_new(
            PolicyDiagnosticCode::EvaluationFailure,
            PolicyDiagnosticSeverity::Error,
            PolicyDiagnosticImpact::RunFailed,
            format!("analysis projection rejected: {error}"),
            None,
            Vec::new(),
        );
        if let Ok(diagnostic) = diagnostic {
            *diagnostics_truncated |=
                insert_policy_diagnostic_bounded(diagnostics, diagnostic, budget.max_diagnostics());
        } else {
            *diagnostics_truncated = true;
        }
        return;
    }
    if matches!(
        completion,
        PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. }
    ) {
        return;
    }
    let incomplete_reason = match &error {
        ProjectionAuthorityError::ProjectionCountBudget { .. } => {
            PolicyIncompleteReason::BatchFindingLimit
        }
        ProjectionAuthorityError::ReportBudgetExceeded { .. } => {
            PolicyIncompleteReason::ReportRetentionBudget
        }
        ProjectionAuthorityError::InvalidProjectionFacts(
            FutureEvidenceError::ProjectionScenarioMembershipBudget { .. },
        ) => PolicyIncompleteReason::ProjectionScenarioMembershipBudget,
        _ => PolicyIncompleteReason::CapabilityIncomplete,
    };
    downgrade_completion(completion, incomplete_reason);
    let code = match &error {
        ProjectionAuthorityError::ProjectionCountBudget { .. } => {
            PolicyDiagnosticCode::BatchFindingLimit
        }
        ProjectionAuthorityError::ReportBudgetExceeded { .. } => {
            PolicyDiagnosticCode::ReportRetentionBudget
        }
        ProjectionAuthorityError::InvalidProjectionFacts(
            FutureEvidenceError::ProjectionScenarioMembershipBudget { .. },
        ) => PolicyDiagnosticCode::ProjectionScenarioMembershipBudget,
        _ => PolicyDiagnosticCode::EvaluationFailure,
    };
    let message = format!("analysis projection rejected: {error}");
    let diagnostic = PolicyDiagnostic::try_new(
        code,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
        None,
        Vec::new(),
    );
    if let Ok(diagnostic) = diagnostic {
        *diagnostics_truncated |=
            insert_policy_diagnostic_bounded(diagnostics, diagnostic, budget.max_diagnostics());
    } else {
        *diagnostics_truncated = true;
    }
}

fn record_weak_anchor(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    completion: &mut PolicyRunCompletion,
    budget: &PolicyBudget,
) {
    if matches!(
        completion,
        PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. }
    ) {
        return;
    }
    downgrade_completion(completion, PolicyIncompleteReason::StableAnchorUnavailable);
    record_projection_diagnostic(
        PolicyDiagnosticCode::StableAnchorUnavailable,
        "analysis projection has no stable semantic finding anchor",
        diagnostics,
        diagnostics_truncated,
        budget,
    );
}

fn record_projection_diagnostic(
    code: PolicyDiagnosticCode,
    message: &str,
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    budget: &PolicyBudget,
) {
    let diagnostic = PolicyDiagnostic::try_new(
        code,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
        None,
        Vec::new(),
    );
    if let Ok(diagnostic) = diagnostic {
        *diagnostics_truncated |=
            insert_policy_diagnostic_bounded(diagnostics, diagnostic, budget.max_diagnostics());
    } else {
        *diagnostics_truncated = true;
    }
}

#[derive(Debug)]
pub(crate) enum ProjectionAuthorityError {
    MissingResolvedSpecification { analysis_type: PolicyAnalysisType },
    AuthorityMismatch,
    InvalidProjectionFacts(FutureEvidenceError),
    FindingEnvelopeMismatch { field: &'static str },
    UnknownTaintSource,
    UnknownTaintSink,
    UnknownTypestateSubject,
    EndpointHashMismatch { role: &'static str },
    EndpointModelMismatch { role: &'static str },
    SinkRejectedReachedLabel,
    SourceScenarioIdentityCollision,
    DuplicateProjectionIdentity,
    ProjectionCountBudget { max_items: usize },
    ReportBudgetExceeded { field: &'static str, limit: usize },
    CompiledProjectionHashMismatch,
    UnknownTypestateEvent,
    UnknownTypestateExpectation,
    TypestateSubjectJoinMismatch,
    TypestateEventJoinMismatch,
    TypestateTransitionJoinMismatch,
    TypestateExpectationJoinMismatch,
}

impl fmt::Display for ProjectionAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingResolvedSpecification { analysis_type } => {
                write!(formatter, "loaded {analysis_type:?} policy is missing its resolved specification")
            }
            Self::AuthorityMismatch => formatter.write_str(
                "analysis adapter returned a projection batch sealed for another policy or compilation",
            ),
            Self::InvalidProjectionFacts(error) => write!(formatter, "invalid projection facts: {error}"),
            Self::FindingEnvelopeMismatch { field } => {
                write!(formatter, "projected finding envelope has an invalid {field} join")
            }
            Self::UnknownTaintSource => formatter.write_str("projection names an unknown taint source"),
            Self::UnknownTaintSink => formatter.write_str("projection names an unknown taint sink"),
            Self::UnknownTypestateSubject => {
                formatter.write_str("projection names an unknown typestate subject")
            }
            Self::EndpointHashMismatch { role } => {
                write!(formatter, "{role} projection hashes do not match the loaded policy")
            }
            Self::EndpointModelMismatch { role } => {
                write!(formatter, "{role} projection model does not match the loaded policy")
            }
            Self::SinkRejectedReachedLabel => {
                formatter.write_str("taint sink does not accept every reported reached label")
            }
            Self::SourceScenarioIdentityCollision => formatter.write_str(
                "one source scenario identity is attributed to distinct source endpoints",
            ),
            Self::DuplicateProjectionIdentity => formatter.write_str(
                "multiple projection envelopes claim the same semantic finding identity",
            ),
            Self::ProjectionCountBudget { max_items } => {
                write!(formatter, "projection count exceeds the host limit of {max_items}")
            }
            Self::ReportBudgetExceeded { field, limit } => {
                write!(formatter, "projected {field} exceeds the effective report limit of {limit}")
            }
            Self::CompiledProjectionHashMismatch => formatter.write_str(
                "typestate projection is not bound to the loaded authoring, protocol, and binding-plan hashes",
            ),
            Self::UnknownTypestateEvent => formatter.write_str("typestate event is unknown"),
            Self::UnknownTypestateExpectation => {
                formatter.write_str("typestate expectation is unknown")
            }
            Self::TypestateSubjectJoinMismatch => {
                formatter.write_str("typestate rule does not apply to the projected subject")
            }
            Self::TypestateEventJoinMismatch => {
                formatter.write_str("typestate event endpoint join does not match its trigger")
            }
            Self::TypestateTransitionJoinMismatch => formatter
                .write_str("typestate error transition does not match the loaded automaton"),
            Self::TypestateExpectationJoinMismatch => formatter
                .write_str("typestate terminal violation does not match the loaded expectation"),
        }
    }
}

impl std::error::Error for ProjectionAuthorityError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analyzer::policy::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
    use crate::analyzer::policy::definition::{
        PolicySemanticEvent, TaintLabel, TypestateExitScope, TypestateExpectationId,
        TypestateStateId,
    };
    use crate::analyzer::policy::finding::{
        PolicyByteSpan, PolicyDisplayRegion, ProofReason, WitnessStep, WitnessStepKind,
    };
    use crate::analyzer::policy::finding_identity::{
        AnalysisEventRef, AnalysisFindingId, AnalysisSubjectRef, EvidenceRef, SourceScenarioId,
        StableSemanticIdentity, TypestateScenarioId, WitnessId,
    };
    use crate::analyzer::policy::future_evidence::{
        ResolvedTypestateTerminal, TaintSourceProjectionFact, TypestatePolicyProjectionFacts,
    };
    use crate::analyzer::policy::registry::{PolicyRegistry, PolicyRegistryLimits};
    use crate::analyzer::policy::resolved::{ResolvedTaintEndpoint, ResolvedTaintSourceDefinition};
    use crate::analyzer::policy::source::PolicySourceIdentity;
    use crate::analyzer::semantic::WorkspaceRelativePath;

    fn taint_policy(id: &str) -> String {
        taint_policy_with_report(id, "")
    }

    fn taint_policy_with_report(id: &str, report: &str) -> String {
        format!(
            r#"(policy
              :id "{id}"
              :name "Taint authority"
              :message (generated-message :relation can-reach)
              :severity warning
              {report}
              :analysis (analysis
                :type taint
                :mode may
                :sources (endpoint-set :entries [
                  (source :id alpha :display-name "alpha input" :categories [input.alpha]
                    :selector (rql (name "alpha")) :bind return-value
                    :labels [untrusted confidential secret])
                  (source :id beta :display-name "beta input" :categories [input.beta]
                    :selector (rql (name "beta")) :bind return-value :labels [untrusted])
                  (source :id gamma :display-name "gamma input" :categories [input.gamma]
                    :selector (rql (name "gamma")) :bind return-value :labels [untrusted])])
                :sinks (endpoint-set :entries [
                  (sink :id store :display-name "sensitive store" :categories [data.sensitive]
                    :selector (rql (name "store")) :dangerous-operand matched-value
                    :accepts [untrusted confidential secret])])))"#
        )
    }

    fn typestate_policy() -> &'static str {
        r#"(policy
          :id "test.typestate-authority"
          :name "Typestate authority"
          :message "Resource was not closed"
          :severity error
          :analysis (analysis
            :type typestate
            :mode may
            :subjects (subject-set :entries [
              (subject :id resource :selector (rql (name "resource"))
                :subject return-value)])
            :uncertainty (uncertainty :unknown-call inconclusive :escape inconclusive)
            :automaton (automaton
              :states [open closed violated]
              :initial open
              :accepting-states [closed]
              :error-states [violated]
              :events [
                (event :id finish :on (normal-procedure-exit :scope analysis-root))]
              :transitions [
                (transition :from open :on finish :to closed)]
              :terminal-expectations [
                (terminal-expectation :id normal-exit
                  :on (normal-procedure-exit :scope analysis-root)
                  :expected-states [closed])])))"#
    }

    fn registry(sources: &[(&str, String)]) -> PolicyRegistry {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        for (identity, source) in sources {
            registry
                .register_policy_bytes(PolicySourceIdentity::new(*identity), source.as_bytes())
                .expect("test policy must load");
        }
        registry
    }

    fn source_fact(
        source: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
        scenario: &str,
    ) -> TaintSourceProjectionFact {
        source_fact_with_label(source, "untrusted", scenario)
    }

    fn source_fact_with_label(
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
            source.definition.evidence.clone(),
            vec![SourceScenarioId::try_new("test", scenario).unwrap()],
            EvidenceRef::try_new("test", scenario).unwrap(),
        )
        .unwrap()
    }

    fn taint_meeting(
        spec: &ResolvedTaintPolicySpec,
        source_facts: Vec<TaintSourceProjectionFact>,
        sink_display_name: Option<&str>,
    ) -> TaintPolicyProjectionFacts {
        let sink = &spec.sinks[0];
        let mut labels = source_facts
            .iter()
            .map(|fact| fact.source_label.clone())
            .collect::<Vec<_>>();
        labels.sort();
        labels.dedup();
        TaintPolicyProjectionFacts::try_new(
            sink.identity.clone(),
            sink.semantic_hash,
            sink.analysis_projection_hash,
            sink_display_name
                .unwrap_or(&sink.definition.display_name)
                .to_string(),
            sink.definition.categories.clone(),
            sink.definition.tags.clone(),
            sink.definition.impacts.clone(),
            labels,
            source_facts,
            &PolicyBudget::default(),
        )
        .unwrap()
    }

    fn location(path: &str) -> PolicySourceLocation {
        PolicySourceLocation::span(
            WorkspaceRelativePath::new(path).unwrap(),
            PolicyByteSpan::new(0, 1).unwrap(),
            PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
        )
    }

    fn projected_report(path: &str) -> ProjectedFindingReport {
        ProjectedFindingReport {
            primary: location(path),
            certainty: FindingCertainty::Definite,
            completeness: FindingCompleteness::Complete,
            related: Vec::new(),
            related_truncated: false,
            omitted_related_locations_lower_bound: 0,
            evidence_refs_truncated: false,
            omitted_evidence_refs_lower_bound: 0,
            proof: ProofMetadata::try_new(
                ProofState::Proven,
                vec![ProofReason::DataflowWitness],
                Vec::new(),
            )
            .unwrap(),
            witnesses: Vec::new(),
            witnesses_truncated: false,
            omitted_witnesses_lower_bound: 0,
        }
    }

    fn taint_projection_envelope(
        facts: TaintPolicyProjectionFacts,
        pairs: Vec<TaintPairProjection>,
    ) -> TaintProjectedFinding {
        TaintProjectedFinding { facts, pairs }
    }

    fn taint_batch(
        authority: &TaintProjectionAuthority<'_>,
        projections: Vec<TaintProjectedFinding>,
        completion: PolicyRunCompletion,
        diagnostics: Vec<PolicyDiagnostic>,
        diagnostics_truncated: bool,
        work: PolicyWorkReport,
    ) -> TaintProjectionBatch {
        authority.seal_batch(TaintProjectionPayload {
            projections,
            completion,
            diagnostics,
            diagnostics_truncated,
            work,
        })
    }

    fn taint_pair(
        facts: &TaintPolicyProjectionFacts,
        source_index: usize,
        sink_key: &str,
    ) -> TaintPairProjection {
        let source_fact = &facts.source_facts[source_index];
        let scenarios = source_fact.source_scenario_ids.clone();
        let scenario_hash =
            super::super::cvss::SourceScenarioSetHash::try_from_scenarios(scenarios.clone())
                .unwrap();
        let sink_identity = StableSemanticIdentity::analyzer_declaration_id(
            "test",
            WorkspaceRelativePath::new("src/test.rs").unwrap(),
            sink_key,
        )
        .unwrap();
        let anchor = TaintFindingAnchor::strong(
            sink_identity,
            source_fact.source_endpoint_analysis_projection_hash,
            facts.sink_endpoint_analysis_projection_hash,
            scenario_hash,
        )
        .unwrap();
        let origins = scenarios
            .into_iter()
            .map(|scenario| TaintOriginProjection {
                source_endpoint: source_fact.source_endpoint.clone(),
                source_label: source_fact.source_label.clone(),
                source_evidence: source_fact.source_evidence.clone(),
                primary: location("src/test.rs"),
                scenario_id: scenario,
                evidence_refs: vec![source_fact.evidence_ref.clone()],
            })
            .collect();
        TaintPairProjection {
            source_endpoint: source_fact.source_endpoint.clone(),
            analysis_finding_id: AnalysisFindingId::try_new(
                "test",
                format!("finding-{source_index}"),
            )
            .unwrap(),
            anchor,
            sink: AnalysisEventRef::try_new("test", "sink-event").unwrap(),
            origins,
            origins_truncated: false,
            witness_refs: Vec::new(),
            witness_refs_truncated: false,
            report: projected_report("src/test.rs"),
        }
    }

    #[test]
    fn batch_seal_rejects_cross_policy_replay() {
        let registry = registry(&[
            ("test:target", taint_policy("test.target")),
            ("test:wrong", taint_policy("test.wrong")),
        ]);
        let target = registry
            .policies()
            .find(|policy| policy.definition().metadata.id.as_str() == "test.target")
            .unwrap();
        let wrong = registry
            .policies()
            .find(|policy| policy.definition().metadata.id.as_str() == "test.wrong")
            .unwrap();
        let target_authority = TaintProjectionAuthority::from_loaded(target).unwrap();
        let wrong_authority = TaintProjectionAuthority::from_loaded(wrong).unwrap();
        let batch = taint_batch(
            &wrong_authority,
            Vec::new(),
            PolicyRunCompletion::Complete,
            Vec::new(),
            false,
            PolicyWorkReport::default(),
        );

        assert!(matches!(
            validate_taint_batch(&target_authority, batch, &PolicyBudget::default()),
            Err(ProjectionAuthorityError::AuthorityMismatch)
        ));
    }

    #[test]
    fn self_consistent_presentation_spoof_is_rejected_without_forging_a_run() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let fact = source_fact(&authority.spec.sources[0], "alpha");
        let facts = taint_meeting(authority.spec, vec![fact], Some("forged sink"));
        assert!(matches!(
            validate_taint_facts(&authority, facts, &PolicyBudget::default()),
            Err(ProjectionAuthorityError::EndpointModelMismatch { role: "taint sink" })
        ));
    }

    #[test]
    fn scenario_collision_rejects_all_aliasing_sources_order_independently() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let sources = &authority.spec.sources;
        let forward = vec![
            source_fact(&sources[0], "shared"),
            source_fact(&sources[1], "shared"),
            source_fact(&sources[2], "unique"),
        ];
        let mut reverse = forward.clone();
        reverse.reverse();

        let validate = |facts| {
            let meeting = taint_meeting(authority.spec, facts, None);
            validate_taint_facts(&authority, meeting, &PolicyBudget::default()).unwrap()
        };
        let first = validate(forward);
        let second = validate(reverse);

        let first_facts = first.value.unwrap();
        let second_facts = second.value.unwrap();
        assert_eq!(first_facts.source_facts.len(), 1);
        assert_eq!(
            first_facts.source_facts[0].source_endpoint,
            sources[2].identity
        );
        assert_eq!(first_facts.semantic_hash, second_facts.semantic_hash);
        assert_eq!(first.rejections.len(), second.rejections.len());
    }

    #[test]
    fn multiple_invalid_facts_reject_one_source_pair_once_without_partial_retention() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let alpha = &authority.spec.sources[0];
        let beta = &authority.spec.sources[1];
        let valid_alpha = source_fact_with_label(alpha, "untrusted", "alpha-valid");
        let invalid_alpha_display = TaintSourceProjectionFact::try_new(
            alpha.identity.clone(),
            alpha.semantic_hash,
            alpha.analysis_projection_hash,
            "forged alpha display".to_string(),
            alpha.definition.categories.clone(),
            TaintLabel::new("confidential").unwrap(),
            alpha.definition.evidence.clone(),
            vec![SourceScenarioId::try_new("test", "alpha-bad-display").unwrap()],
            EvidenceRef::try_new("test", "alpha-bad-display").unwrap(),
        )
        .unwrap();
        let invalid_alpha_categories = TaintSourceProjectionFact::try_new(
            alpha.identity.clone(),
            alpha.semantic_hash,
            alpha.analysis_projection_hash,
            alpha.definition.display_name.clone(),
            Vec::new(),
            TaintLabel::new("secret").unwrap(),
            alpha.definition.evidence.clone(),
            vec![SourceScenarioId::try_new("test", "alpha-bad-categories").unwrap()],
            EvidenceRef::try_new("test", "alpha-bad-categories").unwrap(),
        )
        .unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![
                valid_alpha,
                invalid_alpha_display,
                invalid_alpha_categories,
                source_fact(beta, "beta-valid"),
            ],
            None,
        );
        let alpha_index = facts
            .source_facts
            .iter()
            .position(|fact| {
                fact.source_endpoint == alpha.identity
                    && fact.source_label == TaintLabel::new("untrusted").unwrap()
            })
            .unwrap();
        let beta_index = facts
            .source_facts
            .iter()
            .position(|fact| fact.source_endpoint == beta.identity)
            .unwrap();
        let mut alpha_pair = taint_pair(&facts, alpha_index, "call:sink");
        alpha_pair.origins_truncated = true;
        let beta_pair = taint_pair(&facts, beta_index, "call:sink");
        let batch = taint_batch(
            &authority,
            vec![taint_projection_envelope(
                facts,
                vec![alpha_pair, beta_pair],
            )],
            PolicyRunCompletion::Complete,
            Vec::new(),
            false,
            PolicyWorkReport::default(),
        );

        let validated = validate_taint_batch(&authority, batch, &PolicyBudget::default()).unwrap();

        assert_eq!(validated.projections.len(), 1);
        assert_eq!(
            validated.projections[0].facts.source_facts[0].source_endpoint,
            beta.identity
        );
        assert_eq!(validated.work.omitted_findings_lower_bound(), 1);
        assert!(matches!(
            validated.completion,
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons == vec![PolicyIncompleteReason::CapabilityIncomplete]
        ));
    }

    #[test]
    fn taint_envelope_requires_exact_pair_and_origin_coverage() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![
                source_fact(&authority.spec.sources[0], "alpha"),
                source_fact(&authority.spec.sources[1], "beta"),
            ],
            None,
        );
        let pairs = vec![
            taint_pair(&facts, 0, "call:sink"),
            taint_pair(&facts, 1, "call:sink"),
        ];
        let limits = EffectiveReportLimits::new(authority.report, &PolicyBudget::default());
        let validated = validate_taint_projection(
            &authority,
            taint_projection_envelope(facts.clone(), pairs.clone()),
            &PolicyBudget::default(),
            limits,
        )
        .unwrap();
        assert_eq!(validated.value.unwrap().len(), 2);

        let missing = validate_taint_projection(
            &authority,
            taint_projection_envelope(facts.clone(), vec![pairs[0].clone()]),
            &PolicyBudget::default(),
            limits,
        );
        assert!(matches!(
            missing,
            Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_pair_coverage"
            })
        ));

        let duplicate = validate_taint_projection(
            &authority,
            taint_projection_envelope(
                facts,
                vec![pairs[0].clone(), pairs[0].clone(), pairs[1].clone()],
            ),
            &PolicyBudget::default(),
            limits,
        );
        assert!(matches!(
            duplicate,
            Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_pair_coverage"
            })
        ));
    }

    #[test]
    fn duplicate_envelopes_are_rejected_before_the_deterministic_finding_prefix() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![source_fact(&authority.spec.sources[0], "alpha")],
            None,
        );
        let duplicate =
            taint_projection_envelope(facts.clone(), vec![taint_pair(&facts, 0, "call:duplicate")]);
        let unique =
            taint_projection_envelope(facts.clone(), vec![taint_pair(&facts, 0, "call:unique")]);
        let unique_id =
            PolicyFindingId::from_taint_anchor(&authority.seal.policy_id, &unique.pairs[0].anchor);
        let budget = PolicyBudget::builder()
            .with_max_findings(1)
            .unwrap()
            .build()
            .unwrap();
        let validate = |projections| {
            validate_taint_batch(
                &authority,
                taint_batch(
                    &authority,
                    projections,
                    PolicyRunCompletion::Complete,
                    Vec::new(),
                    false,
                    PolicyWorkReport::default(),
                ),
                &budget,
            )
            .unwrap()
        };

        let first = validate(vec![duplicate.clone(), unique.clone(), duplicate.clone()]);
        let second = validate(vec![duplicate.clone(), duplicate, unique]);
        for validated in [&first, &second] {
            assert_eq!(validated.projections.len(), 1);
            assert_eq!(
                PolicyFindingId::from_taint_anchor(
                    &authority.seal.policy_id,
                    &validated.projections[0].anchor,
                ),
                unique_id
            );
            assert_eq!(validated.work.omitted_findings_lower_bound(), 1);
            assert!(matches!(
                &validated.completion,
                PolicyRunCompletion::Failed { reasons }
                    if reasons == &[PolicyFailureReason::InternalInvariant]
            ));
            assert!(validated.diagnostics.iter().any(|diagnostic| {
                diagnostic.code() == &PolicyDiagnosticCode::EvaluationFailure
                    && diagnostic.severity() == PolicyDiagnosticSeverity::Error
                    && diagnostic.impact() == PolicyDiagnosticImpact::RunFailed
            }));
        }
    }

    #[test]
    fn duplicate_multi_pair_taint_envelopes_count_each_distinct_pair_once() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![
                source_fact(&authority.spec.sources[0], "alpha"),
                source_fact(&authority.spec.sources[1], "beta"),
            ],
            None,
        );
        let duplicate = taint_projection_envelope(
            facts.clone(),
            vec![
                taint_pair(&facts, 0, "call:duplicate"),
                taint_pair(&facts, 1, "call:duplicate"),
            ],
        );
        let batch = taint_batch(
            &authority,
            vec![duplicate.clone(), duplicate.clone(), duplicate],
            PolicyRunCompletion::Complete,
            Vec::new(),
            false,
            PolicyWorkReport::default(),
        );

        let validated = validate_taint_batch(&authority, batch, &PolicyBudget::default()).unwrap();

        assert!(validated.projections.is_empty());
        assert_eq!(validated.work.omitted_findings_lower_bound(), 2);
    }

    #[test]
    fn finding_count_rejection_uses_the_typed_batch_limit_diagnostic() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![source_fact(&authority.spec.sources[0], "alpha")],
            None,
        );
        let budget = PolicyBudget::builder()
            .with_max_findings(1)
            .unwrap()
            .build()
            .unwrap();
        let batch = taint_batch(
            &authority,
            vec![
                taint_projection_envelope(facts.clone(), vec![taint_pair(&facts, 0, "call:first")]),
                taint_projection_envelope(
                    facts.clone(),
                    vec![taint_pair(&facts, 0, "call:second")],
                ),
            ],
            PolicyRunCompletion::Complete,
            Vec::new(),
            false,
            PolicyWorkReport::default(),
        );

        let validated = validate_taint_batch(&authority, batch, &budget).unwrap();
        assert_eq!(validated.projections.len(), 1);
        assert_eq!(validated.work.omitted_findings_lower_bound(), 1);
        assert!(
            validated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code() == &PolicyDiagnosticCode::BatchFindingLimit)
        );
    }

    #[test]
    fn truncated_origins_only_lower_finding_completeness() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![source_fact(&authority.spec.sources[0], "alpha")],
            None,
        );
        let mut pair = taint_pair(&facts, 0, "call:sink");
        pair.origins.clear();
        pair.origins_truncated = true;
        let batch = taint_batch(
            &authority,
            vec![taint_projection_envelope(facts, vec![pair])],
            PolicyRunCompletion::Complete,
            Vec::new(),
            false,
            PolicyWorkReport::default(),
        );

        let validated = validate_taint_batch(&authority, batch, &PolicyBudget::default()).unwrap();
        assert!(matches!(
            validated.completion,
            PolicyRunCompletion::Complete
        ));
        assert_eq!(
            validated.projections[0].report.completeness.reasons(),
            &[FindingIncompleteReason::OriginsTruncated]
        );
    }

    #[test]
    fn taint_origin_membership_is_exact_and_evidence_backed() {
        let registry = registry(&[("test:target", taint_policy("test.target"))]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let facts = taint_meeting(
            authority.spec,
            vec![source_fact(&authority.spec.sources[0], "alpha")],
            None,
        );
        let limits = EffectiveReportLimits::new(authority.report, &PolicyBudget::default());

        let mut duplicate = taint_pair(&facts, 0, "call:sink");
        duplicate.origins.push(duplicate.origins[0].clone());
        assert!(matches!(
            validate_taint_pair(facts.clone(), duplicate, &PolicyBudget::default(), limits),
            Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "duplicate_taint_origin_membership"
            })
        ));

        let mut missing = taint_pair(&facts, 0, "call:sink");
        missing.origins.clear();
        assert!(matches!(
            validate_taint_pair(facts.clone(), missing, &PolicyBudget::default(), limits),
            Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_origin_coverage"
            })
        ));

        let mut unrelated = taint_pair(&facts, 0, "call:sink");
        unrelated.origins[0].evidence_refs =
            vec![EvidenceRef::try_new("test", "unrelated").unwrap()];
        assert!(matches!(
            validate_taint_pair(facts, unrelated, &PolicyBudget::default(), limits),
            Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "taint_origin_evidence_reference"
            })
        ));
    }

    #[test]
    fn authored_and_host_report_caps_form_effective_minimums() {
        let registry = registry(&[(
            "test:target",
            taint_policy_with_report(
                "test.target",
                ":report (report :witness (witness :max-steps 3 :max-bytes 100) \
                 :witnesses-per-finding 2 :origins-per-finding 1)",
            ),
        )]);
        let policy = registry.policies().next().unwrap();
        let authority = TaintProjectionAuthority::from_loaded(policy).unwrap();
        let authored = EffectiveReportLimits::new(authority.report, &PolicyBudget::default());
        assert_eq!(authored.origins_per_finding, 1);
        assert_eq!(authored.witnesses_per_finding, 2);
        assert_eq!(authored.witness_steps, 3);
        assert_eq!(authored.witness_bytes, 100);

        let host = PolicyBudget::builder()
            .with_max_origins_per_finding(0)
            .unwrap()
            .with_max_witnesses_per_finding(1)
            .unwrap()
            .with_max_witness_steps(2)
            .unwrap()
            .with_max_witness_bytes(50)
            .unwrap()
            .build()
            .unwrap();
        let effective = EffectiveReportLimits::new(authority.report, &host);
        assert_eq!(effective.origins_per_finding, 0);
        assert_eq!(effective.witnesses_per_finding, 1);
        assert_eq!(effective.witness_steps, 2);
        assert_eq!(effective.witness_bytes, 50);

        let facts = taint_meeting(
            authority.spec,
            vec![source_fact(&authority.spec.sources[0], "alpha")],
            None,
        );
        assert!(matches!(
            validate_taint_pair(
                facts.clone(),
                taint_pair(&facts, 0, "call:sink"),
                &host,
                effective
            ),
            Err(ProjectionAuthorityError::ReportBudgetExceeded {
                field: "origins",
                limit: 0
            })
        ));

        let witness = BoundedWitness::try_new(
            WitnessId::try_new("test", "witness").unwrap(),
            vec![
                WitnessStep::try_new(
                    WitnessStepKind::Propagation,
                    Some(location("src/test.rs")),
                    "step",
                    Vec::new(),
                )
                .unwrap(),
            ],
            false,
            0,
        )
        .unwrap();
        let witness_host = PolicyBudget::builder()
            .with_max_witness_steps(0)
            .unwrap()
            .build()
            .unwrap();
        let witness_limits = EffectiveReportLimits::new(authority.report, &witness_host);
        let mut report = projected_report("src/test.rs");
        report.witnesses = vec![witness];
        assert!(matches!(
            validate_projected_report(report, Vec::new(), &witness_host, witness_limits),
            Err(ProjectionAuthorityError::ReportBudgetExceeded {
                field: "witness_steps",
                limit: 0
            })
        ));
    }

    fn typestate_facts(
        authority: &TypestateProjectionAuthority<'_>,
        protocol_hash: TypestateProtocolHash,
    ) -> TypestatePolicyProjectionFacts {
        let subject = &authority.spec.subjects[0];
        let dependency = authority
            .spec
            .endpoint_dependencies
            .iter()
            .find(|dependency| dependency.identity() == &subject.identity)
            .unwrap();
        TypestatePolicyProjectionFacts::try_new(
            authority.spec.authoring_projection_hash,
            protocol_hash,
            authority.binding_plan_hash(),
            subject.identity.clone(),
            subject.semantic_hash,
            subject.analysis_projection_hash,
            dependency.model().categories.clone(),
            dependency.model().display_name.clone(),
            None,
            TypestateViolationEvidence::try_terminal_expectation(
                TypestateExpectationId::new("normal-exit").unwrap(),
                ResolvedTypestateTerminal::SemanticEvent {
                    event: PolicySemanticEvent::NormalProcedureExit {
                        scope: TypestateExitScope::AnalysisRoot,
                    },
                },
                TypestateStateId::new("open").unwrap(),
                vec![TypestateStateId::new("closed").unwrap()],
            )
            .unwrap(),
            vec![TypestateScenarioId::try_new("test", "root").unwrap()],
            &PolicyBudget::default(),
        )
        .unwrap()
    }

    fn typestate_projected_finding(
        authority: &TypestateProjectionAuthority<'_>,
    ) -> TypestateProjectedFinding {
        let subject = &authority.spec.subjects[0];
        let dependency = authority
            .spec
            .endpoint_dependencies
            .iter()
            .find(|dependency| dependency.identity() == &subject.identity)
            .unwrap();
        let site = StableSemanticIdentity::protocol_violation_site(
            "test",
            WorkspaceRelativePath::new("src/test.rs").unwrap(),
            "normal-exit",
        )
        .unwrap();
        let violation = TypestateViolationEvidence::try_terminal_expectation(
            TypestateExpectationId::new("normal-exit").unwrap(),
            ResolvedTypestateTerminal::SemanticEvent {
                event: PolicySemanticEvent::NormalProcedureExit {
                    scope: TypestateExitScope::AnalysisRoot,
                },
            },
            TypestateStateId::new("open").unwrap(),
            vec![TypestateStateId::new("closed").unwrap()],
        )
        .unwrap();
        let facts = TypestatePolicyProjectionFacts::try_new(
            authority.spec.authoring_projection_hash,
            authority.protocol_hash(),
            authority.binding_plan_hash(),
            subject.identity.clone(),
            subject.semantic_hash,
            subject.analysis_projection_hash,
            dependency.model().categories.clone(),
            dependency.model().display_name.clone(),
            Some(site.clone()),
            violation.clone(),
            vec![TypestateScenarioId::try_new("test", "root").unwrap()],
            &PolicyBudget::default(),
        )
        .unwrap();
        let subject_identity = StableSemanticIdentity::protocol_subject(
            "test",
            WorkspaceRelativePath::new("src/test.rs").unwrap(),
            "resource-instance",
        )
        .unwrap();
        let anchor = TypestateFindingAnchor::strong(
            authority.protocol_hash(),
            authority.binding_plan_hash(),
            subject_identity,
            site,
            facts.scenario_set_hash,
            &violation,
        )
        .unwrap();
        TypestateProjectedFinding {
            facts,
            analysis_finding_id: AnalysisFindingId::try_new("test", "typestate-finding").unwrap(),
            anchor,
            subject: AnalysisSubjectRef::try_new("test", "resource-instance").unwrap(),
            witness_refs: Vec::new(),
            witness_refs_truncated: false,
            report: projected_report("src/test.rs"),
        }
    }

    #[test]
    fn typestate_rows_are_bound_to_compilation_and_exact_terminal_join() {
        let registry = registry(&[("test:typestate", typestate_policy().to_string())]);
        let policy = registry.policies().next().unwrap();
        let protocol_hash = TypestateProtocolHash::from_canonical_bytes(b"protocol");
        let binding_plan_hash = TypestateBindingPlanHash::from_canonical_bytes(b"bindings");
        let authority = TypestateProjectionAuthority::from_loaded_compilation(
            policy,
            protocol_hash,
            binding_plan_hash,
        )
        .unwrap();

        let valid = typestate_facts(&authority, protocol_hash);
        let validated =
            validate_typestate_facts(&authority, valid, &PolicyBudget::default()).unwrap();
        assert_eq!(validated.protocol_hash, protocol_hash);

        let forged = typestate_facts(
            &authority,
            TypestateProtocolHash::from_canonical_bytes(b"other protocol"),
        );
        assert!(matches!(
            validate_typestate_facts(&authority, forged, &PolicyBudget::default()),
            Err(ProjectionAuthorityError::CompiledProjectionHashMismatch)
        ));

        let valid_projection = typestate_projected_finding(&authority);
        let limits = EffectiveReportLimits::new(authority.report, &PolicyBudget::default());
        assert!(
            validate_typestate_projection(
                &authority,
                valid_projection.clone(),
                &PolicyBudget::default(),
                limits,
            )
            .is_ok()
        );

        let mut wrong_hash = valid_projection;
        let strong = wrong_hash.anchor.strong_fields().unwrap();
        let alternate_violation = TypestateViolationEvidence::try_terminal_expectation(
            TypestateExpectationId::new("normal-exit").unwrap(),
            ResolvedTypestateTerminal::SemanticEvent {
                event: PolicySemanticEvent::NormalProcedureExit {
                    scope: TypestateExitScope::AnalysisRoot,
                },
            },
            TypestateStateId::new("violated").unwrap(),
            vec![TypestateStateId::new("closed").unwrap()],
        )
        .unwrap();
        wrong_hash.anchor = TypestateFindingAnchor::strong(
            strong.protocol_hash(),
            strong.binding_plan_hash(),
            strong.subject_identity().clone(),
            strong.violation_site_identity().clone(),
            strong.scenario_set_hash(),
            &alternate_violation,
        )
        .unwrap();
        assert!(matches!(
            validate_typestate_projection(&authority, wrong_hash, &PolicyBudget::default(), limits,),
            Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
                field: "typestate_anchor"
            })
        ));
    }

    #[test]
    fn duplicate_typestate_envelopes_count_one_distinct_omitted_finding() {
        let registry = registry(&[("test:typestate", typestate_policy().to_string())]);
        let policy = registry.policies().next().unwrap();
        let authority = TypestateProjectionAuthority::from_loaded_compilation(
            policy,
            TypestateProtocolHash::from_canonical_bytes(b"protocol"),
            TypestateBindingPlanHash::from_canonical_bytes(b"bindings"),
        )
        .unwrap();
        let duplicate = typestate_projected_finding(&authority);
        let batch = authority.seal_batch(TypestateProjectionPayload {
            projections: vec![duplicate.clone(), duplicate.clone(), duplicate],
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: PolicyWorkReport::default(),
        });

        let validated =
            validate_typestate_batch(&authority, batch, &PolicyBudget::default()).unwrap();

        assert!(validated.projections.is_empty());
        assert_eq!(validated.work.omitted_findings_lower_bound(), 1);
        assert!(matches!(
            validated.completion,
            PolicyRunCompletion::Failed { reasons }
                if reasons == vec![PolicyFailureReason::InternalInvariant]
        ));
    }
}
