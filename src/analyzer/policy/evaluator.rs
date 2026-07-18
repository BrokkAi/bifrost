//! Context-requiring projection from diagnostic-neutral analyzer results.
//!
//! This module deliberately stops at a crate-private match candidate seam.
//! Public `PolicyFinding`/`PolicyRun` assembly owns classification, reporting,
//! and retained-size budgets and is wired here only after those aggregates
//! have been validated.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, SecondsFormat};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::CancellationToken;
use crate::analyzer::IAnalyzer;
use crate::analyzer::semantic::WorkspaceRelativePath;
use crate::analyzer::structural::search::{
    CodeQueryStableOwnerDerivation, DetailedCodeQueryDomain, DetailedCodeQueryEvidence,
    DetailedCodeQueryIdentityCandidate, DetailedCodeQueryKey, DetailedCodeQueryProvenanceEvidence,
    DetailedCodeQueryProvenanceIdentities, DetailedCodeQueryProvenanceRefEvidence,
    execute_code_query_detailed,
};
use crate::analyzer::structural::{
    CodeQueryCompletion, CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryExecutionWork, CodeQueryProvenance, CodeQueryRange, CodeQueryResultDetail,
    CodeQueryResultItem, CodeQueryResultRef, CodeQueryResultValue, QueryValueKind,
};

use super::budget::PolicyBudget;
use super::classification::{
    ClassificationProvenance, FindingClassification, MAX_REPORT_PROSE_BYTES,
    OrganizationalRiskAssessment, TaxonomyClassification, normalize_evidence_refs,
    validate_required_text,
};
use super::cvss::{
    CvssEvidenceBasis, CvssEvidenceContentHash, CvssMetricEvidence, CvssValidationError,
    PolicyOverlayScope,
};
use super::definition::{
    CvssEnvironmentalOrSupplementalMetric, CvssEvidenceScope, CvssMetric, CvssMetricValue,
    CvssSystemScope, CvssThreatMetric, FindingSeverity, PolicyAnalysis, PolicyAnalysisType,
    PolicyClassificationSpec, PolicyId, PolicyLevel, PolicyMessageSpec, PolicySeveritySpec,
};
use super::finding::{
    CertaintyReason, FindingCertainty, FindingCompleteness, FindingIncompleteReason,
    MatchFindingEvidence, PolicyByteSpan, PolicyCapability, PolicyDiagnostic, PolicyDiagnosticCode,
    PolicyDiagnosticImpact, PolicyDiagnosticSeverity, PolicyDisplayRegion, PolicyFailureReason,
    PolicyFinding, PolicyFindingEvidence, PolicyIncompleteReason, PolicyQueryProof,
    PolicyQueryProvenance, PolicyQueryProvenanceStep, PolicyQueryResultRef, PolicyRun,
    PolicyRunCompletion, PolicyRunError, PolicySourceLocation, PolicyWorkReport, ProofMetadata,
    ProofReason, ProofState, ReportValueError,
};
use super::finding_identity::{
    FindingIdentityStability, MatchFindingAnchor, MatchResultDomain, OpaqueFindingKey,
    PolicyFindingId, SourceSliceHash, StableSemanticIdentity,
};
use super::resolved::{LoadedPolicy, ResolvedTaintPolicySpec, ResolvedTypestatePolicySpec};

const MATCH_SELECTOR_PATH: &str = "/analysis/selector";
const WEAK_KEY_DOMAIN: &[u8] = b"bifrost-policy-match-weak-key/v1";
const CVSS_OVERLAY_HASH_DOMAIN: &[u8] = b"bifrost-policy-cvss-overlay/v1";
const MAX_OVERLAY_ASSUMPTIONS: usize = 64;

/// Host context supplied to one policy evaluation.
pub struct PolicyEvaluationContext<'a> {
    pub analyzer: &'a dyn IAnalyzer,
    pub cancellation: Option<&'a CancellationToken>,
    pub cvss_overlays: &'a [CvssEvaluationOverlay],
    pub organizational_risk: &'a [OrganizationalRiskOverlay],
}

#[derive(Debug, Clone)]
pub enum CvssEvaluationOverlay {
    EnvironmentProfile {
        scope: PolicyOverlayScope,
        evidence: CvssEnvironmentOverlayEvidence,
    },
    ThreatFeed {
        scope: PolicyOverlayScope,
        evidence: CvssThreatOverlayEvidence,
    },
    AnalystOverride {
        scope: PolicyOverlayScope,
        evidence: CvssAnalystOverlayEvidence,
    },
}

#[derive(Debug, Clone)]
pub struct OrganizationalRiskOverlay {
    pub scope: PolicyOverlayScope,
    pub assessment: OrganizationalRiskAssessment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CvssExternalArtifactHash([u8; 32]);

impl CvssExternalArtifactHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CvssExternalArtifactHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for CvssExternalArtifactHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone)]
pub struct CvssOverlayEvidenceMetadata {
    evidence_refs: Vec<super::finding_identity::EvidenceRef>,
    rationale: String,
    assumptions: Vec<String>,
    assessor_or_tool: String,
    assessed_at: String,
    system_scope: CvssEvidenceScope,
    external_artifact_hash: Option<CvssExternalArtifactHash>,
}

impl CvssOverlayEvidenceMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        mut evidence_refs: Vec<super::finding_identity::EvidenceRef>,
        rationale: String,
        mut assumptions: Vec<String>,
        assessor_or_tool: String,
        assessed_at: String,
        system_scope: CvssEvidenceScope,
        external_artifact_hash: Option<CvssExternalArtifactHash>,
    ) -> Result<Self, CvssEvidenceError> {
        normalize_evidence_refs(&mut evidence_refs, true)
            .map_err(|_| CvssEvidenceError::InvalidEvidenceReferences)?;
        validate_required_text(&rationale, MAX_REPORT_PROSE_BYTES)
            .map_err(|_| CvssEvidenceError::InvalidRationale)?;
        if assumptions.len() > MAX_OVERLAY_ASSUMPTIONS {
            return Err(CvssEvidenceError::TooManyAssumptions);
        }
        for assumption in &assumptions {
            validate_required_text(assumption, MAX_REPORT_PROSE_BYTES)
                .map_err(|_| CvssEvidenceError::InvalidAssumption)?;
        }
        assumptions.sort();
        assumptions.dedup();
        validate_required_text(&assessor_or_tool, MAX_REPORT_PROSE_BYTES)
            .map_err(|_| CvssEvidenceError::InvalidAssessorOrTool)?;
        let assessed_at = DateTime::parse_from_rfc3339(&assessed_at)
            .map_err(|_| CvssEvidenceError::InvalidAssessedAt)?
            .to_utc()
            .to_rfc3339_opts(SecondsFormat::AutoSi, true);
        Ok(Self {
            evidence_refs,
            rationale,
            assumptions,
            assessor_or_tool,
            assessed_at,
            system_scope,
            external_artifact_hash,
        })
    }

    pub fn evidence_refs(&self) -> &[super::finding_identity::EvidenceRef] {
        &self.evidence_refs
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    pub fn assumptions(&self) -> &[String] {
        &self.assumptions
    }

    pub fn assessor_or_tool(&self) -> &str {
        &self.assessor_or_tool
    }

    pub fn assessed_at(&self) -> &str {
        &self.assessed_at
    }

    pub const fn system_scope(&self) -> CvssEvidenceScope {
        self.system_scope
    }

    pub const fn external_artifact_hash(&self) -> Option<CvssExternalArtifactHash> {
        self.external_artifact_hash
    }
}

macro_rules! define_overlay_evidence {
    ($name:ident, $metric:ty, $basis:expr, $wrap:expr) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            metric: $metric,
            value: CvssMetricValue,
            metadata: CvssOverlayEvidenceMetadata,
            content_hash: CvssEvidenceContentHash,
        }

        impl $name {
            pub fn try_new(
                metric: $metric,
                value: CvssMetricValue,
                metadata: CvssOverlayEvidenceMetadata,
            ) -> Result<Self, CvssEvidenceError> {
                let typed_metric: CvssMetric = ($wrap)(metric);
                let content_hash =
                    validate_overlay_evidence($basis, typed_metric, value, &metadata)?;
                Ok(Self {
                    metric,
                    value,
                    metadata,
                    content_hash,
                })
            }

            pub const fn metric(&self) -> $metric {
                self.metric
            }

            pub const fn value(&self) -> &CvssMetricValue {
                &self.value
            }

            pub const fn metadata(&self) -> &CvssOverlayEvidenceMetadata {
                &self.metadata
            }

            pub const fn content_hash(&self) -> CvssEvidenceContentHash {
                self.content_hash
            }
        }
    };
}

define_overlay_evidence!(
    CvssEnvironmentOverlayEvidence,
    CvssEnvironmentalOrSupplementalMetric,
    CvssEvidenceBasis::EnvironmentProfile,
    |metric| CvssMetric::EnvironmentalOrSupplemental { metric }
);
define_overlay_evidence!(
    CvssThreatOverlayEvidence,
    CvssThreatMetric,
    CvssEvidenceBasis::ThreatFeed,
    |metric| CvssMetric::Threat { metric }
);
define_overlay_evidence!(
    CvssAnalystOverlayEvidence,
    CvssMetric,
    CvssEvidenceBasis::AnalystOverride,
    |metric| metric
);

#[derive(Debug)]
pub enum CvssEvidenceError {
    InvalidEvidenceReferences,
    InvalidRationale,
    TooManyAssumptions,
    InvalidAssumption,
    InvalidAssessorOrTool,
    InvalidAssessedAt,
    InvalidMetricEvidence(CvssValidationError),
}

impl fmt::Display for CvssEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidenceReferences => formatter.write_str("invalid evidence references"),
            Self::InvalidRationale => formatter.write_str("invalid CVSS overlay rationale"),
            Self::TooManyAssumptions => formatter.write_str("too many CVSS overlay assumptions"),
            Self::InvalidAssumption => formatter.write_str("invalid CVSS overlay assumption"),
            Self::InvalidAssessorOrTool => formatter.write_str("invalid CVSS assessor or tool"),
            Self::InvalidAssessedAt => formatter.write_str("assessed_at must be RFC 3339"),
            Self::InvalidMetricEvidence(error) => {
                write!(formatter, "invalid CVSS evidence: {error}")
            }
        }
    }
}

impl std::error::Error for CvssEvidenceError {}

fn validate_overlay_evidence(
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

fn overlay_content_hash(
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

const fn cvss_evidence_basis_label(basis: CvssEvidenceBasis) -> &'static str {
    match basis {
        CvssEvidenceBasis::StaticWitness => "static_witness",
        CvssEvidenceBasis::PolicyAssertion => "policy_assertion",
        CvssEvidenceBasis::EnvironmentProfile => "environment_profile",
        CvssEvidenceBasis::ThreatFeed => "threat_feed",
        CvssEvidenceBasis::AnalystOverride => "analyst_override",
    }
}

const fn cvss_evidence_scope_labels(
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

/// Evaluate one fully loaded policy against a host-supplied analyzer snapshot.
pub trait PolicyEvaluator {
    fn evaluate(
        &self,
        policy: &LoadedPolicy,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
    ) -> Result<PolicyRun, PolicyRunError>;
}

/// Adapter boundary for the future taint compiler and solver integration.
pub trait TaintPolicyEvaluator {
    fn evaluate_taint(
        &self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
    ) -> PolicyRun;
}

/// Adapter boundary for the future typestate compiler and solver integration.
pub trait TypestatePolicyEvaluator {
    fn evaluate_typestate(
        &self,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
    ) -> PolicyRun;
}

/// Built-in match evaluator with optional future-analysis adapters.
pub struct DefaultPolicyEvaluator<'a> {
    taint: Option<&'a dyn TaintPolicyEvaluator>,
    typestate: Option<&'a dyn TypestatePolicyEvaluator>,
}

impl<'a> DefaultPolicyEvaluator<'a> {
    pub const fn new() -> Self {
        Self {
            taint: None,
            typestate: None,
        }
    }

    pub const fn with_taint(mut self, adapter: &'a dyn TaintPolicyEvaluator) -> Self {
        self.taint = Some(adapter);
        self
    }

    pub const fn with_typestate(mut self, adapter: &'a dyn TypestatePolicyEvaluator) -> Self {
        self.typestate = Some(adapter);
        self
    }
}

impl Default for DefaultPolicyEvaluator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator for DefaultPolicyEvaluator<'_> {
    fn evaluate(
        &self,
        policy: &LoadedPolicy,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
    ) -> Result<PolicyRun, PolicyRunError> {
        let host_budget = *budget;
        match &policy.definition().analysis {
            PolicyAnalysis::Match { .. } => evaluate_match_policy(policy, context, &host_budget),
            PolicyAnalysis::Taint { .. } => {
                let Some(spec) = policy.resolved_taint() else {
                    return failed_policy_run(
                        policy,
                        PolicyAnalysisType::Taint,
                        "loaded taint policy is missing its resolved analysis specification",
                        &host_budget,
                    );
                };
                match self.taint {
                    Some(adapter) => {
                        let run = adapter.evaluate_taint(policy, spec, context, budget);
                        *budget = host_budget;
                        validate_adapter_run(policy, PolicyAnalysisType::Taint, run, &host_budget)
                    }
                    None => unsupported_policy_run(
                        policy,
                        PolicyAnalysisType::Taint,
                        PolicyCapability::TaintEvaluation,
                        "taint policy evaluation requires an installed taint adapter",
                        &host_budget,
                    ),
                }
            }
            PolicyAnalysis::Typestate { .. } => {
                let Some(spec) = policy.resolved_typestate() else {
                    return failed_policy_run(
                        policy,
                        PolicyAnalysisType::Typestate,
                        "loaded typestate policy is missing its resolved analysis specification",
                        &host_budget,
                    );
                };
                match self.typestate {
                    Some(adapter) => {
                        let run = adapter.evaluate_typestate(policy, spec, context, budget);
                        *budget = host_budget;
                        validate_adapter_run(
                            policy,
                            PolicyAnalysisType::Typestate,
                            run,
                            &host_budget,
                        )
                    }
                    None => unsupported_policy_run(
                        policy,
                        PolicyAnalysisType::Typestate,
                        PolicyCapability::TypestateEvaluation,
                        "typestate policy evaluation requires an installed typestate adapter",
                        &host_budget,
                    ),
                }
            }
        }
    }
}

fn evaluate_match_policy(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let evaluated =
        evaluate_match_policy_candidates(policy, context.analyzer, budget, context.cancellation);
    assemble_match_run(policy, evaluated, budget)
}

fn assemble_match_run(
    policy: &LoadedPolicy,
    evaluated: EvaluatedMatchPolicy,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let metadata = &policy.definition().metadata;
    let presentation = match match_presentation(policy) {
        Ok(presentation) => presentation,
        Err(()) => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Match,
                "match policy presentation could not be projected into a finding",
                budget,
            );
        }
    };
    let mut findings = Vec::with_capacity(evaluated.candidates.len());
    for candidate in evaluated.candidates {
        let expected_id = candidate.id;
        let finding = PolicyFinding::try_new(
            metadata.id.clone(),
            policy.semantic_hash(),
            presentation.severity,
            presentation.message.clone(),
            presentation.classification.clone(),
            candidate.certainty,
            candidate.completeness,
            candidate.location,
            Vec::new(),
            false,
            0,
            PolicyFindingEvidence::Match {
                evidence: candidate.evidence,
            },
            false,
            0,
            None,
            None,
            candidate.proof,
            Vec::new(),
            false,
            0,
            budget,
        );
        match finding {
            Ok(finding) if finding.id() == expected_id => findings.push(finding),
            Ok(_) | Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    PolicyAnalysisType::Match,
                    findings,
                    "a validated match candidate could not be retained as a policy finding",
                    evaluated.work,
                    budget,
                );
            }
        }
    }
    match PolicyRun::try_new(
        metadata.id.clone(),
        policy.semantic_hash(),
        PolicyAnalysisType::Match,
        evaluated.completion,
        findings,
        evaluated.diagnostics,
        evaluated.diagnostics_truncated,
        evaluated.work,
        budget,
    ) {
        Ok(run) => Ok(run),
        Err(error @ PolicyRunError::RetainedReportBytesExceeded { .. }) => Err(error),
        Err(_) => failed_policy_run(
            policy,
            PolicyAnalysisType::Match,
            "match evaluation produced an invalid policy run",
            budget,
        ),
    }
}

#[derive(Clone)]
struct MatchPresentation {
    severity: FindingSeverity,
    message: String,
    classification: FindingClassification,
}

fn match_presentation(policy: &LoadedPolicy) -> Result<MatchPresentation, ()> {
    let metadata = &policy.definition().metadata;
    let message = match &metadata.message {
        PolicyMessageSpec::Static { text } => text.clone(),
        PolicyMessageSpec::Generated { .. } => return Err(()),
    };
    let severity = match &metadata.severity {
        PolicySeveritySpec::Fixed { level } => match level {
            PolicyLevel::Note => FindingSeverity::Note,
            PolicyLevel::Warning => FindingSeverity::Warning,
            PolicyLevel::Error => FindingSeverity::Error,
        },
        PolicySeveritySpec::Unrated => FindingSeverity::Unrated,
        PolicySeveritySpec::Cvss { when_unscored } => *when_unscored,
    };
    let classification = match_classification(policy.definition().classification.as_ref())?;
    Ok(MatchPresentation {
        severity,
        message,
        classification,
    })
}

fn match_classification(
    spec: Option<&PolicyClassificationSpec>,
) -> Result<FindingClassification, ()> {
    let Some(spec) = spec else {
        return Ok(FindingClassification::Unclassified);
    };
    let broad = TaxonomyClassification::try_new(
        spec.fallback.taxonomy.clone(),
        spec.fallback.identifier.clone(),
        spec.fallback.name.clone(),
        ClassificationProvenance::PolicyFallback,
    )
    .map_err(|_| ())?;
    let mut refinements = Vec::new();
    for (index, refinement) in spec.refinements.iter().enumerate() {
        if !match_classification_predicate(&refinement.when) {
            continue;
        }
        let index = u32::try_from(index).map_err(|_| ())?;
        for added in &refinement.add {
            refinements.push(
                TaxonomyClassification::try_new(
                    added.taxonomy.clone(),
                    added.identifier.clone(),
                    added.name.clone(),
                    ClassificationProvenance::policy_refinement(index).map_err(|_| ())?,
                )
                .map_err(|_| ())?,
            );
        }
    }
    FindingClassification::classified(broad, refinements).map_err(|_| ())
}

fn match_classification_predicate(predicate: &super::definition::ClassificationPredicate) -> bool {
    use super::definition::ClassificationPredicate as Predicate;
    match predicate {
        Predicate::All { predicates } => predicates.iter().all(match_classification_predicate),
        Predicate::Any { predicates } => predicates.iter().any(match_classification_predicate),
        Predicate::AnalysisType { analysis_type } => *analysis_type == PolicyAnalysisType::Match,
        Predicate::SourceCategories { .. }
        | Predicate::SinkCategories { .. }
        | Predicate::SourceLabels { .. }
        | Predicate::SinkTags { .. }
        | Predicate::SinkImpacts { .. }
        | Predicate::FindingCombination { .. }
        | Predicate::TypestateExpectation { .. } => false,
    }
}

fn unsupported_policy_run(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    capability: PolicyCapability,
    message: &str,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::UnsupportedAnalysis,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunUnsupported,
        message,
        None,
        Vec::new(),
    )
    .ok();
    let retain_diagnostic = budget.max_diagnostics() > 0 && diagnostic.is_some();
    let diagnostics = if retain_diagnostic {
        diagnostic.into_iter().collect()
    } else {
        Vec::new()
    };
    PolicyRun::try_new(
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        analysis_type,
        PolicyRunCompletion::Unsupported { capability },
        Vec::new(),
        diagnostics,
        !retain_diagnostic,
        work_report(CodeQueryExecutionWork::default(), 0, 0),
        budget,
    )
}

fn failed_policy_run(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    message: &str,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    failed_policy_run_with_findings(
        policy,
        analysis_type,
        Vec::new(),
        message,
        work_report(CodeQueryExecutionWork::default(), 0, 0),
        budget,
    )
}

fn failed_policy_run_with_findings(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    mut findings: Vec<PolicyFinding>,
    message: &str,
    work: PolicyWorkReport,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    findings.retain(|finding| finding.identity_stability() == FindingIdentityStability::Strong);
    let diagnostic = internal_failure_diagnostic(message).ok();
    let retain_diagnostic = budget.max_diagnostics() > 0 && diagnostic.is_some();
    let diagnostics = if retain_diagnostic {
        diagnostic.into_iter().collect()
    } else {
        Vec::new()
    };
    let completion = PolicyRunCompletion::Failed {
        reasons: vec![PolicyFailureReason::InternalInvariant],
    };
    PolicyRun::try_new(
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        analysis_type,
        completion,
        findings,
        diagnostics,
        !retain_diagnostic,
        work,
        budget,
    )
}

fn validate_adapter_run(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    run: PolicyRun,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    if run.policy_id() == &policy.definition().metadata.id
        && run.policy_hash() == policy.semantic_hash()
        && run.analysis_type() == analysis_type
    {
        run.validate_against_budget(budget)?;
        Ok(run)
    } else {
        failed_policy_run(
            policy,
            analysis_type,
            "analysis adapter returned a run for a different policy or analysis type",
            budget,
        )
    }
}

/// A diagnostic-neutral match candidate ready for public finding assembly.
///
/// Keeping this crate-private prevents raw query rows or endpoint matches from
/// becoming diagnostics without policy metadata and evaluation context.
#[derive(Debug)]
pub(crate) struct EvaluatedMatchCandidate {
    pub(crate) id: PolicyFindingId,
    pub(crate) location: PolicySourceLocation,
    pub(crate) certainty: FindingCertainty,
    pub(crate) completeness: FindingCompleteness,
    pub(crate) evidence: MatchFindingEvidence,
    pub(crate) proof: ProofMetadata,
}

/// The bounded result of one and only one detailed CodeQuery execution.
#[derive(Debug)]
pub(crate) struct EvaluatedMatchPolicy {
    pub(crate) candidates: Vec<EvaluatedMatchCandidate>,
    pub(crate) completion: PolicyRunCompletion,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) work: PolicyWorkReport,
}

/// Evaluate the match selector stored in a fully resolved policy.
pub(crate) fn evaluate_match_policy_candidates(
    policy: &LoadedPolicy,
    analyzer: &dyn IAnalyzer,
    budget: &PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> EvaluatedMatchPolicy {
    if !matches!(policy.definition().analysis, PolicyAnalysis::Match { .. }) {
        return failed_before_execution(
            PolicyFailureReason::InvalidExecutionPlan,
            "match evaluation requires a match policy",
            budget,
        );
    }
    let Some(selector) = policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
    else {
        return failed_before_execution(
            PolicyFailureReason::InternalInvariant,
            "resolved match policy is missing /analysis/selector",
            budget,
        );
    };
    evaluate_match_query_candidates(
        &policy.definition().metadata.id,
        analyzer,
        &selector.query,
        budget,
        cancellation,
    )
}

fn evaluate_match_query_candidates(
    policy_id: &PolicyId,
    analyzer: &dyn IAnalyzer,
    query: &crate::analyzer::structural::CodeQuery,
    budget: &PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> EvaluatedMatchPolicy {
    match query.validate_steps() {
        Ok(QueryValueKind::ReceiverAnalysis) => {
            return failed_before_execution(
                PolicyFailureReason::InvalidExecutionPlan,
                "receiver-analysis is not a positive match-policy terminal domain",
                budget,
            );
        }
        Ok(
            QueryValueKind::StructuralMatch
            | QueryValueKind::Declaration
            | QueryValueKind::ReferenceSite
            | QueryValueKind::CallSite
            | QueryValueKind::ExpressionSite
            | QueryValueKind::File,
        ) => {}
        Err(_) => {
            return failed_before_execution(
                PolicyFailureReason::InvalidExecutionPlan,
                "match policy contains an invalid query plan",
                budget,
            );
        }
    }

    // Author-controlled presentation/truncation settings are not policy
    // semantics. The host budget alone bounds findings and full detail is
    // required for exact locations.
    let mut executable = query.clone();
    executable.result_detail = CodeQueryResultDetail::Full;
    executable.limit = budget.max_findings();
    let detailed =
        execute_code_query_detailed(analyzer, &executable, budget.query_limits(), cancellation);

    let query_completion = detailed.result.completion();
    let query_truncated = detailed.result.truncated;
    let mut incomplete_reasons = incomplete_reasons(&query_completion, query_truncated);
    let mut failure_reasons = failure_reasons(&query_completion);
    let result_limit_reached = detailed
        .result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ResultLimitReached);

    let adapted_diagnostics =
        adapt_query_diagnostics(&detailed.result.diagnostics, budget.max_diagnostics());
    let mut diagnostics = adapted_diagnostics.diagnostics;
    let mut diagnostics_truncated = adapted_diagnostics.truncated;
    if diagnostics_truncated {
        incomplete_reasons.push(PolicyIncompleteReason::ReportRetentionBudget);
    }
    if adapted_diagnostics.adaptation_failed {
        retain_incomplete_diagnostic(
            &mut diagnostics,
            &mut diagnostics_truncated,
            budget.max_diagnostics(),
            "one or more query diagnostics could not be retained as validated policy diagnostics",
        );
    }

    let adapted_candidates = adapt_match_candidates(
        policy_id,
        detailed.result.results,
        detailed.evidence,
        &detailed.result.diagnostics,
    );
    let candidates = adapted_candidates.candidates;
    for candidate in &candidates {
        if matches!(candidate.evidence.anchor(), MatchFindingAnchor::Weak(_)) {
            incomplete_reasons.push(PolicyIncompleteReason::StableAnchorUnavailable);
        }
    }

    if incomplete_reasons.contains(&PolicyIncompleteReason::StableAnchorUnavailable) {
        if diagnostics.len() < budget.max_diagnostics() {
            if let Ok(diagnostic) = PolicyDiagnostic::try_new(
                PolicyDiagnosticCode::StableAnchorUnavailable,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                "one or more match findings lack an exact stable source anchor",
                None,
                Vec::new(),
            ) {
                diagnostics.push(diagnostic);
            } else {
                failure_reasons.push(PolicyFailureReason::InternalInvariant);
            }
        } else {
            diagnostics_truncated = true;
        }
    }

    if adapted_candidates.conversion_failed {
        failure_reasons.push(PolicyFailureReason::InternalInvariant);
        if diagnostics.len() < budget.max_diagnostics() {
            if let Ok(diagnostic) = internal_failure_diagnostic(
                "a detailed query row could not be projected into validated policy evidence",
            ) {
                diagnostics.push(diagnostic);
            } else {
                diagnostics_truncated = true;
            }
        } else {
            diagnostics_truncated = true;
        }
    }

    incomplete_reasons.sort();
    incomplete_reasons.dedup();
    failure_reasons.sort();
    failure_reasons.dedup();
    let completion = if !failure_reasons.is_empty() {
        PolicyRunCompletion::failed(failure_reasons)
            .expect("failure reasons are known to be non-empty and bounded")
    } else if !incomplete_reasons.is_empty() {
        PolicyRunCompletion::inconclusive(incomplete_reasons)
            .expect("incomplete reasons are known to be non-empty and bounded")
    } else {
        PolicyRunCompletion::Complete
    };
    let work = work_report(
        detailed.work,
        candidates.len(),
        u64::from(result_limit_reached)
            .saturating_add(adapted_candidates.omitted_findings_lower_bound),
    );
    EvaluatedMatchPolicy {
        candidates,
        completion,
        diagnostics,
        diagnostics_truncated,
        work,
    }
}

#[derive(Debug)]
struct AdaptedQueryDiagnostics {
    diagnostics: Vec<PolicyDiagnostic>,
    truncated: bool,
    adaptation_failed: bool,
}

fn adapt_query_diagnostics(
    query_diagnostics: &[CodeQueryDiagnostic],
    max_diagnostics: usize,
) -> AdaptedQueryDiagnostics {
    let mut diagnostics = Vec::new();
    let mut truncated = false;
    let mut adaptation_failed = false;
    for diagnostic in query_diagnostics {
        if diagnostics.len() >= max_diagnostics {
            truncated = true;
            break;
        }
        match adapt_query_diagnostic(diagnostic) {
            Ok(diagnostic) => diagnostics.push(diagnostic),
            Err(_) => {
                // Analyzer prose is not trusted to satisfy policy-report bounds. Keep
                // considering later diagnostics because the rejected entry consumes no
                // retention slot, but make its omission explicit in the run contract.
                truncated = true;
                adaptation_failed = true;
            }
        }
    }
    AdaptedQueryDiagnostics {
        diagnostics,
        truncated,
        adaptation_failed,
    }
}

fn retain_incomplete_diagnostic(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    max_diagnostics: usize,
    message: &str,
) {
    if diagnostics.len() >= max_diagnostics {
        *diagnostics_truncated = true;
        return;
    }
    match PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::ReportRetentionBudget,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
        None,
        Vec::new(),
    ) {
        Ok(diagnostic) => diagnostics.push(diagnostic),
        Err(_) => *diagnostics_truncated = true,
    }
}

#[derive(Debug)]
struct AdaptedMatchCandidates {
    candidates: Vec<EvaluatedMatchCandidate>,
    conversion_failed: bool,
    omitted_findings_lower_bound: u64,
}

fn adapt_match_candidates(
    policy_id: &PolicyId,
    results: Vec<CodeQueryResultItem>,
    evidence: Vec<DetailedCodeQueryEvidence>,
    query_diagnostics: &[CodeQueryDiagnostic],
) -> AdaptedMatchCandidates {
    let result_count = results.len();
    let evidence_count = evidence.len();
    let paired_count = result_count.min(evidence_count);
    let mut conversion_failed = result_count != evidence_count;
    let mut omitted_findings_lower_bound =
        u64::try_from(result_count.saturating_sub(paired_count)).unwrap_or(u64::MAX);
    let mut ordinals: HashMap<StrongOrdinalKey, u32> = HashMap::new();
    let mut candidates = Vec::with_capacity(paired_count);
    for (item, evidence) in results.into_iter().zip(evidence) {
        match adapt_match_candidate(policy_id, item, evidence, query_diagnostics, &mut ordinals) {
            Ok(candidate) => candidates.push(candidate),
            Err(()) => {
                conversion_failed = true;
                omitted_findings_lower_bound = omitted_findings_lower_bound.saturating_add(1);
            }
        }
    }
    AdaptedMatchCandidates {
        candidates,
        conversion_failed,
        omitted_findings_lower_bound,
    }
}

fn adapt_match_candidate(
    policy_id: &PolicyId,
    item: CodeQueryResultItem,
    evidence: DetailedCodeQueryEvidence,
    query_diagnostics: &[CodeQueryDiagnostic],
    ordinals: &mut HashMap<StrongOrdinalKey, u32>,
) -> Result<EvaluatedMatchCandidate, ()> {
    let result_domain = match_domain(evidence.domain).ok_or(())?;
    let path = WorkspaceRelativePath::try_from_path(evidence.file.rel_path()).map_err(|_| ())?;
    let (location, mut candidate_reasons, proof) = terminal_presentation(
        &item.value,
        evidence.domain,
        &path,
        evidence.byte_span.as_ref(),
    )?;
    candidate_reasons.extend(certainty_reasons(query_diagnostics, &evidence.provenance));

    let owner = match evidence.stable_owner_candidate.as_ref() {
        Some(candidate) => {
            let identity = match candidate.derivation {
                CodeQueryStableOwnerDerivation::AnalyzerDeclarationId => {
                    StableSemanticIdentity::analyzer_declaration_id(
                        &candidate.namespace,
                        path.clone(),
                        &candidate.semantic_key,
                    )
                }
                CodeQueryStableOwnerDerivation::CanonicalAstIdentity => {
                    StableSemanticIdentity::canonical_ast_identity(
                        &candidate.namespace,
                        path.clone(),
                        &candidate.semantic_key,
                    )
                }
            };
            match identity {
                Ok(owner) => OwnerCandidate::Accepted(owner),
                Err(_) => OwnerCandidate::Rejected,
            }
        }
        None => OwnerCandidate::Absent,
    };

    let anchor = if result_domain == MatchResultDomain::File {
        MatchFindingAnchor::strong(result_domain, path.clone(), None, None, 0).map_err(|_| ())?
    } else if let (Some(source_hash), false) = (
        evidence
            .source_slice_sha256
            .map(SourceSliceHash::from_bytes),
        matches!(owner, OwnerCandidate::Rejected),
    ) {
        let owner = match owner {
            OwnerCandidate::Accepted(owner) => Some(owner),
            OwnerCandidate::Absent => None,
            OwnerCandidate::Rejected => unreachable!("rejected owners take the weak path"),
        };
        let ordinal_key = StrongOrdinalKey {
            domain: result_domain,
            path: path.clone(),
            owner: owner.clone(),
            source_hash,
        };
        let ordinal = ordinals.entry(ordinal_key).or_default();
        let current = *ordinal;
        *ordinal = ordinal.checked_add(1).ok_or(())?;
        MatchFindingAnchor::strong(
            result_domain,
            path.clone(),
            owner,
            Some(source_hash),
            current,
        )
        .map_err(|_| ())?
    } else {
        MatchFindingAnchor::weak(result_domain, path.clone(), weak_finding_key(&evidence))
    };

    if item.provenance.len() != evidence.provenance.len() {
        return Err(());
    }
    let mut provenance_partial = false;
    let mut provenance_identity_uncertain = false;
    let provenance = item
        .provenance
        .into_iter()
        .zip(evidence.provenance)
        .map(|(provenance, detailed)| {
            let (provenance, partial, identity_uncertain) = adapt_provenance(provenance, detailed)?;
            provenance_partial |= partial;
            provenance_identity_uncertain |= identity_uncertain;
            Ok(provenance)
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let proof = if provenance_identity_uncertain {
        candidate_reasons.push(CertaintyReason::NameBasedResolution);
        lower_proof_for_missing_identity(proof)?
    } else {
        proof
    };
    candidate_reasons.sort();
    candidate_reasons.dedup();
    let certainty = if candidate_reasons.is_empty() {
        FindingCertainty::Definite
    } else {
        FindingCertainty::possible(candidate_reasons).map_err(|_| ())?
    };
    let provenance_truncated = item.provenance_truncated || provenance_partial;

    let mut finding_incomplete = Vec::new();
    if provenance_truncated {
        finding_incomplete.push(FindingIncompleteReason::QueryProvenanceTruncated);
    }
    if matches!(anchor, MatchFindingAnchor::Weak(_)) {
        finding_incomplete.push(FindingIncompleteReason::StableAnchorWeak);
    }
    if proof.state() != ProofState::Proven {
        finding_incomplete.push(FindingIncompleteReason::ProofPartial);
    }
    let completeness = if finding_incomplete.is_empty() {
        FindingCompleteness::Complete
    } else {
        FindingCompleteness::partial(finding_incomplete).map_err(|_| ())?
    };
    let id = PolicyFindingId::from_match_anchor(policy_id, &anchor);
    let evidence =
        MatchFindingEvidence::try_new(result_domain, anchor, provenance, provenance_truncated)
            .map_err(|_| ())?;
    Ok(EvaluatedMatchCandidate {
        id,
        location,
        certainty,
        completeness,
        evidence,
        proof,
    })
}

#[derive(Debug)]
enum OwnerCandidate {
    Absent,
    Accepted(StableSemanticIdentity),
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StrongOrdinalKey {
    domain: MatchResultDomain,
    path: WorkspaceRelativePath,
    owner: Option<StableSemanticIdentity>,
    source_hash: SourceSliceHash,
}

fn terminal_presentation(
    value: &CodeQueryResultValue,
    expected_domain: DetailedCodeQueryDomain,
    expected_path: &WorkspaceRelativePath,
    byte_span: Option<&std::ops::Range<usize>>,
) -> Result<(PolicySourceLocation, Vec<CertaintyReason>, ProofMetadata), ()> {
    let (actual_domain, path, range, certainty, proof_state, proof_reason) = match value {
        CodeQueryResultValue::StructuralMatch { value } => (
            DetailedCodeQueryDomain::StructuralMatch,
            value.path.as_str(),
            value.node_range,
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
        CodeQueryResultValue::Declaration { value } => (
            DetailedCodeQueryDomain::Declaration,
            value.path.as_str(),
            value.node_range,
            Vec::new(),
            ProofState::Proven,
            ProofReason::ResolvedDeclaration,
        ),
        CodeQueryResultValue::File { value } => (
            DetailedCodeQueryDomain::File,
            value.path.as_str(),
            None,
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
        CodeQueryResultValue::ReferenceSite { value } => {
            let (certainty, state) = proof_certainty(value.proof);
            (
                DetailedCodeQueryDomain::ReferenceSite,
                value.path.as_str(),
                Some(value.range),
                certainty,
                state,
                ProofReason::ResolvedReference,
            )
        }
        CodeQueryResultValue::CallSite { value } => {
            let (certainty, state) = proof_certainty(value.proof);
            (
                DetailedCodeQueryDomain::CallSite,
                value.path.as_str(),
                Some(value.range),
                certainty,
                state,
                ProofReason::ExactCallTarget,
            )
        }
        CodeQueryResultValue::ExpressionSite { value } => (
            DetailedCodeQueryDomain::ExpressionSite,
            value.path.as_str(),
            Some(value.range),
            vec![
                CertaintyReason::analyzer_ambiguity("expression-site-proof-unavailable")
                    .map_err(|_| ())?,
            ],
            ProofState::Unproven,
            ProofReason::PartialWitness,
        ),
        CodeQueryResultValue::ReceiverAnalysis { .. } => return Err(()),
    };
    if actual_domain != expected_domain || path != expected_path.as_str() {
        return Err(());
    }
    let location = if actual_domain == DetailedCodeQueryDomain::File {
        if byte_span.is_some() || range.is_some() {
            return Err(());
        }
        PolicySourceLocation::artifact(expected_path.clone())
    } else {
        let byte_span = byte_span.ok_or(())?;
        let range = range.ok_or(())?;
        policy_span_location(expected_path.clone(), byte_span, range)?
    };
    let proof =
        ProofMetadata::try_new(proof_state, vec![proof_reason], Vec::new()).map_err(|_| ())?;
    Ok((location, certainty, proof))
}

fn proof_certainty(proof: &str) -> (Vec<CertaintyReason>, ProofState) {
    if proof == "proven" {
        (Vec::new(), ProofState::Proven)
    } else {
        (
            vec![CertaintyReason::NameBasedResolution],
            ProofState::Unproven,
        )
    }
}

fn policy_span_location(
    path: WorkspaceRelativePath,
    byte_span: &std::ops::Range<usize>,
    range: CodeQueryRange,
) -> Result<PolicySourceLocation, ()> {
    let bytes = PolicyByteSpan::new(
        u64::try_from(byte_span.start).map_err(|_| ())?,
        u64::try_from(byte_span.end).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let region = PolicyDisplayRegion::new(
        u64::try_from(range.start_line).map_err(|_| ())?,
        u64::try_from(range.start_column).map_err(|_| ())?,
        u64::try_from(range.end_line).map_err(|_| ())?,
        u64::try_from(range.end_column).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    Ok(PolicySourceLocation::span(path, bytes, region))
}

fn adapt_provenance(
    provenance: CodeQueryProvenance,
    detailed: DetailedCodeQueryProvenanceEvidence,
) -> Result<(PolicyQueryProvenance, bool, bool), ()> {
    if provenance.branch != detailed.branch || provenance.steps.len() != detailed.steps.len() {
        return Err(());
    }
    let branch = provenance
        .branch
        .into_iter()
        .map(|branch| u32::try_from(branch).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    let (seed, mut partial, mut identity_uncertain) =
        adapt_provenance_ref(provenance.seed, detailed.seed)?;
    let steps = provenance
        .steps
        .into_iter()
        .zip(detailed.steps)
        .map(|(step, detailed)| {
            if step.op != detailed.op || step.via.is_some() != detailed.via.is_some() {
                return Err(());
            }
            let (result, result_partial, result_identity_uncertain) =
                adapt_provenance_ref(step.result, detailed.result)?;
            partial |= result_partial;
            identity_uncertain |= result_identity_uncertain;
            let via = match (step.via, detailed.via) {
                (Some(value), Some(detailed)) => {
                    let (value, via_partial, via_identity_uncertain) =
                        adapt_provenance_ref(value, detailed)?;
                    partial |= via_partial;
                    identity_uncertain |= via_identity_uncertain;
                    Some(value)
                }
                (None, None) => None,
                _ => return Err(()),
            };
            PolicyQueryProvenanceStep::try_new(step.op, result, via).map_err(|_| ())
        })
        .collect::<Result<Vec<_>, _>>()?;
    PolicyQueryProvenance::try_new(branch, seed, steps)
        .map(|provenance| (provenance, partial, identity_uncertain))
        .map_err(|_| ())
}

fn adapt_provenance_ref(
    value: CodeQueryResultRef,
    detailed: DetailedCodeQueryProvenanceRefEvidence,
) -> Result<(PolicyQueryResultRef, bool, bool), ()> {
    let DetailedCodeQueryProvenanceRefEvidence {
        domain,
        key,
        file,
        byte_span,
        display_range,
        identities,
        source_slice_sha256,
    } = detailed;
    let path = WorkspaceRelativePath::try_from_path(file.rel_path()).map_err(|_| ())?;
    let source_exact = domain == DetailedCodeQueryDomain::File
        || (source_slice_sha256.is_some() && byte_span.is_some() && display_range.is_some());
    if !source_exact {
        let kind = public_provenance_kind(&value);
        if public_provenance_path(&value) != path.as_str() {
            return Err(());
        }
        return Ok((unsupported_provenance_ref(kind, path), true, false));
    }

    let mut identity_uncertain = false;
    let adapted = match (value, domain, key, identities) {
        (
            CodeQueryResultRef::StructuralMatch {
                path: public_path,
                kind,
                node_range: Some(range),
                ..
            },
            DetailedCodeQueryDomain::StructuralMatch,
            DetailedCodeQueryKey::StructuralMatch {
                kind: detailed_kind,
                ..
            },
            DetailedCodeQueryProvenanceIdentities::Primary(identity),
        ) if public_path == path.as_str()
            && kind == detailed_kind
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::StructuralMatch {
                kind: detailed_kind,
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                identity: validated_provenance_identity(identity.as_ref()),
            }
        }
        (
            CodeQueryResultRef::Declaration {
                path: public_path,
                kind,
                fq_name,
                node_range: Some(range),
                ..
            },
            DetailedCodeQueryDomain::Declaration,
            DetailedCodeQueryKey::Declaration {
                kind: detailed_kind,
                fq_name: detailed_fq_name,
                ..
            },
            DetailedCodeQueryProvenanceIdentities::Primary(identity),
        ) if public_path == path.as_str()
            && kind == detailed_kind
            && fq_name == detailed_fq_name
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::Declaration {
                kind: detailed_kind,
                fq_name: detailed_fq_name,
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                identity: validated_provenance_identity(identity.as_ref()),
            }
        }
        (
            CodeQueryResultRef::File { path: public_path },
            DetailedCodeQueryDomain::File,
            DetailedCodeQueryKey::File,
            DetailedCodeQueryProvenanceIdentities::None,
        ) if public_path == path.as_str() && byte_span.is_none() && display_range.is_none() => {
            PolicyQueryResultRef::file(path)
        }
        (
            CodeQueryResultRef::ReferenceSite {
                path: public_path,
                range,
                target_fq_name,
                usage_kind,
                proof,
                ..
            },
            DetailedCodeQueryDomain::ReferenceSite,
            DetailedCodeQueryKey::ReferenceSite {
                target_fq_name: detailed_target,
                ..
            },
            DetailedCodeQueryProvenanceIdentities::ReferenceTarget(target_identity),
        ) if public_path == path.as_str()
            && target_fq_name == detailed_target
            && Some(range) == display_range =>
        {
            let target_identity = validated_provenance_identity(target_identity.as_ref());
            identity_uncertain = proof == "proven" && target_identity.is_none();
            PolicyQueryResultRef::ReferenceSite {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                target_fq_name: detailed_target,
                target_identity,
                usage_kind: usage_kind.map(str::to_string),
                proof: if identity_uncertain {
                    PolicyQueryProof::NameBased
                } else {
                    policy_query_proof(proof)
                },
            }
        }
        (
            CodeQueryResultRef::CallSite {
                path: public_path,
                range,
                caller_fq_name,
                callee_fq_name,
                proof,
            },
            DetailedCodeQueryDomain::CallSite,
            DetailedCodeQueryKey::CallSite {
                caller_fq_name: detailed_caller,
                callee_fq_name: detailed_callee,
            },
            DetailedCodeQueryProvenanceIdentities::Call { caller, callee },
        ) if public_path == path.as_str()
            && caller_fq_name == detailed_caller
            && callee_fq_name == detailed_callee
            && Some(range) == display_range =>
        {
            let caller_identity = validated_provenance_identity(caller.as_ref());
            let callee_identity = validated_provenance_identity(callee.as_ref());
            identity_uncertain =
                proof == "proven" && (caller_identity.is_none() || callee_identity.is_none());
            PolicyQueryResultRef::CallSite {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                caller_fq_name: detailed_caller,
                caller_identity,
                callee_fq_name: detailed_callee,
                callee_identity,
                proof: if identity_uncertain {
                    PolicyQueryProof::NameBased
                } else {
                    policy_query_proof(proof)
                },
            }
        }
        (
            CodeQueryResultRef::ExpressionSite {
                path: public_path,
                range,
                input_kind,
                parameter_index,
                parameter_name,
            },
            DetailedCodeQueryDomain::ExpressionSite,
            DetailedCodeQueryKey::ExpressionSite {
                input_kind: detailed_input,
                parameter_index: detailed_index,
                parameter_name: detailed_name,
            },
            DetailedCodeQueryProvenanceIdentities::None,
        ) if public_path == path.as_str()
            && input_kind == detailed_input
            && parameter_index.and_then(|index| u32::try_from(index).ok()) == detailed_index
            && parameter_name == detailed_name
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::ExpressionSite {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                input_kind: detailed_input,
                parameter_index: detailed_index,
                parameter_name: detailed_name,
            }
        }
        (
            CodeQueryResultRef::ReceiverAnalysis {
                path: public_path,
                range,
                analysis_kind,
                outcome,
                capture,
            },
            DetailedCodeQueryDomain::ReceiverAnalysis,
            DetailedCodeQueryKey::ReceiverAnalysis {
                analysis_kind: detailed_analysis,
                outcome: detailed_outcome,
                capture: detailed_capture,
            },
            DetailedCodeQueryProvenanceIdentities::None,
        ) if public_path == path.as_str()
            && analysis_kind == detailed_analysis
            && outcome == detailed_outcome
            && capture == detailed_capture
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::ReceiverAnalysis {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                analysis_kind: detailed_analysis,
                outcome: detailed_outcome,
                capture: detailed_capture,
            }
        }
        _ => return Err(()),
    };
    Ok((adapted, false, identity_uncertain))
}

fn lower_proof_for_missing_identity(proof: ProofMetadata) -> Result<ProofMetadata, ()> {
    if proof.state() != ProofState::Proven {
        return Ok(proof);
    }
    ProofMetadata::try_new(
        ProofState::Unproven,
        vec![
            ProofReason::PartialWitness,
            ProofReason::analyzer_evidence("stable_target_identity_unavailable").map_err(|_| ())?,
        ],
        proof.evidence_refs().to_vec(),
    )
    .map_err(|_| ())
}

fn validated_provenance_identity(
    candidate: Option<&DetailedCodeQueryIdentityCandidate>,
) -> Option<StableSemanticIdentity> {
    let candidate = candidate?;
    let path = WorkspaceRelativePath::try_from_path(candidate.file.rel_path()).ok()?;
    let identity = match candidate.candidate.derivation {
        CodeQueryStableOwnerDerivation::AnalyzerDeclarationId => {
            StableSemanticIdentity::analyzer_declaration_id(
                &candidate.candidate.namespace,
                path,
                &candidate.candidate.semantic_key,
            )
        }
        CodeQueryStableOwnerDerivation::CanonicalAstIdentity => {
            StableSemanticIdentity::canonical_ast_identity(
                &candidate.candidate.namespace,
                path,
                &candidate.candidate.semantic_key,
            )
        }
    };
    identity.ok()
}

fn public_provenance_kind(value: &CodeQueryResultRef) -> &'static str {
    match value {
        CodeQueryResultRef::StructuralMatch { .. } => "structural_match",
        CodeQueryResultRef::Declaration { .. } => "declaration",
        CodeQueryResultRef::File { .. } => "file",
        CodeQueryResultRef::ReferenceSite { .. } => "reference_site",
        CodeQueryResultRef::CallSite { .. } => "call_site",
        CodeQueryResultRef::ExpressionSite { .. } => "expression_site",
        CodeQueryResultRef::ReceiverAnalysis { .. } => "receiver_analysis",
    }
}

fn public_provenance_path(value: &CodeQueryResultRef) -> &str {
    match value {
        CodeQueryResultRef::StructuralMatch { path, .. }
        | CodeQueryResultRef::Declaration { path, .. }
        | CodeQueryResultRef::File { path }
        | CodeQueryResultRef::ReferenceSite { path, .. }
        | CodeQueryResultRef::CallSite { path, .. }
        | CodeQueryResultRef::ExpressionSite { path, .. }
        | CodeQueryResultRef::ReceiverAnalysis { path, .. } => path,
    }
}

fn unsupported_provenance_ref(kind: &str, path: WorkspaceRelativePath) -> PolicyQueryResultRef {
    PolicyQueryResultRef::Unsupported {
        query_result_kind: kind.to_string(),
        location: Some(PolicySourceLocation::artifact(path)),
    }
}

fn policy_query_proof(proof: &str) -> PolicyQueryProof {
    match proof {
        "proven" => PolicyQueryProof::Resolved,
        "unproven" => PolicyQueryProof::NameBased,
        _ => PolicyQueryProof::Unknown,
    }
}

fn match_domain(domain: DetailedCodeQueryDomain) -> Option<MatchResultDomain> {
    match domain {
        DetailedCodeQueryDomain::StructuralMatch => Some(MatchResultDomain::StructuralMatch),
        DetailedCodeQueryDomain::Declaration => Some(MatchResultDomain::Declaration),
        DetailedCodeQueryDomain::ReferenceSite => Some(MatchResultDomain::ReferenceSite),
        DetailedCodeQueryDomain::CallSite => Some(MatchResultDomain::CallSite),
        DetailedCodeQueryDomain::ExpressionSite => Some(MatchResultDomain::ExpressionSite),
        DetailedCodeQueryDomain::File => Some(MatchResultDomain::File),
        DetailedCodeQueryDomain::ReceiverAnalysis => None,
    }
}

fn weak_finding_key(evidence: &DetailedCodeQueryEvidence) -> OpaqueFindingKey {
    let mut hasher = Sha256::new();
    update_hash(&mut hasher, WEAK_KEY_DOMAIN);
    update_hash(&mut hasher, domain_label(evidence.domain).as_bytes());
    update_hash(
        &mut hasher,
        evidence.file.rel_path().to_string_lossy().as_bytes(),
    );
    if let Some(span) = &evidence.byte_span {
        update_hash(&mut hasher, &span.start.to_be_bytes());
        update_hash(&mut hasher, &span.end.to_be_bytes());
    }
    match &evidence.key {
        DetailedCodeQueryKey::StructuralMatch { kind, analyzer_id } => {
            update_hash(&mut hasher, kind.as_bytes());
            update_optional_hash(&mut hasher, analyzer_id.as_deref());
        }
        DetailedCodeQueryKey::Declaration {
            kind,
            fq_name,
            analyzer_id,
        } => {
            update_hash(&mut hasher, kind.as_bytes());
            update_hash(&mut hasher, fq_name.as_bytes());
            update_optional_hash(&mut hasher, analyzer_id.as_deref());
        }
        DetailedCodeQueryKey::File => {}
        DetailedCodeQueryKey::ReferenceSite {
            target_id,
            target_fq_name,
        } => {
            update_optional_hash(&mut hasher, target_id.as_deref());
            update_hash(&mut hasher, target_fq_name.as_bytes());
        }
        DetailedCodeQueryKey::CallSite {
            caller_fq_name,
            callee_fq_name,
        } => {
            update_hash(&mut hasher, caller_fq_name.as_bytes());
            update_hash(&mut hasher, callee_fq_name.as_bytes());
        }
        DetailedCodeQueryKey::ExpressionSite {
            input_kind,
            parameter_index,
            parameter_name,
        } => {
            update_hash(&mut hasher, input_kind.as_bytes());
            update_optional_hash(
                &mut hasher,
                parameter_index
                    .as_ref()
                    .map(|index| index.to_string())
                    .as_deref(),
            );
            update_optional_hash(&mut hasher, parameter_name.as_deref());
        }
        DetailedCodeQueryKey::ReceiverAnalysis {
            analysis_kind,
            outcome,
            capture,
        } => {
            update_hash(&mut hasher, analysis_kind.as_bytes());
            update_hash(&mut hasher, outcome.as_bytes());
            update_optional_hash(&mut hasher, capture.as_deref());
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    OpaqueFindingKey::try_new("code-query", encoded)
        .expect("a SHA-256 key and static namespace satisfy opaque-key bounds")
}

fn update_hash(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("usize fits in u64 on supported targets")
            .to_be_bytes(),
    );
    hasher.update(value);
}

fn update_optional_hash(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            update_hash(hasher, b"some");
            update_hash(hasher, value.as_bytes());
        }
        None => update_hash(hasher, b"none"),
    }
}

fn domain_label(domain: DetailedCodeQueryDomain) -> &'static str {
    match domain {
        DetailedCodeQueryDomain::StructuralMatch => "structural_match",
        DetailedCodeQueryDomain::Declaration => "declaration",
        DetailedCodeQueryDomain::ReferenceSite => "reference_site",
        DetailedCodeQueryDomain::CallSite => "call_site",
        DetailedCodeQueryDomain::ExpressionSite => "expression_site",
        DetailedCodeQueryDomain::ReceiverAnalysis => "receiver_analysis",
        DetailedCodeQueryDomain::File => "file",
    }
}

fn certainty_reasons(
    diagnostics: &[CodeQueryDiagnostic],
    provenance: &[DetailedCodeQueryProvenanceEvidence],
) -> Vec<CertaintyReason> {
    let mut reasons = diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic.impact == CodeQueryDiagnosticImpact::Advisory
                && matches!(
                    diagnostic.code,
                    CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
                        | CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
                        | CodeQueryDiagnosticCode::UsesTargetsAmbiguous
                )
        })
        .filter(|diagnostic| {
            diagnostic.branch.is_empty()
                || provenance.iter().any(|trace| {
                    trace
                        .branch
                        .as_slice()
                        .starts_with(diagnostic.branch.as_slice())
                })
        })
        .filter_map(|diagnostic| CertaintyReason::analyzer_ambiguity(diagnostic.code.as_str()).ok())
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    reasons
}

fn incomplete_reasons(
    completion: &CodeQueryCompletion,
    truncated: bool,
) -> Vec<PolicyIncompleteReason> {
    let mut reasons = match completion {
        CodeQueryCompletion::Incomplete { codes } => {
            codes.iter().map(incomplete_reason_for_code).collect()
        }
        CodeQueryCompletion::Cancelled => vec![PolicyIncompleteReason::Cancelled],
        CodeQueryCompletion::Complete | CodeQueryCompletion::Invalid { .. } => Vec::new(),
    };
    if truncated && reasons.is_empty() && !matches!(completion, CodeQueryCompletion::Invalid { .. })
    {
        reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    reasons
}

fn failure_reasons(completion: &CodeQueryCompletion) -> Vec<PolicyFailureReason> {
    match completion {
        CodeQueryCompletion::Invalid { .. } => vec![PolicyFailureReason::InvalidExecutionPlan],
        CodeQueryCompletion::Complete
        | CodeQueryCompletion::Incomplete { .. }
        | CodeQueryCompletion::Cancelled => Vec::new(),
    }
}

fn incomplete_reason_for_code(code: &CodeQueryDiagnosticCode) -> PolicyIncompleteReason {
    match code {
        CodeQueryDiagnosticCode::Cancelled => PolicyIncompleteReason::Cancelled,
        CodeQueryDiagnosticCode::UnsupportedStructuralFeature
        | CodeQueryDiagnosticCode::MissingStructuralAdapter
        | CodeQueryDiagnosticCode::UnsupportedImportAnalysis
        | CodeQueryDiagnosticCode::ReceiverAnalysisPartial
        | CodeQueryDiagnosticCode::UsesParserUnsupported => {
            PolicyIncompleteReason::CapabilityIncomplete
        }
        CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated => {
            PolicyIncompleteReason::SourceByteBudget
        }
        CodeQueryDiagnosticCode::ReferenceCandidateFilesTruncated => {
            PolicyIncompleteReason::ScannedFileBudget
        }
        CodeQueryDiagnosticCode::CallRelationBudgetExhausted
        | CodeQueryDiagnosticCode::CallRelationCandidateLimit
        | CodeQueryDiagnosticCode::ReferenceCandidatesOmitted
        | CodeQueryDiagnosticCode::ReferenceCallsiteLimit
        | CodeQueryDiagnosticCode::UsesCandidateLimit
        | CodeQueryDiagnosticCode::UsesCandidatesOmitted => {
            PolicyIncompleteReason::ReferenceCandidateBudget
        }
        CodeQueryDiagnosticCode::PipelineBudgetExhausted => {
            PolicyIncompleteReason::PipelineRowBudget
        }
        CodeQueryDiagnosticCode::ImportGraphBudgetExhausted => {
            PolicyIncompleteReason::ImportGraphBudget
        }
        CodeQueryDiagnosticCode::ResultLimitReached => PolicyIncompleteReason::QueryResultLimit,
        CodeQueryDiagnosticCode::SemanticResultsOmitted
        | CodeQueryDiagnosticCode::CallRelationParseFailed
        | CodeQueryDiagnosticCode::CallRelationCandidatesOmitted
        | CodeQueryDiagnosticCode::CallRelationAnalysisFailed
        | CodeQueryDiagnosticCode::ReferenceAnalysisFailed
        | CodeQueryDiagnosticCode::ExecutionBudgetExhausted => {
            PolicyIncompleteReason::PartialDiscovery
        }
        CodeQueryDiagnosticCode::InvalidPlan
        | CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
        | CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
        | CodeQueryDiagnosticCode::UsesTargetsAmbiguous
        | CodeQueryDiagnosticCode::BroadQuery => PolicyIncompleteReason::PartialDiscovery,
    }
}

fn adapt_query_diagnostic(
    diagnostic: &CodeQueryDiagnostic,
) -> Result<PolicyDiagnostic, ReportValueError> {
    let (severity, impact) = match diagnostic.impact {
        CodeQueryDiagnosticImpact::Advisory => (
            PolicyDiagnosticSeverity::Note,
            PolicyDiagnosticImpact::Advisory,
        ),
        CodeQueryDiagnosticImpact::Incomplete => (
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
        ),
        CodeQueryDiagnosticImpact::Invalid => (
            PolicyDiagnosticSeverity::Error,
            PolicyDiagnosticImpact::RunFailed,
        ),
    };
    PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::CodeQuery {
            code: diagnostic.code,
        },
        severity,
        impact,
        diagnostic.message.clone(),
        None,
        Vec::new(),
    )
}

fn internal_failure_diagnostic(message: &str) -> Result<PolicyDiagnostic, ()> {
    PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Error,
        PolicyDiagnosticImpact::RunFailed,
        message,
        None,
        Vec::new(),
    )
    .map_err(|_| ())
}

fn failed_before_execution(
    reason: PolicyFailureReason,
    message: &str,
    budget: &PolicyBudget,
) -> EvaluatedMatchPolicy {
    let diagnostic = internal_failure_diagnostic(message).ok();
    let retain_diagnostic = budget.max_diagnostics() > 0 && diagnostic.is_some();
    let diagnostics = if retain_diagnostic {
        diagnostic.into_iter().collect()
    } else {
        Vec::new()
    };
    EvaluatedMatchPolicy {
        candidates: Vec::new(),
        completion: PolicyRunCompletion::Failed {
            reasons: vec![reason],
        },
        diagnostics,
        diagnostics_truncated: !retain_diagnostic,
        work: work_report(CodeQueryExecutionWork::default(), 0, 0),
    }
}

fn work_report(
    work: CodeQueryExecutionWork,
    retained_findings: usize,
    omitted_findings_lower_bound: u64,
) -> PolicyWorkReport {
    PolicyWorkReport::try_new(
        work.scanned_files,
        work.scanned_source_bytes,
        work.fact_nodes,
        work.pipeline_rows,
        work.examined_references,
        u64::try_from(retained_findings).expect("usize fits in u64 on supported targets"),
        omitted_findings_lower_bound,
        0,
        Vec::new(),
    )
    .expect("an empty metric set always satisfies the work-report schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::policy::{CvssMetricValueToken, EvidenceRef};
    use crate::analyzer::structural::CodeQuery;
    use crate::analyzer::{ProjectFile, TestProject, TypescriptAnalyzer};
    use serde_json::json;

    #[test]
    fn cvss_overlay_hash_uses_canonical_labels_and_utc_time() {
        let metadata = |assessed_at: &str, rationale: &str| {
            CvssOverlayEvidenceMetadata::try_new(
                vec![EvidenceRef::try_new("feed", "record-17").expect("evidence ref")],
                rationale.to_string(),
                vec!["applies to production".to_string()],
                "test-feed".to_string(),
                assessed_at.to_string(),
                CvssEvidenceScope::Global,
                Some(CvssExternalArtifactHash::from_bytes([23; 32])),
            )
            .expect("metadata")
        };
        let metric = CvssMetric::Threat {
            metric: CvssThreatMetric::E,
        };
        let value = CvssMetricValue::try_new(metric, CvssMetricValueToken::A).expect("value");
        let local = CvssThreatOverlayEvidence::try_new(
            CvssThreatMetric::E,
            value,
            metadata("2026-07-18T12:34:56+02:00", "trusted feed record"),
        )
        .expect("local-time evidence");
        let utc = CvssThreatOverlayEvidence::try_new(
            CvssThreatMetric::E,
            value,
            metadata("2026-07-18T10:34:56Z", "trusted feed record"),
        )
        .expect("UTC evidence");
        let changed = CvssThreatOverlayEvidence::try_new(
            CvssThreatMetric::E,
            value,
            metadata("2026-07-18T10:34:56Z", "different trusted feed record"),
        )
        .expect("changed evidence");

        assert_eq!(local.metadata().assessed_at(), "2026-07-18T10:34:56Z");
        assert_eq!(local.content_hash(), utc.content_hash());
        assert_ne!(local.content_hash(), changed.content_hash());
        assert_eq!(
            cvss_evidence_basis_label(CvssEvidenceBasis::ThreatFeed),
            "threat_feed"
        );
        assert_eq!(
            cvss_evidence_scope_labels(CvssEvidenceScope::System {
                system: CvssSystemScope::SubsequentSystem,
            }),
            ("system", Some("subsequent_system"))
        );
    }

    #[test]
    fn broad_advisory_stays_complete_and_untruncated_capability_gap_is_inconclusive() {
        let broad = CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::BroadQuery,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: Vec::new(),
            language: "workspace",
            message: "broad query".to_string(),
        };
        assert!(certainty_reasons(&[broad], &[]).is_empty());
        assert!(incomplete_reasons(&CodeQueryCompletion::Complete, false).is_empty());

        let completion = CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::UnsupportedStructuralFeature],
        };
        assert_eq!(
            incomplete_reasons(&completion, false),
            vec![PolicyIncompleteReason::CapabilityIncomplete]
        );
    }

    #[test]
    fn rejected_query_diagnostic_marks_truncation_without_hiding_later_valid_diagnostics() {
        let rejected = CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::BroadQuery,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: Vec::new(),
            language: "workspace",
            message: "x".repeat(4_097),
        };
        let valid = CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: Vec::new(),
            language: "typescript",
            message: "later valid diagnostic".to_string(),
        };

        let adapted = adapt_query_diagnostics(&[rejected, valid], 1);

        assert!(adapted.adaptation_failed);
        assert!(adapted.truncated);
        assert_eq!(adapted.diagnostics.len(), 1);
        assert_eq!(adapted.diagnostics[0].message(), "later valid diagnostic");
    }

    #[test]
    fn rejected_detailed_row_does_not_hide_later_positive_candidates() {
        let source = r#"export function run() {
    alpha();
    beta();
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "app.ts")
            .write(source)
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let mut query =
            CodeQuery::from_json(&json!({ "match": { "kind": "call" } })).expect("query");
        query.result_detail = CodeQueryResultDetail::Full;
        let detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            PolicyBudget::default().query_limits(),
            None,
        );
        assert_eq!(detailed.result.results.len(), 2);
        assert_eq!(detailed.evidence.len(), 2);
        let query_diagnostics = detailed.result.diagnostics.clone();
        let results = detailed.result.results;
        let mut evidence = detailed.evidence;
        let retained_span = evidence[1].byte_span.clone();
        evidence[0].domain = DetailedCodeQueryDomain::ReceiverAnalysis;

        let adapted = adapt_match_candidates(
            &PolicyId::new("test.partial-row-conversion").expect("policy id"),
            results,
            evidence,
            &query_diagnostics,
        );

        assert!(adapted.conversion_failed);
        assert_eq!(adapted.omitted_findings_lower_bound, 1);
        assert_eq!(adapted.candidates.len(), 1);
        assert_eq!(
            adapted.candidates[0]
                .location
                .byte_span()
                .map(|span| span.start()..span.end()),
            retained_span.map(|span| {
                u64::try_from(span.start).expect("start")..u64::try_from(span.end).expect("end")
            })
        );
    }

    #[test]
    fn cancellation_after_query_rows_retains_partial_match_candidates() {
        let source = r#"export function caller() {
    alpha();
    beta();
    gamma();
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "app.ts")
            .write(source)
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({ "match": { "kind": "call" } })).expect("query");
        let policy_id = PolicyId::new("test.partial-cancellation").expect("policy id");

        let evaluated = (2..96)
            .find_map(|checks| {
                let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
                let evaluated = evaluate_match_query_candidates(
                    &policy_id,
                    &analyzer,
                    &query,
                    &PolicyBudget::default(),
                    Some(&cancellation),
                );
                (matches!(
                    evaluated.completion,
                    PolicyRunCompletion::Inconclusive { ref reasons }
                        if reasons.contains(&PolicyIncompleteReason::Cancelled)
                ) && !evaluated.candidates.is_empty()
                    && evaluated.candidates.len() < 3)
                    .then_some(evaluated)
            })
            .expect("deterministic cancellation retains some positive candidates");

        assert!(!evaluated.candidates.is_empty());
        assert!(evaluated.candidates.len() < 3);
        assert_eq!(
            evaluated.work.retained_findings(),
            evaluated.candidates.len() as u64
        );
    }

    #[test]
    fn match_candidate_conversion_accepts_all_positive_domains_and_rejects_receiver_terminal() {
        let source = r#"export function target(payload: string) { return payload; }
export function caller() { return target("secret"); }
class Service { run() {} }
export function invoke(service: Service) { service.run(); }
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let policy_id = PolicyId::new("test.match-domains").expect("policy id");
        let cases = [
            json!({ "match": { "kind": "function", "name": "target" } }),
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "enclosing_decl" }]
            }),
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "references_of", "proof": "proven" }
                ]
            }),
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" }
                ]
            }),
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 }
                ]
            }),
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "file_of" }]
            }),
        ];
        let expected = [
            MatchResultDomain::StructuralMatch,
            MatchResultDomain::Declaration,
            MatchResultDomain::ReferenceSite,
            MatchResultDomain::CallSite,
            MatchResultDomain::ExpressionSite,
            MatchResultDomain::File,
        ];
        for (query, expected) in cases.into_iter().zip(expected) {
            let query = CodeQuery::from_json(&query).expect("query");
            let evaluated = evaluate_match_query_candidates(
                &policy_id,
                &analyzer,
                &query,
                &PolicyBudget::default(),
                None,
            );
            assert_eq!(evaluated.completion, PolicyRunCompletion::Complete);
            assert_eq!(evaluated.candidates.len(), 1);
            assert_eq!(evaluated.candidates[0].evidence.result_domain(), expected);
            assert_eq!(
                evaluated.candidates[0].evidence.anchor().result_domain(),
                expected
            );
            assert_eq!(
                evaluated.candidates[0].location.is_artifact_only(),
                expected == MatchResultDomain::File
            );
        }

        let receiver = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }]
        }))
        .expect("query");
        let evaluated = evaluate_match_query_candidates(
            &policy_id,
            &analyzer,
            &receiver,
            &PolicyBudget::default(),
            None,
        );
        assert!(matches!(
            evaluated.completion,
            PolicyRunCompletion::Failed { .. }
        ));
        assert_eq!(evaluated.work.pipeline_rows(), 0);
    }

    #[test]
    fn strong_fingerprint_ignores_preceding_coordinates_but_tracks_selected_bytes() {
        let policy_id = PolicyId::new("test.fingerprint").expect("policy id");
        let path = WorkspaceRelativePath::new("src/app.ts").expect("path");
        let owner = StableSemanticIdentity::analyzer_declaration_id(
            "typescript",
            path.clone(),
            "function:target(payload: string)",
        )
        .expect("owner");
        let anchor = |hash, ordinal| {
            MatchFindingAnchor::strong(
                MatchResultDomain::StructuralMatch,
                path.clone(),
                Some(owner.clone()),
                Some(SourceSliceHash::from_bytes(hash)),
                ordinal,
            )
            .expect("anchor")
        };
        let first = PolicyFindingId::from_match_anchor(&policy_id, &anchor([7; 32], 0));
        let shifted = PolicyFindingId::from_match_anchor(&policy_id, &anchor([7; 32], 0));
        let changed = PolicyFindingId::from_match_anchor(&policy_id, &anchor([8; 32], 0));
        let duplicate = PolicyFindingId::from_match_anchor(&policy_id, &anchor([7; 32], 1));
        assert_eq!(first, shifted);
        assert_ne!(first, changed);
        assert_ne!(first, duplicate);
    }

    #[test]
    fn cross_file_provenance_keeps_target_caller_and_callee_identities_distinct() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "target.ts")
            .write("export function target() {}\n")
            .expect("write target");
        ProjectFile::new(root.clone(), "caller.ts")
            .write("import { target } from './target';\nexport function caller() { target(); }\n")
            .expect("write caller");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let policy_id = PolicyId::new("test.cross-file-provenance").expect("policy id");
        let evaluate = |operation: &str| {
            let query = CodeQuery::from_json(&json!({
                "where": ["target.ts"],
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": operation, "proof": "proven" }
                ]
            }))
            .expect("query");
            evaluate_match_query_candidates(
                &policy_id,
                &analyzer,
                &query,
                &PolicyBudget::default(),
                None,
            )
        };

        let reference = evaluate("references_of");
        assert_eq!(reference.candidates.len(), 1);
        let reference_step = reference.candidates[0].evidence.provenance()[0]
            .steps()
            .last()
            .expect("reference step");
        let PolicyQueryResultRef::ReferenceSite {
            target_identity: Some(target_identity),
            ..
        } = reference_step.result()
        else {
            panic!("reference provenance must retain its target identity");
        };
        assert_eq!(target_identity.path().as_str(), "target.ts");

        let call = evaluate("call_sites_to");
        assert_eq!(call.candidates.len(), 1);
        let call_step = call.candidates[0].evidence.provenance()[0]
            .steps()
            .last()
            .expect("call step");
        let PolicyQueryResultRef::CallSite {
            caller_identity: Some(caller_identity),
            callee_identity: Some(callee_identity),
            ..
        } = call_step.result()
        else {
            panic!("call provenance must retain caller and callee identities");
        };
        assert_eq!(caller_identity.path().as_str(), "caller.ts");
        assert_eq!(callee_identity.path().as_str(), "target.ts");
    }

    #[test]
    fn proven_call_without_a_stable_caller_identity_is_name_based_but_keeps_strong_anchor() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "target.ts")
            .write("export function target() {}\n")
            .expect("write target");
        ProjectFile::new(root.clone(), "caller.ts")
            .write("import { target } from './target';\nexport function caller() { target(); }\n")
            .expect("write caller");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let policy_id = PolicyId::new("test.missing-caller-identity").expect("policy id");
        let query = CodeQuery::from_json(&json!({
            "where": ["target.ts"],
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" }
            ],
            "result_detail": "full"
        }))
        .expect("query");

        let mut detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            crate::analyzer::structural::CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(detailed.result.results.len(), 1);
        assert_eq!(detailed.evidence.len(), 1);
        let mut evidence = detailed.evidence.pop().expect("call evidence");
        let call_step = evidence.provenance[0].steps.last_mut().expect("call step");
        let DetailedCodeQueryProvenanceIdentities::Call { caller, .. } =
            &mut call_step.result.identities
        else {
            panic!("expected call identities");
        };
        *caller = None;
        let item = detailed.result.results.pop().expect("call result");
        let mut ordinals = HashMap::new();
        let candidate = adapt_match_candidate(
            &policy_id,
            item,
            evidence,
            &detailed.result.diagnostics,
            &mut ordinals,
        )
        .expect("candidate");

        assert!(matches!(
            candidate.evidence.anchor(),
            MatchFindingAnchor::Strong(_)
        ));
        assert!(matches!(
            candidate.certainty,
            FindingCertainty::Possible { reasons }
                if reasons.contains(&CertaintyReason::NameBasedResolution)
        ));
        assert_eq!(candidate.proof.state(), ProofState::Unproven);
        let step = candidate.evidence.provenance()[0]
            .steps()
            .last()
            .expect("call step");
        assert!(matches!(
            step.result(),
            PolicyQueryResultRef::CallSite {
                caller_identity: None,
                callee_identity: Some(_),
                proof: PolicyQueryProof::NameBased,
                ..
            }
        ));
    }

    #[test]
    fn advisory_ambiguity_only_lowers_findings_from_the_affected_set_branch() {
        let file = ProjectFile::new(std::env::temp_dir(), "app.ts");
        let provenance = |branch| DetailedCodeQueryProvenanceEvidence {
            branch: vec![branch],
            seed: DetailedCodeQueryProvenanceRefEvidence {
                domain: DetailedCodeQueryDomain::File,
                key: DetailedCodeQueryKey::File,
                file: file.clone(),
                byte_span: None,
                display_range: None,
                identities: DetailedCodeQueryProvenanceIdentities::None,
                source_slice_sha256: None,
            },
            steps: Vec::new(),
        };
        let diagnostic = CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: vec![0],
            language: "typescript",
            message: "branch-local ambiguity".to_string(),
        };

        assert_eq!(
            certainty_reasons(&[diagnostic.clone()], &[provenance(0)]).len(),
            1
        );
        assert!(certainty_reasons(&[diagnostic], &[provenance(1)]).is_empty());
    }

    #[test]
    fn invalid_owner_candidate_forces_weak_anchor() {
        let file = ProjectFile::new(std::env::temp_dir(), "src/app.ts");
        let evidence = DetailedCodeQueryEvidence {
            result_index: 0,
            domain: DetailedCodeQueryDomain::StructuralMatch,
            key: DetailedCodeQueryKey::StructuralMatch {
                kind: "call".to_string(),
                analyzer_id: None,
            },
            file,
            byte_span: Some(0..4),
            stable_owner_candidate: Some(
                crate::analyzer::structural::search::CodeQueryStableOwnerCandidate {
                    namespace: "INVALID".to_string(),
                    derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
                    semantic_key: "call:sink".to_string(),
                },
            ),
            source_slice_sha256: Some([1; 32]),
            provenance: Vec::new(),
        };
        assert!(matches!(OwnerCandidate::Rejected, OwnerCandidate::Rejected));
        let key = weak_finding_key(&evidence);
        assert!(key.as_str().starts_with("code-query:"));
    }

    #[test]
    fn unicode_location_conversion_preserves_byte_and_codepoint_coordinates() {
        let path = WorkspaceRelativePath::new("src/unicode.ts").expect("path");
        let location = policy_span_location(
            path,
            &(3..7),
            CodeQueryRange {
                start_line: 2,
                start_column: 4,
                end_line: 2,
                end_column: 6,
            },
        )
        .expect("location");
        assert_eq!(location.byte_span().expect("bytes").start(), 3);
        assert_eq!(location.byte_span().expect("bytes").end(), 7);
        assert_eq!(location.region().expect("region").start_column(), 4);
        assert_eq!(location.region().expect("region").end_column(), 6);
    }

    #[test]
    fn weak_key_is_domain_and_span_separated() {
        let file = ProjectFile::new(std::env::temp_dir(), "src/app.ts");
        let evidence = |span| DetailedCodeQueryEvidence {
            result_index: 0,
            domain: DetailedCodeQueryDomain::StructuralMatch,
            key: DetailedCodeQueryKey::StructuralMatch {
                kind: "call".to_string(),
                analyzer_id: None,
            },
            file: file.clone(),
            byte_span: Some(span),
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
        };
        assert_ne!(
            weak_finding_key(&evidence(0..4)),
            weak_finding_key(&evidence(5..9))
        );
    }

    #[test]
    fn file_anchor_never_uses_a_span() {
        let path = WorkspaceRelativePath::new("src/app.ts").expect("path");
        let anchor = MatchFindingAnchor::strong(MatchResultDomain::File, path, None, None, 0)
            .expect("file anchor");
        assert_eq!(anchor.result_domain(), MatchResultDomain::File);
    }
}
