//! Context-requiring projection from diagnostic-neutral analyzer results.
//!
//! This module deliberately stops at a crate-private match candidate seam.
//! Public `PolicyFinding`/`PolicyRun` assembly owns classification, reporting,
//! and retained-size budgets and is wired here only after those aggregates
//! have been validated.

mod assertion;
mod cvss_evidence;
mod typestate_compilation;

pub(crate) use assertion::SubjectQueryBatch;
use assertion::evaluate_assertion_policy;
use cvss_evidence::*;
pub(crate) use typestate_compilation::TypestateCompilationFailure;

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, SecondsFormat};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use brokk_bifrost_analysis::analyzer::canonical_hash::write_length_prefixed as update_hash;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::Range as AnalyzerRange;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_analysis::analyzer::usages::{UsageHitSurface, UsageProof};
use brokk_bifrost_analysis::analyzer::{CodeUnit, IAnalyzer, ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_flow::flow_state::{
    FileFlowState, FlowRelation, FlowStateAxis, FlowStateDerivation, FlowSubject, StateEventClass,
    StateEventRow, flow_state_for_file_with_snapshot,
};
use brokk_bifrost_rql::structural::edges::EdgeAxis;
use brokk_bifrost_rql::structural::materialization::MaterializationAxis;
use brokk_bifrost_rql::structural::materialization_rows::{
    DeclarationStateRow, MaterializationFileResult, materialization_for_file,
};
use brokk_bifrost_rql::structural::occurrences::OccurrenceClass as InternalOccurrenceClass;
use brokk_bifrost_rql::structural::occurrences::OccurrenceRole;
use brokk_bifrost_rql::structural::reference_edges::{
    EdgeDerivationResult, ReferenceEdgeRow, SelectedInverseEdgeCache, forward_edges_for_file,
    inverse_edges_for_declaration,
};
use brokk_bifrost_rql::structural::rewrite_path::RewriteOutcome;
use brokk_bifrost_rql::structural::rewrite_paths::{FileRewritePaths, RewritePathIncompleteReason};
use brokk_bifrost_rql::structural::search::{
    CodeQueryBinding, CodeQueryCandidateRef, CodeQueryGenerationSite, CodeQueryLexicalScope,
    CodeQueryOccurrence, CodeQueryResolutionCandidate,
};
use brokk_bifrost_rql::structural::search::{
    CodeQueryExecutionScope, CodeQueryRowFamilySession, CodeQueryStableOwnerCandidate,
    CodeQueryStableOwnerDerivation, DetailedCodeQueryDomain,
    DetailedCodeQueryExportLocalDefinition, DetailedCodeQueryKey, UnitRowEvidence,
    UnitRowIdentities, UnitRowIdentityCandidate, UnitRowItem, UnitRowItemProvenance,
    UnitRowItemRef, UnitRowItemRefValue, UnitRowItemTerminal, UnitRowProvenance,
    UnitRowProvenanceRef, execute_code_query_detailed_eager_index,
    execute_code_query_detailed_eager_index_in_scope,
    execute_code_query_detailed_eager_index_with_row_family_session_in_scope,
    execute_code_query_detailed_eager_index_workspace,
    execute_code_query_detailed_eager_index_workspace_in_scope, execute_code_query_unit,
};
use brokk_bifrost_rql::structural::{BoundaryStatus, PrecedenceTier};
use brokk_bifrost_rql::structural::{
    CanonicalIdentity, IDENTITY_PRESERVING_HOPS, OccurrenceFileResult, RoundTripOutcome,
    RouteEndpoint, RouteHopKind, RouteTermination, file_supplies_route_relations,
    identity_routes_from, occurrences_for_file, round_trip_from_site,
};
use brokk_bifrost_rql::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryExecutionWork, CodeQueryRange, CodeQueryResultDetail,
    CodeQueryResultItem, CodeQueryResultValue, CodeQueryRowScalarRef, OwnerRelation,
    QueryValueKind,
};
use brokk_bifrost_rql::structural::{
    NormalizedKind, OccurrenceRow as InternalOccurrenceRow,
    OccurrenceTarget as InternalOccurrenceTarget, canonical_identity_of,
};
use brokk_bifrost_rql::{
    ArityConstraint, BindingOfOptions, CandidateFilter, CodeQueryPlan, CodeQueryPlanSource,
    CodeQuerySeed, GenerationSiteSeed, OccurrenceSeed, Pattern, QueryStep, SCHEMA_VERSION,
    ScopeSeed, exact_path_globs,
};
use std::sync::Arc;

use super::budget::PolicyBudget;
use super::classification::{
    ClassificationProjection, MAX_REPORT_PROSE_BYTES, OrganizationalRiskAssessment,
    TaintPresentationReducer, normalize_evidence_refs, reduce_finding_classification,
    validate_required_text,
};
use super::cvss::{
    CvssEvidenceBasis, CvssEvidenceContentHash, CvssFindingProjection, CvssMetricEvidence,
    CvssSeverity, CvssValidationError, PolicyOverlayScope, reduce_cvss_for_finding,
};
use super::definition::{
    ASSERTION_SUBJECT_SELECTOR_PATH, AssertionPolicySpec, BindingScopeAssert, BoundaryAssert,
    CanonicalAssert, CvssEnvironmentalOrSupplementalMetric, CvssEvidenceScope, CvssMetric,
    CvssMetricValue, CvssThreatMetric, DeclarationStateAssert, EdgeClassAssert,
    EdgeClassConstraint, EdgeParityAssert, EstablishmentRequirement, FindingSeverity,
    FlowEstablishmentAssert, GenerationAssert, OccurrenceAssert, OriginShapeAssert, PolicyAnalysis,
    PolicyAnalysisType, PolicyAssert, PolicyId, PolicyLevel, PolicyMessageSpec, PolicySeveritySpec,
    ResolutionAssert, RoundTripAssert, RouteAssert, ValueOriginAssert,
};
use super::finding::{
    CertaintyReason, FindingCertainty, FindingCompleteness, FindingIncompleteReason,
    MatchFindingEvidence, PolicyCapability, PolicyDiagnostic, PolicyDiagnosticCode,
    PolicyDiagnosticImpact, PolicyDiagnosticSeverity, PolicyExportLocalDefinition,
    PolicyFailureReason, PolicyFinding, PolicyFindingEvidence, PolicyIncompleteReason,
    PolicyLocationRelationship, PolicyQueryProof, PolicyQueryProvenance, PolicyQueryProvenanceStep,
    PolicyQueryResultRef, PolicyRun, PolicyRunCompletion, PolicyRunError, PolicySourceLocation,
    PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit, ProofMetadata, ProofReason, ProofState,
    RelatedPolicyLocation, ReportValueError, insert_policy_diagnostic_bounded,
    normalize_policy_diagnostics_bounded,
};
use super::finding_identity::{
    EvidenceRef, FindingIdentityStability, MatchFindingAnchor, MatchResultDomain, OpaqueFindingKey,
    PolicyFindingId, SourceScenarioId, SourceSliceHash, StableSemanticIdentity,
};
use super::future_evidence::{
    FlowFindingEvidence, FutureEvidenceError, TaintFindingEvidence, TypestateFindingEvidence,
    TypestateViolationEvidence,
};
use super::projection::{
    TaintProjectionAuthority, TaintProjectionBatch, TaintProjectionPayload,
    TypestateCompilationHashes, TypestateProjectionAuthority, TypestateProjectionBatch,
    TypestateProjectionPayload, validate_taint_batch, validate_typestate_batch,
};
use super::resolved::{LoadedPolicy, ResolvedTaintPolicySpec, ResolvedTypestatePolicySpec};
use super::retained::RetainedSize;
use super::unit_execution::{
    SeedPartition, UnitAttempt, UnitQueryExecution, UnitReuse, query_slicing_widen_reason,
    recompute_unit, sliced_query_units,
};
use super::units::{
    PolicyIncrementalContext, PolicyIncrementalRun, PolicyUnitProduct, UnitPartition, WidenReason,
};

const MATCH_SELECTOR_PATH: &str = "/analysis/selector";
const WEAK_KEY_DOMAIN: &[u8] = b"bifrost-policy-match-weak-key/v1";
const CVSS_OVERLAY_HASH_DOMAIN: &[u8] = b"bifrost-policy-cvss-overlay/v1";
const MAX_OVERLAY_ASSUMPTIONS: usize = 64;

/// Host context supplied to one policy evaluation.
pub struct PolicyEvaluationContext<'a> {
    pub analyzer: &'a dyn IAnalyzer,
    /// Full workspace semantics for analyses that lower structural matches
    /// into procedure, value, call-site, and heap identities.
    pub workspace: Option<&'a WorkspaceAnalyzer>,
    pub flow_state: &'a brokk_bifrost_flow::FlowWorkspaceState,
    pub root_memo: Option<&'a brokk_bifrost_rql::TypeFlowRootMemo>,
    pub cancellation: Option<&'a CancellationToken>,
    pub cvss_overlays: &'a [CvssEvaluationOverlay],
    pub organizational_risk: &'a [OrganizationalRiskOverlay],
    /// The units this evaluation may reuse, and the workspace to verify them
    /// against.
    ///
    /// `None` is the ordinary case and is exactly today's evaluation: no
    /// store to look a unit up in, so nothing to reuse and nothing to publish.
    /// A `--diff-base` run with `incremental` on supplies one on both sides.
    pub incremental: Option<&'a PolicyIncrementalContext<'a>>,
}

impl PolicyEvaluationContext<'_> {
    pub(crate) fn flow_resources(&self) -> brokk_bifrost_rql::SemanticFlowResources {
        brokk_bifrost_rql::SemanticFlowResources::from_workspace_state(self.flow_state)
            .with_root_memo(self.root_memo.cloned())
    }
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
        brokk_bifrost_analysis::analyzer::canonical_hash::write_lower_hex(&self.0, formatter)
    }
}

impl Serialize for CvssExternalArtifactHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::serialize_display_value(self, serializer)
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

    pub(crate) fn try_new_metric_evidence(
        &self,
        metric: CvssMetric,
        value: CvssMetricValue,
        basis: CvssEvidenceBasis,
        content_hash: CvssEvidenceContentHash,
    ) -> Result<CvssMetricEvidence, CvssValidationError> {
        CvssMetricEvidence::try_new(
            metric,
            value,
            basis,
            self.evidence_refs.clone(),
            self.rationale.clone(),
            self.assumptions.clone(),
            self.assessor_or_tool.clone(),
            Some(self.assessed_at.clone()),
            self.system_scope,
            content_hash,
        )
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
pub(crate) trait TaintPolicyEvaluator:
    super::projection::sealed::TaintAdapter + Send + Sync
{
    fn evaluate_taint(
        &self,
        authority: &TaintProjectionAuthority,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> TaintProjectionPayload;
}

/// Adapter boundary for the future typestate compiler and solver integration.
pub(crate) trait TypestatePolicyEvaluator:
    super::projection::sealed::TypestateAdapter + Send + Sync
{
    /// Return the exact hashes produced by the in-crate protocol and binding
    /// compilers. This is a trusted compiler claim, not an exhaustion proof.
    fn compilation_hashes(
        &self,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> Result<TypestateCompilationHashes, TypestateCompilationFailure>;

    fn evaluate_typestate(
        &self,
        authority: &TypestateProjectionAuthority,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> TypestateProjectionPayload;

    /// What this adapter's sliced attempt did with its root units, taken once
    /// per evaluation.
    ///
    /// `None` is an adapter that does not partition its work into units at
    /// all, which the caller records as a whole-family run. The default is
    /// `None` because a test fake solves whatever it is asked to and reuses
    /// nothing.
    fn take_unit_attempt(
        &self,
        _policy_id: &PolicyId,
    ) -> Option<(UnitAttempt, Option<WidenReason>)> {
        None
    }
}

/// Built-in match evaluator with optional future-analysis adapters.
pub struct DefaultPolicyEvaluator<'a> {
    subject_batch: Option<&'a SubjectQueryBatch<'a>>,
    taint: Option<&'a dyn TaintPolicyEvaluator>,
    typestate: Option<&'a dyn TypestatePolicyEvaluator>,
    /// Request-selected activation shared by assertion flow derivation and
    /// the installed production adapters.
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
}

impl<'a> DefaultPolicyEvaluator<'a> {
    pub const fn new() -> Self {
        Self::with_optional_adapters(None, None)
    }

    const fn with_optional_adapters(
        taint: Option<&'a dyn TaintPolicyEvaluator>,
        typestate: Option<&'a dyn TypestatePolicyEvaluator>,
    ) -> Self {
        let evaluator = Self {
            subject_batch: None,
            taint: None,
            typestate: None,
            active_semantic_model_snapshot: None,
        };
        let evaluator = match taint {
            Some(adapter) => evaluator.with_taint(adapter),
            None => evaluator,
        };
        match typestate {
            Some(adapter) => evaluator.with_typestate(adapter),
            None => evaluator,
        }
    }

    /// Install the crate-owned taint adapter while preserving any typestate
    /// adapter already configured on this evaluator.
    pub(crate) const fn with_taint(mut self, taint: &'a dyn TaintPolicyEvaluator) -> Self {
        self.taint = Some(taint);
        self
    }

    /// Install the crate-owned typestate adapter while preserving any taint
    /// adapter already configured on this evaluator.
    pub(crate) const fn with_typestate(
        mut self,
        typestate: &'a dyn TypestatePolicyEvaluator,
    ) -> Self {
        self.typestate = Some(typestate);
        self
    }

    pub(crate) fn with_subject_batch(mut self, batch: Option<&'a SubjectQueryBatch<'a>>) -> Self {
        self.subject_batch = batch;
        self
    }

    /// Pin assertion flow derivation to the host's request-level activation.
    pub(crate) fn with_active_semantic_model_snapshot(
        mut self,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        self.active_semantic_model_snapshot = snapshot;
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
        self.evaluate_with_optional_scope(policy, context, budget, None)
    }
}

impl DefaultPolicyEvaluator<'_> {
    /// Evaluate one policy over an explicit seed scope.
    ///
    /// Scoped policy runs intentionally do not use incremental units or the
    /// subject-query batch: both cache whole-workspace questions. The scope is
    /// applied only to the policy's subject/binding query; assertion row-family
    /// and dependency queries retain their existing full-workspace behavior.
    pub(crate) fn evaluate_in_scope(
        &self,
        policy: &LoadedPolicy,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
        execution_scope: CodeQueryExecutionScope<'_>,
    ) -> Result<PolicyRun, PolicyRunError> {
        self.evaluate_with_optional_scope(policy, context, budget, Some(execution_scope))
    }

    fn evaluate_with_optional_scope(
        &self,
        policy: &LoadedPolicy,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
        execution_scope: Option<CodeQueryExecutionScope<'_>>,
    ) -> Result<PolicyRun, PolicyRunError> {
        let host_budget = *budget;
        if execution_scope.is_some() && !policy_supports_execution_scope(policy) {
            return unsupported_scoped_policy_run(policy, &host_budget);
        }
        // Every family accounts for itself. The families that are sliced record
        // their own attempt, whether or not it widened; the rest state here
        // that they were evaluated whole rather than being absent from the
        // review.
        if execution_scope.is_none()
            && let Some(incremental) = context.incremental
            && !evaluates_by_unit(&policy.definition().analysis)
        {
            incremental.record_run(PolicyIncrementalRun::whole_family(
                policy.definition().metadata.id.clone(),
            ));
        }
        match &policy.definition().analysis {
            PolicyAnalysis::Match { .. } => evaluate_match_policy(
                policy,
                context,
                &host_budget,
                execution_scope
                    .is_none()
                    .then_some(self.subject_batch)
                    .flatten(),
                execution_scope,
            ),
            PolicyAnalysis::Assertion { spec } => evaluate_assertion_policy(
                policy,
                spec,
                context,
                &host_budget,
                self.active_semantic_model_snapshot.clone(),
                execution_scope
                    .is_none()
                    .then_some(self.subject_batch)
                    .flatten(),
                execution_scope,
            ),
            // Flow executes the production taint pipeline over the same
            // resolved model with one internal label (#2436); only the run's
            // analysis type and the finding evidence variant differ.
            PolicyAnalysis::Taint { .. } | PolicyAnalysis::Flow { .. } => {
                let analysis_type = policy.definition().analysis.analysis_type();
                let Some(spec) = policy.resolved_taint() else {
                    return failed_policy_run(
                        policy,
                        analysis_type,
                        "loaded policy is missing its resolved taint-shaped analysis specification",
                        &host_budget,
                    );
                };
                match self.taint {
                    Some(adapter) => {
                        let authority = match TaintProjectionAuthority::from_loaded(policy) {
                            Ok(authority) => authority,
                            Err(_) => {
                                return failed_policy_run(
                                    policy,
                                    analysis_type,
                                    "taint projection authority could not be derived from the loaded policy",
                                    &host_budget,
                                );
                            }
                        };
                        let payload =
                            adapter.evaluate_taint(&authority, policy, spec, context, &host_budget);
                        let batch = authority.seal_batch(payload);
                        assemble_taint_projection_batch(
                            policy,
                            &authority,
                            batch,
                            context,
                            &host_budget,
                        )
                    }
                    None => unsupported_policy_run(
                        policy,
                        analysis_type,
                        PolicyCapability::TaintEvaluation,
                        "taint-shaped policy evaluation requires an installed taint adapter",
                        &host_budget,
                    ),
                }
            }
            PolicyAnalysis::Typestate { .. } => {
                let run = self.evaluate_typestate_policy(policy, context, budget, host_budget);
                // The typestate family accounts for its own attempt on every
                // path, including the ones that never reach the adapter: a
                // policy missing from the review would change the review's
                // retained size between a reusing run and the forced-full run
                // it must equal byte for byte.
                if let Some(incremental) = context.incremental {
                    let policy_id = policy.definition().metadata.id.clone();
                    let review = match self
                        .typestate
                        .and_then(|adapter| adapter.take_unit_attempt(&policy_id))
                    {
                        Some((attempt, reason)) => attempt.into_run(policy_id, reason),
                        None => PolicyIncrementalRun::whole_family(policy_id),
                    };
                    note_incremental_run(&review, incremental);
                    incremental.record_run(review);
                }
                run
            }
        }
    }
}

/// Whether the policy's authored seed queries can honor an explicit execution
/// scope. This is intentionally narrower than whole-query support: only the
/// Match selector and Assertion subject or binding queries are narrowed.
pub(crate) fn policy_uses_only_file_facts(policy: &LoadedPolicy) -> bool {
    match_policy_query(policy).is_ok_and(|query| query.plan.source.uses_only_file_facts())
}

pub(crate) fn policy_supports_execution_scope(policy: &LoadedPolicy) -> bool {
    match &policy.definition().analysis {
        PolicyAnalysis::Match { .. } => policy
            .resolved_selectors()
            .iter()
            .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
            .and_then(|selector| selector.as_query().map(|(_, query)| query))
            .is_some_and(query_supports_execution_scope),
        PolicyAnalysis::Assertion { spec } => match &spec.relational {
            Some(plan) => plan.bindings.iter().all(|binding| {
                let super::definition::RowBindingSource::Query(_) = &binding.source;
                let path = super::definition::relational_binding_selector_path(&binding.name);
                policy
                    .resolved_selectors()
                    .iter()
                    .find(|selector| selector.path.as_str() == path)
                    .and_then(|selector| selector.as_query().map(|(_, query)| query))
                    .is_some_and(query_supports_execution_scope)
            }),
            None => policy
                .resolved_selectors()
                .iter()
                .find(|selector| selector.path.as_str() == ASSERTION_SUBJECT_SELECTOR_PATH)
                .and_then(|selector| selector.as_query().map(|(_, query)| query))
                .is_some_and(query_supports_execution_scope),
        },
        PolicyAnalysis::Taint { .. }
        | PolicyAnalysis::Flow { .. }
        | PolicyAnalysis::Typestate { .. } => false,
    }
}

fn query_supports_execution_scope(query: &CodeQuery) -> bool {
    query_plan_source_supports_execution_scope(&query.plan.source)
}

fn query_plan_source_supports_execution_scope(source: &CodeQueryPlanSource) -> bool {
    let mut pending = vec![source];
    while let Some(source) = pending.pop() {
        match source {
            // Configuration seeds and dependency evidence ignore a narrowed
            // unit scope, and a cross-domain operator reads both of its inputs
            // whole (#3284).
            CodeQueryPlanSource::DependencyEvidence(_)
            | CodeQueryPlanSource::ConfigurationFacts(_)
            | CodeQueryPlanSource::Correlate(_)
            | CodeQueryPlanSource::RequireBoth(_) => return false,
            CodeQueryPlanSource::Set { branches, .. } => {
                pending.extend(branches.iter().map(|branch| &branch.source));
            }
            CodeQueryPlanSource::Seed(_)
            | CodeQueryPlanSource::Occurrences(_)
            | CodeQueryPlanSource::Scopes(_)
            | CodeQueryPlanSource::Bindings(_)
            | CodeQueryPlanSource::Paths(_)
            | CodeQueryPlanSource::GenerationSites(_)
            | CodeQueryPlanSource::Exports(_) => {}
        }
    }
    true
}

impl DefaultPolicyEvaluator<'_> {
    /// One typestate policy's evaluation, from its compile through its
    /// projection batch.
    ///
    /// Lifted out of the `match` arm so that every path it can take -- a
    /// missing specification, an incomplete compile, a refused authority, an
    /// absent adapter -- returns to one place that records what this policy's
    /// unit attempt did.
    fn evaluate_typestate_policy(
        &self,
        policy: &LoadedPolicy,
        context: &PolicyEvaluationContext<'_>,
        budget: &mut PolicyBudget,
        host_budget: PolicyBudget,
    ) -> Result<PolicyRun, PolicyRunError> {
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
                let compilation =
                    match adapter.compilation_hashes(policy, spec, context, &host_budget) {
                        Ok(compilation) => compilation,
                        Err(TypestateCompilationFailure::Incomplete {
                            reasons,
                            message,
                            work,
                        }) => {
                            *budget = host_budget;
                            return inconclusive_policy_run_many(
                                policy,
                                PolicyAnalysisType::Typestate,
                                reasons.into_vec(),
                                &message,
                                work,
                                &host_budget,
                            );
                        }
                        Err(TypestateCompilationFailure::Failed {
                            reason,
                            message,
                            work,
                        }) => {
                            *budget = host_budget;
                            return failed_policy_run_with_reason(
                                policy,
                                PolicyAnalysisType::Typestate,
                                Vec::new(),
                                reason,
                                &message,
                                work,
                                &host_budget,
                            );
                        }
                    };
                let authority = match TypestateProjectionAuthority::from_loaded_compilation(
                    policy,
                    compilation.protocol_hash(),
                    compilation.binding_plan_hash(),
                ) {
                    Ok(authority) => authority,
                    Err(_) => {
                        *budget = host_budget;
                        return failed_policy_run(
                            policy,
                            PolicyAnalysisType::Typestate,
                            "typestate projection authority could not be derived from the loaded policy",
                            &host_budget,
                        );
                    }
                };
                let payload =
                    adapter.evaluate_typestate(&authority, policy, spec, context, &host_budget);
                let batch = authority.seal_batch(payload);
                assemble_typestate_projection_batch(
                    policy,
                    &authority,
                    batch,
                    context,
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

/// Whether this analysis records its own reuse review.
///
/// A family that is partitioned into evaluation units reports what its attempt
/// did with them, including the reason it widened when it did; every other
/// family is evaluated exactly as a run with no units evaluates it, and the
/// caller says so once. A relational assertion is not sliced: its plan is
/// evaluated over whole row vectors whose contributor indices are positional.
const fn evaluates_by_unit(analysis: &PolicyAnalysis) -> bool {
    match analysis {
        // An assertion policy is sliced either way: a plain one by its subject
        // selector and its per-file asserts, a relational one by its bindings.
        PolicyAnalysis::Match { .. }
        | PolicyAnalysis::Assertion { .. }
        // A typestate policy is sliced by its solver roots: one unit per root
        // procedure, whose product is what one iteration of the per-root loop
        // appends.
        | PolicyAnalysis::Typestate { .. } => true,
        PolicyAnalysis::Taint { .. } | PolicyAnalysis::Flow { .. } => false,
    }
}

fn evaluate_match_policy(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    subject_batch: Option<&SubjectQueryBatch<'_>>,
    execution_scope: Option<CodeQueryExecutionScope<'_>>,
) -> Result<PolicyRun, PolicyRunError> {
    // An evaluation that holds an incremental context has units to reuse and a
    // workspace to verify them against; one that does not executes exactly as
    // it always has. The two paths meet again at `assemble_match_run`, over
    // the same rendered rows.
    let evaluated = match execution_scope {
        Some(execution_scope) => match match_policy_query(policy) {
            Ok(query) => evaluate_match_query_candidates_in_scope(
                &policy.definition().metadata.id,
                context.flow_resources(),
                context.analyzer,
                context.workspace,
                query,
                budget,
                context.cancellation,
                execution_scope,
            ),
            Err(refusal) => refusal.into_run(budget),
        },
        None => match context.incremental {
            Some(incremental) => {
                evaluate_match_policy_by_unit(policy, incremental, context, budget, subject_batch)
            }
            None => match subject_batch {
                Some(batch) => shared_match_candidates(policy, batch, context, budget),
                None => evaluate_match_policy_candidates(
                    policy,
                    context.flow_resources(),
                    context.analyzer,
                    context.workspace,
                    budget,
                    context.cancellation,
                ),
            },
        },
    };
    assemble_match_run(
        policy,
        evaluated,
        context.cvss_overlays,
        context.organizational_risk,
        budget,
    )
}

fn assemble_match_run(
    policy: &LoadedPolicy,
    mut evaluated: EvaluatedMatchPolicy,
    cvss_overlays: &[CvssEvaluationOverlay],
    organizational_risk: &[OrganizationalRiskOverlay],
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let metadata = &policy.definition().metadata;
    let message = match &metadata.message {
        PolicyMessageSpec::Static { text } => text.clone(),
        PolicyMessageSpec::Generated { .. } => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Match,
                "match policy presentation could not be projected into a finding",
                budget,
            );
        }
    };
    let classification = match reduce_finding_classification(
        policy.definition().classification.as_ref(),
        ClassificationProjection::match_finding(),
        None,
    ) {
        Ok(classification) => classification,
        Err(_) => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Match,
                "match policy classification could not be reduced",
                budget,
            );
        }
    };
    let mut findings = Vec::with_capacity(evaluated.candidates.len());
    for candidate in evaluated.candidates {
        let expected_id = candidate.id;
        let mut retained_evidence_refs = candidate.proof.evidence_refs().to_vec();
        retained_evidence_refs.sort();
        retained_evidence_refs.dedup();
        let organizational_risk = match reduce_organizational_risk(
            organizational_risk,
            &metadata.id,
            &expected_id,
            &[],
            budget,
        ) {
            OrganizationalRiskReduction::Selected(assessment) => assessment,
            OrganizationalRiskReduction::BudgetExceeded => {
                record_run_incomplete(
                    &mut evaluated.completion,
                    &mut evaluated.diagnostics,
                    &mut evaluated.diagnostics_truncated,
                    PolicyIncompleteReason::OrganizationalRiskOverlayBudget,
                    "organizational-risk overlays exceed the host evaluation budget",
                    budget,
                );
                None
            }
            OrganizationalRiskReduction::Conflict => {
                return failed_policy_run_with_reason(
                    policy,
                    PolicyAnalysisType::Match,
                    findings,
                    PolicyFailureReason::ConflictingOrganizationalRiskOverlay,
                    "applicable organizational-risk overlays have conflicting maximal assessments",
                    evaluated.work,
                    budget,
                );
            }
        };
        let (organizational_risk, organizational_risk_omitted_evidence_refs) =
            retain_organizational_risk_evidence(
                organizational_risk,
                &mut retained_evidence_refs,
                budget,
            );
        let Some(available_for_evidence) = available_for_core_evidence(
            &classification,
            &candidate.proof,
            organizational_risk.as_ref(),
            budget,
        ) else {
            omit_finding_for_report_budget(
                &mut evaluated.completion,
                &mut evaluated.diagnostics,
                &mut evaluated.diagnostics_truncated,
                &mut evaluated.work,
                "valid match evidence exceeded the host report-retention budget",
                budget,
            );
            continue;
        };
        let Some(cvss_retained_bytes) =
            available_for_evidence.checked_sub(candidate.evidence.retained_size())
        else {
            omit_finding_for_report_budget(
                &mut evaluated.completion,
                &mut evaluated.diagnostics,
                &mut evaluated.diagnostics_truncated,
                &mut evaluated.work,
                "valid match evidence exceeded the host report-retention budget",
                budget,
            );
            continue;
        };
        let (cvss, cvss_omitted_evidence_refs) = match reduce_cvss_for_finding(
            policy,
            CvssFindingProjection::Match {
                anchor: candidate.evidence.anchor(),
            },
            cvss_overlays,
            &retained_evidence_refs,
            &[],
            cvss_retained_bytes,
            budget,
        ) {
            Ok(outcome) => {
                if let Some(reason) = outcome.incomplete_reason {
                    record_run_incomplete(
                        &mut evaluated.completion,
                        &mut evaluated.diagnostics,
                        &mut evaluated.diagnostics_truncated,
                        reason,
                        "CVSS reduction exceeded its bounded evaluation budget",
                        budget,
                    );
                }
                debug_assert_eq!(
                    outcome.evidence_refs_truncated,
                    outcome.omitted_evidence_refs_lower_bound > 0
                );
                (outcome.assessment, outcome.omitted_evidence_refs)
            }
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    PolicyAnalysisType::Match,
                    findings,
                    "CVSS reduction rejected a validated match projection",
                    evaluated.work,
                    budget,
                );
            }
        };
        let omitted_evidence_refs_lower_bound = combined_evidence_omission_lower_bound(
            0,
            &organizational_risk_omitted_evidence_refs,
            &cvss_omitted_evidence_refs,
        );
        let severity = finding_severity(&metadata.severity, cvss.as_ref());
        let finding = PolicyFinding::try_new(
            metadata.id.clone(),
            policy.semantic_hash(),
            severity,
            message.clone(),
            classification.clone(),
            candidate.certainty,
            finding_completeness_with_omission(
                candidate.completeness,
                omitted_evidence_refs_lower_bound,
                FindingIncompleteReason::EvidenceTruncated,
            ),
            candidate.location,
            Vec::new(),
            false,
            0,
            PolicyFindingEvidence::Match {
                evidence: candidate.evidence,
            },
            omitted_evidence_refs_lower_bound > 0,
            omitted_evidence_refs_lower_bound,
            cvss,
            organizational_risk,
            candidate.proof,
            Vec::new(),
            false,
            0,
            budget,
        );
        match finding {
            Ok(finding) if finding.id() == expected_id => findings.push(finding),
            Err(error) if error.is_budget_limit_exceeded() => {
                omit_finding_for_report_budget(
                    &mut evaluated.completion,
                    &mut evaluated.diagnostics,
                    &mut evaluated.diagnostics_truncated,
                    &mut evaluated.work,
                    "a valid match finding exceeded the host report-retention budget",
                    budget,
                );
            }
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
    finish_assembled_run(
        policy,
        PolicyAnalysisType::Match,
        evaluated.completion,
        findings,
        evaluated.diagnostics,
        evaluated.diagnostics_truncated,
        evaluated.work,
        "match evaluation produced an invalid policy run",
        budget,
    )
}
/// The report severity a finding of this policy carries.
///
/// `cvss` is the finding's own assessment set. Passing `None` therefore asks
/// the same question about the policy itself: the severity a finding would
/// carry before any CVSS evidence exists, which is what a run-level gate such
/// as `(on-unknown :verdict fail-closed)` has to compare against.
pub(crate) fn finding_severity(
    spec: &PolicySeveritySpec,
    cvss: Option<&super::cvss::CvssAssessmentSet>,
) -> FindingSeverity {
    match spec {
        PolicySeveritySpec::Fixed { level } => match level {
            PolicyLevel::Note => FindingSeverity::Note,
            PolicyLevel::Warning => FindingSeverity::Warning,
            PolicyLevel::Error => FindingSeverity::Error,
        },
        PolicySeveritySpec::Unrated => FindingSeverity::Unrated,
        PolicySeveritySpec::Cvss { when_unscored } => cvss
            .and_then(super::cvss::CvssAssessmentSet::selected_severity)
            .map_or(*when_unscored, |severity| match severity {
                CvssSeverity::None | CvssSeverity::Low => FindingSeverity::Note,
                CvssSeverity::Medium => FindingSeverity::Warning,
                CvssSeverity::High | CvssSeverity::Critical => FindingSeverity::Error,
            }),
    }
}

fn finding_completeness_with_omission(
    completeness: FindingCompleteness,
    omitted_lower_bound: u64,
    reason: FindingIncompleteReason,
) -> FindingCompleteness {
    if omitted_lower_bound == 0 {
        return completeness;
    }
    let mut reasons = completeness.reasons().to_vec();
    reasons.push(reason);
    FindingCompleteness::partial(reasons).expect("one typed finding-incomplete reason is canonical")
}

fn finding_completeness_with_declared_non_exhaustiveness(
    completeness: FindingCompleteness,
) -> FindingCompleteness {
    let mut reasons = completeness.reasons().to_vec();
    reasons.push(FindingIncompleteReason::DeclaredNonExhaustive);
    FindingCompleteness::partial(reasons)
        .expect("declared non-exhaustiveness is a bounded typed finding reason")
}

fn combined_evidence_omission_lower_bound(
    prior_unknown_lower_bound: u64,
    organizational_risk_omissions: &[EvidenceRef],
    cvss_omissions: &[EvidenceRef],
) -> u64 {
    let mut known = organizational_risk_omissions.to_vec();
    known.extend_from_slice(cvss_omissions);
    known.sort();
    known.dedup();
    prior_unknown_lower_bound.max(u64::try_from(known.len()).unwrap_or(u64::MAX))
}

fn available_for_core_evidence(
    classification: &super::classification::FindingClassification,
    proof: &ProofMetadata,
    organizational_risk: Option<&OrganizationalRiskAssessment>,
    budget: &PolicyBudget,
) -> Option<usize> {
    let non_core = classification
        .retained_size()
        .saturating_add(proof.retained_size())
        .saturating_add(organizational_risk.map_or(0, OrganizationalRiskAssessment::retained_size));
    budget
        .max_evidence_bytes_per_finding()
        .checked_sub(non_core)
}

fn largest_fitting_future_evidence_prefix<T: RetainedSize>(
    total_items: usize,
    max_items: usize,
    available_bytes: usize,
    mut build: impl FnMut(usize, bool, u64) -> Result<T, FutureEvidenceError>,
) -> Result<Option<(T, u64)>, FutureEvidenceError> {
    let mut lower = 0_usize;
    let mut upper = total_items.min(max_items).saturating_add(1);
    let mut best = None;
    while lower < upper {
        let retained = lower + (upper - lower) / 2;
        let omitted = total_items.saturating_sub(retained);
        match build(
            retained,
            omitted > 0,
            u64::try_from(omitted).unwrap_or(u64::MAX),
        ) {
            Ok(evidence) if evidence.retained_size() <= available_bytes => {
                best = Some((evidence, u64::try_from(omitted).unwrap_or(u64::MAX)));
                lower = retained.saturating_add(1);
            }
            Ok(_) | Err(FutureEvidenceError::RetainedEvidenceBudget { .. }) => {
                upper = retained;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(best)
}

enum OrganizationalRiskReduction {
    Selected(Option<OrganizationalRiskAssessment>),
    BudgetExceeded,
    Conflict,
}

fn reduce_organizational_risk(
    overlays: &[OrganizationalRiskOverlay],
    policy_id: &PolicyId,
    finding_id: &PolicyFindingId,
    source_scenarios: &[SourceScenarioId],
    budget: &PolicyBudget,
) -> OrganizationalRiskReduction {
    if overlays.len() > budget.max_organizational_risk_overlays() {
        return OrganizationalRiskReduction::BudgetExceeded;
    }
    let applicable = overlays
        .iter()
        .filter(|overlay| {
            overlay
                .scope
                .applies_to(policy_id, finding_id, source_scenarios)
        })
        .collect::<Vec<_>>();
    let maximal = applicable
        .iter()
        .copied()
        .filter(|candidate| {
            !applicable
                .iter()
                .any(|other| other.scope.strictly_refines(&candidate.scope))
        })
        .collect::<Vec<_>>();
    let Some(first) = maximal.first() else {
        return OrganizationalRiskReduction::Selected(None);
    };
    if maximal
        .iter()
        .skip(1)
        .any(|overlay| overlay.assessment != first.assessment)
    {
        return OrganizationalRiskReduction::Conflict;
    }
    OrganizationalRiskReduction::Selected(Some(first.assessment.clone()))
}

fn retain_organizational_risk_evidence(
    mut assessment: Option<OrganizationalRiskAssessment>,
    retained_refs: &mut Vec<EvidenceRef>,
    budget: &PolicyBudget,
) -> (Option<OrganizationalRiskAssessment>, Vec<EvidenceRef>) {
    let Some(value) = &mut assessment else {
        return (None, Vec::new());
    };
    let mut allowed = Vec::with_capacity(value.evidence_refs().len());
    let mut omitted = Vec::new();
    for reference in value.evidence_refs() {
        match retained_refs.binary_search(reference) {
            Ok(_) => allowed.push(reference.clone()),
            Err(index) if retained_refs.len() < budget.max_evidence_refs_per_finding() => {
                retained_refs.insert(index, reference.clone());
                allowed.push(reference.clone());
            }
            Err(_) => omitted.push(reference.clone()),
        }
    }
    allowed.sort();
    allowed.dedup();
    omitted.sort();
    omitted.dedup();
    value.retain_evidence_refs(&allowed);
    (assessment, omitted)
}

fn projected_core_evidence_refs(
    report: &super::projection::ProjectedFindingReport,
    origins: &[super::future_evidence::TaintOriginEvidence],
) -> Vec<EvidenceRef> {
    let mut refs = Vec::new();
    for origin in origins {
        refs.extend(origin.evidence_refs().iter().cloned());
    }
    refs.extend(report.proof.evidence_refs().iter().cloned());
    for related in &report.related {
        refs.extend(related.evidence_refs().iter().cloned());
    }
    for witness in &report.witnesses {
        for step in witness.steps() {
            refs.extend(step.evidence_refs().iter().cloned());
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

fn record_run_incomplete(
    completion: &mut PolicyRunCompletion,
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    reason: PolicyIncompleteReason,
    message: &str,
    budget: &PolicyBudget,
) {
    if !completion.mark_inconclusive(reason) {
        return;
    }
    let code = match reason {
        PolicyIncompleteReason::ReportRetentionBudget => {
            PolicyDiagnosticCode::ReportRetentionBudget
        }
        PolicyIncompleteReason::CvssVariantBudget => PolicyDiagnosticCode::CvssVariantBudget,
        PolicyIncompleteReason::OrganizationalRiskOverlayBudget => {
            PolicyDiagnosticCode::OrganizationalRiskOverlayBudget
        }
        _ => PolicyDiagnosticCode::EvaluationFailure,
    };
    if let Some(diagnostic) = incomplete_run_diagnostic(code, message) {
        *diagnostics_truncated |=
            insert_policy_diagnostic_bounded(diagnostics, diagnostic, budget.max_diagnostics());
    } else {
        *diagnostics_truncated = true;
    }
}

pub(super) fn incomplete_run_diagnostic(
    code: PolicyDiagnosticCode,
    message: &str,
) -> Option<PolicyDiagnostic> {
    PolicyDiagnostic::try_new(
        code,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
        None,
        Vec::new(),
    )
    .ok()
}

fn omit_finding_for_report_budget(
    completion: &mut PolicyRunCompletion,
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    work: &mut PolicyWorkReport,
    message: &str,
    budget: &PolicyBudget,
) {
    work.set_retention(
        work.retained_findings(),
        work.omitted_findings_lower_bound().saturating_add(1),
        work.retained_report_bytes(),
    );
    record_run_incomplete(
        completion,
        diagnostics,
        diagnostics_truncated,
        PolicyIncompleteReason::ReportRetentionBudget,
        message,
        budget,
    );
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

fn unsupported_scoped_policy_run(
    policy: &LoadedPolicy,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    unsupported_policy_run(
        policy,
        policy.definition().analysis.analysis_type(),
        PolicyCapability::QueryDomain {
            domain: "execution_scope".to_owned(),
            capability: Some("seed_scope".to_owned()),
            reason: "query_source_not_scope_aware".to_owned(),
        },
        "explicit execution scope is supported only for Match and Assertion seed queries whose sources honor scope; this policy has an unsupported source or analysis family",
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

fn inconclusive_policy_run_many(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    reasons: Vec<PolicyIncompleteReason>,
    message: &str,
    work: PolicyWorkReport,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
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
        PolicyRunCompletion::inconclusive(reasons)
            .expect("typed compilation-incomplete reasons are canonical"),
        Vec::new(),
        diagnostics,
        !retain_diagnostic,
        work,
        budget,
    )
}

fn failed_policy_run_with_findings(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    findings: Vec<PolicyFinding>,
    message: &str,
    work: PolicyWorkReport,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    failed_policy_run_with_reason(
        policy,
        analysis_type,
        findings,
        PolicyFailureReason::InternalInvariant,
        message,
        work,
        budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn failed_policy_run_with_reason(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    mut findings: Vec<PolicyFinding>,
    reason: PolicyFailureReason,
    message: &str,
    work: PolicyWorkReport,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    retain_unique_strong_findings(&mut findings);
    let retain_diagnostic = budget.max_diagnostics() > 0;
    let diagnostics = if retain_diagnostic {
        vec![internal_failure_diagnostic(message)]
    } else {
        Vec::new()
    };
    let completion = PolicyRunCompletion::Failed {
        reasons: vec![reason],
    };
    try_policy_run_with_aggregate_retention(
        policy,
        analysis_type,
        completion,
        findings,
        diagnostics,
        !retain_diagnostic,
        work,
        budget,
    )
}

fn retain_unique_strong_findings(findings: &mut Vec<PolicyFinding>) {
    findings.retain(|finding| finding.identity_stability() == FindingIdentityStability::Strong);
    findings.sort_by_key(PolicyFinding::id);
    let mut retained = Vec::with_capacity(findings.len());
    let mut candidates = std::mem::take(findings).into_iter().peekable();
    while let Some(candidate) = candidates.next() {
        let id = candidate.id();
        let mut duplicate = false;
        while candidates.peek().is_some_and(|next| next.id() == id) {
            candidates.next();
            duplicate = true;
        }
        if !duplicate {
            retained.push(candidate);
        }
    }
    *findings = retained;
}

#[allow(clippy::too_many_arguments)]
fn finish_assembled_run(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    completion: PolicyRunCompletion,
    findings: Vec<PolicyFinding>,
    diagnostics: Vec<PolicyDiagnostic>,
    diagnostics_truncated: bool,
    work: PolicyWorkReport,
    failure_message: &str,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    match try_policy_run_with_aggregate_retention(
        policy,
        analysis_type,
        completion,
        findings.clone(),
        diagnostics,
        diagnostics_truncated,
        work.clone(),
        budget,
    ) {
        Ok(run) => Ok(run),
        Err(error @ PolicyRunError::RetainedReportBytesExceeded { .. }) => Err(error),
        Err(_) => failed_policy_run_with_findings(
            policy,
            analysis_type,
            findings,
            failure_message,
            work,
            budget,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn try_policy_run_prefix(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    completion: &PolicyRunCompletion,
    findings: &[PolicyFinding],
    finding_count: usize,
    diagnostics: &[PolicyDiagnostic],
    diagnostic_count: usize,
    diagnostics_truncated: bool,
    work: &PolicyWorkReport,
    additional_omitted_findings: u64,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let mut retained_work = work.clone();
    retained_work.set_retention(
        retained_work.retained_findings(),
        retained_work
            .omitted_findings_lower_bound()
            .saturating_add(additional_omitted_findings),
        retained_work.retained_report_bytes(),
    );
    PolicyRun::try_new(
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        analysis_type,
        completion.clone(),
        findings[..finding_count].to_vec(),
        diagnostics[..diagnostic_count].to_vec(),
        diagnostics_truncated,
        retained_work,
        budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn try_policy_run_with_aggregate_retention(
    policy: &LoadedPolicy,
    analysis_type: PolicyAnalysisType,
    mut completion: PolicyRunCompletion,
    mut findings: Vec<PolicyFinding>,
    mut diagnostics: Vec<PolicyDiagnostic>,
    mut diagnostics_truncated: bool,
    work: PolicyWorkReport,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    findings.sort_by_key(PolicyFinding::id);
    diagnostics_truncated |=
        normalize_policy_diagnostics_bounded(&mut diagnostics, budget.max_diagnostics());
    match try_policy_run_prefix(
        policy,
        analysis_type,
        &completion,
        &findings,
        findings.len(),
        &diagnostics,
        diagnostics.len(),
        diagnostics_truncated,
        &work,
        0,
        budget,
    ) {
        Ok(run) => return Ok(run),
        Err(PolicyRunError::RetainedReportBytesExceeded { .. }) => {}
        Err(error) => return Err(error),
    }

    record_run_incomplete(
        &mut completion,
        &mut diagnostics,
        &mut diagnostics_truncated,
        PolicyIncompleteReason::ReportRetentionBudget,
        "findings were omitted to satisfy the host aggregate report-retention budget",
        budget,
    );
    let total_findings = findings.len();
    let mut lower = 0_usize;
    let mut upper = total_findings;
    let mut best = None;
    while lower < upper {
        let finding_count = lower + (upper - lower) / 2;
        let additional_omitted =
            u64::try_from(total_findings.saturating_sub(finding_count)).unwrap_or(u64::MAX);
        match try_policy_run_prefix(
            policy,
            analysis_type,
            &completion,
            &findings,
            finding_count,
            &diagnostics,
            diagnostics.len(),
            diagnostics_truncated,
            &work,
            additional_omitted,
            budget,
        ) {
            Ok(run) => {
                best = Some(run);
                lower = finding_count.saturating_add(1);
            }
            Err(PolicyRunError::RetainedReportBytesExceeded { .. }) => {
                upper = finding_count;
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(run) = best {
        return Ok(run);
    }

    diagnostics_truncated = true;
    let additional_omitted = u64::try_from(total_findings).unwrap_or(u64::MAX);
    let mut lower = 0_usize;
    let mut upper = diagnostics.len().saturating_add(1);
    let mut best = None;
    while lower < upper {
        let diagnostic_count = lower + (upper - lower) / 2;
        match try_policy_run_prefix(
            policy,
            analysis_type,
            &completion,
            &findings,
            0,
            &diagnostics,
            diagnostic_count,
            diagnostics_truncated,
            &work,
            additional_omitted,
            budget,
        ) {
            Ok(run) => {
                best = Some(run);
                lower = diagnostic_count.saturating_add(1);
            }
            Err(PolicyRunError::RetainedReportBytesExceeded { .. }) => {
                upper = diagnostic_count;
            }
            Err(error) => return Err(error),
        }
    }
    best.ok_or(PolicyRunError::RetainedReportBytesExceeded {
        max: budget.max_retained_report_bytes(),
    })
}

fn assemble_taint_projection_batch(
    policy: &LoadedPolicy,
    authority: &TaintProjectionAuthority,
    batch: TaintProjectionBatch,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let engine = batch.engine.clone();
    let scope = batch.scope.clone();
    assemble_taint_run(policy, authority, batch, context, budget)
        .map(|run| run.with_engine(engine).with_scope(scope))
}

fn assemble_taint_run(
    policy: &LoadedPolicy,
    authority: &TaintProjectionAuthority,
    batch: TaintProjectionBatch,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    // Taint and flow share this assembly: one resolved model, one adapter,
    // one projection authority. The sealed analysis type is what decides the
    // run's kind and which evidence variant every finding carries (#2436).
    let analysis_type = authority.analysis_type();
    let mut validated = match validate_taint_batch(authority, batch, budget) {
        Ok(validated) => validated,
        Err(_) => {
            return failed_policy_run(
                policy,
                analysis_type,
                "taint adapter returned facts outside the sealed loaded-policy authority",
                budget,
            );
        }
    };
    let Some(spec) = policy.resolved_taint() else {
        return failed_policy_run(
            policy,
            analysis_type,
            "loaded taint policy lost its resolved specification during assembly",
            budget,
        );
    };
    let presentation = match TaintPresentationReducer::try_new(&spec.finding_combinations) {
        Ok(presentation) => presentation,
        Err(_) => {
            return failed_policy_run_with_findings(
                policy,
                analysis_type,
                Vec::new(),
                "taint finding-combination precedence is ambiguous",
                validated.work,
                budget,
            );
        }
    };
    let metadata = &policy.definition().metadata;
    let mut findings = Vec::with_capacity(validated.projections.len());
    'projection: for projection in validated.projections {
        let expected_id = PolicyFindingId::from_taint_anchor(&metadata.id, &projection.anchor);
        let source_fact = &projection.facts.source_facts[0];
        let combination = match presentation.select(
            &source_fact.source_endpoint,
            &projection.facts.sink_endpoint,
        ) {
            Ok(combination) => combination,
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    analysis_type,
                    findings,
                    "taint endpoint pair has no unique presentation winner",
                    validated.work,
                    budget,
                );
            }
        };
        let classification = match reduce_finding_classification(
            policy.definition().classification.as_ref(),
            ClassificationProjection::taint_pair(
                &source_fact.source_categories,
                &projection.facts.sink_categories,
                &projection.facts.reached_source_labels,
                &projection.facts.sink_tags,
                &projection.facts.sink_impacts,
                combination.map(|value| &value.id),
            ),
            combination,
        ) {
            Ok(classification) => classification,
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    analysis_type,
                    findings,
                    "taint classification could not be reduced from pair-local facts",
                    validated.work,
                    budget,
                );
            }
        };
        let mut source_scenarios = projection
            .facts
            .source_facts
            .iter()
            .flat_map(|fact| fact.source_scenario_ids.iter().cloned())
            .collect::<Vec<_>>();
        source_scenarios.sort();
        source_scenarios.dedup();
        let source_scenario_set_hash = match super::cvss::SourceScenarioSetHash::try_from_scenarios(
            source_scenarios.clone(),
        ) {
            Ok(hash) => hash,
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    analysis_type,
                    findings,
                    "taint pair scenario identity could not be reconstructed",
                    validated.work,
                    budget,
                );
            }
        };
        let mut retained_evidence_refs =
            projected_core_evidence_refs(&projection.report, &projection.origins);
        let organizational_risk = match reduce_organizational_risk(
            context.organizational_risk,
            &metadata.id,
            &expected_id,
            &source_scenarios,
            budget,
        ) {
            OrganizationalRiskReduction::Selected(assessment) => assessment,
            OrganizationalRiskReduction::BudgetExceeded => {
                record_run_incomplete(
                    &mut validated.completion,
                    &mut validated.diagnostics,
                    &mut validated.diagnostics_truncated,
                    PolicyIncompleteReason::OrganizationalRiskOverlayBudget,
                    "organizational-risk overlays exceed the host evaluation budget",
                    budget,
                );
                None
            }
            OrganizationalRiskReduction::Conflict => {
                return failed_policy_run_with_reason(
                    policy,
                    analysis_type,
                    findings,
                    PolicyFailureReason::ConflictingOrganizationalRiskOverlay,
                    "applicable organizational-risk overlays have conflicting maximal assessments",
                    validated.work,
                    budget,
                );
            }
        };
        let (organizational_risk, organizational_risk_omitted_evidence_refs) =
            retain_organizational_risk_evidence(
                organizational_risk,
                &mut retained_evidence_refs,
                budget,
            );
        let Some(available_for_evidence) = available_for_core_evidence(
            &classification,
            &projection.report.proof,
            organizational_risk.as_ref(),
            budget,
        ) else {
            omit_finding_for_report_budget(
                &mut validated.completion,
                &mut validated.diagnostics,
                &mut validated.diagnostics_truncated,
                &mut validated.work,
                "valid taint evidence exceeded the host report-retention budget",
                budget,
            );
            continue;
        };
        let evidence = largest_fitting_future_evidence_prefix(
            source_scenarios.len(),
            budget.max_projection_scenario_memberships(),
            available_for_evidence,
            |retained, scenarios_truncated, omitted_scenarios_lower_bound| {
                TaintFindingEvidence::try_new_with_threat_model(
                    projection.analysis_finding_id.clone(),
                    projection.anchor.clone(),
                    projection.sink.clone(),
                    source_fact.source_endpoint.clone(),
                    projection.facts.sink_endpoint.clone(),
                    source_fact.source_display_name.clone(),
                    source_fact.source_threat_model,
                    projection.facts.sink_display_name.clone(),
                    source_fact.source_categories.clone(),
                    projection.facts.sink_categories.clone(),
                    combination.map(|value| value.id.clone()),
                    projection.facts.sink_tags.clone(),
                    projection.facts.sink_impacts.clone(),
                    projection.facts.reached_source_labels.clone(),
                    projection.origins.clone(),
                    projection.origins_truncated,
                    source_scenarios[..retained].to_vec(),
                    scenarios_truncated,
                    omitted_scenarios_lower_bound,
                    source_scenario_set_hash,
                    projection.witness_refs.clone(),
                    projection.witness_refs_truncated,
                    projection.facts.semantic_hash,
                    budget,
                )
            },
        );
        let (evidence, omitted_source_scenarios_lower_bound) = match evidence {
            Ok(Some(value)) => value,
            Ok(None) => {
                omit_finding_for_report_budget(
                    &mut validated.completion,
                    &mut validated.diagnostics,
                    &mut validated.diagnostics_truncated,
                    &mut validated.work,
                    "valid taint evidence exceeded the host report-retention budget",
                    budget,
                );
                continue 'projection;
            }
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    analysis_type,
                    findings,
                    "validated taint facts could not be sealed as finding evidence",
                    validated.work,
                    budget,
                );
            }
        };
        let cvss_retained_bytes = available_for_evidence
            .checked_sub(evidence.retained_size())
            .expect("bounded evidence selection fits the available byte budget");
        let (cvss, cvss_omitted_evidence_refs) = match reduce_cvss_for_finding(
            policy,
            CvssFindingProjection::Taint {
                anchor: &projection.anchor,
                projection: &projection.facts,
                sources: &projection.facts.source_facts,
            },
            context.cvss_overlays,
            &retained_evidence_refs,
            evidence.source_scenarios(),
            cvss_retained_bytes,
            budget,
        ) {
            Ok(outcome) => {
                if let Some(reason) = outcome.incomplete_reason {
                    record_run_incomplete(
                        &mut validated.completion,
                        &mut validated.diagnostics,
                        &mut validated.diagnostics_truncated,
                        reason,
                        "CVSS reduction exceeded its bounded evaluation budget",
                        budget,
                    );
                }
                debug_assert_eq!(
                    outcome.evidence_refs_truncated,
                    outcome.omitted_evidence_refs_lower_bound > 0
                );
                (outcome.assessment, outcome.omitted_evidence_refs)
            }
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    analysis_type,
                    findings,
                    "CVSS reduction rejected a validated taint projection",
                    validated.work,
                    budget,
                );
            }
        };
        let severity_spec = combination
            .and_then(|value| value.severity.as_ref())
            .unwrap_or(&metadata.severity);
        let severity = finding_severity(severity_spec, cvss.as_ref());
        let message = match combination {
            Some(combination) => combination.message.clone(),
            None => match &metadata.message {
                PolicyMessageSpec::Static { text } => text.clone(),
                PolicyMessageSpec::Generated { .. } => format!(
                    "{} can reach {}",
                    source_fact.source_display_name, projection.facts.sink_display_name
                ),
            },
        };
        let report = projection.report;
        let omitted_evidence_refs_lower_bound = combined_evidence_omission_lower_bound(
            report.omitted_evidence_refs_lower_bound,
            &organizational_risk_omitted_evidence_refs,
            &cvss_omitted_evidence_refs,
        );
        let completeness = finding_completeness_with_omission(
            report.completeness,
            omitted_source_scenarios_lower_bound
                .max(u64::from(cvss.as_ref().is_some_and(
                    super::cvss::CvssAssessmentSet::has_truncated_source_scenarios,
                ))),
            FindingIncompleteReason::SourceScenariosTruncated,
        );
        let display_path = report.display_path;
        debug_assert!(display_path.as_ref().is_none_or(|path| {
            path.witness_ids().iter().all(|witness_id| {
                report
                    .witnesses
                    .iter()
                    .any(|witness| witness.id() == witness_id)
            })
        }));
        let finding = PolicyFinding::try_new(
            metadata.id.clone(),
            policy.semantic_hash(),
            severity,
            message,
            classification,
            report.certainty,
            finding_completeness_with_omission(
                completeness,
                omitted_evidence_refs_lower_bound,
                FindingIncompleteReason::EvidenceTruncated,
            ),
            report.primary,
            report.related,
            report.related_truncated,
            report.omitted_related_locations_lower_bound,
            match analysis_type {
                PolicyAnalysisType::Flow => PolicyFindingEvidence::Flow {
                    evidence: FlowFindingEvidence::new(evidence),
                },
                _ => PolicyFindingEvidence::Taint { evidence },
            },
            omitted_evidence_refs_lower_bound > 0,
            omitted_evidence_refs_lower_bound,
            cvss,
            organizational_risk,
            report.proof,
            report.witnesses,
            report.witnesses_truncated,
            report.omitted_witnesses_lower_bound,
            budget,
        )
        .and_then(|finding| {
            finding.with_value_type_barrier_notes(report.value_type_barrier_notes, budget)
        });
        match finding {
            Ok(mut finding) if finding.id() == expected_id => {
                finding.attach_display_path(display_path);
                findings.push(finding);
            }
            Err(error) if error.is_budget_limit_exceeded() => {
                omit_finding_for_report_budget(
                    &mut validated.completion,
                    &mut validated.diagnostics,
                    &mut validated.diagnostics_truncated,
                    &mut validated.work,
                    "a valid taint finding exceeded the host report-retention budget",
                    budget,
                );
            }
            Ok(_) | Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    analysis_type,
                    findings,
                    "a validated taint projection could not be retained as a policy finding",
                    validated.work,
                    budget,
                );
            }
        }
    }
    let mut run = finish_assembled_run(
        policy,
        analysis_type,
        validated.completion,
        findings,
        validated.diagnostics,
        validated.diagnostics_truncated,
        validated.work,
        "taint evaluation produced an invalid policy run",
        budget,
    )?;
    run.set_authored_arm_closures(validated.authored_arm_closures);
    Ok(run)
}

fn assemble_typestate_projection_batch(
    policy: &LoadedPolicy,
    authority: &TypestateProjectionAuthority,
    batch: TypestateProjectionBatch,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let mut validated = match validate_typestate_batch(authority, batch, budget) {
        Ok(validated) => validated,
        Err(_) => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Typestate,
                "typestate adapter returned facts outside the sealed loaded-policy authority",
                budget,
            );
        }
    };
    let metadata = &policy.definition().metadata;
    let message = match &metadata.message {
        PolicyMessageSpec::Static { text } => text.clone(),
        PolicyMessageSpec::Generated { .. } => {
            return failed_policy_run_with_findings(
                policy,
                PolicyAnalysisType::Typestate,
                Vec::new(),
                "typestate policies require static report text",
                validated.work,
                budget,
            );
        }
    };
    let mut findings = Vec::with_capacity(validated.projections.len());
    'projection: for projection in validated.projections {
        let expected_id = PolicyFindingId::from_typestate_anchor(&metadata.id, &projection.anchor);
        let expectation = match &projection.facts.violation {
            TypestateViolationEvidence::TerminalExpectation { expectation_id, .. } => {
                Some(expectation_id)
            }
            TypestateViolationEvidence::ErrorTransition { .. } => None,
        };
        let classification = match reduce_finding_classification(
            policy.definition().classification.as_ref(),
            ClassificationProjection::typestate(&projection.facts.source_categories, expectation),
            None,
        ) {
            Ok(classification) => classification,
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    PolicyAnalysisType::Typestate,
                    findings,
                    "typestate classification could not be reduced from exact violation facts",
                    validated.work,
                    budget,
                );
            }
        };
        let mut retained_evidence_refs = projected_core_evidence_refs(&projection.report, &[]);
        let organizational_risk = match reduce_organizational_risk(
            context.organizational_risk,
            &metadata.id,
            &expected_id,
            &[],
            budget,
        ) {
            OrganizationalRiskReduction::Selected(assessment) => assessment,
            OrganizationalRiskReduction::BudgetExceeded => {
                record_run_incomplete(
                    &mut validated.completion,
                    &mut validated.diagnostics,
                    &mut validated.diagnostics_truncated,
                    PolicyIncompleteReason::OrganizationalRiskOverlayBudget,
                    "organizational-risk overlays exceed the host evaluation budget",
                    budget,
                );
                None
            }
            OrganizationalRiskReduction::Conflict => {
                return failed_policy_run_with_reason(
                    policy,
                    PolicyAnalysisType::Typestate,
                    findings,
                    PolicyFailureReason::ConflictingOrganizationalRiskOverlay,
                    "applicable organizational-risk overlays have conflicting maximal assessments",
                    validated.work,
                    budget,
                );
            }
        };
        let (organizational_risk, organizational_risk_omitted_evidence_refs) =
            retain_organizational_risk_evidence(
                organizational_risk,
                &mut retained_evidence_refs,
                budget,
            );
        let Some(available_for_evidence) = available_for_core_evidence(
            &classification,
            &projection.report.proof,
            organizational_risk.as_ref(),
            budget,
        ) else {
            omit_finding_for_report_budget(
                &mut validated.completion,
                &mut validated.diagnostics,
                &mut validated.diagnostics_truncated,
                &mut validated.work,
                "valid typestate evidence exceeded the host report-retention budget",
                budget,
            );
            continue;
        };
        let evidence = largest_fitting_future_evidence_prefix(
            projection.facts.scenario_ids.len(),
            budget.max_projection_scenario_memberships(),
            available_for_evidence,
            |retained, scenarios_truncated, omitted_scenarios_lower_bound| {
                TypestateFindingEvidence::try_new(
                    projection.analysis_finding_id.clone(),
                    projection.anchor.clone(),
                    projection.facts.protocol_hash,
                    projection.facts.binding_plan_hash,
                    projection.subject.clone(),
                    projection.facts.source_endpoint.clone(),
                    projection.facts.violation_site.clone(),
                    projection.facts.violation.clone(),
                    projection.facts.scenario_ids[..retained].to_vec(),
                    scenarios_truncated,
                    omitted_scenarios_lower_bound,
                    projection.facts.scenario_set_hash,
                    projection.witness_refs.clone(),
                    projection.witness_refs_truncated,
                    projection.facts.semantic_hash,
                    budget,
                )
            },
        );
        let (evidence, omitted_typestate_scenarios_lower_bound) = match evidence {
            Ok(Some(value)) => value,
            Ok(None) => {
                omit_finding_for_report_budget(
                    &mut validated.completion,
                    &mut validated.diagnostics,
                    &mut validated.diagnostics_truncated,
                    &mut validated.work,
                    "valid typestate evidence exceeded the host report-retention budget",
                    budget,
                );
                continue 'projection;
            }
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    PolicyAnalysisType::Typestate,
                    findings,
                    "validated typestate facts could not be sealed as finding evidence",
                    validated.work,
                    budget,
                );
            }
        };
        let cvss_retained_bytes = available_for_evidence
            .checked_sub(evidence.retained_size())
            .expect("bounded evidence selection fits the available byte budget");
        let (cvss, cvss_omitted_evidence_refs) = match reduce_cvss_for_finding(
            policy,
            CvssFindingProjection::Typestate {
                anchor: &projection.anchor,
                projection: &projection.facts,
            },
            context.cvss_overlays,
            &retained_evidence_refs,
            &[],
            cvss_retained_bytes,
            budget,
        ) {
            Ok(outcome) => {
                if let Some(reason) = outcome.incomplete_reason {
                    record_run_incomplete(
                        &mut validated.completion,
                        &mut validated.diagnostics,
                        &mut validated.diagnostics_truncated,
                        reason,
                        "CVSS reduction exceeded its bounded evaluation budget",
                        budget,
                    );
                }
                debug_assert_eq!(
                    outcome.evidence_refs_truncated,
                    outcome.omitted_evidence_refs_lower_bound > 0
                );
                (outcome.assessment, outcome.omitted_evidence_refs)
            }
            Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    PolicyAnalysisType::Typestate,
                    findings,
                    "CVSS reduction rejected a validated typestate projection",
                    validated.work,
                    budget,
                );
            }
        };
        let severity = finding_severity(&metadata.severity, cvss.as_ref());
        let report = projection.report;
        let omitted_evidence_refs_lower_bound = combined_evidence_omission_lower_bound(
            report.omitted_evidence_refs_lower_bound,
            &organizational_risk_omitted_evidence_refs,
            &cvss_omitted_evidence_refs,
        );
        let completeness = finding_completeness_with_omission(
            report.completeness,
            omitted_typestate_scenarios_lower_bound,
            FindingIncompleteReason::TypestateScenariosTruncated,
        );
        let finding = PolicyFinding::try_new(
            metadata.id.clone(),
            policy.semantic_hash(),
            severity,
            message.clone(),
            classification,
            report.certainty,
            finding_completeness_with_omission(
                completeness,
                omitted_evidence_refs_lower_bound,
                FindingIncompleteReason::EvidenceTruncated,
            ),
            report.primary,
            report.related,
            report.related_truncated,
            report.omitted_related_locations_lower_bound,
            PolicyFindingEvidence::Typestate { evidence },
            omitted_evidence_refs_lower_bound > 0,
            omitted_evidence_refs_lower_bound,
            cvss,
            organizational_risk,
            report.proof,
            report.witnesses,
            report.witnesses_truncated,
            report.omitted_witnesses_lower_bound,
            budget,
        );
        match finding {
            Ok(finding) if finding.id() == expected_id => findings.push(finding),
            Err(error) if error.is_budget_limit_exceeded() => {
                omit_finding_for_report_budget(
                    &mut validated.completion,
                    &mut validated.diagnostics,
                    &mut validated.diagnostics_truncated,
                    &mut validated.work,
                    "a valid typestate finding exceeded the host report-retention budget",
                    budget,
                );
            }
            Ok(_) | Err(_) => {
                return failed_policy_run_with_findings(
                    policy,
                    PolicyAnalysisType::Typestate,
                    findings,
                    "a validated typestate projection could not be retained as a policy finding",
                    validated.work,
                    budget,
                );
            }
        }
    }
    finish_assembled_run(
        policy,
        PolicyAnalysisType::Typestate,
        validated.completion,
        findings,
        validated.diagnostics,
        validated.diagnostics_truncated,
        validated.work,
        "typestate evaluation produced an invalid policy run",
        budget,
    )
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

/// Evaluate one match policy unit by unit, or in full with a stated reason.
///
/// Widening is never silent and never a diagnostic: the policy is evaluated
/// exactly as a run without any units would evaluate it, and the reason is
/// reported beside the report rather than inside it.
fn evaluate_match_policy_by_unit(
    policy: &LoadedPolicy,
    incremental: &PolicyIncrementalContext<'_>,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    subject_batch: Option<&SubjectQueryBatch<'_>>,
) -> EvaluatedMatchPolicy {
    let mut attempt = UnitAttempt::default();
    let policy_id = policy.definition().metadata.id.clone();
    let (evaluated, reason) = match sliced_match_candidates(
        policy,
        incremental,
        context,
        budget,
        subject_batch,
        &mut attempt,
    ) {
        Ok(evaluated) => (evaluated, None),
        Err(reason) => (
            widened_match_candidates(policy, context, budget, subject_batch),
            Some(reason),
        ),
    };
    let run = attempt.into_run(policy_id, reason);
    note_incremental_run(&run, incremental);
    incremental.record_run(run);
    evaluated
}

/// Report one policy's reuse under `BIFROST_TIMING`.
///
/// The counts are in the review either way; what only this reports is the
/// verdict log's running totals, which are how many reuse decisions this
/// evaluation has earned against how many rebuilds it has forced. Costs one
/// relaxed load when timing is off.
fn note_incremental_run(run: &PolicyIncrementalRun, incremental: &PolicyIncrementalContext<'_>) {
    brokk_bifrost_analysis::profiling::note_with(|| {
        let (retained, invalidated) = incremental.verdicts().totals();
        format!(
            "policy.units policy={} mode={} total={} reused={} recomputed={} unbounded={} widened={} verdicts_retained={retained} verdicts_invalidated={invalidated}",
            run.policy_id,
            run.mode.stable_label(),
            run.units_total,
            run.units_reused,
            run.units_recomputed,
            run.units_unbounded,
            run.widen_reason.map_or("none", WidenReason::stable_label),
        )
    });
}

/// Evaluate one match policy as the merge of one execution per seed file.
///
/// `Err` is the demand to evaluate the whole policy instead, with the reason
/// that demand exists. `Ok` is a product that equals the whole execution's:
/// every unit was exhaustive, diagnostic-free and fully attributed, and the
/// merged counters proved that no cumulative cap the whole execution enforces
/// was reached.
fn sliced_match_candidates(
    policy: &LoadedPolicy,
    incremental: &PolicyIncrementalContext<'_>,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    subject_batch: Option<&SubjectQueryBatch<'_>>,
    attempt: &mut UnitAttempt,
) -> Result<EvaluatedMatchPolicy, WidenReason> {
    let query = match match_policy_query(policy) {
        Ok(query) => query,
        Err(refusal) => return Ok(refusal.into_run(budget)),
    };
    let executable = match executable_match_query(query, budget) {
        Ok(executable) => executable,
        Err(refusal) => return Ok(refusal.into_run(budget)),
    };
    let limits = budget.query_limits();
    // Computed once per policy: every unit hands the same whole-workspace
    // enumeration to the scanners that still need it, which is what keeps
    // unit-wise execution linear in the file count.
    let workspace_files = context.analyzer.analyzed_files();
    let execution = UnitQueryExecution {
        flow_state: context.flow_resources(),
        analyzer: context.analyzer,
        workspace: context.workspace,
        cancellation: context.cancellation,
        limits,
        workspace_files: &workspace_files,
        subject_batch,
    };
    let mut reuse = UnitReuse::new(policy, incremental, budget, &context.flow_resources());
    let sliced = sliced_query_units(
        policy,
        &executable,
        &mut reuse,
        &execution,
        SeedPartition::seed,
        attempt,
    )?;
    // Every unit of this policy is published and merged, so this list is what
    // another run replays to reproduce the product without executing anything.
    incremental.record_units(policy.definition().metadata.id.clone(), sliced.keys);
    let merged = sliced.merged;
    let completion = merged.completion();
    Ok(adapt_match_execution(
        &policy.definition().metadata.id,
        merged.items,
        merged.evidence,
        &merged.diagnostics,
        completion,
        merged.truncated,
        merged.work,
        budget,
    ))
}

/// Evaluate one match policy in full without recording a unit.
///
/// The execution is the whole-workspace one -- the same entry point the
/// sliced path uses, with the seed enumeration not narrowed, which is what
/// every non-incremental run already does. A widened execution cannot produce a
/// reusable unit: its read set is workspace-wide and cannot survive an edit,
/// while the base evaluation's finding identities already serve the warm diff
/// join.
fn widened_match_candidates(
    policy: &LoadedPolicy,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    subject_batch: Option<&SubjectQueryBatch<'_>>,
) -> EvaluatedMatchPolicy {
    let query = match match_policy_query(policy) {
        Ok(query) => query,
        Err(refusal) => return refusal.into_run(budget),
    };
    let executable = match executable_match_query(query, budget) {
        Ok(executable) => executable,
        Err(refusal) => return refusal.into_run(budget),
    };
    let execute = || {
        execute_code_query_unit(
            context.analyzer,
            context.flow_resources(),
            context.workspace,
            &executable,
            budget.query_limits(),
            context.cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        )
    };
    // Another widened consumer of the same selector runs this same execution,
    // so the batch keeps its whole-workspace unit under no seed file.
    let shared = subject_batch.and_then(|batch| {
        batch.query_units(
            &executable,
            context.analyzer,
            context.workspace,
            budget.query_limits(),
        )
    });
    let product = match shared {
        Some(shared) => shared.execute(None, context.analyzer, context.cancellation, execute),
        None => execute(),
    };
    let mut items = Vec::with_capacity(product.rows.len());
    let mut evidence = Vec::with_capacity(product.rows.len());
    for row in product.rows {
        items.push(row.item);
        evidence.push(row.evidence);
    }
    adapt_match_execution(
        &policy.definition().metadata.id,
        items,
        evidence,
        &product.diagnostics,
        product.completion,
        product.truncated,
        product.work,
        budget,
    )
}

/// The authored query of a match policy, or the failure that stops it.
fn match_policy_query(
    policy: &LoadedPolicy,
) -> Result<&brokk_bifrost_rql::structural::CodeQuery, MatchPolicyRefusal> {
    if !matches!(policy.definition().analysis, PolicyAnalysis::Match { .. }) {
        return Err(MatchPolicyRefusal {
            reason: PolicyFailureReason::InvalidExecutionPlan,
            message: "match evaluation requires a match policy",
        });
    }
    let Some(selector) = policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == MATCH_SELECTOR_PATH)
    else {
        return Err(MatchPolicyRefusal {
            reason: PolicyFailureReason::InternalInvariant,
            message: "resolved match policy is missing /analysis/selector",
        });
    };
    let Some((_, query)) = selector.as_query() else {
        return Err(MatchPolicyRefusal {
            reason: PolicyFailureReason::InvalidExecutionPlan,
            message: "match policies require a query selector; row selectors are endpoint-only",
        });
    };
    Ok(query)
}

/// Evaluate the match selector stored in a fully resolved policy.
pub(crate) fn evaluate_match_policy_candidates(
    policy: &LoadedPolicy,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    budget: &PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> EvaluatedMatchPolicy {
    let flow_state = flow_state.into();
    let query = match match_policy_query(policy) {
        Ok(query) => query,
        Err(refusal) => return refusal.into_run(budget),
    };
    evaluate_match_query_candidates(
        &policy.definition().metadata.id,
        &flow_state,
        analyzer,
        workspace,
        query,
        budget,
        cancellation,
    )
}

/// Evaluate a match policy without units from the batch's one whole execution
/// of its selector.
///
/// The batch executes exactly what `evaluate_match_query_candidates` does --
/// the eager whole-workspace execution, projected into unit rows -- so the
/// adapted candidates are the same whichever consumer executed it.
fn shared_match_candidates(
    policy: &LoadedPolicy,
    batch: &SubjectQueryBatch<'_>,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> EvaluatedMatchPolicy {
    let query = match match_policy_query(policy) {
        Ok(query) => query,
        Err(refusal) => return refusal.into_run(budget),
    };
    let executable = match executable_match_query(query, budget) {
        Ok(executable) => executable,
        Err(refusal) => return refusal.into_run(budget),
    };
    let rows = batch.execute(&executable, context, budget);
    adapt_match_execution(
        &policy.definition().metadata.id,
        rows.items.clone(),
        rows.evidence.clone(),
        &rows.diagnostics,
        rows.completion.clone(),
        rows.truncated,
        rows.work,
        budget,
    )
}

/// Why a match policy stopped before it executed anything.
///
/// Carried instead of the built `EvaluatedMatchPolicy` because the refusal is
/// two words and the run it becomes is two hundred bytes; the caller mints the
/// run at the one place it returns.
#[derive(Debug, Clone, Copy)]
struct MatchPolicyRefusal {
    reason: PolicyFailureReason,
    message: &'static str,
}

impl MatchPolicyRefusal {
    /// The failed run this refusal states.
    fn into_run(self, budget: &PolicyBudget) -> EvaluatedMatchPolicy {
        failed_before_execution(self.reason, self.message, budget)
    }
}

/// The exact query a match policy executes, or the failure that stops it.
///
/// Every path a match policy takes -- one whole execution, or one execution
/// per seed file -- runs this query and no other, so a sliced run and a whole
/// run cannot differ by their result detail, their row limit, or which plans
/// they refuse.
fn executable_match_query(
    query: &brokk_bifrost_rql::structural::CodeQuery,
    budget: &PolicyBudget,
) -> Result<brokk_bifrost_rql::structural::CodeQuery, MatchPolicyRefusal> {
    // A union of different row kinds yields rows of every branch's kind, so
    // every kind must be a positive terminal domain on its own (#5352).
    let Ok(row_kinds) = query.validate_row_kinds() else {
        return Err(MatchPolicyRefusal {
            reason: PolicyFailureReason::InvalidExecutionPlan,
            message: "match policy contains an invalid query plan",
        });
    };
    for kind in row_kinds {
        match kind {
            QueryValueKind::ReceiverAnalysis
            | QueryValueKind::MemberTargetAnalysis
            | QueryValueKind::ReceiverOutcome
            | QueryValueKind::ReceiverEvidence
            | QueryValueKind::CallResult
            | QueryValueKind::ResultSubjectUse
            | QueryValueKind::CallArgumentGroup
            | QueryValueKind::CallArgument
            | QueryValueKind::CallBinding
            | QueryValueKind::CallEffect
            | QueryValueKind::CallResultContract
            | QueryValueKind::CallResultObligation
            | QueryValueKind::ResultContractUse
            | QueryValueKind::ResultContractFailureUse
            | QueryValueKind::NilnessOperation
            | QueryValueKind::SwitchCoverage
            | QueryValueKind::AssignmentRelation
            | QueryValueKind::LoopRelation
            | QueryValueKind::StatementReachability
            | QueryValueKind::PendingCleanupFlow
            | QueryValueKind::ClassSetRow
            | QueryValueKind::AbsentMemberFinding
            | QueryValueKind::AbsentMemberWitness
            | QueryValueKind::DetachedTaskTransfer
            | QueryValueKind::ProcedureEffect
            | QueryValueKind::LiteralOccurrence
            | QueryValueKind::DecoratedParameter
            | QueryValueKind::CallableApplicability
            | QueryValueKind::OverloadSelection
            | QueryValueKind::MemberSelection
            | QueryValueKind::CandidateHop
            | QueryValueKind::DispatchOutcome
            | QueryValueKind::DispatchTarget
            | QueryValueKind::MemberFamily
            | QueryValueKind::MemberFamilyEdge
            | QueryValueKind::StateEvent
            | QueryValueKind::BindingInitializerCall
            | QueryValueKind::FlowRelation
            | QueryValueKind::ControlRelation
            | QueryValueKind::BranchRelation
            | QueryValueKind::FailureHandlerState
            | QueryValueKind::Guard
            | QueryValueKind::SourceSet
            | QueryValueKind::BuildTarget
            | QueryValueKind::TopologyEdge
            | QueryValueKind::RewritePath
            | QueryValueKind::Procedure
            | QueryValueKind::ProgramPoint
            | QueryValueKind::ControlEdge
            | QueryValueKind::TypestateFinding
            | QueryValueKind::TypestateWitness
            | QueryValueKind::FlowEndpoint
            | QueryValueKind::FlowWitness
            | QueryValueKind::PointsToCandidate
            | QueryValueKind::TaintFinding => {
            return Err(MatchPolicyRefusal {
                reason: PolicyFailureReason::InvalidExecutionPlan,
                message: "analysis-only query values are not positive match-policy terminal domains",
            });
        }
            QueryValueKind::StructuralMatch
            | QueryValueKind::Declaration
            | QueryValueKind::ReferenceSite
            | QueryValueKind::CallSite
            | QueryValueKind::ExpressionSite
            | QueryValueKind::JsxAttributeValue
            | QueryValueKind::FieldWriteValue
            | QueryValueKind::KeyedReadValue
            | QueryValueKind::Occurrence
            | QueryValueKind::PythonRuleFact
            | QueryValueKind::PythonHierarchyFact
            | QueryValueKind::RustMarkerImpl
            | QueryValueKind::RustPointerFinding
            // A binding and a resolution candidate are both exact facts about
            // one source position, so a match policy listing suspicious
            // bindings or candidate selections is a legitimate thing to
            // author -- the #1473 occurrence precedent applied unchanged. A
            // lexical scope is likewise a node with a span.
            | QueryValueKind::LexicalScope
            | QueryValueKind::Binding
            | QueryValueKind::ResolutionCandidate
            // Materialization rows are exact per-position (or, for a
            // declaration state without a stated range, per-file) records of
            // what one producer derived (#1476), so the same reasoning
            // admits them.
            | QueryValueKind::GenerationSite
            | QueryValueKind::Export
            | QueryValueKind::DeclarationState
            | QueryValueKind::CallShape
            | QueryValueKind::CallableMetrics
            | QueryValueKind::CallableSignature
            | QueryValueKind::SignatureParameter
            // These result domains become findings only for rows carrying an
            // exact source range and matching detailed source evidence.
            // An unanchored row leaves the run incomplete in candidate
            // adaptation.
            // An authored configuration fact is an exact parser record at
            // one document position (#3277); whether the ingested documents
            // are whole is the query's diagnostics' business, the #1476
            // argument.
            | QueryValueKind::DependencyEvidence
            | QueryValueKind::ConfigurationFact
            // A cross-domain row is an exact record of one structurally
            // proven pair, or of one contributing row of a satisfied
            // requirement (#3284). Its anchors are exact positions, and
            // whether either input was whole is the query's diagnostics'
            // business, the same #1476 argument.
            | QueryValueKind::CrossDomain
            // A reference edge is likewise an exact record of what one
            // producer derived at one site; set-level completeness is the
            // query's diagnostics' business (#1479).
            | QueryValueKind::ReferenceEdge
            // A qualified path and its segments are parser facts about exact
            // token chains, the same argument again (#1475).
            | QueryValueKind::QualifiedPath
            | QueryValueKind::PathSegment
            | QueryValueKind::CppExpression
            | QueryValueKind::File => {}
        }
    }

    // Author-controlled presentation/truncation settings are not policy
    // semantics. The host budget alone bounds findings and full detail is
    // required for exact locations.
    let mut executable = query.clone();
    executable.result_detail = CodeQueryResultDetail::Full;
    executable.limit = budget.max_findings();
    Ok(executable)
}

/// Execute one match policy's query over the whole workspace and adapt it.
fn evaluate_match_query_candidates(
    policy_id: &PolicyId,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    budget: &PolicyBudget,
    cancellation: Option<&CancellationToken>,
) -> EvaluatedMatchPolicy {
    let flow_state = flow_state.into();
    evaluate_match_query_candidates_in_scope(
        policy_id,
        &flow_state,
        analyzer,
        workspace,
        query,
        budget,
        cancellation,
        CodeQueryExecutionScope::whole_workspace(),
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_match_query_candidates_in_scope(
    policy_id: &PolicyId,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &brokk_bifrost_rql::structural::CodeQuery,
    budget: &PolicyBudget,
    cancellation: Option<&CancellationToken>,
    execution_scope: CodeQueryExecutionScope<'_>,
) -> EvaluatedMatchPolicy {
    let flow_state = flow_state.into();
    let executable = match executable_match_query(query, budget) {
        Ok(executable) => executable,
        Err(refusal) => return refusal.into_run(budget),
    };
    // Policy batches run many selectors against one immutable snapshot, so
    // index reuse is guaranteed: build the snapshot index on first use
    // instead of letting Auto's first-request deferral scan the workspace
    // once per policy.
    let detailed = match workspace {
        Some(workspace) => execute_code_query_detailed_eager_index_workspace_in_scope(
            workspace,
            &flow_state,
            &executable,
            budget.query_limits(),
            cancellation,
            execution_scope,
        ),
        None => execute_code_query_detailed_eager_index_in_scope(
            analyzer,
            &flow_state,
            &executable,
            budget.query_limits(),
            cancellation,
            execution_scope,
        ),
    };
    adapt_match_execution(
        policy_id,
        // One adapter serves the whole run and the unit path: the whole run's
        // rendered rows are projected into exactly the product a unit
        // publishes before adaptation, so no finding can differ by which path
        // produced it.
        detailed
            .result
            .results
            .iter()
            .map(UnitRowItem::project)
            .collect(),
        detailed
            .evidence
            .iter()
            .map(UnitRowEvidence::project)
            .collect(),
        &detailed.result.diagnostics,
        detailed.result.completion(),
        detailed.result.truncated,
        detailed.work,
        budget,
    )
}

/// Turn one execution's rendered rows into the policy's match candidates.
///
/// Both paths end here: a whole execution's rows and a merge of per-unit rows
/// are the same vector by construction, so everything that decides a finding's
/// identity, ordinal, completeness and the run's completion is computed once,
/// in one place, from that vector.
#[allow(clippy::too_many_arguments)]
fn adapt_match_execution(
    policy_id: &PolicyId,
    rows: Vec<UnitRowItem>,
    evidence: Vec<UnitRowEvidence>,
    query_diagnostics: &[CodeQueryDiagnostic],
    query_completion: CodeQueryCompletion,
    query_truncated: bool,
    work: CodeQueryExecutionWork,
    budget: &PolicyBudget,
) -> EvaluatedMatchPolicy {
    let mut incomplete_reasons = incomplete_reasons(&query_completion, query_truncated);
    let mut failure_reasons = failure_reasons(&query_completion);
    let result_limit_reached = query_diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ResultLimitReached);

    let adapted_diagnostics = adapt_query_diagnostics(
        query_diagnostics,
        budget.max_diagnostics(),
        budget.max_related_locations_per_finding(),
    );
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

    let adapted_candidates = adapt_match_candidates(policy_id, rows, evidence, query_diagnostics);
    incomplete_reasons.extend(adapted_candidates.incomplete_reasons.iter().copied());
    let mut candidates = adapted_candidates.candidates;
    if matches!(query_completion, CodeQueryCompletion::ProvenSubset { .. }) {
        for candidate in &mut candidates {
            candidate.completeness = finding_completeness_with_declared_non_exhaustiveness(
                std::mem::replace(&mut candidate.completeness, FindingCompleteness::Complete),
            );
        }
    }
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
            diagnostics.push(internal_failure_diagnostic(
                "a detailed query row could not be projected into validated policy evidence",
            ));
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
    } else if let CodeQueryCompletion::ProvenSubset { codes } = query_completion {
        PolicyRunCompletion::proven_subset(codes)
            .expect("the detailed query declared at least one non-exhaustive omission")
    } else {
        PolicyRunCompletion::Complete
    };
    let work = work_report(
        work,
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
    max_related: usize,
) -> AdaptedQueryDiagnostics {
    let mut diagnostics = Vec::new();
    let mut truncated = false;
    let mut adaptation_failed = false;
    for diagnostic in query_diagnostics {
        // The broad-query advisory is a measurement of the execution that
        // raised it: its message renders that execution's own scan counters,
        // and the report's `work` section already carries those numbers. It
        // advises an interactive `query_code` caller to add an anchor, which a
        // policy that audits the whole workspace by design cannot take; and
        // because only a whole execution can raise it, forwarding it would
        // make a sliced run differ from a full one both in the report's bytes
        // and at the retention boundary it feeds.
        if diagnostic.code == CodeQueryDiagnosticCode::BroadQuery {
            continue;
        }
        truncated |= diagnostic.related.len() > max_related;
        match adapt_query_diagnostic(diagnostic, max_related) {
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
    // The run keeps the set of diagnostics it raised, not the first ones it
    // raised. Producers repeat one diagnostic per site: on flask one call
    // binding message repeats hundreds of times, so capping the raw list
    // filled every retention slot with copies, reported the run as over its
    // retention budget and dropped the distinct causes that came later
    // (#6638). Deduplicating before the cap makes the retained list, and the
    // truncation, a function of the set of diagnostics alone; past the cap the
    // set folds by reason family, as the report does (#2356).
    truncated |= normalize_policy_diagnostics_bounded(&mut diagnostics, max_diagnostics);
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
    match incomplete_run_diagnostic(PolicyDiagnosticCode::ReportRetentionBudget, message) {
        Some(diagnostic) => diagnostics.push(diagnostic),
        None => *diagnostics_truncated = true,
    }
}

#[derive(Debug)]
struct AdaptedMatchCandidates {
    candidates: Vec<EvaluatedMatchCandidate>,
    conversion_failed: bool,
    omitted_findings_lower_bound: u64,
    incomplete_reasons: Vec<PolicyIncompleteReason>,
}

fn adapt_match_candidates(
    policy_id: &PolicyId,
    rows: Vec<UnitRowItem>,
    evidence: Vec<UnitRowEvidence>,
    query_diagnostics: &[CodeQueryDiagnostic],
) -> AdaptedMatchCandidates {
    let result_count = rows.len();
    let evidence_count = evidence.len();
    let paired_count = result_count.min(evidence_count);
    let mut conversion_failed = result_count != evidence_count;
    let mut omitted_findings_lower_bound =
        u64::try_from(result_count.saturating_sub(paired_count)).unwrap_or(u64::MAX);
    let mut incomplete_reasons = Vec::new();
    let mut ordinals: HashMap<StrongOrdinalKey, u32> = HashMap::new();
    let mut candidates = Vec::with_capacity(paired_count);
    for (item, evidence) in rows.into_iter().zip(evidence) {
        if match_domain(evidence.domain).is_none()
            && !source_backed_analysis_terminal(&item, &evidence)
        {
            omitted_findings_lower_bound = omitted_findings_lower_bound.saturating_add(1);
            if analysis_terminal_pair_is_consistent(&item, &evidence) {
                incomplete_reasons.push(PolicyIncompleteReason::CapabilityIncomplete);
            } else {
                conversion_failed = true;
            }
            continue;
        }
        if evidence.domain == DetailedCodeQueryDomain::PythonHierarchyFact
            && !matches!(&item.terminal, Some(UnitRowItemTerminal::PythonHierarchyFact { coverage, .. }) if coverage == "complete")
        {
            incomplete_reasons.push(PolicyIncompleteReason::CapabilityIncomplete);
            continue;
        }
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
        incomplete_reasons,
    }
}

fn has_modeled_python_ancestry(evidence: &UnitRowEvidence) -> bool {
    fn modeled(key: &DetailedCodeQueryKey) -> bool {
        matches!(key, DetailedCodeQueryKey::PythonHierarchyFact { ancestry_basis, .. } if !ancestry_basis.claims.is_empty())
    }
    modeled(&evidence.key)
        || evidence.provenance.iter().any(|trace| {
            modeled(&trace.seed.key)
                || trace.steps.iter().any(|step| {
                    modeled(&step.result.key)
                        || step.via.as_ref().is_some_and(|via| modeled(&via.key))
                })
        })
}

fn adapt_match_candidate(
    policy_id: &PolicyId,
    item: UnitRowItem,
    evidence: UnitRowEvidence,
    query_diagnostics: &[CodeQueryDiagnostic],
    ordinals: &mut HashMap<StrongOrdinalKey, u32>,
) -> Result<EvaluatedMatchCandidate, ()> {
    let result_domain = match_domain(evidence.domain)
        .or_else(|| {
            source_backed_analysis_terminal(&item, &evidence)
                .then_some(MatchResultDomain::StructuralMatch)
        })
        .ok_or(())?;
    let path = workspace_relative_path(&evidence.rel_path)?;
    let modeled_ancestry = has_modeled_python_ancestry(&evidence);
    let (location, mut candidate_reasons, proof) =
        terminal_presentation(&item, evidence.domain, &path, evidence.byte_span.as_ref())?;
    candidate_reasons.extend(certainty_reasons(query_diagnostics, &evidence.provenance));

    let owner = match evidence.stable_owner_candidate.as_ref() {
        Some(CodeQueryStableOwnerCandidate::Derived {
            derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
            ..
        }) if matches!(
            evidence.domain,
            DetailedCodeQueryDomain::RustMarkerImpl | DetailedCodeQueryDomain::RustPointerFinding
        ) =>
        {
            // These analysis facts are anchored at their exact source row. Their
            // semantic wire id is not a declaration owner; the source slice
            // hash and row ordinal provide the stable finding key.
            OwnerCandidate::Absent
        }
        Some(candidate) => {
            let identity = match candidate {
                CodeQueryStableOwnerCandidate::Declaration { namespace, id } => {
                    StableSemanticIdentity::analyzer_declaration_id(namespace, path.clone(), id)
                }
                CodeQueryStableOwnerCandidate::Derived {
                    namespace,
                    derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
                    semantic_key,
                } => StableSemanticIdentity::canonical_ast_identity(
                    namespace,
                    path.clone(),
                    semantic_key,
                ),
                CodeQueryStableOwnerCandidate::Derived {
                    derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
                    ..
                } => {
                    return Err(());
                }
            };
            match identity {
                Ok(owner) => OwnerCandidate::Accepted(owner),
                Err(_) => OwnerCandidate::Rejected,
            }
        }
        None => OwnerCandidate::Absent,
    };
    let (terminal, terminal_identity_uncertain) = adapt_terminal_result(
        &item,
        evidence.domain,
        &evidence.key,
        &evidence.identities,
        &path,
        &location,
    )?;

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
        MatchFindingAnchor::weak(
            result_domain,
            path.clone(),
            weak_finding_key(&evidence, &path),
        )
    };

    if item.provenance.len() != evidence.provenance.len() {
        return Err(());
    }
    let mut provenance_partial = false;
    let mut provenance_identity_uncertain = terminal_identity_uncertain;
    if terminal_identity_uncertain {
        candidate_reasons.push(CertaintyReason::NameBasedResolution);
    }
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
    let proof = if modeled_ancestry {
        let mut reasons = proof
            .reasons()
            .iter()
            .filter(|reason| !matches!(reason, ProofReason::DirectStructuralMatch))
            .cloned()
            .collect::<Vec<_>>();
        reasons.push(ProofReason::analyzer_evidence("python_modeled_runtime_c3").map_err(|_| ())?);
        ProofMetadata::try_new(proof.state(), reasons, proof.evidence_refs().to_vec())
            .map_err(|_| ())?
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
    let evidence = MatchFindingEvidence::try_new(
        result_domain,
        anchor,
        terminal,
        provenance,
        provenance_truncated,
    )
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

/// The workspace-relative path a projected row and its evidence agree on.
///
/// A unit product carries the normalized workspace-relative spelling rather
/// than a `ProjectFile`, because a unit produced under one workspace root is
/// adapted under another. The spelling is the same in both, which is the whole
/// reason a base unit can answer a head question.
fn workspace_relative_path(rel_path: &str) -> Result<WorkspaceRelativePath, ()> {
    WorkspaceRelativePath::try_from_path(std::path::Path::new(rel_path)).map_err(|_| ())
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

fn unit_row_label<'a>(item: &'a UnitRowItem, name: &str) -> Result<&'a str, ()> {
    match item.field(name).map_err(|_| ())? {
        Some(
            CodeQueryRowScalarRef::StableId(value)
            | CodeQueryRowScalarRef::ConstrainedEnum(value)
            | CodeQueryRowScalarRef::String(value),
        ) => Ok(value),
        _ => Err(()),
    }
}

fn unit_row_optional_label<'a>(item: &'a UnitRowItem, name: &str) -> Result<Option<&'a str>, ()> {
    match item.field(name).map_err(|_| ())? {
        None => Ok(None),
        Some(
            CodeQueryRowScalarRef::StableId(value)
            | CodeQueryRowScalarRef::ConstrainedEnum(value)
            | CodeQueryRowScalarRef::String(value),
        ) => Ok(Some(value)),
        _ => Err(()),
    }
}

fn unit_row_optional_usize(item: &UnitRowItem, name: &str) -> Result<Option<usize>, ()> {
    match item.field(name).map_err(|_| ())? {
        None => Ok(None),
        Some(CodeQueryRowScalarRef::Integer(value)) => {
            Ok(Some(usize::try_from(value).map_err(|_| ())?))
        }
        _ => Err(()),
    }
}

/// Whether an analysis-only result can stand as a policy finding on its own.
/// The row must have its own source range and paired detailed key, path, byte
/// span, and source-slice digest. Derived rows without a concrete stable source
/// position remain analysis-only and cannot create a positive match finding.
fn source_backed_analysis_terminal(item: &UnitRowItem, evidence: &UnitRowEvidence) -> bool {
    source_backed_analysis_terminal_domain(evidence.domain)
        && analysis_terminal_pair_is_consistent(item, evidence)
        && item.range.is_some()
        && evidence.byte_span.is_some()
        && evidence.source_slice_sha256.is_some()
        && matches!(
            item.terminal.as_ref(),
            Some(UnitRowItemTerminal::SourcePosition)
        )
}

fn analysis_terminal_pair_is_consistent(item: &UnitRowItem, evidence: &UnitRowEvidence) -> bool {
    item.domain == evidence.domain
        && item.path.as_ref() == evidence.rel_path.as_ref()
        && evidence.key.domain() == evidence.domain
}

fn terminal_presentation(
    item: &UnitRowItem,
    expected_domain: DetailedCodeQueryDomain,
    expected_path: &WorkspaceRelativePath,
    byte_span: Option<&std::ops::Range<usize>>,
) -> Result<(PolicySourceLocation, Vec<CertaintyReason>, ProofMetadata), ()> {
    // Source-backed analysis rows may use their own exact range as the
    // finding anchor. Rows without a concrete range are rejected by the
    // candidate adapter before their fields are read.
    let UnitRowItem {
        domain: actual_domain,
        path,
        range,
        terminal: Some(terminal),
        ..
    } = item
    else {
        return Err(());
    };
    let (certainty, proof_state, proof_reason) = match terminal {
        UnitRowItemTerminal::StructuralMatch { .. } => (
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
        UnitRowItemTerminal::Declaration { .. } => (
            Vec::new(),
            ProofState::Proven,
            ProofReason::ResolvedDeclaration,
        ),
        UnitRowItemTerminal::Binding { .. } | UnitRowItemTerminal::Occurrence { .. } => (
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
        UnitRowItemTerminal::File => (
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
        UnitRowItemTerminal::ReferenceSite { proof, .. } => {
            let (certainty, state) = proof_certainty(proof);
            (certainty, state, ProofReason::ResolvedReference)
        }
        UnitRowItemTerminal::CallSite { proof, .. } => {
            let (certainty, state) = proof_certainty(proof);
            (certainty, state, ProofReason::ExactCallTarget)
        }
        UnitRowItemTerminal::ExpressionSite { .. } => (
            vec![
                CertaintyReason::analyzer_ambiguity("expression-site-proof-unavailable")
                    .map_err(|_| ())?,
            ],
            ProofState::Unproven,
            ProofReason::PartialWitness,
        ),
        UnitRowItemTerminal::DecoratedParameter {
            terminal,
            completion,
            coverage,
            ..
        } => {
            let complete = *terminal && &**completion == "complete" && &**coverage == "complete";
            (
                Vec::new(),
                if complete {
                    ProofState::Proven
                } else {
                    ProofState::Unproven
                },
                if complete {
                    ProofReason::DirectStructuralMatch
                } else {
                    ProofReason::PartialWitness
                },
            )
        }
        UnitRowItemTerminal::JsxAttributeValue {
            coverage, reason, ..
        } => {
            let certainty = if &**coverage == "complete" {
                Vec::new()
            } else {
                vec![
                    CertaintyReason::analyzer_ambiguity(
                        reason
                            .as_deref()
                            .unwrap_or("jsx-attribute-value-incomplete"),
                    )
                    .map_err(|_| ())?,
                ]
            };
            (
                certainty,
                ProofState::Proven,
                ProofReason::DirectStructuralMatch,
            )
        }
        UnitRowItemTerminal::FieldWriteValue {
            proof,
            completeness,
            coverage,
            ..
        } => {
            if &**proof != "precise" || &**completeness != "complete" || &**coverage != "exhaustive"
            {
                return Err(());
            }
            (
                Vec::new(),
                ProofState::Proven,
                ProofReason::ResolvedReference,
            )
        }
        UnitRowItemTerminal::CallResult { proof } => (
            Vec::new(),
            if &**proof == "proven" {
                ProofState::Proven
            } else {
                ProofState::Unproven
            },
            ProofReason::DirectStructuralMatch,
        ),
        UnitRowItemTerminal::CallEffect { .. } => {
            (Vec::new(), ProofState::Proven, ProofReason::ExactCallTarget)
        }
        UnitRowItemTerminal::ResultSubjectUse {
            proof,
            completeness,
            outcome,
        } => {
            let proven = &**proof == "proven" && &**outcome == "proven";
            let certainty = if &**completeness == "complete" {
                Vec::new()
            } else {
                vec![
                    CertaintyReason::analyzer_ambiguity("result-subject-use-incomplete")
                        .map_err(|_| ())?,
                ]
            };
            (
                certainty,
                if proven {
                    ProofState::Proven
                } else {
                    ProofState::Unproven
                },
                if proven {
                    ProofReason::ResolvedReference
                } else {
                    ProofReason::PartialWitness
                },
            )
        }
        UnitRowItemTerminal::GenerationSite { .. } => (
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
        UnitRowItemTerminal::SourcePosition
            if *actual_domain == DetailedCodeQueryDomain::PythonRuleFact =>
        {
            let fact_label = |name| match item.field(name) {
                Ok(Some(
                    CodeQueryRowScalarRef::ConstrainedEnum(value)
                    | CodeQueryRowScalarRef::String(value),
                )) => Some(value),
                _ => None,
            };
            let proven = fact_label("proof") == Some("proven");
            let complete = fact_label("completeness") == Some("complete");
            let certainty = if proven && complete {
                Vec::new()
            } else {
                vec![
                    CertaintyReason::analyzer_ambiguity(
                        fact_label("reason")
                            .unwrap_or("Python rule fact proof or completeness is unavailable"),
                    )
                    .map_err(|_| ())?,
                ]
            };
            (
                certainty,
                if proven && complete {
                    ProofState::Proven
                } else {
                    ProofState::Unproven
                },
                if proven && complete {
                    ProofReason::DirectStructuralMatch
                } else {
                    ProofReason::PartialWitness
                },
            )
        }
        UnitRowItemTerminal::PythonHierarchyFact { coverage, .. } => {
            if *actual_domain != DetailedCodeQueryDomain::PythonHierarchyFact {
                return Err(());
            }
            let complete = coverage == "complete";
            let certainty = if complete {
                Vec::new()
            } else {
                vec![
                    CertaintyReason::analyzer_ambiguity("Python hierarchy outcome is incomplete")
                        .map_err(|_| ())?,
                ]
            };
            (
                certainty,
                if complete {
                    ProofState::Proven
                } else {
                    ProofState::Unproven
                },
                if complete {
                    ProofReason::DirectStructuralMatch
                } else {
                    ProofReason::PartialWitness
                },
            )
        }
        UnitRowItemTerminal::SourcePosition
            if *actual_domain == DetailedCodeQueryDomain::RustMarkerImpl =>
        {
            let fact_label = |name| match item.field(name) {
                Ok(Some(
                    CodeQueryRowScalarRef::ConstrainedEnum(value)
                    | CodeQueryRowScalarRef::String(value),
                )) => Some(value),
                _ => None,
            };
            let proven = fact_label("completeness") == Some("complete");
            let complete = fact_label("completeness") == Some("complete");
            let certainty = if proven && complete {
                Vec::new()
            } else {
                vec![
                    CertaintyReason::analyzer_ambiguity("rust_marker_impl_incomplete")
                        .map_err(|_| ())?,
                ]
            };
            (
                certainty,
                if proven && complete {
                    ProofState::Proven
                } else {
                    ProofState::Unproven
                },
                if proven && complete {
                    ProofReason::DirectStructuralMatch
                } else {
                    ProofReason::PartialWitness
                },
            )
        }
        UnitRowItemTerminal::SourcePosition
            if *actual_domain == DetailedCodeQueryDomain::RustPointerFinding =>
        {
            let fact_label = |name| match item.field(name) {
                Ok(Some(
                    CodeQueryRowScalarRef::ConstrainedEnum(value)
                    | CodeQueryRowScalarRef::String(value),
                )) => Some(value),
                _ => None,
            };
            let proven = fact_label("proof") == Some("proven");
            let complete = fact_label("completeness") == Some("complete");
            let certainty = if proven && complete {
                Vec::new()
            } else {
                vec![
                    CertaintyReason::analyzer_ambiguity("rust_pointer_finding_incomplete")
                        .map_err(|_| ())?,
                ]
            };
            (
                certainty,
                if proven && complete {
                    ProofState::Proven
                } else {
                    ProofState::Unproven
                },
                if proven && complete {
                    ProofReason::DirectStructuralMatch
                } else {
                    ProofReason::PartialWitness
                },
            )
        }
        // Every remaining presented family is an exact record of what one
        // producer derived at one position: its own presence is proven, and
        // whatever completeness the row states is the row's own column, not a
        // proof tier of the position.
        UnitRowItemTerminal::SourcePosition
        | UnitRowItemTerminal::CrossDomain { .. }
        | UnitRowItemTerminal::AbsentMemberFinding { .. } => (
            Vec::new(),
            ProofState::Proven,
            ProofReason::DirectStructuralMatch,
        ),
    };
    if *actual_domain != expected_domain || path.as_ref() != expected_path.as_str() {
        return Err(());
    }
    let location = if *actual_domain == DetailedCodeQueryDomain::File
        || (matches!(
            *actual_domain,
            DetailedCodeQueryDomain::DeclarationState | DetailedCodeQueryDomain::CrossDomain
        ) && byte_span.is_none()
            && range.is_none())
    {
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

fn adapt_terminal_result(
    item: &UnitRowItem,
    expected_domain: DetailedCodeQueryDomain,
    key: &DetailedCodeQueryKey,
    identities: &UnitRowIdentities,
    expected_path: &WorkspaceRelativePath,
    location: &PolicySourceLocation,
) -> Result<(PolicyQueryResultRef, bool), ()> {
    let UnitRowItem {
        path,
        range,
        terminal: Some(terminal),
        ..
    } = item
    else {
        return Err(());
    };
    if path.as_ref() != expected_path.as_str() {
        return Err(());
    }
    match (terminal, expected_domain, key, identities) {
        (
            UnitRowItemTerminal::StructuralMatch { kind, .. },
            DetailedCodeQueryDomain::StructuralMatch,
            DetailedCodeQueryKey::StructuralMatch {
                kind: detailed_kind,
                ..
            },
            UnitRowIdentities::Primary(identity),
        ) if kind.as_ref() == detailed_kind.as_str() => Ok((
            PolicyQueryResultRef::StructuralMatch {
                kind: detailed_kind.clone(),
                location: location.clone(),
                identity: validated_provenance_identity(identity.as_ref()),
            },
            false,
        )),
        (
            UnitRowItemTerminal::Declaration { kind, fq_name },
            DetailedCodeQueryDomain::Declaration,
            DetailedCodeQueryKey::Declaration {
                kind: detailed_kind,
                fq_name: detailed_fq_name,
                ..
            },
            UnitRowIdentities::Primary(identity),
        ) if kind.as_ref() == detailed_kind.as_str()
            && fq_name.as_ref() == detailed_fq_name.as_str() =>
        {
            Ok((
                PolicyQueryResultRef::Declaration {
                    kind: detailed_kind.clone(),
                    fq_name: detailed_fq_name.clone(),
                    location: location.clone(),
                    identity: validated_provenance_identity(identity.as_ref()),
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::Binding {
                id, ast_id, name, ..
            },
            DetailedCodeQueryDomain::Binding,
            DetailedCodeQueryKey::Binding {
                id: detailed_id,
                ast_id: detailed_ast_id,
                name: detailed_name,
            },
            UnitRowIdentities::None,
        ) if id.as_ref() == detailed_id
            && ast_id.as_deref() == detailed_ast_id.as_deref()
            && name.as_ref() == detailed_name.as_str()
            && range_matches_location(*range, location) =>
        {
            Ok((
                PolicyQueryResultRef::Binding {
                    id: detailed_id.clone(),
                    ast_id: detailed_ast_id.clone(),
                    name: detailed_name.clone(),
                    location: location.clone(),
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::Occurrence {
                id,
                ast_id,
                class,
                role,
                namespace,
            },
            DetailedCodeQueryDomain::Occurrence,
            DetailedCodeQueryKey::Occurrence {
                id: detailed_id,
                ast_id: detailed_ast_id,
                role: detailed_role,
            },
            UnitRowIdentities::None,
        ) if id.as_ref() == detailed_id
            && ast_id.as_ref() == detailed_ast_id
            && role.as_ref() == detailed_role
            && range_matches_location(*range, location) =>
        {
            Ok((
                PolicyQueryResultRef::Occurrence {
                    id: detailed_id.clone(),
                    ast_id: detailed_ast_id.clone(),
                    class: class.to_string(),
                    role: detailed_role.clone(),
                    namespace: namespace.to_string(),
                    location: location.clone(),
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::File,
            DetailedCodeQueryDomain::File,
            DetailedCodeQueryKey::File,
            UnitRowIdentities::None,
        ) => Ok((PolicyQueryResultRef::file(expected_path.clone()), false)),
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::Export,
            DetailedCodeQueryKey::Export {
                id,
                form,
                exported_name,
                local_definition: detailed_definition,
            },
            UnitRowIdentities::None,
        ) if unit_row_label(item, "id")? == id
            && unit_row_label(item, "form")? == form
            && unit_row_label(item, "exported_name")? == exported_name
            && range_matches_location(*range, location) =>
        {
            let target_fq_name = match item.field("target_fq_name").map_err(|_| ())? {
                None => None,
                Some(CodeQueryRowScalarRef::String(value)) => Some(value.to_owned()),
                _ => return Err(()),
            };
            let definition_status = unit_row_optional_label(item, "definition_status")?;
            let binding_name = unit_row_optional_label(item, "definition_binding_name")?;
            let binding_kind = unit_row_optional_label(item, "definition_binding_kind")?;
            let binding_start_byte =
                unit_row_optional_usize(item, "definition_binding_start_byte")?;
            let binding_end_byte = unit_row_optional_usize(item, "definition_binding_end_byte")?;
            let binding_start_line =
                unit_row_optional_usize(item, "definition_binding_start_line")?;
            let binding_start_column =
                unit_row_optional_usize(item, "definition_binding_start_column")?;
            let binding_end_line = unit_row_optional_usize(item, "definition_binding_end_line")?;
            let binding_end_column =
                unit_row_optional_usize(item, "definition_binding_end_column")?;
            let no_binding_fields = binding_name.is_none()
                && binding_kind.is_none()
                && binding_start_byte.is_none()
                && binding_end_byte.is_none()
                && binding_start_line.is_none()
                && binding_start_column.is_none()
                && binding_end_line.is_none()
                && binding_end_column.is_none();
            let local_definition = match detailed_definition {
                None if definition_status.is_none() && no_binding_fields => None,
                Some(DetailedCodeQueryExportLocalDefinition::Undefined)
                    if definition_status == Some("undefined") && no_binding_fields =>
                {
                    Some(PolicyExportLocalDefinition::Undefined)
                }
                Some(DetailedCodeQueryExportLocalDefinition::Unknown)
                    if definition_status == Some("unknown") && no_binding_fields =>
                {
                    Some(PolicyExportLocalDefinition::Unknown)
                }
                Some(DetailedCodeQueryExportLocalDefinition::Defined {
                    binding_name: detailed_name,
                    binding_kind: detailed_kind,
                    start_byte: detailed_start_byte,
                    end_byte: detailed_end_byte,
                    range: detailed_range,
                }) if definition_status == Some("defined")
                    && binding_name == Some(detailed_name.as_str())
                    && binding_kind == Some(detailed_kind.as_str())
                    && binding_start_byte == Some(*detailed_start_byte)
                    && binding_end_byte == Some(*detailed_end_byte)
                    && binding_start_line == Some(detailed_range.start_line)
                    && binding_start_column == Some(detailed_range.start_column)
                    && binding_end_line == Some(detailed_range.end_line)
                    && binding_end_column == Some(detailed_range.end_column) =>
                {
                    let binding_location = policy_span_location(
                        expected_path.clone(),
                        &(*detailed_start_byte..*detailed_end_byte),
                        *detailed_range,
                    )?;
                    Some(PolicyExportLocalDefinition::Defined {
                        binding_name: detailed_name.clone(),
                        binding_kind: detailed_kind.clone(),
                        binding_location,
                    })
                }
                _ => return Err(()),
            };
            Ok((
                PolicyQueryResultRef::Export {
                    location: location.clone(),
                    id: id.clone(),
                    form: form.clone(),
                    exported_name: exported_name.clone(),
                    target_fq_name,
                    local_definition,
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::DependencyEvidence,
            DetailedCodeQueryKey::DependencyEvidence {
                id,
                ecosystem,
                package,
                evidence_kind,
                scope,
                source_digest,
                version_requirement,
                exact_version,
                source,
                declared_by,
            },
            UnitRowIdentities::None,
        ) => Ok((
            PolicyQueryResultRef::DependencyEvidence {
                location: location.clone(),
                id: id.clone(),
                ecosystem: ecosystem.clone(),
                package: package.clone(),
                evidence_kind: evidence_kind.clone(),
                scope: scope.clone(),
                source_digest: source_digest.clone(),
                version_requirement: version_requirement.clone(),
                exact_version: exact_version.clone(),
                source: source.clone(),
                declared_by: declared_by.clone(),
            },
            false,
        )),
        // Authored configuration facts are exact parser rows. The policy
        // terminal keeps the fact's workspace path and byte span through the
        // structural envelope while carrying no semantic identity: a
        // configuration fact is evidence about a document, never about a
        // resolved declaration.
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::ConfigurationFact,
            DetailedCodeQueryKey::ConfigurationFact { .. },
            UnitRowIdentities::None,
        ) => {
            let DetailedCodeQueryKey::ConfigurationFact { id, fact_id } = key else {
                unreachable!();
            };
            Ok((
                PolicyQueryResultRef::ConfigurationFact {
                    location: location.clone(),
                    id: id.clone(),
                    fact_id: fact_id.clone(),
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::CppExpression,
            DetailedCodeQueryKey::CppExpression { .. },
            UnitRowIdentities::None,
        ) => Ok((
            PolicyQueryResultRef::StructuralMatch {
                kind: "cpp_expression".to_owned(),
                location: location.clone(),
                identity: None,
            },
            false,
        )),
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::PythonRuleFact,
            DetailedCodeQueryKey::PythonRuleFact { relation, .. },
            UnitRowIdentities::None,
        ) => Ok((
            PolicyQueryResultRef::StructuralMatch {
                kind: relation.clone(),
                location: location.clone(),
                identity: None,
            },
            false,
        )),
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::RustMarkerImpl,
            DetailedCodeQueryKey::RustMarkerImpl { .. },
            UnitRowIdentities::Primary(identity),
        ) => Ok((
            PolicyQueryResultRef::StructuralMatch {
                kind: unit_row_label(item, "trait")?.to_owned(),
                location: location.clone(),
                identity: validated_provenance_identity(identity.as_ref()),
            },
            false,
        )),
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::RustPointerFinding,
            DetailedCodeQueryKey::RustPointerFinding { .. },
            UnitRowIdentities::Primary(identity),
        ) => Ok((
            PolicyQueryResultRef::StructuralMatch {
                kind: unit_row_label(item, "relation")?.to_owned(),
                location: location.clone(),
                identity: validated_provenance_identity(identity.as_ref()),
            },
            false,
        )),
        (
            UnitRowItemTerminal::PythonHierarchyFact {
                id,
                root_id,
                declaration_id,
                owner_id,
                target_id,
                target_owner_id,
                fact_kind,
                outcome,
                coverage,
                reason,
                ancestry_basis,
            },
            DetailedCodeQueryDomain::PythonHierarchyFact,
            DetailedCodeQueryKey::PythonHierarchyFact {
                id: key_id,
                root_id: key_root,
                declaration_id: key_declaration,
                owner_id: key_owner,
                target_id: key_target,
                target_owner_id: key_target_owner,
                fact_kind: key_kind,
                outcome: key_outcome,
                coverage: key_coverage,
                reason: key_reason,
                ancestry_basis: key_basis,
            },
            UnitRowIdentities::None,
        ) if id == key_id
            && root_id == key_root
            && declaration_id == key_declaration
            && owner_id == key_owner
            && target_id == key_target
            && target_owner_id == key_target_owner
            && fact_kind == key_kind
            && outcome == key_outcome
            && coverage == key_coverage
            && reason == key_reason
            && ancestry_basis == key_basis =>
        {
            Ok((
                PolicyQueryResultRef::PythonHierarchyFact {
                    id: id.clone(),
                    root_id: root_id.clone(),
                    declaration_id: declaration_id.clone(),
                    owner_id: owner_id.clone(),
                    target_id: target_id.clone(),
                    target_owner_id: target_owner_id.clone(),
                    fact_kind: fact_kind.clone(),
                    outcome: outcome.clone(),
                    coverage: coverage.clone(),
                    reason: reason.clone(),
                    location: location.clone(),
                    ancestry_basis: ancestry_basis.clone(),
                },
                false,
            ))
        }
        // A cross-domain row keeps both identities and both anchors: the row
        // location is the code row (or a configuration witness's fact), and a
        // carried configuration fact keeps its own exact span (#3284).
        (
            UnitRowItemTerminal::CrossDomain {
                operator,
                domain,
                configuration,
                dependency_mitigation,
            },
            DetailedCodeQueryDomain::CrossDomain,
            DetailedCodeQueryKey::CrossDomain {
                id,
                code_id,
                configuration_id,
            },
            UnitRowIdentities::None,
        ) => {
            let configuration_location = configuration
                .as_ref()
                .map(|anchor| {
                    policy_span_location(
                        WorkspaceRelativePath::try_from_path(std::path::Path::new(
                            anchor.path.as_ref(),
                        ))
                        .map_err(|_| ())?,
                        &(anchor.start_byte..anchor.end_byte),
                        anchor.range,
                    )
                })
                .transpose()?;
            let dependency_mitigation = dependency_mitigation
                .as_ref()
                .map(|evidence| {
                    let configuration_contributors = evidence
                        .contributors
                        .iter()
                        .map(|anchor| {
                            policy_span_location(
                                WorkspaceRelativePath::try_from_path(std::path::Path::new(
                                    anchor.path.as_ref(),
                                ))
                                .map_err(|_| ())?,
                                &(anchor.start_byte..anchor.end_byte),
                                anchor.range,
                            )
                        })
                        .collect::<Result<Vec<_>, ()>>()?;
                    Ok::<_, ()>(super::finding::PolicyDependencyMitigation {
                        dependency_id: evidence.dependency_id.clone(),
                        owner: evidence.owner.clone(),
                        mapping_id: evidence.mapping_id.clone(),
                        mitigated: evidence.mitigated,
                        effective_configuration: evidence.effective.clone(),
                        configuration_contributors,
                    })
                })
                .transpose()?;
            Ok((
                PolicyQueryResultRef::CrossDomain {
                    location: location.clone(),
                    id: id.clone(),
                    operator: operator.to_string(),
                    domain: domain.to_string(),
                    code_id: code_id.clone(),
                    configuration_id: configuration_id.clone(),
                    configuration_location,
                    dependency_mitigation,
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::ReferenceSite {
                proof,
                target_fq_name,
                usage_kind,
            },
            DetailedCodeQueryDomain::ReferenceSite,
            DetailedCodeQueryKey::ReferenceSite {
                target_fq_name: detailed_target,
                ..
            },
            UnitRowIdentities::ReferenceTarget(target_identity),
        ) if target_fq_name.as_ref() == detailed_target.as_str() => {
            let target_identity = validated_provenance_identity(target_identity.as_ref());
            let identity_uncertain = &**proof == "proven" && target_identity.is_none();
            Ok((
                PolicyQueryResultRef::ReferenceSite {
                    location: location.clone(),
                    target_fq_name: detailed_target.clone(),
                    target_identity,
                    usage_kind: Some(usage_kind.to_string()),
                    proof: if identity_uncertain {
                        PolicyQueryProof::NameBased
                    } else {
                        policy_query_proof(proof)
                    },
                },
                identity_uncertain,
            ))
        }
        (
            UnitRowItemTerminal::CallSite {
                proof,
                caller_fq_name,
                callee_fq_name,
            },
            DetailedCodeQueryDomain::CallSite,
            DetailedCodeQueryKey::CallSite {
                caller_fq_name: detailed_caller,
                callee_fq_name: detailed_callee,
                ..
            },
            UnitRowIdentities::Call { caller, callee },
        ) if caller_fq_name.as_ref() == detailed_caller.as_str()
            && callee_fq_name.as_ref() == detailed_callee.as_str() =>
        {
            let caller_identity = validated_provenance_identity(caller.as_ref());
            let callee_identity = validated_provenance_identity(callee.as_ref());
            let identity_uncertain =
                &**proof == "proven" && (caller_identity.is_none() || callee_identity.is_none());
            Ok((
                PolicyQueryResultRef::CallSite {
                    location: location.clone(),
                    caller_fq_name: detailed_caller.clone(),
                    caller_identity,
                    callee_fq_name: detailed_callee.clone(),
                    callee_identity,
                    proof: if identity_uncertain {
                        PolicyQueryProof::NameBased
                    } else {
                        policy_query_proof(proof)
                    },
                },
                identity_uncertain,
            ))
        }
        (
            UnitRowItemTerminal::ExpressionSite {
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
            UnitRowIdentities::None,
        ) if input_kind.as_ref() == detailed_input.as_str()
            && parameter_index.and_then(|index| u32::try_from(index).ok()) == *detailed_index
            && parameter_name.as_deref() == detailed_name.as_deref() =>
        {
            Ok((
                PolicyQueryResultRef::ExpressionSite {
                    location: location.clone(),
                    input_kind: detailed_input.clone(),
                    parameter_index: *detailed_index,
                    parameter_name: detailed_name.clone(),
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::GenerationSite { id, ast_id, kind },
            DetailedCodeQueryDomain::GenerationSite,
            DetailedCodeQueryKey::GenerationSite {
                id: detailed_id,
                ast_id: detailed_ast_id,
                kind: detailed_kind,
            },
            UnitRowIdentities::None,
        ) if id.as_ref() == detailed_id.as_str()
            && ast_id.as_deref() == detailed_ast_id.as_deref()
            && kind.as_ref() == detailed_kind.as_str() =>
        {
            Ok((
                PolicyQueryResultRef::GenerationSite {
                    location: location.clone(),
                    id: detailed_id.clone(),
                    ast_id: detailed_ast_id.clone(),
                    kind: detailed_kind.clone(),
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::DecoratedParameter {
                id, parameter_id, ..
            },
            DetailedCodeQueryDomain::DecoratedParameter,
            DetailedCodeQueryKey::DecoratedParameter {
                id: detailed_id,
                parameter_id: detailed_parameter_id,
            },
            UnitRowIdentities::None,
        ) if id.as_ref() == detailed_id.as_str()
            && parameter_id.as_ref() == detailed_parameter_id.as_str()
            && *range
                == location.region().map(|region| CodeQueryRange {
                    start_line: region.start_line() as usize,
                    start_column: region.start_column() as usize,
                    end_line: region.end_line() as usize,
                    end_column: region.end_column() as usize,
                }) =>
        {
            Ok((
                // The policy report has one source-backed terminal structural
                // result shape. Preserve the decorated parameter's exact span as
                // a structural match so matched-value binding can ask the semantic
                // oracle for the corresponding parameter value.
                PolicyQueryResultRef::StructuralMatch {
                    kind: "parameter".to_owned(),
                    location: location.clone(),
                    identity: None,
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::JsxAttributeValue {
                id,
                ast_id,
                element_identity,
                coverage,
                ..
            },
            DetailedCodeQueryDomain::JsxAttributeValue,
            DetailedCodeQueryKey::JsxAttributeValue {
                id: detailed_id,
                ast_id: detailed_ast_id,
            },
            UnitRowIdentities::Primary(_),
        ) if id.as_ref() == detailed_id.as_str() && ast_id.as_ref() == detailed_ast_id.as_str() => {
            Ok((
                PolicyQueryResultRef::JsxAttributeValue {
                    location: location.clone(),
                    ast_id: detailed_ast_id.clone(),
                    element_identity: element_identity.to_string(),
                    coverage: coverage.to_string(),
                },
                &**coverage != "complete",
            ))
        }
        (
            UnitRowItemTerminal::FieldWriteValue {
                id,
                assignment_ast_id,
                rhs_ast_id,
                receiver_identity_id,
                member_target_id,
                proof,
                completeness,
                coverage,
            },
            DetailedCodeQueryDomain::FieldWriteValue,
            DetailedCodeQueryKey::FieldWriteValue {
                id: detailed_id,
                assignment_ast_id: detailed_assignment_ast_id,
                rhs_ast_id: detailed_rhs_ast_id,
                receiver_identity_id: detailed_receiver_identity_id,
                member_target_id: detailed_member_target_id,
            },
            UnitRowIdentities::Primary(_),
        ) if id.as_ref() == detailed_id.as_str()
            && assignment_ast_id.as_ref() == detailed_assignment_ast_id.as_str()
            && rhs_ast_id.as_ref() == detailed_rhs_ast_id.as_str()
            && receiver_identity_id.as_ref() == detailed_receiver_identity_id.as_str()
            && member_target_id.as_ref() == detailed_member_target_id.as_str()
            && &**proof == "precise"
            && &**completeness == "complete"
            && &**coverage == "exhaustive" =>
        {
            Ok((
                PolicyQueryResultRef::FieldWriteValue {
                    location: location.clone(),
                    assignment_ast_id: assignment_ast_id.to_string(),
                    rhs_ast_id: detailed_rhs_ast_id.clone(),
                    receiver_identity_id: receiver_identity_id.to_string(),
                    member_target_id: detailed_member_target_id.clone(),
                    proof: proof.to_string(),
                    completeness: completeness.to_string(),
                    coverage: coverage.to_string(),
                },
                false,
            ))
        }
        (UnitRowItemTerminal::SourcePosition, domain, key, UnitRowIdentities::None)
            if match_domain(domain).is_none()
                && item.range.is_some()
                && key.domain() == domain
                && range_matches_location(*range, location) =>
        {
            Ok((
                PolicyQueryResultRef::StructuralMatch {
                    kind: domain.label().to_owned(),
                    location: location.clone(),
                    identity: None,
                },
                false,
            ))
        }
        (
            UnitRowItemTerminal::SourcePosition,
            DetailedCodeQueryDomain::CallableMetrics,
            DetailedCodeQueryKey::CallableMetrics { .. },
            UnitRowIdentities::None,
        ) if item.range.is_some() && range_matches_location(*range, location) => Ok((
            PolicyQueryResultRef::StructuralMatch {
                kind: "callable_metrics".to_owned(),
                location: location.clone(),
                identity: None,
            },
            false,
        )),
        _ => Err(()),
    }
}

fn source_backed_analysis_terminal_domain(domain: DetailedCodeQueryDomain) -> bool {
    matches!(
        domain,
        DetailedCodeQueryDomain::CallShape
            | DetailedCodeQueryDomain::CallableSignature
            | DetailedCodeQueryDomain::SignatureParameter
    )
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
    PolicySourceLocation::span_from_coordinates(
        path,
        u64::try_from(byte_span.start).map_err(|_| ())?,
        u64::try_from(byte_span.end).map_err(|_| ())?,
        u64::try_from(range.start_line).map_err(|_| ())?,
        u64::try_from(range.start_column).map_err(|_| ())?,
        u64::try_from(range.end_line).map_err(|_| ())?,
        u64::try_from(range.end_column).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

fn range_matches_location(range: Option<CodeQueryRange>, location: &PolicySourceLocation) -> bool {
    let Some(range) = range else {
        return false;
    };
    location.region().is_some_and(|region| {
        range
            == CodeQueryRange {
                start_line: region.start_line() as usize,
                start_column: region.start_column() as usize,
                end_line: region.end_line() as usize,
                end_column: region.end_column() as usize,
            }
    })
}

fn adapt_provenance(
    provenance: UnitRowItemProvenance,
    detailed: UnitRowProvenance,
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
            if step.op.as_ref() != detailed.op.as_str()
                || step.via.is_some() != detailed.via.is_some()
            {
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
            PolicyQueryProvenanceStep::try_new(detailed.op, result, via).map_err(|_| ())
        })
        .collect::<Result<Vec<_>, _>>()?;
    PolicyQueryProvenance::try_new(branch, seed, steps)
        .map(|provenance| (provenance, partial, identity_uncertain))
        .map_err(|_| ())
}

fn adapt_provenance_ref(
    value: UnitRowItemRef,
    detailed: UnitRowProvenanceRef,
) -> Result<(PolicyQueryResultRef, bool, bool), ()> {
    let value_kind = value.kind.clone();
    let kind = value.kind.clone();
    let item_path = value.path.clone();
    let python_hierarchy_fact_ref = value.kind.as_ref() == "python_hierarchy_fact";
    let binding_ref = value.kind.as_ref() == "binding";
    let lexical_scope_ref = value.kind.as_ref() == "lexical_scope";
    let occurrence_ref = value.kind.as_ref() == "occurrence";
    let UnitRowProvenanceRef {
        domain,
        key,
        rel_path,
        byte_span,
        display_range,
        identities,
        source_slice_sha256,
    } = detailed;
    let path = workspace_relative_path(&rel_path)?;
    if item_path.as_ref() != path.as_str() {
        return Err(());
    }
    let source_exact = domain == DetailedCodeQueryDomain::File
        || (source_slice_sha256.is_some() && byte_span.is_some() && display_range.is_some());
    if matches!(&value.value, UnitRowItemRefValue::Unsupported)
        && domain != DetailedCodeQueryDomain::DispatchTarget
    {
        let reference = if source_exact {
            match (byte_span.as_ref(), display_range) {
                (Some(byte_span), Some(range)) => PolicyQueryResultRef::Unsupported {
                    query_result_kind: value.kind.to_string(),
                    location: Some(policy_span_location(path.clone(), byte_span, range)?),
                },
                _ => unsupported_provenance_ref(&value.kind, path),
            }
        } else {
            unsupported_provenance_ref(&value.kind, path)
        };
        return Ok((reference, true, false));
    }
    if !source_exact {
        return Ok((unsupported_provenance_ref(&kind, path), true, false));
    }

    let mut identity_uncertain = false;
    let unsupported = matches!(&value.value, UnitRowItemRefValue::Unsupported);
    let provenance_partial = unsupported
        && matches!(
            domain,
            DetailedCodeQueryDomain::CallShape
                | DetailedCodeQueryDomain::CallArgumentGroup
                | DetailedCodeQueryDomain::CallArgument
                | DetailedCodeQueryDomain::CallBinding
        )
        || matches!(&value.value, UnitRowItemRefValue::PythonHierarchyFact { coverage, .. } if coverage != "complete")
        || matches!(&value.value, UnitRowItemRefValue::CallableSignature { coverage, .. } if coverage.as_ref() != "exact");
    let adapted = match (value.value, domain, key, identities) {
        // Analysis-only rows such as call shapes and call bindings are not
        // terminal policy result families, but they can still occur in the
        // provenance of a source-backed structural finding. Preserve their
        // exact anchor without pretending the policy adapter has a typed
        // payload for them.
        (
            UnitRowItemRefValue::Unsupported,
            DetailedCodeQueryDomain::CallShape
            | DetailedCodeQueryDomain::CallArgumentGroup
            | DetailedCodeQueryDomain::CallArgument
            | DetailedCodeQueryDomain::CallBinding,
            _,
            _,
        ) => PolicyQueryResultRef::Unsupported {
            query_result_kind: kind.to_string(),
            location: Some(policy_span_location(
                path,
                byte_span.as_ref().ok_or(())?,
                display_range.ok_or(())?,
            )?),
        },
        (
            UnitRowItemRefValue::StructuralMatch {
                kind,
                node_range: Some(range),
            },
            DetailedCodeQueryDomain::StructuralMatch,
            DetailedCodeQueryKey::StructuralMatch {
                kind: detailed_kind,
                ..
            },
            UnitRowIdentities::Primary(identity),
        ) if kind.as_ref() == detailed_kind.as_str() && Some(range) == display_range => {
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
            UnitRowItemRefValue::StructuralMatch {
                kind,
                node_range: Some(range),
            },
            DetailedCodeQueryDomain::PythonRuleFact,
            DetailedCodeQueryKey::PythonRuleFact { relation, .. },
            UnitRowIdentities::None,
        ) if value_kind.as_ref() == "python_rule_fact"
            && kind.as_ref() == relation
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::StructuralMatch {
                kind: relation,
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                identity: None,
            }
        }
        (
            UnitRowItemRefValue::StructuralMatch {
                kind,
                node_range: Some(range),
            },
            DetailedCodeQueryDomain::RustMarkerImpl,
            DetailedCodeQueryKey::RustMarkerImpl { .. },
            UnitRowIdentities::Primary(identity),
        ) if value_kind.as_ref() == "rust_marker_impl" && Some(range) == display_range => {
            PolicyQueryResultRef::StructuralMatch {
                kind: kind.to_string(),
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                identity: validated_provenance_identity(identity.as_ref()),
            }
        }
        (
            UnitRowItemRefValue::StructuralMatch {
                kind,
                node_range: Some(range),
            },
            DetailedCodeQueryDomain::RustPointerFinding,
            DetailedCodeQueryKey::RustPointerFinding { .. },
            UnitRowIdentities::Primary(identity),
        ) if value_kind.as_ref() == "rust_pointer_finding" && Some(range) == display_range => {
            PolicyQueryResultRef::StructuralMatch {
                kind: kind.to_string(),
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                identity: validated_provenance_identity(identity.as_ref()),
            }
        }
        (
            UnitRowItemRefValue::Binding {
                id,
                ast_id,
                name,
                range,
                ..
            },
            DetailedCodeQueryDomain::Binding,
            DetailedCodeQueryKey::Binding {
                id: detailed_id,
                ast_id: detailed_ast_id,
                name: detailed_name,
            },
            UnitRowIdentities::None,
        ) if binding_ref
            && id.as_ref() == detailed_id
            && ast_id.as_deref() == detailed_ast_id.as_deref()
            && name.as_ref() == detailed_name.as_str()
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::Binding {
                id: detailed_id,
                ast_id: detailed_ast_id,
                name: detailed_name,
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
            }
        }
        (
            UnitRowItemRefValue::LexicalScope {
                id,
                ast_id,
                index,
                range,
            },
            DetailedCodeQueryDomain::LexicalScope,
            DetailedCodeQueryKey::LexicalScope {
                id: detailed_id,
                ast_id: detailed_ast_id,
                index: detailed_index,
            },
            UnitRowIdentities::None,
        ) if lexical_scope_ref
            && id.as_ref() == detailed_id
            && ast_id.as_deref() == detailed_ast_id.as_deref()
            && index == detailed_index
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::LexicalScope {
                id: detailed_id,
                ast_id: detailed_ast_id,
                index: detailed_index,
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
            }
        }
        (
            UnitRowItemRefValue::Occurrence {
                id,
                ast_id,
                role,
                class,
                namespace,
                range,
            },
            DetailedCodeQueryDomain::Occurrence,
            DetailedCodeQueryKey::Occurrence {
                id: detailed_id,
                ast_id: detailed_ast_id,
                role: detailed_role,
            },
            UnitRowIdentities::None,
        ) if occurrence_ref
            && id.as_ref() == detailed_id
            && ast_id.as_ref() == detailed_ast_id
            && role.as_ref() == detailed_role
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::Occurrence {
                id: detailed_id,
                ast_id: detailed_ast_id,
                class: class.to_string(),
                role: detailed_role,
                namespace: namespace.to_string(),
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
            }
        }
        (
            UnitRowItemRefValue::PythonHierarchyFact {
                id,
                root_id,
                declaration_id,
                owner_id,
                target_id,
                target_owner_id,
                fact_kind,
                outcome,
                coverage,
                reason,
                range,
                ancestry_basis,
            },
            DetailedCodeQueryDomain::PythonHierarchyFact,
            DetailedCodeQueryKey::PythonHierarchyFact {
                id: key_id,
                root_id: key_root,
                declaration_id: key_declaration,
                owner_id: key_owner,
                target_id: key_target,
                target_owner_id: key_target_owner,
                fact_kind: key_kind,
                outcome: key_outcome,
                coverage: key_coverage,
                reason: key_reason,
                ancestry_basis: key_basis,
            },
            UnitRowIdentities::None,
        ) if python_hierarchy_fact_ref
            && Some(range) == display_range
            && id == key_id
            && root_id == key_root
            && declaration_id == key_declaration
            && owner_id == key_owner
            && target_id == key_target
            && target_owner_id == key_target_owner
            && fact_kind == key_kind
            && outcome == key_outcome
            && coverage == key_coverage
            && reason == key_reason
            && ancestry_basis == key_basis =>
        {
            PolicyQueryResultRef::PythonHierarchyFact {
                id,
                root_id,
                declaration_id,
                owner_id,
                target_id,
                target_owner_id,
                fact_kind,
                outcome,
                coverage,
                reason,
                ancestry_basis,
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
            }
        }
        (
            UnitRowItemRefValue::CallableSignature {
                id,
                declaration_id,
                site_id,
                range,
                ..
            },
            DetailedCodeQueryDomain::CallableSignature,
            DetailedCodeQueryKey::CallableSignature {
                id: detailed_id,
                declaration_id: detailed_declaration_id,
                site_id: detailed_site_id,
            },
            UnitRowIdentities::None,
        ) if value_kind.as_ref() == "callable_signature"
            && id.as_ref() == detailed_id.as_str()
            && declaration_id.as_deref() == Some(detailed_declaration_id.as_str())
            && site_id.as_ref() == detailed_site_id.as_str()
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::StructuralMatch {
                kind: "callable_signature".to_owned(),
                location: policy_span_location(path, byte_span.as_ref().ok_or(())?, range)?,
                identity: None,
            }
        }
        (
            UnitRowItemRefValue::SignatureParameter {
                id,
                signature_id,
                range,
                ..
            },
            DetailedCodeQueryDomain::SignatureParameter,
            DetailedCodeQueryKey::SignatureParameter {
                id: detailed_id,
                signature_id: detailed_signature_id,
            },
            UnitRowIdentities::None,
        ) if value_kind.as_ref() == "signature_parameter"
            && id.as_ref() == detailed_id.as_str()
            && signature_id.as_ref() == detailed_signature_id.as_str()
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::StructuralMatch {
                kind: "signature_parameter".to_owned(),
                location: policy_span_location(path, byte_span.as_ref().ok_or(())?, range)?,
                identity: None,
            }
        }
        (
            UnitRowItemRefValue::DecoratedParameter {
                id,
                parameter_id,
                range,
            },
            DetailedCodeQueryDomain::DecoratedParameter,
            DetailedCodeQueryKey::DecoratedParameter {
                id: detailed_id,
                parameter_id: detailed_parameter_id,
            },
            UnitRowIdentities::None,
        ) if id.as_ref() == detailed_id.as_str()
            && parameter_id.as_ref() == detailed_parameter_id.as_str()
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::StructuralMatch {
                kind: "parameter".to_owned(),
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                identity: None,
            }
        }
        (
            UnitRowItemRefValue::StructuralMatch {
                kind,
                node_range: Some(range),
            },
            DetailedCodeQueryDomain::CppExpression,
            DetailedCodeQueryKey::CppExpression { .. },
            UnitRowIdentities::None,
        ) if Some(range) == display_range => PolicyQueryResultRef::StructuralMatch {
            kind: kind.to_string(),
            location: policy_span_location(
                path,
                byte_span.as_ref().ok_or(())?,
                display_range.ok_or(())?,
            )?,
            identity: None,
        },
        (
            UnitRowItemRefValue::Declaration {
                kind,
                fq_name,
                node_range: Some(range),
            },
            DetailedCodeQueryDomain::Declaration,
            DetailedCodeQueryKey::Declaration {
                kind: detailed_kind,
                fq_name: detailed_fq_name,
                ..
            },
            UnitRowIdentities::Primary(identity),
        ) if kind.as_ref() == detailed_kind.as_str()
            && fq_name.as_ref() == detailed_fq_name.as_str()
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
            UnitRowItemRefValue::File,
            DetailedCodeQueryDomain::File,
            DetailedCodeQueryKey::File,
            UnitRowIdentities::None,
        ) if byte_span.is_none() && display_range.is_none() => PolicyQueryResultRef::file(path),
        (
            UnitRowItemRefValue::GenerationSite {
                id,
                ast_id,
                kind,
                range,
            },
            DetailedCodeQueryDomain::GenerationSite,
            DetailedCodeQueryKey::GenerationSite {
                id: detailed_id,
                ast_id: detailed_ast_id,
                kind: detailed_kind,
            },
            UnitRowIdentities::None,
        ) if id.as_ref() == detailed_id.as_str()
            && ast_id.as_deref() == detailed_ast_id.as_deref()
            && kind.as_ref() == detailed_kind.as_str()
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::GenerationSite {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                id: detailed_id,
                ast_id: detailed_ast_id,
                kind: detailed_kind,
            }
        }
        (
            UnitRowItemRefValue::ReferenceSite {
                range,
                target_fq_name,
                usage_kind,
                proof,
            },
            DetailedCodeQueryDomain::ReferenceSite,
            DetailedCodeQueryKey::ReferenceSite {
                target_fq_name: detailed_target,
                ..
            },
            UnitRowIdentities::ReferenceTarget(target_identity),
        ) if target_fq_name.as_ref() == detailed_target.as_str()
            && Some(range) == display_range =>
        {
            let target_identity = validated_provenance_identity(target_identity.as_ref());
            identity_uncertain = &*proof == "proven" && target_identity.is_none();
            PolicyQueryResultRef::ReferenceSite {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                target_fq_name: detailed_target,
                target_identity,
                usage_kind: usage_kind.map(|kind| kind.to_string()),
                proof: if identity_uncertain {
                    PolicyQueryProof::NameBased
                } else {
                    policy_query_proof(&proof)
                },
            }
        }
        (
            UnitRowItemRefValue::CallSite {
                range,
                caller_fq_name,
                callee_fq_name,
                proof,
            },
            DetailedCodeQueryDomain::CallSite,
            DetailedCodeQueryKey::CallSite {
                caller_fq_name: detailed_caller,
                callee_fq_name: detailed_callee,
                ..
            },
            UnitRowIdentities::Call { caller, callee },
        ) if caller_fq_name.as_ref() == detailed_caller.as_str()
            && callee_fq_name.as_ref() == detailed_callee.as_str()
            && Some(range) == display_range =>
        {
            let caller_identity = validated_provenance_identity(caller.as_ref());
            let callee_identity = validated_provenance_identity(callee.as_ref());
            identity_uncertain =
                &*proof == "proven" && (caller_identity.is_none() || callee_identity.is_none());
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
                    policy_query_proof(&proof)
                },
            }
        }
        (
            UnitRowItemRefValue::ExpressionSite {
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
            UnitRowIdentities::None,
        ) if input_kind.as_ref() == detailed_input.as_str()
            && parameter_index.and_then(|index| u32::try_from(index).ok()) == detailed_index
            && parameter_name.as_deref() == detailed_name.as_deref()
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
            UnitRowItemRefValue::JsxAttributeValue {
                id,
                ast_id,
                range,
                element_identity,
                coverage,
            },
            DetailedCodeQueryDomain::JsxAttributeValue,
            DetailedCodeQueryKey::JsxAttributeValue {
                id: detailed_id,
                ast_id: detailed_ast_id,
            },
            UnitRowIdentities::Primary(_),
        ) if id.as_ref() == detailed_id.as_str()
            && ast_id.as_ref() == detailed_ast_id.as_str()
            && Some(range) == display_range =>
        {
            identity_uncertain = &*coverage != "complete";
            PolicyQueryResultRef::JsxAttributeValue {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                ast_id: detailed_ast_id,
                element_identity: element_identity.to_string(),
                coverage: coverage.to_string(),
            }
        }
        (
            UnitRowItemRefValue::MemberTargetAnalysis {
                site_id,
                receiver_range,
                outcome,
                coverage,
                capture,
            },
            DetailedCodeQueryDomain::MemberTargetAnalysis,
            DetailedCodeQueryKey::MemberTargetAnalysis {
                site_id: detailed_site_id,
            },
            UnitRowIdentities::None,
        ) if site_id.as_ref() == detailed_site_id.as_str()
            && Some(receiver_range) == display_range =>
        {
            PolicyQueryResultRef::MemberTargetAnalysis {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                outcome: outcome.to_string(),
                coverage: coverage.to_string(),
                capture: capture.map(|capture| capture.to_string()),
            }
        }
        (
            UnitRowItemRefValue::FieldWriteValue {
                id,
                assignment_ast_id,
                rhs_ast_id,
                receiver_identity_id,
                member_target_id,
                range,
                proof,
                completeness,
                coverage,
            },
            DetailedCodeQueryDomain::FieldWriteValue,
            DetailedCodeQueryKey::FieldWriteValue {
                id: detailed_id,
                assignment_ast_id: detailed_assignment_ast_id,
                rhs_ast_id: detailed_rhs_ast_id,
                receiver_identity_id: detailed_receiver_identity_id,
                member_target_id: detailed_member_target_id,
            },
            UnitRowIdentities::Primary(_),
        ) if id.as_ref() == detailed_id.as_str()
            && assignment_ast_id.as_ref() == detailed_assignment_ast_id.as_str()
            && rhs_ast_id.as_ref() == detailed_rhs_ast_id.as_str()
            && receiver_identity_id.as_ref() == detailed_receiver_identity_id.as_str()
            && member_target_id.as_ref() == detailed_member_target_id.as_str()
            && &*proof == "precise"
            && &*completeness == "complete"
            && &*coverage == "exhaustive"
            && Some(range) == display_range =>
        {
            PolicyQueryResultRef::FieldWriteValue {
                location: policy_span_location(
                    path,
                    byte_span.as_ref().ok_or(())?,
                    display_range.ok_or(())?,
                )?,
                assignment_ast_id: assignment_ast_id.to_string(),
                rhs_ast_id: rhs_ast_id.to_string(),
                receiver_identity_id: receiver_identity_id.to_string(),
                member_target_id: member_target_id.to_string(),
                proof: proof.to_string(),
                completeness: completeness.to_string(),
                coverage: coverage.to_string(),
            }
        }
        (
            UnitRowItemRefValue::ReceiverAnalysis {
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
            UnitRowIdentities::None,
        ) if analysis_kind.as_ref() == detailed_analysis.as_str()
            && outcome.as_ref() == detailed_outcome.as_str()
            && capture.as_deref() == detailed_capture.as_deref()
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
        // Dispatch targets are exact semantic rows used to select a call,
        // but the policy finding envelope has no target-row variant. Keep
        // the exact source position in provenance without downgrading the
        // enclosing declaration finding: the target identity was already
        // validated by the structural filter that produced this row.
        (
            UnitRowItemRefValue::Unsupported,
            DetailedCodeQueryDomain::DispatchTarget,
            DetailedCodeQueryKey::DispatchTarget { .. },
            UnitRowIdentities::None,
        ) => PolicyQueryResultRef::Unsupported {
            query_result_kind: "dispatch_target".to_owned(),
            location: Some(policy_span_location(
                path,
                byte_span.as_ref().ok_or(())?,
                display_range.ok_or(())?,
            )?),
        },
        _ => return Err(()),
    };
    Ok((adapted, provenance_partial, identity_uncertain))
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
    candidate: Option<&UnitRowIdentityCandidate>,
) -> Option<StableSemanticIdentity> {
    let candidate = candidate?;
    let path = workspace_relative_path(&candidate.rel_path).ok()?;
    let identity = match &candidate.candidate {
        CodeQueryStableOwnerCandidate::Declaration { namespace, id } => {
            StableSemanticIdentity::analyzer_declaration_id(namespace, path, id)
        }
        CodeQueryStableOwnerCandidate::Derived {
            namespace,
            derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
            semantic_key,
        } => StableSemanticIdentity::canonical_ast_identity(namespace, path, semantic_key),
        CodeQueryStableOwnerCandidate::Derived {
            derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
            ..
        } => return None,
    };
    identity.ok()
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
        DetailedCodeQueryDomain::JsxAttributeValue => Some(MatchResultDomain::JsxAttributeValue),
        DetailedCodeQueryDomain::FieldWriteValue => Some(MatchResultDomain::FieldWriteValue),
        // Runtime keyed reads are exact source-position rows. Match policies
        // use the existing structural finding envelope while selector policies
        // retain the typed endpoint evidence for taint binding.
        DetailedCodeQueryDomain::RuntimeKeyedReadValue => Some(MatchResultDomain::StructuralMatch),
        // Python rule facts are exact source rows. Their policy finding uses
        // the structural source envelope; selector adaptation retains the
        // typed proof and completeness columns.
        DetailedCodeQueryDomain::PythonRuleFact => Some(MatchResultDomain::StructuralMatch),
        DetailedCodeQueryDomain::RustMarkerImpl => Some(MatchResultDomain::StructuralMatch),
        DetailedCodeQueryDomain::RustPointerFinding => Some(MatchResultDomain::StructuralMatch),
        DetailedCodeQueryDomain::File => Some(MatchResultDomain::File),
        DetailedCodeQueryDomain::Occurrence => Some(MatchResultDomain::Occurrence),
        DetailedCodeQueryDomain::LexicalScope => Some(MatchResultDomain::LexicalScope),
        DetailedCodeQueryDomain::Binding => Some(MatchResultDomain::Binding),
        DetailedCodeQueryDomain::ResolutionCandidate => {
            Some(MatchResultDomain::ResolutionCandidate)
        }
        DetailedCodeQueryDomain::GenerationSite => Some(MatchResultDomain::GenerationSite),
        DetailedCodeQueryDomain::Export => Some(MatchResultDomain::Export),
        DetailedCodeQueryDomain::DeclarationState => Some(MatchResultDomain::DeclarationState),
        // Authored configuration facts are exact parser rows anchored at their
        // own workspace path and byte span. They are parser evidence, not
        // semantic resolution, so they keep a dedicated result domain instead
        // of borrowing a structural one.
        DetailedCodeQueryDomain::DependencyEvidence => Some(MatchResultDomain::DependencyEvidence),
        DetailedCodeQueryDomain::ConfigurationFact => Some(MatchResultDomain::ConfigurationFact),
        // A cross-domain row is anchored at an exact position and carries
        // both input identities, so it keeps its own result domain (#3284).
        DetailedCodeQueryDomain::CrossDomain => Some(MatchResultDomain::CrossDomain),
        DetailedCodeQueryDomain::ReferenceEdge => Some(MatchResultDomain::ReferenceEdge),
        DetailedCodeQueryDomain::QualifiedPath => Some(MatchResultDomain::QualifiedPath),
        DetailedCodeQueryDomain::PathSegment => Some(MatchResultDomain::PathSegment),
        // DecoratedParameter is a typed structural projection anchored at its
        // parameter node. Policy findings retain the existing structural
        // terminal shape so matched-value can bind the exact source span.
        DetailedCodeQueryDomain::DecoratedParameter => Some(MatchResultDomain::StructuralMatch),
        // Callable metrics are exact source-position rows when coverage is
        // exact; incomplete and unrecorded rows remain visible to the
        // selector-quality and query-completion paths.
        DetailedCodeQueryDomain::CallableMetrics => Some(MatchResultDomain::StructuralMatch),
        DetailedCodeQueryDomain::CppExpression => Some(MatchResultDomain::StructuralMatch),
        // This query-local source row is an exact anchor, but the policy
        // finding envelope remains the existing structural source shape.
        DetailedCodeQueryDomain::LiteralOccurrence => Some(MatchResultDomain::StructuralMatch),
        DetailedCodeQueryDomain::StateEvent
        | DetailedCodeQueryDomain::FlowRelation
        | DetailedCodeQueryDomain::ControlRelation
        | DetailedCodeQueryDomain::BranchRelation
        | DetailedCodeQueryDomain::LoopRelation
        | DetailedCodeQueryDomain::FailureHandlerState
        | DetailedCodeQueryDomain::StatementReachability
        | DetailedCodeQueryDomain::PendingCleanupFlow
        | DetailedCodeQueryDomain::Guard
        | DetailedCodeQueryDomain::SourceSet
        | DetailedCodeQueryDomain::BuildTarget
        | DetailedCodeQueryDomain::TopologyEdge
        | DetailedCodeQueryDomain::RewritePath
        | DetailedCodeQueryDomain::Procedure
        | DetailedCodeQueryDomain::ProgramPoint
        | DetailedCodeQueryDomain::ControlEdge
        | DetailedCodeQueryDomain::TypestateFinding
        | DetailedCodeQueryDomain::TypestateWitness
        | DetailedCodeQueryDomain::FlowEndpoint
        | DetailedCodeQueryDomain::FlowWitness
        | DetailedCodeQueryDomain::TaintFinding
        | DetailedCodeQueryDomain::ReceiverAnalysis
        | DetailedCodeQueryDomain::MemberTargetAnalysis
        | DetailedCodeQueryDomain::ReceiverOutcome
        | DetailedCodeQueryDomain::ReceiverEvidence
        | DetailedCodeQueryDomain::PointsToCandidate
        | DetailedCodeQueryDomain::CallShape
        | DetailedCodeQueryDomain::CallResult
        | DetailedCodeQueryDomain::CallArgumentGroup
        | DetailedCodeQueryDomain::CallArgument
        | DetailedCodeQueryDomain::CallBinding
        | DetailedCodeQueryDomain::CallEffect
        | DetailedCodeQueryDomain::CallResultContract
        | DetailedCodeQueryDomain::CallResultObligation
        | DetailedCodeQueryDomain::ResultContractUse
        | DetailedCodeQueryDomain::ResultContractFailureUse
        | DetailedCodeQueryDomain::ResultSubjectUse
        | DetailedCodeQueryDomain::NilnessOperation
        | DetailedCodeQueryDomain::SwitchCoverage
        | DetailedCodeQueryDomain::AssignmentRelation
        | DetailedCodeQueryDomain::ClassSetRow
        | DetailedCodeQueryDomain::AbsentMemberFinding
        | DetailedCodeQueryDomain::AbsentMemberWitness
        | DetailedCodeQueryDomain::DetachedTaskTransfer
        | DetailedCodeQueryDomain::ProcedureEffect
        | DetailedCodeQueryDomain::CallableSignature
        | DetailedCodeQueryDomain::SignatureParameter
        | DetailedCodeQueryDomain::CallableApplicability
        | DetailedCodeQueryDomain::OverloadSelection
        | DetailedCodeQueryDomain::MemberSelection
        | DetailedCodeQueryDomain::CandidateHop
        | DetailedCodeQueryDomain::DispatchOutcome
        | DetailedCodeQueryDomain::DispatchTarget
        | DetailedCodeQueryDomain::MemberFamily
        | DetailedCodeQueryDomain::MemberFamilyEdge
        | DetailedCodeQueryDomain::BindingInitializerCall => None,
        DetailedCodeQueryDomain::PythonHierarchyFact => Some(MatchResultDomain::StructuralMatch),
    }
}

/// The opaque identity of a finding with no strong anchor.
///
/// `path` is the normalized workspace-relative spelling the adapter already
/// derived, not a second rendering of the evidence file: a unit produced at
/// one workspace root is adapted at another, so the one spelling that is the
/// same in both is the only sound input to a pinned finding identity.
fn weak_finding_key(evidence: &UnitRowEvidence, path: &WorkspaceRelativePath) -> OpaqueFindingKey {
    let mut hasher = Sha256::new();
    update_hash(&mut hasher, WEAK_KEY_DOMAIN);
    // The registry's own label, never a second copy of it: this byte
    // sequence is inside a pinned finding identity, so a divergent
    // duplicate would silently change every finding id (issue #2498).
    update_hash(&mut hasher, evidence.domain.label().as_bytes());
    update_hash(&mut hasher, path.as_str().as_bytes());
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
        DetailedCodeQueryKey::Procedure { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::TaintFinding { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::JsxAttributeValue { id, ast_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, ast_id.as_bytes());
        }
        DetailedCodeQueryKey::FieldWriteValue {
            id,
            assignment_ast_id,
            rhs_ast_id,
            receiver_identity_id,
            member_target_id,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, assignment_ast_id.as_bytes());
            update_hash(&mut hasher, rhs_ast_id.as_bytes());
            update_hash(&mut hasher, receiver_identity_id.as_bytes());
            update_hash(&mut hasher, member_target_id.as_bytes());
        }
        DetailedCodeQueryKey::RuntimeKeyedReadValue { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::PythonRuleFact { id, relation } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, relation.as_bytes());
        }
        DetailedCodeQueryKey::RustMarkerImpl { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::RustPointerFinding { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::DependencyEvidence { id, .. } => {
            update_hash(&mut hasher, id.as_bytes())
        }
        DetailedCodeQueryKey::ConfigurationFact { id, fact_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, fact_id.as_bytes());
        }
        DetailedCodeQueryKey::CrossDomain {
            id,
            code_id,
            configuration_id,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, code_id.as_deref());
            update_optional_hash(&mut hasher, configuration_id.as_deref());
        }
        DetailedCodeQueryKey::ProgramPoint { id, procedure_id }
        | DetailedCodeQueryKey::ControlEdge { id, procedure_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, procedure_id.as_bytes());
        }
        DetailedCodeQueryKey::TypestateFinding { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::TypestateWitness { id, finding_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, finding_id.as_bytes());
        }
        DetailedCodeQueryKey::FlowEndpoint { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::FlowWitness { id, endpoint_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, endpoint_id.as_bytes());
        }
        DetailedCodeQueryKey::PointsToCandidate { id, site_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::File => {}
        DetailedCodeQueryKey::Occurrence { id, ast_id, role } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, ast_id.as_bytes());
            update_hash(&mut hasher, role.as_bytes());
        }
        DetailedCodeQueryKey::LexicalScope { id, ast_id, index } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, ast_id.as_deref());
            update_hash(&mut hasher, &index.to_be_bytes());
        }
        DetailedCodeQueryKey::Binding { id, ast_id, name } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, ast_id.as_deref());
            update_hash(&mut hasher, name.as_bytes());
        }
        DetailedCodeQueryKey::ResolutionCandidate {
            id,
            ast_id,
            ordinal,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, ast_id.as_bytes());
            update_hash(&mut hasher, &ordinal.to_be_bytes());
        }
        DetailedCodeQueryKey::GenerationSite { id, ast_id, kind } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, ast_id.as_deref());
            update_hash(&mut hasher, kind.as_bytes());
        }
        DetailedCodeQueryKey::Export {
            id,
            form,
            exported_name,
            local_definition,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, form.as_bytes());
            update_hash(&mut hasher, exported_name.as_bytes());
            match local_definition {
                None => update_hash(&mut hasher, b"no_local_definition"),
                Some(DetailedCodeQueryExportLocalDefinition::Undefined) => {
                    update_hash(&mut hasher, b"undefined")
                }
                Some(DetailedCodeQueryExportLocalDefinition::Unknown) => {
                    update_hash(&mut hasher, b"unknown")
                }
                Some(DetailedCodeQueryExportLocalDefinition::Defined {
                    binding_name,
                    binding_kind,
                    start_byte,
                    end_byte,
                    range,
                }) => {
                    update_hash(&mut hasher, b"defined");
                    update_hash(&mut hasher, binding_name.as_bytes());
                    update_hash(&mut hasher, binding_kind.as_bytes());
                    update_hash(&mut hasher, &start_byte.to_be_bytes());
                    update_hash(&mut hasher, &end_byte.to_be_bytes());
                    update_hash(&mut hasher, &range.start_line.to_be_bytes());
                    update_hash(&mut hasher, &range.start_column.to_be_bytes());
                    update_hash(&mut hasher, &range.end_line.to_be_bytes());
                    update_hash(&mut hasher, &range.end_column.to_be_bytes());
                }
            }
        }
        DetailedCodeQueryKey::DeclarationState {
            id,
            fq_name,
            origin,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, fq_name.as_bytes());
            update_hash(&mut hasher, origin.as_bytes());
        }
        DetailedCodeQueryKey::ReferenceEdge {
            id,
            ast_id,
            target_fq_name,
            provenance,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, ast_id.as_deref());
            update_hash(&mut hasher, target_fq_name.as_bytes());
            update_hash(&mut hasher, provenance.as_bytes());
        }
        DetailedCodeQueryKey::StateEvent {
            id,
            ast_id,
            procedure_id,
            event_class,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, ast_id.as_deref());
            update_hash(&mut hasher, procedure_id.as_bytes());
            update_hash(&mut hasher, event_class.as_bytes());
        }
        DetailedCodeQueryKey::FlowRelation {
            id,
            procedure_id,
            relation,
            certainty,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, procedure_id.as_bytes());
            update_hash(&mut hasher, relation.as_bytes());
            update_hash(&mut hasher, certainty.as_bytes());
        }
        DetailedCodeQueryKey::ControlRelation {
            id,
            procedure_id,
            relation,
            certainty,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, procedure_id.as_bytes());
            update_hash(&mut hasher, relation.as_bytes());
            update_hash(&mut hasher, certainty.as_bytes());
        }
        DetailedCodeQueryKey::BranchRelation {
            id,
            owner_id,
            relation,
            verdict,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, owner_id.as_bytes());
            update_hash(&mut hasher, relation.as_bytes());
            update_hash(&mut hasher, verdict.as_bytes());
        }
        DetailedCodeQueryKey::FailureHandlerState {
            id,
            catch_ast_id,
            verdict,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, catch_ast_id.as_bytes());
            update_hash(&mut hasher, verdict.as_bytes());
        }
        DetailedCodeQueryKey::Guard {
            id,
            procedure_id,
            point_id,
            predicate,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, procedure_id.as_bytes());
            update_hash(&mut hasher, point_id.as_bytes());
            update_hash(&mut hasher, predicate.as_bytes());
        }
        DetailedCodeQueryKey::SourceSet { id, name }
        | DetailedCodeQueryKey::BuildTarget { id, name } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, name.as_bytes());
        }
        DetailedCodeQueryKey::TopologyEdge {
            id,
            from_name,
            to_name,
            scope,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, from_name.as_bytes());
            update_hash(&mut hasher, to_name.as_bytes());
            update_hash(&mut hasher, scope.as_bytes());
        }
        DetailedCodeQueryKey::RewritePath {
            id,
            domain,
            origin_specifier,
            outcome,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, domain.as_bytes());
            update_hash(&mut hasher, origin_specifier.as_bytes());
            update_hash(&mut hasher, outcome.as_bytes());
        }
        DetailedCodeQueryKey::QualifiedPath { id, ast_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, ast_id.as_bytes());
        }
        DetailedCodeQueryKey::PathSegment {
            id,
            ast_id,
            ordinal,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, ast_id.as_deref());
            update_hash(&mut hasher, &ordinal.to_be_bytes());
        }
        DetailedCodeQueryKey::ReferenceSite {
            target_id,
            target_fq_name,
        } => {
            update_optional_hash(&mut hasher, target_id.as_deref());
            update_hash(&mut hasher, target_fq_name.as_bytes());
        }
        DetailedCodeQueryKey::CallSite {
            site_id,
            caller_fq_name,
            callee_fq_name,
        } => {
            update_optional_hash(&mut hasher, site_id.as_deref());
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
        DetailedCodeQueryKey::MemberTargetAnalysis { site_id } => {
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::ReceiverOutcome { id, site_id }
        | DetailedCodeQueryKey::ReceiverEvidence { id, site_id }
        | DetailedCodeQueryKey::CallShape { id, site_id }
        | DetailedCodeQueryKey::CallResult { id, site_id }
        | DetailedCodeQueryKey::CallArgumentGroup { id, site_id }
        | DetailedCodeQueryKey::CallBinding { id, site_id }
        | DetailedCodeQueryKey::CallEffect { id, site_id }
        | DetailedCodeQueryKey::CallResultContract { id, site_id }
        | DetailedCodeQueryKey::CallResultObligation { id, site_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::ResultContractUse { id, acquisition_id }
        | DetailedCodeQueryKey::ResultContractFailureUse { id, acquisition_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, acquisition_id.as_bytes());
        }
        DetailedCodeQueryKey::NilnessOperation { id, procedure_id }
        | DetailedCodeQueryKey::SwitchCoverage { id, procedure_id }
        | DetailedCodeQueryKey::AssignmentRelation { id, procedure_id }
        | DetailedCodeQueryKey::LoopRelation { id, procedure_id }
        | DetailedCodeQueryKey::StatementReachability { id, procedure_id }
        | DetailedCodeQueryKey::PendingCleanupFlow { id, procedure_id }
        | DetailedCodeQueryKey::DetachedTaskTransfer { id, procedure_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, procedure_id.as_bytes());
        }
        DetailedCodeQueryKey::ClassSetRow { id }
        | DetailedCodeQueryKey::ResultSubjectUse { id }
        | DetailedCodeQueryKey::AbsentMemberFinding { id }
        | DetailedCodeQueryKey::CppExpression { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::AbsentMemberWitness { id, finding_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, finding_id.as_bytes());
        }
        DetailedCodeQueryKey::BindingInitializerCall {
            id,
            establishment_event_id,
            site_ast_id,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, establishment_event_id.as_bytes());
            update_hash(&mut hasher, site_ast_id.as_bytes());
        }
        DetailedCodeQueryKey::ProcedureEffect {
            id,
            procedure_id,
            site_id,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, procedure_id.as_bytes());
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::CallableApplicability { id, site_ast_id }
        | DetailedCodeQueryKey::OverloadSelection { id, site_ast_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, site_ast_id.as_bytes());
        }
        DetailedCodeQueryKey::CallableSignature {
            id,
            declaration_id,
            site_id,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, declaration_id.as_bytes());
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::LiteralOccurrence { id } => {
            update_hash(&mut hasher, id.as_bytes());
        }
        DetailedCodeQueryKey::CallableMetrics {
            id,
            callable_id,
            site_id,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_optional_hash(&mut hasher, callable_id.as_deref());
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::SignatureParameter { id, signature_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, signature_id.as_bytes());
        }
        DetailedCodeQueryKey::DecoratedParameter { id, parameter_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, parameter_id.as_bytes());
        }
        DetailedCodeQueryKey::CallArgument { id, group_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, group_id.as_bytes());
        }
        DetailedCodeQueryKey::MemberSelection { id, site_ast_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, site_ast_id.as_bytes());
        }
        DetailedCodeQueryKey::CandidateHop {
            id,
            candidate_id,
            hop,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, candidate_id.as_bytes());
            update_hash(&mut hasher, &hop.to_le_bytes());
        }
        DetailedCodeQueryKey::DispatchOutcome { id, site_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, site_id.as_bytes());
        }
        DetailedCodeQueryKey::DispatchTarget {
            id,
            site_id,
            ordinal,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, site_id.as_bytes());
            update_hash(&mut hasher, &ordinal.to_le_bytes());
        }
        DetailedCodeQueryKey::MemberFamily { id, member_id } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, member_id.as_bytes());
        }
        DetailedCodeQueryKey::MemberFamilyEdge {
            id,
            member_id,
            ordinal,
        } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, member_id.as_bytes());
            update_hash(&mut hasher, &ordinal.to_le_bytes());
        }
        DetailedCodeQueryKey::PythonHierarchyFact { id, root_id, .. } => {
            update_hash(&mut hasher, id.as_bytes());
            update_hash(&mut hasher, root_id.as_bytes());
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

fn update_optional_hash(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            update_hash(hasher, b"some");
            update_hash(hasher, value.as_bytes());
        }
        None => update_hash(hasher, b"none"),
    }
}

fn certainty_reasons(
    diagnostics: &[CodeQueryDiagnostic],
    provenance: &[UnitRowProvenance],
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

pub(super) fn incomplete_reasons(
    completion: &CodeQueryCompletion,
    truncated: bool,
) -> Vec<PolicyIncompleteReason> {
    let mut reasons = match completion {
        CodeQueryCompletion::Incomplete { codes } => {
            codes.iter().map(incomplete_reason_for_code).collect()
        }
        CodeQueryCompletion::Cancelled => vec![PolicyIncompleteReason::Cancelled],
        CodeQueryCompletion::Complete
        | CodeQueryCompletion::ProvenSubset { .. }
        | CodeQueryCompletion::Invalid { .. } => Vec::new(),
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
        | CodeQueryCompletion::ProvenSubset { .. }
        | CodeQueryCompletion::Incomplete { .. }
        | CodeQueryCompletion::Cancelled => Vec::new(),
    }
}

pub(super) fn incomplete_reason_for_code(code: &CodeQueryDiagnosticCode) -> PolicyIncompleteReason {
    match code {
        CodeQueryDiagnosticCode::Cancelled => PolicyIncompleteReason::Cancelled,
        CodeQueryDiagnosticCode::UnsupportedStructuralFeature
        | CodeQueryDiagnosticCode::MissingStructuralAdapter
        | CodeQueryDiagnosticCode::UnsupportedImportAnalysis
        | CodeQueryDiagnosticCode::DynamicImportTarget
        | CodeQueryDiagnosticCode::SemanticWorkspaceRequired
        | CodeQueryDiagnosticCode::SemanticCapabilityUnsupported
        | CodeQueryDiagnosticCode::TypestateCapabilityUnsupported
        | CodeQueryDiagnosticCode::ValueFlowCapabilityUnsupported
        | CodeQueryDiagnosticCode::ReceiverAnalysisPartial
        | CodeQueryDiagnosticCode::UsesParserUnsupported
        | CodeQueryDiagnosticCode::OccurrenceRoleUnsupported
        | CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete
        | CodeQueryDiagnosticCode::EnvironmentAxisUnsupported
        | CodeQueryDiagnosticCode::EnvironmentDerivationIncomplete
        | CodeQueryDiagnosticCode::MaterializationAxisUnsupported
        | CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
        | CodeQueryDiagnosticCode::ResolutionTraceIncomplete
        | CodeQueryDiagnosticCode::PythonHierarchyDerivationIncomplete
        | CodeQueryDiagnosticCode::EdgeAxisUnsupported
        | CodeQueryDiagnosticCode::EdgeDerivationIncomplete
        | CodeQueryDiagnosticCode::FlowStateAxisUnsupported
        | CodeQueryDiagnosticCode::FlowStateDerivationIncomplete
        | CodeQueryDiagnosticCode::RewriteDomainUnsupported
        | CodeQueryDiagnosticCode::RewritePathDerivationIncomplete
        | CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete
        | CodeQueryDiagnosticCode::BranchRelationDerivationIncomplete
        // Syntax recovery may have removed a selected node, and no budget
        // recovers a node the parse never produced (#3777).
        | CodeQueryDiagnosticCode::RecoveredSyntaxIncomplete
        | CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete
        | CodeQueryDiagnosticCode::FailureHandlerDerivationIncomplete
        | CodeQueryDiagnosticCode::StatementReachabilityDerivationIncomplete
        | CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
        | CodeQueryDiagnosticCode::ControlRelationExitPartitionPartial
        // The build model behind a topology row could not be read in full, or
        // no provider answers the axis at all. Either way the absence of a row
        // is not evidence of an absent declaration (#2448).
        | CodeQueryDiagnosticCode::TopologyDerivationIncomplete
        | CodeQueryDiagnosticCode::TopologyOwnershipAmbiguous
        // A cross-domain binding the resolver did not prove, or a key
        // expression with no structured decoder, hides a correlation that no
        // larger budget would recover (#3284).
        | CodeQueryDiagnosticCode::CrossDomainBindingUnproven
        | CodeQueryDiagnosticCode::CrossDomainKeyUnsupported
        | CodeQueryDiagnosticCode::IdentityAxisUnsupported
        | CodeQueryDiagnosticCode::PathDerivationIncomplete
        // An effect derivation that could not establish every callee is a
        // capability gap, not a budget one: the missing fact is a model or a
        // resolution, and no larger bound would recover it (#2437).
        | CodeQueryDiagnosticCode::EffectDerivationIncomplete
        // A call shape the language's lowering could not read suppresses every
        // row family derived from it -- argument groups, arguments, bindings.
        // No larger budget recovers those rows, so the gap is a capability one,
        // and it is the same reason a plan that binds the shape row itself
        // already reports (#1949).
        | CodeQueryDiagnosticCode::CallShapeCoverageIncomplete
        | CodeQueryDiagnosticCode::ResultContractDerivationIncomplete
        | CodeQueryDiagnosticCode::ResultObligationDerivationIncomplete => {
            PolicyIncompleteReason::CapabilityIncomplete
        }
        CodeQueryDiagnosticCode::OccurrenceRowBudgetExhausted
        | CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted
        | CodeQueryDiagnosticCode::MaterializationRowBudgetExhausted
        | CodeQueryDiagnosticCode::EffectBudgetExhausted => {
            PolicyIncompleteReason::PipelineRowBudget
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
        | CodeQueryDiagnosticCode::SemanticAnalysisPartial
        | CodeQueryDiagnosticCode::CallBindingDispatchPartial
        | CodeQueryDiagnosticCode::CallBindingSelectorRejected
        | CodeQueryDiagnosticCode::SemanticBudgetExhausted
        | CodeQueryDiagnosticCode::SemanticProviderFailed
        | CodeQueryDiagnosticCode::SemanticPackAcquisitionPending
        | CodeQueryDiagnosticCode::UnresolvedProtocolReference
        | CodeQueryDiagnosticCode::TypestateRegistrationStale
        | CodeQueryDiagnosticCode::TypestateHandleStale
        | CodeQueryDiagnosticCode::TypestateRootMismatch
        | CodeQueryDiagnosticCode::TypestateAnalysisPartial
        | CodeQueryDiagnosticCode::TypestateProviderFailed
        | CodeQueryDiagnosticCode::TypestateSolverBudgetExhausted
        | CodeQueryDiagnosticCode::TypestateFindingBudgetExhausted
        | CodeQueryDiagnosticCode::TypestateWitnessTruncated
        | CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference
        | CodeQueryDiagnosticCode::ValueFlowRegistrationStale
        | CodeQueryDiagnosticCode::ValueFlowHandleStale
        | CodeQueryDiagnosticCode::ValueFlowRootMismatch
        | CodeQueryDiagnosticCode::ValueFlowAnalysisPartial
        | CodeQueryDiagnosticCode::ValueFlowProviderFailed
        | CodeQueryDiagnosticCode::ValueFlowSolverBudgetExhausted
        | CodeQueryDiagnosticCode::ValueFlowWitnessTruncated
        | CodeQueryDiagnosticCode::TypeFlowWitnessTruncated
        | CodeQueryDiagnosticCode::TypeFlowWitnessUnavailable
        | CodeQueryDiagnosticCode::UnresolvedTaintResultReference
        | CodeQueryDiagnosticCode::TaintRegistrationStale
        | CodeQueryDiagnosticCode::TaintHandleStale
        | CodeQueryDiagnosticCode::TaintRootMismatch
        | CodeQueryDiagnosticCode::TaintPlanReportMismatch
        | CodeQueryDiagnosticCode::TaintProjectionFailed
        | CodeQueryDiagnosticCode::TaintFindingTruncated
        | CodeQueryDiagnosticCode::NoEnclosingProcedure
        | CodeQueryDiagnosticCode::ReceiverAnalysisFailed
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
        CodeQueryDiagnosticCode::JsxProjectionIncomplete => {
            PolicyIncompleteReason::PartialDiscovery
        }
        // A declared document that was not searched, produced no facts, or
        // only partly recovered leaves the correlation's configuration side
        // undiscovered (#3284). Ambiguity is advisory and never blocks a
        // verdict, but every code needs a reason.
        CodeQueryDiagnosticCode::CrossDomainDocumentIncomplete
        | CodeQueryDiagnosticCode::CrossDomainCorrelationAmbiguous => {
            PolicyIncompleteReason::PartialDiscovery
        }
    }
}

fn adapt_query_diagnostic(
    diagnostic: &CodeQueryDiagnostic,
    max_related: usize,
) -> Result<PolicyDiagnostic, ReportValueError> {
    let (severity, impact) = match diagnostic.impact {
        CodeQueryDiagnosticImpact::Advisory => (
            PolicyDiagnosticSeverity::Note,
            PolicyDiagnosticImpact::Advisory,
        ),
        CodeQueryDiagnosticImpact::DeclaredNonExhaustive => (
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::DeclaredNonExhaustive,
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
    let primary = diagnostic
        .source
        .as_ref()
        .map(|source| {
            let path = WorkspaceRelativePath::new(&source.path)
                .map_err(|_| ReportValueError::InvalidWorkspacePath)?;
            policy_span_location(path, &(source.start_byte..source.end_byte), source.range)
                .map_err(|_| ReportValueError::ResultLocationMustHaveSpan)
        })
        .transpose()?;
    let related = diagnostic
        .related
        .iter()
        .take(max_related)
        .map(|related| {
            let source = &related.source;
            let path = WorkspaceRelativePath::new(&source.path)
                .map_err(|_| ReportValueError::InvalidWorkspacePath)?;
            let location =
                policy_span_location(path, &(source.start_byte..source.end_byte), source.range)
                    .map_err(|_| ReportValueError::ResultLocationMustHaveSpan)?;
            RelatedPolicyLocation::try_new(
                PolicyLocationRelationship::Evidence,
                location,
                Vec::new(),
            )?
            .with_label(related.label.clone())
        })
        .collect::<Result<Vec<_>, ReportValueError>>()?;
    PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::CodeQuery {
            code: diagnostic.code,
        },
        severity,
        impact,
        diagnostic.message.clone(),
        primary,
        related,
    )
}

fn internal_failure_diagnostic(message: &str) -> PolicyDiagnostic {
    // Bounded, not validated: an internal-failure explanation must never be
    // dropped for being too long (#2779).
    PolicyDiagnostic::new_bounded(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Error,
        PolicyDiagnosticImpact::RunFailed,
        message,
    )
}

fn failed_before_execution(
    reason: PolicyFailureReason,
    message: &str,
    budget: &PolicyBudget,
) -> EvaluatedMatchPolicy {
    let retain_diagnostic = budget.max_diagnostics() > 0;
    let diagnostics = if retain_diagnostic {
        vec![internal_failure_diagnostic(message)]
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
    work_report_with_metrics(
        work,
        retained_findings,
        omitted_findings_lower_bound,
        Vec::new(),
    )
}

fn work_report_with_metrics(
    work: CodeQueryExecutionWork,
    retained_findings: usize,
    omitted_findings_lower_bound: u64,
    mut metrics: Vec<PolicyWorkMetric>,
) -> PolicyWorkReport {
    super::finding::append_semantic_budget_metrics(
        &mut metrics,
        "query",
        work.semantic.cumulative,
        work.semantic.resident_peaks,
        work.semantic.root_work_peaks,
    );
    PolicyWorkReport::try_new(
        work.scanned_files,
        work.scanned_source_bytes,
        work.fact_nodes,
        work.pipeline_rows,
        work.examined_references,
        u64::try_from(retained_findings).expect("usize fits in u64 on supported targets"),
        omitted_findings_lower_bound,
        0,
        metrics,
    )
    .expect("the work metrics satisfy the work-report schema")
}

fn relational_work_report(
    work: CodeQueryExecutionWork,
    relational: super::relational::RelationalEvaluationWork,
    retained_findings: usize,
    omitted_findings_lower_bound: u64,
) -> PolicyWorkReport {
    let metrics = [
        (
            "assertion.relational_input_rows",
            PolicyWorkUnit::Rows,
            relational.input_rows,
        ),
        (
            "assertion.relational_materialized_rows",
            PolicyWorkUnit::Rows,
            relational.materialized_rows,
        ),
        (
            "assertion.relational_join_key_probes",
            PolicyWorkUnit::Count,
            relational.join_key_probes,
        ),
        (
            "assertion.relational_produced_groups",
            PolicyWorkUnit::Rows,
            relational.produced_groups,
        ),
        (
            "assertion.relational_assertion_checks",
            PolicyWorkUnit::Count,
            relational.assertion_checks,
        ),
    ]
    .into_iter()
    .map(|(name, unit, value)| {
        PolicyWorkMetric::try_new(name, unit, value)
            .expect("static relational work metric names are canonical")
    })
    .collect();
    work_report_with_metrics(
        work,
        retained_findings,
        omitted_findings_lower_bound,
        metrics,
    )
}

#[cfg(test)]
mod tests;
