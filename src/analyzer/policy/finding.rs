//! Stable schema-version-1 policy evaluation and match-evidence domain types.
//!
//! This module deliberately contains no query-to-finding conversion.  The
//! evaluator must combine a loaded policy, detailed analyzer evidence, and a
//! budget before constructing these diagnostic/report values.

use std::fmt;
use std::mem::size_of;

use serde::{Serialize, Serializer};

use crate::analyzer::semantic::WorkspaceRelativePath;
use crate::analyzer::structural::CodeQueryDiagnosticCode;

use super::budget::PolicyBudget;
use super::classification::{
    ClassificationProvenance, FindingClassification, OrganizationalRiskAssessment,
};
use super::cvss::{CvssAssessmentSet, VulnerabilityIdentity};
use super::definition::{FindingSeverity, PolicyAnalysisType, PolicyId};
use super::finding_identity::{
    EvidenceRef, FindingIdentityStability, MatchFindingAnchor, MatchResultDomain, PolicyFindingId,
    StableSemanticIdentity, WitnessId,
};
use super::future_evidence::{TaintFindingEvidence, TypestateFindingEvidence};
use super::identity::PolicySemanticHash;
use super::retained::{RetainedSize, retained_extra};

const MAX_REPORT_PROSE_BYTES: usize = 4_096;
const MAX_REPORT_IDENTIFIER_BYTES: usize = 128;
const MAX_TYPED_REASONS: usize = 256;
const MAX_QUERY_PROVENANCE: usize = 16;
const MAX_QUERY_BRANCH_DEPTH: usize = 128;
const MAX_QUERY_PROVENANCE_STEPS: usize = 1_024;
const MAX_RELATED_LOCATIONS: usize = 64;
const MAX_EVIDENCE_REFS: usize = 256;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
const MAX_WITNESS_STEPS: usize = 1_024;
const MAX_WITNESS_BYTES: u64 = 1024 * 1024;
const MAX_WORK_METRICS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRunCompletion {
    Complete,
    Inconclusive {
        reasons: Vec<PolicyIncompleteReason>,
    },
    Unsupported {
        capability: PolicyCapability,
    },
    Failed {
        reasons: Vec<PolicyFailureReason>,
    },
}

impl PolicyRunCompletion {
    pub fn inconclusive(
        mut reasons: Vec<PolicyIncompleteReason>,
    ) -> Result<Self, CompletionReasonError> {
        normalize_nonempty(&mut reasons)?;
        Ok(Self::Inconclusive { reasons })
    }

    pub fn failed(mut reasons: Vec<PolicyFailureReason>) -> Result<Self, CompletionReasonError> {
        normalize_nonempty(&mut reasons)?;
        Ok(Self::Failed { reasons })
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    fn validate(&self) -> Result<(), CompletionReasonError> {
        match self {
            Self::Complete => Ok(()),
            Self::Inconclusive { reasons } => {
                let mut normalized = reasons.clone();
                normalize_nonempty(&mut normalized)?;
                if &normalized != reasons {
                    return Err(CompletionReasonError::NonCanonical);
                }
                Ok(())
            }
            Self::Unsupported { capability } => capability.validate().map_err(Into::into),
            Self::Failed { reasons } => {
                let mut normalized = reasons.clone();
                normalize_nonempty(&mut normalized)?;
                if &normalized != reasons {
                    return Err(CompletionReasonError::NonCanonical);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyCapability {
    TaintEvaluation,
    TypestateEvaluation,
    QueryFeature { language: String, feature: String },
}

impl PolicyCapability {
    pub fn query_feature(
        language: impl Into<String>,
        feature: impl Into<String>,
    ) -> Result<Self, ReportValueError> {
        let mut language = language.into();
        let mut feature = feature.into();
        validate_report_identifier(&language)?;
        validate_report_identifier(&feature)?;
        tighten_string(&mut language);
        tighten_string(&mut feature);
        Ok(Self::QueryFeature { language, feature })
    }

    pub(crate) fn validate(&self) -> Result<(), ReportValueError> {
        if let Self::QueryFeature { language, feature } = self {
            validate_report_identifier(language)?;
            validate_report_identifier(feature)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingCertainty {
    Definite,
    Possible { reasons: Vec<CertaintyReason> },
}

impl FindingCertainty {
    pub fn possible(mut reasons: Vec<CertaintyReason>) -> Result<Self, CompletionReasonError> {
        normalize_nonempty(&mut reasons)?;
        for reason in &reasons {
            reason.validate()?;
        }
        Ok(Self::Possible { reasons })
    }

    pub fn reasons(&self) -> &[CertaintyReason] {
        match self {
            Self::Definite => &[],
            Self::Possible { reasons } => reasons,
        }
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        if let Self::Possible { reasons } = self {
            if reasons.is_empty() || reasons.len() > MAX_TYPED_REASONS {
                return Err(ReportValueError::NonCanonicalSet {
                    field: "certainty_reasons",
                });
            }
            if reasons.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(ReportValueError::NonCanonicalSet {
                    field: "certainty_reasons",
                });
            }
            for reason in reasons {
                reason.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingCompleteness {
    Complete,
    Partial {
        reasons: Vec<FindingIncompleteReason>,
    },
}

impl FindingCompleteness {
    pub fn partial(
        mut reasons: Vec<FindingIncompleteReason>,
    ) -> Result<Self, CompletionReasonError> {
        normalize_nonempty(&mut reasons)?;
        Ok(Self::Partial { reasons })
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn reasons(&self) -> &[FindingIncompleteReason] {
        match self {
            Self::Complete => &[],
            Self::Partial { reasons } => reasons,
        }
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        if let Self::Partial { reasons } = self
            && (reasons.is_empty()
                || reasons.len() > MAX_TYPED_REASONS
                || reasons.windows(2).any(|pair| pair[0] >= pair[1]))
        {
            return Err(ReportValueError::NonCanonicalSet {
                field: "finding_incomplete_reasons",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionReasonError {
    Empty,
    TooMany { max_items: usize },
    NonCanonical,
    InvalidReason { source: ReportValueError },
}

impl fmt::Display for CompletionReasonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => {
                formatter.write_str("a non-complete state requires at least one typed reason")
            }
            Self::TooMany { max_items } => {
                write!(
                    formatter,
                    "a typed reason set may contain at most {max_items} items"
                )
            }
            Self::NonCanonical => formatter.write_str(
                "typed completion reasons must be sorted, unique, and tightly normalized",
            ),
            Self::InvalidReason { source } => write!(formatter, "invalid typed reason: {source}"),
        }
    }
}

impl std::error::Error for CompletionReasonError {}

impl From<ReportValueError> for CompletionReasonError {
    fn from(source: ReportValueError) -> Self {
        Self::InvalidReason { source }
    }
}

fn normalize_nonempty<T: Ord>(values: &mut Vec<T>) -> Result<(), CompletionReasonError> {
    if values.len() > MAX_TYPED_REASONS {
        return Err(CompletionReasonError::TooMany {
            max_items: MAX_TYPED_REASONS,
        });
    }
    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err(CompletionReasonError::Empty);
    }
    tighten_vec(values);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CertaintyReason {
    AmbiguousReceiver,
    AmbiguousDispatch,
    NameBasedResolution,
    MultipleCandidateDeclarations,
    AnalyzerAmbiguity { code: String },
}

impl CertaintyReason {
    pub fn analyzer_ambiguity(code: impl Into<String>) -> Result<Self, ReportValueError> {
        let mut code = code.into();
        validate_report_identifier(&code)?;
        tighten_string(&mut code);
        Ok(Self::AnalyzerAmbiguity { code })
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        if let Self::AnalyzerAmbiguity { code } = self {
            validate_report_identifier(code)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyIncompleteReason {
    Cancelled,
    QueryResultLimit,
    BatchFindingLimit,
    ScannedFileBudget,
    SourceByteBudget,
    FactNodeBudget,
    PipelineRowBudget,
    ImportGraphBudget,
    ReferenceCandidateBudget,
    PartialDiscovery,
    CapabilityIncomplete,
    EndpointDominanceUndecidable,
    StableAnchorUnavailable,
    ReportRetentionBudget,
    CvssVariantBudget,
    ProjectionScenarioMembershipBudget,
    OrganizationalRiskOverlayBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingIncompleteReason {
    QueryProvenanceTruncated,
    RelatedLocationsTruncated,
    OriginsTruncated,
    SourceScenariosTruncated,
    TypestateScenariosTruncated,
    WitnessTruncated,
    EvidenceTruncated,
    ProofPartial,
    StableAnchorWeak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyFailureReason {
    InvalidExecutionPlan,
    WorkspaceSnapshotUnavailable,
    SourceReadFailed,
    WorkspaceIo,
    AmbiguousEndpointDominance,
    AmbiguousTypestateBinding,
    ConflictingOrganizationalRiskOverlay,
    InternalInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PolicyByteSpan {
    start: u64,
    end: u64,
}

impl PolicyByteSpan {
    pub fn new(start: u64, end: u64) -> Result<Self, PolicyLocationError> {
        if start > end {
            return Err(PolicyLocationError::ReversedByteSpan { start, end });
        }
        Ok(Self { start, end })
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn end(&self) -> u64 {
        self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PolicyDisplayRegion {
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
}

impl PolicyDisplayRegion {
    pub fn new(
        start_line: u64,
        start_column: u64,
        end_line: u64,
        end_column: u64,
    ) -> Result<Self, PolicyLocationError> {
        if [start_line, start_column, end_line, end_column]
            .into_iter()
            .any(|value| value == 0)
        {
            return Err(PolicyLocationError::ZeroDisplayCoordinate);
        }
        if (start_line, start_column) > (end_line, end_column) {
            return Err(PolicyLocationError::ReversedDisplayRegion);
        }
        Ok(Self {
            start_line,
            start_column,
            end_line,
            end_column,
        })
    }

    pub const fn start_line(&self) -> u64 {
        self.start_line
    }

    pub const fn start_column(&self) -> u64 {
        self.start_column
    }

    pub const fn end_line(&self) -> u64 {
        self.end_line
    }

    pub const fn end_column(&self) -> u64 {
        self.end_column
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PolicySourceLocation {
    path: String,
    byte_span: Option<PolicyByteSpan>,
    region: Option<PolicyDisplayRegion>,
}

impl PolicySourceLocation {
    pub fn artifact(path: WorkspaceRelativePath) -> Self {
        Self {
            path: path.as_str().to_string(),
            byte_span: None,
            region: None,
        }
    }

    pub fn span(
        path: WorkspaceRelativePath,
        byte_span: PolicyByteSpan,
        region: PolicyDisplayRegion,
    ) -> Self {
        Self {
            path: path.as_str().to_string(),
            byte_span: Some(byte_span),
            region: Some(region),
        }
    }

    pub fn try_new(
        path: WorkspaceRelativePath,
        byte_span: Option<PolicyByteSpan>,
        region: Option<PolicyDisplayRegion>,
    ) -> Result<Self, PolicyLocationError> {
        if byte_span.is_some() != region.is_some() {
            return Err(PolicyLocationError::SpanRegionMismatch);
        }
        Ok(Self {
            path: path.as_str().to_string(),
            byte_span,
            region,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn byte_span(&self) -> Option<PolicyByteSpan> {
        self.byte_span
    }

    pub const fn region(&self) -> Option<PolicyDisplayRegion> {
        self.region
    }

    pub const fn is_artifact_only(&self) -> bool {
        self.byte_span.is_none()
    }
}

impl RetainedSize for PolicyByteSpan {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for PolicyDisplayRegion {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for PolicySourceLocation {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.path.capacity())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLocationError {
    ReversedByteSpan { start: u64, end: u64 },
    ZeroDisplayCoordinate,
    ReversedDisplayRegion,
    SpanRegionMismatch,
}

impl fmt::Display for PolicyLocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReversedByteSpan { start, end } => {
                write!(formatter, "byte span start {start} exceeds end {end}")
            }
            Self::ZeroDisplayCoordinate => {
                formatter.write_str("display lines and columns are one-based")
            }
            Self::ReversedDisplayRegion => {
                formatter.write_str("display region start must not follow its exclusive end")
            }
            Self::SpanRegionMismatch => formatter.write_str(
                "a policy location must carry both byte span and display region, or neither",
            ),
        }
    }
}

impl std::error::Error for PolicyLocationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchFindingEvidence {
    result_domain: MatchResultDomain,
    anchor: MatchFindingAnchor,
    terminal: PolicyQueryResultRef,
    provenance: Vec<PolicyQueryProvenance>,
    provenance_truncated: bool,
}

impl MatchFindingEvidence {
    pub fn try_new(
        result_domain: MatchResultDomain,
        anchor: MatchFindingAnchor,
        mut terminal: PolicyQueryResultRef,
        mut provenance: Vec<PolicyQueryProvenance>,
        provenance_truncated: bool,
    ) -> Result<Self, ReportValueError> {
        if result_domain != anchor.result_domain() {
            return Err(ReportValueError::AnchorDomainMismatch);
        }
        terminal.validate()?;
        let Some((terminal_domain, terminal_path, _)) = terminal.terminal_shape() else {
            return Err(ReportValueError::UnsupportedTerminalResult);
        };
        if result_domain != terminal_domain {
            return Err(ReportValueError::TerminalDomainMismatch);
        }
        if terminal_path != anchor.path().as_str() {
            return Err(ReportValueError::TerminalAnchorPathMismatch);
        }
        terminal.tighten_owned_storage();
        if provenance.len() > MAX_QUERY_PROVENANCE {
            return Err(ReportValueError::TooManyItems {
                field: "query_provenance",
                max_items: MAX_QUERY_PROVENANCE,
            });
        }
        tighten_vec(&mut provenance);
        let evidence = Self {
            result_domain,
            anchor,
            terminal,
            provenance,
            provenance_truncated,
        };
        if u64::try_from(evidence.retained_size()).unwrap_or(u64::MAX) > MAX_EVIDENCE_BYTES {
            return Err(ReportValueError::TooManyBytes {
                field: "match_evidence",
                max_bytes: MAX_EVIDENCE_BYTES,
            });
        }
        Ok(evidence)
    }

    pub const fn result_domain(&self) -> MatchResultDomain {
        self.result_domain
    }

    pub const fn anchor(&self) -> &MatchFindingAnchor {
        &self.anchor
    }

    pub const fn terminal(&self) -> &PolicyQueryResultRef {
        &self.terminal
    }

    pub fn provenance(&self) -> &[PolicyQueryProvenance] {
        &self.provenance
    }

    pub const fn provenance_truncated(&self) -> bool {
        self.provenance_truncated
    }
}

impl RetainedSize for MatchFindingEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.anchor))
            .saturating_add(retained_extra(&self.terminal))
            .saturating_add(retained_extra(&self.provenance))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyFindingEvidence {
    Match { evidence: MatchFindingEvidence },
    Taint { evidence: TaintFindingEvidence },
    Typestate { evidence: TypestateFindingEvidence },
}

impl PolicyFindingEvidence {
    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        match self {
            Self::Match { .. } => PolicyAnalysisType::Match,
            Self::Taint { .. } => PolicyAnalysisType::Taint,
            Self::Typestate { .. } => PolicyAnalysisType::Typestate,
        }
    }

    pub const fn identity_stability(&self) -> super::finding_identity::FindingIdentityStability {
        match self {
            Self::Match { evidence } => evidence.anchor().stability(),
            Self::Taint { evidence } => evidence.anchor().stability(),
            Self::Typestate { evidence } => evidence.anchor().stability(),
        }
    }
}

impl RetainedSize for PolicyFindingEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Match { evidence } => retained_extra(evidence),
            Self::Taint { evidence } => retained_extra(evidence),
            Self::Typestate { evidence } => retained_extra(evidence),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyQueryProvenance {
    branch: Vec<u32>,
    seed: PolicyQueryResultRef,
    steps: Vec<PolicyQueryProvenanceStep>,
}

impl PolicyQueryProvenance {
    pub fn try_new(
        mut branch: Vec<u32>,
        mut seed: PolicyQueryResultRef,
        mut steps: Vec<PolicyQueryProvenanceStep>,
    ) -> Result<Self, ReportValueError> {
        if branch.len() > MAX_QUERY_BRANCH_DEPTH {
            return Err(ReportValueError::TooManyItems {
                field: "query_provenance_branch",
                max_items: MAX_QUERY_BRANCH_DEPTH,
            });
        }
        if steps.len() > MAX_QUERY_PROVENANCE_STEPS {
            return Err(ReportValueError::TooManyItems {
                field: "query_provenance_steps",
                max_items: MAX_QUERY_PROVENANCE_STEPS,
            });
        }
        seed.validate()?;
        seed.tighten_owned_storage();
        for step in &mut steps {
            step.validate()?;
            step.tighten_owned_storage();
        }
        tighten_vec(&mut branch);
        tighten_vec(&mut steps);
        let provenance = Self {
            branch,
            seed,
            steps,
        };
        if u64::try_from(provenance.retained_size()).unwrap_or(u64::MAX) > MAX_EVIDENCE_BYTES {
            return Err(ReportValueError::TooManyBytes {
                field: "query_provenance",
                max_bytes: MAX_EVIDENCE_BYTES,
            });
        }
        Ok(provenance)
    }

    pub fn branch(&self) -> &[u32] {
        &self.branch
    }

    pub const fn seed(&self) -> &PolicyQueryResultRef {
        &self.seed
    }

    pub fn steps(&self) -> &[PolicyQueryProvenanceStep] {
        &self.steps
    }
}

impl RetainedSize for PolicyQueryProvenance {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.branch))
            .saturating_add(retained_extra(&self.seed))
            .saturating_add(retained_extra(&self.steps))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyQueryProvenanceStep {
    operation: String,
    result: PolicyQueryResultRef,
    via: Option<PolicyQueryResultRef>,
}

impl PolicyQueryProvenanceStep {
    pub fn try_new(
        operation: impl Into<String>,
        result: PolicyQueryResultRef,
        via: Option<PolicyQueryResultRef>,
    ) -> Result<Self, ReportValueError> {
        let mut operation = operation.into();
        tighten_string(&mut operation);
        let mut value = Self {
            operation,
            result,
            via,
        };
        value.validate()?;
        value.tighten_owned_storage();
        Ok(value)
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        validate_report_identifier(&self.operation)?;
        self.result.validate()?;
        if let Some(via) = &self.via {
            via.validate()?;
        }
        Ok(())
    }

    fn tighten_owned_storage(&mut self) {
        tighten_string(&mut self.operation);
        self.result.tighten_owned_storage();
        if let Some(via) = &mut self.via {
            via.tighten_owned_storage();
        }
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub const fn result(&self) -> &PolicyQueryResultRef {
        &self.result
    }

    pub const fn via(&self) -> Option<&PolicyQueryResultRef> {
        self.via.as_ref()
    }
}

impl RetainedSize for PolicyQueryProvenanceStep {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.operation.capacity())
            .saturating_add(retained_extra(&self.result))
            .saturating_add(retained_extra(&self.via))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyQueryResultRef {
    StructuralMatch {
        kind: String,
        location: PolicySourceLocation,
        identity: Option<StableSemanticIdentity>,
    },
    Declaration {
        kind: String,
        fq_name: String,
        location: PolicySourceLocation,
        identity: Option<StableSemanticIdentity>,
    },
    File {
        #[serde(serialize_with = "serialize_workspace_path")]
        path: WorkspaceRelativePath,
    },
    ReferenceSite {
        location: PolicySourceLocation,
        target_fq_name: String,
        target_identity: Option<StableSemanticIdentity>,
        usage_kind: Option<String>,
        proof: PolicyQueryProof,
    },
    CallSite {
        location: PolicySourceLocation,
        caller_fq_name: String,
        caller_identity: Option<StableSemanticIdentity>,
        callee_fq_name: String,
        callee_identity: Option<StableSemanticIdentity>,
        proof: PolicyQueryProof,
    },
    ExpressionSite {
        location: PolicySourceLocation,
        input_kind: String,
        parameter_index: Option<u32>,
        parameter_name: Option<String>,
    },
    ReceiverAnalysis {
        location: PolicySourceLocation,
        analysis_kind: String,
        outcome: String,
        capture: Option<String>,
    },
    Unsupported {
        query_result_kind: String,
        location: Option<PolicySourceLocation>,
    },
}

impl PolicyQueryResultRef {
    pub fn file(path: WorkspaceRelativePath) -> Self {
        Self::File { path }
    }

    pub const fn result_domain(&self) -> Option<MatchResultDomain> {
        match self {
            Self::StructuralMatch { .. } => Some(MatchResultDomain::StructuralMatch),
            Self::Declaration { .. } => Some(MatchResultDomain::Declaration),
            Self::File { .. } => Some(MatchResultDomain::File),
            Self::ReferenceSite { .. } => Some(MatchResultDomain::ReferenceSite),
            Self::CallSite { .. } => Some(MatchResultDomain::CallSite),
            Self::ExpressionSite { .. } => Some(MatchResultDomain::ExpressionSite),
            Self::ReceiverAnalysis { .. } | Self::Unsupported { .. } => None,
        }
    }

    pub const fn location(&self) -> Option<&PolicySourceLocation> {
        match self {
            Self::StructuralMatch { location, .. }
            | Self::Declaration { location, .. }
            | Self::ReferenceSite { location, .. }
            | Self::CallSite { location, .. }
            | Self::ExpressionSite { location, .. }
            | Self::ReceiverAnalysis { location, .. } => Some(location),
            Self::File { .. } => None,
            Self::Unsupported { location, .. } => location.as_ref(),
        }
    }

    pub fn path(&self) -> Option<&str> {
        match self {
            Self::File { path } => Some(path.as_str()),
            _ => self.location().map(PolicySourceLocation::path),
        }
    }

    pub fn validate(&self) -> Result<(), ReportValueError> {
        match self {
            Self::StructuralMatch {
                kind,
                location,
                identity,
            }
            | Self::Declaration {
                kind,
                location,
                identity,
                ..
            } => {
                validate_report_identifier(kind)?;
                require_span_bearing(location)?;
                validate_identity_path(identity.as_ref(), location)?;
            }
            Self::File { .. } => {}
            Self::ReferenceSite {
                location,
                target_fq_name,
                usage_kind,
                ..
            } => {
                require_span_bearing(location)?;
                validate_report_prose(target_fq_name)?;
                if let Some(usage_kind) = usage_kind {
                    validate_report_identifier(usage_kind)?;
                }
            }
            Self::CallSite {
                location,
                caller_fq_name,
                caller_identity,
                callee_fq_name,
                ..
            } => {
                require_span_bearing(location)?;
                validate_identity_path(caller_identity.as_ref(), location)?;
                validate_report_prose(caller_fq_name)?;
                validate_report_prose(callee_fq_name)?;
            }
            Self::ExpressionSite {
                location,
                input_kind,
                parameter_name,
                ..
            } => {
                require_span_bearing(location)?;
                validate_report_identifier(input_kind)?;
                if let Some(parameter_name) = parameter_name {
                    validate_report_prose(parameter_name)?;
                }
            }
            Self::ReceiverAnalysis {
                location,
                analysis_kind,
                outcome,
                capture,
                ..
            } => {
                require_span_bearing(location)?;
                validate_report_identifier(analysis_kind)?;
                validate_report_identifier(outcome)?;
                if let Some(capture) = capture {
                    validate_report_prose(capture)?;
                }
            }
            Self::Unsupported {
                query_result_kind, ..
            } => validate_report_identifier(query_result_kind)?,
        }
        if let Self::Declaration { fq_name, .. } = self {
            validate_report_prose(fq_name)?;
        }
        Ok(())
    }

    fn terminal_shape(&self) -> Option<(MatchResultDomain, &str, Option<&PolicySourceLocation>)> {
        Some((self.result_domain()?, self.path()?, self.location()))
    }

    fn tighten_owned_storage(&mut self) {
        match self {
            Self::StructuralMatch { kind, .. } => tighten_string(kind),
            Self::Declaration { kind, fq_name, .. } => {
                tighten_string(kind);
                tighten_string(fq_name);
            }
            Self::File { .. } => {}
            Self::ReferenceSite {
                target_fq_name,
                usage_kind,
                ..
            } => {
                tighten_string(target_fq_name);
                if let Some(usage_kind) = usage_kind {
                    tighten_string(usage_kind);
                }
            }
            Self::CallSite {
                caller_fq_name,
                callee_fq_name,
                ..
            } => {
                tighten_string(caller_fq_name);
                tighten_string(callee_fq_name);
            }
            Self::ExpressionSite {
                input_kind,
                parameter_name,
                ..
            } => {
                tighten_string(input_kind);
                if let Some(parameter_name) = parameter_name {
                    tighten_string(parameter_name);
                }
            }
            Self::ReceiverAnalysis {
                analysis_kind,
                outcome,
                capture,
                ..
            } => {
                tighten_string(analysis_kind);
                tighten_string(outcome);
                if let Some(capture) = capture {
                    tighten_string(capture);
                }
            }
            Self::Unsupported {
                query_result_kind, ..
            } => tighten_string(query_result_kind),
        }
    }
}

impl RetainedSize for PolicyQueryResultRef {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::StructuralMatch {
                kind,
                location,
                identity,
            } => kind
                .capacity()
                .saturating_add(retained_extra(location))
                .saturating_add(retained_extra(identity)),
            Self::Declaration {
                kind,
                fq_name,
                location,
                identity,
            } => kind
                .capacity()
                .saturating_add(fq_name.capacity())
                .saturating_add(retained_extra(location))
                .saturating_add(retained_extra(identity)),
            Self::File { path } => retained_extra(path),
            Self::ReferenceSite {
                location,
                target_fq_name,
                target_identity,
                usage_kind,
                ..
            } => retained_extra(location)
                .saturating_add(target_fq_name.capacity())
                .saturating_add(retained_extra(target_identity))
                .saturating_add(retained_extra(usage_kind)),
            Self::CallSite {
                location,
                caller_fq_name,
                caller_identity,
                callee_fq_name,
                callee_identity,
                ..
            } => retained_extra(location)
                .saturating_add(caller_fq_name.capacity())
                .saturating_add(retained_extra(caller_identity))
                .saturating_add(callee_fq_name.capacity())
                .saturating_add(retained_extra(callee_identity)),
            Self::ExpressionSite {
                location,
                input_kind,
                parameter_name,
                ..
            } => retained_extra(location)
                .saturating_add(input_kind.capacity())
                .saturating_add(retained_extra(parameter_name)),
            Self::ReceiverAnalysis {
                location,
                analysis_kind,
                outcome,
                capture,
            } => retained_extra(location)
                .saturating_add(analysis_kind.capacity())
                .saturating_add(outcome.capacity())
                .saturating_add(retained_extra(capture)),
            Self::Unsupported {
                query_result_kind,
                location,
            } => query_result_kind
                .capacity()
                .saturating_add(retained_extra(location)),
        })
    }
}

fn serialize_workspace_path<S>(
    path: &WorkspaceRelativePath,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(path.as_str())
}

fn require_span_bearing(location: &PolicySourceLocation) -> Result<(), ReportValueError> {
    if location.is_artifact_only() {
        return Err(ReportValueError::ResultLocationMustHaveSpan);
    }
    Ok(())
}

fn validate_identity_path(
    identity: Option<&StableSemanticIdentity>,
    location: &PolicySourceLocation,
) -> Result<(), ReportValueError> {
    if identity.is_some_and(|identity| identity.path().as_str() != location.path()) {
        return Err(ReportValueError::StableIdentityPathMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyQueryProof {
    Exact,
    Resolved,
    NameBased,
    Ambiguous,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofMetadata {
    state: ProofState,
    reasons: Vec<ProofReason>,
    evidence_refs: Vec<EvidenceRef>,
}

impl ProofMetadata {
    pub fn try_new(
        state: ProofState,
        mut reasons: Vec<ProofReason>,
        mut evidence_refs: Vec<EvidenceRef>,
    ) -> Result<Self, ReportValueError> {
        if reasons.len() > MAX_TYPED_REASONS {
            return Err(ReportValueError::TooManyItems {
                field: "proof_reasons",
                max_items: MAX_TYPED_REASONS,
            });
        }
        if evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ReportValueError::TooManyItems {
                field: "proof_evidence_refs",
                max_items: MAX_EVIDENCE_REFS,
            });
        }
        for reason in &reasons {
            reason.validate()?;
        }
        reasons.sort();
        reasons.dedup();
        evidence_refs.sort();
        evidence_refs.dedup();
        tighten_vec(&mut reasons);
        tighten_vec(&mut evidence_refs);
        let proof = Self {
            state,
            reasons,
            evidence_refs,
        };
        if u64::try_from(proof.retained_size()).unwrap_or(u64::MAX) > MAX_EVIDENCE_BYTES {
            return Err(ReportValueError::TooManyBytes {
                field: "proof_metadata",
                max_bytes: MAX_EVIDENCE_BYTES,
            });
        }
        Ok(proof)
    }

    pub const fn state(&self) -> ProofState {
        self.state
    }

    pub fn reasons(&self) -> &[ProofReason] {
        &self.reasons
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
}

impl RetainedSize for ProofMetadata {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.reasons))
            .saturating_add(retained_extra(&self.evidence_refs))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofState {
    Proven,
    Unproven,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProofReason {
    DirectStructuralMatch,
    ResolvedDeclaration,
    ResolvedReference,
    ExactCallTarget,
    DataflowWitness,
    TypestateWitness,
    AmbiguousTarget,
    PartialWitness,
    AnalyzerEvidence { code: String },
}

impl ProofReason {
    pub fn analyzer_evidence(code: impl Into<String>) -> Result<Self, ReportValueError> {
        let mut code = code.into();
        validate_report_identifier(&code)?;
        tighten_string(&mut code);
        Ok(Self::AnalyzerEvidence { code })
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        if let Self::AnalyzerEvidence { code } = self {
            validate_report_identifier(code)?;
        }
        Ok(())
    }
}

impl RetainedSize for ProofReason {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::AnalyzerEvidence { code } => code.capacity(),
            _ => 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RelatedPolicyLocation {
    relationship: PolicyLocationRelationship,
    location: PolicySourceLocation,
    evidence_refs: Vec<EvidenceRef>,
}

impl RelatedPolicyLocation {
    pub fn try_new(
        relationship: PolicyLocationRelationship,
        location: PolicySourceLocation,
        mut evidence_refs: Vec<EvidenceRef>,
    ) -> Result<Self, ReportValueError> {
        if evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ReportValueError::TooManyItems {
                field: "related_location_evidence_refs",
                max_items: MAX_EVIDENCE_REFS,
            });
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        tighten_vec(&mut evidence_refs);
        let related = Self {
            relationship,
            location,
            evidence_refs,
        };
        if u64::try_from(related.retained_size()).unwrap_or(u64::MAX) > MAX_EVIDENCE_BYTES {
            return Err(ReportValueError::TooManyBytes {
                field: "related_location",
                max_bytes: MAX_EVIDENCE_BYTES,
            });
        }
        Ok(related)
    }

    pub const fn relationship(&self) -> PolicyLocationRelationship {
        self.relationship
    }

    pub const fn location(&self) -> &PolicySourceLocation {
        &self.location
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
}

impl RetainedSize for RelatedPolicyLocation {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.location))
            .saturating_add(retained_extra(&self.evidence_refs))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLocationRelationship {
    Source,
    Sink,
    Origin,
    Evidence,
    WitnessStep,
    Declaration,
    CallTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundedWitness {
    id: WitnessId,
    steps: Vec<WitnessStep>,
    truncated: bool,
    omitted_steps_lower_bound: u64,
    retained_bytes: u64,
}

impl BoundedWitness {
    pub fn try_new(
        id: WitnessId,
        mut steps: Vec<WitnessStep>,
        truncated: bool,
        omitted_steps_lower_bound: u64,
    ) -> Result<Self, ReportValueError> {
        if steps.is_empty() {
            return Err(ReportValueError::EmptyCollection {
                field: "witness_steps",
            });
        }
        if steps.len() > MAX_WITNESS_STEPS {
            return Err(ReportValueError::TooManyItems {
                field: "witness_steps",
                max_items: MAX_WITNESS_STEPS,
            });
        }
        if truncated != (omitted_steps_lower_bound > 0) {
            return Err(ReportValueError::InconsistentTruncation {
                field: "witness_steps",
            });
        }
        for step in &steps {
            step.validate()?;
        }
        tighten_vec(&mut steps);
        let mut witness = Self {
            id,
            steps,
            truncated,
            omitted_steps_lower_bound,
            retained_bytes: 0,
        };
        witness.retained_bytes = u64::try_from(witness.retained_size()).unwrap_or(u64::MAX);
        if witness.retained_bytes > MAX_WITNESS_BYTES {
            return Err(ReportValueError::TooManyBytes {
                field: "witness",
                max_bytes: MAX_WITNESS_BYTES,
            });
        }
        Ok(witness)
    }

    pub const fn id(&self) -> &WitnessId {
        &self.id
    }

    pub fn steps(&self) -> &[WitnessStep] {
        &self.steps
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub const fn omitted_steps_lower_bound(&self) -> u64 {
        self.omitted_steps_lower_bound
    }

    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

impl RetainedSize for BoundedWitness {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.id))
            .saturating_add(retained_extra(&self.steps))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WitnessStep {
    kind: WitnessStepKind,
    location: Option<PolicySourceLocation>,
    label: String,
    evidence_refs: Vec<EvidenceRef>,
}

impl WitnessStep {
    pub fn try_new(
        kind: WitnessStepKind,
        location: Option<PolicySourceLocation>,
        label: impl Into<String>,
        mut evidence_refs: Vec<EvidenceRef>,
    ) -> Result<Self, ReportValueError> {
        if evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ReportValueError::TooManyItems {
                field: "witness_step_evidence_refs",
                max_items: MAX_EVIDENCE_REFS,
            });
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        tighten_vec(&mut evidence_refs);
        let mut label = label.into();
        tighten_string(&mut label);
        let step = Self {
            kind,
            location,
            label,
            evidence_refs,
        };
        step.validate()?;
        Ok(step)
    }

    fn validate(&self) -> Result<(), ReportValueError> {
        validate_report_prose(&self.label)?;
        if self.evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(ReportValueError::TooManyItems {
                field: "witness_step_evidence_refs",
                max_items: MAX_EVIDENCE_REFS,
            });
        }
        Ok(())
    }

    pub const fn kind(&self) -> WitnessStepKind {
        self.kind
    }

    pub const fn location(&self) -> Option<&PolicySourceLocation> {
        self.location.as_ref()
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
}

impl RetainedSize for WitnessStep {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.location))
            .saturating_add(self.label.capacity())
            .saturating_add(retained_extra(&self.evidence_refs))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStepKind {
    Source,
    Propagation,
    Call,
    Return,
    Sanitizer,
    Transform,
    Transition,
    Violation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDiagnostic {
    code: PolicyDiagnosticCode,
    severity: PolicyDiagnosticSeverity,
    impact: PolicyDiagnosticImpact,
    message: String,
    primary: Option<PolicySourceLocation>,
    related: Vec<RelatedPolicyLocation>,
}

impl PolicyDiagnostic {
    pub fn try_new(
        code: PolicyDiagnosticCode,
        severity: PolicyDiagnosticSeverity,
        impact: PolicyDiagnosticImpact,
        message: impl Into<String>,
        primary: Option<PolicySourceLocation>,
        mut related: Vec<RelatedPolicyLocation>,
    ) -> Result<Self, ReportValueError> {
        let mut message = message.into();
        validate_report_prose(&message)?;
        tighten_string(&mut message);
        if related.len() > MAX_RELATED_LOCATIONS {
            return Err(ReportValueError::TooManyItems {
                field: "diagnostic_related_locations",
                max_items: MAX_RELATED_LOCATIONS,
            });
        }
        related.sort();
        related.dedup();
        tighten_vec(&mut related);
        Ok(Self {
            code,
            severity,
            impact,
            message,
            primary,
            related,
        })
    }

    pub const fn code(&self) -> &PolicyDiagnosticCode {
        &self.code
    }

    pub const fn severity(&self) -> PolicyDiagnosticSeverity {
        self.severity
    }

    pub const fn impact(&self) -> PolicyDiagnosticImpact {
        self.impact
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub const fn primary(&self) -> Option<&PolicySourceLocation> {
        self.primary.as_ref()
    }

    pub fn related(&self) -> &[RelatedPolicyLocation] {
        &self.related
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyDiagnosticCode {
    CodeQuery { code: CodeQueryDiagnosticCode },
    UnsupportedAnalysis,
    StableAnchorUnavailable,
    EndpointDominanceUndecidable,
    EvaluationFailure,
    BatchFindingLimit,
    ReportRetentionBudget,
    CvssVariantBudget,
    ProjectionScenarioMembershipBudget,
    OrganizationalRiskOverlayBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDiagnosticImpact {
    Advisory,
    FindingPartial,
    RunIncomplete,
    RunUnsupported,
    RunFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDiagnosticSeverity {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PolicyWorkReport {
    scanned_files: u64,
    scanned_source_bytes: u64,
    fact_nodes: u64,
    pipeline_rows: u64,
    examined_references: u64,
    retained_findings: u64,
    omitted_findings_lower_bound: u64,
    retained_report_bytes: u64,
    metrics: Vec<PolicyWorkMetric>,
}

impl PolicyWorkReport {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        scanned_files: u64,
        scanned_source_bytes: u64,
        fact_nodes: u64,
        pipeline_rows: u64,
        examined_references: u64,
        retained_findings: u64,
        omitted_findings_lower_bound: u64,
        retained_report_bytes: u64,
        mut metrics: Vec<PolicyWorkMetric>,
    ) -> Result<Self, ReportValueError> {
        if metrics.len() > MAX_WORK_METRICS {
            return Err(ReportValueError::TooManyItems {
                field: "work_metrics",
                max_items: MAX_WORK_METRICS,
            });
        }
        metrics.sort_by(|left, right| left.name.cmp(&right.name));
        if metrics.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(ReportValueError::DuplicateWorkMetric);
        }
        tighten_vec(&mut metrics);
        Ok(Self {
            scanned_files,
            scanned_source_bytes,
            fact_nodes,
            pipeline_rows,
            examined_references,
            retained_findings,
            omitted_findings_lower_bound,
            retained_report_bytes,
            metrics,
        })
    }

    pub const fn scanned_files(&self) -> u64 {
        self.scanned_files
    }

    pub const fn scanned_source_bytes(&self) -> u64 {
        self.scanned_source_bytes
    }

    pub const fn fact_nodes(&self) -> u64 {
        self.fact_nodes
    }

    pub const fn pipeline_rows(&self) -> u64 {
        self.pipeline_rows
    }

    pub const fn examined_references(&self) -> u64 {
        self.examined_references
    }

    pub const fn retained_findings(&self) -> u64 {
        self.retained_findings
    }

    pub const fn omitted_findings_lower_bound(&self) -> u64 {
        self.omitted_findings_lower_bound
    }

    pub const fn retained_report_bytes(&self) -> u64 {
        self.retained_report_bytes
    }

    pub fn metrics(&self) -> &[PolicyWorkMetric] {
        &self.metrics
    }

    pub(crate) fn set_retention(
        &mut self,
        retained_findings: u64,
        omitted_findings_lower_bound: u64,
        retained_report_bytes: u64,
    ) {
        self.retained_findings = retained_findings;
        self.omitted_findings_lower_bound = omitted_findings_lower_bound;
        self.retained_report_bytes = retained_report_bytes;
    }

    pub(crate) fn set_retained_report_bytes(&mut self, retained_report_bytes: u64) {
        self.retained_report_bytes = retained_report_bytes;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyWorkMetric {
    name: String,
    unit: PolicyWorkUnit,
    value: u64,
}

impl PolicyWorkMetric {
    pub fn try_new(
        name: impl Into<String>,
        unit: PolicyWorkUnit,
        value: u64,
    ) -> Result<Self, ReportValueError> {
        let mut name = name.into();
        validate_namespaced_metric(&name)?;
        tighten_string(&mut name);
        Ok(Self { name, unit, value })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn unit(&self) -> PolicyWorkUnit {
        self.unit
    }

    pub const fn value(&self) -> u64 {
        self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyWorkUnit {
    Count,
    Bytes,
    Rows,
}

/// One normalized finding in the canonical schema-version-1 report model.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyFinding {
    id: PolicyFindingId,
    identity_stability: FindingIdentityStability,
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    severity: FindingSeverity,
    message: String,
    classification: FindingClassification,
    certainty: FindingCertainty,
    completeness: FindingCompleteness,
    primary: PolicySourceLocation,
    related: Vec<RelatedPolicyLocation>,
    related_truncated: bool,
    omitted_related_locations_lower_bound: u64,
    evidence: PolicyFindingEvidence,
    evidence_refs_truncated: bool,
    omitted_evidence_refs_lower_bound: u64,
    cvss: Option<CvssAssessmentSet>,
    organizational_risk: Option<OrganizationalRiskAssessment>,
    proof: ProofMetadata,
    witnesses: Vec<BoundedWitness>,
    witnesses_truncated: bool,
    omitted_witnesses_lower_bound: u64,
}

impl PolicyFinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
        severity: FindingSeverity,
        mut message: String,
        classification: FindingClassification,
        certainty: FindingCertainty,
        completeness: FindingCompleteness,
        primary: PolicySourceLocation,
        mut related: Vec<RelatedPolicyLocation>,
        related_truncated: bool,
        omitted_related_locations_lower_bound: u64,
        evidence: PolicyFindingEvidence,
        evidence_refs_truncated: bool,
        omitted_evidence_refs_lower_bound: u64,
        cvss: Option<CvssAssessmentSet>,
        organizational_risk: Option<OrganizationalRiskAssessment>,
        proof: ProofMetadata,
        mut witnesses: Vec<BoundedWitness>,
        witnesses_truncated: bool,
        omitted_witnesses_lower_bound: u64,
        budget: &PolicyBudget,
    ) -> Result<Self, PolicyFindingError> {
        if message.is_empty() {
            return Err(PolicyFindingError::EmptyMessage);
        }
        validate_report_prose(&message)?;
        tighten_string(&mut message);
        validate_truncation_pair(
            "related_locations",
            related_truncated,
            omitted_related_locations_lower_bound,
        )?;
        validate_truncation_pair(
            "evidence_refs",
            evidence_refs_truncated,
            omitted_evidence_refs_lower_bound,
        )?;
        validate_truncation_pair(
            "witnesses",
            witnesses_truncated,
            omitted_witnesses_lower_bound,
        )?;

        if related.len() > budget.max_related_locations_per_finding() {
            return Err(ReportValueError::TooManyItems {
                field: "finding_related_locations",
                max_items: budget.max_related_locations_per_finding(),
            }
            .into());
        }
        related.sort();
        related.dedup();
        tighten_vec(&mut related);

        if witnesses.len() > budget.max_witnesses_per_finding() {
            return Err(ReportValueError::TooManyItems {
                field: "finding_witnesses",
                max_items: budget.max_witnesses_per_finding(),
            }
            .into());
        }
        for witness in &witnesses {
            if witness.steps().len() > budget.max_witness_steps() {
                return Err(ReportValueError::TooManyItems {
                    field: "witness_steps",
                    max_items: budget.max_witness_steps(),
                }
                .into());
            }
            if usize::try_from(witness.retained_bytes()).unwrap_or(usize::MAX)
                > budget.max_witness_bytes()
            {
                return Err(ReportValueError::TooManyBytes {
                    field: "witness",
                    max_bytes: u64::try_from(budget.max_witness_bytes()).unwrap_or(u64::MAX),
                }
                .into());
            }
        }
        witnesses.sort_by(|left, right| left.id().cmp(right.id()));
        if witnesses
            .windows(2)
            .any(|pair| pair[0].id() == pair[1].id())
        {
            return Err(PolicyFindingError::DuplicateWitnessId);
        }
        tighten_vec(&mut witnesses);

        let analysis_type = evidence.analysis_type();
        let identity_stability = evidence.identity_stability();
        validate_primary_evidence_shape(&primary, &evidence)?;
        validate_required_completeness_reasons(
            &completeness,
            &evidence,
            &related,
            related_truncated,
            evidence_refs_truncated,
            &proof,
            &witnesses,
            witnesses_truncated,
            cvss.as_ref(),
        )?;
        certainty.validate()?;
        completeness.validate()?;

        let id = match &evidence {
            PolicyFindingEvidence::Match { evidence } => {
                PolicyFindingId::from_match_anchor(&policy_id, evidence.anchor())
            }
            PolicyFindingEvidence::Taint { evidence } => {
                PolicyFindingId::from_taint_anchor(&policy_id, evidence.anchor())
            }
            PolicyFindingEvidence::Typestate { evidence } => {
                PolicyFindingId::from_typestate_anchor(&policy_id, evidence.anchor())
            }
        };
        let finding = Self {
            id,
            identity_stability,
            policy_id,
            policy_hash,
            analysis_type,
            severity,
            message,
            classification,
            certainty,
            completeness,
            primary,
            related,
            related_truncated,
            omitted_related_locations_lower_bound,
            evidence,
            evidence_refs_truncated,
            omitted_evidence_refs_lower_bound,
            cvss,
            organizational_risk,
            proof,
            witnesses,
            witnesses_truncated,
            omitted_witnesses_lower_bound,
        };
        finding.validate_against_budget(budget)?;
        Ok(finding)
    }

    pub const fn id(&self) -> PolicyFindingId {
        self.id
    }
    pub const fn identity_stability(&self) -> FindingIdentityStability {
        self.identity_stability
    }
    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }
    pub const fn policy_hash(&self) -> PolicySemanticHash {
        self.policy_hash
    }
    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        self.analysis_type
    }
    pub const fn severity(&self) -> FindingSeverity {
        self.severity
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub const fn classification(&self) -> &FindingClassification {
        &self.classification
    }
    pub const fn certainty(&self) -> &FindingCertainty {
        &self.certainty
    }
    pub const fn completeness(&self) -> &FindingCompleteness {
        &self.completeness
    }
    pub const fn primary(&self) -> &PolicySourceLocation {
        &self.primary
    }
    pub fn related(&self) -> &[RelatedPolicyLocation] {
        &self.related
    }
    pub const fn related_truncated(&self) -> bool {
        self.related_truncated
    }
    pub const fn omitted_related_locations_lower_bound(&self) -> u64 {
        self.omitted_related_locations_lower_bound
    }
    pub const fn evidence(&self) -> &PolicyFindingEvidence {
        &self.evidence
    }
    pub const fn evidence_refs_truncated(&self) -> bool {
        self.evidence_refs_truncated
    }
    pub const fn omitted_evidence_refs_lower_bound(&self) -> u64 {
        self.omitted_evidence_refs_lower_bound
    }
    pub const fn cvss(&self) -> Option<&CvssAssessmentSet> {
        self.cvss.as_ref()
    }
    pub const fn organizational_risk(&self) -> Option<&OrganizationalRiskAssessment> {
        self.organizational_risk.as_ref()
    }
    pub const fn proof(&self) -> &ProofMetadata {
        &self.proof
    }
    pub fn witnesses(&self) -> &[BoundedWitness] {
        &self.witnesses
    }
    pub const fn witnesses_truncated(&self) -> bool {
        self.witnesses_truncated
    }
    pub const fn omitted_witnesses_lower_bound(&self) -> u64 {
        self.omitted_witnesses_lower_bound
    }

    pub(crate) fn validate_against_budget(
        &self,
        budget: &PolicyBudget,
    ) -> Result<(), PolicyFindingError> {
        if self.related.len() > budget.max_related_locations_per_finding() {
            return Err(ReportValueError::TooManyItems {
                field: "finding_related_locations",
                max_items: budget.max_related_locations_per_finding(),
            }
            .into());
        }
        if self.witnesses.len() > budget.max_witnesses_per_finding() {
            return Err(ReportValueError::TooManyItems {
                field: "finding_witnesses",
                max_items: budget.max_witnesses_per_finding(),
            }
            .into());
        }
        for witness in &self.witnesses {
            if witness.steps().len() > budget.max_witness_steps() {
                return Err(ReportValueError::TooManyItems {
                    field: "witness_steps",
                    max_items: budget.max_witness_steps(),
                }
                .into());
            }
            if usize::try_from(witness.retained_bytes()).unwrap_or(usize::MAX)
                > budget.max_witness_bytes()
            {
                return Err(ReportValueError::TooManyBytes {
                    field: "witness",
                    max_bytes: u64::try_from(budget.max_witness_bytes()).unwrap_or(u64::MAX),
                }
                .into());
            }
        }
        let scenario_cap = budget.max_projection_scenario_memberships();
        let evidence_scenarios = match &self.evidence {
            PolicyFindingEvidence::Match { .. } => 0,
            PolicyFindingEvidence::Taint { evidence } => evidence.source_scenarios().len(),
            PolicyFindingEvidence::Typestate { evidence } => evidence.scenario_ids().len(),
        };
        if evidence_scenarios > scenario_cap
            || self.cvss.as_ref().is_some_and(|cvss| {
                cvss.variants()
                    .iter()
                    .any(|variant| variant.source_scenarios().len() > scenario_cap)
            })
        {
            return Err(ReportValueError::TooManyItems {
                field: "finding_scenario_memberships",
                max_items: scenario_cap,
            }
            .into());
        }
        if self
            .cvss
            .as_ref()
            .is_some_and(|cvss| cvss.variants().len() > budget.max_cvss_variants_per_finding())
        {
            return Err(ReportValueError::TooManyItems {
                field: "cvss_variants",
                max_items: budget.max_cvss_variants_per_finding(),
            }
            .into());
        }
        if self.cvss.as_ref().is_some_and(|cvss| {
            cvss.evidence_record_count() > budget.max_cvss_evidence_records_per_finding()
        }) {
            return Err(ReportValueError::TooManyItems {
                field: "cvss_evidence_records",
                max_items: budget.max_cvss_evidence_records_per_finding(),
            }
            .into());
        }
        let evidence_ref_count = distinct_evidence_ref_count(
            &self.classification,
            &self.related,
            &self.evidence,
            self.cvss.as_ref(),
            self.organizational_risk.as_ref(),
            &self.proof,
            &self.witnesses,
        );
        if evidence_ref_count > budget.max_evidence_refs_per_finding() {
            return Err(ReportValueError::TooManyItems {
                field: "finding_evidence_refs",
                max_items: budget.max_evidence_refs_per_finding(),
            }
            .into());
        }
        let evidence_bytes = self
            .evidence
            .retained_size()
            .saturating_add(self.classification.retained_size())
            .saturating_add(self.proof.retained_size())
            .saturating_add(self.cvss.as_ref().map_or(0, RetainedSize::retained_size))
            .saturating_add(
                self.organizational_risk
                    .as_ref()
                    .map_or(0, RetainedSize::retained_size),
            );
        if evidence_bytes > budget.max_evidence_bytes_per_finding() {
            return Err(ReportValueError::TooManyBytes {
                field: "finding_evidence",
                max_bytes: u64::try_from(budget.max_evidence_bytes_per_finding())
                    .unwrap_or(u64::MAX),
            }
            .into());
        }
        validate_cvss_finding_join_optional(self.cvss.as_ref(), &self.evidence)?;
        validate_retained_witness_references(&self.evidence, self.cvss.as_ref(), &self.witnesses)?;
        Ok(())
    }
}

impl RetainedSize for PolicyFinding {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(self.message.capacity())
            .saturating_add(retained_extra(&self.classification))
            .saturating_add(retained_extra(&self.certainty))
            .saturating_add(retained_extra(&self.completeness))
            .saturating_add(retained_extra(&self.primary))
            .saturating_add(retained_extra(&self.related))
            .saturating_add(retained_extra(&self.evidence))
            .saturating_add(retained_extra(&self.cvss))
            .saturating_add(retained_extra(&self.organizational_risk))
            .saturating_add(retained_extra(&self.proof))
            .saturating_add(retained_extra(&self.witnesses))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyFindingError {
    Value(ReportValueError),
    EmptyMessage,
    PrimaryEvidencePathMismatch,
    PrimaryLocationDomainMismatch,
    PrimaryTerminalLocationMismatch,
    MissingCompletenessReason { reason: FindingIncompleteReason },
    DuplicateWitnessId,
    DanglingWitnessReference { witness_id: WitnessId },
    CvssVulnerabilityIdentityMismatch,
    CvssSourceScenarioJoinMismatch,
}

impl PolicyFindingError {
    pub(crate) const fn is_budget_limit_exceeded(&self) -> bool {
        matches!(
            self,
            Self::Value(
                ReportValueError::TooManyItems { .. } | ReportValueError::TooManyBytes { .. }
            )
        )
    }
}

impl From<ReportValueError> for PolicyFindingError {
    fn from(value: ReportValueError) -> Self {
        Self::Value(value)
    }
}

impl fmt::Display for PolicyFindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(error) => error.fmt(formatter),
            Self::EmptyMessage => formatter.write_str("finding message must not be empty"),
            Self::PrimaryEvidencePathMismatch => {
                formatter.write_str("finding primary location does not match its semantic anchor")
            }
            Self::PrimaryLocationDomainMismatch => formatter
                .write_str("finding primary location shape does not match its analysis domain"),
            Self::PrimaryTerminalLocationMismatch => formatter.write_str(
                "finding primary location does not match its typed terminal result location",
            ),
            Self::MissingCompletenessReason { reason } => {
                write!(
                    formatter,
                    "finding completeness is missing reason {reason:?}"
                )
            }
            Self::DuplicateWitnessId => {
                formatter.write_str("finding witness identifiers must be unique")
            }
            Self::DanglingWitnessReference { witness_id } => write!(
                formatter,
                "finding evidence references unretained witness {witness_id}"
            ),
            Self::CvssVulnerabilityIdentityMismatch => formatter
                .write_str("CVSS variant vulnerability identity does not match the finding anchor"),
            Self::CvssSourceScenarioJoinMismatch => formatter
                .write_str("CVSS variant source scenarios do not resolve to the finding evidence"),
        }
    }
}

impl std::error::Error for PolicyFindingError {}

/// One policy's complete, incomplete, unsupported, or failed evaluation run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyRun {
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    completion: PolicyRunCompletion,
    findings: Vec<PolicyFinding>,
    diagnostics: Vec<PolicyDiagnostic>,
    diagnostics_truncated: bool,
    work: PolicyWorkReport,
}

impl PolicyRun {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
        analysis_type: PolicyAnalysisType,
        completion: PolicyRunCompletion,
        mut findings: Vec<PolicyFinding>,
        mut diagnostics: Vec<PolicyDiagnostic>,
        diagnostics_truncated: bool,
        mut work: PolicyWorkReport,
        budget: &PolicyBudget,
    ) -> Result<Self, PolicyRunError> {
        completion.validate()?;
        if findings.len() > budget.max_findings() {
            return Err(PolicyRunError::TooManyFindings {
                max: budget.max_findings(),
            });
        }
        for finding in &findings {
            if finding.policy_id != policy_id
                || finding.policy_hash != policy_hash
                || finding.analysis_type != analysis_type
            {
                return Err(PolicyRunError::FindingJoinMismatch);
            }
            finding
                .validate_against_budget(budget)
                .map_err(|_| PolicyRunError::FindingBudgetViolation)?;
        }
        findings.sort_by_key(PolicyFinding::id);
        if findings.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(PolicyRunError::DuplicateFindingId);
        }
        tighten_vec(&mut findings);

        diagnostics.sort_by(compare_policy_diagnostics);
        diagnostics.dedup();
        if diagnostics.len() > budget.max_diagnostics() {
            return Err(PolicyRunError::TooManyDiagnostics {
                max: budget.max_diagnostics(),
            });
        }
        tighten_vec(&mut diagnostics);

        if diagnostics_truncated && completion.is_complete() {
            return Err(PolicyRunError::CompletionDoesNotReflectDiagnostics);
        }
        for diagnostic in &diagnostics {
            if !completion_allows_impact(&completion, diagnostic.impact) {
                return Err(PolicyRunError::CompletionDoesNotReflectDiagnostics);
            }
        }
        if findings
            .iter()
            .any(|finding| finding.identity_stability == FindingIdentityStability::Weak)
            && !completion_has_incomplete_reason(
                &completion,
                PolicyIncompleteReason::StableAnchorUnavailable,
            )
        {
            return Err(PolicyRunError::WeakFindingRequiresIncompleteRun);
        }
        if work.omitted_findings_lower_bound > 0 && completion.is_complete() {
            return Err(PolicyRunError::OmittedFindingsRequireIncompleteRun);
        }
        work.set_retention(
            u64::try_from(findings.len()).unwrap_or(u64::MAX),
            work.omitted_findings_lower_bound,
            0,
        );
        let mut run = Self {
            policy_id,
            policy_hash,
            analysis_type,
            completion,
            findings,
            diagnostics,
            diagnostics_truncated,
            work,
        };
        run.refresh_retained_bytes();
        if run.retained_size() > budget.max_retained_report_bytes() {
            return Err(PolicyRunError::RetainedReportBytesExceeded {
                max: budget.max_retained_report_bytes(),
            });
        }
        Ok(run)
    }

    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }
    pub const fn policy_hash(&self) -> PolicySemanticHash {
        self.policy_hash
    }
    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        self.analysis_type
    }
    pub const fn completion(&self) -> &PolicyRunCompletion {
        &self.completion
    }
    pub fn findings(&self) -> &[PolicyFinding] {
        &self.findings
    }

    pub(crate) fn take_findings(&mut self) -> Vec<PolicyFinding> {
        let findings = std::mem::take(&mut self.findings);
        self.work.retained_findings = 0;
        self.refresh_retained_bytes();
        findings
    }

    pub fn diagnostics(&self) -> &[PolicyDiagnostic] {
        &self.diagnostics
    }
    pub const fn diagnostics_truncated(&self) -> bool {
        self.diagnostics_truncated
    }
    pub const fn work(&self) -> &PolicyWorkReport {
        &self.work
    }

    pub(crate) fn validate_against_budget(
        &self,
        budget: &PolicyBudget,
    ) -> Result<(), PolicyRunError> {
        if self.findings.len() > budget.max_findings() {
            return Err(PolicyRunError::TooManyFindings {
                max: budget.max_findings(),
            });
        }
        if self.diagnostics.len() > budget.max_diagnostics() {
            return Err(PolicyRunError::TooManyDiagnostics {
                max: budget.max_diagnostics(),
            });
        }
        if self.diagnostics_truncated && self.completion.is_complete() {
            return Err(PolicyRunError::CompletionDoesNotReflectDiagnostics);
        }
        for finding in &self.findings {
            if finding.policy_id != self.policy_id
                || finding.policy_hash != self.policy_hash
                || finding.analysis_type != self.analysis_type
            {
                return Err(PolicyRunError::FindingJoinMismatch);
            }
            finding
                .validate_against_budget(budget)
                .map_err(|_| PolicyRunError::FindingBudgetViolation)?;
        }
        if self.retained_size() > budget.max_retained_report_bytes() {
            return Err(PolicyRunError::RetainedReportBytesExceeded {
                max: budget.max_retained_report_bytes(),
            });
        }
        Ok(())
    }

    pub(crate) fn mark_inconclusive(
        &mut self,
        reason: PolicyIncompleteReason,
    ) -> Result<(), CompletionReasonError> {
        match &mut self.completion {
            PolicyRunCompletion::Complete => {
                self.completion = PolicyRunCompletion::inconclusive(vec![reason])?;
            }
            PolicyRunCompletion::Inconclusive { reasons } => {
                reasons.push(reason);
                normalize_nonempty(reasons)?;
            }
            PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. } => {}
        }
        self.refresh_retained_bytes();
        Ok(())
    }

    pub(crate) fn replace_findings(&mut self, mut findings: Vec<PolicyFinding>) {
        findings.sort_by_key(PolicyFinding::id);
        tighten_vec(&mut findings);
        self.findings = findings;
        self.work.retained_findings = u64::try_from(self.findings.len()).unwrap_or(u64::MAX);
        self.refresh_retained_bytes();
    }

    pub(crate) fn increment_omitted_findings(&mut self) {
        self.work.omitted_findings_lower_bound =
            self.work.omitted_findings_lower_bound.saturating_add(1);
        self.refresh_retained_bytes();
    }

    pub(crate) fn replace_diagnostics(
        &mut self,
        mut diagnostics: Vec<PolicyDiagnostic>,
        truncated: bool,
    ) {
        diagnostics.sort_by(compare_policy_diagnostics);
        diagnostics.dedup();
        tighten_vec(&mut diagnostics);
        self.diagnostics = diagnostics;
        self.diagnostics_truncated |= truncated;
        self.refresh_retained_bytes();
    }

    pub(crate) fn set_retained_report_bytes(&mut self, retained_report_bytes: usize) {
        self.work
            .set_retained_report_bytes(u64::try_from(retained_report_bytes).unwrap_or(u64::MAX));
    }

    fn refresh_retained_bytes(&mut self) {
        self.work.retained_report_bytes = 0;
        self.work.retained_report_bytes = u64::try_from(self.retained_size()).unwrap_or(u64::MAX);
    }
}

impl RetainedSize for PolicyRun {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(retained_extra(&self.completion))
            .saturating_add(retained_extra(&self.findings))
            .saturating_add(retained_extra(&self.diagnostics))
            .saturating_add(retained_extra(&self.work))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRunError {
    InvalidCompletion(CompletionReasonError),
    TooManyFindings { max: usize },
    TooManyDiagnostics { max: usize },
    FindingJoinMismatch,
    DuplicateFindingId,
    CompletionDoesNotReflectDiagnostics,
    WeakFindingRequiresIncompleteRun,
    OmittedFindingsRequireIncompleteRun,
    FindingBudgetViolation,
    RetainedReportBytesExceeded { max: usize },
}

impl From<CompletionReasonError> for PolicyRunError {
    fn from(value: CompletionReasonError) -> Self {
        Self::InvalidCompletion(value)
    }
}

impl fmt::Display for PolicyRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCompletion(error) => error.fmt(formatter),
            Self::TooManyFindings { max } => {
                write!(formatter, "policy run accepts at most {max} findings")
            }
            Self::TooManyDiagnostics { max } => {
                write!(formatter, "policy run accepts at most {max} diagnostics")
            }
            Self::FindingJoinMismatch => formatter.write_str(
                "every finding must join its run by policy ID, policy hash, and analysis type",
            ),
            Self::DuplicateFindingId => {
                formatter.write_str("policy run finding identifiers must be unique")
            }
            Self::CompletionDoesNotReflectDiagnostics => formatter.write_str(
                "policy run completion does not reflect retained or omitted diagnostic impact",
            ),
            Self::WeakFindingRequiresIncompleteRun => formatter.write_str(
                "a weak finding identity requires stable_anchor_unavailable run completion",
            ),
            Self::OmittedFindingsRequireIncompleteRun => {
                formatter.write_str("omitted findings require an incomplete run")
            }
            Self::FindingBudgetViolation => {
                formatter.write_str("a finding exceeds the original host budget")
            }
            Self::RetainedReportBytesExceeded { max } => {
                write!(formatter, "policy run retains more than {max} bytes")
            }
        }
    }
}

impl std::error::Error for PolicyRunError {}

fn validate_truncation_pair(
    field: &'static str,
    truncated: bool,
    omitted_lower_bound: u64,
) -> Result<(), ReportValueError> {
    if truncated != (omitted_lower_bound > 0) {
        return Err(ReportValueError::InconsistentTruncation { field });
    }
    Ok(())
}

fn validate_primary_evidence_shape(
    primary: &PolicySourceLocation,
    evidence: &PolicyFindingEvidence,
) -> Result<(), PolicyFindingError> {
    let expected_path = match evidence {
        PolicyFindingEvidence::Match { evidence } => Some(evidence.anchor().path().as_str()),
        PolicyFindingEvidence::Taint { evidence } => evidence
            .anchor()
            .strong_fields()
            .map(|anchor| anchor.sink_identity().path().as_str()),
        PolicyFindingEvidence::Typestate { evidence } => evidence
            .anchor()
            .strong_fields()
            .map(|anchor| anchor.violation_site_identity().path().as_str())
            .or_else(|| evidence.violation_site().map(|site| site.path().as_str())),
    };
    if expected_path.is_some_and(|path| path != primary.path()) {
        return Err(PolicyFindingError::PrimaryEvidencePathMismatch);
    }
    let artifact_expected = matches!(
        evidence,
        PolicyFindingEvidence::Match { evidence }
            if evidence.result_domain() == MatchResultDomain::File
    );
    if primary.is_artifact_only() != artifact_expected {
        return Err(PolicyFindingError::PrimaryLocationDomainMismatch);
    }
    if let PolicyFindingEvidence::Match { evidence } = evidence
        && let Some((_, _, Some(terminal_location))) = evidence.terminal().terminal_shape()
        && terminal_location != primary
    {
        return Err(PolicyFindingError::PrimaryTerminalLocationMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_required_completeness_reasons(
    completeness: &FindingCompleteness,
    evidence: &PolicyFindingEvidence,
    _related: &[RelatedPolicyLocation],
    related_truncated: bool,
    evidence_refs_truncated: bool,
    proof: &ProofMetadata,
    witnesses: &[BoundedWitness],
    witnesses_truncated: bool,
    cvss: Option<&CvssAssessmentSet>,
) -> Result<(), PolicyFindingError> {
    let mut required = Vec::new();
    if evidence.identity_stability() == FindingIdentityStability::Weak {
        required.push(FindingIncompleteReason::StableAnchorWeak);
    }
    if related_truncated {
        required.push(FindingIncompleteReason::RelatedLocationsTruncated);
    }
    if evidence_refs_truncated {
        required.push(FindingIncompleteReason::EvidenceTruncated);
    }
    if proof.state() != ProofState::Proven {
        required.push(FindingIncompleteReason::ProofPartial);
    }
    if witnesses_truncated
        || witnesses.iter().any(BoundedWitness::truncated)
        || cvss.is_some_and(CvssAssessmentSet::has_truncated_witness_refs)
    {
        required.push(FindingIncompleteReason::WitnessTruncated);
    }
    if cvss.is_some_and(CvssAssessmentSet::has_truncated_source_scenarios) {
        required.push(FindingIncompleteReason::SourceScenariosTruncated);
    }
    match evidence {
        PolicyFindingEvidence::Match { evidence } if evidence.provenance_truncated() => {
            required.push(FindingIncompleteReason::QueryProvenanceTruncated);
        }
        PolicyFindingEvidence::Taint { evidence } => {
            if evidence.origins_truncated() {
                required.push(FindingIncompleteReason::OriginsTruncated);
            }
            if evidence.source_scenarios_truncated() {
                required.push(FindingIncompleteReason::SourceScenariosTruncated);
            }
            if evidence.witness_refs_truncated() {
                required.push(FindingIncompleteReason::WitnessTruncated);
            }
        }
        PolicyFindingEvidence::Typestate { evidence } => {
            if evidence.scenarios_truncated() {
                required.push(FindingIncompleteReason::TypestateScenariosTruncated);
            }
            if evidence.witness_refs_truncated() {
                required.push(FindingIncompleteReason::WitnessTruncated);
            }
        }
        PolicyFindingEvidence::Match { .. } => {}
    }
    required.sort();
    required.dedup();
    for reason in required {
        if !completeness.reasons().contains(&reason) {
            return Err(PolicyFindingError::MissingCompletenessReason { reason });
        }
    }
    Ok(())
}

fn append_witness_refs<'a>(evidence: &'a PolicyFindingEvidence, output: &mut Vec<&'a WitnessId>) {
    match evidence {
        PolicyFindingEvidence::Match { .. } => {}
        PolicyFindingEvidence::Taint { evidence } => output.extend(evidence.witness_refs()),
        PolicyFindingEvidence::Typestate { evidence } => output.extend(evidence.witness_refs()),
    }
}

fn validate_retained_witness_references(
    evidence: &PolicyFindingEvidence,
    cvss: Option<&CvssAssessmentSet>,
    witnesses: &[BoundedWitness],
) -> Result<(), PolicyFindingError> {
    let mut referenced_witnesses = Vec::new();
    append_witness_refs(evidence, &mut referenced_witnesses);
    if let Some(cvss) = cvss {
        cvss.append_witness_refs(&mut referenced_witnesses);
    }
    for referenced in referenced_witnesses {
        if witnesses
            .binary_search_by(|witness| witness.id().cmp(referenced))
            .is_err()
        {
            return Err(PolicyFindingError::DanglingWitnessReference {
                witness_id: referenced.clone(),
            });
        }
    }
    Ok(())
}

fn validate_cvss_finding_join_optional(
    cvss: Option<&CvssAssessmentSet>,
    evidence: &PolicyFindingEvidence,
) -> Result<(), PolicyFindingError> {
    if let Some(cvss) = cvss {
        validate_cvss_finding_join(cvss, evidence)?;
    }
    Ok(())
}

fn validate_cvss_finding_join(
    cvss: &CvssAssessmentSet,
    evidence: &PolicyFindingEvidence,
) -> Result<(), PolicyFindingError> {
    let vulnerability = VulnerabilityIdentity::from_bytes(match evidence {
        PolicyFindingEvidence::Match { evidence } => {
            super::finding_identity::match_vulnerability_digest(evidence.anchor())
        }
        PolicyFindingEvidence::Taint { evidence } => {
            super::future_evidence::taint_vulnerability_digest(evidence.anchor())
        }
        PolicyFindingEvidence::Typestate { evidence } => {
            super::future_evidence::typestate_vulnerability_digest(evidence.anchor())
        }
    });
    let empty_scenario_hash = super::future_evidence::empty_source_scenario_set_hash();
    for variant in cvss.variants() {
        if variant.vulnerability_identity() != vulnerability {
            return Err(PolicyFindingError::CvssVulnerabilityIdentityMismatch);
        }
        match evidence {
            PolicyFindingEvidence::Taint { evidence } => {
                if variant.source_scenario_set_hash() != evidence.source_scenario_set_hash()
                    || variant
                        .source_scenarios()
                        .iter()
                        .any(|scenario| !evidence.source_scenarios().contains(scenario))
                {
                    return Err(PolicyFindingError::CvssSourceScenarioJoinMismatch);
                }
            }
            PolicyFindingEvidence::Match { .. } | PolicyFindingEvidence::Typestate { .. } => {
                if !variant.source_scenarios().is_empty()
                    || variant.source_scenarios_truncated()
                    || variant.omitted_source_scenarios_lower_bound() != 0
                    || variant.source_scenario_set_hash() != empty_scenario_hash
                {
                    return Err(PolicyFindingError::CvssSourceScenarioJoinMismatch);
                }
            }
        }
    }
    Ok(())
}

fn distinct_evidence_ref_count(
    classification: &FindingClassification,
    related: &[RelatedPolicyLocation],
    evidence: &PolicyFindingEvidence,
    cvss: Option<&CvssAssessmentSet>,
    organizational_risk: Option<&OrganizationalRiskAssessment>,
    proof: &ProofMetadata,
    witnesses: &[BoundedWitness],
) -> usize {
    let mut refs = Vec::new();
    if let Some(broad) = classification.broad() {
        append_classification_refs(broad.provenance(), &mut refs);
    }
    for refinement in classification.refinements() {
        append_classification_refs(refinement.provenance(), &mut refs);
    }
    for location in related {
        refs.extend(location.evidence_refs());
    }
    if let PolicyFindingEvidence::Taint { evidence } = evidence {
        for origin in evidence.origins() {
            refs.extend(origin.evidence_refs());
        }
    }
    if let Some(cvss) = cvss {
        cvss.append_evidence_refs(&mut refs);
    }
    if let Some(risk) = organizational_risk {
        refs.extend(risk.evidence_refs());
    }
    refs.extend(proof.evidence_refs());
    for witness in witnesses {
        for step in witness.steps() {
            refs.extend(step.evidence_refs());
        }
    }
    refs.sort();
    refs.dedup();
    refs.len()
}

fn append_classification_refs<'a>(
    provenance: &'a ClassificationProvenance,
    output: &mut Vec<&'a EvidenceRef>,
) {
    if let ClassificationProvenance::AnalysisEvidence { evidence_refs, .. } = provenance {
        output.extend(evidence_refs);
    }
}

pub(crate) fn insert_policy_diagnostic_bounded(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostic: PolicyDiagnostic,
    max_diagnostics: usize,
) -> bool {
    let mut truncated = normalize_policy_diagnostics_bounded(diagnostics, max_diagnostics);
    match diagnostics.binary_search_by(|current| compare_policy_diagnostics(current, &diagnostic)) {
        Ok(_) => truncated,
        Err(index) => {
            diagnostics.insert(index, diagnostic);
            if diagnostics.len() > max_diagnostics {
                diagnostics.truncate(max_diagnostics);
                truncated = true;
            }
            truncated
        }
    }
}

pub(crate) fn normalize_policy_diagnostics_bounded(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    max_diagnostics: usize,
) -> bool {
    diagnostics.sort_by(compare_policy_diagnostics);
    diagnostics.dedup();
    if diagnostics.len() > max_diagnostics {
        diagnostics.truncate(max_diagnostics);
        true
    } else {
        false
    }
}

fn compare_policy_diagnostics(
    left: &PolicyDiagnostic,
    right: &PolicyDiagnostic,
) -> std::cmp::Ordering {
    (
        &left.code,
        left.severity,
        left.impact,
        &left.message,
        &left.primary,
        &left.related,
    )
        .cmp(&(
            &right.code,
            right.severity,
            right.impact,
            &right.message,
            &right.primary,
            &right.related,
        ))
}

fn completion_allows_impact(
    completion: &PolicyRunCompletion,
    impact: PolicyDiagnosticImpact,
) -> bool {
    match impact {
        PolicyDiagnosticImpact::Advisory | PolicyDiagnosticImpact::FindingPartial => true,
        PolicyDiagnosticImpact::RunIncomplete => {
            matches!(completion, PolicyRunCompletion::Inconclusive { .. })
        }
        PolicyDiagnosticImpact::RunUnsupported => {
            matches!(completion, PolicyRunCompletion::Unsupported { .. })
        }
        PolicyDiagnosticImpact::RunFailed => {
            matches!(completion, PolicyRunCompletion::Failed { .. })
        }
    }
}

fn completion_has_incomplete_reason(
    completion: &PolicyRunCompletion,
    reason: PolicyIncompleteReason,
) -> bool {
    matches!(completion, PolicyRunCompletion::Inconclusive { reasons } if reasons.contains(&reason))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportValueError {
    EmptyIdentifier,
    EmptyCollection {
        field: &'static str,
    },
    IdentifierTooLong {
        max_bytes: usize,
    },
    InvalidIdentifier,
    ProseTooLong {
        max_bytes: usize,
    },
    InvalidWorkspacePath,
    AnchorDomainMismatch,
    TerminalDomainMismatch,
    TerminalAnchorPathMismatch,
    UnsupportedTerminalResult,
    ResultLocationMustHaveSpan,
    StableIdentityPathMismatch,
    TooManyItems {
        field: &'static str,
        max_items: usize,
    },
    TooManyBytes {
        field: &'static str,
        max_bytes: u64,
    },
    InconsistentTruncation {
        field: &'static str,
    },
    DuplicateWorkMetric,
    WorkMetricMustBeNamespaced,
    NonCanonicalSet {
        field: &'static str,
    },
}

impl fmt::Display for ReportValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier => formatter.write_str("report identifier must not be empty"),
            Self::EmptyCollection { field } => {
                write!(formatter, "{field} must contain at least one item")
            }
            Self::IdentifierTooLong { max_bytes } => {
                write!(
                    formatter,
                    "report identifier must be at most {max_bytes} bytes"
                )
            }
            Self::InvalidIdentifier => formatter.write_str(
                "report identifier must use lowercase ASCII alphanumerics, `.`, `-`, or `_`",
            ),
            Self::ProseTooLong { max_bytes } => {
                write!(formatter, "report text must be at most {max_bytes} bytes")
            }
            Self::InvalidWorkspacePath => {
                formatter.write_str("report path must be normalized and workspace-relative")
            }
            Self::AnchorDomainMismatch => {
                formatter.write_str("match evidence domain does not match its anchor domain")
            }
            Self::TerminalDomainMismatch => formatter
                .write_str("match evidence terminal domain does not match its declared domain"),
            Self::TerminalAnchorPathMismatch => {
                formatter.write_str("match evidence terminal path does not match its anchor path")
            }
            Self::UnsupportedTerminalResult => formatter
                .write_str("match evidence terminal must be an accepted diagnostic result domain"),
            Self::ResultLocationMustHaveSpan => formatter
                .write_str("non-file query provenance requires a span-bearing source location"),
            Self::StableIdentityPathMismatch => formatter
                .write_str("stable semantic identity path does not match its source location"),
            Self::TooManyItems { field, max_items } => {
                write!(formatter, "{field} must contain at most {max_items} items")
            }
            Self::TooManyBytes { field, max_bytes } => {
                write!(formatter, "{field} must retain at most {max_bytes} bytes")
            }
            Self::InconsistentTruncation { field } => write!(
                formatter,
                "{field} truncation and omitted-count fields are inconsistent"
            ),
            Self::DuplicateWorkMetric => {
                formatter.write_str("policy work metric names must be unique")
            }
            Self::WorkMetricMustBeNamespaced => {
                formatter.write_str("extension work metrics must have a namespaced name")
            }
            Self::NonCanonicalSet { field } => {
                write!(formatter, "{field} must be sorted, unique, and non-empty")
            }
        }
    }
}

impl std::error::Error for ReportValueError {}

fn validate_report_identifier(value: &str) -> Result<(), ReportValueError> {
    if value.is_empty() {
        return Err(ReportValueError::EmptyIdentifier);
    }
    if value.len() > MAX_REPORT_IDENTIFIER_BYTES {
        return Err(ReportValueError::IdentifierTooLong {
            max_bytes: MAX_REPORT_IDENTIFIER_BYTES,
        });
    }
    let bytes = value.as_bytes();
    if !is_identifier_endpoint(bytes[0]) || !is_identifier_endpoint(bytes[bytes.len() - 1]) {
        return Err(ReportValueError::InvalidIdentifier);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
    }) {
        return Err(ReportValueError::InvalidIdentifier);
    }
    Ok(())
}

const fn is_identifier_endpoint(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

pub(crate) fn validate_report_prose(value: &str) -> Result<(), ReportValueError> {
    if value.len() > MAX_REPORT_PROSE_BYTES {
        return Err(ReportValueError::ProseTooLong {
            max_bytes: MAX_REPORT_PROSE_BYTES,
        });
    }
    Ok(())
}

fn validate_namespaced_metric(value: &str) -> Result<(), ReportValueError> {
    validate_report_identifier(value)?;
    if !value.contains('.') {
        return Err(ReportValueError::WorkMetricMustBeNamespaced);
    }
    Ok(())
}

pub(crate) fn tighten_vec<T>(values: &mut Vec<T>) {
    *values = std::mem::take(values).into_boxed_slice().into_vec();
}

pub(crate) fn tighten_string(value: &mut String) {
    *value = std::mem::take(value).into_boxed_str().into_string();
}

impl RetainedSize for PolicyRunCompletion {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Complete => 0,
            Self::Inconclusive { reasons } => retained_extra(reasons),
            Self::Unsupported { capability } => retained_extra(capability),
            Self::Failed { reasons } => retained_extra(reasons),
        })
    }
}

impl RetainedSize for PolicyCapability {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::TaintEvaluation | Self::TypestateEvaluation => 0,
            Self::QueryFeature { language, feature } => {
                language.capacity().saturating_add(feature.capacity())
            }
        })
    }
}

impl RetainedSize for FindingCertainty {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Definite => 0,
            Self::Possible { reasons } => retained_extra(reasons),
        })
    }
}

impl RetainedSize for FindingCompleteness {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Complete => 0,
            Self::Partial { reasons } => retained_extra(reasons),
        })
    }
}

impl RetainedSize for CertaintyReason {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::AnalyzerAmbiguity { code } => code.capacity(),
            _ => 0,
        })
    }
}

impl RetainedSize for PolicyDiagnostic {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.message.capacity())
            .saturating_add(retained_extra(&self.primary))
            .saturating_add(retained_extra(&self.related))
    }
}

impl RetainedSize for PolicyWorkReport {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.metrics))
    }
}

impl RetainedSize for PolicyWorkMetric {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.name.capacity())
    }
}

macro_rules! fixed_report_retained_size {
    ($($type:ty),+ $(,)?) => {
        $(
            impl RetainedSize for $type {
                fn retained_size(&self) -> usize {
                    size_of::<Self>()
                }
            }
        )+
    };
}

fixed_report_retained_size!(
    PolicyIncompleteReason,
    FindingIncompleteReason,
    PolicyFailureReason,
    PolicyQueryProof,
    ProofState,
    PolicyLocationRelationship,
    WitnessStepKind,
    PolicyDiagnosticCode,
    PolicyDiagnosticImpact,
    PolicyDiagnosticSeverity,
    PolicyWorkUnit,
    PolicyAnalysisType,
    FindingSeverity,
);

impl Serialize for PolicyAnalysisType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Match => "match",
            Self::Taint => "taint",
            Self::Typestate => "typestate",
        })
    }
}

impl Serialize for FindingSeverity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Unrated => "unrated",
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

impl Serialize for PolicyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl Serialize for PolicySemanticHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::cvss::{
        CvssAssessment, CvssAssessmentProvenance, CvssAssessmentSet, CvssAssessmentVariant,
        CvssEvidenceSetHash, CvssUnscoredReason, SourceScenarioSetHash, VulnerabilityIdentity,
    };
    use crate::analyzer::policy::definition::{
        CvssBaseMetric, CvssVersion, PolicyAnalysis, PolicySelector, RqlpDocument,
    };
    use crate::analyzer::policy::finding_identity::{OpaqueFindingKey, SourceSliceHash};
    use crate::analyzer::policy::resolved::{
        LoadedPolicy, PolicyPrecedenceManifest, ResolvedPolicySelector, SelectorOrigin,
    };
    use crate::analyzer::policy::source::{PolicySourceIdentity, parse_rqlp_source};
    use serde_json::json;

    fn path() -> WorkspaceRelativePath {
        WorkspaceRelativePath::new("src/app.rs").unwrap()
    }

    fn location() -> PolicySourceLocation {
        PolicySourceLocation::span(
            path(),
            PolicyByteSpan::new(4, 9).unwrap(),
            PolicyDisplayRegion::new(2, 3, 2, 8).unwrap(),
        )
    }

    fn call_terminal_at(location: PolicySourceLocation) -> PolicyQueryResultRef {
        PolicyQueryResultRef::CallSite {
            location,
            caller_fq_name: "crate::caller".to_string(),
            caller_identity: None,
            callee_fq_name: "crate::callee".to_string(),
            callee_identity: None,
            proof: PolicyQueryProof::Exact,
        }
    }

    fn call_terminal() -> PolicyQueryResultRef {
        call_terminal_at(location())
    }

    fn loaded_match_policy() -> LoadedPolicy {
        let source = include_str!("../../../tests/fixtures/policies/dynamic-eval.rqlp");
        let identity = PolicySourceIdentity::new("policy.rqlp");
        let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
        let schema_resolution = parsed.schema_resolution();
        let RqlpDocument::Policy { definition } = parsed.into_document() else {
            panic!("fixture must be a policy");
        };
        let definition = *definition;
        let PolicyAnalysis::Match { spec } = &definition.analysis else {
            panic!("fixture must be a match policy");
        };
        let PolicySelector::Inline { schema, query } = &spec.selector else {
            panic!("fixture selector must be inline");
        };
        let selector = ResolvedPolicySelector::try_new(
            super::super::definition::PolicySelectorPath::new("/analysis/selector").unwrap(),
            *schema,
            query.clone(),
            SelectorOrigin::Document {
                source: identity.clone(),
            },
        )
        .unwrap();
        LoadedPolicy::try_new(
            definition,
            identity,
            source.as_bytes(),
            schema_resolution,
            vec![selector],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PolicyPrecedenceManifest::default(),
            None,
            None,
        )
        .unwrap()
    }

    fn match_evidence() -> PolicyFindingEvidence {
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([4; 32])),
            0,
        )
        .unwrap();
        PolicyFindingEvidence::Match {
            evidence: MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor,
                call_terminal(),
                Vec::new(),
                false,
            )
            .unwrap(),
        }
    }

    fn unscored_cvss(
        vulnerability: VulnerabilityIdentity,
        source_scenarios: Vec<super::super::finding_identity::SourceScenarioId>,
        source_scenario_set_hash: SourceScenarioSetHash,
        include_conflict_record: bool,
    ) -> CvssAssessmentSet {
        let mut reasons = vec![CvssUnscoredReason::MissingBaseEvidence];
        if include_conflict_record {
            reasons.push(
                CvssUnscoredReason::conflicting_metric_evidence(
                    super::super::definition::CvssMetric::Base {
                        metric: CvssBaseMetric::Av,
                    },
                    CvssEvidenceSetHash::from_bytes([7; 32]),
                    vec![EvidenceRef::try_new("cvss", "conflict").unwrap()],
                    false,
                    0,
                )
                .unwrap(),
            );
        }
        let assessment = CvssAssessment::unscored(
            CvssVersion::V4_0,
            Vec::new(),
            vec![CvssBaseMetric::Av],
            reasons,
            CvssAssessmentProvenance::try_new(
                "bifrost.test".to_string(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
        let variant = CvssAssessmentVariant::try_new(
            vulnerability,
            source_scenarios,
            false,
            0,
            source_scenario_set_hash,
            Vec::new(),
            false,
            assessment,
        )
        .unwrap();
        CvssAssessmentSet::try_new(vec![variant], None).unwrap()
    }

    fn finding_with(
        loaded: &LoadedPolicy,
        evidence: PolicyFindingEvidence,
        witnesses: Vec<BoundedWitness>,
        cvss: Option<CvssAssessmentSet>,
        budget: &PolicyBudget,
    ) -> Result<PolicyFinding, PolicyFindingError> {
        PolicyFinding::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            FindingSeverity::Warning,
            "finding".to_string(),
            FindingClassification::Unclassified,
            FindingCertainty::Definite,
            FindingCompleteness::Complete,
            location(),
            Vec::new(),
            false,
            0,
            evidence,
            false,
            0,
            cvss,
            None,
            ProofMetadata::try_new(
                ProofState::Proven,
                vec![ProofReason::DirectStructuralMatch],
                Vec::new(),
            )
            .unwrap(),
            witnesses,
            false,
            0,
            budget,
        )
    }

    #[test]
    fn completion_is_typed_sorted_and_never_empty_when_non_complete() {
        assert_eq!(
            PolicyRunCompletion::inconclusive(vec![
                PolicyIncompleteReason::PipelineRowBudget,
                PolicyIncompleteReason::Cancelled,
                PolicyIncompleteReason::PipelineRowBudget,
            ])
            .unwrap(),
            PolicyRunCompletion::Inconclusive {
                reasons: vec![
                    PolicyIncompleteReason::Cancelled,
                    PolicyIncompleteReason::PipelineRowBudget,
                ]
            }
        );
        assert!(PolicyRunCompletion::inconclusive(Vec::new()).is_err());
        assert!(FindingCompleteness::partial(Vec::new()).is_err());
        assert_eq!(
            serde_json::to_value(PolicyRunCompletion::Complete).unwrap(),
            json!({ "type": "complete" })
        );
    }

    #[test]
    fn locations_require_paired_byte_and_display_ranges() {
        let artifact = PolicySourceLocation::artifact(path());
        assert!(artifact.is_artifact_only());
        assert_eq!(artifact.path(), "src/app.rs");
        assert_eq!(
            PolicySourceLocation::try_new(path(), Some(PolicyByteSpan::new(0, 1).unwrap()), None,)
                .unwrap_err(),
            PolicyLocationError::SpanRegionMismatch
        );
        assert!(PolicyByteSpan::new(2, 1).is_err());
        assert!(PolicyDisplayRegion::new(0, 1, 1, 1).is_err());
        assert!(PolicyDisplayRegion::new(2, 4, 2, 3).is_err());
        assert_eq!(
            serde_json::to_value(location()).unwrap(),
            json!({
                "path": "src/app.rs",
                "byte_span": { "start": 4, "end": 9 },
                "region": {
                    "start_line": 2,
                    "start_column": 3,
                    "end_line": 2,
                    "end_column": 8,
                }
            })
        );
    }

    #[test]
    fn match_evidence_rejects_anchor_terminal_mismatches_and_unbounded_provenance() {
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([4; 32])),
            0,
        )
        .unwrap();
        assert_eq!(
            MatchFindingEvidence::try_new(
                MatchResultDomain::Declaration,
                anchor.clone(),
                call_terminal(),
                Vec::new(),
                false,
            )
            .unwrap_err(),
            ReportValueError::AnchorDomainMismatch
        );
        assert_eq!(
            MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor.clone(),
                PolicyQueryResultRef::Declaration {
                    kind: "function".to_string(),
                    fq_name: "crate::callee".to_string(),
                    location: location(),
                    identity: None,
                },
                Vec::new(),
                false,
            )
            .unwrap_err(),
            ReportValueError::TerminalDomainMismatch
        );
        let other_location = PolicySourceLocation::span(
            WorkspaceRelativePath::new("src/other.rs").unwrap(),
            PolicyByteSpan::new(4, 9).unwrap(),
            PolicyDisplayRegion::new(2, 3, 2, 8).unwrap(),
        );
        assert_eq!(
            MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor.clone(),
                call_terminal_at(other_location),
                Vec::new(),
                false,
            )
            .unwrap_err(),
            ReportValueError::TerminalAnchorPathMismatch
        );
        assert_eq!(
            MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor.clone(),
                PolicyQueryResultRef::ReceiverAnalysis {
                    location: location(),
                    analysis_kind: "receiver_targets".to_string(),
                    outcome: "unknown".to_string(),
                    capture: None,
                },
                Vec::new(),
                false,
            )
            .unwrap_err(),
            ReportValueError::UnsupportedTerminalResult
        );

        let seed = PolicyQueryResultRef::file(path());
        let provenance = PolicyQueryProvenance::try_new(Vec::new(), seed, Vec::new()).unwrap();
        assert!(
            MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor,
                call_terminal(),
                vec![provenance; MAX_QUERY_PROVENANCE + 1],
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn finding_primary_must_equal_the_typed_terminal_location() {
        let loaded = loaded_match_policy();
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([4; 32])),
            0,
        )
        .unwrap();
        let terminal_location = PolicySourceLocation::span(
            path(),
            PolicyByteSpan::new(10, 15).unwrap(),
            PolicyDisplayRegion::new(3, 1, 3, 6).unwrap(),
        );
        let evidence = PolicyFindingEvidence::Match {
            evidence: MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor,
                call_terminal_at(terminal_location),
                Vec::new(),
                false,
            )
            .unwrap(),
        };

        assert_eq!(
            finding_with(
                &loaded,
                evidence,
                Vec::new(),
                None,
                &PolicyBudget::default(),
            )
            .unwrap_err(),
            PolicyFindingError::PrimaryTerminalLocationMismatch
        );
    }

    #[test]
    fn witness_truncation_is_explicit_and_bounded() {
        let witness_id = WitnessId::try_new("query", "path-1").unwrap();
        let step = WitnessStep::try_new(
            WitnessStepKind::Call,
            Some(location()),
            "resolved call",
            vec![EvidenceRef::try_new("query", "edge-1").unwrap()],
        )
        .unwrap();
        assert!(BoundedWitness::try_new(witness_id.clone(), vec![step.clone()], true, 0).is_err());
        let witness = BoundedWitness::try_new(witness_id, vec![step], true, 2).unwrap();
        assert!(witness.truncated());
        assert_eq!(witness.omitted_steps_lower_bound(), 2);
        assert_eq!(
            witness.retained_bytes(),
            u64::try_from(witness.retained_size()).unwrap()
        );
    }

    #[test]
    fn work_metrics_are_namespaced_sorted_and_unique() {
        let metrics = vec![
            PolicyWorkMetric::try_new("typestate.states", PolicyWorkUnit::Count, 2).unwrap(),
            PolicyWorkMetric::try_new("taint.propagation_states", PolicyWorkUnit::Count, 3)
                .unwrap(),
        ];
        let work = PolicyWorkReport::try_new(1, 2, 3, 4, 5, 6, 7, 8, metrics).unwrap();
        assert_eq!(work.metrics()[0].name(), "taint.propagation_states");
        assert!(PolicyWorkMetric::try_new("scanned_files", PolicyWorkUnit::Count, 1).is_err());
        let duplicate =
            PolicyWorkMetric::try_new("taint.propagation_states", PolicyWorkUnit::Rows, 4).unwrap();
        assert!(
            PolicyWorkReport::try_new(
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                vec![work.metrics()[0].clone(), duplicate],
            )
            .is_err()
        );
    }

    #[test]
    fn weak_match_anchor_remains_partial_evidence_not_a_stable_fingerprint() {
        let anchor = MatchFindingAnchor::weak(
            MatchResultDomain::CallSite,
            path(),
            OpaqueFindingKey::try_new("query", "run-key").unwrap(),
        );
        let evidence = MatchFindingEvidence::try_new(
            MatchResultDomain::CallSite,
            anchor,
            call_terminal(),
            Vec::new(),
            false,
        )
        .unwrap();
        assert_eq!(
            evidence.anchor().stability(),
            super::super::finding_identity::FindingIdentityStability::Weak
        );
        let completeness =
            FindingCompleteness::partial(vec![FindingIncompleteReason::StableAnchorWeak]).unwrap();
        assert!(!completeness.is_complete());
    }

    #[test]
    fn report_identifiers_require_ascii_alphanumeric_ends() {
        for value in [".rust", "rust.", "-rust", "rust-", "_rust", "rust_"] {
            assert!(
                PolicyCapability::query_feature(value, "query.feature").is_err(),
                "identifier {value}"
            );
        }
        assert!(PolicyCapability::query_feature("rust", "query.feature").is_ok());
    }

    #[test]
    fn query_result_refs_enforce_domain_locations_and_identity_paths() {
        let artifact = PolicySourceLocation::artifact(path());
        let artifact_structural = PolicyQueryResultRef::StructuralMatch {
            kind: "call".to_string(),
            location: artifact,
            identity: None,
        };
        assert_eq!(
            artifact_structural.validate().unwrap_err(),
            ReportValueError::ResultLocationMustHaveSpan
        );

        let cross_file_identity = StableSemanticIdentity::analyzer_declaration_id(
            "rust",
            WorkspaceRelativePath::new("src/target.rs").unwrap(),
            "function:crate::Target::run",
        )
        .unwrap();
        let structural = PolicyQueryResultRef::StructuralMatch {
            kind: "call".to_string(),
            location: location(),
            identity: Some(cross_file_identity.clone()),
        };
        assert_eq!(
            structural.validate().unwrap_err(),
            ReportValueError::StableIdentityPathMismatch
        );

        // A reference target may legitimately live in another file; it is not
        // the identity of the span-bearing reference site itself.
        let reference = PolicyQueryResultRef::ReferenceSite {
            location: location(),
            target_fq_name: "crate::Target::run".to_string(),
            target_identity: Some(cross_file_identity),
            usage_kind: Some("call".to_string()),
            proof: PolicyQueryProof::Resolved,
        };
        assert!(reference.validate().is_ok());
    }

    #[test]
    fn provenance_vectors_and_bytes_are_hard_bounded_and_tightly_retained() {
        assert!(matches!(
            PolicyQueryProvenance::try_new(
                vec![0; MAX_QUERY_BRANCH_DEPTH + 1],
                PolicyQueryResultRef::file(path()),
                Vec::new(),
            ),
            Err(ReportValueError::TooManyItems {
                field: "query_provenance_branch",
                ..
            })
        ));

        let step = PolicyQueryProvenanceStep::try_new(
            "query.step",
            PolicyQueryResultRef::file(path()),
            None,
        )
        .unwrap();
        assert!(matches!(
            PolicyQueryProvenance::try_new(
                Vec::new(),
                PolicyQueryResultRef::file(path()),
                vec![step; MAX_QUERY_PROVENANCE_STEPS + 1],
            ),
            Err(ReportValueError::TooManyItems {
                field: "query_provenance_steps",
                ..
            })
        ));

        let mut branch = Vec::with_capacity(4_096);
        branch.push(0);
        let compact =
            PolicyQueryProvenance::try_new(branch, PolicyQueryResultRef::file(path()), Vec::new())
                .unwrap();
        assert_eq!(compact.branch.capacity(), compact.branch.len());

        let large_trace = PolicyQueryProvenance::try_new(
            Vec::new(),
            PolicyQueryResultRef::ReferenceSite {
                location: location(),
                target_fq_name: "x".repeat(MAX_REPORT_PROSE_BYTES),
                target_identity: None,
                usage_kind: None,
                proof: PolicyQueryProof::NameBased,
            },
            Vec::new(),
        )
        .unwrap();
        let anchor = MatchFindingAnchor::strong(
            MatchResultDomain::CallSite,
            path(),
            None,
            Some(SourceSliceHash::from_bytes([9; 32])),
            0,
        )
        .unwrap();
        assert!(matches!(
            MatchFindingEvidence::try_new(
                MatchResultDomain::CallSite,
                anchor,
                call_terminal(),
                vec![large_trace; MAX_QUERY_PROVENANCE],
                false,
            ),
            Err(ReportValueError::TooManyBytes {
                field: "match_evidence",
                ..
            })
        ));
    }

    #[test]
    fn witness_step_evidence_refs_obey_lowered_finding_budget() {
        let loaded = loaded_match_policy();
        let step = WitnessStep::try_new(
            WitnessStepKind::Call,
            Some(location()),
            "call",
            vec![EvidenceRef::try_new("query", "edge").unwrap()],
        )
        .unwrap();
        let witness = BoundedWitness::try_new(
            WitnessId::try_new("query", "witness").unwrap(),
            vec![step],
            false,
            0,
        )
        .unwrap();
        let zero_refs = PolicyBudget::builder()
            .with_max_evidence_refs_per_finding(0)
            .unwrap()
            .build()
            .unwrap();
        assert!(matches!(
            finding_with(
                &loaded,
                match_evidence(),
                vec![witness.clone()],
                None,
                &zero_refs,
            ),
            Err(PolicyFindingError::Value(ReportValueError::TooManyItems {
                field: "finding_evidence_refs",
                ..
            }))
        ));

        let finding = finding_with(
            &loaded,
            match_evidence(),
            vec![witness],
            None,
            &PolicyBudget::default(),
        )
        .unwrap();
        let zero_steps = PolicyBudget::builder()
            .with_max_witness_steps(0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            PolicyRun::try_new(
                loaded.definition().metadata.id.clone(),
                loaded.semantic_hash(),
                PolicyAnalysisType::Match,
                PolicyRunCompletion::Complete,
                vec![finding.clone()],
                Vec::new(),
                false,
                PolicyWorkReport::default(),
                &zero_steps,
            )
            .unwrap_err(),
            PolicyRunError::FindingBudgetViolation
        );

        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            vec![finding],
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            &PolicyBudget::default(),
        )
        .unwrap();
        assert_eq!(
            run.validate_against_budget(&zero_steps).unwrap_err(),
            PolicyRunError::FindingBudgetViolation
        );
    }

    #[test]
    fn cvss_variants_must_join_the_finding_anchor_and_scenario_domain() {
        let loaded = loaded_match_policy();
        let evidence = match_evidence();
        let empty_hash = super::super::future_evidence::empty_source_scenario_set_hash();
        let wrong_identity = unscored_cvss(
            VulnerabilityIdentity::from_bytes([9; 32]),
            Vec::new(),
            empty_hash,
            false,
        );
        assert!(matches!(
            finding_with(
                &loaded,
                evidence.clone(),
                Vec::new(),
                Some(wrong_identity),
                &PolicyBudget::default(),
            ),
            Err(PolicyFindingError::CvssVulnerabilityIdentityMismatch)
        ));

        let PolicyFindingEvidence::Match {
            evidence: match_evidence,
        } = &evidence
        else {
            unreachable!()
        };
        let vulnerability = VulnerabilityIdentity::from_bytes(
            super::super::finding_identity::match_vulnerability_digest(match_evidence.anchor()),
        );
        let scenario =
            super::super::finding_identity::SourceScenarioId::try_new("taint", "s1").unwrap();
        let nonempty_hash =
            SourceScenarioSetHash::try_from_scenarios(vec![scenario.clone()]).unwrap();
        let wrong_scenario = unscored_cvss(vulnerability, vec![scenario], nonempty_hash, false);
        assert!(matches!(
            finding_with(
                &loaded,
                evidence,
                Vec::new(),
                Some(wrong_scenario),
                &PolicyBudget::default(),
            ),
            Err(PolicyFindingError::CvssSourceScenarioJoinMismatch)
        ));
    }

    #[test]
    fn adapter_revalidation_enforces_nested_cvss_record_budget() {
        let loaded = loaded_match_policy();
        let evidence = match_evidence();
        let PolicyFindingEvidence::Match {
            evidence: match_evidence,
        } = &evidence
        else {
            unreachable!()
        };
        let vulnerability = VulnerabilityIdentity::from_bytes(
            super::super::finding_identity::match_vulnerability_digest(match_evidence.anchor()),
        );
        let cvss = unscored_cvss(
            vulnerability,
            Vec::new(),
            super::super::future_evidence::empty_source_scenario_set_hash(),
            true,
        );
        let finding = finding_with(
            &loaded,
            evidence,
            Vec::new(),
            Some(cvss),
            &PolicyBudget::default(),
        )
        .unwrap();
        let run = PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
            vec![finding],
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            &PolicyBudget::default(),
        )
        .unwrap();
        let no_cvss_records = PolicyBudget::builder()
            .with_max_cvss_evidence_records_per_finding(0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            run.validate_against_budget(&no_cvss_records).unwrap_err(),
            PolicyRunError::FindingBudgetViolation
        );
    }

    #[test]
    fn policy_run_constructor_enforces_retained_cap_after_refresh() {
        let loaded = loaded_match_policy();
        let construct = |budget: &PolicyBudget| {
            PolicyRun::try_new(
                loaded.definition().metadata.id.clone(),
                loaded.semantic_hash(),
                PolicyAnalysisType::Match,
                PolicyRunCompletion::Complete,
                Vec::new(),
                Vec::new(),
                false,
                PolicyWorkReport::default(),
                budget,
            )
        };
        let baseline = construct(&PolicyBudget::default()).expect("baseline run");
        let retained_bytes = baseline.retained_size();
        assert_eq!(
            baseline.work().retained_report_bytes(),
            u64::try_from(retained_bytes).unwrap()
        );

        let exact = PolicyBudget::builder()
            .with_max_retained_report_bytes(retained_bytes)
            .unwrap()
            .build()
            .unwrap();
        assert!(construct(&exact).is_ok());

        let too_tight = retained_bytes - 1;
        let budget = PolicyBudget::builder()
            .with_max_retained_report_bytes(too_tight)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            construct(&budget).unwrap_err(),
            PolicyRunError::RetainedReportBytesExceeded { max: too_tight }
        );
    }

    #[test]
    fn complete_run_cannot_claim_truncated_diagnostics() {
        let loaded = loaded_match_policy();
        assert_eq!(
            PolicyRun::try_new(
                loaded.definition().metadata.id.clone(),
                loaded.semantic_hash(),
                PolicyAnalysisType::Match,
                PolicyRunCompletion::Complete,
                Vec::new(),
                Vec::new(),
                true,
                PolicyWorkReport::default(),
                &PolicyBudget::default(),
            )
            .unwrap_err(),
            PolicyRunError::CompletionDoesNotReflectDiagnostics
        );
    }

    #[test]
    fn bounded_diagnostic_insertion_deduplicates_before_applying_the_cap() {
        let diagnostic = |message: &str| {
            PolicyDiagnostic::try_new(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                message,
                None,
                Vec::new(),
            )
            .unwrap()
        };
        let mut retained = Vec::new();
        assert!(!insert_policy_diagnostic_bounded(
            &mut retained,
            diagnostic("same cause"),
            1,
        ));
        assert!(!insert_policy_diagnostic_bounded(
            &mut retained,
            diagnostic("same cause"),
            1,
        ));
        assert_eq!(retained.len(), 1);

        retained.clear();
        assert!(!insert_policy_diagnostic_bounded(
            &mut retained,
            diagnostic("z cause"),
            1,
        ));
        assert!(insert_policy_diagnostic_bounded(
            &mut retained,
            diagnostic("a cause"),
            1,
        ));
        assert_eq!(retained[0].message(), "a cause");
    }
}
