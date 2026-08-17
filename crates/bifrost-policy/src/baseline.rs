//! Bounded, capability-confined bulk baseline-acceptance documents (#1881).
//!
//! A baseline document accepts every finding that exists at one explicit
//! acceptance point so later runs gate only on what appears afterwards. It is
//! deliberately a separate document kind from the suppression store: entries
//! are identity-only (strong finding-id hashes grouped per policy), and the
//! prose burden is one batch-level reason instead of one reason per record.
//!
//! Cap rationale. The size target is tens of thousands of entries, two decimal
//! orders above the 512-record suppression cap. [`MAX_POLICY_BASELINE_ENTRIES`]
//! is 100,000: comfortably above a 50k-finding onboarding while still loading
//! in milliseconds, and far above the 10,000 retained-findings-per-batch cap
//! that bounds what one generation run can produce (the headroom admits a
//! hand-merged multi-selection document). One pretty-printed entry line costs
//! about 80 bytes (64 hex digits plus quotes, comma, and indentation), so
//! 100,000 entries encode in about 8 MiB;
//! [`MAX_POLICY_BASELINE_DOCUMENT_BYTES`] doubles that to 16 MiB for metadata
//! and formatting slack.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use brokk_bifrost_analysis::analyzer::semantic::{
    WorkspaceRelativePath, WorkspaceRelativePathError,
};
use brokk_bifrost_analysis::workspace_document::{
    WorkspaceDocumentError, WorkspaceRoot, read_workspace_document,
};

use super::classification::{TextValidationError, validate_required_text};
use super::definition::{PolicyId, PolicyIdentifierError, Sha256ValueError};
use super::finding_identity::PolicyFindingId;
use super::report::PolicyReportDocument;
use super::retained::{RetainedSize, retained_extra};
use super::suppression::{
    AcceptedPolicyHash, PolicyEvaluationDate, PolicySuppressionPolicyHashState,
    bounded_json_error_message, workspace_error_is_not_found,
};

pub const DEFAULT_POLICY_BASELINE_PATH: &str = ".bifrost/baseline.json";
pub const MAX_POLICY_BASELINE_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_POLICY_BASELINE_ENTRIES: usize = 100_000;
pub const MAX_POLICY_BASELINE_REASON_BYTES: usize = 4_096;
pub const MAX_POLICY_BASELINE_ACCEPTED_BY_BYTES: usize = 256;
pub const MAX_POLICY_BASELINE_PATH_BYTES: usize = 1_024;

/// Upper bound on retained per-entry audit reviews in one baseline review.
///
/// The per-state counts always stay exact; only the entry list truncates,
/// mirroring the diff review's fixed-finding list.
pub(crate) const MAX_BASELINE_REVIEW_ENTRIES: usize = 256;

const POLICY_BASELINE_SCHEMA_VERSION: u32 = 1;

/// One policy's accepted strong finding identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBaselinePolicyRecord {
    policy_id: PolicyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_hash_at_acceptance: Option<AcceptedPolicyHash>,
    finding_ids: Box<[PolicyFindingId]>,
}

impl PolicyBaselinePolicyRecord {
    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub const fn policy_hash_at_acceptance(&self) -> Option<AcceptedPolicyHash> {
        self.policy_hash_at_acceptance
    }

    pub fn finding_ids(&self) -> &[PolicyFindingId] {
        &self.finding_ids
    }
}

/// Canonically sorted schema-version-one baseline document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBaselineDocument {
    schema_version: u32,
    reason: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_by: Option<Box<str>>,
    accepted_at: PolicyEvaluationDate,
    policies: Box<[PolicyBaselinePolicyRecord]>,
}

impl PolicyBaselineDocument {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn accepted_by(&self) -> Option<&str> {
        self.accepted_by.as_deref()
    }

    pub const fn accepted_at(&self) -> PolicyEvaluationDate {
        self.accepted_at
    }

    pub fn policies(&self) -> &[PolicyBaselinePolicyRecord] {
        &self.policies
    }

    pub fn entry_count(&self) -> usize {
        self.policies
            .iter()
            .map(|policy| policy.finding_ids.len())
            .sum()
    }

    /// Build a baseline from one completed run's report: every strong finding
    /// not already claimed by a suppression or scope decision is accepted, and
    /// the count of excluded weak-identity findings is returned beside the
    /// document.
    ///
    /// The caller owns the reliability rule: only a run whose exit status is
    /// clean may define a baseline, because an omitted or unproven finding
    /// cannot be accepted by identity.
    pub fn from_completed_report(
        report: &PolicyReportDocument,
        reason: &str,
        accepted_by: Option<&str>,
        accepted_at: PolicyEvaluationDate,
    ) -> Result<(Self, u64), PolicyBaselineValidationError> {
        validate_reason(reason)?;
        if let Some(accepted_by) = accepted_by {
            validate_accepted_by(accepted_by)?;
        }
        let mut weak_excluded = 0_u64;
        let mut policies = Vec::new();
        for run in report.runs() {
            let mut finding_ids = Vec::new();
            for finding in run.findings() {
                if finding.identity_stability()
                    != super::finding_identity::FindingIdentityStability::Strong
                {
                    weak_excluded = weak_excluded.saturating_add(1);
                    continue;
                }
                if finding.suppression().is_some() || finding.scope().is_some() {
                    continue;
                }
                finding_ids.push(finding.id());
            }
            if finding_ids.is_empty() {
                continue;
            }
            finding_ids.sort();
            policies.push(PolicyBaselinePolicyRecord {
                policy_id: run.policy_id().clone(),
                policy_hash_at_acceptance: Some(AcceptedPolicyHash::from_bytes(
                    *run.policy_hash().as_bytes(),
                )),
                finding_ids: finding_ids.into_boxed_slice(),
            });
        }
        policies.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        let document = Self {
            schema_version: POLICY_BASELINE_SCHEMA_VERSION,
            reason: reason.into(),
            accepted_by: accepted_by.map(Into::into),
            accepted_at,
            policies: policies.into_boxed_slice(),
        };
        assert!(
            document.entry_count() <= MAX_POLICY_BASELINE_ENTRIES,
            "one report cannot exceed the baseline entry cap: {} > {MAX_POLICY_BASELINE_ENTRIES}",
            document.entry_count()
        );
        Ok((document, weak_excluded))
    }

    /// The canonical on-disk encoding: pretty-printed JSON plus one trailing
    /// newline, guaranteed to re-load within the document caps.
    pub fn to_canonical_json(&self) -> String {
        let mut encoded =
            serde_json::to_string_pretty(self).expect("baseline document serializes to JSON");
        encoded.push('\n');
        assert!(
            u64::try_from(encoded.len()).unwrap_or(u64::MAX) <= MAX_POLICY_BASELINE_DOCUMENT_BYTES,
            "a capped baseline document encodes within the document byte cap"
        );
        encoded
    }
}

/// Location used to load one baseline document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicyBaselineSource {
    #[default]
    Conventional,
    Explicit(WorkspaceRelativePath),
}

impl PolicyBaselineSource {
    pub fn explicit(path: impl AsRef<Path>) -> Result<Self, PolicyBaselineSourceError> {
        Self::from_workspace_path(WorkspaceRelativePath::try_from_path(path.as_ref())?)
    }

    pub fn explicit_portable(path: impl AsRef<str>) -> Result<Self, PolicyBaselineSourceError> {
        Self::from_workspace_path(WorkspaceRelativePath::new(path)?)
    }

    pub fn relative_path(&self) -> &str {
        match self {
            Self::Conventional => DEFAULT_POLICY_BASELINE_PATH,
            Self::Explicit(path) => path.as_str(),
        }
    }

    fn from_workspace_path(path: WorkspaceRelativePath) -> Result<Self, PolicyBaselineSourceError> {
        if path.as_str().len() > MAX_POLICY_BASELINE_PATH_BYTES {
            return Err(PolicyBaselineSourceError::TooLong {
                max_bytes: MAX_POLICY_BASELINE_PATH_BYTES,
            });
        }
        Ok(Self::Explicit(path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyBaselineOptions {
    source: PolicyBaselineSource,
}

impl PolicyBaselineOptions {
    pub const fn new(source: PolicyBaselineSource) -> Self {
        Self { source }
    }

    pub const fn source(&self) -> &PolicyBaselineSource {
        &self.source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBaselineSourceError {
    Path(WorkspaceRelativePathError),
    TooLong { max_bytes: usize },
}

impl From<WorkspaceRelativePathError> for PolicyBaselineSourceError {
    fn from(error: WorkspaceRelativePathError) -> Self {
        Self::Path(error)
    }
}

impl fmt::Display for PolicyBaselineSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => error.fmt(formatter),
            Self::TooLong { max_bytes } => {
                write!(formatter, "baseline path must be at most {max_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for PolicyBaselineSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::TooLong { .. } => None,
        }
    }
}

/// Open a workspace capability once, then load and normalize its configured
/// baseline document. Only an actual missing file maps to `Ok(None)`.
pub fn load_policy_baseline(
    workspace_root: &Path,
    options: &PolicyBaselineOptions,
) -> Result<Option<PolicyBaselineDocument>, PolicyBaselineLoadError> {
    let root = WorkspaceRoot::open(workspace_root).map_err(PolicyBaselineLoadError::Workspace)?;
    load_policy_baseline_from_root(&root, options)
}

pub(crate) fn load_policy_baseline_from_root(
    root: &WorkspaceRoot,
    options: &PolicyBaselineOptions,
) -> Result<Option<PolicyBaselineDocument>, PolicyBaselineLoadError> {
    let relative_path = Path::new(options.source.relative_path());
    let document = match read_workspace_document(
        root,
        relative_path,
        &["json"],
        MAX_POLICY_BASELINE_DOCUMENT_BYTES,
    ) {
        Ok(document) => document,
        Err(error) if workspace_error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(PolicyBaselineLoadError::Workspace(error)),
    };
    parse_policy_baseline_document(document.source())
        .map(Some)
        .map_err(PolicyBaselineLoadError::Document)
}

pub fn parse_policy_baseline_document(
    source: &str,
) -> Result<PolicyBaselineDocument, PolicyBaselineDocumentError> {
    if u64::try_from(source.len()).unwrap_or(u64::MAX) > MAX_POLICY_BASELINE_DOCUMENT_BYTES {
        return Err(PolicyBaselineDocumentError::Validation(
            PolicyBaselineValidationError::DocumentTooLarge {
                max_bytes: MAX_POLICY_BASELINE_DOCUMENT_BYTES,
            },
        ));
    }
    let wire = serde_json::from_str::<WireBaselineDocument>(source).map_err(|error| {
        PolicyBaselineDocumentError::JsonDecode {
            message: bounded_json_error_message(&error.to_string()),
            line: error.line(),
            column: error.column(),
        }
    })?;
    normalize_wire_document(wire).map_err(PolicyBaselineDocumentError::Validation)
}

fn normalize_wire_document(
    wire: WireBaselineDocument,
) -> Result<PolicyBaselineDocument, PolicyBaselineValidationError> {
    if wire.schema_version != u64::from(POLICY_BASELINE_SCHEMA_VERSION) {
        return Err(PolicyBaselineValidationError::UnsupportedSchemaVersion {
            observed: wire.schema_version,
        });
    }
    validate_reason(&wire.reason)?;
    if let Some(accepted_by) = wire.accepted_by.as_deref() {
        validate_accepted_by(accepted_by)?;
    }
    let accepted_at = wire
        .accepted_at
        .parse()
        .map_err(|source| PolicyBaselineValidationError::InvalidAcceptedAt { source })?;

    let mut entry_count = 0_usize;
    let mut policies = Vec::with_capacity(wire.policies.len());
    for (policy_index, policy) in wire.policies.into_iter().enumerate() {
        let policy_id = PolicyId::new(&policy.policy_id).map_err(|source| {
            PolicyBaselineValidationError::InvalidPolicyId {
                policy_index,
                source,
            }
        })?;
        let policy_hash_at_acceptance = policy
            .policy_hash_at_acceptance
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(
                |source| PolicyBaselineValidationError::InvalidAcceptedPolicyHash {
                    policy_index,
                    source,
                },
            )?;
        entry_count = entry_count.saturating_add(policy.finding_ids.len());
        if entry_count > MAX_POLICY_BASELINE_ENTRIES {
            return Err(PolicyBaselineValidationError::TooManyEntries {
                max: MAX_POLICY_BASELINE_ENTRIES,
            });
        }
        let mut finding_ids = Vec::with_capacity(policy.finding_ids.len());
        for (entry_index, finding_id) in policy.finding_ids.iter().enumerate() {
            finding_ids.push(finding_id.parse::<PolicyFindingId>().map_err(|source| {
                PolicyBaselineValidationError::InvalidFindingId {
                    policy_index,
                    entry_index,
                    source,
                }
            })?);
        }
        finding_ids.sort();
        if let Some(duplicate) = finding_ids
            .windows(2)
            .find(|pair| pair[0] == pair[1])
            .map(|pair| pair[0])
        {
            return Err(PolicyBaselineValidationError::DuplicateFindingId {
                policy_id,
                finding_id: duplicate,
            });
        }
        policies.push(PolicyBaselinePolicyRecord {
            policy_id,
            policy_hash_at_acceptance,
            finding_ids: finding_ids.into_boxed_slice(),
        });
    }
    policies.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
    if let Some(duplicate) = policies
        .windows(2)
        .find(|pair| pair[0].policy_id == pair[1].policy_id)
    {
        return Err(PolicyBaselineValidationError::DuplicatePolicy {
            policy_id: duplicate[0].policy_id.clone(),
        });
    }
    Ok(PolicyBaselineDocument {
        schema_version: POLICY_BASELINE_SCHEMA_VERSION,
        reason: wire.reason.into_boxed_str(),
        accepted_by: wire.accepted_by.map(String::into_boxed_str),
        accepted_at,
        policies: policies.into_boxed_slice(),
    })
}

fn validate_reason(reason: &str) -> Result<(), PolicyBaselineValidationError> {
    validate_required_text(reason, MAX_POLICY_BASELINE_REASON_BYTES)
        .map_err(|source| PolicyBaselineValidationError::InvalidReason { source })?;
    if reason.trim().is_empty() {
        return Err(PolicyBaselineValidationError::BlankReason);
    }
    Ok(())
}

fn validate_accepted_by(accepted_by: &str) -> Result<(), PolicyBaselineValidationError> {
    validate_required_text(accepted_by, MAX_POLICY_BASELINE_ACCEPTED_BY_BYTES)
        .map_err(|source| PolicyBaselineValidationError::InvalidAcceptedBy { source })?;
    if accepted_by.trim().is_empty() {
        return Err(PolicyBaselineValidationError::BlankAcceptedBy);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBaselineDocument {
    schema_version: u64,
    reason: String,
    accepted_by: Option<String>,
    accepted_at: String,
    policies: Vec<WireBaselinePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBaselinePolicy {
    policy_id: String,
    policy_hash_at_acceptance: Option<String>,
    finding_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBaselineDocumentError {
    JsonDecode {
        message: Box<str>,
        line: usize,
        column: usize,
    },
    Validation(PolicyBaselineValidationError),
}

impl fmt::Display for PolicyBaselineDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonDecode {
                message,
                line,
                column,
            } => write!(
                formatter,
                "invalid baseline JSON at line {line}, column {column}: {message}"
            ),
            Self::Validation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyBaselineDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JsonDecode { .. } => None,
            Self::Validation(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBaselineValidationError {
    DocumentTooLarge {
        max_bytes: u64,
    },
    UnsupportedSchemaVersion {
        observed: u64,
    },
    TooManyEntries {
        max: usize,
    },
    InvalidReason {
        source: TextValidationError,
    },
    BlankReason,
    InvalidAcceptedBy {
        source: TextValidationError,
    },
    BlankAcceptedBy,
    InvalidAcceptedAt {
        source: super::suppression::PolicyDateError,
    },
    InvalidPolicyId {
        policy_index: usize,
        source: PolicyIdentifierError,
    },
    InvalidAcceptedPolicyHash {
        policy_index: usize,
        source: Sha256ValueError,
    },
    InvalidFindingId {
        policy_index: usize,
        entry_index: usize,
        source: Sha256ValueError,
    },
    DuplicatePolicy {
        policy_id: PolicyId,
    },
    DuplicateFindingId {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
}

impl fmt::Display for PolicyBaselineValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { max_bytes } => {
                write!(formatter, "baseline document exceeds {max_bytes} bytes")
            }
            Self::UnsupportedSchemaVersion { observed } => write!(
                formatter,
                "unsupported baseline schema version {observed}; expected {POLICY_BASELINE_SCHEMA_VERSION}"
            ),
            Self::TooManyEntries { max } => {
                write!(
                    formatter,
                    "baseline document may contain at most {max} finding entries"
                )
            }
            Self::InvalidReason { source } => {
                write!(formatter, "baseline has an invalid reason: {source}")
            }
            Self::BlankReason => formatter.write_str("baseline reason must not be blank"),
            Self::InvalidAcceptedBy { source } => {
                write!(formatter, "baseline has invalid accepted_by text: {source}")
            }
            Self::BlankAcceptedBy => {
                formatter.write_str("baseline accepted_by must not be blank when present")
            }
            Self::InvalidAcceptedAt { source } => {
                write!(formatter, "baseline has invalid accepted_at: {source}")
            }
            Self::InvalidPolicyId {
                policy_index,
                source,
            } => write!(
                formatter,
                "baseline policy {policy_index} has an invalid policy_id: {source}"
            ),
            Self::InvalidAcceptedPolicyHash {
                policy_index,
                source,
            } => write!(
                formatter,
                "baseline policy {policy_index} has invalid policy_hash_at_acceptance: {source}"
            ),
            Self::InvalidFindingId {
                policy_index,
                entry_index,
                source,
            } => write!(
                formatter,
                "baseline policy {policy_index} entry {entry_index} has an invalid finding id: {source}"
            ),
            Self::DuplicatePolicy { policy_id } => {
                write!(formatter, "duplicate baseline policy {policy_id}")
            }
            Self::DuplicateFindingId {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "duplicate baseline finding {finding_id} for policy {policy_id}"
            ),
        }
    }
}

impl std::error::Error for PolicyBaselineValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidReason { source } | Self::InvalidAcceptedBy { source } => Some(source),
            Self::InvalidAcceptedAt { source } => Some(source),
            Self::InvalidPolicyId { source, .. } => Some(source),
            Self::InvalidAcceptedPolicyHash { source, .. }
            | Self::InvalidFindingId { source, .. } => Some(source),
            Self::DocumentTooLarge { .. }
            | Self::UnsupportedSchemaVersion { .. }
            | Self::TooManyEntries { .. }
            | Self::BlankReason
            | Self::BlankAcceptedBy
            | Self::DuplicatePolicy { .. }
            | Self::DuplicateFindingId { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum PolicyBaselineLoadError {
    Workspace(WorkspaceDocumentError),
    Document(PolicyBaselineDocumentError),
}

impl fmt::Display for PolicyBaselineLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Document(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyBaselineLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::Document(error) => Some(error),
        }
    }
}

/// How one baseline entry joined the current run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBaselineMatchState {
    /// The entry matched a retained strong finding and claimed it.
    StrongFinding,
    /// The finding exists but a suppression or scope decision already claimed
    /// it; the baseline defers to the governed mechanism.
    FindingClaimed,
    /// The matching finding's identity is not strong, so the baseline cannot
    /// claim it.
    CurrentFindingNotStrong,
    /// An exhaustive completed run proved the finding absent; the entry is
    /// stale.
    FindingAbsent,
    /// The entry's policy was not part of this evaluation.
    PolicyNotEvaluated,
    /// The entry's policy ran but not exhaustively, so absence is unproven.
    PolicyIncomplete,
}

/// Active accepted-decision metadata attached to a retained baselined finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFindingBaseline {
    reason: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_by: Option<Box<str>>,
    accepted_at: PolicyEvaluationDate,
    policy_hash_state: PolicySuppressionPolicyHashState,
}

impl PolicyFindingBaseline {
    pub(crate) fn new(
        document: &PolicyBaselineDocument,
        policy_hash_state: PolicySuppressionPolicyHashState,
    ) -> Self {
        Self {
            reason: document.reason.clone(),
            accepted_by: document.accepted_by.clone(),
            accepted_at: document.accepted_at,
            policy_hash_state,
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn accepted_by(&self) -> Option<&str> {
        self.accepted_by.as_deref()
    }

    pub const fn accepted_at(&self) -> PolicyEvaluationDate {
        self.accepted_at
    }

    pub const fn policy_hash_state(&self) -> PolicySuppressionPolicyHashState {
        self.policy_hash_state
    }
}

/// Canonical audit disposition for one loaded baseline entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBaselineEntryReview {
    policy_id: PolicyId,
    finding_id: PolicyFindingId,
    match_state: PolicyBaselineMatchState,
    policy_hash_state: PolicySuppressionPolicyHashState,
    applied: bool,
    stale: bool,
    result_omitted: bool,
}

impl PolicyBaselineEntryReview {
    pub(crate) fn new(
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
        match_state: PolicyBaselineMatchState,
        policy_hash_state: PolicySuppressionPolicyHashState,
    ) -> Self {
        Self {
            policy_id,
            finding_id,
            match_state,
            policy_hash_state,
            applied: match_state == PolicyBaselineMatchState::StrongFinding,
            stale: match_state == PolicyBaselineMatchState::FindingAbsent,
            result_omitted: false,
        }
    }

    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub const fn finding_id(&self) -> PolicyFindingId {
        self.finding_id
    }

    pub const fn match_state(&self) -> PolicyBaselineMatchState {
        self.match_state
    }

    pub const fn policy_hash_state(&self) -> PolicySuppressionPolicyHashState {
        self.policy_hash_state
    }

    pub const fn applied(&self) -> bool {
        self.applied
    }

    pub const fn stale(&self) -> bool {
        self.stale
    }

    pub const fn result_omitted(&self) -> bool {
        self.result_omitted
    }
}

/// Top-level audit of one baseline-aware evaluation.
///
/// Present only when a baseline document loaded, so a run without one keeps
/// its exact schema-version-3 shape. Every count is exact over the complete
/// document; the `entries` list is bounded and retains only entries that need
/// attention (anything other than applied-with-matching-hash), so a 100k-entry
/// onboarding audit stays within the retained-report budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBaselineReview {
    document_path: Box<str>,
    reason: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_by: Option<Box<str>>,
    accepted_at: PolicyEvaluationDate,
    entry_count: u64,
    applied_count: u64,
    claimed_count: u64,
    not_strong_count: u64,
    stale_count: u64,
    policy_not_evaluated_count: u64,
    policy_incomplete_count: u64,
    drifted_count: u64,
    result_omitted_count: u64,
    entries: Vec<PolicyBaselineEntryReview>,
    entries_truncated: bool,
}

impl PolicyBaselineReview {
    /// Fold the complete entry-review vector into exact counts plus the
    /// bounded needs-attention list. `entries` must arrive in the document's
    /// canonical order (policies sorted by id, finding ids sorted).
    pub(crate) fn new(
        document_path: &str,
        document: &PolicyBaselineDocument,
        entries: Vec<PolicyBaselineEntryReview>,
    ) -> Self {
        assert_eq!(
            entries.len(),
            document.entry_count(),
            "every baseline entry is reviewed exactly once"
        );
        let count = |state: PolicyBaselineMatchState| {
            u64::try_from(
                entries
                    .iter()
                    .filter(|entry| entry.match_state == state)
                    .count(),
            )
            .expect("bounded entry count fits u64")
        };
        let applied_count = count(PolicyBaselineMatchState::StrongFinding);
        let claimed_count = count(PolicyBaselineMatchState::FindingClaimed);
        let not_strong_count = count(PolicyBaselineMatchState::CurrentFindingNotStrong);
        let stale_count = count(PolicyBaselineMatchState::FindingAbsent);
        let policy_not_evaluated_count = count(PolicyBaselineMatchState::PolicyNotEvaluated);
        let policy_incomplete_count = count(PolicyBaselineMatchState::PolicyIncomplete);
        let drifted_count = u64::try_from(
            entries
                .iter()
                .filter(|entry| {
                    entry.policy_hash_state == PolicySuppressionPolicyHashState::Drifted
                })
                .count(),
        )
        .expect("bounded entry count fits u64");
        let entry_count = u64::try_from(entries.len()).expect("bounded entry count fits u64");
        assert_eq!(
            entry_count,
            applied_count
                + claimed_count
                + not_strong_count
                + stale_count
                + policy_not_evaluated_count
                + policy_incomplete_count,
            "baseline match states partition the entries"
        );
        let mut notable = entries
            .into_iter()
            .filter(|entry| {
                !(entry.applied
                    && entry.policy_hash_state == PolicySuppressionPolicyHashState::Matching)
            })
            .collect::<Vec<_>>();
        let entries_truncated = notable.len() > MAX_BASELINE_REVIEW_ENTRIES;
        notable.truncate(MAX_BASELINE_REVIEW_ENTRIES);
        notable.shrink_to_fit();
        Self {
            document_path: document_path.into(),
            reason: document.reason.clone(),
            accepted_by: document.accepted_by.clone(),
            accepted_at: document.accepted_at,
            entry_count,
            applied_count,
            claimed_count,
            not_strong_count,
            stale_count,
            policy_not_evaluated_count,
            policy_incomplete_count,
            drifted_count,
            result_omitted_count: 0,
            entries: notable,
            entries_truncated,
        }
    }

    pub fn document_path(&self) -> &str {
        &self.document_path
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn accepted_by(&self) -> Option<&str> {
        self.accepted_by.as_deref()
    }

    pub const fn accepted_at(&self) -> PolicyEvaluationDate {
        self.accepted_at
    }

    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub const fn applied_count(&self) -> u64 {
        self.applied_count
    }

    pub const fn claimed_count(&self) -> u64 {
        self.claimed_count
    }

    pub const fn not_strong_count(&self) -> u64 {
        self.not_strong_count
    }

    pub const fn stale_count(&self) -> u64 {
        self.stale_count
    }

    pub const fn policy_not_evaluated_count(&self) -> u64 {
        self.policy_not_evaluated_count
    }

    pub const fn policy_incomplete_count(&self) -> u64 {
        self.policy_incomplete_count
    }

    pub const fn drifted_count(&self) -> u64 {
        self.drifted_count
    }

    pub const fn result_omitted_count(&self) -> u64 {
        self.result_omitted_count
    }

    pub fn entries(&self) -> &[PolicyBaselineEntryReview] {
        &self.entries
    }

    pub const fn entries_truncated(&self) -> bool {
        self.entries_truncated
    }

    /// Record that a baselined finding's result was dropped by the retention
    /// budget. The count stays exact even when the entry is outside the
    /// bounded needs-attention list; the per-entry flag flips only for
    /// retained entries.
    pub(crate) fn mark_result_omitted(
        &mut self,
        policy_id: &PolicyId,
        finding_id: PolicyFindingId,
    ) {
        self.result_omitted_count = self.result_omitted_count.saturating_add(1);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.policy_id == *policy_id && entry.finding_id == finding_id)
        {
            entry.result_omitted = true;
        }
    }
}

impl RetainedSize for PolicyBaselinePolicyRecord {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(std::mem::size_of_val::<[PolicyFindingId]>(
                &self.finding_ids,
            ))
    }
}

impl RetainedSize for PolicyBaselineDocument {
    fn retained_size(&self) -> usize {
        self.policies.iter().fold(
            std::mem::size_of::<Self>()
                .saturating_add(self.reason.len())
                .saturating_add(self.accepted_by.as_deref().map_or(0, str::len)),
            |bytes, policy| bytes.saturating_add(policy.retained_size()),
        )
    }
}

impl RetainedSize for PolicyBaselineSource {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Conventional => 0,
            Self::Explicit(path) => retained_extra(path),
        })
    }
}

impl RetainedSize for PolicyBaselineOptions {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(retained_extra(&self.source))
    }
}

impl RetainedSize for PolicyFindingBaseline {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.reason.len())
            .saturating_add(self.accepted_by.as_deref().map_or(0, str::len))
    }
}

impl RetainedSize for PolicyBaselineEntryReview {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(retained_extra(&self.policy_id))
    }
}

impl RetainedSize for PolicyBaselineReview {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.document_path.len())
            .saturating_add(self.reason.len())
            .saturating_add(self.accepted_by.as_deref().map_or(0, str::len))
            .saturating_add(retained_extra(&self.entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_document(policies: serde_json::Value) -> String {
        json!({
            "schema_version": 1,
            "reason": "Onboarding acceptance",
            "accepted_by": "platform-team",
            "accepted_at": "2026-08-08",
            "policies": policies,
        })
        .to_string()
    }

    fn finding_id_hex(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn canonical_document_round_trips_with_sorted_policies_and_ids() {
        let source = valid_document(json!([
            {
                "policy_id": "test.b-policy",
                "policy_hash_at_acceptance": "1".repeat(64),
                "finding_ids": [finding_id_hex(0xbb), finding_id_hex(0xaa)],
            },
            {
                "policy_id": "test.a-policy",
                "finding_ids": [finding_id_hex(0xcc)],
            },
        ]));
        let document = parse_policy_baseline_document(&source).expect("valid document");
        assert_eq!(document.schema_version(), 1);
        assert_eq!(document.reason(), "Onboarding acceptance");
        assert_eq!(document.accepted_by(), Some("platform-team"));
        assert_eq!(document.entry_count(), 3);
        assert_eq!(document.policies()[0].policy_id().as_str(), "test.a-policy");
        assert_eq!(document.policies()[1].policy_id().as_str(), "test.b-policy");
        let ids = document.policies()[1].finding_ids();
        assert!(ids[0] < ids[1], "finding ids are canonically sorted");

        let encoded = document.to_canonical_json();
        let reparsed = parse_policy_baseline_document(&encoded).expect("canonical round trip");
        assert_eq!(reparsed, document);
    }

    #[test]
    fn malformed_documents_are_typed_rejections() {
        assert!(matches!(
            parse_policy_baseline_document("{ not json"),
            Err(PolicyBaselineDocumentError::JsonDecode { .. })
        ));
        assert!(matches!(
            parse_policy_baseline_document(
                &json!({
                    "schema_version": 2,
                    "reason": "r",
                    "accepted_at": "2026-08-08",
                    "policies": [],
                })
                .to_string()
            ),
            Err(PolicyBaselineDocumentError::Validation(
                PolicyBaselineValidationError::UnsupportedSchemaVersion { observed: 2 }
            ))
        ));
        assert!(matches!(
            parse_policy_baseline_document(&valid_document(json!([
                { "policy_id": "test.p", "finding_ids": ["zz"] }
            ]))),
            Err(PolicyBaselineDocumentError::Validation(
                PolicyBaselineValidationError::InvalidFindingId {
                    policy_index: 0,
                    entry_index: 0,
                    ..
                }
            ))
        ));
        assert!(matches!(
            parse_policy_baseline_document(&valid_document(json!([
                {
                    "policy_id": "test.p",
                    "finding_ids": [finding_id_hex(0xaa), finding_id_hex(0xaa)]
                }
            ]))),
            Err(PolicyBaselineDocumentError::Validation(
                PolicyBaselineValidationError::DuplicateFindingId { .. }
            ))
        ));
        assert!(matches!(
            parse_policy_baseline_document(&valid_document(json!([
                { "policy_id": "test.p", "finding_ids": [finding_id_hex(0xaa)] },
                { "policy_id": "test.p", "finding_ids": [finding_id_hex(0xbb)] },
            ]))),
            Err(PolicyBaselineDocumentError::Validation(
                PolicyBaselineValidationError::DuplicatePolicy { .. }
            ))
        ));
        assert!(matches!(
            parse_policy_baseline_document(
                &json!({
                    "schema_version": 1,
                    "reason": " ",
                    "accepted_at": "2026-08-08",
                    "policies": [],
                })
                .to_string()
            ),
            Err(PolicyBaselineDocumentError::Validation(
                PolicyBaselineValidationError::BlankReason
            ))
        ));
        assert!(matches!(
            parse_policy_baseline_document(
                &json!({
                    "schema_version": 1,
                    "reason": "r",
                    "accepted_at": "2026-08-08",
                    "policies": [],
                    "unexpected": true,
                })
                .to_string()
            ),
            Err(PolicyBaselineDocumentError::JsonDecode { .. })
        ));
    }

    #[test]
    fn entry_cap_rejects_oversized_documents_before_allocation() {
        // Two policies whose combined finding_ids exceed the cap; the cap
        // check runs on the running total, so the fixture stays small by
        // using one policy at the cap plus one more entry.
        let mut ids = Vec::with_capacity(MAX_POLICY_BASELINE_ENTRIES);
        for index in 0..MAX_POLICY_BASELINE_ENTRIES {
            ids.push(format!("{index:064x}"));
        }
        let source = json!({
            "schema_version": 1,
            "reason": "r",
            "accepted_at": "2026-08-08",
            "policies": [
                { "policy_id": "test.a", "finding_ids": ids },
                { "policy_id": "test.b", "finding_ids": [finding_id_hex(0xaa)] },
            ],
        })
        .to_string();
        assert!(matches!(
            parse_policy_baseline_document(&source),
            Err(PolicyBaselineDocumentError::Validation(
                PolicyBaselineValidationError::TooManyEntries { .. }
            ))
        ));
    }
}
