//! Bounded, capability-confined policy suppression documents.

use std::cmp::Ordering;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use brokk_bifrost_analysis::analyzer::semantic::{
    WorkspaceRelativePath, WorkspaceRelativePathError,
};
use brokk_bifrost_analysis::workspace_document::{
    WorkspaceDocumentError, WorkspaceRoot, read_workspace_document,
};

use super::classification::{TextValidationError, validate_required_text};
use super::definition::{PolicyId, PolicyIdentifierError, Sha256ValueError, parse_lower_sha256};
use super::finding_identity::{FindingIdentityStability, PolicyFindingId};
use super::identity::PolicySemanticHash;
use super::retained::{RetainedSize, retained_extra};
use super::scope::{PolicyScopeDocumentState, PolicyScopeOptions};

pub const DEFAULT_POLICY_SUPPRESSION_PATH: &str = ".bifrost/suppressions.json";
pub const MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES: u64 = 256 * 1024;
pub const MAX_POLICY_SUPPRESSIONS: usize = 512;
pub const MAX_POLICY_SUPPRESSION_REASON_BYTES: usize = 4_096;
pub const MAX_POLICY_SUPPRESSION_ACCEPTED_BY_BYTES: usize = 256;
pub const MAX_POLICY_SUPPRESSION_PATH_BYTES: usize = 1_024;

const POLICY_SUPPRESSION_SCHEMA_VERSION: u32 = 1;
const MAX_JSON_ERROR_BYTES: usize = 512;

/// One explicit UTC calendar date supplied by a policy-evaluation host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyEvaluationDate(NaiveDate);

impl PolicyEvaluationDate {
    pub fn from_ymd(year: i32, month: u32, day: u32) -> Result<Self, PolicyDateError> {
        if !(0..=9_999).contains(&year) {
            return Err(PolicyDateError::YearOutOfRange);
        }
        NaiveDate::from_ymd_opt(year, month, day)
            .map(Self)
            .ok_or(PolicyDateError::InvalidDate)
    }

    pub fn year(self) -> i32 {
        self.0.year()
    }

    pub fn month(self) -> u32 {
        self.0.month()
    }

    pub fn day(self) -> u32 {
        self.0.day()
    }
}

impl fmt::Display for PolicyEvaluationDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:04}-{:02}-{:02}",
            self.year(),
            self.month(),
            self.day()
        )
    }
}

impl FromStr for PolicyEvaluationDate {
    type Err = PolicyDateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = value.as_bytes();
        if bytes.len() != 10
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes
                .iter()
                .enumerate()
                .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
        {
            return Err(PolicyDateError::InvalidFormat);
        }
        NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map(Self)
            .map_err(|_| PolicyDateError::InvalidDate)
    }
}

impl Serialize for PolicyEvaluationDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PolicyEvaluationDate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDateError {
    InvalidFormat,
    YearOutOfRange,
    InvalidDate,
}

impl fmt::Display for PolicyDateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => formatter.write_str("date must use exact YYYY-MM-DD syntax"),
            Self::YearOutOfRange => formatter.write_str("date year must be between 0000 and 9999"),
            Self::InvalidDate => formatter.write_str("date is not a valid calendar day"),
        }
    }
}

impl std::error::Error for PolicyDateError {}

/// Policy semantic hash recorded by an external reviewer at acceptance time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AcceptedPolicyHash([u8; 32]);

impl AcceptedPolicyHash {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AcceptedPolicyHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for AcceptedPolicyHash {
    type Err = Sha256ValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_lower_sha256(value).map(Self)
    }
}

impl Serialize for AcceptedPolicyHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySuppressionStatus {
    Accepted,
}

/// One normalized exact strong-finding review decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySuppressionRecord {
    policy_id: PolicyId,
    finding_id: PolicyFindingId,
    identity_stability: FindingIdentityStability,
    status: PolicySuppressionStatus,
    reason: Box<str>,
    policy_hash_at_acceptance: Option<AcceptedPolicyHash>,
    accepted_by: Option<Box<str>>,
    accepted_at: PolicyEvaluationDate,
    expires_at: Option<PolicyEvaluationDate>,
}

impl PolicySuppressionRecord {
    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub const fn finding_id(&self) -> PolicyFindingId {
        self.finding_id
    }

    pub const fn identity_stability(&self) -> FindingIdentityStability {
        self.identity_stability
    }

    pub const fn status(&self) -> PolicySuppressionStatus {
        self.status
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub const fn policy_hash_at_acceptance(&self) -> Option<AcceptedPolicyHash> {
        self.policy_hash_at_acceptance
    }

    pub fn accepted_by(&self) -> Option<&str> {
        self.accepted_by.as_deref()
    }

    pub const fn accepted_at(&self) -> PolicyEvaluationDate {
        self.accepted_at
    }

    pub const fn expires_at(&self) -> Option<PolicyEvaluationDate> {
        self.expires_at
    }
}

/// Canonically sorted schema-version-one suppression document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySuppressionDocument {
    schema_version: u32,
    suppressions: Box<[PolicySuppressionRecord]>,
}

impl PolicySuppressionDocument {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn suppressions(&self) -> &[PolicySuppressionRecord] {
        &self.suppressions
    }
}

/// Location used to load one suppression document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicySuppressionSource {
    #[default]
    Conventional,
    Explicit(WorkspaceRelativePath),
}

impl PolicySuppressionSource {
    pub fn explicit(path: impl AsRef<Path>) -> Result<Self, PolicySuppressionSourceError> {
        Self::from_workspace_path(WorkspaceRelativePath::try_from_path(path.as_ref())?)
    }

    pub fn explicit_portable(path: impl AsRef<str>) -> Result<Self, PolicySuppressionSourceError> {
        Self::from_workspace_path(WorkspaceRelativePath::new(path)?)
    }

    pub fn relative_path(&self) -> &str {
        match self {
            Self::Conventional => DEFAULT_POLICY_SUPPRESSION_PATH,
            Self::Explicit(path) => path.as_str(),
        }
    }

    fn from_workspace_path(
        path: WorkspaceRelativePath,
    ) -> Result<Self, PolicySuppressionSourceError> {
        if path.as_str().len() > MAX_POLICY_SUPPRESSION_PATH_BYTES {
            return Err(PolicySuppressionSourceError::TooLong {
                max_bytes: MAX_POLICY_SUPPRESSION_PATH_BYTES,
            });
        }
        Ok(Self::Explicit(path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicySuppressionOptions {
    source: PolicySuppressionSource,
}

impl PolicySuppressionOptions {
    pub const fn new(source: PolicySuppressionSource) -> Self {
        Self { source }
    }

    pub const fn source(&self) -> &PolicySuppressionSource {
        &self.source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySuppressionSourceError {
    Path(WorkspaceRelativePathError),
    TooLong { max_bytes: usize },
}

impl From<WorkspaceRelativePathError> for PolicySuppressionSourceError {
    fn from(error: WorkspaceRelativePathError) -> Self {
        Self::Path(error)
    }
}

impl fmt::Display for PolicySuppressionSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => error.fmt(formatter),
            Self::TooLong { max_bytes } => write!(
                formatter,
                "suppression path must be at most {max_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for PolicySuppressionSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::TooLong { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySuppressionDocumentState {
    NotEvaluated,
    NotFound,
    Loaded,
    Invalid,
}

/// Deterministic report context for one suppression-aware policy batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyReportEvaluationContext {
    evaluation_date: PolicyEvaluationDate,
    suppression_path: Box<str>,
    suppression_document_state: PolicySuppressionDocumentState,
    scope_path: Box<str>,
    scope_document_state: PolicyScopeDocumentState,
}

impl PolicyReportEvaluationContext {
    pub fn new(
        evaluation_date: PolicyEvaluationDate,
        suppressions: &PolicySuppressionOptions,
        suppression_document_state: PolicySuppressionDocumentState,
        scope: &PolicyScopeOptions,
        scope_document_state: PolicyScopeDocumentState,
    ) -> Self {
        Self {
            evaluation_date,
            suppression_path: suppressions.source.relative_path().into(),
            suppression_document_state,
            scope_path: scope.source().relative_path().into(),
            scope_document_state,
        }
    }

    pub const fn evaluation_date(&self) -> PolicyEvaluationDate {
        self.evaluation_date
    }

    pub fn suppression_path(&self) -> &str {
        &self.suppression_path
    }

    pub const fn suppression_document_state(&self) -> PolicySuppressionDocumentState {
        self.suppression_document_state
    }

    pub fn scope_path(&self) -> &str {
        &self.scope_path
    }

    pub const fn scope_document_state(&self) -> PolicyScopeDocumentState {
        self.scope_document_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySuppressionDecision {
    identity_stability: FindingIdentityStability,
    status: PolicySuppressionStatus,
    reason: Box<str>,
    policy_hash_at_acceptance: Option<AcceptedPolicyHash>,
    accepted_by: Option<Box<str>>,
    accepted_at: PolicyEvaluationDate,
    expires_at: Option<PolicyEvaluationDate>,
}

impl PolicySuppressionDecision {
    fn from_record(record: &PolicySuppressionRecord) -> Self {
        Self {
            identity_stability: record.identity_stability,
            status: record.status,
            reason: record.reason.clone(),
            policy_hash_at_acceptance: record.policy_hash_at_acceptance,
            accepted_by: record.accepted_by.clone(),
            accepted_at: record.accepted_at,
            expires_at: record.expires_at,
        }
    }

    pub const fn identity_stability(&self) -> FindingIdentityStability {
        self.identity_stability
    }

    pub const fn status(&self) -> PolicySuppressionStatus {
        self.status
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub const fn policy_hash_at_acceptance(&self) -> Option<AcceptedPolicyHash> {
        self.policy_hash_at_acceptance
    }

    pub fn accepted_by(&self) -> Option<&str> {
        self.accepted_by.as_deref()
    }

    pub const fn accepted_at(&self) -> PolicyEvaluationDate {
        self.accepted_at
    }

    pub const fn expires_at(&self) -> Option<PolicyEvaluationDate> {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySuppressionMatchState {
    StrongFinding,
    CurrentFindingNotStrong,
    FindingAbsent,
    PolicyNotEvaluated,
    PolicyIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySuppressionTemporalState {
    Current,
    Expired,
}

impl PolicySuppressionTemporalState {
    pub(crate) fn for_record(
        record: &PolicySuppressionRecord,
        evaluation_date: PolicyEvaluationDate,
    ) -> Self {
        if record
            .expires_at
            .is_some_and(|expires_at| expires_at < evaluation_date)
        {
            Self::Expired
        } else {
            Self::Current
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySuppressionPolicyHashState {
    Matching,
    Drifted,
    Unknown,
}

impl PolicySuppressionPolicyHashState {
    pub(crate) fn compare(
        accepted: Option<AcceptedPolicyHash>,
        current: Option<PolicySemanticHash>,
    ) -> Self {
        match (accepted, current) {
            (Some(accepted), Some(current)) if accepted.as_bytes() == current.as_bytes() => {
                Self::Matching
            }
            (Some(_), Some(_)) => Self::Drifted,
            (None, _) | (_, None) => Self::Unknown,
        }
    }
}

/// Active accepted-decision metadata attached to a retained finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFindingSuppression {
    #[serde(flatten)]
    decision: PolicySuppressionDecision,
    policy_hash_state: PolicySuppressionPolicyHashState,
}

impl PolicyFindingSuppression {
    pub const fn decision(&self) -> &PolicySuppressionDecision {
        &self.decision
    }

    pub const fn policy_hash_state(&self) -> PolicySuppressionPolicyHashState {
        self.policy_hash_state
    }
}

/// Canonical audit disposition for one loaded suppression record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySuppressionReview {
    policy_id: PolicyId,
    finding_id: PolicyFindingId,
    #[serde(flatten)]
    decision: PolicySuppressionDecision,
    match_state: PolicySuppressionMatchState,
    temporal_state: PolicySuppressionTemporalState,
    policy_hash_state: PolicySuppressionPolicyHashState,
    applied: bool,
    stale: bool,
    result_omitted: bool,
}

impl PolicySuppressionReview {
    pub(crate) fn new(
        record: &PolicySuppressionRecord,
        match_state: PolicySuppressionMatchState,
        temporal_state: PolicySuppressionTemporalState,
        policy_hash_state: PolicySuppressionPolicyHashState,
    ) -> Self {
        Self {
            policy_id: record.policy_id.clone(),
            finding_id: record.finding_id,
            decision: PolicySuppressionDecision::from_record(record),
            match_state,
            temporal_state,
            policy_hash_state,
            applied: match_state == PolicySuppressionMatchState::StrongFinding
                && temporal_state == PolicySuppressionTemporalState::Current,
            stale: match_state == PolicySuppressionMatchState::FindingAbsent,
            result_omitted: false,
        }
    }

    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub const fn finding_id(&self) -> PolicyFindingId {
        self.finding_id
    }

    pub const fn decision(&self) -> &PolicySuppressionDecision {
        &self.decision
    }

    pub const fn match_state(&self) -> PolicySuppressionMatchState {
        self.match_state
    }

    pub const fn temporal_state(&self) -> PolicySuppressionTemporalState {
        self.temporal_state
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

    pub(crate) fn finding_suppression(&self) -> Option<PolicyFindingSuppression> {
        self.applied.then(|| PolicyFindingSuppression {
            decision: self.decision.clone(),
            policy_hash_state: self.policy_hash_state,
        })
    }

    pub(crate) fn mark_result_omitted(&mut self) {
        self.result_omitted = true;
    }
}

/// Open a workspace capability once, then load and normalize its configured
/// suppression document. Only an actual missing file maps to `Ok(None)`.
pub fn load_policy_suppressions(
    workspace_root: &Path,
    options: &PolicySuppressionOptions,
) -> Result<Option<PolicySuppressionDocument>, PolicySuppressionLoadError> {
    let root =
        WorkspaceRoot::open(workspace_root).map_err(PolicySuppressionLoadError::Workspace)?;
    load_policy_suppressions_from_root(&root, options)
}

pub(crate) fn load_policy_suppressions_from_root(
    root: &WorkspaceRoot,
    options: &PolicySuppressionOptions,
) -> Result<Option<PolicySuppressionDocument>, PolicySuppressionLoadError> {
    let relative_path = Path::new(options.source.relative_path());
    let document = match read_workspace_document(
        root,
        relative_path,
        &["json"],
        MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES,
    ) {
        Ok(document) => document,
        Err(error) if workspace_error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(PolicySuppressionLoadError::Workspace(error)),
    };
    parse_policy_suppression_document(document.source())
        .map(Some)
        .map_err(PolicySuppressionLoadError::Document)
}

pub fn parse_policy_suppression_document(
    source: &str,
) -> Result<PolicySuppressionDocument, PolicySuppressionDocumentError> {
    if u64::try_from(source.len()).unwrap_or(u64::MAX) > MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES {
        return Err(PolicySuppressionDocumentError::Validation(
            PolicySuppressionValidationError::DocumentTooLarge {
                max_bytes: MAX_POLICY_SUPPRESSION_DOCUMENT_BYTES,
            },
        ));
    }
    let wire = serde_json::from_str::<WireSuppressionDocument>(source).map_err(|error| {
        PolicySuppressionDocumentError::JsonDecode {
            message: bounded_error_message(&error.to_string()),
            line: error.line(),
            column: error.column(),
        }
    })?;
    normalize_wire_document(wire).map_err(PolicySuppressionDocumentError::Validation)
}

fn normalize_wire_document(
    wire: WireSuppressionDocument,
) -> Result<PolicySuppressionDocument, PolicySuppressionValidationError> {
    if wire.schema_version != u64::from(POLICY_SUPPRESSION_SCHEMA_VERSION) {
        return Err(PolicySuppressionValidationError::UnsupportedSchemaVersion {
            observed: wire.schema_version,
        });
    }
    if wire.suppressions.len() > MAX_POLICY_SUPPRESSIONS {
        return Err(PolicySuppressionValidationError::TooManySuppressions {
            max: MAX_POLICY_SUPPRESSIONS,
        });
    }

    let mut suppressions = Vec::with_capacity(wire.suppressions.len());
    for (index, record) in wire.suppressions.into_iter().enumerate() {
        suppressions.push(normalize_wire_record(index, record)?);
    }
    suppressions.sort_by(compare_suppression_key);
    for records in suppressions.windows(2) {
        let previous = &records[0];
        let current = &records[1];
        if compare_suppression_key(previous, current) == Ordering::Equal {
            let error = if previous == current {
                PolicySuppressionValidationError::DuplicateSuppression {
                    policy_id: current.policy_id.clone(),
                    finding_id: current.finding_id,
                }
            } else {
                PolicySuppressionValidationError::ConflictingSuppression {
                    policy_id: current.policy_id.clone(),
                    finding_id: current.finding_id,
                }
            };
            return Err(error);
        }
    }
    suppressions.shrink_to_fit();
    Ok(PolicySuppressionDocument {
        schema_version: POLICY_SUPPRESSION_SCHEMA_VERSION,
        suppressions: suppressions.into_boxed_slice(),
    })
}

fn normalize_wire_record(
    index: usize,
    wire: WireSuppressionRecord,
) -> Result<PolicySuppressionRecord, PolicySuppressionValidationError> {
    let policy_id = PolicyId::new(&wire.policy_id)
        .map_err(|source| PolicySuppressionValidationError::InvalidPolicyId { index, source })?;
    let finding_id = wire
        .finding_id
        .parse()
        .map_err(|source| PolicySuppressionValidationError::InvalidFindingId { index, source })?;
    if wire.identity_stability != "strong" {
        return Err(PolicySuppressionValidationError::IdentityMustBeStrong { index });
    }
    if wire.status != "accepted" {
        return Err(PolicySuppressionValidationError::StatusMustBeAccepted { index });
    }
    validate_required_text(&wire.reason, MAX_POLICY_SUPPRESSION_REASON_BYTES)
        .map_err(|source| PolicySuppressionValidationError::InvalidReason { index, source })?;
    if wire.reason.trim().is_empty() {
        return Err(PolicySuppressionValidationError::BlankReason { index });
    }
    if let Some(accepted_by) = wire.accepted_by.as_deref() {
        validate_required_text(accepted_by, MAX_POLICY_SUPPRESSION_ACCEPTED_BY_BYTES).map_err(
            |source| PolicySuppressionValidationError::InvalidAcceptedBy { index, source },
        )?;
        if accepted_by.trim().is_empty() {
            return Err(PolicySuppressionValidationError::BlankAcceptedBy { index });
        }
    }
    let accepted_at = wire.accepted_at.parse().map_err(|source| {
        PolicySuppressionValidationError::InvalidDate {
            index,
            field: PolicySuppressionDateField::AcceptedAt,
            source,
        }
    })?;
    let expires_at = wire
        .expires_at
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|source| PolicySuppressionValidationError::InvalidDate {
            index,
            field: PolicySuppressionDateField::ExpiresAt,
            source,
        })?;
    if expires_at.is_some_and(|expires_at| expires_at < accepted_at) {
        return Err(PolicySuppressionValidationError::ExpirationBeforeAcceptance { index });
    }
    let policy_hash_at_acceptance = wire
        .policy_hash_at_acceptance
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(
            |source| PolicySuppressionValidationError::InvalidAcceptedPolicyHash { index, source },
        )?;

    Ok(PolicySuppressionRecord {
        policy_id,
        finding_id,
        identity_stability: FindingIdentityStability::Strong,
        status: PolicySuppressionStatus::Accepted,
        reason: wire.reason.into_boxed_str(),
        policy_hash_at_acceptance,
        accepted_by: wire.accepted_by.map(String::into_boxed_str),
        accepted_at,
        expires_at,
    })
}

fn compare_suppression_key(
    left: &PolicySuppressionRecord,
    right: &PolicySuppressionRecord,
) -> Ordering {
    left.policy_id
        .cmp(&right.policy_id)
        .then_with(|| left.finding_id.cmp(&right.finding_id))
}

fn workspace_error_is_not_found(error: &WorkspaceDocumentError) -> bool {
    matches!(
        error,
        WorkspaceDocumentError::OpenFile { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound
    )
}

fn bounded_error_message(message: &str) -> Box<str> {
    if message.len() <= MAX_JSON_ERROR_BYTES {
        return message.into();
    }
    let mut end = MAX_JSON_ERROR_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &message[..end]).into_boxed_str()
}

impl RetainedSize for PolicyEvaluationDate {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl RetainedSize for AcceptedPolicyHash {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl RetainedSize for PolicySuppressionRecord {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(retained_extra(&self.reason))
            .saturating_add(retained_extra(&self.policy_hash_at_acceptance))
            .saturating_add(retained_extra(&self.accepted_by))
            .saturating_add(retained_extra(&self.accepted_at))
            .saturating_add(retained_extra(&self.expires_at))
    }
}

impl RetainedSize for PolicySuppressionDocument {
    fn retained_size(&self) -> usize {
        self.suppressions
            .iter()
            .fold(std::mem::size_of::<Self>(), |bytes, suppression| {
                bytes.saturating_add(suppression.retained_size())
            })
    }
}

impl RetainedSize for PolicySuppressionSource {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Conventional => 0,
            Self::Explicit(path) => retained_extra(path),
        })
    }
}

impl RetainedSize for PolicySuppressionOptions {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(retained_extra(&self.source))
    }
}

impl RetainedSize for PolicyReportEvaluationContext {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.suppression_path.len())
            .saturating_add(self.scope_path.len())
    }
}

impl RetainedSize for PolicySuppressionDecision {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.reason))
            .saturating_add(retained_extra(&self.accepted_by))
    }
}

impl RetainedSize for PolicyFindingSuppression {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(retained_extra(&self.decision))
    }
}

impl RetainedSize for PolicySuppressionReview {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(retained_extra(&self.decision))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSuppressionDocument {
    schema_version: u64,
    suppressions: Vec<WireSuppressionRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSuppressionRecord {
    policy_id: String,
    finding_id: String,
    identity_stability: String,
    status: String,
    reason: String,
    policy_hash_at_acceptance: Option<String>,
    accepted_by: Option<String>,
    accepted_at: String,
    expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySuppressionDocumentError {
    JsonDecode {
        message: Box<str>,
        line: usize,
        column: usize,
    },
    Validation(PolicySuppressionValidationError),
}

impl fmt::Display for PolicySuppressionDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonDecode {
                message,
                line,
                column,
            } => write!(
                formatter,
                "invalid suppression JSON at line {line}, column {column}: {message}"
            ),
            Self::Validation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicySuppressionDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JsonDecode { .. } => None,
            Self::Validation(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySuppressionValidationError {
    DocumentTooLarge {
        max_bytes: u64,
    },
    UnsupportedSchemaVersion {
        observed: u64,
    },
    TooManySuppressions {
        max: usize,
    },
    InvalidPolicyId {
        index: usize,
        source: PolicyIdentifierError,
    },
    InvalidFindingId {
        index: usize,
        source: Sha256ValueError,
    },
    IdentityMustBeStrong {
        index: usize,
    },
    StatusMustBeAccepted {
        index: usize,
    },
    InvalidReason {
        index: usize,
        source: TextValidationError,
    },
    BlankReason {
        index: usize,
    },
    InvalidAcceptedBy {
        index: usize,
        source: TextValidationError,
    },
    BlankAcceptedBy {
        index: usize,
    },
    InvalidDate {
        index: usize,
        field: PolicySuppressionDateField,
        source: PolicyDateError,
    },
    ExpirationBeforeAcceptance {
        index: usize,
    },
    InvalidAcceptedPolicyHash {
        index: usize,
        source: Sha256ValueError,
    },
    DuplicateSuppression {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
    ConflictingSuppression {
        policy_id: PolicyId,
        finding_id: PolicyFindingId,
    },
}

impl fmt::Display for PolicySuppressionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { max_bytes } => {
                write!(formatter, "suppression document exceeds {max_bytes} bytes")
            }
            Self::UnsupportedSchemaVersion { observed } => write!(
                formatter,
                "unsupported suppression schema version {observed}; expected {POLICY_SUPPRESSION_SCHEMA_VERSION}"
            ),
            Self::TooManySuppressions { max } => {
                write!(
                    formatter,
                    "suppression document may contain at most {max} records"
                )
            }
            Self::InvalidPolicyId { index, source } => {
                write!(
                    formatter,
                    "suppression {index} has an invalid policy_id: {source}"
                )
            }
            Self::InvalidFindingId { index, source } => write!(
                formatter,
                "suppression {index} has an invalid finding_id: {source}"
            ),
            Self::IdentityMustBeStrong { index } => write!(
                formatter,
                "suppression {index} identity_stability must be strong"
            ),
            Self::StatusMustBeAccepted { index } => {
                write!(formatter, "suppression {index} status must be accepted")
            }
            Self::InvalidReason { index, source } => {
                write!(
                    formatter,
                    "suppression {index} has an invalid reason: {source}"
                )
            }
            Self::BlankReason { index } => {
                write!(formatter, "suppression {index} reason must not be blank")
            }
            Self::InvalidAcceptedBy { index, source } => write!(
                formatter,
                "suppression {index} has invalid accepted_by text: {source}"
            ),
            Self::BlankAcceptedBy { index } => write!(
                formatter,
                "suppression {index} accepted_by must not be blank when present"
            ),
            Self::InvalidDate {
                index,
                field,
                source,
            } => write!(
                formatter,
                "suppression {index} has invalid {}: {source}",
                field.as_str()
            ),
            Self::ExpirationBeforeAcceptance { index } => write!(
                formatter,
                "suppression {index} expires_at must not precede accepted_at"
            ),
            Self::InvalidAcceptedPolicyHash { index, source } => write!(
                formatter,
                "suppression {index} has invalid policy_hash_at_acceptance: {source}"
            ),
            Self::DuplicateSuppression {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "duplicate suppression for policy {policy_id} finding {finding_id}"
            ),
            Self::ConflictingSuppression {
                policy_id,
                finding_id,
            } => write!(
                formatter,
                "conflicting suppression records for policy {policy_id} finding {finding_id}"
            ),
        }
    }
}

impl std::error::Error for PolicySuppressionValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicyId { source, .. } => Some(source),
            Self::InvalidFindingId { source, .. }
            | Self::InvalidAcceptedPolicyHash { source, .. } => Some(source),
            Self::InvalidReason { source, .. } | Self::InvalidAcceptedBy { source, .. } => {
                Some(source)
            }
            Self::InvalidDate { source, .. } => Some(source),
            Self::DocumentTooLarge { .. }
            | Self::UnsupportedSchemaVersion { .. }
            | Self::TooManySuppressions { .. }
            | Self::IdentityMustBeStrong { .. }
            | Self::StatusMustBeAccepted { .. }
            | Self::BlankReason { .. }
            | Self::BlankAcceptedBy { .. }
            | Self::ExpirationBeforeAcceptance { .. }
            | Self::DuplicateSuppression { .. }
            | Self::ConflictingSuppression { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySuppressionDateField {
    AcceptedAt,
    ExpiresAt,
}

impl PolicySuppressionDateField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedAt => "accepted_at",
            Self::ExpiresAt => "expires_at",
        }
    }
}

#[derive(Debug)]
pub enum PolicySuppressionLoadError {
    Workspace(WorkspaceDocumentError),
    Document(PolicySuppressionDocumentError),
}

impl fmt::Display for PolicySuppressionLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Document(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicySuppressionLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::Document(error) => Some(error),
        }
    }
}
